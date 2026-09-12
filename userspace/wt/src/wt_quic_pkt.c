/* QUIC packet protection. See wt_quic_pkt.h for the interface and for what is
 * deliberately explicit here.
 *
 * RFC 9001 sections 5.3, 5.4, 5.5; RFC 9000 section 17.1 for packet numbers.
 */

#include "wt_quic_pkt.h"

#include <string.h>

/* RFC 9000 section 17.1: the smallest number of bytes whose encoding lets the
 * receiver recover the packet number, which is "twice the range": the
 * difference must be less than half the encoding's range.
 *
 *   if the difference is less than 2^7,   one byte is enough
 *   less than 2^15, two bytes; less than 2^23, three; otherwise four.
 *
 * The first version of this doubled 256 and compared against the full range,
 * so it used one byte for a difference of 255 -- which the receiver cannot
 * decode, because its window is only 128 wide and it recovers a number 256
 * lower. The failure is silent at the sender: the packet is well formed and
 * the peer simply rejects it, or worse, recovers a different packet number and
 * fails authentication. */
size_t wt_quic_packet_number_length(uint64_t packet_number,
                                    uint64_t largest_acked) {
  uint64_t half_range = 128U; /* 2^7 */
  size_t length = 1U;
  uint64_t difference;

  if (packet_number > WT_QUIC_MAX_PACKET_NUMBER) return 0U;
  /* A packet number that is not greater than the largest acknowledged cannot
   * be sent; the caller has a bug, and saying so here is better than encoding
   * a number the peer will reject. */
  if (packet_number <= largest_acked) return 0U;

  difference = packet_number - largest_acked;
  while (length < 4U && difference >= half_range) {
    half_range <<= 8;
    length++;
  }
  return length;
}

size_t wt_quic_encode_packet_number(uint64_t packet_number,
                                    uint64_t largest_acked, uint8_t *out) {
  size_t length = wt_quic_packet_number_length(packet_number, largest_acked);
  size_t i;
  if (out == NULL || length == 0U) return 0U;
  for (i = 0U; i < length; i++) {
    out[i] = (uint8_t)(packet_number >> (8U * (length - 1U - i)));
  }
  return length;
}

/* RFC 9000 section 17.1, the decoding half. The expected value is the
 * truncated number placed nearest to `largest_seen` within the encoding's
 * window; "append zeros" is a different and wrong answer.
 *
 *   expected_pn  = largest_pn + 1
 *   pn_win       = 1 << (pn_len * 8)
 *   pn_hwin      = pn_win / 2
 *   pn_mask      = pn_win - 1
 *   candidate_pn = (expected_pn & ~pn_mask) | truncated_pn          // base
 *   if candidate_pn <= expected_pn - pn_hwin and
 *      candidate_pn < (1 << 62) - pn_win:
 *       return candidate_pn + pn_win
 *   if candidate_pn > expected_pn + pn_hwin and candidate_pn >= pn_win:
 *       return candidate_pn - pn_win
 *   return candidate_pn
 */
int wt_quic_decode_packet_number(uint64_t truncated, size_t pn_len,
                                 uint64_t largest_seen, uint64_t *out) {
  uint64_t expected;
  uint64_t window;
  uint64_t half_window;
  uint64_t mask;
  uint64_t candidate;

  if (out == NULL) return -1;
  if (pn_len == 0U || pn_len > 4U) return -1;
  /* The truncated value must fit the encoding it came from; a wider value
   * means the caller read the wrong bytes. */
  if (pn_len < 4U && truncated >= (UINT64_C(1) << (8U * pn_len))) return -1;

  expected = largest_seen + 1U;
  window = UINT64_C(1) << (8U * pn_len);
  half_window = window / 2U;
  mask = window - 1U;

  candidate = (expected & ~mask) | truncated;

  /* The first version of this had the first comparison inverted. The
     condition is that the candidate is at or below the bottom of the window
     around the expected value, which is `candidate + half_window <= expected`;
     the RFC writes it as `candidate_pn <= expected_pn - pn_hwin` and the two
     are the same thing only if `expected - half_window` cannot underflow,
     which it can when `largest_seen` is small. Written this way there is no
     subtraction that can wrap. */
  if (candidate + half_window <= expected &&
      candidate < (UINT64_C(1) << 62) - window) {
    candidate += window;
  } else if (candidate > expected + half_window && candidate >= window) {
    candidate -= window;
  }

  *out = candidate;
  return 0;
}

int wt_quic_packet_nonce(const uint8_t iv[WT_TLS_IV_LEN],
                         uint64_t packet_number, uint8_t out[WT_TLS_IV_LEN]) {
  uint64_t number = packet_number;
  size_t i;
  if (iv == NULL || out == NULL) return -1;
  memcpy(out, iv, WT_TLS_IV_LEN);
  /* XOR into the rightmost bytes, one at a time, so a packet number wider than
   * 64 bits would be handled by the same code as one that is not. */
  for (i = 0U; i < WT_TLS_IV_LEN; i++) {
    out[WT_TLS_IV_LEN - 1U - i] ^= (uint8_t)(number & 0xFFU);
    number >>= 8;
  }
  return 0;
}

/* The header protection mask, and then its application.
 *
 * RFC 9001 sections 5.4.3 and 5.4.4:
 *
 *   AES:      mask = AES-ECB(hp_key, sample)[0..4]
 *   ChaCha20: mask = ChaCha20(hp_key, counter = sample[0..3] little-endian,
 *                             nonce = sample[4..15])(five zero bytes)
 *
 * The sample is 16 bytes starting at pn_offset + 4, which is four bytes past
 * the start of the packet number field and independent of how long the packet
 * number actually is. Sampling from the packet number itself is the classic
 * error: it works for every packet whose number happens to be long and fails
 * for the rest.
 *
 * The first byte is masked with 0x0f for a long header and 0x1f for a short
 * one, because the short header's key phase bit is protected too. */
static int header_protection_mask(wt_tls_aead_t aead, const uint8_t *hp_key,
                                  size_t hp_len, const uint8_t sample[16],
                                  uint8_t mask[5]) {
  if (aead == WT_TLS_AEAD_AES_128_GCM) {
    uint8_t block[16];
    if (hp_len != 16U) return -1;
    if (wt_aes128_ecb_encrypt_block(hp_key, sample, block) != 0) return -1;
    memcpy(mask, block, 5);
    wt_secure_zero(block, sizeof(block));
    return 0;
  }
  if (aead == WT_TLS_AEAD_CHACHA20_POLY1305) {
    uint32_t counter;
    uint8_t zero[5] = {0, 0, 0, 0, 0};
    if (hp_len != 32U) return -1;
    counter = (uint32_t)sample[0] | ((uint32_t)sample[1] << 8) |
              ((uint32_t)sample[2] << 16) | ((uint32_t)sample[3] << 24);
    return wt_chacha20_xor(hp_key, sample + 4, counter, zero, 5, mask);
  }
  return -1;
}

int wt_quic_header_protection(wt_tls_aead_t aead, const uint8_t *hp_key,
                              size_t hp_len,
                              const wt_quic_packet_header_t *header,
                              uint8_t *packet, size_t packet_len) {
  uint8_t sample[16];
  uint8_t mask[5];
  size_t sample_offset;
  size_t i;

  if (hp_key == NULL || header == NULL || packet == NULL) return -1;
  if (header->pn_len < 1U || header->pn_len > 4U) return -1;
  if (header->len < header->pn_offset + header->pn_len) return -1;
  if (packet_len < header->len) return -1;

  /* Four bytes past the start of the packet number field, then sixteen bytes.
   * The sample may extend past the header into the protected payload, which is
   * why it is read from `packet` rather than from `header->bytes`. */
  sample_offset = header->pn_offset + 4U;
  if (sample_offset + sizeof(sample) > packet_len) {
    /* Not enough packet to sample from. RFC 9001 section 5.4.2 requires a
     * packet to be long enough; a short one is refused rather than sampled
     * partly out of bounds. */
    return -1;
  }
  memcpy(sample, packet + sample_offset, sizeof(sample));

  if (header_protection_mask(aead, hp_key, hp_len, sample, mask) != 0) {
    return -1;
  }

  /* The first byte: the low four bits for a long header, the low five for a
   * short one (the short header protects the key phase bit as well). */
  packet[0] ^= (uint8_t)(mask[0] & (header->long_header ? 0x0FU : 0x1FU));
  for (i = 0U; i < header->pn_len; i++) {
    packet[header->pn_offset + i] ^= mask[1U + i];
  }

  wt_secure_zero(sample, sizeof(sample));
  wt_secure_zero(mask, sizeof(mask));
  return 0;
}

int wt_quic_protect_packet(wt_tls_aead_t aead,
                           const wt_tls_traffic_keys_t *keys,
                           const wt_quic_packet_header_t *header,
                           uint64_t packet_number, uint8_t *packet,
                           size_t packet_len, size_t *out_len) {
  uint8_t nonce[WT_TLS_IV_LEN];
  uint8_t tag[16];
  size_t plaintext_len;

  if (keys == NULL || header == NULL || packet == NULL || out_len == NULL) {
    return -1;
  }
  /* Only AES-128-GCM has a decrypt path here; ChaCha20-Poly1305 does not, and
   * claiming to protect with it would produce packets no test covers. */
  if (aead != WT_TLS_AEAD_AES_128_GCM) return -1;
  if (packet_len < header->len) return -1;
  if (header->len > WT_QUIC_MAX_HEADER_LEN) return -1;
  if (header->len < header->pn_offset + header->pn_len) return -1;
  if (keys->hp_len == 0U) return -1;

  plaintext_len = packet_len - header->len;

  /* The associated data is the header with the packet number in the clear, so
   * it is taken from the packet before anything is written. */
  if (wt_quic_packet_nonce(keys->iv, packet_number, nonce) != 0) return -1;

  /* Encrypt in place: the payload sits immediately after the header, so the
   * AEAD's output goes over the same bytes. */
  if (wt_aes128_gcm_encrypt(keys->key, nonce, packet, header->len,
                            packet + header->len, plaintext_len,
                            packet + header->len, tag) != 0) {
    wt_secure_zero(nonce, sizeof(nonce));
    return -1;
  }
  /* The tag follows the ciphertext. */
  memcpy(packet + packet_len, tag, sizeof(tag));
  *out_len = packet_len + sizeof(tag);

  /* Header protection is applied last, over the now-protected packet, because
   * the sample comes from the ciphertext. */
  if (wt_quic_header_protection(aead, keys->hp, keys->hp_len, header, packet,
                                *out_len) != 0) {
    wt_secure_zero(nonce, sizeof(nonce));
    wt_secure_zero(tag, sizeof(tag));
    return -1;
  }

  wt_secure_zero(nonce, sizeof(nonce));
  wt_secure_zero(tag, sizeof(tag));
  return 0;
}

int wt_quic_unprotect_packet(wt_tls_aead_t aead,
                             const wt_tls_traffic_keys_t *keys,
                             const wt_quic_packet_header_t *header,
                             uint64_t packet_number, const uint8_t *packet,
                             size_t packet_len, uint8_t *plaintext,
                             size_t plaintext_capacity, size_t *out_len) {
  uint8_t nonce[WT_TLS_IV_LEN];
  size_t ciphertext_len;
  const uint8_t *tag;

  if (keys == NULL || header == NULL || packet == NULL || plaintext == NULL ||
      out_len == NULL || header->bytes == NULL) {
    return -1;
  }
  if (aead != WT_TLS_AEAD_AES_128_GCM) return -1;
  if (packet_len < header->len + 16U) return -1;
  if (header->len > WT_QUIC_MAX_HEADER_LEN) return -1;
  if (header->len < header->pn_offset + header->pn_len) return -1;
  if (keys->hp_len == 0U) return -1;

  ciphertext_len = packet_len - header->len - 16U;
  tag = packet + packet_len - 16U;

  /* The plaintext must not be written into the caller's receive buffer until
     the tag has verified. It cannot be decrypted in place over the ciphertext
     either: the AEAD binding copies its input into its output buffer before
     working, so an overlapping in-place call would feed it its own plaintext
     from the second block on. Hence a separate buffer, with the capacity
     stated by the caller and checked here rather than assumed. */
  if (ciphertext_len > plaintext_capacity) return -1;

  if (wt_quic_packet_nonce(keys->iv, packet_number, nonce) != 0) return -1;

  {
    /* Decrypt, then compare the tag the receiver computed against the one on
       the wire. The comparison is constant time and happens here rather than
       inside the crypto layer because discarding the plaintext is this layer's
       decision. The plaintext has been written to the caller's buffer by the
       time the comparison runs, so a mismatch clears it: a failure must not
       leave an unauthenticated payload behind for code that ignored the return
       value. */
    uint8_t computed_tag[16];
    int equal;
    if (wt_aes128_gcm_decrypt(keys->key, nonce, header->bytes, header->len,
                              packet + header->len, ciphertext_len, plaintext,
                              computed_tag) != 0) {
      wt_secure_zero(nonce, sizeof(nonce));
      return -1;
    }
    equal = wt_ct_equal(computed_tag, tag, sizeof(computed_tag));
    wt_secure_zero(computed_tag, sizeof(computed_tag));
    if (!equal) {
      wt_secure_zero(plaintext, ciphertext_len);
      wt_secure_zero(nonce, sizeof(nonce));
      return -1;
    }
  }

  *out_len = ciphertext_len;
  wt_secure_zero(nonce, sizeof(nonce));
  return 0;
}
