/* QUIC packet protection. See webtransport/quic/protection.h.
 *
 * The two halves -- payload and header -- are separate functions because they
 * happen at different times and in a fixed order, and a single "protect this
 * packet" function would hide that order at exactly the point where getting it
 * wrong is invisible until a peer cannot read anything.
 */

#include "webtransport/quic/protection.h"

#include <string.h>

/* RFC 9001 section 5.2: the version 1 Initial salt, "the salt for version 1".
 * It is the ASCII of the draft version this QUIC version came from, which is why
 * it looks random and is not. */
const uint8_t wt_quic_initial_salt_v1[20] = {
    0x38U, 0x76U, 0x2cU, 0xf7U, 0xf5U, 0x59U, 0x34U, 0xb3U, 0x4dU, 0x17U,
    0x9aU, 0xe6U, 0xa4U, 0xc8U, 0x0cU, 0xadU, 0xccU, 0xbbU, 0x7fU, 0x0aU};

/* The label lengths RFC 9001 section 5.1 uses: six for "quic ku" and eight for
 * the rest. The lengths are not written as constants in the derivation -- the
 * key and hp lengths come from the AEAD -- but the IV is always twelve bytes and
 * the secret always a hash. */
#define WT_QUIC_SECRET_LEN WT_SHA256_LEN

void wt_quic_packet_keys_clear(wt_quic_packet_keys_t *keys) {
  if (keys == NULL) return;
  wt_secure_zero(keys, sizeof(*keys));
}

wt_status_t wt_quic_initial_secret(const uint8_t *salt, size_t salt_len,
                                   const uint8_t *dcid, size_t dcid_len,
                                   uint8_t out[WT_SHA256_LEN]) {
  if (salt == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* A connection ID of zero length is legal in QUIC (RFC 9000 section 5.1), so it
   * is not refused here: the Initial keys of a connection whose client chose an
   * empty ID are derived from an empty IKM, which is what RFC 9001 section 5.2
   * says and what the derivation does. */
  if (dcid == NULL && dcid_len != 0U) return WT_ERR_INVALID_ARGUMENT;
  return wt_hkdf_extract_sha256(salt, salt_len, dcid, dcid_len, out);
}

/* The key, IV and header protection key a traffic secret produces. Shared by the
 * initial, traffic and update paths, because RFC 9001 section 5.1 uses the same
 * three labels for all of them and three copies of this would be three chances to
 * write a different label. */
static wt_status_t wt_quic_derive_packet_keys(
    const uint8_t secret[WT_SHA256_LEN], wt_aead_t aead,
    wt_quic_packet_keys_t *out) {
  size_t key_len = wt_aead_key_len(aead);
  size_t iv_len = wt_aead_iv_len(aead);
  wt_status_t status;

  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (key_len == 0U || iv_len == 0U) return WT_ERR_UNSUPPORTED;
  if (key_len > sizeof(out->key) || key_len > sizeof(out->hp)) {
    return WT_ERR_UNSUPPORTED;
  }
  memset(out, 0, sizeof(*out));
  memcpy(out->secret, secret, WT_QUIC_SECRET_LEN);
  out->aead = aead;
  out->key_len = key_len;
  /* `quic hp` uses the AEAD's own key length, so hp_len and key_len are the same
   * number for both suites -- which is a fact about RFC 9001 section 5.1 and not
   * a simplification this code is allowed to make silently. */
  out->hp_len = key_len;

  status = wt_hkdf_expand_label_sha256(secret, WT_QUIC_SECRET_LEN, "quic key",
                                       NULL, 0U, out->key, key_len);
  if (status != WT_OK) goto fail;
  status = wt_hkdf_expand_label_sha256(secret, WT_QUIC_SECRET_LEN, "quic iv",
                                       NULL, 0U, out->iv, iv_len);
  if (status != WT_OK) goto fail;
  status = wt_hkdf_expand_label_sha256(secret, WT_QUIC_SECRET_LEN, "quic hp",
                                       NULL, 0U, out->hp, key_len);
  if (status != WT_OK) goto fail;
  return WT_OK;

fail:
  /* A half-derived key set is worse than none: it would encrypt with a key whose
   * IV came from somewhere else. */
  wt_quic_packet_keys_clear(out);
  return status;
}

wt_status_t wt_quic_packet_keys_from_secret(
    const uint8_t secret[WT_SHA256_LEN], wt_aead_t aead,
    wt_quic_packet_keys_t *out) {
  if (secret == NULL) return WT_ERR_INVALID_ARGUMENT;
  return wt_quic_derive_packet_keys(secret, aead, out);
}

wt_status_t wt_quic_initial_packet_keys(const uint8_t initial_secret[WT_SHA256_LEN],
                                        int from_server, wt_aead_t aead,
                                        wt_quic_packet_keys_t *out) {
  uint8_t secret[WT_QUIC_SECRET_LEN];
  wt_status_t status;
  if (initial_secret == NULL) return WT_ERR_INVALID_ARGUMENT;
  status = wt_hkdf_expand_label_sha256(
      initial_secret, WT_QUIC_SECRET_LEN,
      from_server ? "server in" : "client in", NULL, 0U, secret,
      sizeof(secret));
  if (status != WT_OK) return status;
  status = wt_quic_derive_packet_keys(secret, aead, out);
  wt_secure_zero(secret, sizeof(secret));
  return status;
}

wt_status_t wt_quic_packet_keys_update(const wt_quic_packet_keys_t *current,
                                       wt_quic_packet_keys_t *out) {
  uint8_t next_secret[WT_QUIC_SECRET_LEN];
  wt_status_t status;
  if (current == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* RFC 9001 section 6: the AEAD does not change across a key update, so the
   * suite comes from the current keys rather than from the caller -- a caller
   * that passed a different one would have a connection whose two directions use
   * different algorithms. */
  status = wt_hkdf_expand_label_sha256(current->secret, WT_QUIC_SECRET_LEN,
                                       "quic ku", NULL, 0U, next_secret,
                                       sizeof(next_secret));
  if (status != WT_OK) return status;
  status = wt_quic_derive_packet_keys(next_secret, current->aead, out);
  wt_secure_zero(next_secret, sizeof(next_secret));
  if (status != WT_OK) return status;
  /* RFC 9001 section 6.1: "The header protection key is not updated." The new set's AEAD key and IV come from the
   * next secret and its header protection key comes from the CURRENT one, so a packet this endpoint protects
   * after an update uses a key its peer already has -- which is the whole point of the update being cheap.
   *
   * The function used to return a freshly derived hp, and its only in-tree caller copied the old one back over it
   * (`derive_next_keys` in connection.c), so the tree worked while the PUBLIC function was wrong and its header
   * documented the wrong behaviour. An audit found it by calling the function directly. */
  memcpy(out->hp, current->hp, sizeof(out->hp));
  out->hp_len = current->hp_len;
  return WT_OK;
}

wt_status_t wt_quic_packet_nonce(const uint8_t iv[WT_AEAD_IV_LEN],
                                 uint64_t packet_number,
                                 uint8_t out[WT_AEAD_IV_LEN]) {
  size_t i;
  if (iv == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memcpy(out, iv, WT_AEAD_IV_LEN);
  /* RFC 9001 section 5.3: "The packet number is XORed with the static IV,
   * starting from the end." The last eight bytes hold it, most significant byte
   * first, so byte 11 of the nonce takes the packet number's low byte. */
  for (i = 0U; i < 8U; i++) {
    out[WT_AEAD_IV_LEN - 1U - i] ^= (uint8_t)((packet_number >> (8U * i)) & 0xFFU);
  }
  return WT_OK;
}

wt_status_t wt_quic_header_protection_sample(size_t pn_offset,
                                             const uint8_t *packet,
                                             size_t packet_len,
                                             uint8_t sample[16]) {
  size_t sample_offset;
  if (packet == NULL || sample == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* RFC 9001 section 5.4.2: the sample starts four bytes after the start of the
   * packet number field. Four rather than zero because the packet number is at
   * most four bytes, so the sample never overlaps it -- which is what lets the
   * header be unmasked without knowing the packet number length. */
  if (pn_offset > SIZE_MAX - WT_QUIC_HP_SAMPLE_OFFSET) return WT_ERR_OVERFLOW;
  sample_offset = pn_offset + WT_QUIC_HP_SAMPLE_OFFSET;
  if (sample_offset > packet_len || packet_len - sample_offset < WT_QUIC_HP_SAMPLE_LENGTH) {
    /* A packet too short to sample cannot be protected. QUIC requires a minimum
     * datagram size partly for this reason (RFC 9000 section 14.1); a SENDER pads
     * its plaintext instead, which `wt_quic_packet_build` does. */
    return WT_ERR_TRUNCATED;
  }
  memcpy(sample, packet + sample_offset, WT_QUIC_HP_SAMPLE_LENGTH);
  return WT_OK;
}

wt_status_t wt_quic_header_protection_mask(wt_aead_t aead, const uint8_t *hp,
                                           size_t hp_len,
                                           const uint8_t sample[16],
                                           uint8_t out[5]) {
  if (hp == NULL || sample == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (hp_len < wt_aead_key_len(aead)) return WT_ERR_INVALID_ARGUMENT;
  switch (aead) {
    case WT_AEAD_AES_128_GCM: {
      uint8_t block[16];
      wt_status_t status = wt_aes128_ecb_encrypt_block(hp, sample, block);
      if (status != WT_OK) {
        wt_secure_zero(block, sizeof(block));
        return status;
      }
      memcpy(out, block, 5U);
      wt_secure_zero(block, sizeof(block));
      return WT_OK;
    }
    case WT_AEAD_CHACHA20_POLY1305: {
      /* RFC 9001 section 5.4.4: the counter is the sample's first four bytes
       * little-endian and the nonce is its last twelve, and the mask is the first
       * five bytes of the keystream over five zero bytes. This is the ChaCha20
       * stream cipher and not the AEAD. */
      uint8_t counter_bytes[4];
      uint8_t zeros[5] = {0, 0, 0, 0, 0};
      uint32_t counter;
      wt_status_t status;
      counter_bytes[0] = sample[0];
      counter_bytes[1] = sample[1];
      counter_bytes[2] = sample[2];
      counter_bytes[3] = sample[3];
      counter = (uint32_t)counter_bytes[0] | ((uint32_t)counter_bytes[1] << 8) |
                ((uint32_t)counter_bytes[2] << 16) |
                ((uint32_t)counter_bytes[3] << 24);
      status = wt_chacha20_xor(hp, sample + 4U, counter, zeros, sizeof(zeros),
                               out);
      wt_secure_zero(zeros, sizeof(zeros));
      return status;
    }
    default:
      return WT_ERR_UNSUPPORTED;
  }
}

wt_status_t wt_quic_protect_header(wt_aead_t aead, const uint8_t *hp,
                                   size_t hp_len, uint8_t *packet,
                                   size_t packet_len, size_t pn_offset,
                                   size_t pn_len) {
  uint8_t sample[16];
  uint8_t mask[5];
  size_t i;
  wt_status_t status;

  if (packet == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (pn_len == 0U || pn_len > 4U) return WT_ERR_INVALID_ARGUMENT;
  if (pn_offset >= packet_len) return WT_ERR_INVALID_ARGUMENT;
  if (pn_len > packet_len - pn_offset) return WT_ERR_INVALID_ARGUMENT;

  status = wt_quic_header_protection_sample(pn_offset, packet, packet_len,
                                            sample);
  if (status != WT_OK) return status;
  status = wt_quic_header_protection_mask(aead, hp, hp_len, sample, mask);
  wt_secure_zero(sample, sizeof(sample));
  if (status != WT_OK) {
    wt_secure_zero(mask, sizeof(mask));
    return status;
  }

  /* RFC 9001 section 5.4.1: for a long header the mask's low four bits cover the
   * first byte, because its high four are the version-dependent form; for a short
   * header the low five are masked, because bit 3 is the key phase. The rule is
   * "the low four bits for a long header and the low five for a short one", and
   * the packet's own first byte says which it is. */
  if ((packet[0] & 0x80U) != 0U) {
    packet[0] ^= (uint8_t)(mask[0] & 0x0FU);
  } else {
    packet[0] ^= (uint8_t)(mask[0] & 0x1FU);
  }
  for (i = 0U; i < pn_len; i++) {
    packet[pn_offset + i] ^= mask[1U + i];
  }
  wt_secure_zero(mask, sizeof(mask));
  return WT_OK;
}

wt_status_t wt_quic_unprotect_header(wt_aead_t aead, const uint8_t *hp,
                                     size_t hp_len, uint8_t *packet,
                                     size_t packet_len, size_t pn_offset,
                                     size_t *out_pn_len) {
  uint8_t sample[16];
  uint8_t mask[5];
  size_t pn_len;
  size_t i;
  wt_status_t status;

  if (packet == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (pn_offset >= packet_len) return WT_ERR_INVALID_ARGUMENT;
  if (out_pn_len != NULL) *out_pn_len = 0U;

  status = wt_quic_header_protection_sample(pn_offset, packet, packet_len,
                                            sample);
  if (status != WT_OK) return status;
  status = wt_quic_header_protection_mask(aead, hp, hp_len, sample, mask);
  wt_secure_zero(sample, sizeof(sample));
  if (status != WT_OK) {
    wt_secure_zero(mask, sizeof(mask));
    return status;
  }

  if ((packet[0] & 0x80U) != 0U) {
    packet[0] ^= (uint8_t)(mask[0] & 0x0FU);
  } else {
    packet[0] ^= (uint8_t)(mask[0] & 0x1FU);
  }
  /* The packet number length is in the unmasked first byte, which is why it can
   * only be read after this step. */
  pn_len = (size_t)(packet[0] & 0x03U) + 1U;
  if (pn_len > packet_len - pn_offset) {
    wt_secure_zero(mask, sizeof(mask));
    return WT_ERR_TRUNCATED;
  }
  for (i = 0U; i < pn_len; i++) {
    packet[pn_offset + i] ^= mask[1U + i];
  }
  wt_secure_zero(mask, sizeof(mask));
  if (out_pn_len != NULL) *out_pn_len = pn_len;
  return WT_OK;
}

wt_status_t wt_quic_protect_frames(const wt_quic_packet_keys_t *keys,
                                   uint64_t packet_number, const uint8_t *aad,
                                   size_t aad_len, const uint8_t *frames,
                                   size_t frames_len, uint8_t *out,
                                   size_t out_capacity, size_t *out_len) {
  uint8_t nonce[WT_AEAD_IV_LEN];
  uint8_t tag[WT_AEAD_TAG_LEN];
  wt_status_t status;

  if (keys == NULL || out == NULL || out_len == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *out_len = 0U;
  if (aad == NULL && aad_len != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (frames == NULL && frames_len != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (out_capacity < frames_len ||
      out_capacity - frames_len < WT_AEAD_TAG_LEN) {
    return WT_ERR_LIMIT;
  }
  status = wt_quic_packet_nonce(keys->iv, packet_number, nonce);
  if (status != WT_OK) return status;
  status = wt_aead_seal(keys->aead, keys->key, nonce, aad, aad_len, frames,
                        frames_len, out, tag);
  wt_secure_zero(nonce, sizeof(nonce));
  if (status != WT_OK) {
    wt_secure_zero(tag, sizeof(tag));
    return status;
  }
  memcpy(out + frames_len, tag, WT_AEAD_TAG_LEN);
  wt_secure_zero(tag, sizeof(tag));
  *out_len = frames_len + WT_AEAD_TAG_LEN;
  return WT_OK;
}

wt_status_t wt_quic_unprotect_frames(const wt_quic_packet_keys_t *keys,
                                     uint64_t packet_number, const uint8_t *aad,
                                     size_t aad_len, uint8_t *packet,
                                     size_t len,
                                     const uint8_t tag[WT_AEAD_TAG_LEN]) {
  uint8_t nonce[WT_AEAD_IV_LEN];
  wt_status_t status;

  if (keys == NULL || tag == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (packet == NULL && len != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (aad == NULL && aad_len != 0U) return WT_ERR_INVALID_ARGUMENT;

  status = wt_quic_packet_nonce(keys->iv, packet_number, nonce);
  if (status != WT_OK) return status;
  /* Decrypting in place: `packet` is both the ciphertext and the destination.
   * The AEAD is a stream-like construction over counters, so OpenSSL's
   * EVP_CipherUpdate handles an overlapping in and out; a backend that could not
   * would have to be given a scratch buffer here, and that is a fact about the
   * backend rather than about QUIC.
   *
   * The peer's tag is verified inside the AEAD, in constant time. The plaintext
   * is cleared here as well as there, because this function's promise is that a
   * caller never holds bytes whose tag did not verify, and that promise should
   * not depend on the backend keeping the same one. */
  status = wt_aead_open(keys->aead, keys->key, nonce, aad, aad_len, packet, len,
                        tag, packet);
  wt_secure_zero(nonce, sizeof(nonce));
  if (status == WT_ERR_AUTHENTICATION) {
    if (len != 0U) wt_secure_zero(packet, len);
    /* Reported as the authentication failure it is, not as WT_ERR_PROTOCOL: status.h reserves that
     * name for bytes that violate the protocol, and a tag that does not verify is the ordinary
     * outcome of a lossy or hostile network -- the packet is well formed and simply was not produced
     * by the holder of the key. WHETHER TO DISCARD QUIETLY OR TO CLOSE THE CONNECTION IS THE CALLER'S
     * DECISION (RFC 9001 section 5.3 discards; a connection may also treat it as a violation), so this
     * layer reports the fact and does not make the policy call for it. */
    return WT_ERR_AUTHENTICATION;
  }
  return status;
}

/* RFC 9001 section 5.8's constants for version 1. They are protocol constants like the Initial salt,
 * written here rather than extracted because the RFC states them and nothing derives them. */
static const uint8_t WT_QUIC_RETRY_KEY[16] = {0xbeU, 0x0cU, 0x69U, 0x0bU, 0x9fU, 0x66U, 0x57U, 0x5aU,
                                              0x1dU, 0x76U, 0x6bU, 0x54U, 0xe3U, 0x68U, 0xc8U, 0x4eU};
static const uint8_t WT_QUIC_RETRY_NONCE[12] = {0x46U, 0x15U, 0x99U, 0xd3U, 0x5dU, 0x63U,
                                                 0x2bU, 0xf2U, 0x23U, 0x98U, 0x25U, 0xbbU};

/* The pseudo-packet: one length byte, the original destination connection ID, and the packet. Bounded by
 * the protocol's own connection ID bound plus a packet, so the buffer is a constant. */
#define WT_QUIC_RETRY_PSEUDO_MAX (1U + 20U + 1500U)

wt_status_t wt_quic_retry_integrity_tag(const uint8_t *original_destination_connection_id,
                                        size_t original_destination_connection_id_len,
                                        const uint8_t *retry_packet_without_tag, size_t length,
                                        uint8_t out[WT_AEAD_TAG_LEN]) {
  uint8_t pseudo[WT_QUIC_RETRY_PSEUDO_MAX];
  /* A zero-length message has no bytes to point at, but the AEAD wrapper refuses a NULL buffer in
   * either direction, so this is the one byte it may read (nothing) and write (nothing) through.
   * Initializing it is not cosmetic: gcc's -Wmaybe-uninitialized cannot prove that a zero-length
   * plaintext is never read, and it is right that a backend which did read the buffer would be
   * reading uninitialized memory. The release build on Linux fails on that warning. */
  uint8_t empty[1] = {0U};
  size_t total;
  wt_status_t status;

  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (original_destination_connection_id == NULL && original_destination_connection_id_len != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (retry_packet_without_tag == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (original_destination_connection_id_len > 20U) return WT_ERR_LIMIT;
  if (length > WT_QUIC_RETRY_PSEUDO_MAX - 1U - original_destination_connection_id_len) {
    return WT_ERR_LIMIT;
  }

  total = 1U + original_destination_connection_id_len + length;
  pseudo[0] = (uint8_t)original_destination_connection_id_len;
  /* A Retry with no ODCID or no payload is legal at this layer, so the copies are
   * guarded: that is what keeps a NULL with a zero length away from `memcpy`'s
   * nonnull parameters. */
  if (original_destination_connection_id_len != 0U) {
    memcpy(pseudo + 1U, original_destination_connection_id, original_destination_connection_id_len);
  }
  if (length != 0U) {
    memcpy(pseudo + 1U + original_destination_connection_id_len, retry_packet_without_tag, length);
  }

  status = wt_aead_seal(WT_AEAD_AES_128_GCM, WT_QUIC_RETRY_KEY, WT_QUIC_RETRY_NONCE, pseudo, total,
                        empty, 0U, empty, out);
  wt_secure_zero(pseudo, sizeof(pseudo));
  return status;
}

wt_status_t wt_quic_retry_integrity_verify(const uint8_t *original_destination_connection_id,
                                           size_t original_destination_connection_id_len,
                                           const uint8_t *retry_packet, size_t length) {
  uint8_t expected[WT_AEAD_TAG_LEN];
  uint8_t difference = 0U;
  size_t i;
  wt_status_t status;

  if (retry_packet == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (length < WT_AEAD_TAG_LEN) return WT_ERR_TRUNCATED;
  status = wt_quic_retry_integrity_tag(original_destination_connection_id,
                                       original_destination_connection_id_len, retry_packet,
                                       length - WT_AEAD_TAG_LEN, expected);
  if (status != WT_OK) return status;
  for (i = 0U; i < WT_AEAD_TAG_LEN; i++) {
    difference |= (uint8_t)(expected[i] ^ retry_packet[length - WT_AEAD_TAG_LEN + i]);
  }
  wt_secure_zero(expected, sizeof(expected));
  return difference == 0U ? WT_OK : WT_ERR_AUTHENTICATION;
}
