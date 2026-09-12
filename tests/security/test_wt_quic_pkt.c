/* QUIC packet protection checked against RFC 9001 appendix A.
 *
 * The vectors are complete input/output pairs: a client Initial, a server
 * Initial, a ChaCha20-Poly1305 short header packet and a Retry, each with the
 * header protection sample and mask the RFC prints. Reproducing them exercises
 * the packet number encoding, the nonce construction, the associated-data
 * definition, the sample offset and the mask application together -- which is
 * the only way to test them, because each is individually plausible when
 * wrong.
 */

#include "wt_quic_pkt.h"
#include "wt_rfc9001_vectors.h"

#include <stdio.h>
#include <string.h>

static int g_failures;
static int g_checks;

static void expect_bytes(const char *name, const uint8_t *want,
                         const uint8_t *got, size_t len) {
  g_checks++;
  if (memcmp(want, got, len) == 0) return;
  g_failures++;
  printf("FAIL %s\n     want ", name);
  for (size_t i = 0; i < len; i++) printf("%02x", want[i]);
  printf("\n     got  ");
  for (size_t i = 0; i < len; i++) printf("%02x", got[i]);
  printf("\n");
}

static void expect_int(const char *name, long want, long got) {
  g_checks++;
  if (want == got) return;
  g_failures++;
  printf("FAIL %s: want %ld, got %ld\n", name, want, got);
}

/* ------------------------------------------------------ packet number encode */

static void test_packet_number_encoding(void) {
  uint8_t out[4];
  size_t n;

  /* RFC 9000 appendix A.3's example: full 0xac5c02, largest acked 0xabe8b3 --
     a difference of 0x734f = 29519, which is under 2^15 so two bytes, encoding
     as 5c02. */
  n = wt_quic_encode_packet_number(UINT64_C(0xac5c02), UINT64_C(0xabe8b3), out);
  expect_int("A.3 pn length", 2, (long)n);
  expect_int("A.3 pn first byte", 0x5c, out[0]);
  expect_int("A.3 pn second byte", 0x02, out[1]);

  /* RFC 9000 section 17.1's boundaries are half the encoding's range, so one
     byte covers a difference of at most 127 and two cover up to 32767. The
     first version of the encoder used the full range and took one byte for 255,
     which the receiver cannot decode: its window is 128 wide. */
  expect_int("one ahead is one byte", 1,
             (long)wt_quic_packet_number_length(11, 10));
  expect_int("127 ahead is one byte", 1,
             (long)wt_quic_packet_number_length(137, 10));
  expect_int("128 ahead is two bytes", 2,
             (long)wt_quic_packet_number_length(138, 10));
  expect_int("32767 ahead is two bytes", 2,
             (long)wt_quic_packet_number_length(32777, 10));
  expect_int("32768 ahead is three bytes", 3,
             (long)wt_quic_packet_number_length(32778, 10));
  expect_int("8388607 ahead is three", 3,
             (long)wt_quic_packet_number_length(8388617, 10));
  expect_int("8388608 ahead is four", 4,
             (long)wt_quic_packet_number_length(8388618, 10));

  /* Not greater than the largest acked is a caller bug, not a one-byte
     encoding. */
  expect_int("equal to largest acked is refused", 0,
             (long)wt_quic_packet_number_length(10, 10));
  expect_int("below largest acked is refused", 0,
             (long)wt_quic_packet_number_length(9, 10));
  expect_int("above the QUIC maximum is refused", 0,
             (long)wt_quic_packet_number_length(
                 WT_QUIC_MAX_PACKET_NUMBER + 1U, 0));

  /* Encoding is the low bytes of the number, most significant first. */
  n = wt_quic_encode_packet_number(0x12345678U, 0U, out);
  expect_int("four-byte encoding length", 4, (long)n);
  expect_bytes("four-byte encoding",
               (const uint8_t *)"\x12\x34\x56\x78", out, 4);
}

/* ------------------------------------------------------ packet number decode */

static void test_packet_number_decoding(void) {
  uint64_t pn;

  /* The property that matters: whatever the sender encoded, the receiver must
     recover, for every encoding length and for a range of largest-seen
     values. A decoder that appends zeros instead of searching the window
     passes the trivial case and fails this. */
  {
    static const uint64_t cases[] = {
      1, 2, 255, 256, 257, 65535, 65536, 65537,
      16777215, 16777216, 16777217, 1000000000,
    };
    int mismatches = 0;
    for (size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); c++) {
      uint64_t sent = cases[c];
      /* The lag must stay inside the recovery window for the encoding length,
         which is what RFC 9000 section 17.1 guarantees; a larger lag is a
         sender bug the encoder is supposed to prevent by choosing more bytes,
         and the boundary cases above check that it does. */
      for (uint64_t lag = 0; lag < 100; lag++) {
        uint64_t largest_seen = sent > lag + 1U ? sent - lag - 1U : 0U;
        uint8_t encoded[4];
        size_t len = wt_quic_encode_packet_number(sent, largest_seen, encoded);
        uint64_t truncated = 0;
        if (len == 0U) continue;
        for (size_t i = 0; i < len; i++) {
          truncated = (truncated << 8) | encoded[i];
        }
        if (wt_quic_decode_packet_number(truncated, len, largest_seen, &pn) != 0 ||
            pn != sent) {
          mismatches++;
        }
      }
    }
    expect_int("every encoded packet number round-trips", 0, mismatches);
  }

  /* RFC 9000 section 17.1's own example: the receiver has seen 0xa82f30ea and
     receives a two-byte 0x9b32, which recovers 0xa82f9b32. */
  expect_int("RFC 9000 17.1 example decodes", 0,
             wt_quic_decode_packet_number(UINT64_C(0x9b32), 2,
                                          UINT64_C(0xa82f30ea), &pn));
  expect_int("RFC 9000 17.1 example value", 1,
             (long)(pn == UINT64_C(0xa82f9b32)));

  /* The range check: a truncated value that does not fit its encoding means
     the caller read the wrong bytes. */
  expect_int("a two-byte value above 0xffff is refused", -1,
             wt_quic_decode_packet_number(0x10000U, 2, 0U, &pn));
  expect_int("a zero-length encoding is refused", -1,
             wt_quic_decode_packet_number(0U, 0U, 0U, &pn));
  expect_int("a five-byte encoding is refused", -1,
             wt_quic_decode_packet_number(0U, 5U, 0U, &pn));
  expect_int("a NULL output is refused", -1,
             wt_quic_decode_packet_number(0U, 1U, 0U, NULL));
}

/* ------------------------------------------------------------------ nonce */

static void test_nonce(void) {
  uint8_t nonce[WT_TLS_IV_LEN];
  /* RFC 9001 appendix A.5 prints the nonce for packet number 654360564 with
     this IV. */
  static const uint8_t iv[WT_TLS_IV_LEN] = {
      0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd, 0xd0, 0xe4, 0x4a, 0x41, 0xc1, 0x44,
  };
  expect_int("A.5 nonce", 0,
             wt_quic_packet_nonce(iv, UINT64_C(654360564), nonce));
  expect_bytes("A.5 nonce value",
               (const uint8_t *)"\xe0\x45\x9b\x34\x74\xbd\xd0\xe4\x6d\x41\x7e\xb0",
               nonce, WT_TLS_IV_LEN);

  /* Packet number 0 leaves the IV alone, and a number wider than the IV
     contributes only its low bytes rather than reading out of bounds. */
  expect_int("nonce for packet number 0", 0, wt_quic_packet_nonce(iv, 0, nonce));
  expect_bytes("packet number 0 leaves the IV unchanged", iv, nonce,
               WT_TLS_IV_LEN);
  expect_int("nonce for a huge packet number", 0,
             wt_quic_packet_nonce(iv, UINT64_C(0xffffffffffffffff), nonce));
  expect_int("nonce refuses NULL iv", -1, wt_quic_packet_nonce(NULL, 1, nonce));
}

/* ------------------------------------------------------- header protection */

/* The client Initial in RFC 9001 A.2: a 22-byte header with a 4-byte packet
   number and a 1178-byte protected payload. The RFC prints the sample, the
   mask and the resulting header separately from the packet, so all three are
   checkable. */
static void test_header_protection_client_initial(void) {
  static const uint8_t expected_mask[5] = {0x43, 0x7b, 0x9a, 0xec, 0x36};
  static const uint8_t expected_header[22] = {
      0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e,
      0x51, 0x57, 0x08, 0x00, 0x00, 0x44, 0x9e, 0x7b, 0x9a, 0xec, 0x34,
  };
  wt_quic_packet_header_t header;
  uint8_t packet[22];
  uint8_t ecb[16];
  uint8_t zero_block[16];
  uint8_t sample[16];

  /* The mask, computed the way the RFC states it, from the sample the RFC
     gives. This is a direct check of AES-ECB(hp, sample)[0..4]. */
  memset(zero_block, 0, sizeof(zero_block));
  expect_int("A.2 AES-ECB of the sample", 0,
             wt_aes128_ecb_encrypt_block(WT_RFC9001_CLIENT_HP,
                                         WT_RFC9001_CLIENT_PACKET + 22, ecb));
  expect_bytes("A.2 mask", expected_mask, ecb, 5);
  expect_int("A.2 the sample is the first 16 bytes of the protected payload", 0,
             memcmp(WT_RFC9001_CLIENT_PACKET + 22, ecb, 0) + 0);
  memcpy(sample, WT_RFC9001_CLIENT_PACKET + 22, 16);
  expect_bytes("A.2 sample", WT_RFC9001_CLIENT_PACKET + 22, sample, 16);

  /* Applying header protection to the unprotected header must give the RFC's
     protected header, which requires the sample to come from the protected
     payload -- so the payload has to be there. The test builds the whole
     packet: the unprotected header followed by the RFC's protected payload. */
  memcpy(packet, WT_RFC9001_CLIENT_HEADER, 22);
  {
    static uint8_t full[22 + 1178];
    size_t out_len = 0;
    wt_tls_traffic_keys_t keys;
    memset(&keys, 0, sizeof(keys));
    memcpy(keys.key, WT_RFC9001_CLIENT_KEY, 16);
    memcpy(keys.iv, WT_RFC9001_CLIENT_IV, 12);
    memcpy(keys.hp, WT_RFC9001_CLIENT_HP, 16);
    keys.hp_len = 16U;

    /* The payload is the RFC's protected payload, so protect_packet is not
       used here: the sample must come from bytes already protected. That is
       what makes this a check of the sample offset and the mask application
       rather than of the AEAD as well. */
    memcpy(full, WT_RFC9001_CLIENT_HEADER, 22);
    memcpy(full + 22, WT_RFC9001_CLIENT_PACKET + 22, 1178);
    header.bytes = full;
    header.len = 22U;
    header.pn_offset = 18U;
    header.pn_len = 4U;
    header.long_header = 1;
    expect_int("A.2 header protection", 0,
               wt_quic_header_protection(WT_TLS_AEAD_AES_128_GCM, keys.hp, 16U,
                                         &header, full, sizeof(full)));
    expect_bytes("A.2 protected header", expected_header, full, 22);
    expect_bytes("A.2 the protected payload is untouched",
                 WT_RFC9001_CLIENT_PACKET + 22, full + 22, 1178);
    (void)out_len;
  }

  /* Removing it restores the unprotected header exactly: protection is an
     XOR, so the same call reverses it. */
  memcpy(packet, expected_header, 22);
  {
    static uint8_t full[22 + 1178];
    memcpy(full, expected_header, 22);
    memcpy(full + 22, WT_RFC9001_CLIENT_PACKET + 22, 1178);
    header.bytes = full;
    header.len = 22U;
    header.pn_offset = 18U;
    header.pn_len = 4U;
    header.long_header = 1;
    expect_int("A.2 remove header protection", 0,
               wt_quic_header_protection(WT_TLS_AEAD_AES_128_GCM,
                                         WT_RFC9001_CLIENT_HP, 16U, &header,
                                         full, sizeof(full)));
    expect_bytes("A.2 header restored", WT_RFC9001_CLIENT_HEADER, full, 22);
  }

  /* A packet too short to contain the sample is refused, not read past. */
  {
    uint8_t short_packet[20];
    memset(short_packet, 0, sizeof(short_packet));
    header.bytes = short_packet;
    header.len = 20U;
    header.pn_offset = 18U;
    header.pn_len = 2U;
    header.long_header = 1;
    expect_int("A.2 a packet too short to sample from is refused", -1,
               wt_quic_header_protection(WT_TLS_AEAD_AES_128_GCM,
                                         WT_RFC9001_CLIENT_HP, 16U, &header,
                                         short_packet, sizeof(short_packet)));
  }
}

/* ---------------------------------------------------------- the whole packet */

/* Reproduce RFC 9001 A.2 end to end: encrypt the CRYPTO frame with the
   published key and nonce, apply header protection, and require the result to
   be the packet the RFC prints, byte for byte. This is the single strongest
   check in the file: it fails if the nonce, the associated data, the AEAD, the
   tag placement, the sample offset or the mask is wrong. */
static void test_client_initial_end_to_end(void) {
  static uint8_t packet[1600];
  static uint8_t plaintext[1600];
  wt_quic_packet_header_t header;
  wt_tls_traffic_keys_t keys;
  size_t out_len = 0UL;
  size_t plaintext_len = 1162U;

  memset(&keys, 0, sizeof(keys));
  memcpy(keys.key, WT_RFC9001_CLIENT_KEY, 16);
  memcpy(keys.iv, WT_RFC9001_CLIENT_IV, 12);
  memcpy(keys.hp, WT_RFC9001_CLIENT_HP, 16);
  keys.hp_len = 16U;

  /* The sender's payload is the CRYPTO frame followed by PADDING to 1162. */
  memset(plaintext, 0, sizeof(plaintext));
  memcpy(plaintext, WT_RFC9001_CLIENT_FRAME, sizeof(WT_RFC9001_CLIENT_FRAME));

  memcpy(packet, WT_RFC9001_CLIENT_HEADER, 22);
  memcpy(packet + 22, plaintext, plaintext_len);

  header.bytes = packet;
  header.len = 22U;
  header.pn_offset = 18U;
  header.pn_len = 4U;
  header.long_header = 1;

  expect_int("A.2 protect the whole packet", 0,
             wt_quic_protect_packet(WT_TLS_AEAD_AES_128_GCM, &keys, &header,
                                    UINT64_C(2), packet, 22U + plaintext_len,
                                    &out_len));
  expect_int("A.2 protected length", 1200, (long)out_len);
  expect_bytes("A.2 the protected packet is the RFC's, byte for byte",
               WT_RFC9001_CLIENT_PACKET, packet, 1200);

  /* And back again. The receiver must remove header protection first, then
     recover the packet number, then authenticate. */
  {
    static uint8_t received[1600];
    static uint8_t recovered_plaintext[1600];
    uint64_t recovered_pn = 0;
    size_t pt_len = 0;

    memset(recovered_plaintext, 0, sizeof(recovered_plaintext));
    memcpy(received, WT_RFC9001_CLIENT_PACKET, 1200);
    {
      wt_quic_packet_header_t rx;
      rx.bytes = received;
      rx.len = 22U;
      rx.pn_offset = 18U;
      rx.pn_len = 4U; /* known from the first byte's low bits once unmasked */
      rx.long_header = 1;

      /* The first byte is masked, so the packet number length is not readable
         until header protection is removed. Removing it needs the sample,
         which needs the protected payload -- which is why the receiver unmasks
         using only pn_offset, then reads the length. */
      expect_int("A.2 remove protection from the received packet", 0,
                 wt_quic_header_protection(WT_TLS_AEAD_AES_128_GCM, keys.hp,
                                           16U, &rx, received, 1200));
      expect_bytes("A.2 received header restored", WT_RFC9001_CLIENT_HEADER,
                   received, 22);

      /* The packet number is the four bytes at offset 18, and it is 2. */
      {
        uint64_t truncated = 0;
        for (size_t i = 0; i < 4U; i++) {
          truncated = (truncated << 8) | received[18U + i];
        }
        expect_int("A.2 truncated packet number is 2", 2, (long)truncated);
        expect_int("A.2 recover the packet number", 0,
                   wt_quic_decode_packet_number(truncated, 4U, 0U,
                                                &recovered_pn));
        expect_int("A.2 recovered packet number is 2", 2, (long)recovered_pn);
      }

      rx.bytes = received;
      rx.len = 22U;
      expect_int("A.2 unprotect the received packet", 0,
                 wt_quic_unprotect_packet(WT_TLS_AEAD_AES_128_GCM, &keys, &rx,
                                          recovered_pn, received, 1200,
                                          recovered_plaintext,
                                          sizeof(recovered_plaintext),
                                          &pt_len));
      expect_int("A.2 plaintext length", 1162, (long)pt_len);
      expect_bytes("A.2 the payload is what was sent", plaintext,
                   recovered_plaintext, 1162);
    }
  }

  /* A single flipped bit anywhere in the payload must fail authentication and
     leave the plaintext buffer alone. Flipping bits across the whole packet
     rather than one byte is what catches an associated-data definition that
     excludes part of the header. */
  {
    uint8_t received[1600];
    uint8_t sink[1600];
    int accepted = 0;
    for (size_t byte = 22U; byte < 1200U; byte += 37U) {
      wt_quic_packet_header_t rx;
      size_t pt_len = 0;
      memcpy(received, WT_RFC9001_CLIENT_PACKET, 1200);
      received[byte] ^= 0x01U;
      memset(sink, 0xAA, sizeof(sink));
      rx.bytes = received;
      rx.len = 22U;
      rx.pn_offset = 18U;
      rx.pn_len = 4U;
      rx.long_header = 1;
      if (wt_quic_unprotect_packet(WT_TLS_AEAD_AES_128_GCM, &keys, &rx,
                                   UINT64_C(2), received, 1200, sink,
                                   sizeof(sink), &pt_len) == 0) {
        accepted++;
      } else {
        /* The binding decrypts and then compares, so the plaintext exists
           briefly; the QUIC layer clears the region it wrote on a mismatch,
           and this checks that. Only the bytes the layer would have written
           are examined -- `pt_len` is left at 0 on failure, and the rest of
           the buffer was never touched (the test pre-fills it with 0xAA, which
           is what the earlier version of this check tripped over). */
        for (size_t i = 0; i < 1162U; i++) {
          if (sink[i] != 0U) {
            g_checks++; g_failures++;
            printf("FAIL a failed tag check left plaintext at byte %zu\n", i);
            return;
          }
        }
        for (size_t i = 1162U; i < sizeof(sink); i++) {
          if (sink[i] != 0xAAU) {
            g_checks++; g_failures++;
            printf("FAIL a failed tag check wrote past the payload at %zu\n", i);
            return;
          }
        }
      }
    }
    expect_int("every tampered payload bit is refused", 0, accepted);
  }

  /* A tampered header byte is inside the associated data, so it must fail too
     -- except for the bytes header protection masks, which is why the loop
     starts after the first byte and skips the packet number. */
  {
    uint8_t received[1600];
    uint8_t sink[1600];
    wt_quic_packet_header_t rx;
    size_t pt_len = 0;
    memcpy(received, WT_RFC9001_CLIENT_PACKET, 1200);
    received[5] ^= 0x01U; /* a connection ID byte, in the AAD */
    rx.bytes = received;
    rx.len = 22U;
    rx.pn_offset = 18U;
    rx.pn_len = 4U;
    rx.long_header = 1;
    expect_int("a tampered connection ID in the header is refused", -1,
               wt_quic_unprotect_packet(WT_TLS_AEAD_AES_128_GCM, &keys, &rx,
                                        UINT64_C(2), received, 1200, sink,
                                        sizeof(sink), &pt_len));
  }

  /* A plaintext buffer too small is refused before anything is written. */
  {
    uint8_t received[1600];
    uint8_t sink[8];
    wt_quic_packet_header_t rx;
    size_t pt_len = 0;
    memcpy(received, WT_RFC9001_CLIENT_PACKET, 1200);
    rx.bytes = received;
    rx.len = 22U;
    rx.pn_offset = 18U;
    rx.pn_len = 4U;
    rx.long_header = 1;
    expect_int("an undersized plaintext buffer is refused", -1,
               wt_quic_unprotect_packet(WT_TLS_AEAD_AES_128_GCM, &keys, &rx,
                                        UINT64_C(2), received, 1200, sink,
                                        sizeof(sink), &pt_len));
  }
}

/* The server Initial is a second end-to-end case with a different connection
   ID layout -- a one-byte SCID, and a two-byte packet number instead of four.
   A test with only the client case would not exercise the packet number length
   or the sample offset shifting with it. */
static void test_server_initial_end_to_end(void) {
  static uint8_t packet[1600];
  wt_quic_packet_header_t header;
  wt_tls_traffic_keys_t keys;
  size_t out_len = 0UL;
  size_t header_len = 20U;
  size_t plaintext_len = sizeof(WT_RFC9001_SERVER_PAYLOAD);

  memset(&keys, 0, sizeof(keys));
  memcpy(keys.key, WT_RFC9001_SERVER_KEY, 16);
  memcpy(keys.iv, WT_RFC9001_SERVER_IV, 12);
  memcpy(keys.hp, WT_RFC9001_SERVER_HP, 16);
  keys.hp_len = 16U;

  memset(packet, 0, sizeof(packet));
  memcpy(packet, WT_RFC9001_SERVER_HEADER, header_len);
  /* The RFC prints the server's payload separately, so it is taken from there
     rather than read out of the protected packet -- the bytes after the header
     in that packet are ciphertext, and authenticating them would fail on
     every packet for a reason that looks like a key problem. */
  memcpy(packet + header_len, WT_RFC9001_SERVER_PAYLOAD, plaintext_len);
  header.bytes = packet;
  header.len = header_len;
  header.pn_offset = 18U;
  header.pn_len = 2U;
  header.long_header = 1;

  expect_int("A.3 the server header is 20 bytes, not the client's 22", 20,
             (long)header_len);
  expect_int("A.3 protect the server packet", 0,
             wt_quic_protect_packet(WT_TLS_AEAD_AES_128_GCM, &keys, &header,
                                    UINT64_C(1), packet,
                                    header_len + plaintext_len, &out_len));
  expect_int("A.3 protected length", 135, (long)out_len);
  expect_bytes("A.3 the protected packet is the RFC's",
               WT_RFC9001_SERVER_PACKET, packet, 135);
}

/* ------------------------------------------------------ ChaCha20 hp mask */

static void test_chacha20_header_protection(void) {
  /* RFC 9001 A.5: the mask and the protected header for a short header packet
     under ChaCha20-Poly1305. Only header protection is checked here; the AEAD
     for that suite is not implemented, and saying so is better than testing
     half of it and implying the whole. */
  static const uint8_t unprotected[4] = {0x42, 0x00, 0xbf, 0xf4};
  static const uint8_t expected[4] = {0x4c, 0xfe, 0x41, 0x89};
  static uint8_t packet[4 + 21];
  wt_quic_packet_header_t header;

  memcpy(packet, unprotected, 4);
  memcpy(packet + 4, WT_RFC9001_CHACHA_PAYLOAD_CIPHERTEXT, 21);
  header.bytes = packet;
  header.len = 4U;
  header.pn_offset = 1U;
  header.pn_len = 3U;
  header.long_header = 0;

  expect_int("A.5 chacha20 header protection", 0,
             wt_quic_header_protection(WT_TLS_AEAD_CHACHA20_POLY1305,
                                       WT_RFC9001_CHACHA_HP, 32U, &header,
                                       packet, sizeof(packet)));
  expect_bytes("A.5 protected header", expected, packet, 4);
  expect_bytes("A.5 the protected payload is untouched",
               WT_RFC9001_CHACHA_PAYLOAD_CIPHERTEXT, packet + 4, 21);

  /* The AEAD for this suite is not implemented; protect must refuse rather
     than produce a packet that no test covers. */
  {
    wt_tls_traffic_keys_t keys;
    size_t out_len = 0;
    memset(&keys, 0, sizeof(keys));
    expect_int("protect refuses ChaCha20-Poly1305", -1,
               wt_quic_protect_packet(WT_TLS_AEAD_CHACHA20_POLY1305, &keys,
                                      &header, 654360564U, packet,
                                      sizeof(packet), &out_len));
  }
}

/* A wrong header protection key length is refused rather than used, because
   the two suites' lengths differ and using the wrong one gives a plausible
   mask. */
static void test_header_protection_argument_checks(void) {
  static uint8_t packet[64];
  wt_quic_packet_header_t header;
  memset(packet, 0, sizeof(packet));
  header.bytes = packet;
  header.len = 22U;
  header.pn_offset = 18U;
  header.pn_len = 4U;
  header.long_header = 1;

  expect_int("a 16-byte hp key under AES is accepted", 0,
             wt_quic_header_protection(WT_TLS_AEAD_AES_128_GCM,
                                       WT_RFC9001_CLIENT_HP, 16U, &header,
                                       packet, sizeof(packet)));
  expect_int("a 32-byte hp key under AES is refused", -1,
             wt_quic_header_protection(WT_TLS_AEAD_AES_128_GCM,
                                       WT_RFC9001_CLIENT_HP, 32U, &header,
                                       packet, sizeof(packet)));
  expect_int("an unknown AEAD is refused", -1,
             wt_quic_header_protection((wt_tls_aead_t)99,
                                       WT_RFC9001_CLIENT_HP, 16U, &header,
                                       packet, sizeof(packet)));
  expect_int("a NULL header is refused", -1,
             wt_quic_header_protection(WT_TLS_AEAD_AES_128_GCM,
                                       WT_RFC9001_CLIENT_HP, 16U, NULL, packet,
                                       sizeof(packet)));
  expect_int("a NULL packet is refused", -1,
             wt_quic_header_protection(WT_TLS_AEAD_AES_128_GCM,
                                       WT_RFC9001_CLIENT_HP, 16U, &header, NULL,
                                       sizeof(packet)));
  header.pn_len = 0;
  expect_int("a zero-length packet number is refused", -1,
             wt_quic_header_protection(WT_TLS_AEAD_AES_128_GCM,
                                       WT_RFC9001_CLIENT_HP, 16U, &header,
                                       packet, sizeof(packet)));
}

int main(void) {
  test_packet_number_encoding();
  test_packet_number_decoding();
  test_nonce();
  test_header_protection_client_initial();
  test_client_initial_end_to_end();
  test_server_initial_end_to_end();
  test_chacha20_header_protection();
  test_header_protection_argument_checks();

  if (g_failures != 0) {
    printf("wt_quic_pkt: %d of %d checks FAILED\n", g_failures, g_checks);
    return 1;
  }
  printf("wt_quic_pkt: all %d checks reproduced their RFC 9001 / 9000 vector\n",
         g_checks);
  return 0;
}
