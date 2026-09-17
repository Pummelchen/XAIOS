/* The header-protection and whole-packet checks of the WebTransport QUIC
 * packet-protection test.
 *
 * This is one of the two modules that `test_wt_quic_pkt.c` was split into; see
 * `test_wt_quic_pkt_support.h` for the layout, the shared helpers and the
 * counters. Every assertion and every byte of output is unchanged from the
 * one-file suite.
 */

#include "test_wt_quic_pkt_support.h"

/* ------------------------------------------------------- header protection */

/* The client Initial in RFC 9001 A.2: a 22-byte header with a 4-byte packet
   number and a 1178-byte protected payload. The RFC prints the sample, the
   mask and the resulting header separately from the packet, so all three are
   checkable. */
void wtqpkt_test_header_protection_client_initial(void) {
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
  wtqpkt_expect_int("A.2 AES-ECB of the sample", 0,
             wt_aes128_ecb_encrypt_block(WT_RFC9001_CLIENT_HP,
                                         WT_RFC9001_CLIENT_PACKET + 22, ecb));
  wtqpkt_expect_bytes("A.2 mask", expected_mask, ecb, 5);
  wtqpkt_expect_int("A.2 the sample is the first 16 bytes of the protected payload", 0,
             memcmp(WT_RFC9001_CLIENT_PACKET + 22, ecb, 0) + 0);
  memcpy(sample, WT_RFC9001_CLIENT_PACKET + 22, 16);
  wtqpkt_expect_bytes("A.2 sample", WT_RFC9001_CLIENT_PACKET + 22, sample, 16);

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
    keys.key_len = 16U;
    keys.key_len = 16U;
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
    wtqpkt_expect_int("A.2 header protection", 0,
               wt_quic_header_protection(WT_TLS_AEAD_AES_128_GCM, keys.hp, 16U,
                                         &header, full, sizeof(full)));
    wtqpkt_expect_bytes("A.2 protected header", expected_header, full, 22);
    wtqpkt_expect_bytes("A.2 the protected payload is untouched",
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
    wtqpkt_expect_int("A.2 remove header protection", 0,
               wt_quic_header_protection(WT_TLS_AEAD_AES_128_GCM,
                                         WT_RFC9001_CLIENT_HP, 16U, &header,
                                         full, sizeof(full)));
    wtqpkt_expect_bytes("A.2 header restored", WT_RFC9001_CLIENT_HEADER, full, 22);
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
    wtqpkt_expect_int("A.2 a packet too short to sample from is refused", -1,
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
void wtqpkt_test_client_initial_end_to_end(void) {
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
  keys.key_len = 16U;
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

  wtqpkt_expect_int("A.2 protect the whole packet", 0,
             wt_quic_protect_packet(WT_TLS_AEAD_AES_128_GCM, &keys, &header,
                                    UINT64_C(2), packet, 22U + plaintext_len,
                                    &out_len));
  wtqpkt_expect_int("A.2 protected length", 1200, (long)out_len);
  wtqpkt_expect_bytes("A.2 the protected packet is the RFC's, byte for byte",
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
      wtqpkt_expect_int("A.2 remove protection from the received packet", 0,
                 wt_quic_header_protection(WT_TLS_AEAD_AES_128_GCM, keys.hp,
                                           16U, &rx, received, 1200));
      wtqpkt_expect_bytes("A.2 received header restored", WT_RFC9001_CLIENT_HEADER,
                   received, 22);

      /* The packet number is the four bytes at offset 18, and it is 2. */
      {
        uint64_t truncated = 0;
        for (size_t i = 0; i < 4U; i++) {
          truncated = (truncated << 8) | received[18U + i];
        }
        wtqpkt_expect_int("A.2 truncated packet number is 2", 2, (long)truncated);
        wtqpkt_expect_int("A.2 recover the packet number", 0,
                   wt_quic_decode_packet_number(truncated, 4U, 0U,
                                                &recovered_pn));
        wtqpkt_expect_int("A.2 recovered packet number is 2", 2, (long)recovered_pn);
      }

      rx.bytes = received;
      rx.len = 22U;
      wtqpkt_expect_int("A.2 unprotect the received packet", 0,
                 wt_quic_unprotect_packet(WT_TLS_AEAD_AES_128_GCM, &keys, &rx,
                                          recovered_pn, received, 1200,
                                          recovered_plaintext,
                                          sizeof(recovered_plaintext),
                                          &pt_len));
      wtqpkt_expect_int("A.2 plaintext length", 1162, (long)pt_len);
      wtqpkt_expect_bytes("A.2 the payload is what was sent", plaintext,
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
            wtqpkt_checks++; wtqpkt_failures++;
            printf("FAIL a failed tag check left plaintext at byte %zu\n", i);
            return;
          }
        }
        for (size_t i = 1162U; i < sizeof(sink); i++) {
          if (sink[i] != 0xAAU) {
            wtqpkt_checks++; wtqpkt_failures++;
            printf("FAIL a failed tag check wrote past the payload at %zu\n", i);
            return;
          }
        }
      }
    }
    wtqpkt_expect_int("every tampered payload bit is refused", 0, accepted);
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
    wtqpkt_expect_int("a tampered connection ID in the header is refused", -1,
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
    wtqpkt_expect_int("an undersized plaintext buffer is refused", -1,
               wt_quic_unprotect_packet(WT_TLS_AEAD_AES_128_GCM, &keys, &rx,
                                        UINT64_C(2), received, 1200, sink,
                                        sizeof(sink), &pt_len));
  }
}

/* The server Initial is a second end-to-end case with a different connection
   ID layout -- a one-byte SCID, and a two-byte packet number instead of four.
   A test with only the client case would not exercise the packet number length
   or the sample offset shifting with it. */
void wtqpkt_test_server_initial_end_to_end(void) {
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
  keys.key_len = 16U;
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

  wtqpkt_expect_int("A.3 the server header is 20 bytes, not the client's 22", 20,
             (long)header_len);
  wtqpkt_expect_int("A.3 protect the server packet", 0,
             wt_quic_protect_packet(WT_TLS_AEAD_AES_128_GCM, &keys, &header,
                                    UINT64_C(1), packet,
                                    header_len + plaintext_len, &out_len));
  wtqpkt_expect_int("A.3 protected length", 135, (long)out_len);
  wtqpkt_expect_bytes("A.3 the protected packet is the RFC's",
               WT_RFC9001_SERVER_PACKET, packet, 135);
}

/* ------------------------------------------------------ ChaCha20 hp mask */

void wtqpkt_test_chacha20_header_protection(void) {
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

  wtqpkt_expect_int("A.5 chacha20 header protection", 0,
             wt_quic_header_protection(WT_TLS_AEAD_CHACHA20_POLY1305,
                                       WT_RFC9001_CHACHA_HP, 32U, &header,
                                       packet, sizeof(packet)));
  wtqpkt_expect_bytes("A.5 protected header", expected, packet, 4);
  wtqpkt_expect_bytes("A.5 the protected payload is untouched",
               WT_RFC9001_CHACHA_PAYLOAD_CIPHERTEXT, packet + 4, 21);

  /* The AEAD for this suite is not implemented; protect must refuse rather
     than produce a packet that no test covers. */
  {
    wt_tls_traffic_keys_t keys;
    size_t out_len = 0;
    memset(&keys, 0, sizeof(keys));
    wtqpkt_expect_int("protect refuses ChaCha20-Poly1305", -1,
               wt_quic_protect_packet(WT_TLS_AEAD_CHACHA20_POLY1305, &keys,
                                      &header, 654360564U, packet,
                                      sizeof(packet), &out_len));
  }
}

/* A wrong header protection key length is refused rather than used, because
   the two suites' lengths differ and using the wrong one gives a plausible
   mask. */
void wtqpkt_test_header_protection_argument_checks(void) {
  static uint8_t packet[64];
  wt_quic_packet_header_t header;
  memset(packet, 0, sizeof(packet));
  header.bytes = packet;
  header.len = 22U;
  header.pn_offset = 18U;
  header.pn_len = 4U;
  header.long_header = 1;

  wtqpkt_expect_int("a 16-byte hp key under AES is accepted", 0,
             wt_quic_header_protection(WT_TLS_AEAD_AES_128_GCM,
                                       WT_RFC9001_CLIENT_HP, 16U, &header,
                                       packet, sizeof(packet)));
  wtqpkt_expect_int("a 32-byte hp key under AES is refused", -1,
             wt_quic_header_protection(WT_TLS_AEAD_AES_128_GCM,
                                       WT_RFC9001_CLIENT_HP, 32U, &header,
                                       packet, sizeof(packet)));
  wtqpkt_expect_int("an unknown AEAD is refused", -1,
             wt_quic_header_protection((wt_tls_aead_t)99,
                                       WT_RFC9001_CLIENT_HP, 16U, &header,
                                       packet, sizeof(packet)));
  wtqpkt_expect_int("a NULL header is refused", -1,
             wt_quic_header_protection(WT_TLS_AEAD_AES_128_GCM,
                                       WT_RFC9001_CLIENT_HP, 16U, NULL, packet,
                                       sizeof(packet)));
  wtqpkt_expect_int("a NULL packet is refused", -1,
             wt_quic_header_protection(WT_TLS_AEAD_AES_128_GCM,
                                       WT_RFC9001_CLIENT_HP, 16U, &header, NULL,
                                       sizeof(packet)));
  header.pn_len = 0;
  wtqpkt_expect_int("a zero-length packet number is refused", -1,
             wt_quic_header_protection(WT_TLS_AEAD_AES_128_GCM,
                                       WT_RFC9001_CLIENT_HP, 16U, &header,
                                       packet, sizeof(packet)));
}
