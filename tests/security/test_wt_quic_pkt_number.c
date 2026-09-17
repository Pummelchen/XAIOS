/* The RFC 9000 packet-number and RFC 9001 A.5 nonce checks of the WebTransport
 * QUIC packet-protection test.
 *
 * This is one of the two modules that `test_wt_quic_pkt.c` was split into; see
 * `test_wt_quic_pkt_support.h` for the layout, the shared helpers and the
 * counters. Every assertion and every byte of output is unchanged from the
 * one-file suite.
 */

#include "test_wt_quic_pkt_support.h"

/* The two counters shared with the driver and the protect module. This module
 * owns them. */
int wtqpkt_failures;
int wtqpkt_checks;

/* ------------------------------------------------------ packet number encode */

void wtqpkt_test_packet_number_encoding(void) {
  uint8_t out[4];
  size_t n;

  /* RFC 9000 appendix A.3's example: full 0xac5c02, largest acked 0xabe8b3 --
     a difference of 0x734f = 29519, which is under 2^15 so two bytes, encoding
     as 5c02. */
  n = wt_quic_encode_packet_number(UINT64_C(0xac5c02), UINT64_C(0xabe8b3), out);
  wtqpkt_expect_int("A.3 pn length", 2, (long)n);
  wtqpkt_expect_int("A.3 pn first byte", 0x5c, out[0]);
  wtqpkt_expect_int("A.3 pn second byte", 0x02, out[1]);

  /* RFC 9000 section 17.1's boundaries are half the encoding's range, so one
     byte covers a difference of at most 127 and two cover up to 32767. The
     first version of the encoder used the full range and took one byte for 255,
     which the receiver cannot decode: its window is 128 wide. */
  wtqpkt_expect_int("one ahead is one byte", 1,
             (long)wt_quic_packet_number_length(11, 10));
  wtqpkt_expect_int("127 ahead is one byte", 1,
             (long)wt_quic_packet_number_length(137, 10));
  wtqpkt_expect_int("128 ahead is two bytes", 2,
             (long)wt_quic_packet_number_length(138, 10));
  wtqpkt_expect_int("32767 ahead is two bytes", 2,
             (long)wt_quic_packet_number_length(32777, 10));
  wtqpkt_expect_int("32768 ahead is three bytes", 3,
             (long)wt_quic_packet_number_length(32778, 10));
  wtqpkt_expect_int("8388607 ahead is three", 3,
             (long)wt_quic_packet_number_length(8388617, 10));
  wtqpkt_expect_int("8388608 ahead is four", 4,
             (long)wt_quic_packet_number_length(8388618, 10));

  /* Not greater than the largest acked is a caller bug, not a one-byte
     encoding. */
  wtqpkt_expect_int("equal to largest acked is refused", 0,
             (long)wt_quic_packet_number_length(10, 10));
  wtqpkt_expect_int("below largest acked is refused", 0,
             (long)wt_quic_packet_number_length(9, 10));
  wtqpkt_expect_int("above the QUIC maximum is refused", 0,
             (long)wt_quic_packet_number_length(
                 WT_QUIC_MAX_PACKET_NUMBER + 1U, 0));

  /* Encoding is the low bytes of the number, most significant first. */
  n = wt_quic_encode_packet_number(0x12345678U, 0U, out);
  wtqpkt_expect_int("four-byte encoding length", 4, (long)n);
  wtqpkt_expect_bytes("four-byte encoding",
               (const uint8_t *)"\x12\x34\x56\x78", out, 4);
}

/* ------------------------------------------------------ packet number decode */

void wtqpkt_test_packet_number_decoding(void) {
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
    wtqpkt_expect_int("every encoded packet number round-trips", 0, mismatches);
  }

  /* RFC 9000 section 17.1's own example: the receiver has seen 0xa82f30ea and
     receives a two-byte 0x9b32, which recovers 0xa82f9b32. */
  wtqpkt_expect_int("RFC 9000 17.1 example decodes", 0,
             wt_quic_decode_packet_number(UINT64_C(0x9b32), 2,
                                          UINT64_C(0xa82f30ea), &pn));
  wtqpkt_expect_int("RFC 9000 17.1 example value", 1,
             (long)(pn == UINT64_C(0xa82f9b32)));

  /* The range check: a truncated value that does not fit its encoding means
     the caller read the wrong bytes. */
  wtqpkt_expect_int("a two-byte value above 0xffff is refused", -1,
             wt_quic_decode_packet_number(0x10000U, 2, 0U, &pn));
  wtqpkt_expect_int("a zero-length encoding is refused", -1,
             wt_quic_decode_packet_number(0U, 0U, 0U, &pn));
  wtqpkt_expect_int("a five-byte encoding is refused", -1,
             wt_quic_decode_packet_number(0U, 5U, 0U, &pn));
  wtqpkt_expect_int("a NULL output is refused", -1,
             wt_quic_decode_packet_number(0U, 1U, 0U, NULL));
}

/* ------------------------------------------------------------------ nonce */

void wtqpkt_test_nonce(void) {
  uint8_t nonce[WT_TLS_IV_LEN];
  /* RFC 9001 appendix A.5 prints the nonce for packet number 654360564 with
     this IV. */
  static const uint8_t iv[WT_TLS_IV_LEN] = {
      0xe0, 0x45, 0x9b, 0x34, 0x74, 0xbd, 0xd0, 0xe4, 0x4a, 0x41, 0xc1, 0x44,
  };
  wtqpkt_expect_int("A.5 nonce", 0,
             wt_quic_packet_nonce(iv, UINT64_C(654360564), nonce));
  wtqpkt_expect_bytes("A.5 nonce value",
               (const uint8_t *)"\xe0\x45\x9b\x34\x74\xbd\xd0\xe4\x6d\x41\x7e\xb0",
               nonce, WT_TLS_IV_LEN);

  /* Packet number 0 leaves the IV alone, and a number wider than the IV
     contributes only its low bytes rather than reading out of bounds. */
  wtqpkt_expect_int("nonce for packet number 0", 0, wt_quic_packet_nonce(iv, 0, nonce));
  wtqpkt_expect_bytes("packet number 0 leaves the IV unchanged", iv, nonce,
               WT_TLS_IV_LEN);
  wtqpkt_expect_int("nonce for a huge packet number", 0,
             wt_quic_packet_nonce(iv, UINT64_C(0xffffffffffffffff), nonce));
  wtqpkt_expect_int("nonce refuses NULL iv", -1, wt_quic_packet_nonce(NULL, 1, nonce));
}
