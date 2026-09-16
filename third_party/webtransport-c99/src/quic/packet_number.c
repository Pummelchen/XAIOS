/* QUIC packet numbers. See webtransport/quic/packet_number.h. */

#include "webtransport/quic/packet_number.h"

#include "webtransport/endian.h"

uint64_t wt_quic_packet_number_window(size_t byte_count) {
  if (byte_count == 0U || byte_count > 4U) return 0U;
  return (uint64_t)1U << (byte_count * 8U);
}

size_t wt_quic_packet_number_size(uint64_t packet_number,
                                  uint64_t largest_acknowledged) {
  uint64_t delta;
  size_t byte_count;

  /* A number at or below the largest acknowledged is in the past. RFC 9000
   * section 17.1 forbids reusing a packet number, so this cannot be encoded. */
  if (packet_number <= largest_acknowledged) return 0U;
  delta = packet_number - (largest_acknowledged + 1U);

  /* The smallest width whose half-window covers the distance from the peer's
   * expectation to the number. Half, not the whole window: a receiver picks the
   * candidate nearest its expectation, and the nearest candidate to a value
   * more than half a window away is on the wrong side. */
  for (byte_count = 1U; byte_count < 4U; byte_count++) {
    uint64_t half = wt_quic_packet_number_window(byte_count) / 2U;
    if (delta < half) return byte_count;
  }
  /* Four bytes covers a window of 2^32, so half of it is 2^31. A packet number
   * further than that from the expectation cannot be sent at all, and the
   * caller has to acknowledge more before it can. */
  if (delta < (wt_quic_packet_number_window(4U) / 2U)) return 4U;
  return 0U;
}

size_t wt_quic_packet_number_encode(uint64_t packet_number, size_t byte_count,
                                    uint8_t out[4]) {
  if (out == NULL || byte_count == 0U || byte_count > 4U) return 0U;
  switch (byte_count) {
    case 1U:
      out[0] = (uint8_t)(packet_number & 0xFFU);
      break;
    case 2U:
      wt_store_be16(out, (uint16_t)(packet_number & 0xFFFFU));
      break;
    case 3U:
      wt_store_be24(out, (uint32_t)(packet_number & 0xFFFFFFU));
      break;
    default:
      wt_store_be32(out, (uint32_t)(packet_number & 0xFFFFFFFFU));
      break;
  }
  return byte_count;
}

uint64_t wt_quic_packet_number_decode(uint64_t truncated, size_t byte_count,
                                      uint64_t largest_received) {
  uint64_t expected;
  uint64_t window;
  uint64_t half;
  uint64_t mask;
  uint64_t candidate;

  if (byte_count == 0U || byte_count > 4U) return 0U;

  /* RFC 9000 appendix A.2: `expected_pn = largest_pn + 1`. A caller that has
   * received nothing passes 0, which is the convention the Swift implementation
   * this mirrors uses and the one the header documents. The RFC's own text
   * treats the first packet as `largest_pn = -1`; the two agree for every first
   * packet, because a first packet number is smaller than the window and the
   * only truncations that could distinguish them are ones the sender is not
   * allowed to produce. */
  expected = largest_received + 1U;
  window = wt_quic_packet_number_window(byte_count);
  half = window / 2U;
  mask = window - 1U;

  if (truncated > mask) return 0U; /* not a truncated value at all */

  /* The candidate is the value with the same low bits, in the epoch of the
   * expectation. */
  candidate = (expected & ~mask) | truncated;

  /* If the candidate is more than half a window below the expectation, the
   * number has wrapped into the next epoch. The second condition guards the
   * addition: near the top of the 62-bit range, `candidate + half` could exceed
   * the largest packet number QUIC allows, and RFC 9000 appendix A.2 says not to
   * shift in that case because the result could not be a valid packet number
   * anyway. */
  /* `(1 << 62) - window`, not `WT_QUIC_PACKET_NUMBER_MAX - window`: the RFC's
   * guard is against the largest packet number QUIC can *carry* plus one, and
   * writing it with the maximum instead is off by one at the very top of the
   * range -- exactly where the guard exists to matter. */
  if (candidate + half <= expected &&
      candidate < (UINT64_C(1) << 62) - window) {
    candidate += window;
  } else if (candidate > expected + half && candidate >= window) {
    candidate -= window;
  }
  return candidate;
}
