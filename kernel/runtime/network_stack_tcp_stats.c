/*
 * The TCP counters, the TCP latency samples and the sliding-window self-check,
 * moved verbatim out of network_stack.c. See network_stack_tcp_stats.h for the
 * contract: the caller holds the stack guard, and every note here is the plain
 * `++` the old code made in place.
 *
 * Two of the increments -- the closed and retransmit counters -- were already
 * called from network_stack_tcp_flow.c through the declarations in
 * network_stack_tcp.h; they are defined here now because their state moved
 * here. The queue/core mismatch counter is bumped from network_stack_udp_rx.c
 * through network_stack_udp_rx.h the same way.
 */

#include "network_stack_tcp_stats.h"

#include "network_stack_selftest.h"
#include "network_stack_tcp.h"
#include "network_stack_udp_rx.h"
#include "network_stack_wire.h"

#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/network_stack.h>
#include <xaios/socket_buffer.h>

static uint64_t g_tcp_handshake_count;
static uint64_t g_tcp_reset_count;
static uint64_t g_tcp_timeout_count;
static uint64_t g_tcp_retransmit_count;
static uint64_t g_tcp_established_count;
static uint64_t g_tcp_closed_count;

/* The two increments the TCP flow module makes, kept beside the counters it
   writes and declared in network_stack_tcp.h. Caller holds the stack guard;
   each is the plain increment the moved code made in place of these. */
void net_tcp_note_closed(void) { ++g_tcp_closed_count; }
void net_tcp_note_retransmit(void) { ++g_tcp_retransmit_count; }
static uint64_t g_flow_core_mismatch_count;

/* The queue/core mismatch increment the moved UDP receive handlers make; the
   counter stays here with the rest of the stack's counters. Caller holds the
   guard, and this is the plain `++` it replaced. Declared in
   network_stack_udp_rx.h. */
void net_stack_note_flow_core_mismatch(void) { ++g_flow_core_mismatch_count; }

/* The increments the frame handlers and the timers that stayed in
   network_stack.c make, one per counter. Caller holds the guard. */
void net_tcp_note_handshake(void) { ++g_tcp_handshake_count; }
void net_tcp_note_reset(void) { ++g_tcp_reset_count; }
void net_tcp_note_timeout(void) { ++g_tcp_timeout_count; }
void net_tcp_note_established(void) { ++g_tcp_established_count; }

static uint64_t g_tcp_latency_samples[NETWORK_MAX_SAMPLES];
static uint32_t g_tcp_latency_count;

static void record_latency(uint64_t *samples, uint32_t *count, uint64_t value) {
  if (*count < NETWORK_MAX_SAMPLES) {
    samples[*count] = value;
    ++(*count);
  }
}

/* The latency sample the frame handlers record, the exact call they made. */
void net_tcp_record_latency(uint64_t value) {
  record_latency(g_tcp_latency_samples, &g_tcp_latency_count, value);
}

/* Zero everything network_stack_init() used to zero here, in the same order. */
void net_tcp_stats_reset(void) {
  g_tcp_handshake_count = 0;
  g_tcp_reset_count = 0;
  g_tcp_timeout_count = 0;
  g_tcp_retransmit_count = 0;
  g_tcp_established_count = 0;
  g_tcp_closed_count = 0;
  g_tcp_latency_count = 0;
  g_flow_core_mismatch_count = 0;

  for (uint32_t i = 0; i < NETWORK_MAX_SAMPLES; ++i) {
    g_tcp_latency_samples[i] = 0;
  }
}

uint64_t network_stack_tcp_handshake_count(void) {
  return g_tcp_handshake_count;
}

uint64_t network_stack_tcp_reset_count(void) {
  return g_tcp_reset_count;
}

uint64_t network_stack_tcp_timeout_count(void) {
  return g_tcp_timeout_count;
}

uint64_t network_stack_tcp_retransmit_count(void) {
  return g_tcp_retransmit_count;
}

uint64_t network_stack_tcp_established_count(void) {
  return g_tcp_established_count;
}

uint64_t network_stack_tcp_closed_count(void) {
  return g_tcp_closed_count;
}

uint64_t network_stack_flow_core_mismatch_count(void) {
  return g_flow_core_mismatch_count;
}

uint64_t network_stack_tcp_latency_p50_ns(void) {
  return net_wire_percentile(g_tcp_latency_samples, g_tcp_latency_count, 50U);
}

uint64_t network_stack_tcp_latency_p95_ns(void) {
  return net_wire_percentile(g_tcp_latency_samples, g_tcp_latency_count, 95U);
}

uint64_t network_stack_tcp_latency_p99_ns(void) {
  return net_wire_percentile(g_tcp_latency_samples, g_tcp_latency_count, 99U);
}

uint64_t network_stack_tcp_latency_p999_ns(void) {
  return net_wire_percentile(g_tcp_latency_samples, g_tcp_latency_count, 999U);
}

void net_stack_tcp_sliding_window_self_test(void) {
  network_tcp_flow_t flow;
  uint8_t payload[10];
  net_wire_bytes_zero(&flow, sizeof(flow));
  for (uint32_t i = 0U; i < sizeof(payload); ++i) {
    payload[i] = (uint8_t)(i + 1U);
  }
  flow.state = XAIOS_NETWORK_FLOW_ESTABLISHED;
  flow.tx_buf = sockbuf_alloc();
  kassert(flow.tx_buf != 0);
  flow.local_seq = 100U;
  flow.next_send_seq = 100U;
  flow.highest_acked = 100U;
  flow.peer_mss = 4U;
  flow.peer_window = 12U;
  flow.cwnd = 12U;
  flow.rto_ns = NETWORK_TCP_RETRANSMIT_NS;
  kassert(sockbuf_write(flow.tx_buf, payload, sizeof(payload)) ==
          sizeof(payload));

  net_tcp_queue_send_window(&flow);
  kassert(net_tcp_tx_segment_count(&flow) == 3U);
  kassert(flow.in_flight == 10U && flow.next_send_seq == 110U);
  kassert(flow.tx_segments[0].seq == 100U &&
          flow.tx_segments[0].len == 4U);
  kassert(flow.tx_segments[1].seq == 104U &&
          flow.tx_segments[1].len == 4U);
  kassert(flow.tx_segments[2].seq == 108U &&
          flow.tx_segments[2].len == 2U);

  kassert(net_tcp_acknowledge(&flow, 106U, 1U) == 0);
  kassert(net_tcp_tx_segment_count(&flow) == 2U);
  kassert(flow.in_flight == 4U && flow.local_seq == 106U);
  kassert(flow.tx_segments[1].seq == 106U &&
          flow.tx_segments[1].len == 2U &&
          flow.tx_segments[1].data[0] == 7U);
  kassert(net_tcp_acknowledge(&flow, 110U, 2U) == 0);
  kassert(net_tcp_tx_segment_count(&flow) == 0U && flow.in_flight == 0U);
  sockbuf_free(flow.tx_buf);

  uint8_t option_header[60];
  tcp_parsed_options_t options;
  net_wire_bytes_zero(option_header, sizeof(option_header));
  option_header[20] = TCP_OPT_SACK_PERMITTED;
  option_header[21] = 2U;
  option_header[22] = TCP_OPT_SACK;
  option_header[23] = 10U;
  net_wire_write_be32(option_header + 24U, 204U);
  net_wire_write_be32(option_header + 28U, 208U);
  kassert(net_wire_parse_tcp_options(option_header, 32U, &options) != 0);
  kassert(options.sack_permitted == 1U && options.sack_count == 1U);

  net_wire_bytes_zero(&flow, sizeof(flow));
  flow.state = XAIOS_NETWORK_FLOW_ESTABLISHED;
  flow.local_seq = 200U;
  flow.next_send_seq = 212U;
  flow.in_flight = 12U;
  flow.cwnd = 12U;
  flow.ssthresh = 12U;
  for (uint32_t i = 0U; i < 3U; ++i) {
    flow.tx_segments[i].seq = 200U + i * 4U;
    flow.tx_segments[i].len = 4U;
    flow.tx_segments[i].in_use = 1U;
  }
  kassert(net_tcp_apply_sack_blocks(&flow, &options) == 4U);
  kassert(flow.tx_segments[1].in_use == 0U && flow.in_flight == 8U);
  uint64_t retransmits_before = g_tcp_retransmit_count;
  kassert(net_tcp_acknowledge(&flow, 200U, 10U) == 0);
  kassert(net_tcp_acknowledge(&flow, 200U, 11U) == 0);
  kassert(net_tcp_acknowledge(&flow, 200U, 12U) == 0);
  kassert(flow.in_retransmit == 1U &&
          flow.tx_segments[0].retransmitted == 1U);
  g_tcp_retransmit_count = retransmits_before;

  net_wire_bytes_zero(&flow, sizeof(flow));
  flow.state = XAIOS_NETWORK_FLOW_ESTABLISHED;
  flow.tx_buf = sockbuf_alloc();
  kassert(flow.tx_buf != 0);
  flow.next_send_seq = 300U;
  flow.peer_mss = 8U;
  flow.peer_window = 0U;
  flow.cwnd = 8U;
  kassert(sockbuf_write(flow.tx_buf, payload, 4U) == 4U);
  net_tcp_queue_send_window(&flow);
  kassert(flow.zero_window_probe == 1U && flow.in_flight == 1U &&
          flow.tx_segments[0].len == 1U);
  sockbuf_free(flow.tx_buf);

  net_wire_bytes_zero(&flow, sizeof(flow));
  flow.rx_buf = sockbuf_alloc();
  kassert(flow.rx_buf != 0);
  flow.expected_seq = 400U;
  flow.window_size = 32U;
  flow.peer_sack_permitted = 1U;
  kassert(net_tcp_ooo_buffer_store(&flow, 404U, payload + 4U, 4U,
                           flow.expected_seq) == 4U);
  uint8_t generated[40];
  uint32_t generated_len =
      net_tcp_build_options(&flow, NETWORK_TCP_FLAG_ACK, generated);
  net_wire_bytes_zero(option_header, sizeof(option_header));
  for (uint32_t i = 0U; i < generated_len; ++i) {
    option_header[20U + i] = generated[i];
  }
  kassert(net_wire_parse_tcp_options(option_header, 20U + generated_len, &options) != 0);
  kassert(options.sack_count == 1U && options.sack_left[0] == 404U &&
          options.sack_right[0] == 408U);
  kassert(sockbuf_write(flow.rx_buf, payload, 4U) == 4U);
  flow.expected_seq += 4U;
  kassert(net_tcp_ooo_buffer_drain(&flow) == 4U && flow.expected_seq == 408U);
  uint8_t reordered[8];
  kassert(sockbuf_read(flow.rx_buf, reordered, sizeof(reordered)) ==
          sizeof(reordered));
  for (uint32_t i = 0U; i < sizeof(reordered); ++i) {
    kassert(reordered[i] == payload[i]);
  }
  sockbuf_free(flow.rx_buf);

  net_wire_bytes_zero(&flow, sizeof(flow));
  flow.rto_ns = NETWORK_TCP_RETRANSMIT_NS;
  flow.cwnd = NETWORK_TCP_MSS * 8U;
  net_tcp_backoff_rto(&flow);
  kassert(flow.rto_ns == NETWORK_TCP_RETRANSMIT_NS * 2U &&
          flow.cwnd == NETWORK_TCP_MSS);
  net_tcp_backoff_rto(&flow);
  kassert(flow.rto_ns == NETWORK_TCP_RETRANSMIT_NS * 4U);

  option_header[20] = TCP_OPT_SACK;
  option_header[21] = 9U;
  kassert(net_wire_parse_tcp_options(option_header, 29U, &options) == 0);
  klog("network: TCP sliding-window self-test passed segments=3 cumulative_ack=1 partial_ack=1 sack=1 fast_retransmit=1 zero_window=1 reorder=1 rto_backoff=1\n");
}
