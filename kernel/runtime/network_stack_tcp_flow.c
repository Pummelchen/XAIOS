/*
 * The TCP per-flow state machine: bounded out-of-order receive buffering, flow
 * release, RTO estimation and backoff, the transmit window, the close
 * handshake, and ACK and SACK processing.
 *
 * This is one half of the cut network_stack_tcp.h describes, and the reason it
 * is the cut that landed rather than the receive dispatch: every function here
 * takes the flow row from its caller -- the row is a pointer into g_tcp_flows
 * in network_stack.c, and this file never hands such a pointer back out -- so
 * no flow-table accessor is needed and no table is copied. The only
 * file-scope state the moved code touched was two counters, and those stay in
 * network_stack.c behind net_tcp_note_closed()/net_tcp_note_retransmit()
 * below.
 *
 * Locking. The caller holds the stack's guard, g_network_guard, through
 * network_stack_lock()/network_stack_unlock(); nothing here takes a lock of
 * its own. Each function replaces the code that was inlined in
 * network_stack.c at the same point under the same guard, so no critical
 * section is widened, narrowed or split.
 */

#include "network_stack_tcp.h"

#include <xaios/klog.h>
#include <xaios/timer.h>

#include "network_stack_listener.h"
#include "network_stack_wire.h"

/* Buffer an out-of-order TCP segment within the current receive window. */
uint32_t net_tcp_ooo_buffer_store(network_tcp_flow_t *flow, uint32_t seq,
                                   const uint8_t *data, uint32_t len,
                                   uint32_t expected_seq) {
  uint32_t distance = seq - expected_seq;
  if (len == 0U || len > NETWORK_TCP_IPV4_RX_MAX ||
      !net_wire_tcp_seq_after(seq, expected_seq) ||
      distance >= flow->window_size) return 0;
  uint32_t available = flow->window_size - distance;
  if (len > available) len = available;
  if (len == 0U) return 0;
  for (uint32_t i = 0; i < TCP_OOO_BUF_ENTRIES; ++i) {
    if (flow->ooo_buf[i].in_use != 0U && flow->ooo_buf[i].seq == seq) return 0;
  }
  for (uint32_t i = 0; i < TCP_OOO_BUF_ENTRIES; ++i) {
    if (!flow->ooo_buf[i].in_use) {
      uint32_t copy_len = len;
      for (uint32_t j = 0; j < copy_len; ++j)
        flow->ooo_buf[i].data[j] = data[j];
      flow->ooo_buf[i].seq = seq;
      flow->ooo_buf[i].len = (uint16_t)copy_len;
      flow->ooo_buf[i].in_use = 1;
      flow->pending_ack = 1U;
      return copy_len;
    }
  }
  return 0;
}

/* Drain in-order or overlapping buffered segments without losing a short tail. */
uint32_t net_tcp_ooo_buffer_drain(network_tcp_flow_t *flow) {
  uint32_t total = 0;
  int progress = 1;
  while (progress) {
    progress = 0;
    for (uint32_t i = 0; i < TCP_OOO_BUF_ENTRIES; ++i) {
      if (flow->ooo_buf[i].in_use &&
          !net_wire_tcp_seq_after(flow->ooo_buf[i].seq, flow->expected_seq)) {
        uint32_t overlap = flow->expected_seq - flow->ooo_buf[i].seq;
        if (overlap >= flow->ooo_buf[i].len) {
          flow->ooo_buf[i].in_use = 0U;
          progress = 1;
          continue;
        }
        uint32_t remaining = flow->ooo_buf[i].len - overlap;
        uint32_t written = sockbuf_write(flow->rx_buf,
                            flow->ooo_buf[i].data + overlap, remaining);
        flow->expected_seq += written;
        flow->pending_ack = 1;
        flow->window_size = (uint16_t)sockbuf_available(flow->rx_buf);
        if (written == remaining) {
          flow->ooo_buf[i].in_use = 0U;
        } else if (written != 0U) {
          uint32_t consumed = overlap + written;
          uint32_t tail = flow->ooo_buf[i].len - consumed;
          for (uint32_t j = 0; j < tail; ++j) {
            flow->ooo_buf[i].data[j] = flow->ooo_buf[i].data[consumed + j];
          }
          flow->ooo_buf[i].seq = flow->expected_seq;
          flow->ooo_buf[i].len = (uint16_t)tail;
        }
        total += written;
        progress = written != 0U;
      }
    }
  }
  return total;
}

/* B-63: say how a flow ended when the ending is the interesting kind.
 *
 * The defect is a connection accepted and then never serviced: the client
 * gives up after about eighteen seconds and sshd closes it thirty or a hundred
 * and twenty seconds later with packet-read-failed or auth-timeout, and the
 * console says nothing about where the bytes went. Two flow states discriminate
 * between the only two explanations there are, and neither is visible from
 * userspace:
 *
 *   rx_unread > 0   the stack received the client's data and the application
 *                   never got it -- a delivery fault on this side
 *   packets_rx == 0 nothing ever arrived for this flow, so the segments did
 *                   not reach the guest at all
 *
 * Both are abnormal, so this is quiet on a healthy connection: an ordinary
 * close has read everything it was sent and has seen at least a handshake. In
 * a 7138-round soak that is fourteen thousand closes saying nothing and the
 * three that matter saying which of the two happened.
 *
 * What has been demonstrated, and what has not. With the condition removed,
 * 121 connections through the rate gate produced 280 release lines, so the
 * call site is reached and the line arrives on the console. Every one of those
 * 280 reported rx_unread=0 with rx_packets>=1, so the condition suppresses all
 * of them -- checked against that output rather than by reading it. The case
 * it exists for has not been provoked on demand, and that is not for want of
 * trying: pushing 200 KB and resetting the connection six times produced
 * nothing, because sshd reads what it is sent. The condition fires when the
 * application does not get bytes the stack holds, which is the fault under
 * investigation and not something a healthy system can be asked to do. */
static void log_flow_release_if_odd(const network_tcp_flow_t *flow) {
  uint32_t rx_unread = flow->rx_buf != 0 ? sockbuf_used(flow->rx_buf) : 0U;
  if (rx_unread == 0U && flow->packets_rx != 0U) return;
  uint64_t now_ns = timer_now_ns();
  uint64_t idle_ms = now_ns > flow->last_seen_ns
                         ? (now_ns - flow->last_seen_ns) / 1000000U
                         : 0U;
  klog("network: tcp flow id=%u released state=%u rx_packets=%lu "
       "tx_packets=%lu rx_unread=%u idle_ms=%lu\n",
       flow->flow_id, (uint32_t)flow->state, flow->packets_rx,
       flow->packets_tx, rx_unread, idle_ms);
}

void net_tcp_release_flow(network_tcp_flow_t *flow) {
  if (flow == 0 || flow->state == XAIOS_NETWORK_FLOW_FREE) return;
  log_flow_release_if_odd(flow);
  uint32_t flow_id = flow->flow_id;
  if (flow->rx_buf != 0) sockbuf_free(flow->rx_buf);
  if (flow->tx_buf != 0) sockbuf_free(flow->tx_buf);
  /* Copy each live row out, compact it, and commit it back. The row is never
     a pointer into the registry: this runs under the caller's guard and a
     copy is what the accessor contract gives. */
  for (uint32_t listener_index = 0;
       listener_index < network_listener_slot_count(); ++listener_index) {
    network_listener_ex_t listener;
    if (!network_listener_slot_read(listener_index, &listener)) continue;
    uint32_t write_index = 0;
    for (uint32_t read_index = 0;
         read_index < listener.backlog_count; ++read_index) {
      if (listener.backlog[read_index].flow_id != flow_id) {
        if (write_index != read_index) {
          listener.backlog[write_index] = listener.backlog[read_index];
        }
        ++write_index;
      }
    }
    if (write_index != listener.backlog_count) {
      listener.backlog_count = write_index;
      network_listener_slot_write(listener_index, &listener);
    }
  }
  flow->rx_buf = 0;
  flow->tx_buf = 0;
  flow->flow_id = 0;
  flow->pending_synack = 0;
  flow->pending_syn = 0;
  flow->pending_fin = 0;
  flow->pending_ack = 0;
  flow->close_requested = 0;
  flow->in_flight = 0;
  flow->in_retransmit = 0;
  for (uint32_t i = 0U; i < TCP_TX_WINDOW_SEGMENTS; ++i) {
    flow->tx_segments[i].in_use = 0U;
    flow->tx_segments[i].pending = 0U;
  }
  flow->fin_outstanding = 0;
  flow->peer_fin_pending = 0;
  flow->peer_fin_received = 0;
  flow->pending_keepalive = 0;
  flow->state = XAIOS_NETWORK_FLOW_FREE;
}

static void tcp_enter_time_wait(network_tcp_flow_t *flow, uint64_t now_ns) {
  if (flow->rx_buf != 0) sockbuf_free(flow->rx_buf);
  if (flow->tx_buf != 0) sockbuf_free(flow->tx_buf);
  flow->rx_buf = 0;
  flow->tx_buf = 0;
  flow->state = XAIOS_NETWORK_FLOW_TIME_WAIT;
  flow->last_seen_ns = now_ns;
}

void net_tcp_release_udp_flow(network_udp_flow_t *flow) {
  if (flow == 0 || flow->active == 0U) return;
  uint32_t flow_id = flow->flow_id;
  if (flow->rx_buf != 0) sockbuf_free(flow->rx_buf);
  for (uint32_t listener_index = 0;
       listener_index < network_listener_slot_count(); ++listener_index) {
    network_listener_ex_t listener;
    if (!network_listener_slot_read(listener_index, &listener)) continue;
    uint32_t write_index = 0;
    for (uint32_t read_index = 0;
         read_index < listener.backlog_count; ++read_index) {
      if (listener.backlog[read_index].flow_id != flow_id) {
        if (write_index != read_index) {
          listener.backlog[write_index] = listener.backlog[read_index];
        }
        ++write_index;
      }
    }
    if (write_index != listener.backlog_count) {
      listener.backlog_count = write_index;
      network_listener_slot_write(listener_index, &listener);
    }
  }
  for (uint32_t i = 0; i < socket_map_slot_count(); ++i) {
    socket_flow_mapping_t row;
    if (!socket_map_slot_read(i, &row)) continue;
    if (row.protocol == NETWORK_IP_PROTO_UDP && row.flow_id == flow_id) {
      row.active = 0U;
      socket_map_slot_write(i, &row);
    }
  }
  flow->rx_buf = 0;
  flow->flow_id = 0U;
  flow->active = 0U;
}

static void tcp_update_rto(network_tcp_flow_t *flow, uint64_t sample_ns) {
  if (sample_ns == 0U) sample_ns = 1U;
  if (flow->srtt_ns == 0U) {
    flow->srtt_ns = sample_ns;
    flow->rttvar_ns = sample_ns / 2U;
  } else {
    uint64_t error = flow->srtt_ns > sample_ns ?
                         flow->srtt_ns - sample_ns : sample_ns - flow->srtt_ns;
    flow->rttvar_ns = (3U * flow->rttvar_ns + error) / 4U;
    flow->srtt_ns = (7U * flow->srtt_ns + sample_ns) / 8U;
  }
  uint64_t variation = 4U * flow->rttvar_ns;
  flow->rto_ns = flow->srtt_ns + variation;
  if (flow->rto_ns < NETWORK_TCP_RETRANSMIT_NS) {
    flow->rto_ns = NETWORK_TCP_RETRANSMIT_NS;
  } else if (flow->rto_ns > UINT64_C(60000000000)) {
    flow->rto_ns = UINT64_C(60000000000);
  }
}

void net_tcp_backoff_rto(network_tcp_flow_t *flow) {
  if (flow->rto_ns > UINT64_C(30000000000)) {
    flow->rto_ns = UINT64_C(60000000000);
  } else {
    flow->rto_ns *= 2U;
  }
  flow->ssthresh = flow->cwnd > 1U ? flow->cwnd >> 1U : 1U;
  flow->cwnd = NETWORK_TCP_MSS;
}

uint32_t net_tcp_tx_segment_count(const network_tcp_flow_t *flow) {
  uint32_t count = 0U;
  for (uint32_t i = 0U; i < TCP_TX_WINDOW_SEGMENTS; ++i) {
    count += flow->tx_segments[i].in_use != 0U ? 1U : 0U;
  }
  return count;
}

int net_tcp_tx_has_pending(const network_tcp_flow_t *flow) {
  for (uint32_t i = 0U; i < TCP_TX_WINDOW_SEGMENTS; ++i) {
    if (flow->tx_segments[i].in_use != 0U &&
        flow->tx_segments[i].pending != 0U) {
      return 1;
    }
  }
  return 0;
}

uint32_t net_tcp_tx_oldest_index(const network_tcp_flow_t *flow) {
  uint32_t oldest = TCP_TX_WINDOW_SEGMENTS;
  for (uint32_t i = 0U; i < TCP_TX_WINDOW_SEGMENTS; ++i) {
    if (flow->tx_segments[i].in_use == 0U) continue;
    if (oldest == TCP_TX_WINDOW_SEGMENTS ||
        net_wire_tcp_seq_before(flow->tx_segments[i].seq,
                       flow->tx_segments[oldest].seq)) {
      oldest = i;
    }
  }
  return oldest;
}

static uint32_t tcp_tx_free_index(const network_tcp_flow_t *flow) {
  for (uint32_t i = 0U; i < TCP_TX_WINDOW_SEGMENTS; ++i) {
    if (flow->tx_segments[i].in_use == 0U) return i;
  }
  return TCP_TX_WINDOW_SEGMENTS;
}

void net_tcp_queue_send_window(network_tcp_flow_t *flow) {
  if (flow->tx_buf == 0 || sockbuf_used(flow->tx_buf) == 0U) return;
  uint32_t allowed = flow->cwnd;
  if (flow->peer_window < allowed) allowed = flow->peer_window;
  flow->zero_window_probe = allowed == 0U ? 1U : 0U;
  if (allowed == 0U) allowed = 1U;
  while (flow->in_flight < allowed && sockbuf_used(flow->tx_buf) != 0U) {
    uint32_t slot = tcp_tx_free_index(flow);
    if (slot == TCP_TX_WINDOW_SEGMENTS) break;
    uint32_t send_limit = flow->peer_mss != 0U ?
                              flow->peer_mss : NETWORK_TCP_MSS;
    if (send_limit > NETWORK_TCP_MSS) send_limit = NETWORK_TCP_MSS;
    uint32_t window_remaining = allowed - flow->in_flight;
    if (send_limit > window_remaining) send_limit = window_remaining;
    uint32_t bytes = sockbuf_read(flow->tx_buf,
                                  flow->tx_segments[slot].data, send_limit);
    if (bytes == 0U) break;
    flow->tx_segments[slot].seq = flow->next_send_seq;
    flow->tx_segments[slot].len = (uint16_t)bytes;
    flow->tx_segments[slot].in_use = 1U;
    flow->tx_segments[slot].pending = 1U;
    flow->tx_segments[slot].retransmitted = 0U;
    flow->tx_segments[slot].retries = 0U;
    flow->tx_segments[slot].first_tx_ns = 0U;
    flow->tx_segments[slot].last_tx_ns = 0U;
    flow->next_send_seq += bytes;
    flow->in_flight += bytes;
  }
}

void net_tcp_accept_peer_fin(network_tcp_flow_t *flow, uint64_t now_ns) {
  if (flow->peer_fin_pending == 0U ||
      flow->peer_fin_seq != flow->expected_seq) return;
  flow->expected_seq++;
  flow->peer_fin_pending = 0U;
  flow->peer_fin_received = 1U;
  flow->pending_ack = 1U;
  if (flow->state == XAIOS_NETWORK_FLOW_ESTABLISHED) {
    flow->state = XAIOS_NETWORK_FLOW_CLOSE_WAIT;
  } else if (flow->state == XAIOS_NETWORK_FLOW_FIN_WAIT_2) {
    tcp_enter_time_wait(flow, now_ns);
  }
}

/* Returns 1 if the flow was released, -1 for an invalid ACK, and 0 otherwise. */
int net_tcp_acknowledge(network_tcp_flow_t *flow, uint32_t ack,
                                uint64_t now_ns) {
  if (flow == 0) return 0;
  if (net_wire_tcp_seq_after(ack, flow->next_send_seq)) return -1;
  if (flow->state == XAIOS_NETWORK_FLOW_LAST_ACK &&
      flow->fin_outstanding != 0U &&
      !net_wire_tcp_seq_before(ack, flow->fin_seq + 1U)) {
    net_tcp_note_closed();
    net_tcp_release_flow(flow);
    return 1;
  }
  if (flow->state == XAIOS_NETWORK_FLOW_FIN_WAIT &&
      flow->fin_outstanding != 0U &&
      !net_wire_tcp_seq_before(ack, flow->fin_seq + 1U)) {
    flow->fin_outstanding = 0U;
    if (flow->peer_fin_received == 0U) {
      flow->state = XAIOS_NETWORK_FLOW_FIN_WAIT_2;
      flow->last_seen_ns = now_ns;
    } else {
      tcp_enter_time_wait(flow, now_ns);
    }
  }
  if (net_wire_tcp_seq_after(ack, flow->local_seq)) {
    flow->local_seq = ack;
    flow->highest_acked = ack;
    uint32_t released = 0U;
    for (uint32_t i = 0U; i < TCP_TX_WINDOW_SEGMENTS; ++i) {
      if (flow->tx_segments[i].in_use == 0U) continue;
      uint32_t end = flow->tx_segments[i].seq + flow->tx_segments[i].len;
      if (!net_wire_tcp_seq_before(ack, end)) {
        if (flow->tx_segments[i].retransmitted == 0U &&
            flow->tx_segments[i].first_tx_ns != 0U &&
            now_ns > flow->tx_segments[i].first_tx_ns) {
          tcp_update_rto(flow, now_ns - flow->tx_segments[i].first_tx_ns);
        }
        released += flow->tx_segments[i].len;
        flow->tx_segments[i].in_use = 0U;
        flow->tx_segments[i].pending = 0U;
      } else if (net_wire_tcp_seq_after(ack, flow->tx_segments[i].seq)) {
        uint32_t prefix = ack - flow->tx_segments[i].seq;
        if (prefix > flow->tx_segments[i].len) {
          prefix = flow->tx_segments[i].len;
        }
        uint32_t tail = flow->tx_segments[i].len - prefix;
        for (uint32_t j = 0U; j < tail; ++j) {
          flow->tx_segments[i].data[j] =
              flow->tx_segments[i].data[prefix + j];
        }
        flow->tx_segments[i].seq = ack;
        flow->tx_segments[i].len = (uint16_t)tail;
        released += prefix;
      }
    }
    if (released > flow->in_flight) released = flow->in_flight;
    flow->in_flight -= released;
    if (net_tcp_tx_segment_count(flow) == 0U) {
      flow->in_retransmit = 0U;
      flow->zero_window_probe = 0U;
    }
    flow->dup_ack_count = 0;
    uint32_t mss = flow->peer_mss > 0U ? flow->peer_mss : NETWORK_TCP_MSS;
    if (flow->cwnd < flow->ssthresh) {
      flow->cwnd += mss;
    } else {
      flow->cwnd += (mss * mss) / (flow->cwnd > 0U ? flow->cwnd : 1U);
    }
  } else if (ack == flow->local_seq && flow->in_flight > 0U) {
    if (flow->zero_window_probe != 0U) {
      if (flow->peer_window != 0U) {
        uint32_t oldest = net_tcp_tx_oldest_index(flow);
        if (oldest != TCP_TX_WINDOW_SEGMENTS) {
          flow->tx_segments[oldest].pending = 1U;
        }
      }
      return 0;
    }
    ++flow->dup_ack_count;
    if (flow->dup_ack_count >= TCP_MAX_DUP_ACK &&
        flow->in_retransmit == 0U) {
      flow->ssthresh = flow->cwnd > 1U ? flow->cwnd >> 1U : 1U;
      flow->cwnd = flow->ssthresh + TCP_MAX_DUP_ACK * NETWORK_TCP_MSS;
      flow->in_retransmit = 1;
      uint32_t oldest = net_tcp_tx_oldest_index(flow);
      if (oldest != TCP_TX_WINDOW_SEGMENTS) {
        flow->tx_segments[oldest].pending = 1U;
        flow->tx_segments[oldest].retransmitted = 1U;
        flow->tx_segments[oldest].last_tx_ns = now_ns;
        ++flow->retransmits;
        net_tcp_note_retransmit();
      }
    }
  }
  return 0;
}

uint32_t net_tcp_apply_sack_blocks(
    network_tcp_flow_t *flow, const tcp_parsed_options_t *options) {
  uint32_t released = 0U;
  for (uint32_t block = 0U; block < options->sack_count; ++block) {
    uint32_t left = options->sack_left[block];
    uint32_t right = options->sack_right[block];
    if (!net_wire_tcp_seq_before(left, right) || net_wire_tcp_seq_before(left, flow->local_seq) ||
        net_wire_tcp_seq_after(right, flow->next_send_seq)) {
      continue;
    }
    for (uint32_t i = 0U; i < TCP_TX_WINDOW_SEGMENTS; ++i) {
      if (flow->tx_segments[i].in_use == 0U) continue;
      uint32_t end = flow->tx_segments[i].seq + flow->tx_segments[i].len;
      if (!net_wire_tcp_seq_before(flow->tx_segments[i].seq, left) &&
          !net_wire_tcp_seq_after(end, right)) {
        released += flow->tx_segments[i].len;
        flow->tx_segments[i].in_use = 0U;
        flow->tx_segments[i].pending = 0U;
      }
    }
  }
  if (released > flow->in_flight) released = flow->in_flight;
  flow->in_flight -= released;
  return released;
}
