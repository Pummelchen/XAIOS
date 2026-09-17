/*
 * The TCP connection API and the socket-readiness helper, moved out of
 * network_stack.c: the active open and its status, abort, send, close, receive,
 * peer-closed and network_stack_socket_ready().
 *
 * Every function here was already written against the `_unlocked` shape
 * network_stack.c's public wrappers call. They walk the table, so they cannot
 * copy a row: the table crosses as the caller-owned `network_tcp_flow_t
 * *flows` the public wrappers in network_stack.c supply. The two scalars the
 * moved code touched directly -- the shared flow-id counter and the half-open
 * count -- cross through net_stack_alloc_flow_id() and the half-open helpers;
 * the interface MAC is read into a caller-owned local through the existing
 * net_stack_local_mac() copy-out accessor.
 *
 * Locking. The `_unlocked` bodies took the reentrant guard themselves exactly
 * where they do now, through network_stack_lock()/network_stack_unlock() (the
 * aliases the old static network_lock()/network_unlock() pair named); the
 * outer public wrappers still take it first. No critical section is widened,
 * narrowed or split.
 */

#include <xaios/arp.h>

#include "network_stack_app.h"
#include "network_stack_icmp.h"
#include "network_stack_listener.h"
#include "network_stack_packet.h"
#include "network_stack_poll.h"
#include "network_stack_selftest.h"
#include "network_stack_tcp_stats.h"
#include "network_stack_lifecycle.h"
#include "network_stack_udp.h"
#include "network_stack_udp_rx.h"
#include "network_stack_v6.h"
#include "network_stack_wire.h"
#include "network_stack_tcp.h"
#include "network_stack_tcp_table.h"
#include <xaios/assert.h>
#include <xaios/dns.h>
#include <xaios/entropy.h>
#include <xaios/icmp.h>
#include <xaios/icmpv6.h>
#include <xaios/ip_addr.h>
#include <xaios/ipv4.h>
#include <xaios/ipv6.h>
#include <xaios/klog.h>
#include <xaios/ndp.h>
#include <xaios/ntp.h>
#include <xaios/operations.h>
#include <xaios/network_stack.h>
#include <xaios/smp.h>
#include <xaios/spinlock.h>
#include <xaios/routing.h>
#include <xaios/socket_buffer.h>
#include <xaios/timer.h>
#include <xaios/net_device.h>
#include <xaios/network_config.h>

xaios_status_t net_tcp_api_open(network_tcp_flow_t *flows,
                                const xaios_ip_addr_t *remote_addr,
                                uint16_t remote_port, uint16_t local_port,
                                uint32_t *out_flow_id) {
  xaios_status_t status = XAIOS_ERR_INVALID;
  if (remote_addr == 0 || out_flow_id == 0 || remote_port == 0U ||
      local_port == 0U ||
      (remote_addr->family != XAIOS_IP_FAMILY_V4 &&
       remote_addr->family != XAIOS_IP_FAMILY_V6))
    return XAIOS_ERR_INVALID;
  network_stack_lock();
  uint8_t local_mac[6];
  net_stack_local_mac(local_mac);
  uint32_t remote_address = 0U;
  uint32_t local_address = 0U;
  if (remote_addr->family == XAIOS_IP_FAMILY_V4) {
    remote_address = (uint32_t)remote_addr->addr[0] |
                     ((uint32_t)remote_addr->addr[1] << 8U) |
                     ((uint32_t)remote_addr->addr[2] << 16U) |
                     ((uint32_t)remote_addr->addr[3] << 24U);
    local_address = network_config_local_ipv4();
    if (net_tcp_table_find_v4(flows, local_port, remote_port,
                              remote_address) != 0)
      goto busy;
  } else if (net_tcp_table_find_v6(flows, local_port, remote_port,
                                   remote_addr) != 0) {
    goto busy;
  }
  xaios_ip_addr_t link_local_v6;
  net_v6_link_local(&link_local_v6);
  network_queue_binding_t binding;
  if (!net_queue_binding_select(local_port, remote_port,
                                remote_addr->family == XAIOS_IP_FAMILY_V4
                                    ? local_address
                                    : xaios_ip_addr_hash(&link_local_v6),
                                remote_addr->family == XAIOS_IP_FAMILY_V4
                                    ? remote_address
                                    : xaios_ip_addr_hash(remote_addr),
                                &binding)) {
    status = XAIOS_ERR_NOT_FOUND;
    goto out;
  }
  network_tcp_flow_t *flow = net_tcp_table_alloc(
      flows, local_port, remote_port, remote_address, remote_addr);
  if (flow == 0) {
    status = XAIOS_ERR_NO_MEMORY;
    goto out;
  }
  flow->flow_id = net_stack_alloc_flow_id();
  flow->local_port = local_port;
  flow->remote_port = remote_port;
  flow->queue_id = binding.queue_id;
  flow->cell_id = binding.cell_id;
  flow->remote_address = remote_address;
  flow->local_address = local_address;
  flow->remote_addr = *remote_addr;
  if (remote_addr->family == XAIOS_IP_FAMILY_V4) {
    flow->local_addr = xaios_ip_addr_from_ipv4(network_config_local_ipv4());
  } else {
    net_v6_flow_local_address(remote_addr, local_mac, &flow->local_addr);
  }
  flow->local_seq = net_wire_tcp_generate_isn(flow->flow_id);
  flow->next_send_seq = flow->local_seq + 1U;
  flow->expected_seq = 0U;
  flow->window_size = (uint16_t)SOCKET_BUFFER_SIZE;
  flow->pending_syn = 1U;
  flow->last_seen_ns = timer_now_ns();
  flow->rx_buf = sockbuf_alloc();
  flow->tx_buf = sockbuf_alloc();
  if (flow->rx_buf == 0 || flow->tx_buf == 0) {
    net_tcp_half_open_release();
    net_tcp_release_flow(flow);
    status = XAIOS_ERR_NO_MEMORY;
    goto out;
  }
  flow->state = XAIOS_NETWORK_FLOW_SYN_SENT;
  if (remote_addr->family == XAIOS_IP_FAMILY_V6) {
    uint8_t solicitation[128];
    uint64_t solicitation_length = 0U;
    /* Solicit the first hop, not the far end. For an on-link peer they are
       the same address; for anything else the far end is on somebody else's
       network and no neighbour here will ever answer for it. */
    xaios_ip_addr_t next_hop;
    net_v6_next_hop(remote_addr, timer_now_ns(), &next_hop);
    if (ndp_build_neighbor_solicitation(
            solicitation, &solicitation_length, local_mac,
            &flow->local_addr, &next_hop) != XAIOS_OK ||
        network_device_tx(solicitation, solicitation_length) != XAIOS_OK) {
      net_tcp_half_open_release();
      net_tcp_release_flow(flow);
      status = XAIOS_ERR_IO;
      goto out;
    }
  }
  *out_flow_id = flow->flow_id;
  klog("network: active TCP open flow=%u local=%u remote=%u\n",
       flow->flow_id, local_port, remote_port);
  status = XAIOS_OK;
  goto out;

busy:
  status = XAIOS_ERR_BUSY;
out:
  network_stack_unlock();
  return status;
}

xaios_status_t net_tcp_api_open_status(network_tcp_flow_t *flows,
                                       uint32_t flow_id) {
  xaios_status_t status = XAIOS_ERR_NOT_FOUND;
  network_stack_lock();
  for (uint32_t i = 0U; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (flows[i].flow_id != flow_id) continue;
    if (flows[i].state == XAIOS_NETWORK_FLOW_ESTABLISHED) {
      status = XAIOS_OK;
    } else if (flows[i].state == XAIOS_NETWORK_FLOW_SYN_SENT) {
      status = XAIOS_ERR_BUSY;
    } else {
      status = XAIOS_ERR_IO;
    }
    break;
  }
  network_stack_unlock();
  return status;
}

xaios_status_t net_tcp_api_abort_flow(network_tcp_flow_t *flows,
                                      uint32_t flow_id) {
  for (uint32_t i = 0U; i < NETWORK_TCP_CONNECTIONS; ++i) {
    network_tcp_flow_t *flow = &flows[i];
    if (flow->flow_id != flow_id) continue;
    if (flow->state == XAIOS_NETWORK_FLOW_SYN_RECV ||
        flow->state == XAIOS_NETWORK_FLOW_SYN_SENT) {
      net_tcp_half_open_release();
    }
    net_tcp_note_closed();
    net_tcp_release_flow(flow);
    return XAIOS_OK;
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t net_tcp_api_send(network_tcp_flow_t *flows, uint32_t flow_id,
                                const uint8_t *data, uint32_t len,
                                uint32_t *bytes_written) {
  if (data == 0 || bytes_written == 0 || len == 0U) return XAIOS_ERR_INVALID;
  *bytes_written = 0U;
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (flows[i].flow_id == flow_id &&
        (flows[i].state == XAIOS_NETWORK_FLOW_ESTABLISHED ||
         flows[i].state == XAIOS_NETWORK_FLOW_CLOSE_WAIT)) {
      if (flows[i].tx_buf == 0) {
        return XAIOS_ERR_INVALID;
      }
      *bytes_written = sockbuf_write(flows[i].tx_buf, data, len);
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t net_tcp_api_close_flow(network_tcp_flow_t *flows,
                                      uint32_t flow_id) {
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (flows[i].flow_id == flow_id) {
      if (flows[i].state == XAIOS_NETWORK_FLOW_SYN_RECV ||
          flows[i].state == XAIOS_NETWORK_FLOW_SYN_SENT) {
        return network_stack_tcp_abort_flow(flow_id);
      }
      flows[i].close_requested = 1;
      flows[i].pending_fin = 1;
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

uint32_t net_tcp_api_recv(network_tcp_flow_t *flows, uint32_t flow_id,
                          uint8_t *buffer, uint32_t buffer_size) {
  if (buffer == 0 || buffer_size == 0U) return 0U;
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (flows[i].flow_id == flow_id &&
        flows[i].rx_buf != 0) {
      uint32_t bytes_read = sockbuf_read(flows[i].rx_buf,
                                            buffer, buffer_size);
      flows[i].window_size =
          (uint16_t)sockbuf_available(flows[i].rx_buf);
      if (bytes_read != 0U) {
        flows[i].pending_ack = 1;
      }
      return bytes_read;
    }
  }
  return 0;
}

int net_tcp_api_peer_closed(network_tcp_flow_t *flows, uint32_t flow_id) {
  for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
    if (flows[i].flow_id == flow_id) {
      return flows[i].state == XAIOS_NETWORK_FLOW_CLOSE_WAIT ||
             flows[i].state == XAIOS_NETWORK_FLOW_CLOSED ||
             flows[i].state == XAIOS_NETWORK_FLOW_TIME_WAIT;
    }
  }
  return 1;
}

int net_tcp_api_socket_ready(network_tcp_flow_t *flows, uint64_t sockfd,
                             uint8_t protocol, uint16_t port,
                             uint32_t listening) {
  int ready = 0;
  network_stack_lock();
  if (listening != 0U) {
    for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
      network_listener_ex_t row;
      if (!network_listener_slot_read(i, &row)) continue;
      const int match =
          protocol == NETWORK_IP_PROTO_UDP
              ? (row.sockfd == sockfd && row.protocol == NETWORK_IP_PROTO_UDP)
              : (row.port == port && row.protocol == NETWORK_IP_PROTO_TCP);
      if (match) {
        ready = row.backlog_count != 0U;
        break;
      }
    }
  } else {
    socket_flow_mapping_t mapping;
    if (network_stack_get_socket_mapping_unlocked(sockfd, &mapping) != 0 &&
        mapping.protocol == XAIOS_NETWORK_PROTOCOL_TCP) {
      int found = 0;
      for (uint32_t i = 0; i < NETWORK_TCP_CONNECTIONS; ++i) {
        if (flows[i].flow_id != mapping.flow_id) continue;
        found = 1;
        if (flows[i].rx_buf != 0 && flows[i].rx_buf->count != 0U) {
          ready = 1;
        }
        break;
      }
      if (ready == 0 &&
          (found == 0 ||
           net_tcp_api_peer_closed(flows, mapping.flow_id) != 0)) {
        ready = 1;
      }
    }
  }
  network_stack_unlock();
  return ready;
}
