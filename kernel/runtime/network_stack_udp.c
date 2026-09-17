/*
 * The UDP flow table and the UDP data plane, moved verbatim out of
 * network_stack.c. See network_stack_udp.h for the interface and the locking
 * contract.
 */

#include "network_stack_udp.h"

#include "network_stack_listener.h"
#include "network_stack_packet.h"
#include "network_stack_wire.h"

#include <xaios/ip_addr.h>
#include <xaios/ipv4.h>
#include <xaios/ipv6.h>
#include <xaios/klog.h>
#include <xaios/network_config.h>
#include <xaios/net_device.h>
#include <xaios/socket_buffer.h>
#include <xaios/timer.h>

static network_udp_flow_t g_udp_flows[NETWORK_UDP_FLOWS];

static uint64_t g_udp_tx_count;
static uint64_t g_udp_rx_count;
static uint64_t g_udp_malformed_count;
static uint64_t g_udp_dropped_count;
static uint64_t g_udp_flow_hit_count;
static uint64_t g_udp_expired_count;

static uint64_t g_udp_latency_samples[NETWORK_MAX_SAMPLES];
static uint32_t g_udp_latency_count;

static network_udp_flow_t *find_udp_flow_v6(
    uint16_t local_port, uint16_t remote_port,
    const xaios_ip_addr_t *local_addr, const xaios_ip_addr_t *remote_addr) {
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    if (g_udp_flows[i].active != 0 &&
        g_udp_flows[i].local_port == local_port &&
        g_udp_flows[i].remote_port == remote_port &&
        xaios_ip_addr_equal(&g_udp_flows[i].local_addr, local_addr) &&
        xaios_ip_addr_equal(&g_udp_flows[i].remote_addr, remote_addr)) {
      return &g_udp_flows[i];
    }
  }
  return 0;
}

static network_udp_flow_t *find_udp_flow(uint16_t local_port,
                                         uint16_t remote_port,
                                         uint32_t local_address,
                                         uint32_t remote_address) {
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    if (g_udp_flows[i].active != 0 &&
        g_udp_flows[i].local_port == local_port &&
        g_udp_flows[i].remote_port == remote_port &&
        g_udp_flows[i].local_address == local_address &&
        g_udp_flows[i].remote_address == remote_address) {
      return &g_udp_flows[i];
    }
  }
  return 0;
}

static network_udp_flow_t *alloc_udp_flow(uint32_t queue_id, uint32_t cell_id,
                                          uint16_t local_port,
                                          uint16_t remote_port,
                                          uint32_t local_address,
                                          uint32_t remote_address,
                                          uint64_t now_ns) {
  network_udp_flow_t *flow = find_udp_flow(local_port, remote_port,
                                           local_address, remote_address);
  if (flow != 0) {
    ++g_udp_flow_hit_count;
    flow->last_seen_ns = now_ns;
    return flow;
  }
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    if (g_udp_flows[i].active == 0) {
      g_udp_flows[i].active = 1;
      g_udp_flows[i].flow_id = net_stack_alloc_flow_id();
      g_udp_flows[i].queue_id = queue_id;
      g_udp_flows[i].cell_id = cell_id;
      g_udp_flows[i].local_port = local_port;
      g_udp_flows[i].remote_port = remote_port;
      g_udp_flows[i].local_address = local_address;
      g_udp_flows[i].remote_address = remote_address;
      g_udp_flows[i].packets_rx = 0;
      g_udp_flows[i].packets_tx = 0;
      g_udp_flows[i].rx_buf = sockbuf_alloc();
      if (g_udp_flows[i].rx_buf == 0) {
        g_udp_flows[i].flow_id = 0U;
        g_udp_flows[i].active = 0U;
        return 0;
      }
      g_udp_flows[i].last_seen_ns = now_ns;
      g_udp_flows[i].remote_mac_valid = 0;
      xaios_ip_addr_zero(&g_udp_flows[i].local_addr);
      xaios_ip_addr_zero(&g_udp_flows[i].remote_addr);
      klog("network: udp flow id=%u queue=%u cell=%u local=%u remote=%u\n",
           g_udp_flows[i].flow_id, queue_id, cell_id, local_port, remote_port);
      return &g_udp_flows[i];
    }
  }
  return 0;
}

int net_udp_flow_find_v4(uint16_t local_port, uint16_t remote_port,
                         uint32_t local_address, uint32_t remote_address,
                         network_udp_flow_t *out) {
  network_udp_flow_t *flow =
      find_udp_flow(local_port, remote_port, local_address, remote_address);
  if (flow == 0) {
    return 0;
  }
  if (out != 0) {
    *out = *flow;
  }
  return 1;
}

int net_udp_flow_find_v6(uint16_t local_port, uint16_t remote_port,
                         const xaios_ip_addr_t *local_addr,
                         const xaios_ip_addr_t *remote_addr,
                         network_udp_flow_t *out) {
  network_udp_flow_t *flow =
      find_udp_flow_v6(local_port, remote_port, local_addr, remote_addr);
  if (flow == 0) {
    return 0;
  }
  if (out != 0) {
    *out = *flow;
  }
  return 1;
}

int net_udp_flow_alloc(uint32_t queue_id, uint32_t cell_id,
                       uint16_t local_port, uint16_t remote_port,
                       uint32_t local_address, uint32_t remote_address,
                       const xaios_ip_addr_t *local_addr,
                       const xaios_ip_addr_t *remote_addr, uint64_t now_ns,
                       network_udp_flow_t *out, uint32_t *out_index) {
  network_udp_flow_t *flow = alloc_udp_flow(queue_id, cell_id, local_port,
                                            remote_port, local_address,
                                            remote_address, now_ns);
  if (flow == 0) {
    return 0;
  }
  if (local_addr != 0) {
    flow->local_addr = *local_addr;
  }
  if (remote_addr != 0) {
    flow->remote_addr = *remote_addr;
  }
  if (out != 0) {
    *out = *flow;
  }
  if (out_index != 0) {
    *out_index = (uint32_t)(flow - g_udp_flows);
  }
  return 1;
}

void net_udp_flow_commit(uint32_t index, const network_udp_flow_t *row) {
  if (index >= NETWORK_UDP_FLOWS || row == 0) {
    return;
  }
  g_udp_flows[index] = *row;
}

int net_udp_flow_find_by_id(uint32_t flow_id, network_udp_flow_t *out) {
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    if (g_udp_flows[i].active != 0 && g_udp_flows[i].flow_id == flow_id) {
      if (out != 0) {
        *out = g_udp_flows[i];
      }
      return 1;
    }
  }
  return 0;
}

void net_udp_note_rx(void) { ++g_udp_rx_count; }
void net_udp_note_tx(void) { ++g_udp_tx_count; }
void net_udp_note_dropped(void) { ++g_udp_dropped_count; }
void net_udp_note_malformed(void) { ++g_udp_malformed_count; }

void net_udp_record_latency(uint64_t value) {
  if (g_udp_latency_count < NETWORK_MAX_SAMPLES) {
    g_udp_latency_samples[g_udp_latency_count] = value;
    ++g_udp_latency_count;
  }
}

static xaios_status_t network_stack_udp_send_unlocked(uint32_t flow_id, const uint8_t *data,
                                       uint32_t len, uint32_t *bytes_written) {
  if (data == 0 || bytes_written == 0 || len == 0U) return XAIOS_ERR_INVALID;
  *bytes_written = 0U;
  uint8_t local_mac[6];
  net_stack_local_mac(local_mac);
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    if (g_udp_flows[i].flow_id == flow_id && g_udp_flows[i].active != 0) {
      uint8_t frame[NETWORK_BUFFER_SIZE];
      if (g_udp_flows[i].remote_addr.family == XAIOS_IP_FAMILY_V6) {
        if (len > NETWORK_BUFFER_SIZE - 62U) return XAIOS_ERR_INVALID;
        uint16_t udp_len = (uint16_t)(8U + len);
        uint64_t frame_len = 14U + 40U + (uint64_t)udp_len;
        if (g_udp_flows[i].remote_mac_valid == 0U) return XAIOS_ERR_BUSY;
        for (uint32_t j = 0; j < 6U; ++j) {
          frame[j] = g_udp_flows[i].remote_mac[j];
          frame[6U + j] = local_mac[j];
        }
        net_wire_write_be16(frame + 12U, NETWORK_ETHERTYPE_IPV6);
        uint8_t *ip6 = frame + 14U;
        for (uint32_t j = 0; j < 40U; ++j) ip6[j] = 0U;
        ip6[0] = 0x60U;
        net_wire_write_be16(ip6 + 4U, udp_len);
        ip6[6] = NETWORK_IP_PROTO_UDP;
        ip6[7] = 64U;
        for (uint32_t j = 0; j < 16U; ++j) {
          ip6[8U + j] = g_udp_flows[i].local_addr.addr[j];
          ip6[24U + j] = g_udp_flows[i].remote_addr.addr[j];
        }
        uint8_t *udp = ip6 + 40U;
        net_wire_write_be16(udp, g_udp_flows[i].local_port);
        net_wire_write_be16(udp + 2U, g_udp_flows[i].remote_port);
        net_wire_write_be16(udp + 4U, udp_len);
        net_wire_write_be16(udp + 6U, 0U);
        for (uint32_t j = 0; j < len; ++j) udp[8U + j] = data[j];
        uint16_t checksum = ipv6_pseudo_checksum(
            &g_udp_flows[i].local_addr, &g_udp_flows[i].remote_addr,
            NETWORK_IP_PROTO_UDP, udp_len, udp, udp_len);
        net_wire_write_be16(udp + 6U, checksum == 0U ? UINT16_MAX : checksum);
        *bytes_written = len;
        return network_device_tx(frame, frame_len);
      }

      /* Build Ethernet + IPv4 + UDP frame. */
      if (len > NETWORK_BUFFER_SIZE - 42U) return XAIOS_ERR_INVALID;
      uint16_t udp_len = (uint16_t)(8U + len);
      uint16_t ip_total = (uint16_t)(20U + udp_len);
      uint64_t frame_len = 14U + (uint64_t)ip_total;
      if (frame_len > NETWORK_BUFFER_SIZE) {
        return XAIOS_ERR_INVALID;
      }
      uint32_t dst_ip_be = ((g_udp_flows[i].remote_address & 0xFFU) << 24U) |
                            (((g_udp_flows[i].remote_address >> 8U) & 0xFFU) << 16U) |
                            (((g_udp_flows[i].remote_address >> 16U) & 0xFFU) << 8U) |
                            ((g_udp_flows[i].remote_address >> 24U) & 0xFFU);
      uint8_t dst_mac[6];
      if (g_udp_flows[i].remote_mac_valid != 0) {
        for (uint32_t j = 0; j < 6U; ++j) {
          dst_mac[j] = g_udp_flows[i].remote_mac[j];
        }
      } else if (!net_tcp_resolve_mac(dst_ip_be, dst_mac, local_mac)) {
        return XAIOS_ERR_BUSY;
      }
      /* Ethernet */
      for (uint32_t j = 0; j < 6; ++j) { frame[j] = dst_mac[j]; }
      for (uint32_t j = 0; j < 6; ++j) { frame[6U + j] = local_mac[j]; }
      net_wire_write_be16(frame + 12, 0x0800U);
      /* IPv4 */
      ipv4_build_header(frame + 14, ip_total, 17,
                         network_config_local_ipv4(), dst_ip_be);
      /* UDP header */
      uint8_t *udp = frame + 34U;
      net_wire_write_be16(udp, g_udp_flows[i].local_port);
      net_wire_write_be16(udp + 2, g_udp_flows[i].remote_port);
      net_wire_write_be16(udp + 4, udp_len);
      net_wire_write_be16(udp + 6, 0U);
      /* Payload */
      for (uint32_t j = 0; j < len; ++j) {
        frame[42U + j] = data[j];
      }
      uint16_t checksum = ipv4_pseudo_checksum(
          network_config_local_ipv4(), dst_ip_be, NETWORK_IP_PROTO_UDP, udp_len,
          udp, udp_len);
      net_wire_write_be16(udp + 6U, checksum == 0U ? UINT16_MAX : checksum);
      *bytes_written = len;
      return network_device_tx(frame, frame_len);
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t network_stack_udp_send(uint32_t flow_id, const uint8_t *data,
                                       uint32_t len, uint32_t *bytes_written) {
  network_stack_lock();
  xaios_status_t result = network_stack_udp_send_unlocked(flow_id, data, len, bytes_written);
  network_stack_unlock();
  return result;
}

static xaios_status_t network_stack_udp_sendto_unlocked(
    uint16_t local_port, const xaios_ip_addr_t *remote_addr,
    uint16_t remote_port, const uint8_t *data, uint32_t len,
    uint32_t *bytes_written, uint32_t *out_flow_id) {
  if (remote_addr == 0 || data == 0 || bytes_written == 0 || len == 0U ||
      local_port == 0U || remote_port == 0U) {
    return XAIOS_ERR_INVALID;
  }
  if (remote_addr->family != XAIOS_IP_FAMILY_V4) {
    /* See the header: the v6 transmit branch needs state this path does not
       fill, so it is refused rather than half-built. */
    return XAIOS_ERR_UNSUPPORTED;
  }
  /* Both address fields are stored the way the receive path stores them, and
     that is not the way network_config_local_ipv4() holds an address.
     net_wire_parse_udp runs the wire bytes through net_wire_ip4_addr_host_order, which yields
     the byte-reversed integer -- 10.0.2.2 becomes 0x0202000a, not 0x0a000202
     -- and network_stack_udp_send_unlocked reverses remote_address again on
     its way back out to the wire. A flow created here with the natural order
     would transmit to the wrong host, and would additionally fail to match
     find_udp_flow when the peer replied, so the reply would allocate a second
     flow for the same four-tuple. The user's octets already arrive in the
     reversed order when read low byte first, which is why the expression
     below looks backwards and is not; the local address has to be swapped
     explicitly. */
  uint32_t remote_address = (uint32_t)remote_addr->addr[0] |
                            ((uint32_t)remote_addr->addr[1] << 8U) |
                            ((uint32_t)remote_addr->addr[2] << 16U) |
                            ((uint32_t)remote_addr->addr[3] << 24U);
  uint32_t configured_local = network_config_local_ipv4();
  uint32_t local_address = ((configured_local & 0xFFU) << 24U) |
                           (((configured_local >> 8U) & 0xFFU) << 16U) |
                           (((configured_local >> 16U) & 0xFFU) << 8U) |
                           ((configured_local >> 24U) & 0xFFU);
  network_udp_flow_t *flow =
      find_udp_flow(local_port, remote_port, local_address, remote_address);
  if (flow == 0) {
    /* A queue binding if the machine has one, and no flow refused if it does
       not. The binding decides which receive queue a flow's inbound frames
       are steered to, so it is required on the receive path and is genuinely
       optional here: transmit picks its queue pair from the sending CPU
       inside the driver and never consults this. Refusing to send because no
       AI cell happens to hold a queue would make an ordinary socket depend on
       an unrelated subsystem. What it costs, honestly: a flow created with no
       binding cannot receive -- process_udp_frame looks the binding up from
       the flow and drops the frame when it finds none -- so a reply to a
       datagram sent before any binding exists is dropped, exactly as it is
       today for a peer nobody has bound a queue for. */
    network_queue_binding_t binding;
    int have_binding = net_queue_binding_select(local_port, remote_port,
                                                local_address, remote_address,
                                                &binding);
    flow = alloc_udp_flow(
        have_binding != 0 ? binding.queue_id : XAIOS_NETWORK_QUEUE_ID_INVALID,
        have_binding != 0 ? binding.cell_id : 0U, local_port, remote_port,
        local_address, remote_address, timer_now_ns());
    if (flow == 0) {
      return XAIOS_ERR_NO_MEMORY;
    }
  }
  if (out_flow_id != 0) {
    *out_flow_id = flow->flow_id;
  }
  return network_stack_udp_send_unlocked(flow->flow_id, data, len,
                                         bytes_written);
}

xaios_status_t network_stack_udp_sendto(uint16_t local_port,
                                        const xaios_ip_addr_t *remote_addr,
                                        uint16_t remote_port,
                                        const uint8_t *data, uint32_t len,
                                        uint32_t *bytes_written,
                                        uint32_t *out_flow_id) {
  network_stack_lock();
  xaios_status_t result =
      network_stack_udp_sendto_unlocked(local_port, remote_addr, remote_port,
                                        data, len, bytes_written, out_flow_id);
  network_stack_unlock();
  return result;
}

uint64_t network_stack_expire_udp_flows(uint64_t now_ns) {
  uint64_t expired = 0;
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    if (g_udp_flows[i].active != 0 &&
        now_ns > g_udp_flows[i].last_seen_ns &&
        now_ns - g_udp_flows[i].last_seen_ns >= NETWORK_UDP_IDLE_TIMEOUT_NS) {
      uint32_t flow_id = g_udp_flows[i].flow_id;
      uint32_t queue_id = g_udp_flows[i].queue_id;
      uint32_t cell_id = g_udp_flows[i].cell_id;
      uint64_t packets_rx = g_udp_flows[i].packets_rx;
      uint64_t packets_tx = g_udp_flows[i].packets_tx;
      net_tcp_release_udp_flow(&g_udp_flows[i]);
      ++g_udp_expired_count;
      ++expired;
      klog("network: udp flow id=%u expired queue=%u cell=%u rx=%lu tx=%lu\n",
           flow_id, queue_id, cell_id, packets_rx, packets_tx);
    }
  }
  return expired;
}

void net_udp_reset(void) {
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    g_udp_flows[i].active = 0;
    g_udp_flows[i].flow_id = 0;
    g_udp_flows[i].queue_id = XAIOS_NETWORK_QUEUE_ID_INVALID;
    g_udp_flows[i].cell_id = 0;
    g_udp_flows[i].local_port = 0;
    g_udp_flows[i].remote_port = 0;
    g_udp_flows[i].local_address = 0;
    g_udp_flows[i].remote_address = 0;
    g_udp_flows[i].packets_rx = 0;
    g_udp_flows[i].packets_tx = 0;
    g_udp_flows[i].last_seen_ns = 0;
  }
  g_udp_tx_count = 0;
  g_udp_rx_count = 0;
  g_udp_malformed_count = 0;
  g_udp_dropped_count = 0;
  g_udp_flow_hit_count = 0;
  g_udp_expired_count = 0;
  g_udp_latency_count = 0;
  for (uint32_t i = 0; i < NETWORK_MAX_SAMPLES; ++i) {
    g_udp_latency_samples[i] = 0;
  }
}

void net_udp_clear_active(void) {
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    g_udp_flows[i].active = 0;
    g_udp_flows[i].flow_id = 0;
    g_udp_flows[i].rx_buf = 0;
  }
}

uint64_t network_stack_udp_tx_count(void) {
  return g_udp_tx_count;
}

uint64_t network_stack_udp_rx_count(void) {
  return g_udp_rx_count;
}

uint64_t network_stack_udp_malformed_count(void) {
  return g_udp_malformed_count;
}

uint64_t network_stack_udp_dropped_count(void) {
  return g_udp_dropped_count;
}

uint64_t network_stack_udp_flow_count(void) {
  uint64_t active = 0;
  for (uint32_t i = 0; i < NETWORK_UDP_FLOWS; ++i) {
    if (g_udp_flows[i].active != 0) {
      ++active;
    }
  }
  return active;
}

uint64_t network_stack_udp_flow_hit_count(void) {
  return g_udp_flow_hit_count;
}

uint64_t network_stack_udp_expired_count(void) {
  return g_udp_expired_count;
}

uint64_t network_stack_udp_latency_p50_ns(void) {
  return net_wire_percentile(g_udp_latency_samples, g_udp_latency_count, 50U);
}

uint64_t network_stack_udp_latency_p95_ns(void) {
  return net_wire_percentile(g_udp_latency_samples, g_udp_latency_count, 95U);
}

uint64_t network_stack_udp_latency_p99_ns(void) {
  return net_wire_percentile(g_udp_latency_samples, g_udp_latency_count, 99U);
}

uint64_t network_stack_udp_latency_p999_ns(void) {
  return net_wire_percentile(g_udp_latency_samples, g_udp_latency_count, 999U);
}
