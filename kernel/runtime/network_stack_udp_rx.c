/*
 * The UDP receive plane -- the two frame handlers that turn a received UDP
 * frame into a flow row and a queued datagram, and the receive call that
 * drains one listener's backlog -- moved verbatim out of network_stack.c.
 *
 * These three functions were already written against the cursor-plus-commit
 * rows network_stack_udp.h declares and the listener rows
 * network_stack_listener.h declares, so almost nothing of network_stack.c
 * crosses with them. Only two of its counters are written here: the
 * queue/core mismatch count and the IPv6 receive count. Both stay beside the
 * rest of that file's counters and are reached through the two plain
 * increments declared in network_stack_udp_rx.h, which are exactly the `++`
 * the moved code made.
 *
 * Locking. The stack guard is held through network_stack_lock()/
 * network_stack_unlock(); the old file reached the same two functions through
 * its static listener_lock()/listener_unlock() aliases, which the moved code
 * calls directly here. No critical section is widened, narrowed or split, and
 * every net_udp_* accessor below is lock-free on purpose because the caller
 * already holds that guard.
 */

#include "network_stack_udp_rx.h"

#include "network_stack_listener.h"
#include "network_stack_packet.h"
#include "network_stack_udp.h"
#include "network_stack_wire.h"

#include <xaios/ip_addr.h>
#include <xaios/network_stack.h>
#include <xaios/socket_buffer.h>
#include <xaios/timer.h>

xaios_status_t network_stack_process_udp_frame(const uint8_t *frame,
                                            uint64_t frame_len) {
  if (frame == 0 || frame_len < 34U) {
    net_udp_note_dropped();
    net_udp_note_malformed();
    net_note_packet_drop();
    return XAIOS_ERR_INVALID;
  }

  uint64_t start = timer_now_ns();
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint16_t payload_len = 0;
  uint32_t src_address = 0;
  uint32_t dst_address = 0;

  if (net_wire_parse_udp(frame, frame_len, &src_port, &dst_port, &payload_len,
                &src_address, &dst_address) == 0) {
    net_udp_note_dropped();
    net_udp_note_malformed();
    net_note_packet_drop();
    return XAIOS_ERR_INVALID;
  }

  if (src_port == 0 || dst_port == 0 || payload_len == 0) {
    net_udp_note_dropped();
    net_note_packet_drop();
    return XAIOS_ERR_INVALID;
  }

  network_udp_flow_t existing_row;
  int have_existing = net_udp_flow_find_v4(dst_port, src_port, dst_address,
                                           src_address, &existing_row);
  network_queue_binding_t binding;
  int have_binding =
      have_existing != 0
          ? net_queue_binding_find(existing_row.queue_id, &binding)
          : net_queue_binding_select(dst_port, src_port, dst_address,
                                     src_address, &binding);
  if (have_binding == 0) {
    net_udp_note_dropped();
    net_note_packet_drop();
    return XAIOS_ERR_NOT_FOUND;
  }

  uint32_t packet =
      net_packet_alloc(binding.queue_id, frame_len, start, src_port, dst_port,
                       src_address, dst_address, 0, 0);
  if (packet == 0) {
    net_udp_note_dropped();
    return XAIOS_ERR_NO_MEMORY;
  }

  network_udp_flow_t flow_row;
  uint32_t flow_index = 0U;
  if (!net_udp_flow_alloc(binding.queue_id, binding.cell_id, dst_port, src_port,
                          dst_address, src_address, 0, 0, start, &flow_row,
                          &flow_index)) {
    net_udp_note_dropped();
    net_packet_mark_dropped(packet);
    return XAIOS_ERR_NO_MEMORY;
  }
  if (flow_row.queue_id != binding.queue_id ||
      flow_row.cell_id != binding.cell_id) {
    net_stack_note_flow_core_mismatch();
    net_packet_mark_dropped(packet);
    return XAIOS_ERR_BUSY;
  }
  ++flow_row.packets_rx;
  net_udp_note_rx();
  for (uint32_t i = 0; i < 6U; ++i) {
    flow_row.remote_mac[i] = frame[6U + i];
  }
  flow_row.remote_mac_valid = 1;
  /* The row is written back here, before the listener block below can return
     early: the old code held a pointer into the table, so these increments
     were visible on every path out of the function. */
  net_udp_flow_commit(flow_index, &flow_row);
  
  /* Deliver UDP payload to flow rx_buf */
  if (flow_row.rx_buf != 0 && payload_len > 8) {
    const network_ip4_header_t *ip4 =
        (const network_ip4_header_t *)(frame + 14U);
    uint64_t ip_hdr_bytes = (uint64_t)(ip4->version_ihl & 0x0FU) * 4U;
    const uint8_t *udp_payload = frame + 14U + ip_hdr_bytes + 8U;
    uint32_t data_len = (uint32_t)(payload_len - 8U);
    xaios_ip_addr_t peer_addr;
    peer_addr.family = XAIOS_IP_FAMILY_V4;
    for (uint32_t i = 0; i < 4U; ++i) {
      peer_addr.addr[i] = frame[26U + i];
    }
    for (uint32_t i = 4U; i < 16U; ++i) {
      peer_addr.addr[i] = 0;
    }
    /* The row is copied out under the guard, so no pointer into the registry
       is held across udp_listener_enqueue(), which takes the same reentrant
       guard again. */
    network_stack_lock();
    network_listener_ex_t listener_row;
    uint32_t listener_backlog = 0U;
    int listener_found = 0;
    for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
      if (!network_listener_slot_read(i, &listener_row)) continue;
      if (listener_row.port == dst_port &&
          listener_row.protocol == NETWORK_IP_PROTO_UDP) {
        listener_backlog = listener_row.backlog_count;
        listener_found = 1;
        break;
      }
    }
    if (listener_found != 0) {
      /* A datagram that does not fit is dropped here, whole, and counted; it is
         never queued in part. The test is against `sockbuf_available`, the flow
         ring's *free space*, so this is backpressure as much as a size policy:
         a large datagram is admitted on an empty ring and refused once the ring
         is partly full. It is not the check that bounds how large a datagram
         can be.
       *
         The frame is what bounds that. `network_device_rx_poll` reads into a
         `NETWORK_BUFFER_SIZE` (1520) buffer and this function's caller rejects
         a reassembled frame longer than that, so `net_wire_parse_udp` can only ever see
         a UDP length inside a 1520-byte frame and the largest deliverable
         datagram is 1520 - 14 - 20 - 8 = 1478 bytes of payload.
       *
         The receive path below is therefore safe for a caller that asks for a
         full-size buffer: admission is against free space (at most
         SOCKET_BUFFER_SIZE) and the syscall caps a read at SOCKET_BUFFER_SIZE,
         both of which are at or above the 1478 the frame can produce, so no
         clamp can occur. A caller that asks for less than the datagram's length
         is truncated silently and told nothing. A truncation flag is what would
         make that last case honest, and it is a syscall change rather than a
         stack one. */
      if (listener_backlog >= NETWORK_LISTENER_BACKLOG ||
          data_len > sockbuf_available(flow_row.rx_buf) ||
          sockbuf_write(flow_row.rx_buf, udp_payload, data_len) != data_len ||
          !udp_listener_enqueue(dst_port, flow_row.flow_id, src_port, &peer_addr,
                                (uint16_t)data_len)) {
        network_stack_unlock();
        net_udp_note_dropped();
        net_packet_mark_dropped(packet);
        return XAIOS_ERR_BUSY;
      }
    }
    network_stack_unlock();
  }
  
  net_packet_mark_tx(packet);
  ++flow_row.packets_tx;
  net_udp_note_tx();
  net_udp_flow_commit(flow_index, &flow_row);
  net_packet_mark_complete(packet);
  net_udp_record_latency(timer_now_ns() - start);
  return XAIOS_OK;
}

static uint32_t network_stack_udp_recv_unlocked(uint64_t sockfd, uint8_t *buffer,
                                uint32_t buffer_size,
                                xaios_ip_addr_t *source_addr,
                                uint16_t *source_port,
                                uint32_t *flow_id) {
  network_stack_lock();
  network_listener_ex_t listener_row;
  uint32_t listener_index = 0U;
  int listener_found = 0;
  for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
    if (!network_listener_slot_read(i, &listener_row)) continue;
    if (listener_row.sockfd == sockfd &&
        listener_row.protocol == NETWORK_IP_PROTO_UDP) {
      listener_index = i;
      listener_found = 1;
      break;
    }
  }
  if (listener_found == 0 || listener_row.backlog_count == 0 || buffer == 0 ||
      buffer_size == 0) {
    { network_stack_unlock(); return 0; }
  }

  listener_accept_entry_t entry = listener_row.backlog[0];
  for (uint32_t i = 1; i < listener_row.backlog_count; ++i) {
    listener_row.backlog[i - 1U] = listener_row.backlog[i];
  }
  --listener_row.backlog_count;
  network_listener_slot_write(listener_index, &listener_row);

  network_udp_flow_t udp_flow;
  if (net_udp_flow_find_by_id(entry.flow_id, &udp_flow) &&
      udp_flow.rx_buf != 0) {
    uint32_t read_limit = entry.payload_len;
    if (read_limit > buffer_size) {
      read_limit = buffer_size;
    }
    uint32_t bytes_read = sockbuf_read(udp_flow.rx_buf, buffer, read_limit);
    if (entry.payload_len > bytes_read) {
      sockbuf_discard(udp_flow.rx_buf,
                      (uint32_t)entry.payload_len - bytes_read);
    }
    if (source_addr != 0) {
      *source_addr = entry.peer_addr;
    }
    if (source_port != 0) {
      *source_port = entry.peer_port;
    }
    if (flow_id != 0) {
      *flow_id = entry.flow_id;
    }
    /* The unlocked variant: this function already runs under the network
       guard, and calling the public wrapper from here would take that guard
       from inside a listener-guard section, inverting the order the two
       guards are documented to keep. Reentrancy hid this while there was
       only one guard. */
    /* The datagram has already been handed to the caller, so there is
       nothing to refuse here; an exhausted table costs this socket its
       reply path and says so in the log (B-47). */
    (void)network_stack_map_socket_unlocked(sockfd, entry.flow_id,
                                            NETWORK_IP_PROTO_UDP);
    { network_stack_unlock(); return bytes_read; }
  }
  { network_stack_unlock(); return 0; }
  network_stack_unlock();
}

uint32_t network_stack_udp_recv(uint64_t sockfd, uint8_t *buffer,
                                uint32_t buffer_size,
                                xaios_ip_addr_t *source_addr,
                                uint16_t *source_port,
                                uint32_t *flow_id) {
  network_stack_lock();
  uint32_t result = network_stack_udp_recv_unlocked(sockfd, buffer, buffer_size, source_addr, source_port, flow_id);
  network_stack_unlock();
  return result;
}

xaios_status_t network_stack_process_udp_frame_v6(const uint8_t *frame,
                                                  uint64_t frame_len) {
  if (frame == 0 || frame_len < 62U) {
    net_udp_note_dropped();
    net_udp_note_malformed();
    net_note_packet_drop();
    return XAIOS_ERR_INVALID;
  }

  uint64_t start = timer_now_ns();
  uint16_t src_port = 0;
  uint16_t dst_port = 0;
  uint16_t payload_len = 0;
  xaios_ip_addr_t src_addr;
  xaios_ip_addr_t dst_addr;
  xaios_ip_addr_zero(&src_addr);
  xaios_ip_addr_zero(&dst_addr);

  if (net_wire_parse_udp_v6(frame, frame_len, &src_port, &dst_port, &payload_len,
                   &src_addr, &dst_addr) == 0) {
    net_udp_note_dropped();
    net_udp_note_malformed();
    net_note_packet_drop();
    return XAIOS_ERR_INVALID;
  }
  if (src_port == 0 || dst_port == 0 || payload_len == 0) {
    net_udp_note_dropped();
    net_note_packet_drop();
    return XAIOS_ERR_INVALID;
  }

  network_udp_flow_t existing_row;
  int have_existing = net_udp_flow_find_v6(dst_port, src_port, &dst_addr,
                                           &src_addr, &existing_row);
  network_queue_binding_t binding;
  int have_binding =
      have_existing != 0
          ? net_queue_binding_find(existing_row.queue_id, &binding)
          : net_queue_binding_select(dst_port, src_port,
                                     xaios_ip_addr_hash(&dst_addr),
                                     xaios_ip_addr_hash(&src_addr), &binding);
  if (have_binding == 0) {
    net_udp_note_dropped();
    net_note_packet_drop();
    return XAIOS_ERR_NOT_FOUND;
  }

  /* The legacy IPv4 projections the old code copied out of the packet
     descriptor: 0 for a v6 packet, exactly the value the descriptor held. */
  uint32_t legacy_src_address = 0U;
  uint32_t legacy_dst_address = 0U;
  if (src_addr.family == XAIOS_IP_FAMILY_V4) {
    legacy_src_address = xaios_ip_addr_to_ipv4(&src_addr);
    legacy_dst_address = xaios_ip_addr_to_ipv4(&dst_addr);
  }

  uint32_t packet =
      net_packet_alloc(binding.queue_id, frame_len, start, src_port, dst_port,
                       legacy_src_address, legacy_dst_address, &src_addr,
                       &dst_addr);
  if (packet == 0) {
    net_udp_note_dropped();
    return XAIOS_ERR_NO_MEMORY;
  }

  network_udp_flow_t flow_row;
  uint32_t flow_index = 0U;
  if (!net_udp_flow_alloc(binding.queue_id, binding.cell_id, dst_port, src_port,
                          legacy_dst_address, legacy_src_address, &dst_addr,
                          &src_addr, start, &flow_row, &flow_index)) {
    net_udp_note_dropped();
    net_packet_mark_dropped(packet);
    return XAIOS_ERR_NO_MEMORY;
  }
  /* The IPv6 address fields are set by net_udp_flow_alloc(), before the
     queue/core mismatch test below, exactly where the old handler wrote them
     onto the table row. */
  if (flow_row.queue_id != binding.queue_id ||
      flow_row.cell_id != binding.cell_id) {
    net_stack_note_flow_core_mismatch();
    net_packet_mark_dropped(packet);
    return XAIOS_ERR_BUSY;
  }
  ++flow_row.packets_rx;
  net_udp_note_rx();
  net_stack_note_ipv6_rx();
  for (uint32_t i = 0; i < 6U; ++i) {
    flow_row.remote_mac[i] = frame[6U + i];
  }
  flow_row.remote_mac_valid = 1;
  net_udp_flow_commit(flow_index, &flow_row);
  
  /* Deliver UDP payload to flow rx_buf */
  if (flow_row.rx_buf != 0 && payload_len > 8) {
    /* IPv6 header is 40 bytes at offset 14 */
    const uint8_t *udp_payload = frame + 14U + 40U + 8U;
    uint32_t data_len = (uint32_t)(payload_len - 8U);
    /* Same as the IPv4 path: the row is copied out under the guard, so no
       pointer into the registry crosses udp_listener_enqueue(). */
    network_stack_lock();
    network_listener_ex_t listener_row;
    uint32_t listener_backlog = 0U;
    int listener_found = 0;
    for (uint32_t i = 0; i < network_listener_slot_count(); ++i) {
      if (!network_listener_slot_read(i, &listener_row)) continue;
      if (listener_row.port == dst_port &&
          listener_row.protocol == NETWORK_IP_PROTO_UDP) {
        listener_backlog = listener_row.backlog_count;
        listener_found = 1;
        break;
      }
    }
    if (listener_found != 0) {
      if (listener_backlog >= NETWORK_LISTENER_BACKLOG ||
          data_len > sockbuf_available(flow_row.rx_buf) ||
          sockbuf_write(flow_row.rx_buf, udp_payload, data_len) != data_len ||
          !udp_listener_enqueue(dst_port, flow_row.flow_id, src_port, &src_addr,
                                (uint16_t)data_len)) {
        network_stack_unlock();
        net_udp_note_dropped();
        net_packet_mark_dropped(packet);
        return XAIOS_ERR_BUSY;
      }
    }
    network_stack_unlock();
  }
  
  net_packet_mark_tx(packet);
  ++flow_row.packets_tx;
  net_udp_note_tx();
  net_udp_flow_commit(flow_index, &flow_row);
  net_packet_mark_complete(packet);
  net_udp_record_latency(timer_now_ns() - start);
  return XAIOS_OK;
}
