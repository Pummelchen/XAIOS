/*
 * The boot-time network self-test, moved verbatim out of network_stack.c: the
 * latency snapshot, the listener-pool capacity check and
 * network_stack_self_test(). See network_stack_selftest.h for the interface.
 */

#include "network_stack_selftest.h"

#include "network_stack_app.h"
#include "network_stack_listener.h"
#include "network_stack_tcp.h"
#include "network_stack_udp.h"
#include "network_stack_v6.h"
#include "network_stack_wire.h"

#include <xaios/assert.h>
#include <xaios/icmpv6.h>
#include <xaios/ip_addr.h>
#include <xaios/ipv4.h>
#include <xaios/klog.h>
#include <xaios/network_stack.h>
#include <xaios/timer.h>

static void emit_latency_snapshot(uint64_t *udp50, uint64_t *udp95,
                                 uint64_t *udp99, uint64_t *udp999,
                                 uint64_t *tcp50, uint64_t *tcp95,
                                 uint64_t *tcp99, uint64_t *tcp999) {
  *udp50 = network_stack_udp_latency_p50_ns();
  *udp95 = network_stack_udp_latency_p95_ns();
  *udp99 = network_stack_udp_latency_p99_ns();
  *udp999 = network_stack_udp_latency_p999_ns();
  *tcp50 = network_stack_tcp_latency_p50_ns();
  *tcp95 = network_stack_tcp_latency_p95_ns();
  *tcp99 = network_stack_tcp_latency_p99_ns();
  *tcp999 = network_stack_tcp_latency_p999_ns();
}

static void listener_pool_capacity_self_test(void) {
  uint64_t sockfd = 1000U;
  for (uint32_t i = 0; i < NETWORK_MAX_UDP_LISTENERS; ++i) {
    kassert(network_stack_register_udp_listener((uint16_t)(0x6000U + i),
                                                sockfd++) == XAIOS_OK);
  }
  kassert(network_stack_register_udp_listener(UINT16_C(0x7000), sockfd++) ==
          XAIOS_ERR_NO_MEMORY);
  /* The UDP pool is full and the TCP pool has not noticed: all sixteen rows
     are still there, and TCP refuses only at sixteen of its own. */
  for (uint32_t i = 0; i < NETWORK_MAX_TCP_LISTENERS; ++i) {
    kassert(network_stack_register_listener((uint16_t)(0x7001U + i),
                                            sockfd++) == XAIOS_OK);
  }
  kassert(network_stack_register_listener(UINT16_C(0x7100), sockfd++) ==
          XAIOS_ERR_NO_MEMORY);
  for (uint32_t i = 0; i < NETWORK_MAX_UDP_LISTENERS; ++i) {
    network_stack_unregister_udp_listener((uint16_t)(0x6000U + i));
  }
  for (uint32_t i = 0; i < NETWORK_MAX_TCP_LISTENERS; ++i) {
    network_stack_unregister_listener((uint16_t)(0x7001U + i));
  }
}

void network_stack_self_test(void) {
  uint8_t frame_udp[NETWORK_BUFFER_SIZE];
  uint8_t frame_udp_bad[NETWORK_BUFFER_SIZE];
  uint8_t frame_tcp_syn[NETWORK_BUFFER_SIZE];
  uint8_t frame_tcp_syn_ack[NETWORK_BUFFER_SIZE];
  uint8_t frame_tcp_timeout[NETWORK_BUFFER_SIZE];
  net_wire_bytes_zero(frame_udp, sizeof(frame_udp));
  net_wire_bytes_zero(frame_udp_bad, sizeof(frame_udp_bad));
  net_wire_bytes_zero(frame_tcp_syn, sizeof(frame_tcp_syn));
  net_wire_bytes_zero(frame_tcp_syn_ack, sizeof(frame_tcp_syn_ack));
  net_wire_bytes_zero(frame_tcp_timeout, sizeof(frame_tcp_timeout));

  network_stack_init();
  listener_pool_capacity_self_test();
  net_stack_tcp_sliding_window_self_test();

  kassert(network_stack_bind_queue(0, 1, 0x2U) == XAIOS_OK);
  kassert(network_stack_bind_queue(0, 1, 0x2U) == XAIOS_ERR_BUSY);
  kassert(network_stack_bind_queue(1, 2, 0x4U) == XAIOS_OK);
  kassert(network_stack_bind_queue(2, 2, 0x8U) == XAIOS_ERR_BUSY);

  kassert(network_stack_release_queue(2, 1) == XAIOS_OK);
  kassert(network_stack_bind_queue(1, 2, 0x4U) == XAIOS_OK);

  kassert(network_stack_queue_bindings() == 2U);
  kassert(network_stack_register_listener(80U, 1U) == XAIOS_OK);
  kassert(network_stack_register_udp_listener(UINT16_C(0x5678), 2U) == XAIOS_OK);

  frame_udp[12U] = 0x08;
  frame_udp[13U] = 0x00;
  frame_udp[14U] = 0x45;
  frame_udp[15U] = 0x00;
  frame_udp[16U] = 0x00;
  frame_udp[17U] = 0x20;
  frame_udp[18U] = 0x00;
  frame_udp[19U] = 0x00;
  frame_udp[20U] = 0x00;
  frame_udp[21U] = 0x00;
  frame_udp[22U] = 64;
  frame_udp[23U] = NETWORK_IP_PROTO_UDP;
  frame_udp[24U] = 0x00;
  frame_udp[25U] = 0x00;
  frame_udp[26U] = 10;
  frame_udp[27U] = 0;
  frame_udp[28U] = 2;
  frame_udp[29U] = 15;
  frame_udp[30U] = 10;
  frame_udp[31U] = 0;
  frame_udp[32U] = 2;
  frame_udp[33U] = 2;
  frame_udp[34U] = 0x12;
  frame_udp[35U] = 0x34;
  frame_udp[36U] = 0x56;
  frame_udp[37U] = 0x78;
  frame_udp[38U] = 0x00;
  frame_udp[39U] = 0x0C;
  frame_udp[40U] = 0x00;
  frame_udp[41U] = 0x00;
  frame_udp[42U] = 1;
  frame_udp[43U] = 2;
  frame_udp[44U] = 3;
  frame_udp[45U] = 4;
  net_wire_write_be16(frame_udp + 24U, ipv4_checksum(frame_udp + 14U, 20U));

  kassert(network_stack_process_udp_frame(frame_udp, 46U) == XAIOS_OK);
  kassert(network_stack_process_udp_frame(frame_udp, 46U) == XAIOS_OK);
  {
    uint8_t short_datagram[4];
    kassert(network_stack_udp_recv(2U, short_datagram, 2U, 0, 0, 0) == 2U);
    kassert(short_datagram[0] == 1U && short_datagram[1] == 2U);
    kassert(network_stack_udp_recv(2U, short_datagram, sizeof(short_datagram),
                                   0, 0, 0) == sizeof(short_datagram));
    kassert(short_datagram[0] == 1U && short_datagram[1] == 2U &&
            short_datagram[2] == 3U && short_datagram[3] == 4U);
  }
  {
    /* The refusals on the send-to-a-named-peer path, which is the half of
       B-29 that no boot exercises.
   
       The positive half of that fix is demonstrated by /bin/netmqtest and by
       the driver's own transmit counters, and it cannot be demonstrated here:
       a real datagram needs a device, and this self-test runs against frames
       it builds itself. What can be pinned here is that the path refuses what
       it must refuse, which is the control the positive result needs -- a
       send that returned XAIOS_OK for every set of arguments would make
       frames_sent=16 meaningless. None of these calls allocates a flow or
       touches a counter, deliberately, so the figures asserted below still
       describe the receive path alone. */
    xaios_ip_addr_t probe_v4 = xaios_ip_addr_from_ipv4(XAIOS_IPV4_GATEWAY);
    xaios_ip_addr_t probe_v6;
    xaios_ip_addr_zero(&probe_v6);
    probe_v6.family = XAIOS_IP_FAMILY_V6;
    const uint8_t probe_payload[4] = {9U, 8U, 7U, 6U};
    uint32_t probe_written = 0xffffffffU;
    kassert(network_stack_udp_sendto(0U, &probe_v4, 9U, probe_payload,
                                     sizeof(probe_payload), &probe_written,
                                     0) == XAIOS_ERR_INVALID);
    kassert(network_stack_udp_sendto(24000U, &probe_v4, 0U, probe_payload,
                                     sizeof(probe_payload), &probe_written,
                                     0) == XAIOS_ERR_INVALID);
    kassert(network_stack_udp_sendto(24000U, 0, 9U, probe_payload,
                                     sizeof(probe_payload), &probe_written,
                                     0) == XAIOS_ERR_INVALID);
    kassert(network_stack_udp_sendto(24000U, &probe_v4, 9U, probe_payload, 0U,
                                     &probe_written, 0) == XAIOS_ERR_INVALID);
    /* IPv6 is refused rather than attempted: see network_stack_udp_sendto. A
       machine that grows the v6 transmit path will fail this line, which is
       the right place to be reminded that the refusal was deliberate. */
    kassert(network_stack_udp_sendto(24000U, &probe_v6, 9U, probe_payload,
                                     sizeof(probe_payload), &probe_written,
                                     0) == XAIOS_ERR_UNSUPPORTED);
    kassert(network_stack_udp_flow_count() == 1U);
  }
  kassert(network_stack_udp_rx_count() == 2U);
  kassert(network_stack_udp_flow_hit_count() == 1U);
  kassert(network_stack_udp_flow_count() == 1U);
  kassert(network_stack_expire_udp_flows(timer_now_ns() +
                                         NETWORK_UDP_IDLE_TIMEOUT_NS + 1U) ==
          1U);
  kassert(network_stack_udp_expired_count() == 1U);
  kassert(network_stack_udp_flow_count() == 0U);
  kassert(network_stack_process_udp_frame(frame_udp, 46U) == XAIOS_OK);
  kassert(network_stack_udp_rx_count() == 3U);
  kassert(network_stack_udp_flow_count() == 1U);
  frame_udp_bad[13] = 0x06;
  kassert(network_stack_process_udp_frame(frame_udp_bad, 4U) == XAIOS_ERR_INVALID);
  kassert(network_stack_udp_dropped_count() == 1U);
  kassert(network_stack_udp_malformed_count() == 1U);

  frame_tcp_syn[12] = 0x08;
  frame_tcp_syn[13] = 0x00;
  frame_tcp_syn[14] = 0x45;
  frame_tcp_syn[15] = 0x00;
  frame_tcp_syn[16] = 0x00;
  frame_tcp_syn[17] = 0x2c;
  frame_tcp_syn[18] = 0x00;
  frame_tcp_syn[19] = 0x00;
  frame_tcp_syn[20] = 0x40;
  frame_tcp_syn[21] = 0x00;
  frame_tcp_syn[22] = 64;
  frame_tcp_syn[23] = NETWORK_IP_PROTO_TCP;
  frame_tcp_syn[26] = 10;
  frame_tcp_syn[27] = 0;
  frame_tcp_syn[28] = 2;
  frame_tcp_syn[29] = 15;
  frame_tcp_syn[30] = 10;
  frame_tcp_syn[31] = 0;
  frame_tcp_syn[32] = 2;
  frame_tcp_syn[33] = 2;

  frame_tcp_syn[34] = 0x1f;
  frame_tcp_syn[35] = 0x90;
  frame_tcp_syn[36] = 0x00;
  frame_tcp_syn[37] = 0x50;
  frame_tcp_syn[38] = 0;
  frame_tcp_syn[39] = 0;
  frame_tcp_syn[40] = 0;
  frame_tcp_syn[41] = 1;
  frame_tcp_syn[42] = 0;
  frame_tcp_syn[43] = 0;
  frame_tcp_syn[44] = 0;
  frame_tcp_syn[45] = 0;
  frame_tcp_syn[46] = 0x60; /* offset 6 words */
  frame_tcp_syn[47] = NETWORK_TCP_FLAG_SYN;
  {
    uint16_t tcp_checksum =
        ipv4_pseudo_checksum(0x0a00020fU, 0x0a000202U,
                             NETWORK_IP_PROTO_TCP, 24U,
                             frame_tcp_syn + 34U, 24U);
    frame_tcp_syn[50] = (uint8_t)(tcp_checksum >> 8U);
    frame_tcp_syn[51] = (uint8_t)tcp_checksum;
  }
  net_wire_write_be16(frame_tcp_syn + 24U,
             ipv4_checksum(frame_tcp_syn + 14U, 20U));

  frame_tcp_timeout[0] = 0U;
  for (uint32_t i = 0; i < 58U; ++i) frame_tcp_timeout[i] = frame_tcp_syn[i];
  frame_tcp_timeout[50U] = 0U;
  frame_tcp_timeout[51U] = 0U;
  kassert(net_wire_parse_tcp(frame_tcp_timeout, 58U, &(uint16_t){0}, &(uint16_t){0},
                    &(uint32_t){0}, &(uint32_t){0}, &(uint8_t){0}) == 0);

  kassert(network_stack_process_tcp_frame(frame_tcp_syn, 58U) == XAIOS_OK);
  kassert(network_stack_tcp_handshake_count() == 1U);
  kassert(network_stack_tcp_connections() == 0U);

  frame_tcp_syn_ack[14] = 0x45;
  for (uint32_t i = 0; i < 58U; ++i) {
    frame_tcp_syn_ack[i] = frame_tcp_syn[i];
  }
  frame_tcp_syn_ack[14] = frame_tcp_syn[14];
  frame_tcp_syn_ack[23] = NETWORK_IP_PROTO_TCP;
  frame_tcp_syn_ack[34] = 0x1f;
  frame_tcp_syn_ack[35] = 0x90;
  frame_tcp_syn_ack[36] = 0x00;
  frame_tcp_syn_ack[37] = 0x50;
  frame_tcp_syn_ack[38] = 0;
  frame_tcp_syn_ack[39] = 0;
  frame_tcp_syn_ack[40] = 0;
  frame_tcp_syn_ack[41] = 0;
  /* The SYN-RECV row for this frame's tuple (local port 80, remote
     0x1f90), copied out instead of dereferenced through g_tcp_flows. */
  uint32_t syn_expected_seq = 0U;
  uint32_t syn_next_send_seq = 0U;
  (void)net_stack_tcp_flow_read_syn_recv_seqs(UINT16_C(80),
                                              UINT16_C(0x1f90),
                                              &syn_expected_seq,
                                              &syn_next_send_seq);
  net_wire_write_be32(frame_tcp_syn_ack + 38U, syn_expected_seq);
  net_wire_write_be32(frame_tcp_syn_ack + 42U, syn_next_send_seq);
  frame_tcp_syn_ack[46] = 0x60; /* offset 6 words */
  frame_tcp_syn_ack[47] = NETWORK_TCP_FLAG_ACK;
  frame_tcp_syn_ack[48] = 0x40;
  frame_tcp_syn_ack[49] = 0x00;
  frame_tcp_syn_ack[50] = 0;
  frame_tcp_syn_ack[51] = 0;
  {
    uint16_t tcp_checksum =
        ipv4_pseudo_checksum(0x0a00020fU, 0x0a000202U,
                             NETWORK_IP_PROTO_TCP, 24U,
                             frame_tcp_syn_ack + 34U, 24U);
    net_wire_write_be16(frame_tcp_syn_ack + 50U,
               tcp_checksum == 0U ? UINT16_MAX : tcp_checksum);
  }

  kassert(network_stack_process_tcp_frame(frame_tcp_syn_ack, 58U) == XAIOS_OK);
  kassert(network_stack_tcp_connections() == 1U);
  kassert(network_stack_tcp_established_count() == 1U);

  for (uint32_t i = 0; i < 58U; ++i) {
    frame_tcp_timeout[i] = frame_tcp_syn[i];
  }
  frame_tcp_timeout[35] = 0x91;
  frame_tcp_timeout[50] = 0;
  frame_tcp_timeout[51] = 0;
  {
    uint16_t tcp_checksum =
        ipv4_pseudo_checksum(0x0a00020fU, 0x0a000202U,
                             NETWORK_IP_PROTO_TCP, 24U,
                             frame_tcp_timeout + 34U, 24U);
    net_wire_write_be16(frame_tcp_timeout + 50U,
               tcp_checksum == 0U ? UINT16_MAX : tcp_checksum);
  }
  kassert(network_stack_process_tcp_frame(frame_tcp_timeout, 58U) == XAIOS_OK);
  kassert(network_stack_retransmit_tcp_flows(timer_now_ns() +
                                             NETWORK_TCP_RETRANSMIT_NS + 1U) ==
          1U);
  kassert(network_stack_tcp_retransmit_count() == 1U);
  kassert(network_stack_expire_tcp_flows(timer_now_ns() +
                                         NETWORK_TCP_RETRANSMIT_NS +
                                         NETWORK_TCP_SYN_TIMEOUT_NS + 2U) ==
          1U);
  kassert(network_stack_tcp_timeout_count() == 1U);
  kassert(network_stack_tcp_closed_count() == 1U);
  kassert(network_stack_tcp_connections() == 1U);

  kassert(network_stack_release_queue(1, 0) == XAIOS_OK);
  kassert(network_stack_release_queue(2, 1) == XAIOS_OK);
  network_stack_unregister_udp_listener(UINT16_C(0x5678));
  kassert(network_stack_queue_bindings() == 0U);

  {
    uint8_t ra_frame[14U + 40U + 16U + 32U] = {0};
    uint8_t saved_mac[6];
    const uint8_t test_mac[6] = {0x02U, 0x11U, 0x22U,
                                 0x33U, 0x44U, 0x55U};
    net_stack_local_mac(saved_mac);
    net_stack_local_mac_set(test_mac);
    net_wire_write_be16(ra_frame + 18U, 48U);
    uint8_t *ra_icmpv6 = ra_frame + XAIOS_ICMPV6_OFFSET;
    ra_icmpv6[0] = XAIOS_ICMPV6_ROUTER_ADVERT;
    ra_icmpv6[16] = 3U; /* Prefix Information option */
    ra_icmpv6[17] = 4U; /* 32 bytes */
    ra_icmpv6[18] = 64U;
    ra_icmpv6[19] = UINT8_C(0x40); /* Autonomous address configuration */
    net_wire_write_be32(ra_icmpv6 + 20U, 60U);
    ra_icmpv6[32] = UINT8_C(0x20);
    ra_icmpv6[33] = UINT8_C(0x01);
    ra_icmpv6[34] = UINT8_C(0x0d);
    ra_icmpv6[35] = UINT8_C(0xb8);
    xaios_ip_addr_t public_v6;
    uint64_t public_v6_valid_until_ns = 0U;
    net_v6_reset_public();
    net_v6_apply_router_advertisement(ra_frame, sizeof(ra_frame), 10U,
                                      test_mac);
    net_v6_public_read(&public_v6, &public_v6_valid_until_ns);
    kassert(net_v6_is_global_unicast(&public_v6));
    kassert(public_v6.addr[0] == UINT8_C(0x20));
    kassert(public_v6.addr[8] == 0U);
    kassert(public_v6.addr[11] == UINT8_C(0xff));
    kassert(public_v6.addr[12] == UINT8_C(0xfe));
    kassert(public_v6.addr[15] == UINT8_C(0x55));
    kassert(public_v6_valid_until_ns == UINT64_C(60000000010));
    ra_icmpv6[17] = 0U;
    net_v6_reset_public();
    net_v6_apply_router_advertisement(ra_frame, sizeof(ra_frame), 10U,
                                      test_mac);
    net_v6_public_read(&public_v6, &public_v6_valid_until_ns);
    kassert(!net_v6_is_global_unicast(&public_v6));
    net_stack_local_mac_set(saved_mac);
    klog("network: public IPv6 SLAAC self-test passed\n");
  }

  kassert(network_stack_udp_tx_count() == 3U);
  kassert(network_stack_udp_rx_count() == 3U);
  kassert(network_stack_tcp_reset_count() == 0U);
  kassert(network_stack_rx_packet_count() == 6U);
  kassert(network_stack_tx_packet_count() == 6U);
  kassert(network_stack_packet_drop_count() == 2U);
  kassert(network_stack_packet_lifecycle_count() == 18U);
  kassert(network_stack_queue_rx_enqueue_count() == 6U);
  kassert(network_stack_queue_tx_enqueue_count() == 6U);
  kassert(network_stack_queue_completion_count() == 6U);
  kassert(network_stack_queue_backpressure_drop_count() == 0U);
  kassert(network_stack_flow_core_mismatch_count() == 0U);

  {
    /* B-47: fill the socket-to-flow table and watch it refuse.
   
       Nothing in a boot fills this table, and nothing in the syscall paths
       could see it full, because the failure was a void return. So the only
       honest gate is to fill it here -- every row, from whatever the tests
       above left behind -- and then ask for one more. The probe descriptor is
       above anything the kernel socket allocator hands out, so it cannot
       collide with a real row.
   
       Three things are asserted, and they fail for three different reasons:
       the table really is full (a fill that quietly reused one row would
       prove nothing), the extra mapping is refused with a status the caller
       can act on (this is the line that goes red if the refusal is removed),
       and the probe descriptor genuinely has no mapping afterwards -- which
       is what the accept path used to hand to userspace without a word. */
    const uint64_t probe_base = UINT64_C(0x5841494f53000000);
    uint32_t capacity = network_stack_socket_map_capacity();
    uint32_t before = network_stack_socket_map_count();
    uint64_t exhausted_before = network_stack_socket_map_exhausted_count();
    uint32_t filled = 0U;
    kassert(before < capacity);
    for (uint32_t i = before; i < capacity; ++i) {
      kassert(network_stack_map_socket(probe_base + i, 0x4000U + i,
                                       NETWORK_IP_PROTO_TCP) == XAIOS_OK);
      ++filled;
    }
    kassert(network_stack_socket_map_count() == capacity);
    kassert(network_stack_socket_map_exhausted_count() == exhausted_before);

    socket_flow_mapping_t overflow_mapping;
    const uint64_t overflow_fd = probe_base + capacity;
    kassert(network_stack_map_socket(overflow_fd, 0x9999U,
                                     NETWORK_IP_PROTO_TCP) ==
            XAIOS_ERR_NO_MEMORY);
    kassert(network_stack_socket_map_exhausted_count() ==
            exhausted_before + 1U);
    kassert(network_stack_get_socket_mapping(overflow_fd,
                                             &overflow_mapping) == 0);
    /* A descriptor already in the table is still updated when the table is
       full -- the first scan matches before the second one runs out. Without
       this the refusal would break every established socket the moment one
       new one could not be admitted. */
    socket_flow_mapping_t rebind_mapping;
    kassert(network_stack_map_socket(probe_base + before, 0x7777U,
                                     NETWORK_IP_PROTO_TCP) == XAIOS_OK);
    kassert(network_stack_get_socket_mapping(probe_base + before,
                                             &rebind_mapping) != 0);
    kassert(rebind_mapping.flow_id == 0x7777U);
    kassert(network_stack_socket_map_exhausted_count() ==
            exhausted_before + 1U);

    for (uint32_t i = before; i < capacity; ++i) {
      network_stack_unmap_socket(probe_base + i);
    }
    kassert(network_stack_socket_map_count() == before);
    klog("network: socket-flow map exhaustion self-test passed capacity=%u "
         "filled=%u refused=%lu\n",
         capacity, filled,
         network_stack_socket_map_exhausted_count() - exhausted_before);
  }

  uint64_t udp50;
  uint64_t udp95;
  uint64_t udp99;
  uint64_t udp999;
  uint64_t tcp50;
  uint64_t tcp95;
  uint64_t tcp99;
  uint64_t tcp999;
  emit_latency_snapshot(&udp50, &udp95, &udp99, &udp999, &tcp50, &tcp95,
                        &tcp99, &tcp999);

  klog(
      "network: queue-backed udp/tcp self-test passed rx=%lu tx=%lu drops=%lu "
      "lifecycle=%lu udp_flows=%lu udp_hits=%lu udp_expired=%lu "
      "tcp_timeouts=%lu tcp_retransmits=%lu queue_rx=%lu queue_tx=%lu "
      "queue_done=%lu backpressure=%lu flow_mismatch=%lu udp_p50=%lu p95=%lu "
      "p99=%lu p999=%lu tcp_p50=%lu p95=%lu p99=%lu p999=%lu\n",
      network_stack_rx_packet_count(), network_stack_tx_packet_count(),
      network_stack_packet_drop_count(), network_stack_packet_lifecycle_count(),
      network_stack_udp_flow_count(), network_stack_udp_flow_hit_count(),
      network_stack_udp_expired_count(), network_stack_tcp_timeout_count(),
      network_stack_tcp_retransmit_count(),
      network_stack_queue_rx_enqueue_count(),
      network_stack_queue_tx_enqueue_count(),
      network_stack_queue_completion_count(),
      network_stack_queue_backpressure_drop_count(),
      network_stack_flow_core_mismatch_count(),
      udp50, udp95, udp99, udp999, tcp50, tcp95, tcp99, tcp999);
}
