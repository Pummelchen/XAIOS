/*
 * The application/external-session plane, moved verbatim out of
 * network_stack.c: the synthetic IPv4 frames the loopback echo and connect
 * tests build, the echo and connect entry points themselves, and the external
 * session dispatcher that formats their result. See network_stack_app.h for the
 * interface and the locking contract.
 */

#include "network_stack_app.h"

#include "network_stack_tcp.h"
#include "network_stack_wire.h"

#include <xaios/assert.h>
#include <xaios/ipv4.h>
#include <xaios/klog.h>
#include <xaios/network_stack.h>

static void build_app_udp_frame(uint8_t *frame, uint64_t payload_len) {
  net_wire_bytes_zero(frame, NETWORK_BUFFER_SIZE);
  frame[12U] = 0x08;
  frame[13U] = 0x00;
  frame[14U] = 0x45;
  frame[15U] = 0x00;
  const uint16_t total = (uint16_t)(20U + 8U + payload_len);
  frame[16U] = (uint8_t)(total >> 8U);
  frame[17U] = (uint8_t)total;
  frame[22U] = 64;
  frame[23U] = NETWORK_IP_PROTO_UDP;
  frame[26U] = 10;
  frame[27U] = 0;
  frame[28U] = 2;
  frame[29U] = 15;
  frame[30U] = 10;
  frame[31U] = 0;
  frame[32U] = 2;
  frame[33U] = 2;
  frame[34U] = 0x60;
  frame[35U] = 0x01;
  frame[36U] = 0x22;
  frame[37U] = 0xB8;
  const uint16_t udp_len = (uint16_t)(8U + payload_len);
  frame[38U] = (uint8_t)(udp_len >> 8U);
  frame[39U] = (uint8_t)udp_len;
  net_wire_write_be16(frame + 24U, ipv4_checksum(frame + 14U, 20U));
}

static void build_app_tcp_frame(uint8_t *frame, uint8_t flags,
                                uint16_t remote_port) {
  net_wire_bytes_zero(frame, NETWORK_BUFFER_SIZE);
  frame[12U] = 0x08;
  frame[13U] = 0x00;
  frame[14U] = 0x45;
  frame[15U] = 0x00;
  frame[16U] = 0x00;
  frame[17U] = 0x2c;
  frame[22U] = 64;
  frame[23U] = NETWORK_IP_PROTO_TCP;
  frame[26U] = 10;
  frame[27U] = 0;
  frame[28U] = 2;
  frame[29U] = 15;
  frame[30U] = 10;
  frame[31U] = 0;
  frame[32U] = 2;
  frame[33U] = 2;
  frame[34U] = (uint8_t)(remote_port >> 8U);
  frame[35U] = (uint8_t)remote_port;
  frame[36U] = 0x00;
  frame[37U] = 0x16;
  frame[41U] = 1;
  frame[46U] = 0x60;
  frame[47U] = flags;
}

static void finalize_app_tcp_frame(uint8_t *frame) {
  frame[50U] = 0U;
  frame[51U] = 0U;
  uint16_t checksum =
      ipv4_pseudo_checksum(UINT32_C(0x0a00020f), UINT32_C(0x0a000202),
                           NETWORK_IP_PROTO_TCP, 24U, frame + 34U, 24U);
  net_wire_write_be16(frame + 50U, checksum == 0U ? UINT16_MAX : checksum);
  frame[24U] = 0U;
  frame[25U] = 0U;
  net_wire_write_be16(frame + 24U, ipv4_checksum(frame + 14U, 20U));
}

static xaios_status_t network_stack_app_udp_echo_unlocked(const uint8_t *payload,
                                         uint64_t payload_len,
                                         uint64_t *echoed_bytes) {
  if (payload == 0 || echoed_bytes == 0 || payload_len == 0 ||
      payload_len > 64U) {
    return XAIOS_ERR_INVALID;
  }

  uint8_t frame[NETWORK_BUFFER_SIZE];
  build_app_udp_frame(frame, payload_len);
  for (uint64_t i = 0; i < payload_len; ++i) {
    frame[42U + i] = payload[i];
  }

  const uint32_t queue_id = 3U;
  const uint32_t cell_id = 3U;
  if (network_stack_bind_queue(cell_id, queue_id, 0x8U) != XAIOS_OK) {
    return XAIOS_ERR_BUSY;
  }
  xaios_status_t status = network_stack_process_udp_frame(frame, 42U + payload_len);
  kassert(network_stack_release_queue(queue_id, cell_id) == XAIOS_OK);
  if (status != XAIOS_OK) {
    return status;
  }
  *echoed_bytes = payload_len;
  klog("network: app udp echo payload=%lu queue=%u cell=%u\n",
       payload_len, queue_id, cell_id);
  return XAIOS_OK;
}

xaios_status_t network_stack_app_udp_echo(const uint8_t *payload,
                                         uint64_t payload_len,
                                         uint64_t *echoed_bytes) {
  network_stack_lock();
  xaios_status_t result = network_stack_app_udp_echo_unlocked(payload, payload_len, echoed_bytes);
  network_stack_unlock();
  return result;
}

static xaios_status_t network_stack_app_tcp_connect_unlocked(uint64_t *round_trips) {
  if (round_trips == 0) {
    return XAIOS_ERR_INVALID;
  }

  const uint32_t queue_id = 3U;
  const uint32_t cell_id = 3U;
  uint8_t syn[NETWORK_BUFFER_SIZE];
  uint8_t ack[NETWORK_BUFFER_SIZE];
  uint8_t rst[NETWORK_BUFFER_SIZE];
  const uint16_t remote_port = 0x6010U;
  const uint16_t local_port = 22U;
  int temporary_listener = 0;

  if (!network_stack_has_listener(local_port)) {
    if (network_stack_register_listener(local_port, UINT64_MAX) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
    temporary_listener = 1;
  }

  if (network_stack_bind_queue(cell_id, queue_id, 0x8U) != XAIOS_OK) {
    if (temporary_listener != 0) {
      network_stack_unregister_listener(local_port);
    }
    return XAIOS_ERR_BUSY;
  }
  build_app_tcp_frame(syn, NETWORK_TCP_FLAG_SYN, remote_port);
  build_app_tcp_frame(ack, NETWORK_TCP_FLAG_ACK, remote_port);
  build_app_tcp_frame(rst, NETWORK_TCP_FLAG_RST, remote_port);
  ack[48U] = 0x40U;
  rst[48U] = 0x40U;
  finalize_app_tcp_frame(syn);

  xaios_status_t status = network_stack_process_tcp_frame(syn, 58U);
  if (status == XAIOS_OK) {
    /* The half-open row is copied out under the guard rather than pointed at:
       see net_stack_tcp_flow_read_syn_recv_seqs(). */
    uint32_t expected_seq = 0U;
    uint32_t next_send_seq = 0U;
    if (!net_stack_tcp_flow_read_syn_recv_seqs(local_port, remote_port,
                                               &expected_seq,
                                               &next_send_seq)) {
      status = XAIOS_ERR_NOT_FOUND;
    } else {
      net_wire_write_be32(ack + 38U, expected_seq);
      net_wire_write_be32(ack + 42U, next_send_seq);
      net_wire_write_be32(rst + 38U, expected_seq);
      net_wire_write_be32(rst + 42U, next_send_seq);
      finalize_app_tcp_frame(ack);
      finalize_app_tcp_frame(rst);
    }
  }
  if (status == XAIOS_OK) {
    status = network_stack_process_tcp_frame(ack, 58U);
  }
  if (status == XAIOS_OK) {
    if (network_stack_process_tcp_frame(rst, 58U) == XAIOS_ERR_INVALID) {
      status = XAIOS_OK;
    } else {
      status = XAIOS_ERR_IO;
    }
  }
  kassert(network_stack_release_queue(queue_id, cell_id) == XAIOS_OK);
  if (temporary_listener != 0) {
    network_stack_unregister_listener(local_port);
  }
  if (status != XAIOS_OK) return status;
  *round_trips = 2U;
  klog("network: app tcp connect-close queue=%u cell=%u round_trips=%lu\n",
       queue_id, cell_id, *round_trips);
  return XAIOS_OK;
}

xaios_status_t network_stack_app_tcp_connect(uint64_t *round_trips) {
  network_stack_lock();
  xaios_status_t result = network_stack_app_tcp_connect_unlocked(round_trips);
  network_stack_unlock();
  return result;
}

static void network_append(char *output, uint64_t capacity, uint64_t *offset,
                           const char *text) {
  if (output == 0 || offset == 0 || text == 0 || capacity == 0) {
    return;
  }
  for (uint64_t i = 0; text[i] != '\0' && *offset + 1U < capacity; ++i) {
    output[*offset] = text[i];
    ++(*offset);
  }
  output[*offset] = '\0';
}

static void network_append_u64(char *output, uint64_t capacity,
                               uint64_t *offset, uint64_t value) {
  char digits[20];
  uint64_t count = 0;
  if (value == 0) {
    network_append(output, capacity, offset, "0");
    return;
  }
  while (value != 0 && count < sizeof(digits)) {
    digits[count++] = (char)('0' + (value % 10U));
    value /= 10U;
  }
  while (count > 0) {
    char one[2];
    --count;
    one[0] = digits[count];
    one[1] = '\0';
    network_append(output, capacity, offset, one);
  }
}

static xaios_status_t network_stack_external_session_unlocked(uint64_t protocol, uint64_t port,
                                             const uint8_t *payload,
                                             uint64_t payload_len,
                                             char *output,
                                             uint64_t output_capacity,
                                             uint64_t *output_bytes) {
  if (payload == 0 || payload_len == 0 || payload_len > 64U ||
      output == 0 || output_capacity < 16U || output_bytes == 0 ||
      port == 0 || port > 65535U) {
    return XAIOS_ERR_INVALID;
  }

  output[0] = '\0';
  uint64_t offset = 0;
  if (protocol == XAIOS_NETWORK_PROTOCOL_UDP) {
    uint64_t echoed = 0;
    if (network_stack_app_udp_echo(payload, payload_len, &echoed) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
    network_append(output, output_capacity, &offset, "udp:");
    network_append_u64(output, output_capacity, &offset, port);
    network_append(output, output_capacity, &offset, ":echo:");
    network_append_u64(output, output_capacity, &offset, echoed);
    network_append(output, output_capacity, &offset, "\n");
    *output_bytes = offset;
    klog("network: external host udp session port=%lu bytes=%lu echoed=%lu\n",
         port, payload_len, echoed);
    return XAIOS_OK;
  }

  if (protocol == XAIOS_NETWORK_PROTOCOL_TCP) {
    uint64_t round_trips = 0;
    if (network_stack_app_tcp_connect(&round_trips) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
    network_append(output, output_capacity, &offset, "tcp:");
    network_append_u64(output, output_capacity, &offset, port);
    network_append(output, output_capacity, &offset, ":established:");
    network_append_u64(output, output_capacity, &offset, round_trips);
    network_append(output, output_capacity, &offset, "\n");
    *output_bytes = offset;
    klog("network: external host tcp session port=%lu bytes=%lu round_trips=%lu\n",
         port, payload_len, round_trips);
    return XAIOS_OK;
  }

  return XAIOS_ERR_INVALID;
}

xaios_status_t network_stack_external_session(uint64_t protocol, uint64_t port,
                                             const uint8_t *payload,
                                             uint64_t payload_len,
                                             char *output,
                                             uint64_t output_capacity,
                                             uint64_t *output_bytes) {
  network_stack_lock();
  xaios_status_t result = network_stack_external_session_unlocked(protocol, port, payload, payload_len, output, output_capacity, output_bytes);
  network_stack_unlock();
  return result;
}
