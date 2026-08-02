#include "ssh_protocol.h"
#include "ssh_crypto.h"
#include "ssh_connection.h"
#include "ssh_utils.h"
#include <xaios_user.h>

uint32_t ssh_read_u32_be(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
         ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

void ssh_write_u32_be(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24); p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);  p[3] = (uint8_t)v;
}

uint32_t ssh_read_string_len(const uint8_t *p) {
  return ssh_read_u32_be(p);
}

static int send_all(int sockfd, const void *data, uint64_t len) {
  uint64_t sent = 0;
  while (sent < len) {
    u64 n = 0;
    int r = xaios_net_send((u64)(uint64_t)sockfd,
                          (const uint8_t *)data + sent, len - sent, &n);
    if (r != 0 || n == 0) return -1;
    sent += n;
  }
  return 0;
}

static int recv_all(int sockfd, void *data, uint64_t len) {
  uint64_t got = 0;
  while (got < len) {
    u64 n = 0;
    int r = xaios_net_recv((u64)(uint64_t)sockfd,
                          (uint8_t *)data + got, len - got, &n);
    if (r != 0 || n == 0) return -1;
    got += n;
  }
  return 0;
}

static void increment_counter(uint8_t counter[16], uint32_t blocks) {
  while (blocks-- != 0U) {
    for (int32_t index = 15; index >= 0; --index) {
      counter[index]++;
      if (counter[index] != 0U) break;
    }
  }
}

int ssh_send_version(int sockfd) {
  const char *version = SSH_VERSION_SERVER "\r\n";
  uint64_t len = 0;
  while (version[len]) ++len;
  return send_all(sockfd, version, len);
}

int ssh_recv_version(int sockfd, uint8_t *buf, uint32_t buf_size,
                     uint32_t *out_len) {
  /* Read until \n */
  uint32_t pos = 0;
  while (pos < buf_size) {
    u64 n = 0;
    int r = xaios_net_recv((u64)(uint64_t)sockfd, buf + pos, 1, &n);
    if (r != 0 || n == 0) return -1;
    
    /* FIX-003: Reject overly long version strings (buffer overflow protection) */
    if (pos > 255) {
      return -1;  /* Version string too long */
    }
    
    if (buf[pos] == '\n') {
      *out_len = pos + 1;
      return 0;
    }
    ++pos;
  }
  return -1;
}

int ssh_packet_read(int sockfd, ssh_packet_t *pkt) {
  /* Read 4-byte packet length */
  uint8_t len_buf[4];
  if (recv_all(sockfd, len_buf, 4) != 0) return -1;
  uint32_t pkt_len = ssh_read_u32_be(len_buf);
  
  /* FIX-003: Comprehensive packet size validation */
  if (pkt_len > SSH_MAX_PACKET_SIZE) {
    return -1;  /* Packet too large */
  }
  if (pkt_len < 2) {
    return -1;  /* Packet too small */
  }
  
  if (recv_all(sockfd, pkt->data, pkt_len) != 0) return -1;
  
  /* FIX-003: Validate padding length */
  uint32_t padding = pkt->data[0];
  if (padding >= pkt_len - 1) {
    return -1;  /* Invalid padding */
  }
  
  pkt->len = pkt_len - padding - 1;
  
  /* FIX-003: Validate payload length */
  if (pkt->len > SSH_MAX_PACKET_SIZE - 5) {
    return -1;  /* Payload too large */
  }
  
  /* Shift payload to start */
  for (uint32_t i = 0; i < pkt->len; ++i) {
    pkt->data[i] = pkt->data[1 + i];
  }
  return 0;
}

int ssh_packet_write(int sockfd, const uint8_t *data, uint32_t len) {
  const uint32_t block_size = 8U;
  if (len > SSH_MAX_PACKET_SIZE - 16U) return -1;
  uint32_t padding = block_size - ((len + 5U) % block_size);
  if (padding < 4U) padding += block_size;
  uint32_t packet_len = len + padding + 1U;
  uint32_t wire_len = packet_len + 4U;
  ssh_connection_scratch_t *scratch = ssh_conn_scratch();
  uint8_t *packet = scratch->encrypt_packet;
  ssh_write_u32_be(packet, packet_len);
  packet[4] = (uint8_t)padding;
  ssh_mem_copy(packet + 5U, data, len);
  crypto_random_bytes(packet + 5U + len, padding);
  return send_all(sockfd, packet, wire_len);
}

int ssh_packet_write_encrypted(int sockfd, const uint8_t *data, uint32_t len) {
  ssh_connection_t *conn = ssh_conn_find((uint64_t)(uint64_t)sockfd);
  if (!conn || !conn->crypto.enabled) return -1;

  const uint32_t block_size = 16U;
  const uint32_t mac_len = 32U;
  if (len > SSH_MAX_PACKET_SIZE - 32U) return -1;
  uint32_t padding = block_size - ((len + 5U) % block_size);
  if (padding < 4U) padding += block_size;
  uint32_t packet_len = len + padding + 1U;
  uint32_t encrypted_len = 4U + packet_len;
  if (encrypted_len + mac_len > SSH_MAX_PACKET_SIZE) return -1;

  ssh_connection_scratch_t *scratch = ssh_conn_scratch();
  uint8_t *plaintext = scratch->encrypt_packet;
  uint8_t *encrypted = scratch->encrypt_output;
  ssh_write_u32_be(plaintext, packet_len);
  plaintext[4] = (uint8_t)padding;
  for (uint32_t i = 0; i < len; ++i) plaintext[5U + i] = data[i];
  crypto_random_bytes(plaintext + 5U + len, padding);

  /* RFC 4253 MAC input is uint32 sequence number plus plaintext packet. */
  uint8_t *mac_input = scratch->mac_input;
  ssh_write_u32_be(mac_input, (uint32_t)conn->crypto.encrypt_seq);
  ssh_mem_copy(mac_input + 4U, plaintext, encrypted_len);
  uint8_t mac[32];
  hmac_sha256(conn->crypto.encrypt_mac_key, 32, mac_input,
              4U + encrypted_len, mac);

  aes128_ctr(&conn->crypto.encrypt_ctx, conn->crypto.encrypt_iv,
             plaintext, encrypted, encrypted_len);
  increment_counter(conn->crypto.encrypt_iv, encrypted_len / block_size);
  if (send_all(sockfd, encrypted, encrypted_len) != 0) return -1;
  if (send_all(sockfd, mac, mac_len) != 0) return -1;
  conn->crypto.encrypt_seq =
      (uint32_t)(conn->crypto.encrypt_seq + 1U);
  return 0;
}

int ssh_packet_read_encrypted(int sockfd, ssh_packet_t *out_pkt) {
  ssh_connection_t *conn = ssh_conn_find((uint64_t)(uint64_t)sockfd);
  if (!conn || !conn->crypto.enabled) return -1;

  const uint32_t block_size = 16U;
  const uint32_t mac_len = 32U;
  ssh_connection_scratch_t *scratch = ssh_conn_scratch();
  if (scratch->encrypted_rx_owner != 0 &&
      scratch->encrypted_rx_owner != (uint64_t)(uint64_t)sockfd) {
    return 1;
  }
  if (scratch->encrypted_rx_owner == 0) {
    scratch->encrypted_rx_owner = (uint64_t)(uint64_t)sockfd;
    scratch->encrypted_rx_used = 0;
    scratch->encrypted_rx_expected = 0;
  }
  uint8_t *wire = scratch->encrypted_rx;

  if (scratch->encrypted_rx_used < block_size) {
    u64 received = 0;
    uint32_t needed = block_size - scratch->encrypted_rx_used;
    if (xaios_net_recv((u64)(uint64_t)sockfd,
                       wire + scratch->encrypted_rx_used, needed,
                       &received) != 0) {
      return -1;
    }
    scratch->encrypted_rx_used += (uint32_t)received;
    if (scratch->encrypted_rx_used < block_size) {
      return 1;
    }
  }

  uint8_t first_plaintext[16];
  aes128_ctr(&conn->crypto.decrypt_ctx, conn->crypto.decrypt_iv,
             wire, first_plaintext, sizeof(first_plaintext));
  uint32_t packet_len = ssh_read_u32_be(first_plaintext);
  uint32_t encrypted_len = 4U + packet_len;
  if (packet_len < 5U || encrypted_len > SSH_MAX_PACKET_SIZE ||
      (encrypted_len % block_size) != 0U) return -1;
  scratch->encrypted_rx_expected = encrypted_len + mac_len;

  if (scratch->encrypted_rx_used < scratch->encrypted_rx_expected) {
    u64 received = 0;
    uint32_t needed =
        scratch->encrypted_rx_expected - scratch->encrypted_rx_used;
    if (xaios_net_recv((u64)(uint64_t)sockfd,
                       wire + scratch->encrypted_rx_used, needed,
                       &received) != 0) {
      return -1;
    }
    scratch->encrypted_rx_used += (uint32_t)received;
    if (scratch->encrypted_rx_used < scratch->encrypted_rx_expected) {
      return 1;
    }
  }

  uint8_t *full_plaintext = scratch->decrypt_full_packet;
  ssh_mem_copy(full_plaintext, first_plaintext, sizeof(first_plaintext));
  uint32_t remaining = encrypted_len - block_size;
  if (remaining != 0U) {
    uint8_t continuation_iv[16];
    ssh_mem_copy(continuation_iv, conn->crypto.decrypt_iv,
                 sizeof(continuation_iv));
    increment_counter(continuation_iv, 1U);
    aes128_ctr(&conn->crypto.decrypt_ctx, continuation_iv,
               wire + block_size, full_plaintext + block_size,
               remaining);
  }

  const uint8_t *received_mac = wire + encrypted_len;
  uint8_t *mac_input = scratch->decrypt_mac_input;
  ssh_write_u32_be(mac_input, (uint32_t)conn->crypto.decrypt_seq);
  ssh_mem_copy(mac_input + 4U, full_plaintext, encrypted_len);
  uint8_t computed_mac[32];
  hmac_sha256(conn->crypto.decrypt_mac_key, 32, mac_input,
              4U + encrypted_len, computed_mac);
  uint32_t different = 0;
  for (uint32_t i = 0; i < mac_len; ++i) {
    different |= (uint32_t)(computed_mac[i] ^ received_mac[i]);
  }
  if (different != 0U) return -1;

  uint8_t padding = full_plaintext[4];
  if (padding < 4U || padding >= packet_len) return -1;
  uint32_t payload_len = packet_len - padding - 1U;
  if (payload_len > sizeof(out_pkt->data)) return -1;

  out_pkt->len = payload_len;
  for (uint32_t i = 0; i < payload_len; ++i) {
    out_pkt->data[i] = full_plaintext[5U + i];
  }
  increment_counter(conn->crypto.decrypt_iv, encrypted_len / block_size);
  conn->crypto.decrypt_seq =
      (uint32_t)(conn->crypto.decrypt_seq + 1U);
  scratch->encrypted_rx_owner = 0;
  scratch->encrypted_rx_used = 0;
  scratch->encrypted_rx_expected = 0;
  return 0;
}
