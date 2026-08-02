#ifndef SSH_CONNECTION_H
#define SSH_CONNECTION_H

#include "ssh_crypto.h"
#include "ssh_protocol.h"
#include <xaios_user.h>

#define SSH_MAX_CONNECTIONS 4U
#define SSH_PLAINTEXT_PACKET_SIZE 4096U

#define SSH_STATE_INIT 0
#define SSH_STATE_KEX 1
#define SSH_STATE_KEX_SENT 2
#define SSH_STATE_NEWKEYS 3
#define SSH_STATE_NEWKEYS_SENT 4
#define SSH_STATE_AUTH 5
#define SSH_STATE_AUTHENTICATED 6
#define SSH_STATE_CHANNEL 7
#define SSH_STATE_CLOSED 8
#define SSH_STATE_REKEY_KEXINIT 9
#define SSH_STATE_REKEY_DH 10
#define SSH_STATE_REKEY_NEWKEYS 11

typedef struct {
  int enabled;
  aes128_ctx_t encrypt_ctx;
  aes128_ctx_t decrypt_ctx;
  uint8_t encrypt_iv[16];
  uint8_t decrypt_iv[16];
  uint8_t encrypt_mac_key[32];
  uint8_t decrypt_mac_key[32];
  uint64_t encrypt_seq;
  uint64_t decrypt_seq;
} ssh_connection_crypto_t;

typedef struct {
  int active;
  uint64_t sockfd;
  ssh_connection_crypto_t crypto;
  ssh_connection_crypto_t pending_crypto;
  uint64_t last_activity;
  uint64_t last_keepalive;
  xaios_ip_addr_user_t client_addr;
  uint16_t client_port;
  uint32_t auth_attempts;
  int state;
  uint8_t session_id[32];
  uint8_t exchange_hash[32];
  uint8_t shared_secret[32];
  uint8_t version_buf[256];
  uint32_t version_len;
  uint8_t plaintext_rx[SSH_PLAINTEXT_PACKET_SIZE + 4U];
  uint32_t plaintext_rx_used;
  uint32_t plaintext_rx_expected;
  uint8_t encrypted_rx[SSH_MAX_PACKET_SIZE + 32U];
  uint32_t encrypted_rx_used;
  uint32_t encrypted_rx_expected;
  uint8_t server_kexinit[512];
  uint32_t server_kexinit_len;
  sha256_ctx_t exchange_hash_ctx;
  uint8_t server_ephemeral_priv[32];
  uint8_t server_ephemeral_pub[32];
  uint8_t client_ephemeral_pub[32];
  uint64_t connect_time;
  uint64_t kex_start_time;
  uint64_t rekey_encrypt_base;
  int rekey_resume_state;
} ssh_connection_t;

typedef struct {
  uint8_t encrypt_packet[SSH_MAX_PACKET_SIZE];
  uint8_t encrypt_output[SSH_MAX_PACKET_SIZE];
  uint8_t mac_input[8 + SSH_MAX_PACKET_SIZE];
  uint8_t decrypt_rest[SSH_MAX_PACKET_SIZE];
  uint8_t decrypt_mac_input[8 + SSH_MAX_PACKET_SIZE];
  uint8_t decrypt_full_packet[SSH_MAX_PACKET_SIZE];
  ssh_packet_t pkt;
} ssh_connection_scratch_t;

ssh_connection_t *ssh_conn_alloc(void);
void ssh_conn_free(ssh_connection_t *conn);
ssh_connection_t *ssh_conn_find(uint64_t sockfd);
ssh_connection_t *ssh_conn_by_index(uint32_t idx);
void ssh_conn_pool_init(void);
ssh_connection_scratch_t *ssh_conn_scratch(void);

#endif
