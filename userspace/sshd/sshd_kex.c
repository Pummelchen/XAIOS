/*
 * sshd's key exchange and per-connection encryption.
 *
 * The KEXINIT offer and its validation, the exchange-hash transcript, the
 * curve25519/mlkem768 KEXDH exchange, and the derivation that turns the shared
 * secret into the connection's AES-CTR keys and MAC keys. The state machine
 * that drives it stays in sshd.c; see sshd_internal.h for what crosses.
 */

#include "sshd_internal.h"

#include "ssh_crypto.h"
#include "ssh_host_key.h"
#include "ssh_mlkem.h"
#include "ssh_utils.h"
#include "tweetnacl_subset.h"

static void sha256_update_u32(sha256_ctx_t *context, uint32_t value) {
  uint8_t encoded[4];
  ssh_write_u32_be(encoded, value);
  sha256_update(context, encoded, sizeof(encoded));
}

static void sha256_update_string(sha256_ctx_t *context, const uint8_t *value,
                                 uint32_t value_len) {
  sha256_update_u32(context, value_len);
  sha256_update(context, value, value_len);
}

static void sha256_update_mpint(sha256_ctx_t *context,
                                const uint8_t value[32]) {
  uint32_t first = 0;
  while (first < 32U && value[first] == 0U) ++first;
  uint32_t value_len = 32U - first;
  uint32_t leading_zero = value_len != 0U && (value[first] & 0x80U) != 0U;
  sha256_update_u32(context, value_len + leading_zero);
  if (leading_zero != 0U) {
    static const uint8_t zero = 0;
    sha256_update(context, &zero, 1);
  }
  if (value_len != 0U) sha256_update(context, value + first, value_len);
}

static void sha256_update_kex_secret(sha256_ctx_t *context,
                                     const uint8_t value[32],
                                     uint32_t hybrid) {
  if (hybrid != 0U)
    sha256_update_string(context, value, 32U);
  else
    sha256_update_mpint(context, value);
}

/* ---- Per-connection encryption (replaces globals) ---- */

static int derive_connection_crypto(ssh_connection_crypto_t *c,
                                    const uint8_t *shared_secret,
                                    uint32_t secret_len,
                                    const uint8_t *exchange_hash,
                                    uint32_t hash_len,
                                    const uint8_t session_id[32],
                                    uint32_t hybrid) {
  uint8_t derive_buf[128];
  sha256_ctx_t ctx;

  if (c == 0 || shared_secret == 0 || exchange_hash == 0 ||
      session_id == 0 || secret_len != 32U || hash_len != 32U) return -1;
  ssh_mem_zero(c, sizeof(*c));
  sha256_init(&ctx);
  sha256_update_kex_secret(&ctx, shared_secret, hybrid);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_update(&ctx, (const uint8_t*)"A", 1);
  sha256_update(&ctx, session_id, 32U);
  sha256_final(&ctx, derive_buf);
  ssh_mem_copy(c->decrypt_iv, derive_buf, 16);

  sha256_init(&ctx);
  sha256_update_kex_secret(&ctx, shared_secret, hybrid);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_update(&ctx, (const uint8_t*)"B", 1);
  sha256_update(&ctx, session_id, 32U);
  sha256_final(&ctx, derive_buf);
  ssh_mem_copy(c->encrypt_iv, derive_buf, 16);

  sha256_init(&ctx);
  sha256_update_kex_secret(&ctx, shared_secret, hybrid);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_update(&ctx, (const uint8_t*)"C", 1);
  sha256_update(&ctx, session_id, 32U);
  sha256_final(&ctx, derive_buf);
  aes128_init(&c->decrypt_ctx, derive_buf);

  sha256_init(&ctx);
  sha256_update_kex_secret(&ctx, shared_secret, hybrid);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_update(&ctx, (const uint8_t*)"D", 1);
  sha256_update(&ctx, session_id, 32U);
  sha256_final(&ctx, derive_buf);
  aes128_init(&c->encrypt_ctx, derive_buf);

  sha256_init(&ctx);
  sha256_update_kex_secret(&ctx, shared_secret, hybrid);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_update(&ctx, (const uint8_t*)"E", 1);
  sha256_update(&ctx, session_id, 32U);
  sha256_final(&ctx, derive_buf);
  ssh_mem_copy(c->decrypt_mac_key, derive_buf, 32);

  sha256_init(&ctx);
  sha256_update_kex_secret(&ctx, shared_secret, hybrid);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_update(&ctx, (const uint8_t*)"F", 1);
  sha256_update(&ctx, session_id, 32U);
  sha256_final(&ctx, derive_buf);
  ssh_mem_copy(c->encrypt_mac_key, derive_buf, 32);

  c->enabled = 1;
  ssh_mem_zero(derive_buf, sizeof(derive_buf));
  ssh_mem_zero(&ctx, sizeof(ctx));
  return 0;
}

int conn_init_encryption(ssh_connection_t *conn) {
  if (derive_connection_crypto(&conn->crypto, conn->shared_secret, 32U,
                               conn->exchange_hash, 32U,
                               conn->session_id, conn->kex_hybrid) != 0)
    return -1;
  /* Three packets in each direction precede the first encrypted packet. */
  conn->crypto.encrypt_seq = 3U;
  conn->crypto.decrypt_seq = 3U;
  conn->rekey_encrypt_base = conn->crypto.encrypt_seq;
  return 0;
}

int conn_packet_write_encrypted(ssh_connection_t *conn,
                                        const uint8_t *data, uint32_t len) {
  return ssh_packet_write_encrypted((int)conn->sockfd, data, len);
}

int conn_packet_read_encrypted(ssh_connection_t *conn,
                                       ssh_packet_t *out_pkt) {
  return ssh_packet_read_encrypted((int)conn->sockfd, out_pkt);
}

/* ---- Build KEXINIT Packet ---- */
static int build_kexinit(uint8_t *buf, uint32_t *out_len) {
  uint32_t pos = 0;
  buf[pos++] = 20;
  if (crypto_random_bytes(buf + pos, 16) != 0) return -1;
  pos += 16;
  const char *kex =
      "mlkem768x25519-sha256,curve25519-sha256";
  uint32_t kex_len = ssh_str_len(kex);
  ssh_write_u32_be(buf + pos, kex_len); pos += 4;
  ssh_mem_copy(buf + pos, kex, kex_len); pos += kex_len;
  const char *hkey = "ssh-ed25519";
  uint32_t hkey_len = ssh_str_len(hkey);
  ssh_write_u32_be(buf + pos, hkey_len); pos += 4;
  ssh_mem_copy(buf + pos, hkey, hkey_len); pos += hkey_len;
  const char *enc = "aes128-ctr";
  uint32_t enc_len = ssh_str_len(enc);
  ssh_write_u32_be(buf + pos, enc_len); pos += 4;
  ssh_mem_copy(buf + pos, enc, enc_len); pos += enc_len;
  ssh_write_u32_be(buf + pos, enc_len); pos += 4;
  ssh_mem_copy(buf + pos, enc, enc_len); pos += enc_len;
  const char *mac = "hmac-sha2-256";
  uint32_t mac_len = ssh_str_len(mac);
  ssh_write_u32_be(buf + pos, mac_len); pos += 4;
  ssh_mem_copy(buf + pos, mac, mac_len); pos += mac_len;
  ssh_write_u32_be(buf + pos, mac_len); pos += 4;
  ssh_mem_copy(buf + pos, mac, mac_len); pos += mac_len;
  const char *comp = "none";
  uint32_t comp_len = ssh_str_len(comp);
  ssh_write_u32_be(buf + pos, comp_len); pos += 4;
  ssh_mem_copy(buf + pos, comp, comp_len); pos += comp_len;
  ssh_write_u32_be(buf + pos, comp_len); pos += 4;
  ssh_mem_copy(buf + pos, comp, comp_len); pos += comp_len;
  ssh_write_u32_be(buf + pos, 0); pos += 4;
  ssh_write_u32_be(buf + pos, 0); pos += 4;
  buf[pos++] = 0;
  ssh_write_u32_be(buf + pos, 0); pos += 4;
  *out_len = pos;
  return 0;
}

static int name_list_contains(const uint8_t *list, uint32_t list_len,
                              const char *required) {
  uint32_t required_len = ssh_str_len(required);
  uint32_t start = 0U;
  for (uint32_t i = 0U; i <= list_len; ++i) {
    if (i == list_len || list[i] == ',') {
      if (i - start == required_len &&
          sshd_bytes_equal(list + start, (const uint8_t *)required,
                      required_len)) return 1;
      start = i + 1U;
    }
  }
  return 0;
}

static int consume_required_name_list(const ssh_packet_t *pkt,
                                      uint32_t *offset,
                                      const char *required) {
  if (*offset + 4U > pkt->len) return -1;
  uint32_t length = ssh_read_u32_be(pkt->data + *offset);
  *offset += 4U;
  if (length > pkt->len - *offset ||
      !name_list_contains(pkt->data + *offset, length, required)) return -1;
  *offset += length;
  return 0;
}

static int consume_name_list(const ssh_packet_t *pkt, uint32_t *offset) {
  if (*offset + 4U > pkt->len) return -1;
  uint32_t length = ssh_read_u32_be(pkt->data + *offset);
  *offset += 4U;
  if (length > pkt->len - *offset) return -1;
  *offset += length;
  return 0;
}

static int select_client_kex(const uint8_t *list, uint32_t list_len,
                             uint32_t *hybrid) {
  uint32_t start = 0U;
  for (uint32_t i = 0U; i <= list_len; ++i) {
    if (i != list_len && list[i] != ',') continue;
    uint32_t length = i - start;
    if (length == 21U &&
        sshd_bytes_equal(list + start,
                    (const uint8_t *)"mlkem768x25519-sha256", length)) {
      *hybrid = 1U;
      return 0;
    }
    if (length == 17U &&
        sshd_bytes_equal(list + start, (const uint8_t *)"curve25519-sha256",
                    length)) {
      *hybrid = 0U;
      return 0;
    }
    start = i + 1U;
  }
  return -1;
}

int validate_client_kexinit(ssh_connection_t *conn,
                                   const ssh_packet_t *pkt) {
  if (pkt == 0 || pkt->len < 21U || pkt->data[0] != SSH_MSG_KEXINIT) {
    return -1;
  }
  uint32_t offset = 17U;
  if (offset + 4U > pkt->len) return -1;
  uint32_t kex_length = ssh_read_u32_be(pkt->data + offset);
  offset += 4U;
  if (kex_length > pkt->len - offset ||
      select_client_kex(pkt->data + offset, kex_length,
                        &conn->kex_hybrid) != 0) return -1;
  offset += kex_length;
  if (
      consume_required_name_list(pkt, &offset, "ssh-ed25519") != 0 ||
      consume_required_name_list(pkt, &offset, "aes128-ctr") != 0 ||
      consume_required_name_list(pkt, &offset, "aes128-ctr") != 0 ||
      consume_required_name_list(pkt, &offset, "hmac-sha2-256") != 0 ||
      consume_required_name_list(pkt, &offset, "hmac-sha2-256") != 0 ||
      consume_required_name_list(pkt, &offset, "none") != 0 ||
      consume_required_name_list(pkt, &offset, "none") != 0 ||
      consume_name_list(pkt, &offset) != 0 ||
      consume_name_list(pkt, &offset) != 0 || offset + 5U != pkt->len ||
      pkt->data[offset] != 0U) return -1;
  return 0;
}

void init_exchange_hash(ssh_connection_t *conn,
                               const ssh_packet_t *client_kexinit) {
  uint32_t client_version_len = conn->version_len;
  while (client_version_len > 0U &&
         (conn->version_buf[client_version_len - 1U] == '\r' ||
          conn->version_buf[client_version_len - 1U] == '\n')) {
    --client_version_len;
  }
  sha256_init(&conn->exchange_hash_ctx);
  sha256_update_string(&conn->exchange_hash_ctx, conn->version_buf,
                       client_version_len);
  static const uint8_t server_version[] = "SSH-2.0-XAIOS_1.0";
  sha256_update_string(&conn->exchange_hash_ctx, server_version,
                       sizeof(server_version) - 1U);
  sha256_update_string(&conn->exchange_hash_ctx, client_kexinit->data,
                       client_kexinit->len);
  sha256_update_string(&conn->exchange_hash_ctx, conn->server_kexinit,
                       conn->server_kexinit_len);
}

int send_server_kexinit(ssh_connection_t *conn, int encrypted) {
  if (build_kexinit(conn->server_kexinit,
                    &conn->server_kexinit_len) != 0) return -1;
  if (encrypted != 0) {
    return conn_packet_write_encrypted(conn, conn->server_kexinit,
                                       conn->server_kexinit_len);
  }
  return ssh_packet_write((int)conn->sockfd, conn->server_kexinit,
                          conn->server_kexinit_len);
}

static int send_kex_packet(ssh_connection_t *conn, int encrypted,
                           const uint8_t *packet, uint32_t packet_len) {
  if (encrypted != 0) {
    return conn_packet_write_encrypted(conn, packet, packet_len);
  }
  return ssh_packet_write((int)conn->sockfd, packet, packet_len);
}

int handle_kexdh_init(ssh_connection_t *conn,
                             const ssh_packet_t *pkt, int encrypted) {
  uint32_t client_blob_len = conn->kex_hybrid != 0U
                                 ? SSH_MLKEM768_PUBLIC_KEY_SIZE + 32U
                                 : 32U;
  if (pkt == 0 || pkt->len != client_blob_len + 5U ||
      pkt->data[0] != SSH_MSG_KEXDH_INIT ||
      ssh_read_string_len(pkt->data + 1U) != client_blob_len) return -1;
  const uint8_t *client_blob = pkt->data + 5U;
  const uint8_t *client_x25519 = client_blob;
  if (conn->kex_hybrid != 0U)
    client_x25519 += SSH_MLKEM768_PUBLIC_KEY_SIZE;
  ssh_mem_copy(conn->client_ephemeral_pub, client_x25519, 32U);
  if (crypto_random_bytes(conn->server_ephemeral_priv, 32U) != 0) return -1;
  xaios_x25519_base(conn->server_ephemeral_pub,
                    conn->server_ephemeral_priv);
  uint8_t x25519_secret[32];
  xaios_x25519(x25519_secret, conn->server_ephemeral_priv,
               client_x25519);
  uint8_t shared_nonzero = 0U;
  for (uint32_t i = 0U; i < sizeof(x25519_secret); ++i)
    shared_nonzero |= x25519_secret[i];
  if (shared_nonzero == 0U) return -1;

  uint8_t server_blob[SSH_MLKEM768_CIPHERTEXT_SIZE + 32U];
  uint32_t server_blob_len = 32U;
  if (conn->kex_hybrid != 0U) {
    uint8_t mlkem_secret[SSH_MLKEM768_SHARED_SECRET_SIZE];
    if (ssh_mlkem768_encapsulate(server_blob, mlkem_secret,
                                 client_blob) != 0) return -1;
    ssh_mem_copy(server_blob + SSH_MLKEM768_CIPHERTEXT_SIZE,
                 conn->server_ephemeral_pub, 32U);
    uint8_t combined[64];
    ssh_mem_copy(combined, mlkem_secret, 32U);
    ssh_mem_copy(combined + 32U, x25519_secret, 32U);
    sha256_hash(combined, sizeof(combined), conn->shared_secret);
    ssh_mem_zero(combined, sizeof(combined));
    ssh_mem_zero(mlkem_secret, sizeof(mlkem_secret));
    server_blob_len = sizeof(server_blob);
  } else {
    ssh_mem_copy(conn->shared_secret, x25519_secret, 32U);
    ssh_mem_copy(server_blob, conn->server_ephemeral_pub, 32U);
  }
  ssh_mem_zero(x25519_secret, sizeof(x25519_secret));

  sha256_ctx_t hash_ctx = conn->exchange_hash_ctx;
  uint8_t host_pub[32];
  if (ssh_host_key_get_public(host_pub) != 0) return -1;
  uint8_t host_key_blob[64];
  uint32_t host_key_blob_pos = 0U;
  ssh_write_u32_be(host_key_blob + host_key_blob_pos, 4U + 11U + 4U + 32U);
  host_key_blob_pos += 4U;
  ssh_write_u32_be(host_key_blob + host_key_blob_pos, 11U);
  host_key_blob_pos += 4U;
  ssh_mem_copy(host_key_blob + host_key_blob_pos, "ssh-ed25519", 11U);
  host_key_blob_pos += 11U;
  ssh_write_u32_be(host_key_blob + host_key_blob_pos, 32U);
  host_key_blob_pos += 4U;
  ssh_mem_copy(host_key_blob + host_key_blob_pos, host_pub, 32U);
  host_key_blob_pos += 32U;
  sha256_update(&hash_ctx, host_key_blob, host_key_blob_pos);
  sha256_update_string(&hash_ctx, client_blob, client_blob_len);
  sha256_update_string(&hash_ctx, server_blob, server_blob_len);
  sha256_update_kex_secret(&hash_ctx, conn->shared_secret,
                           conn->kex_hybrid);
  sha256_final(&hash_ctx, conn->exchange_hash);
  if (encrypted == 0) {
    ssh_mem_copy(conn->session_id, conn->exchange_hash,
                 sizeof(conn->session_id));
  }

  uint8_t reply[SSH_MLKEM768_CIPHERTEXT_SIZE + 256U];
  uint32_t position = 0U;
  reply[position++] = SSH_MSG_KEXDH_REPLY;
  ssh_write_u32_be(reply + position, host_key_blob_pos - 4U);
  position += 4U;
  ssh_mem_copy(reply + position, host_key_blob + 4U,
               host_key_blob_pos - 4U);
  position += host_key_blob_pos - 4U;
  ssh_write_u32_be(reply + position, server_blob_len);
  position += 4U;
  ssh_mem_copy(reply + position, server_blob, server_blob_len);
  position += server_blob_len;

  uint8_t signature[64];
  uint8_t host_priv[32];
  if (ssh_host_key_get_private(host_priv) != 0) return -1;
  xaios_ed25519_sign(signature, conn->exchange_hash, 32U, host_pub,
                     host_priv);
  ssh_mem_zero(host_priv, sizeof(host_priv));
  ssh_write_u32_be(reply + position, 4U + 11U + 4U + 64U);
  position += 4U;
  ssh_write_u32_be(reply + position, 11U);
  position += 4U;
  ssh_mem_copy(reply + position, "ssh-ed25519", 11U);
  position += 11U;
  ssh_write_u32_be(reply + position, 64U);
  position += 4U;
  ssh_mem_copy(reply + position, signature, sizeof(signature));
  position += sizeof(signature);

  if (send_kex_packet(conn, encrypted, reply, position) != 0) return -1;
  uint8_t newkeys = SSH_MSG_NEWKEYS;
  if (send_kex_packet(conn, encrypted, &newkeys, 1U) != 0) return -1;
  if (encrypted != 0 &&
      derive_connection_crypto(&conn->pending_crypto, conn->shared_secret,
                               32U, conn->exchange_hash, 32U,
                               conn->session_id, conn->kex_hybrid) != 0)
    return -1;
  ssh_mem_zero(signature, sizeof(signature));
  ssh_mem_zero(&hash_ctx, sizeof(hash_ctx));
  return 0;
}

int begin_client_rekey(ssh_connection_t *conn,
                              const ssh_packet_t *client_kexinit,
                              int resume_state, uint64_t now) {
  if (validate_client_kexinit(conn, client_kexinit) != 0 ||
      send_server_kexinit(conn, 1) != 0) return -1;
  init_exchange_hash(conn, client_kexinit);
  conn->rekey_resume_state = resume_state;
  conn->kex_start_time = now;
  conn->state = SSH_STATE_REKEY_DH;
  return 0;
}

int begin_server_rekey(ssh_connection_t *conn, int resume_state,
                              uint64_t now) {
  if (send_server_kexinit(conn, 1) != 0) return -1;
  conn->rekey_resume_state = resume_state;
  conn->kex_start_time = now;
  conn->state = SSH_STATE_REKEY_KEXINIT;
  return 0;
}
