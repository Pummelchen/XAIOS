#include "sshd.h"
#include "ssh_connection.h"
#include "ssh_crypto.h"
#include "ssh_protocol.h"
#include "ssh_channel.h"
#include "ssh_host_key.h"
#include "ssh_utils.h"
#include "tweetnacl_subset.h"
#include <xaios_user.h>
#include <stdarg.h>

static sshd_user_t g_users[SSHD_MAX_USERS];
static uint32_t g_user_count = 0;

static sshd_rate_limit_entry_t g_rate_limits[SSHD_RATE_LIMIT_MAX_ENTRIES];
static uint32_t g_rate_limit_count = 0;

static sshd_stats_t g_server_stats;

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

static int g_log_fd = -1;

static void int_to_str(uint64_t val, char *buf, uint32_t buf_size) {
  if (buf_size == 0) return;
  char temp[32];
  uint32_t pos = 0;
  if (val == 0) { temp[pos++] = '0'; }
  else {
    while (val > 0 && pos < 31) {
      temp[pos++] = '0' + (val % 10);
      val /= 10;
    }
  }
  uint32_t len = 0;
  for (int32_t i = (int32_t)(pos - 1); i >= 0 && len < buf_size - 1; i--) {
    buf[len++] = temp[i];
  }
  buf[len] = '\0';
}

static void hex_to_str(uint64_t val, char *buf, uint32_t buf_size) {
  if (buf_size < 3) return;
  const char *hex_chars = "0123456789abcdef";
  uint32_t len = 0;
  for (int i = 60; i >= 0 && len < buf_size - 2; i -= 4) {
    uint8_t digit = (uint8_t)((val >> i) & 0xF);
    if (digit != 0 || len > 0) {
      buf[len++] = hex_chars[digit];
    }
  }
  if (len == 0) buf[len++] = '0';
  buf[len] = '\0';
}

void ssh_log(int level, const char *fmt, ...) {
  if (g_log_fd < 0) {
    g_log_fd = xaios_fs_open("/state/sshd.log",
                             XAIOS_MFS_OPEN_WRITE | XAIOS_MFS_OPEN_CREATE);
    if (g_log_fd < 0) return;
  }
  const char *prefix;
  switch (level) {
    case SSH_LOG_INFO:  prefix = "[INFO]";  break;
    case SSH_LOG_WARN:  prefix = "[WARN]";  break;
    case SSH_LOG_ERROR: prefix = "[ERROR]"; break;
    default: prefix = "[UNKNOWN]"; break;
  }
  xaios_fs_write(g_log_fd, (const void*)prefix, ssh_str_len(prefix));
  xaios_fs_write(g_log_fd, " ", 1);
  va_list args;
  va_start(args, fmt);
  char buffer[512];
  uint32_t buf_pos = 0;
  for (const char *p = fmt; *p && buf_pos < 511; p++) {
    if (*p == '%' && *(p+1)) {
      p++;
      if (*p == 's') {
        const char *str = va_arg(args, const char*);
        if (str) {
          uint32_t len = ssh_str_len(str);
          if (buf_pos + len < 511) {
            for (uint32_t i = 0; i < len; i++) buffer[buf_pos++] = str[i];
          }
        }
      } else if (*p == 'u' || *p == 'd') {
        uint64_t val = va_arg(args, uint64_t);
        char num_buf[32];
        int_to_str(val, num_buf, 32);
        uint32_t len = ssh_str_len(num_buf);
        if (buf_pos + len < 511) {
          for (uint32_t i = 0; i < len; i++) buffer[buf_pos++] = num_buf[i];
        }
      } else if (*p == 'x' || *p == 'X') {
        uint64_t val = va_arg(args, uint64_t);
        char num_buf[32];
        hex_to_str(val, num_buf, 32);
        uint32_t len = ssh_str_len(num_buf);
        if (buf_pos + len < 511) {
          for (uint32_t i = 0; i < len; i++) buffer[buf_pos++] = num_buf[i];
        }
      } else if (*p == 'p') {
        uint64_t val = (uint64_t)va_arg(args, void*);
        char num_buf[32];
        hex_to_str(val, num_buf, 32);
        uint32_t len = ssh_str_len(num_buf);
        if (buf_pos + len + 2 < 511) {
          buffer[buf_pos++] = '0';
          buffer[buf_pos++] = 'x';
          for (uint32_t i = 0; i < len; i++) buffer[buf_pos++] = num_buf[i];
        }
      } else if (*p == '%') {
        if (buf_pos < 511) buffer[buf_pos++] = '%';
      }
    } else {
      buffer[buf_pos++] = *p;
    }
  }
  buffer[buf_pos] = '\0';
  va_end(args);
  xaios_fs_write(g_log_fd, buffer, buf_pos);
  xaios_fs_write(g_log_fd, "\n", 1);
}

static int ip_addr_equal(const xaios_ip_addr_user_t *a,
                         const xaios_ip_addr_user_t *b) {
  if (a->family != b->family) return 0;
  uint32_t len = (a->family == 4) ? 4U : 16U;
  for (uint32_t i = 0; i < len; ++i) {
    if (a->addr[i] != b->addr[i]) return 0;
  }
  return 1;
}

/* ---- Per-connection encryption (replaces globals) ---- */

static void conn_init_encryption(ssh_connection_t *conn,
                                  const uint8_t *shared_secret,
                                  uint32_t secret_len,
                                  const uint8_t *exchange_hash,
                                  uint32_t hash_len) {
  ssh_connection_crypto_t *c = &conn->crypto;
  uint8_t derive_buf[128];
  sha256_ctx_t ctx;

  sha256_init(&ctx);
  if (secret_len != 32U) return;
  sha256_update_mpint(&ctx, shared_secret);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_update(&ctx, (const uint8_t*)"A", 1);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_final(&ctx, derive_buf);
  ssh_mem_copy(c->decrypt_iv, derive_buf, 16);

  sha256_init(&ctx);
  sha256_update_mpint(&ctx, shared_secret);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_update(&ctx, (const uint8_t*)"B", 1);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_final(&ctx, derive_buf);
  ssh_mem_copy(c->encrypt_iv, derive_buf, 16);

  sha256_init(&ctx);
  sha256_update_mpint(&ctx, shared_secret);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_update(&ctx, (const uint8_t*)"C", 1);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_final(&ctx, derive_buf);
  aes128_init(&c->decrypt_ctx, derive_buf);

  sha256_init(&ctx);
  sha256_update_mpint(&ctx, shared_secret);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_update(&ctx, (const uint8_t*)"D", 1);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_final(&ctx, derive_buf);
  aes128_init(&c->encrypt_ctx, derive_buf);

  sha256_init(&ctx);
  sha256_update_mpint(&ctx, shared_secret);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_update(&ctx, (const uint8_t*)"E", 1);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_final(&ctx, derive_buf);
  ssh_mem_copy(c->decrypt_mac_key, derive_buf, 32);

  sha256_init(&ctx);
  sha256_update_mpint(&ctx, shared_secret);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_update(&ctx, (const uint8_t*)"F", 1);
  sha256_update(&ctx, exchange_hash, hash_len);
  sha256_final(&ctx, derive_buf);
  ssh_mem_copy(c->encrypt_mac_key, derive_buf, 32);

  /* Packet sequence numbers start at the first KEXINIT packet and do not
   * reset when NEWKEYS activates encryption. This initial exchange has sent
   * and received KEXINIT, KEXDH_INIT/REPLY, and NEWKEYS. */
  c->encrypt_seq = 3;
  c->decrypt_seq = 3;
  c->enabled = 1;
}

static int conn_packet_write_encrypted(ssh_connection_t *conn,
                                        const uint8_t *data, uint32_t len) {
  return ssh_packet_write_encrypted((int)conn->sockfd, data, len);
}

static int conn_packet_read_encrypted(ssh_connection_t *conn,
                                       ssh_packet_t *out_pkt) {
  return ssh_packet_read_encrypted((int)conn->sockfd, out_pkt);
}

/* ---- Timer ---- */
static uint64_t timer_now(void) {
  return xaios_clock_nanos();
}

/* ---- User Database ---- */
static int load_user_database(void) {
  if (g_user_count == 0) {
    ssh_mem_copy(g_users[0].username, "admin", 6);
    static const uint8_t admin_hash[32] = {
      0x8c, 0x69, 0x76, 0xe5, 0xb5, 0x41, 0x04, 0x15,
      0xbd, 0xe9, 0x08, 0xbd, 0x4d, 0xee, 0x15, 0xdf,
      0xb1, 0x67, 0xa9, 0xc8, 0x73, 0xfc, 0x4b, 0xb8,
      0xa8, 0x1f, 0x6f, 0x2a, 0xb4, 0x48, 0xa9, 0x18
    };
    ssh_mem_copy(g_users[0].password_hash, admin_hash, 32);
    g_users[0].active = 1;
    g_user_count = 1;
    ssh_log(SSH_LOG_INFO, "Loaded default admin user\n");
  }
  return 0;
}

static int authenticate_password(const char *username, const char *password) {
  for (uint32_t i = 0; i < g_user_count; ++i) {
    if (!g_users[i].active) continue;
    if (!ssh_str_eq(g_users[i].username, username)) continue;
    uint8_t hash[32];
    sha256_hash((const uint8_t *)password, ssh_str_len(password), hash);
    uint8_t diff = 0;
    for (uint32_t j = 0; j < 32; ++j) diff |= hash[j] ^ g_users[i].password_hash[j];
    if (diff != 0) { ssh_mem_zero(hash, 32); return -1; }
    ssh_mem_zero(hash, 32);
    return 0;
  }
  return -1;
}

/* ---- Authorized Keys for Public Key Auth ---- */
#define AUTHORIZED_KEYS_PATH "/etc/xaios_authorized_keys"
#define MAX_AUTHORIZED_KEYS 16

typedef struct {
  uint8_t key[32];
  int active;
} authorized_key_t;

static authorized_key_t g_authorized_keys[MAX_AUTHORIZED_KEYS];
static uint32_t g_authorized_key_count = 0;

static int hex_to_key(const char *hex, uint8_t *key) {
  uint32_t len = 0;
  while (hex[len]) ++len;
  if (len != 64) return -1;
  for (uint32_t i = 0; i < 32; ++i) {
    int hi = 0, lo = 0;
    char c = hex[i * 2];
    if (c >= '0' && c <= '9') hi = c - '0';
    else if (c >= 'a' && c <= 'f') hi = 10 + (c - 'a');
    else if (c >= 'A' && c <= 'F') hi = 10 + (c - 'A');
    else return -1;
    c = hex[i * 2 + 1];
    if (c >= '0' && c <= '9') lo = c - '0';
    else if (c >= 'a' && c <= 'f') lo = 10 + (c - 'a');
    else if (c >= 'A' && c <= 'F') lo = 10 + (c - 'A');
    else return -1;
    key[i] = (uint8_t)((hi << 4) | lo);
  }
  return 0;
}

static int load_authorized_keys(void) {
  if (g_authorized_key_count > 0) return 0;
  char buf[4096];
  int ret = xaios_read_file(AUTHORIZED_KEYS_PATH, buf, sizeof(buf));
  if (ret != 0) {
    ssh_log(SSH_LOG_INFO, "No authorized keys file\n");
    return -1;
  }
  uint32_t line_start = 0;
  uint32_t key_idx = 0;
  for (uint32_t i = 0; buf[i] && key_idx < MAX_AUTHORIZED_KEYS; ++i) {
    if (buf[i] == '\n' || buf[i] == '\0') {
      uint32_t line_len = i - line_start;
      if (line_len == 64) {
        char hex[65];
        ssh_mem_copy(hex, buf + line_start, 64);
        hex[64] = '\0';
        if (hex_to_key(hex, g_authorized_keys[key_idx].key) == 0) {
          g_authorized_keys[key_idx].active = 1;
          key_idx++;
        }
      }
      line_start = i + 1;
    }
  }
  g_authorized_key_count = key_idx;
  ssh_log(SSH_LOG_INFO, "Loaded %u authorized keys\n", g_authorized_key_count);
  return (g_authorized_key_count > 0) ? 0 : -1;
}

static int check_authorized_key(const uint8_t *pubkey) {
  for (uint32_t i = 0; i < g_authorized_key_count; ++i) {
    if (!g_authorized_keys[i].active) continue;
    int match = 1;
    for (uint32_t j = 0; j < 32; ++j) {
      if (g_authorized_keys[i].key[j] != pubkey[j]) { match = 0; break; }
    }
    if (match) return 0;
  }
  return -1;
}

/* ---- Rate Limiting ---- */
static sshd_rate_limit_entry_t *find_rate_limit_entry(
    const xaios_ip_addr_user_t *ip) {
  for (uint32_t i = 0; i < g_rate_limit_count; ++i) {
    if (ip_addr_equal(&g_rate_limits[i].ip_address, ip)) {
      return &g_rate_limits[i];
    }
  }
  return 0;
}

static int check_rate_limit(const xaios_ip_addr_user_t *client_addr) {
  sshd_rate_limit_entry_t *entry = find_rate_limit_entry(client_addr);
  if (entry == 0) return 0;
  uint64_t now = timer_now();
  if (entry->ban_until > now) return -1;
  if (entry->ban_until > 0 && entry->ban_until <= now) {
    entry->failure_count = 0;
    entry->ban_until = 0;
  }
  return 0;
}

static void record_auth_failure(const xaios_ip_addr_user_t *client_addr) {
  sshd_rate_limit_entry_t *entry = find_rate_limit_entry(client_addr);
  uint64_t now = timer_now();
  if (entry == 0) {
    if (g_rate_limit_count < SSHD_RATE_LIMIT_MAX_ENTRIES) {
      entry = &g_rate_limits[g_rate_limit_count++];
      entry->ip_address = *client_addr;
      entry->last_attempt_time = now;
      entry->failure_count = 1;
      entry->ban_until = 0;
    }
  } else {
    entry->last_attempt_time = now;
    entry->failure_count++;
    if (entry->failure_count >= SSHD_RATE_LIMIT_MAX_FAILURES) {
      entry->ban_until = now + SSHD_RATE_LIMIT_BAN_DURATION;
    }
  }
}

static void record_auth_success(const xaios_ip_addr_user_t *client_addr) {
  sshd_rate_limit_entry_t *entry = find_rate_limit_entry(client_addr);
  if (entry) { entry->failure_count = 0; entry->ban_until = 0; }
}

/* ---- Build KEXINIT Packet ---- */
static uint32_t build_kexinit(uint8_t *buf) {
  uint32_t pos = 0;
  buf[pos++] = 20;
  crypto_random_bytes(buf + pos, 16);
  pos += 16;
  const char *kex = "curve25519-sha256";
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
  return pos;
}

/* ---- Connection State Machine Processor ---- */

/* Process one step for a connection. Returns 0 if connection should remain,
   -1 if closed/done. */
static int process_connection(ssh_connection_t *conn) {
  int sockfd = (int)conn->sockfd;
  ssh_packet_t *pkt = &ssh_conn_scratch()->pkt;
  uint64_t now = timer_now();

  if (conn->state == SSH_STATE_INIT) {
    /* Send server version */
    if (ssh_send_version(sockfd) != 0) {
      ssh_log(SSH_LOG_ERROR, "Failed to send version\n");
      return -1;
    }
    conn->state = SSH_STATE_KEX;
    conn->kex_start_time = now;
    return 0;
  }

  if (conn->state == SSH_STATE_KEX) {
    /* Receive client version */
    if (conn->version_len == 0U ||
        conn->version_buf[conn->version_len - 1U] != '\n') {
      while (conn->version_len < sizeof(conn->version_buf)) {
        u64 n = 0;
        int status = xaios_net_recv(conn->sockfd,
            conn->version_buf + conn->version_len, 1, &n);
        if (status != 0) return -1;
        if (n == 0) return 0;
        conn->version_len += (uint32_t)n;
        if (conn->version_buf[conn->version_len - 1U] == '\n') break;
      }
      if (conn->version_len == sizeof(conn->version_buf) &&
          conn->version_buf[conn->version_len - 1U] != '\n') {
        return -1;
      }
    }

    /* Send KEXINIT */
    conn->server_kexinit_len = build_kexinit(conn->server_kexinit);
    if (ssh_packet_write(sockfd, conn->server_kexinit, conn->server_kexinit_len) != 0) {
      return -1;
    }
    conn->state = SSH_STATE_KEX_SENT;
    return 0;
  }

  if (conn->state == SSH_STATE_KEX_SENT) {
    /* Receive client KEXINIT */
    int packet_status = ssh_packet_read(sockfd, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0) return -1;
    if (pkt->len == 0 || pkt->data[0] != 20) return -1;

    uint32_t vc_len = conn->version_len;
    while (vc_len > 0 && (conn->version_buf[vc_len - 1U] == '\r' ||
           conn->version_buf[vc_len - 1U] == '\n')) {
      --vc_len;
    }
    sha256_init(&conn->exchange_hash_ctx);
    sha256_update_string(&conn->exchange_hash_ctx, conn->version_buf, vc_len);

    const char *server_version = "SSH-2.0-XAIOS_1.0";
    uint32_t vs_len = ssh_str_len(server_version);
    sha256_update_string(&conn->exchange_hash_ctx,
                         (const uint8_t *)server_version, vs_len);
    sha256_update_string(&conn->exchange_hash_ctx, pkt->data, pkt->len);
    sha256_update_string(&conn->exchange_hash_ctx, conn->server_kexinit,
                         conn->server_kexinit_len);
    conn->state = SSH_STATE_NEWKEYS;
    return 0;
  }

  if (conn->state == SSH_STATE_NEWKEYS) {
    /* KEXDH_INIT */
    int packet_status = ssh_packet_read(sockfd, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0) return -1;
    if (pkt->len == 0 || pkt->data[0] != 30) return -1;

    if (pkt->len < 5) return -1;
    uint32_t client_pub_len = ssh_read_string_len(pkt->data + 1);
    if (client_pub_len != 32 || pkt->len < 5 + 32) return -1;
    ssh_mem_copy(conn->client_ephemeral_pub, pkt->data + 5, 32);

    /* Generate server ephemeral key pair */
    crypto_random_bytes(conn->server_ephemeral_priv, 32);
    xaios_x25519_base(conn->server_ephemeral_pub,
                      conn->server_ephemeral_priv);

    /* Compute shared secret */
    xaios_x25519(conn->shared_secret, conn->server_ephemeral_priv,
                 conn->client_ephemeral_pub);

    /* Build exchange hash */
    sha256_ctx_t hash_ctx = conn->exchange_hash_ctx;

    /* K_S: host key blob */
    uint8_t host_pub[32];
    ssh_host_key_get_public(host_pub);
    uint8_t host_key_blob[64];
    uint32_t host_key_blob_pos = 0;
    ssh_write_u32_be(host_key_blob + host_key_blob_pos, 4 + 11 + 4 + 32);
    host_key_blob_pos += 4;
    ssh_write_u32_be(host_key_blob + host_key_blob_pos, 11);
    host_key_blob_pos += 4;
    ssh_mem_copy(host_key_blob + host_key_blob_pos, "ssh-ed25519", 11);
    host_key_blob_pos += 11;
    ssh_write_u32_be(host_key_blob + host_key_blob_pos, 32);
    host_key_blob_pos += 4;
    ssh_mem_copy(host_key_blob + host_key_blob_pos, host_pub, 32);
    host_key_blob_pos += 32;
    sha256_update(&hash_ctx, host_key_blob, host_key_blob_pos);

    /* e: client ephemeral */
    uint8_t client_pub_blob[36];
    ssh_write_u32_be(client_pub_blob, 32);
    ssh_mem_copy(client_pub_blob + 4, conn->client_ephemeral_pub, 32);
    sha256_update(&hash_ctx, client_pub_blob, 36);

    /* f: server ephemeral */
    uint8_t server_pub_blob[36];
    ssh_write_u32_be(server_pub_blob, 32);
    ssh_mem_copy(server_pub_blob + 4, conn->server_ephemeral_pub, 32);
    sha256_update(&hash_ctx, server_pub_blob, 36);

    /* K: shared secret encoded as an SSH positive mpint. */
    sha256_update_mpint(&hash_ctx, conn->shared_secret);

    sha256_final(&hash_ctx, conn->exchange_hash);
    ssh_mem_copy(conn->session_id, conn->exchange_hash,
                 sizeof(conn->session_id));

    /* Build KEXDH_REPLY */
    uint8_t reply[512];
    uint32_t rpos = 0;
    reply[rpos++] = 31;

    /* host key */
    uint32_t host_key_blob_len = 4 + 11 + 4 + 32;
    ssh_write_u32_be(reply + rpos, host_key_blob_len); rpos += 4;
    ssh_write_u32_be(reply + rpos, 11); rpos += 4;
    ssh_mem_copy(reply + rpos, "ssh-ed25519", 11); rpos += 11;
    ssh_write_u32_be(reply + rpos, 32); rpos += 4;
    ssh_mem_copy(reply + rpos, host_pub, 32); rpos += 32;

    /* f (server public) */
    ssh_write_u32_be(reply + rpos, 32); rpos += 4;
    ssh_mem_copy(reply + rpos, conn->server_ephemeral_pub, 32); rpos += 32;

    /* Signature */
    uint8_t signature[64];
    uint8_t host_priv[32];
    ssh_host_key_get_private(host_priv);
    xaios_ed25519_sign(signature, conn->exchange_hash, 32, host_pub,
                       host_priv);

    ssh_write_u32_be(reply + rpos, 4 + 11 + 4 + 64); rpos += 4;
    ssh_write_u32_be(reply + rpos, 11); rpos += 4;
    ssh_mem_copy(reply + rpos, "ssh-ed25519", 11); rpos += 11;
    ssh_write_u32_be(reply + rpos, 64); rpos += 4;
    ssh_mem_copy(reply + rpos, signature, 64); rpos += 64;

    if (ssh_packet_write(sockfd, reply, rpos) != 0) return -1;

    /* Send NEWKEYS */
    uint8_t newkeys = 21;
    if (ssh_packet_write(sockfd, &newkeys, 1) != 0) return -1;

    conn->state = SSH_STATE_NEWKEYS_SENT;
    return 0;
  }

  if (conn->state == SSH_STATE_NEWKEYS_SENT) {
    /* Receive NEWKEYS */
    int packet_status = ssh_packet_read(sockfd, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0) return -1;
    if (pkt->len == 0 || pkt->data[0] != 21) return -1;

    conn_init_encryption(conn, conn->shared_secret, 32,
                         conn->exchange_hash, 32);

    ssh_log(SSH_LOG_INFO, "KEX completed for connection %llx\n", conn->sockfd);
    conn->state = SSH_STATE_AUTH;
    return 0;
  }

  if (conn->state == SSH_STATE_AUTH) {
    int packet_status = conn_packet_read_encrypted(conn, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0) return -1;
    if (pkt->len == 0) return 0;
    uint8_t msg = pkt->data[0];

    if (msg == SSH_MSG_SERVICE_REQUEST) {
      uint8_t sa[32];
      sa[0] = SSH_MSG_SERVICE_ACCEPT;
      const char *svc = "ssh-userauth";
      uint32_t svc_len = ssh_str_len(svc);
      ssh_write_u32_be(sa + 1, svc_len);
      ssh_mem_copy(sa + 5, svc, svc_len);
      conn_packet_write_encrypted(conn, sa, 5 + svc_len);
      return 0;
    }

    if (msg == SSH_MSG_USERAUTH_REQUEST) {
      uint32_t offset = 1;
      if (offset + 4U > pkt->len) return 0;
      uint32_t user_len = ssh_read_string_len(pkt->data + offset);
      offset += 4U;
      if (user_len > 64U || offset + user_len > pkt->len) return 0;
      char username[65];
      ssh_mem_copy(username, pkt->data + offset, user_len);
      username[user_len] = '\0';
      offset += user_len;

      if (offset + 4U > pkt->len) return 0;
      uint32_t service_len = ssh_read_string_len(pkt->data + offset);
      offset += 4U;
      if (service_len > 64U || offset + service_len > pkt->len) return 0;
      char service[65];
      ssh_mem_copy(service, pkt->data + offset, service_len);
      service[service_len] = '\0';
      offset += service_len;
      if (!ssh_str_eq(service, "ssh-connection")) return 0;

      if (offset + 4U > pkt->len) return 0;
      uint32_t method_len = ssh_read_string_len(pkt->data + offset);
      offset += 4U;
      if (method_len > 64U || offset + method_len > pkt->len) return 0;
      char method[65];
      ssh_mem_copy(method, pkt->data + offset, method_len);
      method[method_len] = '\0';
      offset += method_len;
      uint32_t auth_data_offset = offset;

      if (check_rate_limit(&conn->client_addr) != 0) {
        uint8_t reject[64];
        reject[0] = SSH_MSG_USERAUTH_FAILURE;
        const char *methods = "password,publickey";
        uint32_t mlen = ssh_str_len(methods);
        ssh_write_u32_be(reject + 1, mlen);
        ssh_mem_copy(reject + 5, methods, mlen);
        reject[5 + mlen] = 0;
        conn_packet_write_encrypted(conn, reject, 6 + mlen);
        return 0;
      }

      if (conn->auth_attempts >= SSHD_MAX_AUTH_ATTEMPTS) {
        record_auth_failure(&conn->client_addr);
        uint8_t reject[64];
        reject[0] = SSH_MSG_USERAUTH_FAILURE;
        const char *methods = "password,publickey";
        uint32_t mlen = ssh_str_len(methods);
        ssh_write_u32_be(reject + 1, mlen);
        ssh_mem_copy(reject + 5, methods, mlen);
        reject[5 + mlen] = 0;
        conn_packet_write_encrypted(conn, reject, 6 + mlen);
        return 0;
      }

      /* ---- "password" method ---- */
      if (ssh_str_eq(method, "password")) {
        uint32_t password_offset = auth_data_offset;
        if (password_offset + 5U > pkt->len) return 0;
        if (pkt->data[password_offset] != 0U) return 0;
        password_offset += 1U;
        uint32_t pass_len = ssh_read_string_len(pkt->data + password_offset);
        if (pass_len > 128U || password_offset + 4U + pass_len > pkt->len) return 0;
        char password[129];
        ssh_mem_copy(password, pkt->data + password_offset + 4U, pass_len);
        password[pass_len] = '\0';

        if (authenticate_password(username, password) == 0) {
          uint8_t auth_reply[1] = {SSH_MSG_USERAUTH_SUCCESS};
          conn_packet_write_encrypted(conn, auth_reply, 1);
          conn->auth_attempts = 0;
          record_auth_success(&conn->client_addr);
          ssh_log(SSH_LOG_INFO, "Password auth success: '%s'\n", username);
          conn->state = SSH_STATE_AUTHENTICATED;
        } else {
          conn->auth_attempts++;
          record_auth_failure(&conn->client_addr);
          uint8_t reject[64];
          reject[0] = SSH_MSG_USERAUTH_FAILURE;
          const char *methods = "password,publickey";
          uint32_t mlen = ssh_str_len(methods);
          ssh_write_u32_be(reject + 1, mlen);
          ssh_mem_copy(reject + 5, methods, mlen);
          reject[5 + mlen] = 0;
          conn_packet_write_encrypted(conn, reject, 6 + mlen);
          ssh_log(SSH_LOG_WARN, "Password auth failed: '%s'\n", username);
        }
        return 0;
      }

      /* ---- "publickey" method (RFC 4252 Section 7) ---- */
      if (ssh_str_eq(method, "publickey")) {
        offset = auth_data_offset;
        if (offset + 1 > pkt->len) return 0;
        uint8_t has_signature = pkt->data[offset];
        offset += 1;

        /* Read public key algorithm */
        if (offset + 4 > pkt->len) return 0;
        uint32_t algo_len = ssh_read_string_len(pkt->data + offset);
        offset += 4;
        if (offset + algo_len > pkt->len) return 0;
        offset += algo_len;

        /* Read public key blob */
        if (offset + 4 > pkt->len) return 0;
        uint32_t pubkey_len = ssh_read_string_len(pkt->data + offset);
        offset += 4;
        if (pubkey_len != 32 || offset + 32 > pkt->len) return 0;
        uint8_t client_pubkey[32];
        ssh_mem_copy(client_pubkey, pkt->data + offset, 32);
        offset += 32;

        load_authorized_keys();

        if (check_authorized_key(client_pubkey) != 0) {
          ssh_log(SSH_LOG_WARN, "Public key not authorized\n");
          uint8_t reject[64];
          reject[0] = SSH_MSG_USERAUTH_FAILURE;
          const char *methods = "password,publickey";
          uint32_t mlen = ssh_str_len(methods);
          ssh_write_u32_be(reject + 1, mlen);
          ssh_mem_copy(reject + 5, methods, mlen);
          reject[5 + mlen] = 0;
          conn_packet_write_encrypted(conn, reject, 6 + mlen);
          return 0;
        }

        if (!has_signature) {
          /* Test request: public key is acceptable */
          uint8_t pk_ok[64];
          pk_ok[0] = SSH_MSG_USERAUTH_PK_OK;
          uint32_t poff = 1;
          ssh_write_u32_be(pk_ok + poff, algo_len); poff += 4;
          ssh_mem_copy(pk_ok + poff, pkt->data + offset - 32 - 4, algo_len);
          poff += algo_len;
          ssh_write_u32_be(pk_ok + poff, 32); poff += 4;
          ssh_mem_copy(pk_ok + poff, client_pubkey, 32); poff += 32;
          conn_packet_write_encrypted(conn, pk_ok, poff);
          return 0;
        }

        /* Read signature blob */
        if (offset + 4 > pkt->len) return 0;
        uint32_t sig_len = ssh_read_string_len(pkt->data + offset);
        offset += 4;
        if (offset + sig_len > pkt->len) return 0;
        uint8_t *sig_blob = pkt->data + offset;

        /* Parse signature: string algorithm + string (R,s) */
        uint32_t sig_algo_len = ssh_read_string_len(sig_blob);
        uint32_t sig_data_off = 4 + sig_algo_len;
        if (sig_data_off + 4 > sig_len) return 0;
        uint32_t sig_data_len = ssh_read_string_len(sig_blob + sig_data_off);
        if (sig_data_off + 4 + sig_data_len > sig_len) return 0;
        uint8_t *sig_data = sig_blob + sig_data_off + 4;
        if (sig_data_len != 64) return 0;

        /* Build data to verify: session_id || SSH_MSG_USERAUTH_REQUEST packet */
        uint8_t verify_buf[1024];
        uint32_t vpos = 0;
        ssh_write_u32_be(verify_buf + vpos, 32U);
        vpos += 4U;
        ssh_mem_copy(verify_buf + vpos, conn->session_id, 32U);
        vpos += 32U;
        ssh_mem_copy(verify_buf + vpos, pkt->data, pkt->len);
        vpos += pkt->len;

        int verify_result = xaios_ed25519_verify(sig_data, verify_buf, vpos,
                                                  client_pubkey);
        if (verify_result == 0) {
          uint8_t auth_reply[1] = {SSH_MSG_USERAUTH_SUCCESS};
          conn_packet_write_encrypted(conn, auth_reply, 1);
          conn->auth_attempts = 0;
          record_auth_success(&conn->client_addr);
          ssh_log(SSH_LOG_INFO, "Public key auth success\n");
          conn->state = SSH_STATE_AUTHENTICATED;
        } else {
          conn->auth_attempts++;
          record_auth_failure(&conn->client_addr);
          uint8_t reject[64];
          reject[0] = SSH_MSG_USERAUTH_FAILURE;
          const char *methods = "password,publickey";
          uint32_t mlen = ssh_str_len(methods);
          ssh_write_u32_be(reject + 1, mlen);
          ssh_mem_copy(reject + 5, methods, mlen);
          reject[5 + mlen] = 0;
          conn_packet_write_encrypted(conn, reject, 6 + mlen);
          ssh_log(SSH_LOG_WARN, "Public key auth failed (verify)\n");
        }
        return 0;
      }

      /* Unknown auth method */
      {
        uint8_t reject[64];
        reject[0] = SSH_MSG_USERAUTH_FAILURE;
        const char *methods = "password,publickey";
        uint32_t mlen = ssh_str_len(methods);
        ssh_write_u32_be(reject + 1, mlen);
        ssh_mem_copy(reject + 5, methods, mlen);
        reject[5 + mlen] = 0;
        conn_packet_write_encrypted(conn, reject, 6 + mlen);
      }
      return 0;
    }

    return 0;
  }

  if (conn->state == SSH_STATE_AUTHENTICATED ||
      conn->state == SSH_STATE_CHANNEL) {
    conn->state = SSH_STATE_CHANNEL;

    /* Rekey negotiation is not implemented; expire the encrypted session. */
    uint64_t total_sent = conn->crypto.encrypt_seq;
    uint64_t elapsed = now - conn->kex_start_time;
    if (total_sent >= 1048576 || elapsed >= SSHD_REKEY_INTERVAL) {
      ssh_log(SSH_LOG_INFO, "Closing session at re-key boundary\n");
      return -1;
    }

    /* Check keepalive */
    if (now - conn->last_keepalive > SSHD_KEEPALIVE_INTERVAL) {
      uint8_t keepalive[32];
      keepalive[0] = SSH_MSG_GLOBAL_REQUEST;
      const char *ka_name = "keepalive@xaios.os";
      uint32_t ka_len = ssh_str_len(ka_name);
      ssh_write_u32_be(keepalive + 1, ka_len);
      ssh_mem_copy(keepalive + 5, ka_name, ka_len);
      keepalive[5 + ka_len] = 1;
      conn_packet_write_encrypted(conn, keepalive, 6 + ka_len);
      conn->last_keepalive = now;
      if (now - conn->last_activity > SSHD_TIMEOUT_IDLE) {
        ssh_log(SSH_LOG_WARN, "Idle timeout\n");
        return -1;
      }
    }

    /* Read one packet */
    int packet_status = conn_packet_read_encrypted(conn, pkt);
    if (packet_status > 0) return 0;
    if (packet_status < 0) return -1;
    if (pkt->len == 0) return 0;

    conn->last_activity = now;
    uint8_t msg = pkt->data[0];

    if (msg == SSH_MSG_GLOBAL_REQUEST) {
      return 0;
    }

    if (msg >= 90 && msg <= 100) {
      if (ssh_channel_handle_packet(sockfd, pkt) != 0) return -1;
      return 0;
    }

    if (msg == SSH_MSG_DISCONNECT) {
      ssh_log(SSH_LOG_INFO, "Client disconnected\n");
      return -1;
    }

    /* Unknown message */
    return 0;
  }

  return 0;
}

/* ---- Cooperative Polling Main Loop ---- */
int sshd_run(void) {
  int crypto_status = ssh_crypto_self_test();
  if (crypto_status != 0) {
    ssh_log(SSH_LOG_ERROR, "SSH crypto self-test failed check=%u\n",
            (uint64_t)(uint32_t)(-crypto_status));
    return -1;
  }
  ssh_log(SSH_LOG_INFO, "SSH crypto self-test passed\n");

  load_user_database();
  load_authorized_keys();

  ssh_mem_zero(&g_server_stats, sizeof(g_server_stats));

  ssh_conn_pool_init();

  u64 listen_fd = 0;
  if (xaios_net_listen(SSHD_PORT, &listen_fd) != 0) {
    ssh_log(SSH_LOG_ERROR, "Failed to listen on port %u\n", SSHD_PORT);
    return -1;
  }
  u64 udp_fd = 0;
  if (xaios_net_bind_udp(SSHD_UDP_ECHO_PORT, &udp_fd) != 0) {
    ssh_log(SSH_LOG_ERROR, "Failed to bind UDP port %u\n",
            SSHD_UDP_ECHO_PORT);
    xaios_net_close(listen_fd);
    return -1;
  }
  ssh_log(SSH_LOG_INFO, "SSH server listening on port %u\n", SSHD_PORT);
  ssh_log(SSH_LOG_INFO, "UDP echo service listening on port %u\n",
          SSHD_UDP_ECHO_PORT);
  ssh_log(SSH_LOG_INFO, "Cooperative polling: max %u concurrent connections\n",
          (uint64_t)SSH_MAX_CONNECTIONS);

  ssh_channel_init();

  for (;;) {
    for (uint32_t i = 0; i < 4U; ++i) {
      uint8_t udp_buffer[1400];
      xaios_ip_addr_user_t source_addr;
      u64 bytes_read = 0;
      u64 bytes_written = 0;
      xaios_memzero(&source_addr, sizeof(source_addr));
      if (xaios_net_recvfrom(udp_fd, udp_buffer, sizeof(udp_buffer),
                             &bytes_read, &source_addr) != 0 ||
          bytes_read == 0) {
        break;
      }
      if (xaios_net_send(udp_fd, udp_buffer, bytes_read, &bytes_written) != 0 ||
          bytes_written != bytes_read) {
        ssh_log(SSH_LOG_WARN, "UDP echo send failed\n");
      } else {
        ssh_log(SSH_LOG_INFO, "UDP payload delivered bytes=%u\n", bytes_read);
      }
    }

    /* Try to accept new connections (non-blocking) */
    for (uint32_t i = 0; i < 4; ++i) {
      u64 conn_fd = 0;
      xaios_ip_addr_user_t peer_addr;
      u64 peer_port = 0;
      xaios_memzero(&peer_addr, sizeof(peer_addr));
      if (xaios_net_accept_addr(listen_fd, &conn_fd, &peer_addr, &peer_port) != 0) {
        break;
      }

      uint32_t active = __atomic_load_n(&g_server_stats.active_connections,
                                         __ATOMIC_ACQUIRE);
      if (active >= SSH_MAX_CONNECTIONS) {
        ssh_log(SSH_LOG_WARN, "Max connections reached\n");
        __atomic_add_fetch(&g_server_stats.rejected_connections, 1,
                           __ATOMIC_RELEASE);
        xaios_net_close(conn_fd);
        continue;
      }

      ssh_connection_t *conn = ssh_conn_alloc();
      if (!conn) {
        xaios_net_close(conn_fd);
        continue;
      }

      conn->sockfd = conn_fd;
      conn->client_addr = peer_addr;
      conn->client_port = (uint16_t)peer_port;
      conn->state = SSH_STATE_INIT;
      conn->last_activity = timer_now();
      conn->last_keepalive = conn->last_activity;
      conn->connect_time = conn->last_activity;
      conn->version_len = 0;
      conn->auth_attempts = 0;

      __atomic_add_fetch(&g_server_stats.total_connections, 1, __ATOMIC_RELEASE);
      __atomic_add_fetch(&g_server_stats.active_connections, 1, __ATOMIC_RELEASE);
      ssh_log(SSH_LOG_INFO, "Accepted connection %llx (total: %u)\n",
              conn_fd, active + 1);
    }

    /* Process each active connection (cooperative time-slicing) */
    for (uint32_t i = 0; i < SSH_MAX_CONNECTIONS; ++i) {
      ssh_connection_t *conn = ssh_conn_by_index(i);
      if (!conn) continue;

      /* Check for timeouts */
      uint64_t now = timer_now();
      if (conn->state == SSH_STATE_INIT || conn->state == SSH_STATE_KEX ||
          conn->state == SSH_STATE_KEX_SENT || conn->state == SSH_STATE_NEWKEYS ||
          conn->state == SSH_STATE_NEWKEYS_SENT) {
        if (now - conn->connect_time > SSHD_TIMEOUT_CONNECT) {
          ssh_log(SSH_LOG_WARN, "Connect timeout\n");
          goto close_conn;
        }
      }
      if (conn->state == SSH_STATE_AUTH) {
        if (now - conn->connect_time > SSHD_TIMEOUT_AUTH) {
          ssh_log(SSH_LOG_WARN, "Auth timeout\n");
          goto close_conn;
        }
      }

      int result = process_connection(conn);
      if (result != 0) {
close_conn:
        /* Send disconnect message if encrypted */
        if (conn->state >= SSH_STATE_AUTH) {
          uint8_t disconnect_msg[17];
          ssh_mem_zero(disconnect_msg, sizeof(disconnect_msg));
          disconnect_msg[0] = SSH_MSG_DISCONNECT;
          ssh_write_u32_be(disconnect_msg + 1, SSH_DISCONNECT_BY_APPLICATION);
          ssh_write_u32_be(disconnect_msg + 5, 0);
          ssh_write_u32_be(disconnect_msg + 9, 0);
          conn_packet_write_encrypted(conn, disconnect_msg, 13);
        }

        ssh_channel_close_connection((int)conn->sockfd);
        xaios_net_close(conn->sockfd);
        __atomic_sub_fetch(&g_server_stats.active_connections, 1,
                           __ATOMIC_RELEASE);
        ssh_conn_free(conn);
        ssh_log(SSH_LOG_INFO, "Connection closed\n");
      }
    }
  }

  return 0;
}

int main(void) {
  int status = sshd_run();
  xaios_exit(status == 0 ? 0 : 1);
  return 0;
}
