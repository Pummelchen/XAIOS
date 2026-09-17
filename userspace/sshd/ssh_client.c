#include "ssh_client.h"

#include "ssh_client_scp.h"
#include "ssh_sftp.h"

#include "ssh_channel.h"
#include "ssh_connection.h"
#include "ssh_crypto.h"
#include "ssh_identity.h"
#include "ssh_known_hosts.h"
#include "ssh_mlkem.h"
#include "ssh_protocol.h"
#include "ssh_utils.h"
#include "tweetnacl_subset.h"
#include <xaios_user.h>

#if defined(XAIOS_SSH_CLIENT_APP)
#define SSH_CLIENT_CONTEXTS 1U
#else
#define SSH_CLIENT_CONTEXTS SSH_MAX_CLIENT_CONNECTIONS
#endif
/* How long a credential prompt waits for an answer before giving up.
 *
 * B-37. This client cannot ask whether the session it was launched in has a
 * terminal: the child is handed a channel id, a working directory and a
 * command line, and nothing else -- no PTY flag reaches it. So a prompt
 * written into a session nobody is sitting at, which is every script and
 * every CI job, used to wait for an answer that could not arrive, and the
 * caller saw a command that never returned. A bounded wait turns that into a
 * failure with a reason, which a script can act on. The clock measures
 * silence rather than total time: every byte typed at the prompt restarts
 * it, so a person part-way through a passphrase is never cut off mid-word.
 */
#define SSH_CLIENT_PROMPT_IDLE_NS UINT64_C(60000000000)
#define SSH_CLIENT_RELAY_SOCKET UINT32_C(0x7fff0001)

static ssh_client_context_t g_clients[SSH_CLIENT_CONTEXTS];

#if defined(XAIOS_SSH_CLIENT_APP)
static char g_client_app_cwd[SSH_CLIENT_PATH_MAX];

void ssh_client_app_set_cwd(const char *cwd) {
  if (cwd == 0) {
    g_client_app_cwd[0] = '\0';
    return;
  }
  (void)sshclient_string_copy(g_client_app_cwd, sizeof(g_client_app_cwd), cwd);
}
#endif

static int proxy_stream_send(void *context, const uint8_t *data,
                             u64 length, u64 *sent);
static int proxy_stream_recv(void *context, uint8_t *data,
                             u64 length, u64 *received);

static int bytes_equal(const uint8_t *a, const uint8_t *b, uint32_t length) {
  uint8_t difference = 0U;
  for (uint32_t i = 0U; i < length; ++i) difference |= a[i] ^ b[i];
  return difference == 0U;
}

uint32_t sshclient_string_copy(char *output, uint32_t capacity,
                               const char *input) {
  uint32_t length = 0U;
  if (capacity == 0U) return 0U;
  while (input[length] != '\0' && length + 1U < capacity) {
    output[length] = input[length];
    ++length;
  }
  output[length] = '\0';
  return length;
}

static int output_text(const ssh_client_context_t *client, const char *text) {
  return ssh_channel_send_data((int)client->outer_sockfd,
                               client->outer_remote_id,
                               (const uint8_t *)text, ssh_str_len(text));
}

static ssh_client_context_t *client_for_channel(const ssh_channel_t *channel) {
  if (channel == 0 || channel->ssh_client_slot == 0U ||
      channel->ssh_client_slot > SSH_CLIENT_CONTEXTS) {
    return 0;
  }
  ssh_client_context_t *client =
      &g_clients[channel->ssh_client_slot - 1U];
  return client->active != 0U ? client : 0;
}

static ssh_client_context_t *client_allocate(ssh_channel_t *channel) {
  for (uint32_t i = 0U; i < SSH_CLIENT_CONTEXTS; ++i) {
    if (g_clients[i].active != 0U) continue;
    ssh_mem_zero(&g_clients[i], sizeof(g_clients[i]));
    g_clients[i].active = 1U;
    g_clients[i].outer_sockfd = channel->owner_sockfd;
    g_clients[i].outer_remote_id = channel->remote_id;
    g_clients[i].port = 22U;
    channel->ssh_client_slot = i + 1U;
    return &g_clients[i];
  }
  return 0;
}

static void client_release(ssh_channel_t *channel,
                           ssh_client_context_t *client) {
  if (client == 0) return;
  if (client->sockfd != 0U && client->sockfd != SSH_CLIENT_RELAY_SOCKET)
    (void)xaios_net_close(client->sockfd);
  if (client->transport != 0) ssh_conn_free(client->transport);
  if (client->proxy_transport != 0) {
    if (client->proxy_transport->crypto.enabled != 0) {
      uint8_t close[5] = {SSH_MSG_CHANNEL_CLOSE, 0U, 0U, 0U, 0U};
      ssh_write_u32_be(close + 1U, client->proxy_remote_channel);
      (void)ssh_packet_write_encrypted((int)client->proxy_sockfd, close,
                                       sizeof(close));
    }
    ssh_conn_free(client->proxy_transport);
  }
  if (client->proxy_sockfd != 0U) (void)xaios_net_close(client->proxy_sockfd);
  ssh_mem_zero(client->password, sizeof(client->password));
  ssh_mem_zero(client, sizeof(*client));
  if (channel != 0) channel->ssh_client_slot = 0U;
}

uint32_t append_string(uint8_t *buffer, uint32_t position,
                              uint32_t capacity, const uint8_t *value,
                              uint32_t value_length) {
  if (position > capacity || value_length > capacity - position - 4U)
    return UINT32_MAX;
  ssh_write_u32_be(buffer + position, value_length);
  position += 4U;
  ssh_mem_copy(buffer + position, value, value_length);
  return position + value_length;
}

static void sha256_update_string(sha256_ctx_t *context, const uint8_t *value,
                                 uint32_t value_length) {
  uint8_t encoded[4];
  ssh_write_u32_be(encoded, value_length);
  sha256_update(context, encoded, sizeof(encoded));
  sha256_update(context, value, value_length);
}

static void sha256_update_mpint(sha256_ctx_t *context,
                                const uint8_t value[32]) {
  uint32_t first = 0U;
  while (first < 32U && value[first] == 0U) ++first;
  uint32_t length = 32U - first;
  uint32_t leading_zero =
      length != 0U && (value[first] & UINT8_C(0x80)) != 0U;
  uint8_t encoded[4];
  ssh_write_u32_be(encoded, length + leading_zero);
  sha256_update(context, encoded, sizeof(encoded));
  if (leading_zero != 0U) {
    static const uint8_t zero = 0U;
    sha256_update(context, &zero, 1U);
  }
  if (length != 0U) sha256_update(context, value + first, length);
}

static void sha256_update_kex_secret(sha256_ctx_t *context,
                                     const uint8_t value[32],
                                     uint32_t hybrid) {
  if (hybrid != 0U)
    sha256_update_string(context, value, 32U);
  else
    sha256_update_mpint(context, value);
}

static void derive_one(const uint8_t shared_secret[32], uint32_t hybrid,
                       const uint8_t exchange_hash[32],
                       const uint8_t session_id[32], uint8_t letter,
                       uint8_t output[32]) {
  sha256_ctx_t context;
  sha256_init(&context);
  sha256_update_kex_secret(&context, shared_secret, hybrid);
  sha256_update(&context, exchange_hash, 32U);
  sha256_update(&context, &letter, 1U);
  sha256_update(&context, session_id, 32U);
  sha256_final(&context, output);
  ssh_mem_zero(&context, sizeof(context));
}

static int derive_client_crypto(ssh_connection_t *connection) {
  uint8_t derived[32];
  ssh_connection_crypto_t *crypto = &connection->crypto;
  ssh_mem_zero(crypto, sizeof(*crypto));
  derive_one(connection->shared_secret, connection->kex_hybrid,
             connection->exchange_hash,
             connection->session_id, (uint8_t)'A', derived);
  ssh_mem_copy(crypto->encrypt_iv, derived, 16U);
  derive_one(connection->shared_secret, connection->kex_hybrid,
             connection->exchange_hash,
             connection->session_id, (uint8_t)'B', derived);
  ssh_mem_copy(crypto->decrypt_iv, derived, 16U);
  derive_one(connection->shared_secret, connection->kex_hybrid,
             connection->exchange_hash,
             connection->session_id, (uint8_t)'C', derived);
  aes128_init(&crypto->encrypt_ctx, derived);
  derive_one(connection->shared_secret, connection->kex_hybrid,
             connection->exchange_hash,
             connection->session_id, (uint8_t)'D', derived);
  aes128_init(&crypto->decrypt_ctx, derived);
  derive_one(connection->shared_secret, connection->kex_hybrid,
             connection->exchange_hash,
             connection->session_id, (uint8_t)'E', derived);
  ssh_mem_copy(crypto->encrypt_mac_key, derived, 32U);
  derive_one(connection->shared_secret, connection->kex_hybrid,
             connection->exchange_hash,
             connection->session_id, (uint8_t)'F', derived);
  ssh_mem_copy(crypto->decrypt_mac_key, derived, 32U);
  crypto->encrypt_seq = 3U;
  crypto->decrypt_seq = 3U;
  crypto->enabled = 1;
  ssh_mem_zero(derived, sizeof(derived));
  return 0;
}

static int wait_plain_packet_fd(int sockfd, ssh_packet_t *packet,
                                uint64_t deadline) {
  for (;;) {
    int result = ssh_packet_read(sockfd, packet);
    if (result <= 0) return result;
    if (xaios_clock_nanos() >= deadline) return -1;
  }
}

static int wait_plain_packet(ssh_client_context_t *client, ssh_packet_t *packet,
                             uint64_t deadline) {
  return wait_plain_packet_fd((int)client->sockfd, packet, deadline);
}

static int wait_encrypted_packet_fd(int sockfd, ssh_packet_t *packet,
                                    uint64_t deadline) {
  for (;;) {
    int result = ssh_packet_read_encrypted(sockfd, packet);
    if (result <= 0) return result;
    if (xaios_clock_nanos() >= deadline) return -1;
  }
}

int wait_encrypted_packet(ssh_client_context_t *client,
                                 ssh_packet_t *packet, uint64_t deadline) {
  return wait_encrypted_packet_fd((int)client->sockfd, packet, deadline);
}

static int build_kexinit(uint8_t *buffer, uint32_t capacity,
                         uint32_t *out_length) {
  uint32_t position = 0U;
  if (capacity < 256U) return -1;
  buffer[position++] = SSH_MSG_KEXINIT;
  if (crypto_random_bytes(buffer + position, 16U) != 0) return -1;
  position += 16U;
  static const char *lists[] = {
      "mlkem768x25519-sha256,curve25519-sha256", "ssh-ed25519",
      "aes128-ctr", "aes128-ctr",
      "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", ""};
  for (uint32_t i = 0U; i < 10U; ++i) {
    uint32_t length = ssh_str_len(lists[i]);
    position = append_string(buffer, position, capacity,
                             (const uint8_t *)lists[i], length);
    if (position == UINT32_MAX) return -1;
  }
  buffer[position++] = 0U;
  ssh_write_u32_be(buffer + position, 0U);
  position += 4U;
  *out_length = position;
  return 0;
}

static int list_has_name(const uint8_t *list, uint32_t length,
                         const char *name) {
  uint32_t name_length = ssh_str_len(name);
  uint32_t start = 0U;
  for (uint32_t i = 0U; i <= length; ++i) {
    if (i != length && list[i] != ',') continue;
    if (i - start == name_length &&
        bytes_equal(list + start, (const uint8_t *)name, name_length)) {
      return 1;
    }
    start = i + 1U;
  }
  return 0;
}

static int validate_server_kexinit(const ssh_packet_t *packet,
                                   uint32_t *hybrid) {
  static const char *required[] = {
      "curve25519-sha256", "ssh-ed25519", "aes128-ctr", "aes128-ctr",
      "hmac-sha2-256", "hmac-sha2-256", "none", "none"};
  if (packet == 0 || packet->len < 62U ||
      packet->data[0] != SSH_MSG_KEXINIT) return -1;
  uint32_t position = 17U;
  for (uint32_t i = 0U; i < 10U; ++i) {
    if (position + 4U > packet->len) return -1;
    uint32_t length = ssh_read_u32_be(packet->data + position);
    position += 4U;
    if (length > packet->len - position) return -1;
    if (i == 0U) {
      if (list_has_name(packet->data + position, length,
                        "mlkem768x25519-sha256"))
        *hybrid = 1U;
      else if (list_has_name(packet->data + position, length,
                             "curve25519-sha256"))
        *hybrid = 0U;
      else
        return -1;
    } else if (i < 8U &&
        !list_has_name(packet->data + position, length, required[i])) {
      return -1;
    }
    position += length;
  }
  return position + 5U == packet->len && packet->data[position] == 0U ? 0 : -1;
}

static int parse_ipv4(const char *text, xaios_ip_addr_user_t *address) {
  uint32_t part = 0U;
  uint32_t value = 0U;
  uint32_t digits = 0U;
  xaios_memzero(address, sizeof(*address));
  for (uint32_t i = 0U;; ++i) {
    char character = text[i];
    if (character >= '0' && character <= '9') {
      value = value * 10U + (uint32_t)(character - '0');
      if (value > 255U || ++digits > 3U) return -1;
    } else if (character == '.' || character == '\0') {
      if (digits == 0U || part >= 4U) return -1;
      address->addr[part++] = (uint8_t)value;
      value = 0U;
      digits = 0U;
      if (character == '\0') break;
    } else {
      return -1;
    }
  }
  if (part != 4U) return -1;
  address->family = 4U;
  return 0;
}

static int hex_value(char character);

static int parse_ipv6_hex(const char *text, uint32_t length, uint16_t *value) {
  uint32_t parsed = 0U;
  if (length == 0U || length > 4U) return -1;
  for (uint32_t i = 0U; i < length; ++i) {
    int digit = hex_value(text[i]);
    if (digit < 0) return -1;
    parsed = (parsed << 4U) | (uint32_t)digit;
  }
  *value = (uint16_t)parsed;
  return 0;
}

static int parse_ipv6(const char *text, xaios_ip_addr_user_t *address) {
  uint16_t groups[8];
  uint32_t group_count = 0U;
  uint32_t compressed_at = UINT32_MAX;
  uint32_t position = 0U;
  uint32_t length = ssh_str_len(text);
  if (length == 0U) return -1;
  if (text[position] == ':' && text[position + 1U] == ':') {
    compressed_at = 0U;
    position += 2U;
  }
  while (position < length) {
    if (group_count >= 8U) return -1;
    uint32_t start = position;
    while (position < length && text[position] != ':') ++position;
    if (parse_ipv6_hex(text + start, position - start,
                       &groups[group_count++]) != 0) return -1;
    if (position == length) break;
    ++position;
    if (position < length && text[position] == ':') {
      if (compressed_at != UINT32_MAX) return -1;
      compressed_at = group_count;
      ++position;
      if (position == length) break;
    }
  }
  if (compressed_at == UINT32_MAX) {
    if (group_count != 8U) return -1;
  } else {
    if (group_count >= 8U) return -1;
    uint32_t missing = 8U - group_count;
    for (uint32_t i = group_count; i > compressed_at; --i)
      groups[i + missing - 1U] = groups[i - 1U];
    for (uint32_t i = 0U; i < missing; ++i) groups[compressed_at + i] = 0U;
  }
  xaios_memzero(address, sizeof(*address));
  address->family = 6U;
  for (uint32_t i = 0U; i < 8U; ++i) {
    address->addr[i * 2U] = (uint8_t)(groups[i] >> 8U);
    address->addr[i * 2U + 1U] = (uint8_t)groups[i];
  }
  return 0;
}

static int resolve_host(const char *host, xaios_ip_addr_user_t *address,
                        uint64_t deadline) {
  if (parse_ipv4(host, address) == 0) return 0;
  if (parse_ipv6(host, address) == 0) return 0;
  uint32_t family = 4U;
  while (xaios_clock_nanos() < deadline) {
    int status = xaios_net_resolve_address(host, family, address);
    if (status == 0) return 0;
    if (status != XAIOS_ERR_BUSY) {
      if (family == 4U) {
        family = 6U;
        continue;
      }
      return -1;
    }
  }
  return -1;
}

static int hex_value(char character) {
  if (character >= '0' && character <= '9') return character - '0';
  if (character >= 'a' && character <= 'f') return character - 'a' + 10;
  if (character >= 'A' && character <= 'F') return character - 'A' + 10;
  return -1;
}

/* Reading the file is in ssh_known_hosts.c, where it can be argued with
   directly: what B-01 turned on is a property about text and chunk
   boundaries, and a property like that should not need a booted guest and a
   real peer to check. */
struct known_hosts_file {
  int fd;
};

static long long known_hosts_read(void *context, void *buffer,
                                  unsigned long long size,
                                  unsigned long long offset) {
  struct known_hosts_file *file = (struct known_hosts_file *)context;
  return (long long)xaios_fs_pread(file->fd, buffer, size, offset);
}

static ssh_known_host_result_t known_host_lookup(
    const char *path, const char *expected, uint32_t expected_length,
    const uint8_t public_key[32]) {
  struct known_hosts_file file;
  file.fd = xaios_fs_open(path, XAIOS_XBFS_OPEN_READ);
  if (file.fd < 0) return SSH_KNOWN_HOST_ABSENT;
  ssh_known_host_result_t result = ssh_known_hosts_scan(
      known_hosts_read, &file, expected, expected_length, public_key);
  (void)xaios_fs_close(file.fd);
  return result;
}

static int verify_known_host(ssh_client_context_t *client,
                             const uint8_t public_key[32]) {
  static const char path[] = "/home/admin/.ssh/known_hosts";
  char expected[SSH_CLIENT_HOST_MAX + 8U];
  uint32_t expected_length = 0U;
  uint32_t port = client->port;
  uint32_t host_length = ssh_str_len(client->host);
  if (host_length + 7U >= sizeof(expected)) return -1;
  ssh_mem_copy(expected, client->host, host_length);
  expected_length = host_length;
  expected[expected_length++] = ':';
  char digits[5];
  uint32_t digit_count = 0U;
  do {
    digits[digit_count++] = (char)('0' + port % 10U);
    port /= 10U;
  } while (port != 0U);
  while (digit_count != 0U) expected[expected_length++] = digits[--digit_count];
  expected[expected_length] = '\0';

  ssh_known_host_result_t known = known_host_lookup(path, expected,
                                                    expected_length,
                                                    public_key);
  if (known == SSH_KNOWN_HOST_MATCH) return 0;
  if (known == SSH_KNOWN_HOST_MISMATCH) return -1;
  if (known == SSH_KNOWN_HOST_UNREADABLE) {
    /* Refused, not appended. A file this program cannot read may already hold
       a different key for this host, and adding a second line for it would
       leave the machine trusting a key it has no reason to. */
    (void)output_text(client,
                      "ssh: cannot read /home/admin/.ssh/known_hosts; refusing "
                      "to trust this host key\r\n");
    return -1;
  }

  (void)xaios_fs_mkdir("/home/admin/.ssh");
  int fd = xaios_fs_open(path, XAIOS_XBFS_OPEN_WRITE | XAIOS_XBFS_OPEN_CREATE);
  if (fd < 0) return -1;
  xaios_xbfs_stat_user_t stat;
  uint64_t offset = 0U;
  if (xaios_fs_stat(path, &stat) != 0) {
    /* Without a size there is no append offset, and writing at zero would
       land on top of whatever the first entry is -- turning a file of known
       hosts into a file with one mangled line at the front. */
    (void)xaios_fs_close(fd);
    return -1;
  }
  offset = stat.size;
  char line[SSH_KNOWN_HOSTS_LINE_MAX];
  uint32_t used = ssh_known_hosts_format(line, sizeof(line), expected,
                                         expected_length, public_key);
  if (used == 0U) {
    (void)xaios_fs_close(fd);
    return -1;
  }
  int written = (int)xaios_fs_pwrite(fd, line, used, offset);
  int synced = xaios_fs_fsync(fd);
  (void)xaios_fs_close(fd);
  if (written != (int)used || synced != 0) return -1;
  return output_text(client, "Warning: permanently added host key to /home/admin/.ssh/known_hosts\r\n");
}

static int parse_kex_reply(ssh_client_context_t *client,
                           const ssh_packet_t *packet,
                           const uint8_t *client_version,
                           uint32_t client_version_length,
                           const uint8_t *server_version,
                           uint32_t server_version_length,
                           const uint8_t *client_kex,
                           uint32_t client_kex_length,
                           const uint8_t *server_kex,
                           uint32_t server_kex_length,
                           const uint8_t client_private[32],
                           const uint8_t *client_public,
                           uint32_t client_public_length,
                           const uint8_t *mlkem_secret_key) {
  if (packet->len < 1U || packet->data[0] != SSH_MSG_KEXDH_REPLY) return -1;
  uint32_t position = 1U;
  if (position + 4U > packet->len) return -1;
  uint32_t host_blob_length = ssh_read_u32_be(packet->data + position);
  position += 4U;
  if (host_blob_length > packet->len - position) return -1;
  const uint8_t *host_blob = packet->data + position;
  position += host_blob_length;
  if (host_blob_length != 51U || ssh_read_u32_be(host_blob) != 11U ||
      !bytes_equal(host_blob + 4U, (const uint8_t *)"ssh-ed25519", 11U) ||
      ssh_read_u32_be(host_blob + 15U) != 32U) return -1;
  const uint8_t *host_public = host_blob + 19U;

  if (position + 4U > packet->len) return -1;
  uint32_t server_public_length = ssh_read_u32_be(packet->data + position);
  position += 4U;
  uint32_t expected_server_length = client->transport->kex_hybrid != 0U
                                        ? SSH_MLKEM768_CIPHERTEXT_SIZE + 32U
                                        : 32U;
  if (server_public_length != expected_server_length ||
      server_public_length > packet->len - position)
    return -1;
  const uint8_t *server_public = packet->data + position;
  position += server_public_length;
  if (position + 4U > packet->len) return -1;
  uint32_t signature_blob_length = ssh_read_u32_be(packet->data + position);
  position += 4U;
  if (signature_blob_length != packet->len - position ||
      signature_blob_length != 83U) return -1;
  const uint8_t *signature_blob = packet->data + position;
  if (ssh_read_u32_be(signature_blob) != 11U ||
      !bytes_equal(signature_blob + 4U, (const uint8_t *)"ssh-ed25519", 11U) ||
      ssh_read_u32_be(signature_blob + 15U) != 64U) return -1;
  const uint8_t *signature = signature_blob + 19U;

  const uint8_t *server_x25519 = server_public;
  if (client->transport->kex_hybrid != 0U)
    server_x25519 += SSH_MLKEM768_CIPHERTEXT_SIZE;
  uint8_t x25519_secret[32];
  if (xaios_x25519(x25519_secret, client_private, server_x25519) != 0)
    return -1;
  uint8_t nonzero = 0U;
  for (uint32_t i = 0U; i < 32U; ++i)
    nonzero |= x25519_secret[i];
  if (nonzero == 0U) return -1;
  if (client->transport->kex_hybrid != 0U) {
    uint8_t mlkem_secret[SSH_MLKEM768_SHARED_SECRET_SIZE];
    uint8_t combined[64];
    if (mlkem_secret_key == 0 ||
        ssh_mlkem768_decapsulate(mlkem_secret, server_public,
                                 mlkem_secret_key) != 0) return -1;
    ssh_mem_copy(combined, mlkem_secret, 32U);
    ssh_mem_copy(combined + 32U, x25519_secret, 32U);
    sha256_hash(combined, sizeof(combined),
                client->transport->shared_secret);
    ssh_mem_zero(mlkem_secret, sizeof(mlkem_secret));
    ssh_mem_zero(combined, sizeof(combined));
  } else {
    ssh_mem_copy(client->transport->shared_secret, x25519_secret, 32U);
  }
  ssh_mem_zero(x25519_secret, sizeof(x25519_secret));

  sha256_ctx_t hash;
  sha256_init(&hash);
  sha256_update_string(&hash, client_version, client_version_length);
  sha256_update_string(&hash, server_version, server_version_length);
  sha256_update_string(&hash, client_kex, client_kex_length);
  sha256_update_string(&hash, server_kex, server_kex_length);
  sha256_update_string(&hash, host_blob, host_blob_length);
  sha256_update_string(&hash, client_public, client_public_length);
  sha256_update_string(&hash, server_public, server_public_length);
  sha256_update_kex_secret(&hash, client->transport->shared_secret,
                           client->transport->kex_hybrid);
  sha256_final(&hash, client->transport->exchange_hash);
  ssh_mem_copy(client->transport->session_id,
               client->transport->exchange_hash, 32U);
  ssh_mem_zero(&hash, sizeof(hash));
  if (xaios_ed25519_verify(signature, client->transport->exchange_hash, 32U,
                           host_public) != 0) return -1;
  return verify_known_host(client, host_public) == 0 ? 0 : -2;
}

static int send_service_request(ssh_client_context_t *client,
                                const char *service) {
  uint8_t packet[96];
  packet[0] = SSH_MSG_SERVICE_REQUEST;
  uint32_t length = ssh_str_len(service);
  uint32_t position = append_string(packet, 1U, sizeof(packet),
                                    (const uint8_t *)service, length);
  return position == UINT32_MAX ? -1 :
      ssh_packet_write_encrypted((int)client->sockfd, packet, position);
}

static int authenticate_password(ssh_client_context_t *client,
                                 uint64_t deadline) {
  if (send_service_request(client, "ssh-userauth") != 0) return -1;
  ssh_packet_t *packet = &client->packet_workspace;
  if (wait_encrypted_packet(client, packet, deadline) != 0 ||
      packet->len < 1U || packet->data[0] != SSH_MSG_SERVICE_ACCEPT) return -1;

  uint8_t request[512];
  uint32_t position = 0U;
  request[position++] = SSH_MSG_USERAUTH_REQUEST;
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)client->user,
                           ssh_str_len(client->user));
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)"ssh-connection", 14U);
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)"password", 8U);
  if (position == UINT32_MAX || position + 1U > sizeof(request)) return -1;
  request[position++] = 0U;
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)client->password,
                           client->password_length);
  if (position == UINT32_MAX ||
      ssh_packet_write_encrypted((int)client->sockfd, request, position) != 0)
    return -1;
  ssh_mem_zero(request, sizeof(request));
  ssh_mem_zero(client->password, sizeof(client->password));
  client->password_length = 0U;
  if (wait_encrypted_packet(client, packet, deadline) != 0 || packet->len < 1U)
    return -1;
  return packet->data[0] == SSH_MSG_USERAUTH_SUCCESS ? 0 : -1;
}

static int authenticate_public_key(ssh_client_context_t *client,
                                   uint64_t deadline,
                                   const ssh_identity_t *identity) {
  if (send_service_request(client, "ssh-userauth") != 0) return -1;
  ssh_packet_t *response = &client->packet_workspace;
  if (wait_encrypted_packet(client, response, deadline) != 0 ||
      response->len < 1U || response->data[0] != SSH_MSG_SERVICE_ACCEPT)
    return -1;

  uint8_t public_blob[64];
  uint32_t public_length = append_string(
      public_blob, 0U, sizeof(public_blob),
      (const uint8_t *)"ssh-ed25519", 11U);
  public_length = append_string(public_blob, public_length,
                                sizeof(public_blob), identity->public_key, 32U);
  if (public_length == UINT32_MAX) return -1;

  uint8_t request[512];
  uint32_t position = 0U;
  request[position++] = SSH_MSG_USERAUTH_REQUEST;
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)client->user,
                           ssh_str_len(client->user));
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)"ssh-connection", 14U);
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)"publickey", 9U);
  if (position == UINT32_MAX || position >= sizeof(request)) return -1;
  uint32_t signature_flag_position = position;
  request[position++] = 0U;
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)"ssh-ed25519", 11U);
  position = append_string(request, position, sizeof(request), public_blob,
                           public_length);
  if (position == UINT32_MAX) return -1;

  if (ssh_packet_write_encrypted((int)client->sockfd, request, position) != 0 ||
      wait_encrypted_packet(client, response, deadline) != 0 ||
      response->len != 1U + 4U + 11U + 4U + public_length ||
      response->data[0] != SSH_MSG_USERAUTH_PK_OK ||
      ssh_read_u32_be(response->data + 1U) != 11U ||
      !bytes_equal(response->data + 5U, (const uint8_t *)"ssh-ed25519", 11U) ||
      ssh_read_u32_be(response->data + 16U) != public_length ||
      !bytes_equal(response->data + 20U, public_blob, public_length)) return -1;
  request[signature_flag_position] = 1U;

  uint8_t signed_data[512];
  uint32_t signed_length = append_string(
      signed_data, 0U, sizeof(signed_data), client->transport->session_id, 32U);
  if (signed_length == UINT32_MAX || position > sizeof(signed_data) - signed_length)
    return -1;
  ssh_mem_copy(signed_data + signed_length, request, position);
  signed_length += position;
  uint8_t signature[64];
  if (xaios_ed25519_sign(signature, signed_data, signed_length,
                         identity->public_key, identity->seed) != 0)
    return -1;
  uint8_t signature_blob[96];
  uint32_t signature_length = append_string(
      signature_blob, 0U, sizeof(signature_blob),
      (const uint8_t *)"ssh-ed25519", 11U);
  signature_length = append_string(signature_blob, signature_length,
                                   sizeof(signature_blob), signature, 64U);
  position = append_string(request, position, sizeof(request), signature_blob,
                           signature_length);
  ssh_mem_zero(signature, sizeof(signature));
  ssh_mem_zero(signed_data, sizeof(signed_data));
  if (position == UINT32_MAX ||
      ssh_packet_write_encrypted((int)client->sockfd, request, position) != 0)
    return -1;
  ssh_mem_zero(request, sizeof(request));
  if (wait_encrypted_packet(client, response, deadline) != 0 ||
      response->len < 1U) return -1;
  return response->data[0] == SSH_MSG_USERAUTH_SUCCESS ? 0 : -1;
}

#if defined(XAIOS_SSH_CLIENT_APP)
static int agent_exchange_payload(const uint8_t *payload,
                                  uint32_t payload_length, uint8_t *response,
                                  uint32_t response_capacity,
                                  uint32_t *response_length,
                                  uint64_t deadline) {
  uint8_t request[1024];
  if (payload == 0 || payload_length == 0U ||
      payload_length > sizeof(request) - 4U) return -1;
  ssh_write_u32_be(request, payload_length);
  ssh_mem_copy(request + 4U, payload, payload_length);
  return ssh_client_app_agent_exchange(request, payload_length + 4U, response,
                                       response_capacity, response_length,
                                       deadline);
}

static int agent_first_ed25519(uint8_t *public_blob,
                               uint32_t *public_blob_length,
                               uint64_t deadline) {
  uint8_t response[4096];
  uint32_t response_length = 0U;
  static const uint8_t request_identities = 11U;
  if (agent_exchange_payload(&request_identities, 1U, response,
                             sizeof(response), &response_length,
                             deadline) != 0 ||
      response_length < 9U || ssh_read_u32_be(response) + 4U != response_length ||
      response[4U] != 12U) return -1;
  uint32_t count = ssh_read_u32_be(response + 5U);
  uint32_t position = 9U;
  for (uint32_t i = 0U; i < count; ++i) {
    if (position > response_length || response_length - position < 4U)
      return -1;
    uint32_t key_length = ssh_read_u32_be(response + position);
    position += 4U;
    if (key_length > response_length - position) return -1;
    const uint8_t *key = response + position;
    position += key_length;
    if (response_length - position < 4U) return -1;
    uint32_t comment_length = ssh_read_u32_be(response + position);
    position += 4U;
    if (comment_length > response_length - position) return -1;
    position += comment_length;
    if (key_length == 51U && ssh_read_u32_be(key) == 11U &&
        bytes_equal(key + 4U, (const uint8_t *)"ssh-ed25519", 11U) &&
        ssh_read_u32_be(key + 15U) == 32U) {
      ssh_mem_copy(public_blob, key, key_length);
      *public_blob_length = key_length;
      return 0;
    }
  }
  return -1;
}

static int agent_sign(const uint8_t *public_blob, uint32_t public_blob_length,
                      const uint8_t *data, uint32_t data_length,
                      uint8_t *signature_blob, uint32_t signature_capacity,
                      uint32_t *signature_length, uint64_t deadline) {
  uint8_t payload[1024];
  uint8_t response[512];
  uint32_t position = 0U;
  uint32_t response_length = 0U;
  payload[position++] = 13U;
  position = append_string(payload, position, sizeof(payload), public_blob,
                           public_blob_length);
  position = append_string(payload, position, sizeof(payload), data,
                           data_length);
  if (position == UINT32_MAX || position + 4U > sizeof(payload)) return -1;
  ssh_write_u32_be(payload + position, 0U);
  position += 4U;
  if (agent_exchange_payload(payload, position, response, sizeof(response),
                             &response_length, deadline) != 0 ||
      response_length < 9U || ssh_read_u32_be(response) + 4U != response_length ||
      response[4U] != 14U) return -1;
  uint32_t length = ssh_read_u32_be(response + 5U);
  if (length != response_length - 9U || length > signature_capacity ||
      length != 83U || ssh_read_u32_be(response + 9U) != 11U ||
      !bytes_equal(response + 13U, (const uint8_t *)"ssh-ed25519", 11U) ||
      ssh_read_u32_be(response + 24U) != 64U) return -1;
  ssh_mem_copy(signature_blob, response + 9U, length);
  *signature_length = length;
  return 0;
}

static int authenticate_agent(ssh_client_context_t *client,
                              uint64_t deadline) {
  uint8_t public_blob[64];
  uint32_t public_length = 0U;
  if (send_service_request(client, "ssh-userauth") != 0) return -1;
  ssh_packet_t *response = &client->packet_workspace;
  if (wait_encrypted_packet(client, response, deadline) != 0 ||
      response->len < 1U || response->data[0] != SSH_MSG_SERVICE_ACCEPT ||
      agent_first_ed25519(public_blob, &public_length, deadline) != 0)
    return -1;

  uint8_t request[512];
  uint32_t position = 0U;
  request[position++] = SSH_MSG_USERAUTH_REQUEST;
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)client->user,
                           ssh_str_len(client->user));
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)"ssh-connection", 14U);
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)"publickey", 9U);
  if (position == UINT32_MAX || position >= sizeof(request)) return -1;
  uint32_t signature_flag_position = position;
  request[position++] = 0U;
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)"ssh-ed25519", 11U);
  position = append_string(request, position, sizeof(request), public_blob,
                           public_length);
  if (position == UINT32_MAX ||
      ssh_packet_write_encrypted((int)client->sockfd, request, position) != 0 ||
      wait_encrypted_packet(client, response, deadline) != 0 ||
      response->len != 1U + 4U + 11U + 4U + public_length ||
      response->data[0] != SSH_MSG_USERAUTH_PK_OK) return -1;
  request[signature_flag_position] = 1U;

  uint8_t signed_data[512];
  uint32_t signed_length = append_string(
      signed_data, 0U, sizeof(signed_data), client->transport->session_id, 32U);
  if (signed_length == UINT32_MAX || position > sizeof(signed_data) - signed_length)
    return -1;
  ssh_mem_copy(signed_data + signed_length, request, position);
  signed_length += position;
  uint8_t signature_blob[96];
  uint32_t signature_length = 0U;
  if (agent_sign(public_blob, public_length, signed_data, signed_length,
                 signature_blob, sizeof(signature_blob), &signature_length,
                 deadline) != 0) return -1;
  position = append_string(request, position, sizeof(request), signature_blob,
                           signature_length);
  ssh_mem_zero(signed_data, sizeof(signed_data));
  ssh_mem_zero(signature_blob, sizeof(signature_blob));
  if (position == UINT32_MAX ||
      ssh_packet_write_encrypted((int)client->sockfd, request, position) != 0 ||
      wait_encrypted_packet(client, response, deadline) != 0 ||
      response->len < 1U) return -1;
  return response->data[0] == SSH_MSG_USERAUTH_SUCCESS ? 0 : -1;
}
#endif

static int wait_channel_reply(ssh_client_context_t *client, uint8_t expected,
                              uint64_t deadline, ssh_packet_t *out_packet) {
  for (;;) {
    if (wait_encrypted_packet(client, out_packet, deadline) != 0) return -1;
    if (out_packet->len != 0U && out_packet->data[0] == expected) return 0;
    if (out_packet->len >= 9U &&
        out_packet->data[0] == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
      uint32_t added = ssh_read_u32_be(out_packet->data + 5U);
      if (UINT32_MAX - client->remote_window < added) return -1;
      client->remote_window += added;
      continue;
    }
    if (out_packet->len != 0U &&
        (out_packet->data[0] == SSH_MSG_CHANNEL_FAILURE ||
         out_packet->data[0] == SSH_MSG_CHANNEL_OPEN_FAILURE ||
         out_packet->data[0] == SSH_MSG_DISCONNECT)) return -1;
  }
}

static int open_session_channel(ssh_client_context_t *client,
                                const ssh_channel_t *outer,
                                uint64_t deadline) {
  uint8_t packet[512];
  uint32_t position = 0U;
  packet[position++] = SSH_MSG_CHANNEL_OPEN;
  position = append_string(packet, position, sizeof(packet),
                           (const uint8_t *)"session", 7U);
  if (position == UINT32_MAX || position + 12U > sizeof(packet)) return -1;
  ssh_write_u32_be(packet + position, client->local_channel);
  position += 4U;
  ssh_write_u32_be(packet + position, SSH_CLIENT_WINDOW);
  position += 4U;
  ssh_write_u32_be(packet + position, SSH_CLIENT_PACKET);
  position += 4U;
  if (ssh_packet_write_encrypted((int)client->sockfd, packet, position) != 0)
    return -1;
  ssh_packet_t *response = &client->packet_workspace;
  if (wait_channel_reply(client, SSH_MSG_CHANNEL_OPEN_CONFIRM, deadline,
                         response) != 0 || response->len < 17U ||
      ssh_read_u32_be(response->data + 1U) != client->local_channel) return -1;
  client->remote_channel = ssh_read_u32_be(response->data + 5U);
  client->remote_window = ssh_read_u32_be(response->data + 9U);
  client->remote_max_packet = ssh_read_u32_be(response->data + 13U);
  client->receive_window = SSH_CLIENT_WINDOW;
  if (client->remote_max_packet == 0U) return -1;

  if (client->mode == SSH_CLIENT_MODE_SHELL) {
    position = 0U;
    packet[position++] = SSH_MSG_CHANNEL_REQUEST;
    ssh_write_u32_be(packet + position, client->remote_channel);
    position += 4U;
    position = append_string(packet, position, sizeof(packet),
                             (const uint8_t *)"pty-req", 7U);
    packet[position++] = 1U;
    position = append_string(packet, position, sizeof(packet),
                             (const uint8_t *)"xterm-256color", 14U);
    ssh_write_u32_be(packet + position, outer->terminal_columns);
    position += 4U;
    ssh_write_u32_be(packet + position, outer->terminal_rows);
    position += 4U;
    ssh_write_u32_be(packet + position, 0U);
    position += 4U;
    ssh_write_u32_be(packet + position, 0U);
    position += 4U;
    position = append_string(packet, position, sizeof(packet), 0, 0U);
    if (position == UINT32_MAX ||
        ssh_packet_write_encrypted((int)client->sockfd, packet, position) != 0 ||
        wait_channel_reply(client, SSH_MSG_CHANNEL_SUCCESS, deadline,
                           response) != 0) return -1;
  }

  position = 0U;
  packet[position++] = SSH_MSG_CHANNEL_REQUEST;
  ssh_write_u32_be(packet + position, client->remote_channel);
  position += 4U;
  const char *request = client->mode == SSH_CLIENT_MODE_SHELL
                            ? "shell"
                            : (client->mode == SSH_CLIENT_MODE_EXEC
                                   ? "exec"
                                   : "subsystem");
  position = append_string(packet, position, sizeof(packet),
                           (const uint8_t *)request, ssh_str_len(request));
  packet[position++] = 1U;
  if (client->mode == SSH_CLIENT_MODE_EXEC) {
    position = append_string(packet, position, sizeof(packet),
                             (const uint8_t *)client->command,
                             ssh_str_len(client->command));
  }
  if (client->mode == SSH_CLIENT_MODE_SCP_UPLOAD ||
      client->mode == SSH_CLIENT_MODE_SCP_DOWNLOAD) {
    position = append_string(packet, position, sizeof(packet),
                             (const uint8_t *)"sftp", 4U);
  }
  if (position == UINT32_MAX ||
      ssh_packet_write_encrypted((int)client->sockfd, packet, position) != 0 ||
      wait_channel_reply(client, SSH_MSG_CHANNEL_SUCCESS, deadline,
                         response) != 0) return -1;
  return 0;
}

static int proxy_send_window_adjust(ssh_client_context_t *client,
                                    uint32_t added) {
  uint8_t packet[9];
  packet[0] = SSH_MSG_CHANNEL_WINDOW_ADJUST;
  ssh_write_u32_be(packet + 1U, client->proxy_remote_channel);
  ssh_write_u32_be(packet + 5U, added);
  return ssh_packet_write_encrypted((int)client->proxy_sockfd, packet,
                                    sizeof(packet));
}

static int proxy_process_packet(ssh_client_context_t *client,
                                const ssh_packet_t *packet) {
  if (packet->len == 0U) return -1;
  uint8_t type = packet->data[0];
  if (type == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
    if (packet->len != 9U ||
        ssh_read_u32_be(packet->data + 1U) != client->proxy_local_channel)
      return -1;
    uint32_t added = ssh_read_u32_be(packet->data + 5U);
    if (UINT32_MAX - client->proxy_remote_window < added) return -1;
    client->proxy_remote_window += added;
    return 0;
  }
  if (type == SSH_MSG_CHANNEL_DATA) {
    if (packet->len < 9U ||
        ssh_read_u32_be(packet->data + 1U) != client->proxy_local_channel)
      return -1;
    uint32_t length = ssh_read_u32_be(packet->data + 5U);
    if (length > packet->len - 9U ||
        length > sizeof(client->proxy_rx) - client->proxy_rx_used ||
        length > client->proxy_receive_window) return -1;
    ssh_mem_copy(client->proxy_rx + client->proxy_rx_used, packet->data + 9U,
                 length);
    client->proxy_rx_used += length;
    client->proxy_receive_window -= length;
    if (client->proxy_receive_window <= SSH_CLIENT_WINDOW / 2U) {
      uint32_t added = SSH_CLIENT_WINDOW - client->proxy_receive_window;
      if (proxy_send_window_adjust(client, added) != 0) return -1;
      client->proxy_receive_window += added;
    }
    return 0;
  }
  if (type == SSH_MSG_CHANNEL_EOF || type == SSH_MSG_CHANNEL_CLOSE ||
      type == SSH_MSG_DISCONNECT) {
    return -1;
  }
  if (type == SSH_MSG_GLOBAL_REQUEST && packet->len >= 6U) {
    uint32_t name_length = ssh_read_u32_be(packet->data + 1U);
    if (name_length > packet->len - 6U) return -1;
    if (packet->data[5U + name_length] != 0U) {
      uint8_t failure = SSH_MSG_REQUEST_FAILURE;
      return ssh_packet_write_encrypted((int)client->proxy_sockfd, &failure,
                                        1U);
    }
  }
  return 0;
}

static int proxy_pump(ssh_client_context_t *client, uint64_t deadline) {
  if (client == 0 || client->proxy_transport == 0) return -1;
  int result = wait_encrypted_packet_fd((int)client->proxy_sockfd,
                                        &client->proxy_packet_workspace,
                                        deadline);
  if (result != 0) return result;
  return proxy_process_packet(client, &client->proxy_packet_workspace);
}

static int proxy_stream_send(void *context, const uint8_t *data,
                             u64 length, u64 *sent) {
  ssh_client_context_t *client = (ssh_client_context_t *)context;
  if (client == 0 || data == 0 || sent == 0 || client->proxy_established == 0U ||
      client->proxy_transport == 0) return -1;
  *sent = 0U;
  uint64_t deadline = xaios_clock_nanos() + SSH_CLIENT_TIMEOUT_NS;
  while (client->proxy_remote_window == 0U) {
    if (proxy_pump(client, deadline) != 0) return -1;
  }
  uint32_t chunk = length > UINT32_MAX ? UINT32_MAX : (uint32_t)length;
  if (chunk > client->proxy_remote_window) chunk = client->proxy_remote_window;
  if (chunk > client->proxy_remote_max_packet) chunk = client->proxy_remote_max_packet;
  if (chunk > SSH_WIRE_MAX_CHUNK) chunk = SSH_WIRE_MAX_CHUNK;
  if (chunk == 0U) return -1;
  /* The target handshake retains frame_workspace as its server KEXINIT. */
  uint8_t *packet = client->proxy_packet_workspace.data;
  packet[0] = SSH_MSG_CHANNEL_DATA;
  ssh_write_u32_be(packet + 1U, client->proxy_remote_channel);
  ssh_write_u32_be(packet + 5U, chunk);
  ssh_mem_copy(packet + 9U, data, chunk);
  if (ssh_packet_write_encrypted((int)client->proxy_sockfd, packet,
                                 chunk + 9U) != 0) return -1;
  client->proxy_remote_window -= chunk;
  *sent = chunk;
  return 0;
}

static int proxy_stream_recv(void *context, uint8_t *data,
                             u64 length, u64 *received) {
  ssh_client_context_t *client = (ssh_client_context_t *)context;
  if (client == 0 || data == 0 || received == 0 ||
      client->proxy_established == 0U || client->proxy_transport == 0) return -1;
  *received = 0U;
  for (uint32_t attempts = 0U; attempts < 16U; ++attempts) {
    if (client->proxy_rx_used != 0U) {
      uint32_t count = length < client->proxy_rx_used ? (uint32_t)length
                                                       : client->proxy_rx_used;
      ssh_mem_copy(data, client->proxy_rx, count);
      uint32_t remaining = client->proxy_rx_used - count;
      for (uint32_t i = 0U; i < remaining; ++i)
        client->proxy_rx[i] = client->proxy_rx[count + i];
      client->proxy_rx_used = remaining;
      *received = count;
      return 0;
    }
    int result = proxy_pump(client, xaios_clock_nanos() + SSH_CLIENT_TIMEOUT_NS);
    if (result > 0) return 0;
    if (result < 0) return -1;
  }
  return 0;
}

static int open_proxy_channel(ssh_client_context_t *client, uint64_t deadline) {
  uint8_t packet[512];
  uint32_t position = 0U;
  packet[position++] = SSH_MSG_CHANNEL_OPEN;
  position = append_string(packet, position, sizeof(packet),
                           (const uint8_t *)"direct-tcpip", 12U);
  if (position == UINT32_MAX || position + 12U > sizeof(packet)) return -1;
  client->local_channel = 1U;
  ssh_write_u32_be(packet + position, client->local_channel);
  position += 4U;
  ssh_write_u32_be(packet + position, SSH_CLIENT_WINDOW);
  position += 4U;
  ssh_write_u32_be(packet + position, SSH_CLIENT_PACKET);
  position += 4U;
  position = append_string(packet, position, sizeof(packet),
                           (const uint8_t *)client->target_host,
                           ssh_str_len(client->target_host));
  if (position == UINT32_MAX || position + 4U > sizeof(packet)) return -1;
  ssh_write_u32_be(packet + position, client->target_port);
  position += 4U;
  position = append_string(packet, position, sizeof(packet),
                           (const uint8_t *)"127.0.0.1", 9U);
  if (position == UINT32_MAX || position + 4U > sizeof(packet)) return -1;
  ssh_write_u32_be(packet + position, 0U);
  position += 4U;
  if (ssh_packet_write_encrypted((int)client->sockfd, packet, position) != 0)
    return -1;
  for (;;) {
    ssh_packet_t *response = &client->packet_workspace;
    if (wait_encrypted_packet(client, response, deadline) != 0 ||
        response->len == 0U) return -1;
    if (response->data[0] == SSH_MSG_CHANNEL_OPEN_FAILURE ||
        response->data[0] == SSH_MSG_DISCONNECT) return -1;
    if (response->data[0] != SSH_MSG_CHANNEL_OPEN_CONFIRM) continue;
    if (response->len != 17U ||
        ssh_read_u32_be(response->data + 1U) != client->local_channel)
      return -1;
    client->remote_channel = ssh_read_u32_be(response->data + 5U);
    client->remote_window = ssh_read_u32_be(response->data + 9U);
    client->remote_max_packet = ssh_read_u32_be(response->data + 13U);
    client->receive_window = SSH_CLIENT_WINDOW;
    return client->remote_max_packet == 0U ? -1 : 0;
  }
}

static void promote_proxy_transport(ssh_client_context_t *client) {
  client->proxy_sockfd = client->sockfd;
  client->proxy_transport = client->transport;
  client->proxy_local_channel = client->local_channel;
  client->proxy_remote_channel = client->remote_channel;
  client->proxy_remote_window = client->remote_window;
  client->proxy_remote_max_packet = client->remote_max_packet;
  client->proxy_receive_window = client->receive_window;
  client->sockfd = 0U;
  client->transport = 0;
  client->local_channel = 0U;
  client->remote_channel = 0U;
  client->remote_window = 0U;
  client->remote_max_packet = 0U;
  client->receive_window = 0U;
  sshclient_string_copy(client->host, sizeof(client->host), client->target_host);
  sshclient_string_copy(client->user, sizeof(client->user), client->target_user);
  client->port = client->target_port;
  client->use_identity = client->target_use_identity;
  client->use_agent = 0U;
  client->proxy_established = 1U;
  ssh_mem_zero(client->password, sizeof(client->password));
  client->password_length = 0U;
}

static int client_handshake(ssh_client_context_t *client,
                            const ssh_channel_t *outer) {
  uint64_t deadline = xaios_clock_nanos() + SSH_CLIENT_TIMEOUT_NS;
  client->transport = ssh_conn_client_alloc();
  if (client->transport == 0) return -11;
  if (client->proxy_established != 0U) {
    client->sockfd = SSH_CLIENT_RELAY_SOCKET;
    client->transport->sockfd = client->sockfd;
    client->transport->send_fn = proxy_stream_send;
    client->transport->recv_fn = proxy_stream_recv;
    client->transport->io_context = client;
  } else {
    xaios_ip_addr_user_t address;
    if (resolve_host(client->host, &address, deadline) != 0) return -10;
    if (xaios_net_connect(&address, client->port, &client->sockfd) != 0)
      return -26;
    client->transport->sockfd = client->sockfd;
  }

  static const uint8_t client_version[] = "SSH-2.0-XAIOS_Client_1.0";
  static const uint8_t client_version_line[] = "SSH-2.0-XAIOS_Client_1.0\r\n";
  u64 sent = 0U;
  if (ssh_conn_send(client->transport, client_version_line,
                    sizeof(client_version_line) - 1U, &sent) != 0 ||
      sent != sizeof(client_version_line) - 1U) return -12;
  uint8_t server_version[256];
  uint32_t server_version_length = 0U;
  for (;;) {
    u64 received = 0U;
    if (ssh_conn_recv(client->transport, server_version + server_version_length,
                      1U, &received) != 0) return -13;
    if (received == 0U) {
      if (xaios_clock_nanos() >= deadline) return -14;
      continue;
    }
    if (server_version[server_version_length++] == '\n') break;
    if (server_version_length == sizeof(server_version)) return -15;
  }
  while (server_version_length != 0U &&
         (server_version[server_version_length - 1U] == '\r' ||
          server_version[server_version_length - 1U] == '\n')) {
    --server_version_length;
  }
  if (server_version_length < 8U ||
      !bytes_equal(server_version, (const uint8_t *)"SSH-2.0-", 8U)) return -16;

  uint8_t client_kex[512];
  uint32_t client_kex_length = 0U;
  if (build_kexinit(client_kex, sizeof(client_kex), &client_kex_length) != 0 ||
      ssh_packet_write((int)client->sockfd, client_kex, client_kex_length) != 0)
    return -17;
  ssh_packet_t *packet = &client->packet_workspace;
  uint32_t hybrid = 0U;
  if (wait_plain_packet(client, packet, deadline) != 0 ||
      validate_server_kexinit(packet, &hybrid) != 0) return -18;
  uint32_t server_kex_length = packet->len;
  if (server_kex_length > sizeof(client->frame_workspace)) return -18;
  ssh_mem_copy(client->frame_workspace, packet->data, server_kex_length);
  client->transport->kex_hybrid = hybrid;

  uint8_t client_private[32];
  uint8_t client_public[SSH_MLKEM768_PUBLIC_KEY_SIZE + 32U];
  uint8_t mlkem_secret_key[SSH_MLKEM768_SECRET_KEY_SIZE];
  uint32_t client_public_length = 32U;
  if (crypto_random_bytes(client_private, sizeof(client_private)) != 0 ||
      xaios_x25519_base(client_public + (hybrid != 0U
                                            ? SSH_MLKEM768_PUBLIC_KEY_SIZE
                                            : 0U),
                        client_private) != 0) return -19;
  if (hybrid != 0U) {
    if (ssh_mlkem768_keypair(client_public, mlkem_secret_key) != 0) return -19;
    client_public_length = sizeof(client_public);
  }
  uint8_t init[SSH_MLKEM768_PUBLIC_KEY_SIZE + 32U + 5U];
  init[0] = SSH_MSG_KEXDH_INIT;
  ssh_write_u32_be(init + 1U, client_public_length);
  ssh_mem_copy(init + 5U, client_public, client_public_length);
  if (ssh_packet_write((int)client->sockfd, init,
                       client_public_length + 5U) != 0) return -20;
  if (wait_plain_packet(client, packet, deadline) != 0) return -21;
  int kex_reply = parse_kex_reply(client, packet, client_version,
                                  sizeof(client_version) - 1U, server_version,
                                  server_version_length, client_kex,
                                  client_kex_length, client->frame_workspace,
                                  server_kex_length, client_private,
                                  client_public, client_public_length,
                                  hybrid != 0U ? mlkem_secret_key : 0);
  if (kex_reply == -2) return -25;
  if (kex_reply != 0) return -21;
  ssh_mem_zero(client_private, sizeof(client_private));
  ssh_mem_zero(mlkem_secret_key, sizeof(mlkem_secret_key));
  if (wait_plain_packet(client, packet, deadline) != 0 ||
      packet->len != 1U || packet->data[0] != SSH_MSG_NEWKEYS) return -22;
  uint8_t client_newkeys = SSH_MSG_NEWKEYS;
  if (ssh_packet_write((int)client->sockfd, &client_newkeys, 1U) != 0 ||
      derive_client_crypto(client->transport) != 0) return -23;
  if (client->use_agent != 0U) {
#if defined(XAIOS_SSH_CLIENT_APP)
    if (authenticate_agent(client, deadline) != 0) return -28;
#else
    return -28;
#endif
  } else if (client->use_identity != 0U) {
    ssh_identity_t identity;
    if (ssh_identity_load(client->identity_path, client->password, &identity) !=
        0) {
      ssh_mem_zero(&identity, sizeof(identity));
      return -27;
    }
    if (authenticate_public_key(client, deadline, &identity) != 0) {
      ssh_mem_zero(&identity, sizeof(identity));
      return -28;
    }
    ssh_mem_zero(&identity, sizeof(identity));
    ssh_mem_zero(client->password, sizeof(client->password));
    client->password_length = 0U;
  } else if (authenticate_password(client, deadline) != 0) {
    return -23;
  }
  if (client->proxy_enabled != 0U && client->proxy_established == 0U) {
    if (open_proxy_channel(client, deadline) != 0) return -24;
    promote_proxy_transport(client);
    return 1;
  }
  if (open_session_channel(client, outer, deadline) != 0) return -24;
  client->connected = 1U;
  return 0;
}

static int parse_port(const char *text, uint16_t *port) {
  uint32_t value = 0U;
  if (text == 0 || text[0] == '\0') return -1;
  for (uint32_t i = 0U; text[i] != '\0'; ++i) {
    if (text[i] < '0' || text[i] > '9') return -1;
    uint32_t digit = (uint32_t)(text[i] - '0');
    if (value > (65535U - digit) / 10U) return -1;
    value = value * 10U + digit;
  }
  if (value == 0U) return -1;
  *port = (uint16_t)value;
  return 0;
}

static int next_token(const char *command, uint32_t *position, char *token,
                      uint32_t capacity) {
  uint32_t used = 0U;
  while (command[*position] == ' ' || command[*position] == '\t') ++*position;
  if (command[*position] == '\0') return -1;
  char quote = 0;
  while (command[*position] != '\0') {
    char value = command[*position];
    if (quote == 0 && (value == ' ' || value == '\t')) break;
    ++*position;
    if (value == '\\' && command[*position] != '\0') value = command[(*position)++];
    else if (value == '\'' || value == '"') {
      if (quote == 0) { quote = value; continue; }
      if (quote == value) { quote = 0; continue; }
    }
    if (used + 1U >= capacity) return -1;
    token[used++] = value;
  }
  if (quote != 0) return -1;
  token[used] = '\0';
  return 0;
}

static int parse_destination(ssh_client_context_t *client, const char *text) {
  uint32_t at = UINT32_MAX;
  uint32_t length = ssh_str_len(text);
  for (uint32_t i = 0U; i < length; ++i) if (text[i] == '@') at = i;
  uint32_t host_start = at + 1U;
  uint32_t host_end = length;
  if (host_start < length && text[host_start] == '[') {
    if (length < host_start + 3U || text[length - 1U] != ']') return -1;
    ++host_start;
    --host_end;
  }
  uint32_t host_length = host_end - host_start;
  if (at == 0U || at == UINT32_MAX || host_length == 0U ||
      at >= sizeof(client->user) || host_length >= sizeof(client->host)) {
    return -1;
  }
  ssh_mem_copy(client->user, text, at);
  client->user[at] = '\0';
  ssh_mem_copy(client->host, text + host_start, host_length);
  client->host[host_length] = '\0';
  return 0;
}

static int parse_proxy_destination(ssh_client_context_t *client,
                                   const char *text) {
  uint32_t length = ssh_str_len(text);
  uint32_t at = UINT32_MAX;
  for (uint32_t i = 0U; i < length; ++i) {
    if (text[i] == '@') at = i;
  }
  if (at == 0U || at == UINT32_MAX || at + 1U >= length ||
      at >= sizeof(client->proxy_user)) return -1;
  uint32_t host_start = at + 1U;
  uint32_t host_end = length;
  uint16_t port = 22U;
  if (text[host_start] == '[') {
    uint32_t close = host_start + 1U;
    while (close < length && text[close] != ']') ++close;
    if (close == host_start + 1U || close == length) return -1;
    host_start += 1U;
    host_end = close;
    if (close + 1U != length) {
      if (text[close + 1U] != ':' ||
          parse_port(text + close + 2U, &port) != 0) return -1;
    }
  } else {
    uint32_t colon = UINT32_MAX;
    for (uint32_t i = host_start; i < length; ++i) {
      if (text[i] != ':') continue;
      if (colon != UINT32_MAX) return -1;
      colon = i;
    }
    if (colon != UINT32_MAX) {
      host_end = colon;
      if (parse_port(text + colon + 1U, &port) != 0) return -1;
    }
  }
  uint32_t host_length = host_end - host_start;
  if (host_length == 0U || host_length >= sizeof(client->proxy_host)) return -1;
  for (uint32_t i = 0U; i < at; ++i) {
    char value = text[i];
    if (value == '@' || value == '/' || value == '\\' || value == '\r' ||
        value == '\n') return -1;
  }
  for (uint32_t i = 0U; i < host_length; ++i) {
    char value = text[host_start + i];
    if (value == '@' || value == '/' || value == '\\' || value == '\r' ||
        value == '\n') return -1;
  }
  ssh_mem_copy(client->proxy_user, text, at);
  client->proxy_user[at] = '\0';
  ssh_mem_copy(client->proxy_host, text + host_start, host_length);
  client->proxy_host[host_length] = '\0';
  client->proxy_port = port;
  return 0;
}

static int client_prompt_password(ssh_client_context_t *client,
                                  const ssh_channel_t *channel) {
  char prompt[SSH_CLIENT_USER_MAX + SSH_CLIENT_HOST_MAX + 24U];
  uint32_t used = 0U;
  uint32_t user_length = ssh_str_len(client->user);
  uint32_t host_length = ssh_str_len(client->host);
  ssh_mem_copy(prompt + used, client->user, user_length);
  used += user_length;
  prompt[used++] = '@';
  ssh_mem_copy(prompt + used, client->host, host_length);
  used += host_length;
  static const char password_suffix[] = "'s password: ";
  static const char passphrase_suffix[] = " key passphrase: ";
  static const char agent_suffix[] = " forwarded agent: ";
  const char *suffix = client->use_agent != 0U
                           ? agent_suffix
                           : (client->use_identity != 0U ? passphrase_suffix
                                                        : password_suffix);
  uint32_t suffix_length = ssh_str_len(suffix);
  ssh_mem_copy(prompt + used, suffix, suffix_length);
  used += suffix_length;
  if (ssh_channel_send_data((int)channel->owner_sockfd, channel->remote_id,
                            (const uint8_t *)prompt, used) != 0) {
    return -1;
  }
  client->prompting = 1U;
  client->prompt_deadline = xaios_clock_nanos() + SSH_CLIENT_PROMPT_IDLE_NS;
  return 0;
}

/* What the identity file at `path` needs before it can be used:
   0 -- nothing, it is stored unencrypted and was parsed here;
   1 -- a passphrase, it is readable but will not parse without one;
  -1 -- it cannot be read at all.

   An OpenSSH private key says in its header which it is: the cipher field is
   "none" for a key with no passphrase and names a cipher for one with. This
   asks the question by loading the key with an empty passphrase rather than
   by reading that field separately, because the loader already refuses an
   encrypted key when the passphrase is empty, and one parser cannot disagree
   with itself. A key that needs nothing is therefore never asked about --
   which is the whole of B-37's first half, since the prompt used to go out
   for every identity file regardless. */
static int identity_state(const char *path) {
  xaios_xbfs_stat_user_t info;
  ssh_identity_t identity;
  if (path == 0 || path[0] == '\0' || xaios_fs_stat(path, &info) != 0)
    return -1;
  int loaded = ssh_identity_load(path, "", &identity);
  ssh_mem_zero(&identity, sizeof(identity));
  return loaded == 0 ? 0 : 1;
}

static char lower_case(char value) {
  return value >= 'A' && value <= 'Z' ? (char)(value - 'A' + 'a') : value;
}

static int equal_fold(const char *left, const char *right) {
  for (uint32_t i = 0U;; ++i) {
    if (lower_case(left[i]) != lower_case(right[i])) return 0;
    if (left[i] == '\0') return 1;
  }
}

/* `-o Name=value`, spelled the way OpenSSH spells it. BatchMode is the only
   name this client has an answer for, and anything else is refused rather
   than ignored: an option that is accepted and does nothing is worse than
   one that is not accepted, because the caller believes it took effect. */
static int client_set_option(ssh_client_context_t *client, const char *text) {
  static const char batch_mode[] = "batchmode";
  uint32_t split = 0U;
  while (text[split] != '\0' && text[split] != '=') ++split;
  if (text[split] != '=' || split != sizeof(batch_mode) - 1U) return -1;
  for (uint32_t i = 0U; i < split; ++i)
    if (lower_case(text[i]) != batch_mode[i]) return -1;
  const char *value = text + split + 1U;
  if (equal_fold(value, "yes") != 0) {
    client->batch_mode = 1U;
    return 0;
  }
  if (equal_fold(value, "no") != 0) {
    client->batch_mode = 0U;
    return 0;
  }
  return -1;
}

/* The credential the next handshake needs, and how it is obtained.
   0 -- nothing is needed, go straight on;
   1 -- a prompt has been sent and its answer is awaited;
  -1 -- it cannot be had here, and the reason has been printed. */
static int client_request_credential(ssh_client_context_t *client,
                                     ssh_channel_t *channel) {
  if (client->use_identity != 0U) {
    int state = identity_state(client->identity_path);
    if (state == 0) return 0;
    if (state < 0) {
      (void)output_text(client, "ssh: identity file cannot be read\r\n");
      return -1;
    }
  }
  if (client->batch_mode != 0U) {
    (void)output_text(
        client,
        client->use_identity != 0U
            ? "ssh: identity file needs a passphrase and BatchMode=yes is set\r\n"
            : "ssh: password authentication needs a terminal and BatchMode=yes is set\r\n");
    return -1;
  }
  return client_prompt_password(client, channel) == 0 ? 1 : -1;
}

/* One attempt with the credential the client now holds: the handshake, the
   sentence when it fails, the next credential when a jump host asks for one,
   and the transfer when the command was scp.
   1 -- the session is live, or the transfer is finished;
   0 -- a further credential is outstanding and its prompt has gone out;
  -1 -- the attempt failed and the client has been released.
   `echo_newline` is for the prompt path only: it closes the line the typed
   password was hidden on. Nothing was typed when no prompt was shown. */
static int client_proceed(ssh_client_context_t *client, ssh_channel_t *channel,
                          int echo_newline) {
  for (;;) {
    int handshake = client_handshake(client, channel);
    int echo_failed = echo_newline != 0 && output_text(client, "\r\n") != 0;
    echo_newline = 0;
    if (echo_failed || handshake < 0) {
      if (handshake < 0) {
        xaios_log("ssh-client: handshake failed\n");
      }
      const char *message = "ssh: connection or authentication failed\r\n";
      if (handshake == -10 || handshake == -26)
        message = "ssh: connection failed\r\n";
      if (handshake == -11) message = "ssh: client memory unavailable\r\n";
      if (handshake == -12 || handshake == -13 || handshake == -14 ||
          handshake == -15 || handshake == -16) {
        message = "ssh: protocol version exchange failed\r\n";
      }
      if (handshake == -17 || handshake == -18 || handshake == -19 ||
          handshake == -20 || handshake == -21 || handshake == -22) {
        message = "ssh: key exchange failed\r\n";
      }
      if (handshake == -17) message = "ssh: key exchange initialization failed\r\n";
      if (handshake == -18) message = "ssh: server key exchange proposal invalid\r\n";
      if (handshake == -19) message = "ssh: key generation failed\r\n";
      if (handshake == -20) message = "ssh: key exchange request failed\r\n";
      if (handshake == -21) message = "ssh: key exchange reply invalid\r\n";
      if (handshake == -22) message = "ssh: new-keys exchange failed\r\n";
      if (handshake == -23) message = "ssh: authentication failed\r\n";
      if (handshake == -24) message = "ssh: session open failed\r\n";
      if (handshake == -25) message = "ssh: host key verification failed\r\n";
      if (handshake == -27) message = "ssh: identity file or passphrase invalid\r\n";
      if (handshake == -28) message = "ssh: public-key authentication failed\r\n";
      (void)output_text(client, message);
      client_release(channel, client);
      return -1;
    }
    if (handshake != 1) break;
    int credential = client_request_credential(client, channel);
    if (credential < 0) {
      client_release(channel, client);
      return -1;
    }
    if (credential > 0) return 0;
  }
  if (client->mode == SSH_CLIENT_MODE_SCP_UPLOAD ||
      client->mode == SSH_CLIENT_MODE_SCP_DOWNLOAD) {
    int transfer = sshclient_scp_transfer(client);
    const char *status = "scp: transfer failed\r\n";
    if (transfer == 0) status = "scp: transfer complete\r\n";
    else if (transfer == -11) status = "scp: SFTP request send failed\r\n";
    else if (transfer == -12) status = "scp: invalid SFTP version reply\r\n";
    else if (transfer == -41) status = "scp: SFTP reply timeout\r\n";
    else if (transfer == -42) status = "scp: remote SFTP service closed\r\n";
    else if (transfer == -43) status = "scp: remote SFTP service error\r\n";
    else if (transfer == -21) status = "scp: local source not found\r\n";
    else if (transfer == -22) status = "scp: local source open failed\r\n";
    else if (transfer == -23) status = "scp: remote destination open failed\r\n";
    else if (transfer == -24) status = "scp: local source read failed\r\n";
    else if (transfer == -25) status = "scp: remote write failed\r\n";
    else if (transfer == -26) status = "scp: remote rejected write\r\n";
    else if (transfer == -27) status = "scp: local close failed\r\n";
    else if (transfer == -28) status = "scp: remote close failed\r\n";
    else if (transfer == -29) status = "scp: directory requires -r or unsupported file type\r\n";
    else if (transfer == -30) status = "scp: cannot create destination directory\r\n";
    else if (transfer == -31) status = "scp: directory path or listing exceeds XAIOS limits\r\n";
    else if (transfer == -32) status = "scp: cannot create local destination\r\n";
    else if (transfer == -33) status = "scp: cannot inspect remote source\r\n";
    (void)output_text(client, status);
    client_release(channel, client);
    return transfer == 0 ? 1 : -1;
  }
  return 1;
}

static int remote_specification(const char *text, uint32_t *colon) {
  uint32_t at = UINT32_MAX;
  uint32_t bracket = 0U;
  for (uint32_t i = 0U; text[i] != '\0'; ++i) {
    if (text[i] == '@') at = i;
    if (text[i] == '[' && at != UINT32_MAX) bracket = 1U;
    if (text[i] == ']' && bracket != 0U) bracket = 0U;
    if (text[i] == ':' && bracket == 0U && at != UINT32_MAX && i > at + 1U) {
      *colon = i;
      return 1;
    }
  }
  return 0;
}

static int resolve_local_path(const ssh_channel_t *channel, const char *input,
                              char *output, uint32_t capacity) {
  uint32_t length = ssh_str_len(input);
  if (length == 0U || length + 1U > capacity) return -1;
  if (input[0] == '/') {
    ssh_mem_copy(output, input, length + 1U);
    while (length > 1U && output[length - 1U] == '/') output[--length] = '\0';
    return 0;
  }
  char cwd[SSH_CLIENT_PATH_MAX];
#if defined(XAIOS_SSH_CLIENT_APP)
  (void)channel;
  uint32_t cwd_length = sshclient_string_copy(cwd, sizeof(cwd), g_client_app_cwd);
  if (cwd_length == 0U) return -1;
#else
  u64 cwd_length = 0U;
  if (xaios_remote_login_session(channel->owner_sockfd, "admin", "pwd", cwd,
                                 sizeof(cwd), &cwd_length) < 0 ||
      cwd_length == 0U || cwd_length >= sizeof(cwd)) return -1;
#endif
  while (cwd_length != 0U &&
         (cwd[cwd_length - 1U] == '\n' || cwd[cwd_length - 1U] == '\r'))
    --cwd_length;
  uint32_t separator = cwd_length == 1U && cwd[0] == '/' ? 0U : 1U;
  if (cwd_length + separator + length + 1U > capacity) return -1;
  ssh_mem_copy(output, cwd, cwd_length);
  uint32_t used = (uint32_t)cwd_length;
  if (separator != 0U) output[used++] = '/';
  ssh_mem_copy(output + used, input, length + 1U);
  used += length;
  while (used > 1U && output[used - 1U] == '/') output[--used] = '\0';
  return 0;
}

static void client_usage(const ssh_channel_t *channel, int scp) {
  const char *usage = scp
      ? "usage: scp [-r] [-B] [-i key] [-o BatchMode=yes] [-P port] "
        "SOURCE DESTINATION\r\n"
      : "usage: ssh [-J user@host[:port]] [-i key] [-o BatchMode=yes] "
        "[-p port] user@host [command]\r\n";
  (void)ssh_channel_send_data((int)channel->owner_sockfd, channel->remote_id,
                              (const uint8_t *)usage, ssh_str_len(usage));
}

int ssh_client_prepare(struct ssh_channel *channel, const char *command) {
  uint32_t position = 0U;
  char token[SSH_CLIENT_COMMAND_MAX];
  if (next_token(command, &position, token, sizeof(token)) != 0) return 0;
  int is_ssh = ssh_str_eq(token, "ssh");
  int is_scp = ssh_str_eq(token, "scp");
  if (!is_ssh && !is_scp) return 0;
  ssh_client_context_t *client = client_allocate(channel);
  if (client == 0) {
    static const char busy[] = "ssh: outbound client capacity reached\r\n";
    (void)ssh_channel_send_data((int)channel->owner_sockfd, channel->remote_id,
                                (const uint8_t *)busy, sizeof(busy) - 1U);
    return -1;
  }
  client->mode = is_ssh ? SSH_CLIENT_MODE_SHELL : SSH_CLIENT_MODE_SCP_UPLOAD;
  if (is_scp) {
    char source[SSH_CLIENT_PATH_MAX + SSH_CLIENT_HOST_MAX];
    char destination[SSH_CLIENT_PATH_MAX + SSH_CLIENT_HOST_MAX];
    for (;;) {
      uint32_t saved = position;
      if (next_token(command, &position, token, sizeof(token)) != 0) {
        client_usage(channel, 1);
        client_release(channel, client);
        return -1;
      }
      if (ssh_str_eq(token, "-P")) {
        if (next_token(command, &position, token, sizeof(token)) != 0 ||
            parse_port(token, &client->port) != 0) {
          client_usage(channel, 1);
          client_release(channel, client);
          return -1;
        }
        continue;
      }
      if (ssh_str_eq(token, "-r")) {
        client->recursive = 1U;
        continue;
      }
      /* -B is what OpenSSH's scp calls batch mode, and it means what
         -o BatchMode=yes means: ask for nothing. */
      if (ssh_str_eq(token, "-B")) {
        client->batch_mode = 1U;
        continue;
      }
      if (token[0] == '-' && token[1] == 'o') {
        const char *option = token + 2U;
        if (option[0] == '\0') {
          if (next_token(command, &position, token, sizeof(token)) != 0) {
            client_usage(channel, 1);
            client_release(channel, client);
            return -1;
          }
          option = token;
        }
        if (client_set_option(client, option) != 0) {
          (void)output_text(
              client,
              "scp: only -o BatchMode=yes|no is understood\r\n");
          client_release(channel, client);
          return -1;
        }
        continue;
      }
      if (ssh_str_eq(token, "-A")) {
        client->use_agent = 1U;
        continue;
      }
      if (ssh_str_eq(token, "-i")) {
        if (next_token(command, &position, client->identity_path,
                       sizeof(client->identity_path)) != 0) {
          client_usage(channel, 1);
          client_release(channel, client);
          return -1;
        }
        client->use_identity = 1U;
        continue;
      }
      if (token[0] == '-') {
        client_usage(channel, 1);
        client_release(channel, client);
        return -1;
      }
      position = saved;
      break;
    }
    if (next_token(command, &position, source, sizeof(source)) != 0 ||
        next_token(command, &position, destination, sizeof(destination)) != 0) {
      client_usage(channel, 1);
      client_release(channel, client);
      return -1;
    }
    while (command[position] == ' ' || command[position] == '\t') ++position;
    if (command[position] != '\0') {
      client_usage(channel, 1);
      client_release(channel, client);
      return -1;
    }
    uint32_t source_colon = 0U;
    uint32_t destination_colon = 0U;
    int source_remote = remote_specification(source, &source_colon);
    int destination_remote =
        remote_specification(destination, &destination_colon);
    if (source_remote == destination_remote) {
      client_usage(channel, 1);
      client_release(channel, client);
      return -1;
    }
    char endpoint[SSH_CLIENT_HOST_MAX + SSH_CLIENT_USER_MAX];
    const char *remote = source_remote ? source : destination;
    uint32_t colon = source_remote ? source_colon : destination_colon;
    if (colon == 0U || colon >= sizeof(endpoint) || remote[colon + 1U] == '\0') {
      client_usage(channel, 1);
      client_release(channel, client);
      return -1;
    }
    ssh_mem_copy(endpoint, remote, colon);
    endpoint[colon] = '\0';
    if (parse_destination(client, endpoint) != 0 ||
        sshclient_string_copy(client->remote_path, sizeof(client->remote_path),
                    remote + colon + 1U) != ssh_str_len(remote + colon + 1U) ||
        resolve_local_path(channel, source_remote ? destination : source,
                           client->local_path,
                           sizeof(client->local_path)) != 0) {
      client_usage(channel, 1);
      client_release(channel, client);
      return -1;
    }
    client->mode = source_remote ? SSH_CLIENT_MODE_SCP_DOWNLOAD
                                 : SSH_CLIENT_MODE_SCP_UPLOAD;
    goto send_password_prompt;
  }
  for (;;) {
    uint32_t saved = position;
    if (next_token(command, &position, token, sizeof(token)) != 0) {
      client_release(channel, client);
      client_usage(channel, 0);
      return -1;
    }
    if (ssh_str_eq(token, "-p")) {
      if (next_token(command, &position, token, sizeof(token)) != 0 ||
          parse_port(token, &client->port) != 0) {
        client_release(channel, client);
        client_usage(channel, 0);
        return -1;
      }
      continue;
    }
    if (ssh_str_eq(token, "-J")) {
      if (client->proxy_enabled != 0U ||
          next_token(command, &position, token, sizeof(token)) != 0 ||
          parse_proxy_destination(client, token) != 0) {
        client_release(channel, client);
        client_usage(channel, 0);
        return -1;
      }
      client->proxy_enabled = 1U;
      continue;
    }
    if (ssh_str_eq(token, "-A")) {
      client->use_agent = 1U;
      continue;
    }
    if (token[0] == '-' && token[1] == 'o') {
      const char *option = token + 2U;
      if (option[0] == '\0') {
        if (next_token(command, &position, token, sizeof(token)) != 0) {
          client_release(channel, client);
          client_usage(channel, 0);
          return -1;
        }
        option = token;
      }
      if (client_set_option(client, option) != 0) {
        (void)output_text(client,
                          "ssh: only -o BatchMode=yes|no is understood\r\n");
        client_release(channel, client);
        return -1;
      }
      continue;
    }
    if (ssh_str_eq(token, "-i")) {
      if (next_token(command, &position, client->identity_path,
                     sizeof(client->identity_path)) != 0) {
        client_release(channel, client);
        client_usage(channel, 0);
        return -1;
      }
      client->use_identity = 1U;
      continue;
    }
    if (token[0] == '-') {
      client_release(channel, client);
      client_usage(channel, 0);
      return -1;
    }
    position = saved;
    break;
  }
  if (next_token(command, &position, token, sizeof(token)) != 0 ||
      parse_destination(client, token) != 0) {
    client_release(channel, client);
    client_usage(channel, 0);
    return -1;
  }
  while (command[position] == ' ' || command[position] == '\t') ++position;
  if (command[position] != '\0') {
    if (sshclient_string_copy(client->command, sizeof(client->command),
                    command + position) != ssh_str_len(command + position)) {
      client_release(channel, client);
      client_usage(channel, 0);
      return -1;
    }
    client->mode = SSH_CLIENT_MODE_EXEC;
  }
  if (client->proxy_enabled != 0U) {
    if (client->use_agent != 0U) {
      (void)output_text(client,
                        "ssh: -J with forwarded-agent authentication is not supported\r\n");
      client_release(channel, client);
      return -1;
    }
    if (sshclient_string_copy(client->target_host, sizeof(client->target_host),
                    client->host) != ssh_str_len(client->host) ||
        sshclient_string_copy(client->target_user, sizeof(client->target_user),
                    client->user) != ssh_str_len(client->user)) {
      client_release(channel, client);
      client_usage(channel, 0);
      return -1;
    }
    client->target_port = client->port;
    client->target_use_identity = client->use_identity;
    sshclient_string_copy(client->host, sizeof(client->host), client->proxy_host);
    sshclient_string_copy(client->user, sizeof(client->user), client->proxy_user);
    client->port = client->proxy_port;
    client->use_identity = 0U;
    client->use_agent = 0U;
  }
send_password_prompt:
  if (client->use_agent != 0U && client->use_identity != 0U) {
    client_usage(channel, is_scp);
    client_release(channel, client);
    return -1;
  }
  if (client->use_agent != 0U) {
    if (output_text(client, "ssh: authenticating with forwarded agent\r\n") != 0)
      goto agent_failed;
    int handshake = client_handshake(client, channel);
    if (handshake != 0) goto agent_failed;
    if (client->mode == SSH_CLIENT_MODE_SCP_UPLOAD ||
        client->mode == SSH_CLIENT_MODE_SCP_DOWNLOAD) {
      int transfer = sshclient_scp_transfer(client);
      (void)output_text(client, transfer == 0 ? "scp: transfer complete\r\n"
                                                : "scp: transfer failed\r\n");
      client_release(channel, client);
      return transfer == 0 ? 1 : -1;
    }
    return 1;
agent_failed:
    (void)output_text(client,
                      "ssh: forwarded-agent authentication failed\r\n");
    client_release(channel, client);
    return -1;
  }
  /* B-37. The prompt is no longer unconditional: an identity file with no
     passphrase is loaded without asking anybody anything, which is what lets
     a run with no terminal finish. When something genuinely has to be asked
     for and there is nobody to ask -- BatchMode -- that is an error here,
     and an error here is a non-zero exit rather than a wait. */
  int credential = client_request_credential(client, channel);
  if (credential < 0) {
    client_release(channel, client);
    return -1;
  }
  if (credential > 0) return 1;
  return client_proceed(client, channel, 0) < 0 ? -1 : 1;
}

int ssh_client_password_input(struct ssh_channel *channel,
                              const uint8_t *data, uint32_t length) {
  ssh_client_context_t *client = client_for_channel(channel);
  if (client == 0 || client->prompting == 0U) return -1;
  /* Somebody is there: the idle clock starts again from this keystroke. */
  client->prompt_deadline = xaios_clock_nanos() + SSH_CLIENT_PROMPT_IDLE_NS;
  for (uint32_t i = 0U; i < length; ++i) {
    uint8_t value = data[i];
    if (value == 3U) {
      (void)output_text(client, "^C\r\n");
      client_release(channel, client);
      return 1;
    }
    if (value == 8U || value == 127U) {
      if (client->password_length != 0U)
        client->password[--client->password_length] = '\0';
      continue;
    }
    if (value != '\r' && value != '\n') {
      if (value >= 32U && value <= 126U &&
          client->password_length < SSH_CLIENT_PASSWORD_MAX) {
        client->password[client->password_length++] = (char)value;
        client->password[client->password_length] = '\0';
      }
      continue;
    }
    client->prompting = 0U;
    return client_proceed(client, channel, 1) == 0 ? 0 : 1;
  }
  return 0;
}

int send_channel_data(ssh_client_context_t *client,
                             const uint8_t *data, uint32_t length) {
  uint32_t offset = 0U;
  while (offset < length) {
    if (client->remote_window == 0U) {
      uint64_t deadline = xaios_clock_nanos() + SSH_CLIENT_TIMEOUT_NS;
      for (;;) {
        ssh_packet_t *packet = &client->packet_workspace;
        if (wait_encrypted_packet(client, packet, deadline) != 0 ||
            packet->len == 0U) return -1;
        if (packet->data[0] == SSH_MSG_CHANNEL_WINDOW_ADJUST &&
            packet->len >= 9U) {
          uint32_t added = ssh_read_u32_be(packet->data + 5U);
          if (UINT32_MAX - client->remote_window < added) return -1;
          client->remote_window += added;
          break;
        }
        if (packet->data[0] == SSH_MSG_CHANNEL_CLOSE ||
            packet->data[0] == SSH_MSG_DISCONNECT) return -1;
      }
    }
    uint32_t chunk = length - offset;
    if (chunk > client->remote_window) chunk = client->remote_window;
    if (chunk > client->remote_max_packet) chunk = client->remote_max_packet;
    if (chunk > SSH_WIRE_MAX_CHUNK) chunk = SSH_WIRE_MAX_CHUNK;
    uint8_t *packet = client->packet_workspace.data;
    packet[0] = SSH_MSG_CHANNEL_DATA;
    ssh_write_u32_be(packet + 1U, client->remote_channel);
    ssh_write_u32_be(packet + 5U, chunk);
    ssh_mem_copy(packet + 9U, data + offset, chunk);
    if (ssh_packet_write_encrypted((int)client->sockfd, packet, chunk + 9U) != 0)
      return -1;
    client->remote_window -= chunk;
    offset += chunk;
  }
  return 0;
}

int ssh_client_forward_input(struct ssh_channel *channel,
                             const uint8_t *data, uint32_t length) {
  ssh_client_context_t *client = client_for_channel(channel);
  if (client == 0 || client->connected == 0U ||
      client->mode != SSH_CLIENT_MODE_SHELL) return -1;
  return send_channel_data(client, data, length);
}

static int client_send_close(ssh_client_context_t *client) {
  if (client->close_sent != 0U) return 0;
  uint8_t packet[5];
  packet[0] = SSH_MSG_CHANNEL_CLOSE;
  ssh_write_u32_be(packet + 1U, client->remote_channel);
  if (ssh_packet_write_encrypted((int)client->sockfd, packet,
                                 sizeof(packet)) != 0) return -1;
  client->close_sent = 1U;
  return 0;
}

int ssh_client_tick(struct ssh_channel *channel, uint64_t now_ns) {
  ssh_client_context_t *client = client_for_channel(channel);
  if (client == 0) return 0;
  if (client->prompting != 0U) {
    /* B-37's backstop. A prompt this client cannot know is unanswerable --
       it is never told whether the session has a terminal -- stops being a
       wait once nothing has been typed at it for long enough, and becomes a
       failure the caller can see and act on. */
    if (now_ns < client->prompt_deadline) return 0;
    (void)output_text(
        client,
        "\r\nssh: nothing answered the prompt; no terminal? "
        "use -o BatchMode=yes\r\n");
    client_release(channel, client);
    return -1;
  }
  if (client->connected == 0U) return 0;
  for (uint32_t iteration = 0U; iteration < 8U; ++iteration) {
    ssh_packet_t *packet = &client->packet_workspace;
    int result = ssh_packet_read_encrypted((int)client->sockfd, packet);
    if (result > 0) return 0;
    if (result < 0 || packet->len == 0U) {
      (void)output_text(client, "\r\nssh: connection closed with protocol error\r\n");
      client_release(channel, client);
      return 1;
    }
    uint8_t type = packet->data[0];
    if ((type == SSH_MSG_CHANNEL_DATA ||
         type == SSH_MSG_CHANNEL_EXTENDED_DATA) && packet->len >= 9U) {
      uint32_t string_offset = type == SSH_MSG_CHANNEL_DATA ? 5U : 9U;
      if (type == SSH_MSG_CHANNEL_EXTENDED_DATA && packet->len < 13U)
        return -1;
      uint32_t length = ssh_read_u32_be(packet->data + string_offset);
      string_offset += 4U;
      if (length > packet->len - string_offset) return -1;
      if (ssh_channel_send_data((int)client->outer_sockfd,
                                client->outer_remote_id,
                                packet->data + string_offset, length) != 0)
        return -1;
      if (length > client->receive_window) return -1;
      client->receive_window -= length;
      if (client->receive_window <= SSH_CLIENT_WINDOW / 2U) {
        uint32_t added = SSH_CLIENT_WINDOW - client->receive_window;
        uint8_t adjust[9];
        adjust[0] = SSH_MSG_CHANNEL_WINDOW_ADJUST;
        ssh_write_u32_be(adjust + 1U, client->remote_channel);
        ssh_write_u32_be(adjust + 5U, added);
        if (ssh_packet_write_encrypted((int)client->sockfd, adjust,
                                       sizeof(adjust)) != 0) return -1;
        client->receive_window += added;
      }
    } else if (type == SSH_MSG_CHANNEL_WINDOW_ADJUST && packet->len >= 9U) {
      uint32_t added = ssh_read_u32_be(packet->data + 5U);
      if (UINT32_MAX - client->remote_window < added) return -1;
      client->remote_window += added;
    } else if (type == SSH_MSG_CHANNEL_REQUEST && packet->len >= 9U) {
      uint32_t name_length = ssh_read_u32_be(packet->data + 5U);
      if (name_length == 11U && packet->len >= 25U &&
          bytes_equal(packet->data + 9U, (const uint8_t *)"exit-status", 11U)) {
        client->exit_status = ssh_read_u32_be(packet->data + 21U);
      }
    } else if (type == SSH_MSG_CHANNEL_EOF) {
      (void)client_send_close(client);
    } else if (type == SSH_MSG_CHANNEL_CLOSE || type == SSH_MSG_DISCONNECT) {
      (void)client_send_close(client);
      if (client->mode == SSH_CLIENT_MODE_SHELL)
        (void)output_text(client, "\r\nConnection closed.\r\n");
      else if (client->exit_status != 0U)
        (void)output_text(client, "ssh: remote command failed\r\n");
      client_release(channel, client);
      return 1;
    } else if (type == SSH_MSG_GLOBAL_REQUEST && packet->len >= 6U) {
      uint32_t name_length = ssh_read_u32_be(packet->data + 1U);
      if (name_length <= packet->len - 6U && packet->data[5U + name_length] != 0U) {
        uint8_t failure = SSH_MSG_REQUEST_FAILURE;
        if (ssh_packet_write_encrypted((int)client->sockfd, &failure, 1U) != 0)
          return -1;
      }
    }
  }
  return 0;
}

void ssh_client_close(struct ssh_channel *channel) {
  ssh_client_context_t *client = client_for_channel(channel);
  if (client == 0) return;
  if (client->connected != 0U) (void)client_send_close(client);
  client_release(channel, client);
}

int ssh_client_is_prompting(const struct ssh_channel *channel) {
  ssh_client_context_t *client = client_for_channel(channel);
  return client != 0 && client->prompting != 0U;
}

int ssh_client_is_active(const struct ssh_channel *channel) {
  ssh_client_context_t *client = client_for_channel(channel);
  /* A client waiting for an answer is active too, so that it is ticked and
     the prompt's idle clock is read. Without this the only caller ticks
     nothing until a connection exists, and the wait would be unbounded
     again. */
  return client != 0 && (client->connected != 0U || client->prompting != 0U);
}
