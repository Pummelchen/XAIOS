/* The SSH client's key exchange and transport core, split out of
 * `ssh_client.c`: SHA-256 key derivation, the plain and encrypted packet waits,
 * the KEXINIT build and validation, host address resolution, known-hosts
 * verification and the KEXDH reply parser. One contiguous run moved verbatim;
 * it holds no `XAIOS_SSH_CLIENT_APP` region, so a guard-off build still sees
 * exactly the code it saw before. The only edits are the `static` dropped from
 * the seven symbols the other two files call.
 */

#include "ssh_client_internal.h"

#include "ssh_known_hosts.h"
#include "ssh_mlkem.h"
#include "tweetnacl_subset.h"

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

int sshclient_derive_crypto(ssh_connection_t *connection) {
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

int sshclient_wait_plain_packet(ssh_client_context_t *client, ssh_packet_t *packet,
                             uint64_t deadline) {
  return wait_plain_packet_fd((int)client->sockfd, packet, deadline);
}

int sshclient_wait_encrypted_packet_fd(int sockfd, ssh_packet_t *packet,
                                    uint64_t deadline) {
  for (;;) {
    int result = ssh_packet_read_encrypted(sockfd, packet);
    if (result <= 0) return result;
    if (xaios_clock_nanos() >= deadline) return -1;
  }
}

int wait_encrypted_packet(ssh_client_context_t *client,
                                 ssh_packet_t *packet, uint64_t deadline) {
  return sshclient_wait_encrypted_packet_fd((int)client->sockfd, packet, deadline);
}

int sshclient_build_kexinit(uint8_t *buffer, uint32_t capacity,
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
        sshclient_bytes_equal(list + start, (const uint8_t *)name, name_length)) {
      return 1;
    }
    start = i + 1U;
  }
  return 0;
}

int sshclient_validate_server_kexinit(const ssh_packet_t *packet,
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

int sshclient_resolve_host(const char *host, xaios_ip_addr_user_t *address,
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
    (void)sshclient_output_text(client,
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
  return sshclient_output_text(client, "Warning: permanently added host key to /home/admin/.ssh/known_hosts\r\n");
}

int sshclient_parse_kex_reply(ssh_client_context_t *client,
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
      !sshclient_bytes_equal(host_blob + 4U, (const uint8_t *)"ssh-ed25519", 11U) ||
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
      !sshclient_bytes_equal(signature_blob + 4U, (const uint8_t *)"ssh-ed25519", 11U) ||
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
