#include "ssh_identity.h"

#include "bcrypt_pbkdf.h"
#include "ssh_crypto.h"
#include "ssh_utils.h"
#include "tweetnacl_subset.h"
#if !defined(XAIOS_IDENTITY_HOSTED)
#include <xaios_user.h>
#endif

#define SSH_IDENTITY_FILE_MAX 8192U
#define SSH_IDENTITY_BLOB_MAX 6144U

typedef struct identity_reader {
  const uint8_t *data;
  uint32_t length;
  uint32_t position;
} identity_reader_t;

#if !defined(XAIOS_IDENTITY_HOSTED)
static uint8_t g_identity_file[SSH_IDENTITY_FILE_MAX + 1U];
#endif
static uint8_t g_identity_blob[SSH_IDENTITY_BLOB_MAX];
static uint8_t g_identity_private[SSH_IDENTITY_BLOB_MAX];

static int identity_equal(const uint8_t *left, const uint8_t *right,
                          uint32_t length) {
  uint8_t difference = 0U;
  for (uint32_t i = 0U; i < length; ++i) difference |= left[i] ^ right[i];
  return difference == 0U;
}

static int read_u32(identity_reader_t *reader, uint32_t *value) {
  if (reader->position > reader->length ||
      reader->length - reader->position < 4U) return -1;
  const uint8_t *bytes = reader->data + reader->position;
  *value = ((uint32_t)bytes[0] << 24U) | ((uint32_t)bytes[1] << 16U) |
           ((uint32_t)bytes[2] << 8U) | (uint32_t)bytes[3];
  reader->position += 4U;
  return 0;
}

static int read_string(identity_reader_t *reader, const uint8_t **value,
                       uint32_t *length) {
  if (read_u32(reader, length) != 0 || reader->position > reader->length ||
      *length > reader->length - reader->position) return -1;
  *value = reader->data + reader->position;
  reader->position += *length;
  return 0;
}

static int text_equal(const uint8_t *value, uint32_t length,
                      const char *expected) {
  uint32_t expected_length = ssh_str_len(expected);
  return length == expected_length &&
         identity_equal(value, (const uint8_t *)expected, length);
}

static int base64_value(char value) {
  if (value >= 'A' && value <= 'Z') return value - 'A';
  if (value >= 'a' && value <= 'z') return value - 'a' + 26;
  if (value >= '0' && value <= '9') return value - '0' + 52;
  if (value == '+') return 62;
  if (value == '/') return 63;
  return -1;
}

static int decode_pem(const char *pem, uint32_t pem_length, uint8_t *output,
                      uint32_t capacity, uint32_t *output_length) {
  static const char begin[] = "-----BEGIN OPENSSH PRIVATE KEY-----";
  static const char end[] = "-----END OPENSSH PRIVATE KEY-----";
  uint32_t position = 0U;
  while (position < pem_length && pem[position] != '\n') ++position;
  if (position != sizeof(begin) - 1U ||
      !identity_equal((const uint8_t *)pem, (const uint8_t *)begin,
                      sizeof(begin) - 1U)) return -1;
  if (position < pem_length) ++position;
  uint32_t accumulator = 0U, bits = 0U, used = 0U;
  uint32_t saw_padding = 0U;
  while (position < pem_length) {
    if (pem_length - position >= sizeof(end) - 1U &&
        identity_equal((const uint8_t *)pem + position,
                       (const uint8_t *)end, sizeof(end) - 1U)) break;
    char character = pem[position++];
    if (character == '\r' || character == '\n') continue;
    if (character == '=') {
      saw_padding = 1U;
      continue;
    }
    int value = base64_value(character);
    if (value < 0 || saw_padding != 0U) return -1;
    accumulator = (accumulator << 6U) | (uint32_t)value;
    bits += 6U;
    if (bits >= 8U) {
      bits -= 8U;
      if (used >= capacity) return -1;
      output[used++] = (uint8_t)(accumulator >> bits);
      accumulator &= bits == 0U ? 0U : ((1U << bits) - 1U);
    }
  }
  if (position == pem_length || used == 0U || bits >= 6U) return -1;
  *output_length = used;
  return 0;
}

static int parse_public_blob(const uint8_t *blob, uint32_t blob_length,
                             uint8_t public_key[32]) {
  identity_reader_t reader = {blob, blob_length, 0U};
  const uint8_t *algorithm, *key;
  uint32_t algorithm_length, key_length;
  if (read_string(&reader, &algorithm, &algorithm_length) != 0 ||
      !text_equal(algorithm, algorithm_length, "ssh-ed25519") ||
      read_string(&reader, &key, &key_length) != 0 || key_length != 32U ||
      reader.position != reader.length) return -1;
  ssh_mem_copy(public_key, key, 32U);
  return 0;
}

static int decrypt_private(const uint8_t *cipher, uint32_t cipher_length,
                           const uint8_t *kdf, uint32_t kdf_length,
                           const uint8_t *options, uint32_t options_length,
                           const char *passphrase, const uint8_t *encrypted,
                           uint32_t encrypted_length) {
  if (encrypted_length > sizeof(g_identity_private)) return -1;
  if (text_equal(cipher, cipher_length, "none") &&
      text_equal(kdf, kdf_length, "none") && options_length == 0U) {
    ssh_mem_copy(g_identity_private, encrypted, encrypted_length);
    return 0;
  }
  if (!text_equal(cipher, cipher_length, "aes256-ctr") ||
      !text_equal(kdf, kdf_length, "bcrypt") || passphrase == 0 ||
      passphrase[0] == '\0') return -1;
  identity_reader_t reader = {options, options_length, 0U};
  const uint8_t *salt;
  uint32_t salt_length, rounds;
  uint8_t material[48];
  if (read_string(&reader, &salt, &salt_length) != 0 || salt_length == 0U ||
      salt_length > 64U || read_u32(&reader, &rounds) != 0 ||
      rounds == 0U || rounds > 1000000U || reader.position != reader.length ||
      bcrypt_pbkdf(passphrase, ssh_str_len(passphrase), salt, salt_length,
                   material, sizeof(material), rounds) != 0) return -1;
  aes256_ctx_t aes;
  aes256_init(&aes, material);
  aes256_ctr(&aes, material + 32U, encrypted, g_identity_private,
             encrypted_length);
  ssh_mem_zero(material, sizeof(material));
  ssh_mem_zero(&aes, sizeof(aes));
  return 0;
}

int ssh_identity_parse_openssh(const char *pem, uint32_t pem_length,
                               const char *passphrase,
                               ssh_identity_t *identity) {
  static const uint8_t magic[] = "openssh-key-v1\0";
  uint32_t blob_length = 0U;
  if (pem == 0 || identity == 0 || pem_length == 0U ||
      pem_length > SSH_IDENTITY_FILE_MAX ||
      decode_pem(pem, pem_length, g_identity_blob, sizeof(g_identity_blob),
                 &blob_length) != 0 || blob_length < sizeof(magic) - 1U ||
      !identity_equal(g_identity_blob, magic, sizeof(magic) - 1U)) return -1;
  identity_reader_t reader = {g_identity_blob, blob_length,
                              sizeof(magic) - 1U};
  const uint8_t *cipher, *kdf, *options, *public_blob, *encrypted;
  uint32_t cipher_length, kdf_length, options_length, public_blob_length;
  uint32_t encrypted_length, key_count;
  uint8_t outer_public[32];
  if (read_string(&reader, &cipher, &cipher_length) != 0 ||
      read_string(&reader, &kdf, &kdf_length) != 0 ||
      read_string(&reader, &options, &options_length) != 0 ||
      read_u32(&reader, &key_count) != 0 || key_count != 1U ||
      read_string(&reader, &public_blob, &public_blob_length) != 0 ||
      parse_public_blob(public_blob, public_blob_length, outer_public) != 0 ||
      read_string(&reader, &encrypted, &encrypted_length) != 0 ||
      reader.position != reader.length || encrypted_length == 0U ||
      encrypted_length % 8U != 0U ||
      decrypt_private(cipher, cipher_length, kdf, kdf_length, options,
                      options_length, passphrase, encrypted,
                      encrypted_length) != 0) return -1;

  identity_reader_t private_reader = {g_identity_private, encrypted_length, 0U};
  uint32_t check1, check2;
  const uint8_t *algorithm, *public_key, *private_key, *comment;
  uint32_t algorithm_length, public_length, private_length, comment_length;
  if (read_u32(&private_reader, &check1) != 0 ||
      read_u32(&private_reader, &check2) != 0 || check1 != check2 ||
      read_string(&private_reader, &algorithm, &algorithm_length) != 0 ||
      !text_equal(algorithm, algorithm_length, "ssh-ed25519") ||
      read_string(&private_reader, &public_key, &public_length) != 0 ||
      public_length != 32U ||
      read_string(&private_reader, &private_key, &private_length) != 0 ||
      private_length != 64U ||
      read_string(&private_reader, &comment, &comment_length) != 0) return -1;
  (void)comment;
  (void)comment_length;
  for (uint32_t padding = 1U; private_reader.position < private_reader.length;
       ++padding) {
    if (padding > 255U ||
        private_reader.data[private_reader.position++] != (uint8_t)padding)
      return -1;
  }
  uint8_t generated_public[32];
  xaios_ed25519_public_key(generated_public, private_key);
  if (!identity_equal(public_key, outer_public, 32U) ||
      !identity_equal(private_key + 32U, outer_public, 32U) ||
      !identity_equal(generated_public, outer_public, 32U)) return -1;
  ssh_mem_copy(identity->public_key, outer_public, 32U);
  ssh_mem_copy(identity->seed, private_key, 32U);
  ssh_mem_zero(g_identity_private, sizeof(g_identity_private));
  return 0;
}

#if !defined(XAIOS_IDENTITY_HOSTED)
int ssh_identity_load(const char *path, const char *passphrase,
                      ssh_identity_t *identity) {
  int descriptor = xaios_fs_open(path, XAIOS_XBFS_OPEN_READ);
  if (descriptor < 0) return -1;
  uint64_t used = 0U;
  int result = 0;
  while (used < SSH_IDENTITY_FILE_MAX) {
    int received = xaios_fs_read(descriptor, g_identity_file + used,
                                 SSH_IDENTITY_FILE_MAX - used);
    if (received < 0) {
      result = -1;
      break;
    }
    if (received == 0U) break;
    used += (uint32_t)received;
  }
  if (used == SSH_IDENTITY_FILE_MAX) {
    uint8_t extra;
    int received = xaios_fs_read(descriptor, &extra, 1U);
    if (received != 0)
      result = -1;
  }
  if (xaios_fs_close(descriptor) != 0) result = -1;
  if (result == 0)
    result = ssh_identity_parse_openssh((const char *)g_identity_file,
                                        (uint32_t)used, passphrase, identity);
  ssh_mem_zero(g_identity_file, sizeof(g_identity_file));
  ssh_mem_zero(g_identity_blob, sizeof(g_identity_blob));
  ssh_mem_zero(g_identity_private, sizeof(g_identity_private));
  return result;
}
#endif
