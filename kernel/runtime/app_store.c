#include <xaios/app_store.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/xaiboot_fs.h>
#include <xaios/security.h>
#include <xaios/sha256.h>

#define APP_PATH_MAX 96U
#define APP_SIGNATURE_HEX_BYTES 128U
#define APP_PUBLIC_KEY_BYTES 32U
#define APP_PUBLIC_KEY_HEX_BYTES 64U
#define APP_TRUST_CHAIN_MAX 4096U
#define APP_TRUST_LINE_MAX 384U
#define APP_REVOKED_KEY_MAX 8U

typedef struct app_trust_state {
  uint32_t generation;
  uint8_t active_key[APP_PUBLIC_KEY_BYTES];
  uint32_t revoked_count;
  uint8_t revoked_keys[APP_REVOKED_KEY_MAX][APP_PUBLIC_KEY_BYTES];
} app_trust_state_t;

static xaios_status_t validate_trust_chain(const char *data, uint64_t size,
                                           app_trust_state_t *state);
static xaios_status_t parse_catalog_identity(const char *data, uint64_t size,
                                             uint32_t *generation);
static xaios_status_t copy_if_present(const char *source, const char *target);
static xaios_status_t read_file_alloc(const char *path, uint64_t maximum,
                                      void **data, uint64_t *size);

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0U; i < size; ++i) bytes[i] = 0U;
}

static void bytes_copy(void *dst, const void *src, uint64_t size) {
  uint8_t *output = (uint8_t *)dst;
  const uint8_t *input = (const uint8_t *)src;
  for (uint64_t i = 0U; i < size; ++i) output[i] = input[i];
}

static uint64_t text_length(const char *text) {
  uint64_t length = 0U;
  if (text == 0) return 0U;
  while (text[length] != '\0') ++length;
  return length;
}

static int text_equal(const char *left, const char *right) {
  uint64_t i = 0U;
  if (left == 0 || right == 0) return 0;
  while (left[i] != '\0' && left[i] == right[i]) ++i;
  return left[i] == right[i];
}

static int bytes_equal(const uint8_t *left, const uint8_t *right,
                       uint64_t size) {
  uint8_t difference = 0U;
  for (uint64_t i = 0U; i < size; ++i) difference |= left[i] ^ right[i];
  return difference == 0U;
}

static int trust_key_is_revoked(const app_trust_state_t *state,
                                const uint8_t key[APP_PUBLIC_KEY_BYTES]) {
  for (uint32_t i = 0U; i < state->revoked_count; ++i) {
    if (bytes_equal(state->revoked_keys[i], key, APP_PUBLIC_KEY_BYTES))
      return 1;
  }
  return 0;
}

static int trust_revoke_key(app_trust_state_t *state,
                            const uint8_t key[APP_PUBLIC_KEY_BYTES]) {
  if (trust_key_is_revoked(state, key)) return 1;
  if (state->revoked_count >= APP_REVOKED_KEY_MAX) return 0;
  bytes_copy(state->revoked_keys[state->revoked_count++], key,
             APP_PUBLIC_KEY_BYTES);
  return 1;
}

static int app_name_valid(const char *name) {
  uint64_t length = text_length(name);
  if (length == 0U || length >= XAIOS_APP_NAME_MAX) return 0;
  for (uint64_t i = 0U; i < length; ++i) {
    char ch = name[i];
    if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') ||
          ch == '-' || ch == '_')) {
      return 0;
    }
  }
  return 1;
}

static int append_text(char *path, uint64_t capacity, uint64_t *offset,
                       const char *text) {
  uint64_t i = 0U;
  while (text[i] != '\0') {
    if (*offset + 1U >= capacity) return 0;
    path[(*offset)++] = text[i++];
  }
  path[*offset] = '\0';
  return 1;
}

static int app_path(char *path, uint64_t capacity, const char *name,
                    const char *leaf, int staging) {
  uint64_t offset = 0U;
  path[0] = '\0';
  return app_name_valid(name) &&
         append_text(path, capacity, &offset,
                     staging ? "/update/xapt/" : "/apps/") &&
         append_text(path, capacity, &offset, name) &&
         (staging || append_text(path, capacity, &offset, "/")) &&
         append_text(path, capacity, &offset, leaf);
}

static int hex_digit(char ch) {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return 10 + ch - 'a';
  if (ch >= 'A' && ch <= 'F') return 10 + ch - 'A';
  return -1;
}

static int parse_hex(const char *text, uint8_t *output, uint32_t size) {
  for (uint32_t i = 0U; i < size; ++i) {
    int high = hex_digit(text[i * 2U]);
    int low = hex_digit(text[i * 2U + 1U]);
    if (high < 0 || low < 0) return 0;
    output[i] = (uint8_t)((high << 4) | low);
  }
  return 1;
}

static int parse_u64(const char *text, uint64_t length, uint64_t *value) {
  uint64_t result = 0U;
  if (length == 0U) return 0;
  for (uint64_t i = 0U; i < length; ++i) {
    uint64_t digit;
    if (text[i] < '0' || text[i] > '9') return 0;
    digit = (uint64_t)(text[i] - '0');
    if (result > (UINT64_MAX - digit) / 10U) return 0;
    result = result * 10U + digit;
  }
  *value = result;
  return 1;
}

static int copy_field(char *dst, uint64_t capacity, const char *src,
                      uint64_t length) {
  if (length == 0U || length >= capacity) return 0;
  for (uint64_t i = 0U; i < length; ++i) dst[i] = src[i];
  dst[length] = '\0';
  return 1;
}

static int next_field(const char *data, uint64_t size, uint64_t *cursor,
                      const char *key, const char **value,
                      uint64_t *value_length) {
  uint64_t key_length = text_length(key);
  uint64_t start = *cursor;
  if (start + key_length + 2U > size) return 0;
  for (uint64_t i = 0U; i < key_length; ++i) {
    if (data[start + i] != key[i]) return 0;
  }
  if (data[start + key_length] != '=') return 0;
  start += key_length + 1U;
  uint64_t end = start;
  while (end < size && data[end] != '\n') {
    if ((uint8_t)data[end] < 32U || (uint8_t)data[end] > 126U) return 0;
    ++end;
  }
  if (end >= size || end == start) return 0;
  *value = data + start;
  *value_length = end - start;
  *cursor = end + 1U;
  return 1;
}

static int parse_semver(const char *version, uint32_t parts[3]) {
  uint64_t cursor = 0U;
  for (uint32_t part = 0U; part < 3U; ++part) {
    uint64_t value = 0U;
    uint64_t digits = 0U;
    while (version[cursor] >= '0' && version[cursor] <= '9') {
      value = value * 10U + (uint64_t)(version[cursor++] - '0');
      if (value > UINT32_MAX) return 0;
      ++digits;
    }
    if (digits == 0U || (part < 2U && version[cursor++] != '.') ||
        (part == 2U && version[cursor] != '\0')) {
      return 0;
    }
    parts[part] = (uint32_t)value;
  }
  return 1;
}

/* Whether this build satisfies a package's declared minimum. The minimum is a
   whole number in text; anything that is not one is refused rather than
   assumed to be zero, so a malformed manifest cannot install everywhere. */
static int build_at_least(uint32_t current, const char *minimum) {
  if (minimum == 0 || minimum[0] == '\0') return 0;
  uint32_t value = 0U;
  for (const char *cursor = minimum; *cursor != '\0'; ++cursor) {
    if (*cursor < '0' || *cursor > '9') return 0;
    if (value > (UINT32_MAX - (uint32_t)(*cursor - '0')) / 10U) return 0;
    value = value * 10U + (uint32_t)(*cursor - '0');
  }
  return current >= value;
}

static int architecture_matches(const char *architecture) {
#if defined(__aarch64__)
  return text_equal(architecture, "aarch64");
#elif defined(__x86_64__)
  return text_equal(architecture, "x86_64");
#elif defined(__riscv)
  /* This returned zero here, so a RISC-V machine refused every package and
     every catalog -- including ones published for it. The refusal is the
     right shape and the list it consulted was two architectures old; xapt's
     own client has reported "riscv64" for its architecture since this port
     gained userspace. */
  return text_equal(architecture, "riscv64");
#else
  (void)architecture;
  return 0;
#endif
}

static xaios_status_t verify_signed_document(const char *data, uint64_t size,
                                             const char *prefix,
                                             uint64_t maximum,
                                             uint64_t *signed_size) {
  static const char key_prefix[] = "key=";
  static const char signature_key[] = "signature=";
  uint64_t prefix_length = text_length(prefix);
  uint64_t key_length = sizeof(key_prefix) - 1U +
                        APP_PUBLIC_KEY_HEX_BYTES + 1U;
  uint64_t signature_offset = UINT64_MAX;
  uint8_t signature[64];
  uint8_t public_key[APP_PUBLIC_KEY_BYTES];
  if (data == 0 || size > maximum ||
      size < prefix_length + key_length + sizeof(signature_key) +
                 APP_SIGNATURE_HEX_BYTES ||
      data[size - 1U] != '\n') {
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t i = 0U; i < prefix_length; ++i) {
    if (data[i] != prefix[i]) return XAIOS_ERR_INVALID;
  }
  for (uint64_t i = prefix_length; i + sizeof(signature_key) - 1U < size;
       ++i) {
    if ((i == 0U || data[i - 1U] == '\n')) {
      uint64_t j = 0U;
      while (j < sizeof(signature_key) - 1U &&
             data[i + j] == signature_key[j]) {
        ++j;
      }
      if (j == sizeof(signature_key) - 1U) {
        signature_offset = i;
        break;
      }
    }
  }
  if (signature_offset == UINT64_MAX || signature_offset < key_length ||
      signature_offset + sizeof(signature_key) - 1U +
              APP_SIGNATURE_HEX_BYTES + 1U !=
          size) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t key_offset = signature_offset - key_length;
  for (uint64_t i = 0U; i < sizeof(key_prefix) - 1U; ++i)
    if (data[key_offset + i] != key_prefix[i]) return XAIOS_ERR_INVALID;
  if (data[signature_offset - 1U] != '\n' ||
      !parse_hex(data + key_offset + sizeof(key_prefix) - 1U, public_key,
                 sizeof(public_key)) ||
      !security_release_key_matches(public_key))
    return XAIOS_ERR_INVALID;
  if (!parse_hex(data + signature_offset + sizeof(signature_key) - 1U,
                 signature, sizeof(signature))) {
    return XAIOS_ERR_INVALID;
  }
  if (signature_offset > UINT32_MAX ||
      security_verify_release_signature(data, (uint32_t)signature_offset,
                                        signature) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (signed_size != 0) *signed_size = signature_offset;
  return XAIOS_OK;
}

static xaios_status_t parse_trust_line(const char *line, uint64_t size,
                                       const app_trust_state_t *current,
                                       app_trust_state_t *next) {
  static const char prefix[] = "XAIOS-TRUST-V1:gen=";
  static const char mode_field[] = ":mode=";
  static const char active_field[] = ":active=";
  static const char revoke_field[] = ":revoke=";
  static const char signer_field[] = ":signer=";
  static const char signature_field[] = ":sig=";
  uint64_t cursor = sizeof(prefix) - 1U;
  uint64_t start;
  uint64_t generation = 0U;
  uint8_t active[APP_PUBLIC_KEY_BYTES];
  uint8_t revoked[APP_PUBLIC_KEY_BYTES];
  uint8_t signer[APP_PUBLIC_KEY_BYTES];
  uint8_t signature[64];
  int recovery = 0;
  if (line == 0 || current == 0 || next == 0 || size > APP_TRUST_LINE_MAX ||
      size < sizeof(prefix) + 250U || line[size - 1U] != '\n')
    return XAIOS_ERR_INVALID;
  for (uint64_t i = 0U; i < sizeof(prefix) - 1U; ++i)
    if (line[i] != prefix[i]) return XAIOS_ERR_INVALID;
  start = cursor;
  while (cursor < size && line[cursor] >= '0' && line[cursor] <= '9')
    ++cursor;
  if (!parse_u64(line + start, cursor - start, &generation) ||
      generation <= current->generation || generation > UINT32_MAX)
    return XAIOS_ERR_INVALID;
#define TRUST_EXPECT(field)                                                   \
  do {                                                                        \
    for (uint64_t i = 0U; i < sizeof(field) - 1U; ++i)                        \
      if (cursor + i >= size || line[cursor + i] != field[i])                 \
        return XAIOS_ERR_INVALID;                                              \
    cursor += sizeof(field) - 1U;                                              \
  } while (0)
  TRUST_EXPECT(mode_field);
  if (cursor + 6U <= size && line[cursor] == 'r' && line[cursor + 1U] == 'o' &&
      line[cursor + 2U] == 't' && line[cursor + 3U] == 'a' &&
      line[cursor + 4U] == 't' && line[cursor + 5U] == 'e') {
    cursor += 6U;
  } else if (cursor + 8U <= size && line[cursor] == 'r' &&
             line[cursor + 1U] == 'e' && line[cursor + 2U] == 'c' &&
             line[cursor + 3U] == 'o' && line[cursor + 4U] == 'v' &&
             line[cursor + 5U] == 'e' && line[cursor + 6U] == 'r' &&
             line[cursor + 7U] == 'y') {
    recovery = 1;
    cursor += 8U;
  } else {
    return XAIOS_ERR_INVALID;
  }
  TRUST_EXPECT(active_field);
  if (cursor + APP_PUBLIC_KEY_HEX_BYTES > size ||
      !parse_hex(line + cursor, active, sizeof(active)))
    return XAIOS_ERR_INVALID;
  cursor += APP_PUBLIC_KEY_HEX_BYTES;
  TRUST_EXPECT(revoke_field);
  if (cursor + APP_PUBLIC_KEY_HEX_BYTES > size ||
      !parse_hex(line + cursor, revoked, sizeof(revoked)))
    return XAIOS_ERR_INVALID;
  cursor += APP_PUBLIC_KEY_HEX_BYTES;
  TRUST_EXPECT(signer_field);
  if (cursor + APP_PUBLIC_KEY_HEX_BYTES > size ||
      !parse_hex(line + cursor, signer, sizeof(signer)))
    return XAIOS_ERR_INVALID;
  cursor += APP_PUBLIC_KEY_HEX_BYTES;
  uint64_t signed_size = cursor;
  TRUST_EXPECT(signature_field);
  if (cursor + APP_SIGNATURE_HEX_BYTES + 1U != size ||
      !parse_hex(line + cursor, signature, sizeof(signature)))
    return XAIOS_ERR_INVALID;
  if (recovery) {
    if (!security_recovery_key_matches(signer)) return XAIOS_ERR_INVALID;
  } else if (!bytes_equal(signer, current->active_key, sizeof(signer)) ||
             !bytes_equal(revoked, current->active_key, sizeof(revoked)) ||
             trust_key_is_revoked(current, active)) {
    return XAIOS_ERR_INVALID;
  }
  if (bytes_equal(active, revoked, sizeof(active)) ||
      security_verify_signature_with_key(line, (uint32_t)signed_size,
                                         signature, signer) != XAIOS_OK)
    return XAIOS_ERR_INVALID;
  *next = *current;
  if (recovery) next->revoked_count = 0U;
  if (!trust_revoke_key(next, revoked)) return XAIOS_ERR_NO_MEMORY;
  next->generation = (uint32_t)generation;
  bytes_copy(next->active_key, active, sizeof(active));
#undef TRUST_EXPECT
  return XAIOS_OK;
}

static void default_trust_state(app_trust_state_t *state) {
  bytes_zero(state, sizeof(*state));
  state->generation = 1U;
  (void)parse_hex(XAIOS_RELEASE_PUBLIC_KEY_HEX, state->active_key,
                  sizeof(state->active_key));
}

static xaios_status_t load_trust_and_catalog(const char *trust_path,
                                             const char *catalog_path,
                                             app_trust_state_t *trust) {
  void *trust_data = 0;
  uint64_t trust_size = 0U;
  void *catalog_data = 0;
  uint64_t catalog_size = 0U;
  uint32_t generation = 0U;
  default_trust_state(trust);
  xaios_status_t trust_status = read_file_alloc(
      trust_path, APP_TRUST_CHAIN_MAX, &trust_data, &trust_size);
  if (trust_status == XAIOS_OK &&
      validate_trust_chain((const char *)trust_data, trust_size, trust) !=
          XAIOS_OK) {
    kheap_free(trust_data);
    return XAIOS_ERR_INVALID;
  }
  kheap_free(trust_data);
  (void)security_set_release_key(trust->active_key);
  xaios_status_t catalog_status = read_file_alloc(
      catalog_path, XAIOS_APP_CATALOG_MAX, &catalog_data, &catalog_size);
  if (trust_status == XAIOS_OK && catalog_status != XAIOS_OK) {
    kheap_free(catalog_data);
    return XAIOS_ERR_INVALID;
  }
  if (catalog_status == XAIOS_OK &&
      parse_catalog_identity((const char *)catalog_data, catalog_size,
                             &generation) != XAIOS_OK) {
    kheap_free(catalog_data);
    return XAIOS_ERR_INVALID;
  }
  kheap_free(catalog_data);
  return catalog_status == XAIOS_ERR_INVALID ? XAIOS_OK : catalog_status;
}

static xaios_status_t validate_trust_chain(const char *data, uint64_t size,
                                           app_trust_state_t *state) {
  app_trust_state_t current;
  default_trust_state(&current);
  uint64_t cursor = 0U;
  while (cursor < size) {
    uint64_t start = cursor;
    while (cursor < size && data[cursor] != '\n') ++cursor;
    if (cursor >= size || cursor == start ||
        parse_trust_line(data + start, cursor - start + 1U, &current,
                         state) != XAIOS_OK)
      return XAIOS_ERR_INVALID;
    current = *state;
    ++cursor;
  }
  *state = current;
  return XAIOS_OK;
}

static xaios_status_t parse_catalog_identity(const char *data, uint64_t size,
                                             uint32_t *generation) {
  static const char prefix[] = "XAIOS-CATALOG-V1\n";
  const char *value;
  uint64_t value_length;
  uint64_t cursor = sizeof(prefix) - 1U;
  uint64_t number = 0U;
  uint64_t signed_size = 0U;
  char architecture[XAIOS_APP_ARCH_MAX];

  if (generation == 0 ||
      verify_signed_document(data, size, prefix, XAIOS_APP_CATALOG_MAX,
                             &signed_size) != XAIOS_OK ||
      !next_field(data, signed_size, &cursor, "generation", &value,
                  &value_length) ||
      !parse_u64(value, value_length, &number) || number == 0U ||
      number > UINT32_MAX ||
      !next_field(data, signed_size, &cursor, "generated", &value,
                  &value_length) ||
      !next_field(data, signed_size, &cursor, "arch", &value,
                  &value_length) ||
      !copy_field(architecture, sizeof(architecture), value, value_length) ||
      !architecture_matches(architecture)) {
    return XAIOS_ERR_INVALID;
  }
  *generation = (uint32_t)number;
  return XAIOS_OK;
}

static xaios_status_t parse_manifest(const char *data, uint64_t size,
                                     xaios_app_manifest_t *manifest) {
  static const char prefix[] = "XAIOS-APP-V1\n";
  const char *value;
  uint64_t value_length;
  uint64_t cursor = sizeof(prefix) - 1U;
  uint64_t number;
  uint64_t signed_size;
  bytes_zero(manifest, sizeof(*manifest));
  if (verify_signed_document(data, size, prefix, XAIOS_APP_MANIFEST_MAX,
                             &signed_size) != XAIOS_OK ||
      !next_field(data, signed_size, &cursor, "name", &value,
                  &value_length) ||
      !copy_field(manifest->name, sizeof(manifest->name), value,
                  value_length) ||
      !next_field(data, signed_size, &cursor, "version", &value,
                  &value_length) ||
      !copy_field(manifest->version, sizeof(manifest->version), value,
                  value_length) ||
      !next_field(data, signed_size, &cursor, "arch", &value,
                  &value_length) ||
      !copy_field(manifest->architecture, sizeof(manifest->architecture),
                  value, value_length) ||
      !next_field(data, signed_size, &cursor, "min_os", &value,
                  &value_length) ||
      !copy_field(manifest->minimum_os, sizeof(manifest->minimum_os), value,
                  value_length) ||
      !next_field(data, signed_size, &cursor, "min_abi", &value,
                  &value_length) ||
      !parse_u64(value, value_length, &number) || number > UINT32_MAX) {
    return XAIOS_ERR_INVALID;
  }
  manifest->minimum_abi = (uint32_t)number;
  if (!next_field(data, signed_size, &cursor, "capabilities", &value,
                  &value_length) ||
      !parse_u64(value, value_length, &manifest->capabilities) ||
      !next_field(data, signed_size, &cursor, "size", &value,
                  &value_length) ||
      !parse_u64(value, value_length, &manifest->binary_size) ||
      !next_field(data, signed_size, &cursor, "sha256", &value,
                  &value_length) ||
      value_length != 64U ||
      !parse_hex(value, manifest->binary_hash,
                 sizeof(manifest->binary_hash)) ||
      !next_field(data, signed_size, &cursor, "key", &value,
                  &value_length) ||
      value_length != sizeof(XAIOS_RELEASE_PUBLIC_KEY_HEX) - 1U ||
      cursor != signed_size) {
    return XAIOS_ERR_INVALID;
  }
  if (!app_name_valid(manifest->name) ||
      !parse_semver(manifest->version, (uint32_t[3]){0U, 0U, 0U}) ||
      !architecture_matches(manifest->architecture) ||
      !build_at_least(XAIOS_APP_OS_BUILD, manifest->minimum_os) ||
      manifest->minimum_abi > XAIOS_APP_KERNEL_ABI_VERSION ||
      manifest->binary_size == 0U ||
      manifest->binary_size > XAIOS_XBFS_MAX_FILE_BYTES_V5) {
    return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
}

static xaios_status_t read_file_alloc(const char *path, uint64_t maximum,
                                      void **data, uint64_t *size) {
  xaios_xbfs_stat_t stat;
  if (xaiboot_fs_stat(path, &stat) != XAIOS_OK || stat.type != 2U ||
      stat.size == 0U || stat.size > maximum) {
    return XAIOS_ERR_INVALID;
  }
  void *buffer = kheap_alloc(stat.size + 1U, 16U);
  if (buffer == 0) return XAIOS_ERR_NO_MEMORY;
  uint64_t read_size = 0U;
  if (xaiboot_fs_read(path, buffer, stat.size, &read_size) != XAIOS_OK ||
      read_size != stat.size) {
    kheap_free(buffer);
    return XAIOS_ERR_IO;
  }
  ((uint8_t *)buffer)[stat.size] = 0U;
  *data = buffer;
  *size = stat.size;
  return XAIOS_OK;
}

static xaios_status_t load_version(const char *name, const char *leaf_prefix,
                                   xaios_app_image_t *image) {
  char manifest_path[APP_PATH_MAX];
  char binary_path[APP_PATH_MAX];
  char manifest_leaf[32];
  char binary_leaf[32];
  uint64_t offset = 0U;
  void *manifest_data = 0;
  uint64_t manifest_size = 0U;
  void *binary_data = 0;
  uint64_t binary_size = 0U;
  xaios_app_manifest_t manifest;
  uint8_t digest[32];
  manifest_leaf[0] = '\0';
  binary_leaf[0] = '\0';
  if (!append_text(manifest_leaf, sizeof(manifest_leaf), &offset, leaf_prefix) ||
      !append_text(manifest_leaf, sizeof(manifest_leaf), &offset,
                   ".manifest")) {
    return XAIOS_ERR_INVALID;
  }
  offset = 0U;
  if (!append_text(binary_leaf, sizeof(binary_leaf), &offset, leaf_prefix) ||
      !append_text(binary_leaf, sizeof(binary_leaf), &offset, ".elf") ||
      !app_path(manifest_path, sizeof(manifest_path), name, manifest_leaf, 0) ||
      !app_path(binary_path, sizeof(binary_path), name, binary_leaf, 0) ||
      read_file_alloc(manifest_path, XAIOS_APP_MANIFEST_MAX, &manifest_data,
                      &manifest_size) != XAIOS_OK ||
      parse_manifest((const char *)manifest_data, manifest_size, &manifest) !=
          XAIOS_OK ||
      !text_equal(name, manifest.name) ||
      read_file_alloc(binary_path, XAIOS_XBFS_MAX_FILE_BYTES_V5, &binary_data,
                      &binary_size) != XAIOS_OK ||
      binary_size != manifest.binary_size) {
    kheap_free(manifest_data);
    kheap_free(binary_data);
    return XAIOS_ERR_INVALID;
  }
  xaios_sha256(binary_data, binary_size, digest);
  if (!bytes_equal(digest, manifest.binary_hash, sizeof(digest))) {
    kheap_free(manifest_data);
    kheap_free(binary_data);
    return XAIOS_ERR_INVALID;
  }
  bytes_zero(image, sizeof(*image));
  bytes_copy(image->path, binary_path, text_length(binary_path) + 1U);
  bytes_copy(image->version, manifest.version,
             text_length(manifest.version) + 1U);
  image->capabilities = manifest.capabilities;
  image->file.path = image->path;
  image->file.base = binary_data;
  image->file.size = binary_size;
  image->file.executable = 1U;
  image->file.content_hash = 0U;
  kheap_free(manifest_data);
  return XAIOS_OK;
}

void app_store_init(void) {
  static const char trust_path[] = "/state/xapt/trust";
  static const char catalog_path[] = "/state/xapt/catalog";
  static const char previous_trust_path[] = "/state/xapt/trust.previous";
  static const char previous_catalog_path[] = "/state/xapt/catalog.previous";
  app_trust_state_t trust;
  (void)xaiboot_fs_mkdir("/apps");
  (void)xaiboot_fs_mkdir("/update");
  (void)xaiboot_fs_mkdir("/update/xapt");
  (void)xaiboot_fs_mkdir("/state/xapt");
  if (load_trust_and_catalog(trust_path, catalog_path, &trust) != XAIOS_OK) {
    klog("app-store: interrupted trust/catalog activation detected\n");
    if (copy_if_present(previous_trust_path, trust_path) != XAIOS_OK)
      (void)xaiboot_fs_delete(trust_path);
    if (copy_if_present(previous_catalog_path, catalog_path) != XAIOS_OK)
      (void)xaiboot_fs_delete(catalog_path);
    if (load_trust_and_catalog(trust_path, catalog_path, &trust) != XAIOS_OK) {
      (void)xaiboot_fs_delete(trust_path);
      (void)xaiboot_fs_delete(catalog_path);
      default_trust_state(&trust);
      klog("app-store: no verified rollback pair; bootstrap root retained\n");
    } else {
      klog("app-store: restored last verified trust/catalog pair\n");
    }
  }
  (void)security_set_release_key(trust.active_key);
  klog("app-store: initialized format=%u os_build=%u abi=%u\n",
       XAIOS_APP_FORMAT_VERSION, (unsigned)XAIOS_APP_OS_BUILD,
       XAIOS_APP_KERNEL_ABI_VERSION);
}

xaios_status_t app_store_load(const char *name, xaios_app_image_t *image) {
  if (image == 0 || !app_name_valid(name)) return XAIOS_ERR_INVALID;
  if (load_version(name, "current", image) == XAIOS_OK) return XAIOS_OK;
  return load_version(name, "previous", image);
}

void app_store_release(xaios_app_image_t *image) {
  if (image == 0) return;
  kheap_free(image->file.base);
  bytes_zero(image, sizeof(*image));
}

static xaios_status_t copy_if_present(const char *source, const char *target) {
  void *data = 0;
  uint64_t size = 0U;
  xaios_status_t status = read_file_alloc(source, XAIOS_XBFS_MAX_FILE_BYTES_V5,
                                          &data, &size);
  if (status != XAIOS_OK) return status;
  status = xaiboot_fs_write(target, data, size);
  kheap_free(data);
  return status;
}

xaios_status_t app_store_activate(const char *name) {
  char staged_manifest[APP_PATH_MAX];
  char staged_binary[APP_PATH_MAX];
  char app_dir[APP_PATH_MAX];
  char current_manifest[APP_PATH_MAX];
  char current_binary[APP_PATH_MAX];
  char previous_manifest[APP_PATH_MAX];
  char previous_binary[APP_PATH_MAX];
  void *manifest_data = 0;
  uint64_t manifest_size = 0U;
  void *binary_data = 0;
  uint64_t binary_size = 0U;
  xaios_app_manifest_t manifest;
  uint8_t binary_hash[32];
  uint64_t offset = 0U;
  if (!app_path(staged_manifest, sizeof(staged_manifest), name, ".manifest", 1) ||
      !app_path(staged_binary, sizeof(staged_binary), name, ".elf", 1) ||
      !app_path(current_manifest, sizeof(current_manifest), name,
                "current.manifest", 0) ||
      !app_path(current_binary, sizeof(current_binary), name, "current.elf", 0) ||
      !app_path(previous_manifest, sizeof(previous_manifest), name,
                "previous.manifest", 0) ||
      !app_path(previous_binary, sizeof(previous_binary), name,
                "previous.elf", 0)) {
    return XAIOS_ERR_INVALID;
  }
  app_dir[0] = '\0';
  if (!append_text(app_dir, sizeof(app_dir), &offset, "/apps/") ||
      !append_text(app_dir, sizeof(app_dir), &offset, name) ||
      xaiboot_fs_mkdir(app_dir) != XAIOS_OK ||
      read_file_alloc(staged_manifest, XAIOS_APP_MANIFEST_MAX, &manifest_data,
                      &manifest_size) != XAIOS_OK ||
      parse_manifest((const char *)manifest_data, manifest_size, &manifest) !=
          XAIOS_OK ||
      !text_equal(name, manifest.name) ||
      read_file_alloc(staged_binary, XAIOS_XBFS_MAX_FILE_BYTES_V5, &binary_data,
                      &binary_size) != XAIOS_OK ||
      binary_size != manifest.binary_size) {
    kheap_free(manifest_data);
    kheap_free(binary_data);
    return XAIOS_ERR_INVALID;
  }
  xaios_sha256(binary_data, binary_size, binary_hash);
  if (!bytes_equal(binary_hash, manifest.binary_hash, sizeof(binary_hash))) {
    kheap_free(manifest_data);
    kheap_free(binary_data);
    return XAIOS_ERR_INVALID;
  }

  /* A valid old pair becomes the one-step rollback version. */
  xaios_app_image_t old;
  bytes_zero(&old, sizeof(old));
  if (load_version(name, "current", &old) == XAIOS_OK) {
    app_store_release(&old);
    if (copy_if_present(current_binary, previous_binary) != XAIOS_OK ||
        copy_if_present(current_manifest, previous_manifest) != XAIOS_OK) {
      kheap_free(manifest_data);
      kheap_free(binary_data);
      return XAIOS_ERR_IO;
    }
  }

  /* The manifest is written last and is therefore the activation marker. */
  if (xaiboot_fs_write(current_binary, binary_data, binary_size) != XAIOS_OK ||
      xaiboot_fs_write(current_manifest, manifest_data, manifest_size) !=
      XAIOS_OK) {
    kheap_free(manifest_data);
    kheap_free(binary_data);
    return XAIOS_ERR_IO;
  }
  (void)xaiboot_fs_delete(staged_binary);
  (void)xaiboot_fs_delete(staged_manifest);
  kheap_free(manifest_data);
  kheap_free(binary_data);
  klog("app-store: activated name=%s version=%s bytes=%lu\n", name,
       manifest.version, manifest.binary_size);
  return XAIOS_OK;
}

xaios_status_t app_store_remove(const char *name) {
  char path[APP_PATH_MAX];
  uint64_t offset = 0U;
  if (!app_name_valid(name) ||
      !append_text(path, sizeof(path), &offset, "/apps/") ||
      !append_text(path, sizeof(path), &offset, name)) {
    return XAIOS_ERR_INVALID;
  }
  return xaiboot_fs_delete_tree(path);
}

xaios_status_t app_store_rollback(const char *name) {
  char current_manifest[APP_PATH_MAX];
  char current_binary[APP_PATH_MAX];
  char previous_manifest[APP_PATH_MAX];
  char previous_binary[APP_PATH_MAX];
  xaios_app_image_t previous;
  void *manifest = 0;
  void *binary = 0;
  uint64_t manifest_size = 0U;
  uint64_t binary_size = 0U;
  bytes_zero(&previous, sizeof(previous));
  if (!app_path(current_manifest, sizeof(current_manifest), name,
                "current.manifest", 0) ||
      !app_path(current_binary, sizeof(current_binary), name, "current.elf", 0) ||
      !app_path(previous_manifest, sizeof(previous_manifest), name,
                "previous.manifest", 0) ||
      !app_path(previous_binary, sizeof(previous_binary), name,
                "previous.elf", 0) ||
      load_version(name, "previous", &previous) != XAIOS_OK ||
      read_file_alloc(previous_manifest, XAIOS_APP_MANIFEST_MAX, &manifest,
                      &manifest_size) != XAIOS_OK ||
      read_file_alloc(previous_binary, XAIOS_XBFS_MAX_FILE_BYTES_V5, &binary,
                      &binary_size) != XAIOS_OK) {
    app_store_release(&previous);
    kheap_free(manifest);
    kheap_free(binary);
    return XAIOS_ERR_INVALID;
  }
  app_store_release(&previous);
  if (xaiboot_fs_write(current_binary, binary, binary_size) != XAIOS_OK ||
      xaiboot_fs_write(current_manifest, manifest, manifest_size) != XAIOS_OK) {
    kheap_free(manifest);
    kheap_free(binary);
    return XAIOS_ERR_IO;
  }
  kheap_free(manifest);
  kheap_free(binary);
  return XAIOS_OK;
}

xaios_status_t app_store_activate_catalog(void) {
  static const char staged_path[] = "/update/xapt/catalog";
  static const char active_path[] = "/state/xapt/catalog";
  static const char staged_trust_path[] = "/update/xapt/trust";
  static const char active_trust_path[] = "/state/xapt/trust";
  static const char previous_path[] = "/state/xapt/catalog.previous";
  static const char previous_trust_path[] = "/state/xapt/trust.previous";
  void *data = 0;
  uint64_t size = 0U;
  void *active = 0;
  uint64_t active_size = 0U;
  uint32_t generation = 0U;
  uint32_t active_generation = 0U;
  void *trust_data = 0;
  uint64_t trust_size = 0U;
  void *active_trust_data = 0;
  uint64_t active_trust_size = 0U;
  app_trust_state_t current_trust;
  app_trust_state_t candidate_trust;
  uint8_t original_key[APP_PUBLIC_KEY_BYTES];
  default_trust_state(&current_trust);
  if (read_file_alloc(active_trust_path, APP_TRUST_CHAIN_MAX,
                      &active_trust_data, &active_trust_size) == XAIOS_OK &&
      validate_trust_chain((const char *)active_trust_data, active_trust_size,
                           &current_trust) != XAIOS_OK) {
    klog("app-store: catalog reject stage=active-trust\n");
    kheap_free(active_trust_data);
    return XAIOS_ERR_INVALID;
  }
  (void)security_set_release_key(current_trust.active_key);
  if (read_file_alloc(active_path, XAIOS_APP_CATALOG_MAX, &active,
                      &active_size) == XAIOS_OK &&
      parse_catalog_identity((const char *)active, active_size,
                             &active_generation) != XAIOS_OK) {
    klog("app-store: catalog reject stage=active-catalog\n");
    kheap_free(active);
    kheap_free(active_trust_data);
    return XAIOS_ERR_INVALID;
  }
  candidate_trust = current_trust;
  if (read_file_alloc(staged_trust_path, APP_TRUST_CHAIN_MAX, &trust_data,
                      &trust_size) == XAIOS_OK) {
    if (validate_trust_chain((const char *)trust_data, trust_size,
                             &candidate_trust) != XAIOS_OK ||
        candidate_trust.generation < current_trust.generation ||
        (candidate_trust.generation == current_trust.generation &&
         (trust_size != active_trust_size ||
          !bytes_equal((const uint8_t *)trust_data,
                       (const uint8_t *)active_trust_data, trust_size)))) {
      klog("app-store: catalog reject stage=staged-trust current=%u candidate=%u\n",
           current_trust.generation, candidate_trust.generation);
      kheap_free(active_trust_data);
      kheap_free(trust_data);
      return XAIOS_ERR_INVALID;
    }
  }
  security_get_release_key(original_key);
  (void)security_set_release_key(candidate_trust.active_key);
  if (read_file_alloc(staged_path, XAIOS_APP_CATALOG_MAX, &data, &size) !=
          XAIOS_OK ||
      parse_catalog_identity((const char *)data, size, &generation) !=
          XAIOS_OK) {
    klog("app-store: catalog reject stage=staged-catalog trust=%u\n",
         candidate_trust.generation);
    (void)security_set_release_key(original_key);
    kheap_free(active_trust_data);
    kheap_free(active);
    kheap_free(trust_data);
    kheap_free(data);
    return XAIOS_ERR_INVALID;
  }
  if (active != 0) {
    if (generation < active_generation ||
        (generation == active_generation &&
         (size != active_size ||
          !bytes_equal((const uint8_t *)data, (const uint8_t *)active,
                       size)))) {
      klog("app-store: catalog reject stage=catalog-replay active=%u staged=%u\n",
           active_generation, generation);
      kheap_free(active);
      (void)security_set_release_key(original_key);
      kheap_free(active_trust_data);
      kheap_free(trust_data);
      kheap_free(data);
      return XAIOS_ERR_INVALID;
    }
    if (generation == active_generation) {
      kheap_free(active);
      kheap_free(active_trust_data);
      kheap_free(trust_data);
      kheap_free(data);
      (void)xaiboot_fs_delete(staged_path);
      (void)xaiboot_fs_delete(staged_trust_path);
      return XAIOS_OK;
    }
  }
  if ((active_trust_data != 0 &&
       xaiboot_fs_write(previous_trust_path, active_trust_data,
                        active_trust_size) != XAIOS_OK) ||
      (active != 0 &&
       xaiboot_fs_write(previous_path, active, active_size) != XAIOS_OK)) {
    (void)security_set_release_key(original_key);
    kheap_free(active_trust_data);
    kheap_free(trust_data);
    kheap_free(data);
    return XAIOS_ERR_IO;
  }
  if ((trust_data != 0 &&
       xaiboot_fs_write(active_trust_path, trust_data, trust_size) !=
           XAIOS_OK) ||
      xaiboot_fs_write(active_path, data, size) != XAIOS_OK) {
    klog("app-store: catalog reject stage=write\n");
    if (active_trust_data != 0)
      (void)xaiboot_fs_write(active_trust_path, active_trust_data,
                             active_trust_size);
    else
      (void)xaiboot_fs_delete(active_trust_path);
    if (active != 0)
      (void)xaiboot_fs_write(active_path, active, active_size);
    else
      (void)xaiboot_fs_delete(active_path);
    (void)security_set_release_key(original_key);
    kheap_free(active_trust_data);
    kheap_free(trust_data);
    kheap_free(data);
    return XAIOS_ERR_IO;
  }
  kheap_free(active_trust_data);
  kheap_free(active);
  kheap_free(trust_data);
  kheap_free(data);
  (void)xaiboot_fs_delete(staged_path);
  (void)xaiboot_fs_delete(staged_trust_path);
  klog("app-store: activated catalog generation=%u trust_generation=%u\n",
       generation, candidate_trust.generation);
  return XAIOS_OK;
}
