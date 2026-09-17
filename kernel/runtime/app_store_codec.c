/* The app store's signed-text codec: byte and string helpers, the
 * release-signed document reader, the package manifest and the catalog
 * identity.
 *
 * kernel/runtime/app_store.c keeps the store's public entry points and the
 * on-disk activation order; this file only reads and validates the bytes those
 * entry points hand it, plus the one bounded file read they share. Declared in
 * app_store_internal.h. */
#include "app_store_internal.h"

#include <xaios/kheap.h>
#include <xaios/security.h>
#include <xaios/xaiboot_fs.h>

void app_store_bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0U; i < size; ++i) bytes[i] = 0U;
}

void app_store_bytes_copy(void *dst, const void *src, uint64_t size) {
  uint8_t *output = (uint8_t *)dst;
  const uint8_t *input = (const uint8_t *)src;
  for (uint64_t i = 0U; i < size; ++i) output[i] = input[i];
}

uint64_t app_store_text_length(const char *text) {
  uint64_t length = 0U;
  if (text == 0) return 0U;
  while (text[length] != '\0') ++length;
  return length;
}

int app_store_text_equal(const char *left, const char *right) {
  uint64_t i = 0U;
  if (left == 0 || right == 0) return 0;
  while (left[i] != '\0' && left[i] == right[i]) ++i;
  return left[i] == right[i];
}

int app_store_bytes_equal(const uint8_t *left, const uint8_t *right,
                          uint64_t size) {
  uint8_t difference = 0U;
  for (uint64_t i = 0U; i < size; ++i) difference |= left[i] ^ right[i];
  return difference == 0U;
}

int app_store_name_valid(const char *name) {
  uint64_t length = app_store_text_length(name);
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

int app_store_append_text(char *path, uint64_t capacity, uint64_t *offset,
                          const char *text) {
  uint64_t i = 0U;
  while (text[i] != '\0') {
    if (*offset + 1U >= capacity) return 0;
    path[(*offset)++] = text[i++];
  }
  path[*offset] = '\0';
  return 1;
}

int app_store_app_path(char *path, uint64_t capacity, const char *name,
                       const char *leaf, int staging) {
  uint64_t offset = 0U;
  path[0] = '\0';
  return app_store_name_valid(name) &&
         app_store_append_text(path, capacity, &offset,
                               staging ? "/update/xapt/" : "/apps/") &&
         app_store_append_text(path, capacity, &offset, name) &&
         (staging || app_store_append_text(path, capacity, &offset, "/")) &&
         app_store_append_text(path, capacity, &offset, leaf);
}

static int hex_digit(char ch) {
  if (ch >= '0' && ch <= '9') return ch - '0';
  if (ch >= 'a' && ch <= 'f') return 10 + ch - 'a';
  if (ch >= 'A' && ch <= 'F') return 10 + ch - 'A';
  return -1;
}

int app_store_parse_hex(const char *text, uint8_t *output, uint32_t size) {
  for (uint32_t i = 0U; i < size; ++i) {
    int high = hex_digit(text[i * 2U]);
    int low = hex_digit(text[i * 2U + 1U]);
    if (high < 0 || low < 0) return 0;
    output[i] = (uint8_t)((high << 4) | low);
  }
  return 1;
}

int app_store_parse_u64(const char *text, uint64_t length, uint64_t *value) {
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
  uint64_t key_length = app_store_text_length(key);
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
  return app_store_text_equal(architecture, "aarch64");
#elif defined(__x86_64__)
  return app_store_text_equal(architecture, "x86_64");
#elif defined(__riscv)
  /* This returned zero here, so a RISC-V machine refused every package and
     every catalog -- including ones published for it. The refusal is the
     right shape and the list it consulted was two architectures old; xapt's
     own client has reported "riscv64" for its architecture since this port
     gained userspace. */
  return app_store_text_equal(architecture, "riscv64");
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
  uint64_t prefix_length = app_store_text_length(prefix);
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
      !app_store_parse_hex(data + key_offset + sizeof(key_prefix) - 1U,
                           public_key, sizeof(public_key)) ||
      !security_release_key_matches(public_key))
    return XAIOS_ERR_INVALID;
  if (!app_store_parse_hex(data + signature_offset + sizeof(signature_key) - 1U,
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

xaios_status_t app_store_parse_catalog_identity(const char *data, uint64_t size,
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
      !app_store_parse_u64(value, value_length, &number) || number == 0U ||
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

xaios_status_t app_store_parse_manifest(const char *data, uint64_t size,
                                        xaios_app_manifest_t *manifest) {
  static const char prefix[] = "XAIOS-APP-V1\n";
  const char *value;
  uint64_t value_length;
  uint64_t cursor = sizeof(prefix) - 1U;
  uint64_t number;
  uint64_t signed_size;
  app_store_bytes_zero(manifest, sizeof(*manifest));
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
      !app_store_parse_u64(value, value_length, &number) ||
      number > UINT32_MAX) {
    return XAIOS_ERR_INVALID;
  }
  manifest->minimum_abi = (uint32_t)number;
  if (!next_field(data, signed_size, &cursor, "capabilities", &value,
                  &value_length) ||
      !app_store_parse_u64(value, value_length, &manifest->capabilities) ||
      !next_field(data, signed_size, &cursor, "size", &value,
                  &value_length) ||
      !app_store_parse_u64(value, value_length, &manifest->binary_size) ||
      !next_field(data, signed_size, &cursor, "sha256", &value,
                  &value_length) ||
      value_length != 64U ||
      !app_store_parse_hex(value, manifest->binary_hash,
                           sizeof(manifest->binary_hash)) ||
      !next_field(data, signed_size, &cursor, "key", &value,
                  &value_length) ||
      value_length != sizeof(XAIOS_RELEASE_PUBLIC_KEY_HEX) - 1U ||
      cursor != signed_size) {
    return XAIOS_ERR_INVALID;
  }
  if (!app_store_name_valid(manifest->name) ||
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

xaios_status_t app_store_read_file_alloc(const char *path, uint64_t maximum,
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
