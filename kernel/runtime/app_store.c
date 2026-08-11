#include <xaios/app_store.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/mutable_fs.h>
#include <xaios/security.h>
#include <xaios/sha256.h>

#define APP_PATH_MAX 96U
#define APP_SIGNATURE_HEX_BYTES 128U

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

static int version_at_least(const char *current, const char *minimum) {
  uint32_t current_parts[3];
  uint32_t minimum_parts[3];
  if (!parse_semver(current, current_parts) ||
      !parse_semver(minimum, minimum_parts)) {
    return 0;
  }
  for (uint32_t i = 0U; i < 3U; ++i) {
    if (current_parts[i] != minimum_parts[i])
      return current_parts[i] > minimum_parts[i];
  }
  return 1;
}

static int architecture_matches(const char *architecture) {
#if defined(__aarch64__)
  return text_equal(architecture, "aarch64");
#elif defined(__x86_64__)
  return text_equal(architecture, "x86_64");
#else
  (void)architecture;
  return 0;
#endif
}

static xaios_status_t verify_signed_document(const char *data, uint64_t size,
                                             const char *prefix,
                                             uint64_t maximum,
                                             uint64_t *signed_size) {
  static const char key_line[] =
      "key=" XAIOS_RELEASE_PUBLIC_KEY_HEX "\n";
  static const char signature_key[] = "signature=";
  uint64_t prefix_length = text_length(prefix);
  uint64_t key_length = sizeof(key_line) - 1U;
  uint64_t signature_offset = UINT64_MAX;
  uint8_t signature[64];
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
  for (uint64_t i = 0U; i < key_length; ++i) {
    if (data[signature_offset - key_length + i] != key_line[i])
      return XAIOS_ERR_INVALID;
  }
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
      !version_at_least(XAIOS_APP_OS_VERSION, manifest->minimum_os) ||
      manifest->minimum_abi > XAIOS_APP_KERNEL_ABI_VERSION ||
      manifest->binary_size == 0U ||
      manifest->binary_size > XAIOS_MFS_MAX_FILE_BYTES_V4) {
    return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
}

static xaios_status_t read_file_alloc(const char *path, uint64_t maximum,
                                      void **data, uint64_t *size) {
  xaios_mfs_stat_t stat;
  if (mutable_fs_stat(path, &stat) != XAIOS_OK || stat.type != 2U ||
      stat.size == 0U || stat.size > maximum) {
    return XAIOS_ERR_INVALID;
  }
  void *buffer = kheap_alloc(stat.size + 1U, 16U);
  if (buffer == 0) return XAIOS_ERR_NO_MEMORY;
  uint64_t read_size = 0U;
  if (mutable_fs_read(path, buffer, stat.size, &read_size) != XAIOS_OK ||
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
      read_file_alloc(binary_path, XAIOS_MFS_MAX_FILE_BYTES_V4, &binary_data,
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
  (void)mutable_fs_mkdir("/apps");
  (void)mutable_fs_mkdir("/update");
  (void)mutable_fs_mkdir("/update/xapt");
  (void)mutable_fs_mkdir("/state/xapt");
  klog("app-store: initialized format=%u os=%s abi=%u\n",
       XAIOS_APP_FORMAT_VERSION, XAIOS_APP_OS_VERSION,
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
  xaios_status_t status = read_file_alloc(source, XAIOS_MFS_MAX_FILE_BYTES_V4,
                                          &data, &size);
  if (status != XAIOS_OK) return status;
  status = mutable_fs_write(target, data, size);
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
      mutable_fs_mkdir(app_dir) != XAIOS_OK ||
      read_file_alloc(staged_manifest, XAIOS_APP_MANIFEST_MAX, &manifest_data,
                      &manifest_size) != XAIOS_OK ||
      parse_manifest((const char *)manifest_data, manifest_size, &manifest) !=
          XAIOS_OK ||
      !text_equal(name, manifest.name) ||
      read_file_alloc(staged_binary, XAIOS_MFS_MAX_FILE_BYTES_V4, &binary_data,
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
  if (mutable_fs_write(current_binary, binary_data, binary_size) != XAIOS_OK ||
      mutable_fs_write(current_manifest, manifest_data, manifest_size) !=
      XAIOS_OK) {
    kheap_free(manifest_data);
    kheap_free(binary_data);
    return XAIOS_ERR_IO;
  }
  (void)mutable_fs_delete(staged_binary);
  (void)mutable_fs_delete(staged_manifest);
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
  return mutable_fs_delete_tree(path);
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
      read_file_alloc(previous_binary, XAIOS_MFS_MAX_FILE_BYTES_V4, &binary,
                      &binary_size) != XAIOS_OK) {
    app_store_release(&previous);
    kheap_free(manifest);
    kheap_free(binary);
    return XAIOS_ERR_INVALID;
  }
  app_store_release(&previous);
  if (mutable_fs_write(current_binary, binary, binary_size) != XAIOS_OK ||
      mutable_fs_write(current_manifest, manifest, manifest_size) != XAIOS_OK) {
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
  void *data = 0;
  uint64_t size = 0U;
  void *active = 0;
  uint64_t active_size = 0U;
  uint32_t generation = 0U;
  uint32_t active_generation = 0U;
  if (read_file_alloc(staged_path, XAIOS_APP_CATALOG_MAX, &data, &size) !=
          XAIOS_OK ||
      parse_catalog_identity((const char *)data, size, &generation) !=
          XAIOS_OK) {
    kheap_free(data);
    return XAIOS_ERR_INVALID;
  }
  if (read_file_alloc(active_path, XAIOS_APP_CATALOG_MAX, &active,
                      &active_size) == XAIOS_OK &&
      parse_catalog_identity((const char *)active, active_size,
                             &active_generation) == XAIOS_OK) {
    if (generation < active_generation ||
        (generation == active_generation &&
         (size != active_size ||
          !bytes_equal((const uint8_t *)data, (const uint8_t *)active,
                       size)))) {
      kheap_free(active);
      kheap_free(data);
      return XAIOS_ERR_INVALID;
    }
    if (generation == active_generation) {
      kheap_free(active);
      kheap_free(data);
      (void)mutable_fs_delete(staged_path);
      return XAIOS_OK;
    }
  }
  kheap_free(active);
  if (mutable_fs_write(active_path, data, size) != XAIOS_OK) {
    kheap_free(data);
    return XAIOS_ERR_IO;
  }
  kheap_free(data);
  (void)mutable_fs_delete(staged_path);
  klog("app-store: activated catalog generation=%u\n", generation);
  return XAIOS_OK;
}
