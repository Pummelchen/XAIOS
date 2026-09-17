#include <xaios/app_store.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/xaiboot_fs.h>
#include <xaios/security.h>
#include <xaios/sha256.h>

#include "app_store_internal.h"

static xaios_status_t copy_if_present(const char *source, const char *target);

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
  if (!app_store_append_text(manifest_leaf, sizeof(manifest_leaf), &offset,
                             leaf_prefix) ||
      !app_store_append_text(manifest_leaf, sizeof(manifest_leaf), &offset,
                             ".manifest")) {
    return XAIOS_ERR_INVALID;
  }
  offset = 0U;
  if (!app_store_append_text(binary_leaf, sizeof(binary_leaf), &offset,
                             leaf_prefix) ||
      !app_store_append_text(binary_leaf, sizeof(binary_leaf), &offset,
                             ".elf") ||
      !app_store_app_path(manifest_path, sizeof(manifest_path), name,
                          manifest_leaf, 0) ||
      !app_store_app_path(binary_path, sizeof(binary_path), name, binary_leaf,
                          0) ||
      app_store_read_file_alloc(manifest_path, XAIOS_APP_MANIFEST_MAX,
                                &manifest_data, &manifest_size) != XAIOS_OK ||
      app_store_parse_manifest((const char *)manifest_data, manifest_size,
                               &manifest) != XAIOS_OK ||
      !app_store_text_equal(name, manifest.name) ||
      app_store_read_file_alloc(binary_path, XAIOS_XBFS_MAX_FILE_BYTES_V5,
                                &binary_data, &binary_size) != XAIOS_OK ||
      binary_size != manifest.binary_size) {
    kheap_free(manifest_data);
    kheap_free(binary_data);
    return XAIOS_ERR_INVALID;
  }
  xaios_sha256(binary_data, binary_size, digest);
  if (!app_store_bytes_equal(digest, manifest.binary_hash, sizeof(digest))) {
    kheap_free(manifest_data);
    kheap_free(binary_data);
    return XAIOS_ERR_INVALID;
  }
  app_store_bytes_zero(image, sizeof(*image));
  app_store_bytes_copy(image->path, binary_path,
                       app_store_text_length(binary_path) + 1U);
  app_store_bytes_copy(image->version, manifest.version,
                       app_store_text_length(manifest.version) + 1U);
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
  if (app_store_load_trust_and_catalog(trust_path, catalog_path, &trust) !=
      XAIOS_OK) {
    klog("app-store: interrupted trust/catalog activation detected\n");
    if (copy_if_present(previous_trust_path, trust_path) != XAIOS_OK)
      (void)xaiboot_fs_delete(trust_path);
    if (copy_if_present(previous_catalog_path, catalog_path) != XAIOS_OK)
      (void)xaiboot_fs_delete(catalog_path);
    if (app_store_load_trust_and_catalog(trust_path, catalog_path, &trust) !=
        XAIOS_OK) {
      (void)xaiboot_fs_delete(trust_path);
      (void)xaiboot_fs_delete(catalog_path);
      app_store_default_trust_state(&trust);
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
  if (image == 0 || !app_store_name_valid(name)) return XAIOS_ERR_INVALID;
  if (load_version(name, "current", image) == XAIOS_OK) return XAIOS_OK;
  return load_version(name, "previous", image);
}

void app_store_release(xaios_app_image_t *image) {
  if (image == 0) return;
  kheap_free(image->file.base);
  app_store_bytes_zero(image, sizeof(*image));
}

static xaios_status_t copy_if_present(const char *source, const char *target) {
  void *data = 0;
  uint64_t size = 0U;
  xaios_status_t status =
      app_store_read_file_alloc(source, XAIOS_XBFS_MAX_FILE_BYTES_V5, &data,
                                &size);
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
  if (!app_store_app_path(staged_manifest, sizeof(staged_manifest), name,
                          ".manifest", 1) ||
      !app_store_app_path(staged_binary, sizeof(staged_binary), name, ".elf",
                          1) ||
      !app_store_app_path(current_manifest, sizeof(current_manifest), name,
                          "current.manifest", 0) ||
      !app_store_app_path(current_binary, sizeof(current_binary), name,
                          "current.elf", 0) ||
      !app_store_app_path(previous_manifest, sizeof(previous_manifest), name,
                          "previous.manifest", 0) ||
      !app_store_app_path(previous_binary, sizeof(previous_binary), name,
                          "previous.elf", 0)) {
    return XAIOS_ERR_INVALID;
  }
  app_dir[0] = '\0';
  if (!app_store_append_text(app_dir, sizeof(app_dir), &offset, "/apps/") ||
      !app_store_append_text(app_dir, sizeof(app_dir), &offset, name) ||
      xaiboot_fs_mkdir(app_dir) != XAIOS_OK ||
      app_store_read_file_alloc(staged_manifest, XAIOS_APP_MANIFEST_MAX,
                                &manifest_data, &manifest_size) != XAIOS_OK ||
      app_store_parse_manifest((const char *)manifest_data, manifest_size,
                               &manifest) != XAIOS_OK ||
      !app_store_text_equal(name, manifest.name) ||
      app_store_read_file_alloc(staged_binary, XAIOS_XBFS_MAX_FILE_BYTES_V5,
                                &binary_data, &binary_size) != XAIOS_OK ||
      binary_size != manifest.binary_size) {
    kheap_free(manifest_data);
    kheap_free(binary_data);
    return XAIOS_ERR_INVALID;
  }
  xaios_sha256(binary_data, binary_size, binary_hash);
  if (!app_store_bytes_equal(binary_hash, manifest.binary_hash,
                             sizeof(binary_hash))) {
    kheap_free(manifest_data);
    kheap_free(binary_data);
    return XAIOS_ERR_INVALID;
  }

  /* A valid old pair becomes the one-step rollback version. */
  xaios_app_image_t old;
  app_store_bytes_zero(&old, sizeof(old));
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
  if (!app_store_name_valid(name) ||
      !app_store_append_text(path, sizeof(path), &offset, "/apps/") ||
      !app_store_append_text(path, sizeof(path), &offset, name)) {
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
  app_store_bytes_zero(&previous, sizeof(previous));
  if (!app_store_app_path(current_manifest, sizeof(current_manifest), name,
                          "current.manifest", 0) ||
      !app_store_app_path(current_binary, sizeof(current_binary), name,
                          "current.elf", 0) ||
      !app_store_app_path(previous_manifest, sizeof(previous_manifest), name,
                          "previous.manifest", 0) ||
      !app_store_app_path(previous_binary, sizeof(previous_binary), name,
                          "previous.elf", 0) ||
      load_version(name, "previous", &previous) != XAIOS_OK ||
      app_store_read_file_alloc(previous_manifest, XAIOS_APP_MANIFEST_MAX,
                                &manifest, &manifest_size) != XAIOS_OK ||
      app_store_read_file_alloc(previous_binary, XAIOS_XBFS_MAX_FILE_BYTES_V5,
                                &binary, &binary_size) != XAIOS_OK) {
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
  app_store_default_trust_state(&current_trust);
  if (app_store_read_file_alloc(active_trust_path, APP_TRUST_CHAIN_MAX,
                                &active_trust_data,
                                &active_trust_size) == XAIOS_OK &&
      app_store_validate_trust_chain((const char *)active_trust_data,
                                     active_trust_size,
                                     &current_trust) != XAIOS_OK) {
    klog("app-store: catalog reject stage=active-trust\n");
    kheap_free(active_trust_data);
    return XAIOS_ERR_INVALID;
  }
  (void)security_set_release_key(current_trust.active_key);
  if (app_store_read_file_alloc(active_path, XAIOS_APP_CATALOG_MAX, &active,
                                &active_size) == XAIOS_OK &&
      app_store_parse_catalog_identity((const char *)active, active_size,
                                       &active_generation) != XAIOS_OK) {
    klog("app-store: catalog reject stage=active-catalog\n");
    kheap_free(active);
    kheap_free(active_trust_data);
    return XAIOS_ERR_INVALID;
  }
  candidate_trust = current_trust;
  if (app_store_read_file_alloc(staged_trust_path, APP_TRUST_CHAIN_MAX,
                                &trust_data, &trust_size) == XAIOS_OK) {
    if (app_store_validate_trust_chain((const char *)trust_data, trust_size,
                                       &candidate_trust) != XAIOS_OK ||
        candidate_trust.generation < current_trust.generation ||
        (candidate_trust.generation == current_trust.generation &&
         (trust_size != active_trust_size ||
          !app_store_bytes_equal((const uint8_t *)trust_data,
                                 (const uint8_t *)active_trust_data,
                                 trust_size)))) {
      klog("app-store: catalog reject stage=staged-trust current=%u candidate=%u\n",
           current_trust.generation, candidate_trust.generation);
      kheap_free(active_trust_data);
      kheap_free(trust_data);
      return XAIOS_ERR_INVALID;
    }
  }
  security_get_release_key(original_key);
  (void)security_set_release_key(candidate_trust.active_key);
  if (app_store_read_file_alloc(staged_path, XAIOS_APP_CATALOG_MAX, &data,
                                &size) != XAIOS_OK ||
      app_store_parse_catalog_identity((const char *)data, size,
                                       &generation) != XAIOS_OK) {
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
          !app_store_bytes_equal((const uint8_t *)data,
                                 (const uint8_t *)active, size)))) {
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
