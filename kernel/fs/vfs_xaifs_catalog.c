/* The catalog and the staging lifecycle of the model VFS.
 *
 * Split out of vfs_xaifs.c so no source file exceeds 500 lines. What moves
 * here is the catalog lookup the mount and stat paths share, the
 * register/cleanup/verify/activate staging entry points the control protocol
 * calls, and the signed-active/staging self-test. The mount, the read/write
 * path and the block/engine glue stay in vfs_xaifs.c and vfs_xaifs_io.c; the
 * files share the model context layout and the exported helpers through
 * vfs_xaifs_internal.h.
 *
 * The shared model context does not move, and is reached through
 * vfs_xaifs_model(). The alias below keeps the moved code reading exactly as
 * it did against the variable, as vfs_xaifs_trim.c and vfs_xaifs_scrub.c
 * already do.
 */

#include "vfs_xaifs_internal.h"

#include <xaios/klog.h>

#include <string.h>

#define g_model_vfs (*vfs_xaifs_model())

/* Used by cleanup below, defined further down in this file. */
static xaios_status_t staging_path_from_id(const char *package_id,
                                           char path[82]);

static int hex_value(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

static int parse_package_path(const char *path, uint32_t *required_state,
                              uint8_t package_id[32]) {
  const char *name = 0;
  if (strncmp(path, "/.staging/", 10U) == 0) {
    *required_state = XAIOS_XAI_FS_PACKAGE_STAGING;
    name = path + 10U;
  } else if (path[0] == '/') {
    *required_state = XAIOS_XAI_FS_PACKAGE_ACTIVE;
    name = path + 1U;
  } else {
    return 0;
  }
  for (uint32_t index = 0U; index < MODEL_PACKAGE_NAME_LENGTH; ++index) {
    int high = hex_value(name[index]);
    int low = index + 1U < MODEL_PACKAGE_NAME_LENGTH
                  ? hex_value(name[index + 1U])
                  : -1;
    if ((index & 1U) != 0U) continue;
    if (high < 0 || low < 0) return 0;
    package_id[index / 2U] = (uint8_t)((high << 4U) | low);
  }
  return name[MODEL_PACKAGE_NAME_LENGTH] == '\0';
}

static int package_id_equal(const uint8_t left[32], const uint8_t right[32]) {
  uint8_t difference = 0U;
  for (uint32_t index = 0U; index < 32U; ++index) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0U;
}

xaios_status_t vfs_xaifs_find_package(model_vfs_context_t *model,
                                      const char *path, uint64_t *index,
                                      xaios_xai_fs_package_t *package) {
  uint32_t required_state = 0U;
  uint8_t package_id[32];
  if (!parse_package_path(path, &required_state, package_id)) {
    return XAIOS_ERR_NOT_FOUND;
  }
  for (uint64_t current = 0U; current < model->volume.package_count;
       ++current) {
    xaios_engine_status_t status =
        xaios_xai_fs_read_package(&model->volume, current, package);
    if (status != XAIOS_ENGINE_OK) return map_engine_status(status);
    if (package->state == required_state &&
        package_id_equal(package->package_id, package_id)) {
      *index = current;
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t vfs_xaifs_register_staging(
    const xaios_model_registration_t *registration, uint64_t *generation) {
  if (registration == 0 || generation == 0 || g_model_vfs.mounted == 0U) {
    return XAIOS_ERR_INVALID;
  }
  xaios_spin_lock(&g_model_vfs.lock);
  if (g_model_vfs.read_only != 0U || catalog_maintenance_active()) {
    xaios_spin_unlock(&g_model_vfs.lock);
    return g_model_vfs.read_only != 0U ? XAIOS_ERR_UNSUPPORTED
                                       : XAIOS_ERR_BUSY;
  }
  xaios_xai_fs_package_t package_template;
  memset(&package_template, 0, sizeof(package_template));
  memcpy(package_template.model_uuid, registration->model_uuid, 16U);
  memcpy(package_template.package_id, registration->package_id, 32U);
  memcpy(package_template.signer_public_key, registration->signer_public_key,
         32U);
  memcpy(package_template.signature, registration->signature, 64U);
  memcpy(package_template.source_revision, registration->source_revision, 32U);
  package_template.logical_size = registration->logical_size;
  package_template.chunk_size = g_model_vfs.volume.chunk_size;
  memcpy(package_template.architecture_id, registration->architecture_id,
         sizeof(package_template.architecture_id));
  memcpy(package_template.target_id, registration->target_id,
         sizeof(package_template.target_id));
  xaios_xai_fs_writer_t writer = {
      &g_model_vfs, vfs_xaifs_write_at, vfs_xaifs_flush};
  xaios_xai_fs_package_t registered;
  xaios_status_t status = map_engine_status(xaios_xai_fs_register_staging(
      &g_model_vfs.volume, &package_template, &writer, g_model_vfs.scratch,
      sizeof(g_model_vfs.scratch), &registered));
  if (status == XAIOS_OK) *generation = g_model_vfs.volume.generation;
  xaios_spin_unlock(&g_model_vfs.lock);
  if (status == XAIOS_OK) {
    klog("xaifs: registered dynamic staging package record=%lu bytes=%lu generation=%lu\n",
         registered.record_id, registered.logical_size, *generation);
  }
  return status;
}

xaios_status_t vfs_xaifs_cleanup_staging(const char *package_id,
                                          uint64_t *generation,
                                          uint64_t *reclaimed_bytes) {
  char path[82];
  if (generation == 0 || reclaimed_bytes == 0 ||
      g_model_vfs.mounted == 0U ||
      staging_path_from_id(package_id, path) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  xaios_spin_lock(&g_model_vfs.lock);
  if (g_model_vfs.read_only != 0U || catalog_maintenance_active()) {
    xaios_spin_unlock(&g_model_vfs.lock);
    return g_model_vfs.read_only != 0U ? XAIOS_ERR_UNSUPPORTED
                                       : XAIOS_ERR_BUSY;
  }
  for (uint32_t index = 0U; index < MODEL_VFS_MAX_HANDLES; ++index) {
    if (g_model_vfs.handles[index].active != 0U) {
      xaios_spin_unlock(&g_model_vfs.lock);
      return XAIOS_ERR_BUSY;
    }
  }
  uint64_t package_index = 0U;
  xaios_xai_fs_package_t package;
  xaios_status_t status =
      vfs_xaifs_find_package(&g_model_vfs, path, &package_index, &package);
  if (status == XAIOS_OK) {
    xaios_xai_fs_writer_t writer = {
        &g_model_vfs, vfs_xaifs_write_at, vfs_xaifs_flush};
    status = map_engine_status(xaios_xai_fs_remove_staging(
        &g_model_vfs.volume, &package, &writer, g_model_vfs.scratch,
        sizeof(g_model_vfs.scratch), reclaimed_bytes));
  }
  if (status == XAIOS_OK) *generation = g_model_vfs.volume.generation;
  xaios_spin_unlock(&g_model_vfs.lock);
  if (status == XAIOS_OK) {
    klog("xaifs: cleaned staging package=%s reclaimed=%lu generation=%lu\n",
         package_id, *reclaimed_bytes, *generation);
  }
  return status;
}

static xaios_status_t staging_path_from_id(const char *package_id,
                                           char path[82]) {
  if (package_id == 0) return XAIOS_ERR_INVALID;
  memcpy(path, "/.staging/", 10U);
  for (uint32_t index = 0U; index < MODEL_PACKAGE_NAME_LENGTH; ++index) {
    if (hex_value(package_id[index]) < 0) return XAIOS_ERR_INVALID;
    path[10U + index] = package_id[index];
  }
  if (package_id[MODEL_PACKAGE_NAME_LENGTH] != '\0') {
    return XAIOS_ERR_INVALID;
  }
  path[74] = '\0';
  return XAIOS_OK;
}

xaios_status_t vfs_xaifs_verify_staging(const char *package_id,
                                         uint64_t *generation) {
  char path[82];
  if (generation == 0 || g_model_vfs.mounted == 0U ||
      staging_path_from_id(package_id, path) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  xaios_spin_lock(&g_model_vfs.lock);
  if (catalog_maintenance_active()) {
    xaios_spin_unlock(&g_model_vfs.lock);
    return XAIOS_ERR_BUSY;
  }
  uint64_t package_index = 0U;
  xaios_xai_fs_package_t package;
  xaios_status_t status =
      vfs_xaifs_find_package(&g_model_vfs, path, &package_index, &package);
  uint64_t bad_offset = UINT64_MAX;
  if (status == XAIOS_OK) {
    status = map_engine_status(xaios_xai_fs_verify_package(
        &g_model_vfs.volume, &package, g_model_vfs.scratch,
        sizeof(g_model_vfs.scratch), &bad_offset));
  }
  if (status == XAIOS_OK) *generation = g_model_vfs.volume.generation;
  xaios_spin_unlock(&g_model_vfs.lock);
  if (status != XAIOS_OK) {
    klog("xaifs: verify rejected package=%s bad_offset=%lu status=%d\n",
         package_id, bad_offset, (int)status);
  }
  return status;
}

xaios_status_t vfs_xaifs_activate_staging(const char *package_id,
                                           uint64_t *generation) {
  char path[82];
  if (generation == 0 || g_model_vfs.mounted == 0U ||
      staging_path_from_id(package_id, path) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  xaios_spin_lock(&g_model_vfs.lock);
  if (catalog_maintenance_active()) {
    xaios_spin_unlock(&g_model_vfs.lock);
    return XAIOS_ERR_BUSY;
  }
  uint64_t package_index = 0U;
  xaios_xai_fs_package_t package;
  xaios_status_t status =
      vfs_xaifs_find_package(&g_model_vfs, path, &package_index, &package);
  if (status == XAIOS_OK) {
    for (uint32_t index = 0U; index < MODEL_VFS_MAX_HANDLES; ++index) {
      if (g_model_vfs.handles[index].active != 0U &&
          g_model_vfs.handles[index].writable != 0U &&
          g_model_vfs.handles[index].package_index == package_index) {
        status = XAIOS_ERR_BUSY;
        break;
      }
    }
  }
  if (status == XAIOS_OK) {
    xaios_xai_fs_writer_t writer = {
        &g_model_vfs, vfs_xaifs_write_at, vfs_xaifs_flush};
    status = map_engine_status(xaios_xai_fs_activate_staging(
        &g_model_vfs.volume, &package, &writer, g_model_vfs.scratch,
        sizeof(g_model_vfs.scratch)));
  }
  if (status == XAIOS_OK) *generation = g_model_vfs.volume.generation;
  xaios_spin_unlock(&g_model_vfs.lock);
  if (status == XAIOS_OK) {
    klog("xaifs: activated package=%s generation=%lu\n", package_id,
         *generation);
  } else {
    klog("xaifs: activation rejected package=%s status=%d\n", package_id,
         (int)status);
  }
  return status;
}

void vfs_xaifs_self_test(void) {
  char listing[128];
  uint64_t listing_size = 0U;
  if (g_model_vfs.mounted == 0U) {
    klog("xaifs: self-test skipped no volume\n");
    return;
  }
  if (vfs_list("/models", listing, sizeof(listing), &listing_size) !=
          XAIOS_OK ||
      listing_size < 9U || strncmp(listing, ".staging\n", 9U) != 0) {
    klog("xaifs: self-test failed listing\n");
    return;
  }
  if (listing_size == 9U) {
    klog("xaifs: self-test metadata passed; no active packages\n");
    return;
  }
  if (listing_size < 74U) {
    klog("xaifs: self-test failed package name\n");
    return;
  }
  char path[73];
  memcpy(path, "/models/", 8U);
  memcpy(path + 8U, listing + 9U, MODEL_PACKAGE_NAME_LENGTH);
  path[72] = '\0';
  xaios_vfs_stat_t stat;
  int64_t fd = vfs_open(path, XAIOS_VFS_OPEN_READ, UINT32_C(0x4d4f444c));
  uint8_t data[8192];
  if (fd <= 0 || vfs_stat(path, &stat) != XAIOS_OK) {
    klog("xaifs: self-test failed package open/stat\n");
    if (fd > 0) (void)vfs_close((uint32_t)fd, UINT32_C(0x4d4f444c));
    return;
  }
  uint64_t offset = stat.size > sizeof(data) ? stat.size - sizeof(data) : 0U;
  uint64_t count = stat.size < sizeof(data) ? stat.size : sizeof(data);
  if (count == 0U ||
      vfs_pread((uint32_t)fd, UINT32_C(0x4d4f444c), data, count, offset) !=
          (int64_t)count) {
    klog("xaifs: self-test failed package read\n");
    (void)vfs_close((uint32_t)fd, UINT32_C(0x4d4f444c));
    return;
  }
  if (vfs_close((uint32_t)fd, UINT32_C(0x4d4f444c)) != XAIOS_OK ||
      vfs_open(path, XAIOS_VFS_OPEN_WRITE, UINT32_C(0x4d4f444c)) !=
          XAIOS_ERR_UNSUPPORTED) {
    klog("xaifs: self-test failed active immutability policy\n");
    return;
  }

  char staging_listing[256];
  uint64_t staging_listing_size = 0U;
  if (vfs_list("/models/.staging", staging_listing,
               sizeof(staging_listing), &staging_listing_size) != XAIOS_OK ||
      staging_listing_size < MODEL_PACKAGE_NAME_LENGTH + 1U) {
    klog("xaifs: self-test failed staging listing\n");
    return;
  }
  char staging_path[82];
  memcpy(staging_path, "/models/.staging/", 17U);
  memcpy(staging_path + 17U, staging_listing, MODEL_PACKAGE_NAME_LENGTH);
  staging_path[81] = '\0';
  for (uint64_t index = 0U; index < 4096U; ++index) {
    data[index] = (uint8_t)((index * 7U + 3U) & 0xffU);
  }
  uint32_t staging_ready = 0U;
  int64_t staging_read = vfs_open(staging_path, XAIOS_VFS_OPEN_READ,
                                  UINT32_C(0x4d4f444c));
  if (staging_read > 0) {
    uint8_t existing[4096];
    int64_t existing_length =
        vfs_pread((uint32_t)staging_read, UINT32_C(0x4d4f444c), existing,
                  sizeof(existing), 0U);
    if (existing_length == (int64_t)sizeof(existing)) {
      staging_ready = 1U;
      for (uint64_t index = 0U; index < sizeof(existing); ++index) {
        if (existing[index] != (uint8_t)((index * 7U + 3U) & 0xffU)) {
          staging_ready = 0U;
          break;
        }
      }
    }
    (void)vfs_close((uint32_t)staging_read, UINT32_C(0x4d4f444c));
  }
  if (staging_ready == 0U) {
    fd = vfs_open(staging_path,
                  XAIOS_VFS_OPEN_WRITE | XAIOS_VFS_OPEN_CREATE |
                      XAIOS_VFS_OPEN_TRUNCATE,
                  UINT32_C(0x4d4f444c));
    if (fd <= 0) {
      klog("xaifs: self-test failed staging open status=%d\n", (int)fd);
      return;
    }
    int64_t written = vfs_pwrite((uint32_t)fd, UINT32_C(0x4d4f444c),
                                 data, 4096U, 0U);
    if (written != 4096) {
      klog("xaifs: self-test failed staging write status=%d\n",
           (int)written);
      (void)vfs_close((uint32_t)fd, UINT32_C(0x4d4f444c));
      return;
    }
    xaios_status_t sync_status =
        vfs_fsync((uint32_t)fd, UINT32_C(0x4d4f444c));
    if (sync_status != XAIOS_OK) {
      klog("xaifs: self-test failed staging fsync status=%d\n",
           (int)sync_status);
      (void)vfs_close((uint32_t)fd, UINT32_C(0x4d4f444c));
      return;
    }
    xaios_status_t close_status =
        vfs_close((uint32_t)fd, UINT32_C(0x4d4f444c));
    if (close_status != XAIOS_OK) {
      klog("xaifs: self-test failed staging close status=%d\n",
           (int)close_status);
      return;
    }
  }
  memset(data, 0, 4096U);
  fd = vfs_open(staging_path, XAIOS_VFS_OPEN_READ,
                UINT32_C(0x4d4f444c));
  if (fd <= 0 ||
      vfs_pread((uint32_t)fd, UINT32_C(0x4d4f444c), data, 4096U, 0U) !=
          4096 ||
      vfs_close((uint32_t)fd, UINT32_C(0x4d4f444c)) != XAIOS_OK) {
    klog("xaifs: self-test failed committed staging read\n");
    if (fd > 0) (void)vfs_close((uint32_t)fd, UINT32_C(0x4d4f444c));
    return;
  }
  for (uint64_t index = 0U; index < 4096U; ++index) {
    if (data[index] != (uint8_t)((index * 7U + 3U) & 0xffU)) {
      klog("xaifs: self-test failed staging data index=%lu\n", index);
      return;
    }
  }
  if (vfs_open(staging_path,
               XAIOS_VFS_OPEN_WRITE | XAIOS_VFS_OPEN_TRUNCATE,
               UINT32_C(0x4d4f444c)) != XAIOS_ERR_BUSY) {
    klog("xaifs: self-test failed resumable truncate protection\n");
    return;
  }
  klog("xaifs: signed active read and crash-consistent staging write self-test passed active_bytes=%lu staging_bytes=4096\n",
       count);
}
