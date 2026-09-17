/*
 * The initramfs manifest's key=value configuration.
 *
 * Split out of initramfs.c, which was 552 lines. This is the whole of the
 * parsing side -- the line splitter, the seven fields it fills, and the checks
 * that the descriptor names real files in the loaded table -- and it owns
 * every buffer it writes. initramfs.c keeps the on-disk image codec and the
 * file table, which this side reads through the read-only accessors in
 * xaios/initramfs.h.
 */

#include "initramfs_internal.h"

#include <xaios/klog.h>

static char g_config_service_path[INITFS_PATH_MAX];
static char g_config_service_manager_path[INITFS_PATH_MAX];
static char g_config_service_descriptor_path[INITFS_PATH_MAX];
static char g_config_mode[INITFS_MODE_MAX];
static char g_config_child_service_path[INITFS_PATH_MAX];
static char g_config_child_service_parent[INITFS_PATH_MAX];
static char g_config_child_service_restart[INITFS_MODE_MAX];
static xaios_initramfs_config_t g_config;

static int bytes_eq(const char *a, const char *b, uint64_t count) {
  for (uint64_t i = 0; i < count; ++i) {
    if (a[i] != b[i]) {
      return 0;
    }
  }
  return 1;
}

static xaios_status_t copy_config_value(char *dst, uint32_t capacity,
                                       const char *src, uint64_t size) {
  if (capacity == 0 || size == 0 || size >= capacity) {
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t i = 0; i < size; ++i) {
    char c = src[i];
    if (c == '\r' || c == '\n' || c == '\0') {
      return XAIOS_ERR_INVALID;
    }
    dst[i] = c;
  }
  dst[size] = '\0';
  return XAIOS_OK;
}

static xaios_status_t parse_config_line(const char *line, uint64_t len) {
  if (len == 0 || line[0] == '#') {
    return XAIOS_OK;
  }
  if (len > 8 && bytes_eq(line, "service=", 8)) {
    return copy_config_value(g_config_service_path, INITFS_PATH_MAX, line + 8,
                             len - 8);
  }
  if (len > 16 && bytes_eq(line, "service_manager=", 16)) {
    return copy_config_value(g_config_service_manager_path, INITFS_PATH_MAX,
                             line + 16, len - 16);
  }
  if (len > 19 && bytes_eq(line, "service_descriptor=", 19)) {
    return copy_config_value(g_config_service_descriptor_path, INITFS_PATH_MAX,
                             line + 19, len - 19);
  }
  if (len > 5 && bytes_eq(line, "mode=", 5)) {
    return copy_config_value(g_config_mode, INITFS_MODE_MAX, line + 5,
                             len - 5);
  }
  if (len > 14 && bytes_eq(line, "child_service=", 14)) {
    return copy_config_value(g_config_child_service_path, INITFS_PATH_MAX,
                             line + 14, len - 14);
  }
  if (len > 13 && bytes_eq(line, "child_parent=", 13)) {
    return copy_config_value(g_config_child_service_parent, INITFS_PATH_MAX,
                             line + 13, len - 13);
  }
  if (len > 14 && bytes_eq(line, "child_restart=", 14)) {
    return copy_config_value(g_config_child_service_restart, INITFS_MODE_MAX,
                             line + 14, len - 14);
  }
  klog("initramfs: rejected config line len=%lu\n", len);
  return XAIOS_ERR_INVALID;
}

xaios_status_t initramfs_parse_config_manifest(
    const xaios_initramfs_file_t *file) {
  if (file == 0 || file->base == 0 || file->size == 0 ||
      file->manifest == 0) {
    return XAIOS_ERR_INVALID;
  }

  g_config_service_path[0] = '\0';
  g_config_service_manager_path[0] = '\0';
  g_config_service_descriptor_path[0] = '\0';
  g_config_mode[0] = '\0';
  g_config_child_service_path[0] = '\0';
  g_config_child_service_parent[0] = '\0';
  g_config_child_service_restart[0] = '\0';
  const char *bytes = (const char *)file->base;
  uint64_t line_start = 0;
  for (uint64_t i = 0; i <= file->size; ++i) {
    if (i == file->size || bytes[i] == '\n') {
      uint64_t line_len = i - line_start;
      if (line_len != 0 && bytes[line_start + line_len - 1U] == '\r') {
        --line_len;
      }
      if (parse_config_line(bytes + line_start, line_len) != XAIOS_OK) {
        return XAIOS_ERR_INVALID;
      }
      line_start = i + 1U;
    }
  }

  if (g_config_service_path[0] == '\0' ||
      g_config_service_manager_path[0] == '\0' ||
      g_config_service_descriptor_path[0] == '\0' ||
      g_config_mode[0] == '\0' ||
      g_config_child_service_path[0] == '\0' ||
      g_config_child_service_parent[0] == '\0' ||
      g_config_child_service_restart[0] == '\0') {
    klog("initramfs: config missing required service/mode/child descriptor\n");
    return XAIOS_ERR_INVALID;
  }

  g_config.service_path = g_config_service_path;
  g_config.service_manager_path = g_config_service_manager_path;
  g_config.service_descriptor_path = g_config_service_descriptor_path;
  g_config.mode = g_config_mode;
  g_config.child_service_path = g_config_child_service_path;
  g_config.child_service_parent = g_config_child_service_parent;
  g_config.child_service_restart = g_config_child_service_restart;
  g_config.valid = 1;
  klog("initramfs: config service=%s mode=%s\n",
       g_config.service_path, g_config.mode);
  klog("initramfs: service-manager path=%s descriptor=%s\n",
       g_config.service_manager_path, g_config.service_descriptor_path);
  klog("initramfs: child service=%s parent=%s restart=%s\n",
       g_config.child_service_path, g_config.child_service_parent,
       g_config.child_service_restart);
  return XAIOS_OK;
}

static xaios_status_t validate_executable_target(const char *path) {
  for (uint32_t i = 0; i < initramfs_file_count(); ++i) {
    const xaios_initramfs_file_t *file = initramfs_file_at(i);
    if (initramfs_str_eq(file->path, path)) {
      if (file->executable == 0) {
        klog("initramfs: config service target is not executable path=%s\n",
             path);
        return XAIOS_ERR_INVALID;
      }
      return XAIOS_OK;
    }
  }
  klog("initramfs: config service target missing path=%s\n",
       path);
  return XAIOS_ERR_NOT_FOUND;
}

static xaios_status_t validate_descriptor_target(void) {
  for (uint32_t i = 0; i < initramfs_file_count(); ++i) {
    const xaios_initramfs_file_t *file = initramfs_file_at(i);
    if (initramfs_str_eq(file->path, g_config.service_descriptor_path)) {
      if (file->executable != 0 || file->manifest != 0) {
        klog("initramfs: descriptor has invalid flags path=%s\n",
             g_config.service_descriptor_path);
        return XAIOS_ERR_INVALID;
      }
      return XAIOS_OK;
    }
  }
  klog("initramfs: descriptor target missing path=%s\n",
       g_config.service_descriptor_path);
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t initramfs_config_validate_targets(void) {
  if (validate_executable_target(g_config.service_path) != XAIOS_OK ||
      validate_executable_target(g_config.service_manager_path) != XAIOS_OK ||
      validate_descriptor_target() != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
}

void initramfs_config_reset(void) { g_config.valid = 0; }

const xaios_initramfs_config_t *initramfs_config(void) {
  return g_config.valid != 0 ? &g_config : 0;
}
