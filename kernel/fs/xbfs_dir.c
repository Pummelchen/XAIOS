/*
 * The namespace xaibootFS exposes: path validation, node lookup, and the
 * directory operations -- create, delete, rename, stat and list.
 *
 * Split out of xaiboot_fs.c. The bodies are unchanged; only the names that
 * cross a translation unit gained the xbfs_ prefix. The two tables this file
 * mutates on another file's behalf -- the open-file handles reachable from a
 * deleted or renamed subtree -- are named operations on their owner
 * (xbfs_open_files_forget_tree and xbfs_open_files_rebase) rather than a loop
 * written here over that owner's state.
 *
 * The volume state stays in xaiboot_fs.c. Every accessor this file calls is
 * declared in xbfs_internal.h; xbfs_node_row() hands back a pointer into the
 * live node table that is good for the duration of one call and no longer.
 * Every entry point runs with the volume lock already held, exactly as the
 * static functions it replaces did, and none of them takes the lock itself.
 */

#include <xaios/klog.h>

#include "xbfs_internal.h"

static int node_is_visible(const xaios_xbfs_node_t *node) {
  return node != 0 && (node->active != 0 || node->snapshot_active != 0);
}

xaios_status_t xbfs_validate_path(const char *path) {
  if (path == 0 || path[0] != '/') {
    return XAIOS_ERR_INVALID;
  }
  uint32_t len = 0;
  uint32_t last_slash = 1;
  for (uint32_t i = 0; i < xbfs_geometry_path_max(); ++i) {
    char c = path[i];
    if (c == '\0') {
      if (len == 0 || (len > 1U && last_slash != 0)) {
        return XAIOS_ERR_INVALID;
      }
      return XAIOS_OK;
    }
    if (c < '!' || c > '~' || c == ':' || c == '*' || c == '?' ||
        c == '"' || c == '<' || c == '>' || c == '|') {
      return XAIOS_ERR_INVALID;
    }
    if (c == '/' && last_slash != 0 && i != 0) {
      return XAIOS_ERR_INVALID;
    }
    last_slash = c == '/' ? 1U : 0U;
    ++len;
  }
  return XAIOS_ERR_INVALID;
}

xaios_status_t xbfs_normalize_path(const char *path,
                                    char normalized[XBFS_PATH_MAX]) {
  if (xbfs_validate_path(path) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  xbfs_copy_path(normalized, path);
  return XAIOS_OK;
}

xaios_xbfs_node_t *xbfs_find_node(const char *path, uint32_t include_snapshot) {
  for (uint32_t i = 0; i < xbfs_geometry_max_nodes(); ++i) {
    xaios_xbfs_node_t *node = xbfs_node_row(i);
    if ((node->active != 0 ||
         (include_snapshot != 0 && node->snapshot_active != 0)) &&
        xbfs_str_eq(node->path, path)) {
      return node;
    }
  }
  return 0;
}

xaios_xbfs_node_t *xbfs_find_free_node(void) {
  for (uint32_t i = 0; i < xbfs_geometry_max_nodes(); ++i) {
    if (xbfs_node_row(i)->active == 0 && xbfs_node_row(i)->snapshot_active == 0) {
      return xbfs_node_row(i);
    }
  }
  return 0;
}

int xbfs_parent_exists_for(const char *path) {
  char parent[XBFS_PATH_MAX];
  xbfs_parent_path_of(path, parent);
  if (xbfs_str_eq(parent, "/")) {
    return 1;
  }
  xaios_xbfs_node_t *node = xbfs_find_node(parent, 0);
  return node != 0 && node->active != 0 && node->type == XBFS_NODE_DIR;
}

xaios_status_t xbfs_create_dir(const char *path) {
  if (xbfs_mounted() == 0 || (xbfs_mount_flags() & XBFS_MOUNT_READ_WRITE) == 0 ||
      xbfs_validate_path(path) != XAIOS_OK || !xbfs_parent_exists_for(path)) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }
  xaios_xbfs_node_t *node = xbfs_find_node(path, 1);
  if (node != 0 && node->active != 0) {
    return node->type == XBFS_NODE_DIR ? XAIOS_OK : XAIOS_ERR_INVALID;
  }
  if (node == 0) {
    node = xbfs_find_free_node();
  }
  if (node == 0) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_NO_MEMORY;
  }
  if (node->snapshot_active == 0) {
    xbfs_bytes_zero(node, sizeof(*node));
  }
  node->active = 1;
  node->type = XBFS_NODE_DIR;
  node->size = 0;
  node->content_hash = 0;
  node->generation = xbfs_generation_take();
  node->extent_count = 0;
  xbfs_bytes_zero(node->extents, sizeof(node->extents));
  xbfs_copy_path(node->path, path);
  klog("xaibootfs: mkdir path=%s generation=%lu\n",
       node->path, node->generation);
  return xbfs_write_metadata();
}

xaios_status_t xbfs_ensure_base_directories(void) {
  static const char *const paths[] = {
      "/", "/etc", "/bin", "/state", "/state/services",
      "/state/workspaces", "/state/updates", "/config", "/logs",
      "/workspaces", "/models", "/tmp", "/home", "/home/admin",
  };
  for (uint32_t i = 0; i < sizeof(paths) / sizeof(paths[0]); ++i) {
    if (xbfs_create_dir(paths[i]) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
  }
  return XAIOS_OK;
}

/* Sized for the largest format, not for the one that existed when it was
   written. `xbfs_rename_node` walks `xbfs_geometry_max_nodes()`, which v6 raised to 1024
   while this stayed at v5's 256 -- so a rename on a v6 volume cleared and
   read back rows 256 through 1023, running 191 KiB past a 64 KiB array. That
   is the same mistake `write_limit` exists to prevent for `g_file_buffer`,
   made once more here and missed because no v6 volume in any test had ever
   been renamed on.

   Sized rather than clamped, because clamping is wrong for this one: a rename
   that skips the nodes past the limit leaves them holding paths under a
   directory that no longer exists, which is worse than refusing. */
static char g_path_transaction[XBFS_V6_MAX_NODES][XBFS_PATH_MAX];

/* Every format's node count has to fit, so a future one cannot quietly
   reintroduce the overflow by raising the maximum alone. */
typedef char xbfs_path_transaction_fits
    [(XBFS_V6_MAX_NODES >= XBFS_V5_MAX_NODES &&
      XBFS_V6_MAX_NODES >= XBFS_V4_MAX_NODES &&
      XBFS_V6_MAX_NODES >= XBFS_MAX_NODES)
         ? 1
         : -1];

static int has_active_children(const char *path) {
  uint64_t parent_len = xbfs_cstr_len(path);
  for (uint32_t i = 0; i < xbfs_geometry_max_nodes(); ++i) {
    xaios_xbfs_node_t *node = xbfs_node_row(i);
    if (node->active == 0 || xbfs_str_eq(node->path, path)) {
      continue;
    }
    if (xbfs_bytes_eq(node->path, path, parent_len) && node->path[parent_len] == '/') {
      return 1;
    }
  }
  return 0;
}


xaios_status_t xbfs_delete_node(const char *path) {
  if (xbfs_mounted() == 0 || (xbfs_mount_flags() & XBFS_MOUNT_READ_WRITE) == 0 ||
      xbfs_validate_path(path) != XAIOS_OK) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }
  xaios_xbfs_node_t *node = xbfs_find_node(path, 0);
  if (node == 0 || node->active == 0) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_NOT_FOUND;
  }
  if (node->type == XBFS_NODE_DIR && has_active_children(path)) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_BUSY;
  }
  if (node->type == XBFS_NODE_FILE) {
    xbfs_free_extents(node->extents, node->extent_count);
    node->extent_count = 0;
  }
  node->active = 0;
  node->generation = xbfs_generation_take();
  xbfs_stat_bump(XBFS_STAT_DELETE);
  klog("xaibootfs: delete path=%s generation=%lu\n",
       node->path, node->generation);
  return xbfs_write_metadata();
}

xaios_status_t xbfs_delete_tree(const char *path) {
  char normalized[XBFS_PATH_MAX];
  if (xbfs_mounted() == 0 || (xbfs_mount_flags() & XBFS_MOUNT_READ_WRITE) == 0 ||
      xbfs_normalize_path(path, normalized) != XAIOS_OK ||
      xbfs_str_eq(normalized, "/")) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }
  xaios_xbfs_node_t *root = xbfs_find_node(normalized, 0);
  if (root == 0 || root->active == 0) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_NOT_FOUND;
  }
  uint32_t deleted = 0;
  for (uint32_t i = 0; i < xbfs_geometry_max_nodes(); ++i) {
    xaios_xbfs_node_t *node = xbfs_node_row(i);
    if (node->active == 0 || !xbfs_path_is_at_or_below(node->path, normalized)) {
      continue;
    }
    if (node->type == XBFS_NODE_FILE) {
      xbfs_free_extents(node->extents, node->extent_count);
      node->extent_count = 0;
      xbfs_bytes_zero(node->extents, sizeof(node->extents));
    }
    node->active = 0;
    node->generation = xbfs_generation_take();
    ++deleted;
  }
  xbfs_open_files_forget_tree(normalized);
  xbfs_stat_add(XBFS_STAT_DELETE, deleted);
  klog("xaibootfs: delete-tree path=%s nodes=%u generation=%lu\n",
       normalized, deleted, xbfs_generation_get());
  return xbfs_write_metadata();
}

xaios_status_t xbfs_rename_node(const char *old_path, const char *new_path) {
  char normalized_old[XBFS_PATH_MAX];
  char normalized_new[XBFS_PATH_MAX];
  if (xbfs_mounted() == 0 || (xbfs_mount_flags() & XBFS_MOUNT_READ_WRITE) == 0 ||
      xbfs_normalize_path(old_path, normalized_old) != XAIOS_OK ||
      xbfs_normalize_path(new_path, normalized_new) != XAIOS_OK ||
      !xbfs_parent_exists_for(normalized_new)) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }
  xaios_xbfs_node_t *node = xbfs_find_node(normalized_old, 0);
  if (node == 0 || node->active == 0) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_NOT_FOUND;
  }
  if (xbfs_find_node(normalized_new, 0) != 0) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_BUSY;
  }
  if (xbfs_str_eq(normalized_old, "/") ||
      (node->type == XBFS_NODE_DIR &&
       xbfs_path_is_at_or_below(normalized_new, normalized_old))) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }

  uint64_t old_len = xbfs_cstr_len(normalized_old);
  uint64_t new_len = xbfs_cstr_len(normalized_new);
  for (uint32_t i = 0; i < xbfs_geometry_max_nodes(); ++i) {
    g_path_transaction[i][0] = '\0';
    xaios_xbfs_node_t *candidate = xbfs_node_row(i);
    if (candidate->active == 0 ||
        !xbfs_path_is_at_or_below(candidate->path, normalized_old)) {
      continue;
    }
    const char *suffix = candidate->path + old_len;
    uint64_t suffix_len = xbfs_cstr_len(suffix);
    if (new_len + suffix_len + 1U > xbfs_geometry_path_max()) {
      xbfs_stat_bump(XBFS_STAT_REJECT);
      return XAIOS_ERR_INVALID;
    }
    xbfs_copy_path(g_path_transaction[i], normalized_new);
    xbfs_bytes_copy(g_path_transaction[i] + new_len, suffix, suffix_len + 1U);
    if (xbfs_validate_path(g_path_transaction[i]) != XAIOS_OK) {
      xbfs_stat_bump(XBFS_STAT_REJECT);
      return XAIOS_ERR_INVALID;
    }
  }
  for (uint32_t i = 0; i < xbfs_geometry_max_nodes(); ++i) {
    if (g_path_transaction[i][0] == '\0') {
      continue;
    }
    for (uint32_t j = 0; j < xbfs_geometry_max_nodes(); ++j) {
      if (g_path_transaction[j][0] == '\0' && xbfs_node_row(j)->active != 0 &&
          xbfs_str_eq(g_path_transaction[i], xbfs_node_row(j)->path)) {
        xbfs_stat_bump(XBFS_STAT_REJECT);
        return XAIOS_ERR_BUSY;
      }
    }
  }
  for (uint32_t i = 0; i < xbfs_geometry_max_nodes(); ++i) {
    if (g_path_transaction[i][0] != '\0') {
      xbfs_copy_path(xbfs_node_row(i)->path, g_path_transaction[i]);
      xbfs_node_row(i)->generation = xbfs_generation_take();
    }
  }
  xbfs_open_files_rebase(normalized_old, normalized_new);
  xbfs_stat_bump(XBFS_STAT_RENAME);
  klog("xaibootfs: rename old=%s new=%s generation=%lu\n",
       normalized_old, normalized_new, xbfs_generation_get());
  return xbfs_write_metadata();
}

xaios_status_t xbfs_stat_node(const char *path, xaios_xbfs_stat_t *stat) {
  char normalized[XBFS_PATH_MAX];
  if (stat == 0 || xbfs_normalize_path(path, normalized) != XAIOS_OK) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }
  xaios_xbfs_node_t *node = xbfs_find_node(normalized, 1);
  if (!node_is_visible(node)) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_NOT_FOUND;
  }
  stat->type = node->type;
  stat->block_count =
      (uint16_t)xbfs_extent_blocks(node->extents, node->extent_count);
  stat->size = node->size;
  stat->generation = node->generation;
  stat->content_hash = node->content_hash;
  xbfs_stat_bump(XBFS_STAT_STAT);
  klog("xaibootfs: stat path=%s type=%u size=%lu generation=%lu\n",
       normalized, stat->type, stat->size, stat->generation);
  return XAIOS_OK;
}


xaios_status_t xbfs_list_dir(const char *path, char *buffer,
                              uint64_t buffer_size, uint64_t *out_size) {
  char normalized[XBFS_PATH_MAX];
  uint64_t offset = 0;
  xaios_status_t append_status = XAIOS_OK;
  if (buffer == 0 || out_size == 0 || buffer_size == 0 ||
      xbfs_normalize_path(path, normalized) != XAIOS_OK) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }

  xaios_xbfs_node_t *dir = xbfs_find_node(normalized, 1);
  if (!node_is_visible(dir) || dir->type != XBFS_NODE_DIR) {
    if (!xbfs_str_eq(normalized, "/")) {
      xbfs_stat_bump(XBFS_STAT_REJECT);
      return XAIOS_ERR_NOT_FOUND;
    }
  }

  buffer[0] = '\0';
  for (uint32_t i = 0; i < xbfs_geometry_max_nodes(); ++i) {
    xaios_xbfs_node_t *node = xbfs_node_row(i);
    const char *name = 0;
    if (!node_is_visible(node) || xbfs_str_eq(node->path, normalized) ||
        !xbfs_direct_child_of(normalized, node->path, &name)) {
      continue;
    }
    append_status = xbfs_append_cstr(buffer, buffer_size, &offset, name);
    if (append_status == XAIOS_OK) {
      append_status = xbfs_append_char(buffer, buffer_size, &offset, '\n');
    }
    if (append_status != XAIOS_OK) {
      if (out_size != 0) {
        *out_size = offset;
      }
      xbfs_stat_bump(XBFS_STAT_REJECT);
      return append_status;
    }
  }

  if (xbfs_str_eq(normalized, "/") && offset == 0U) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_NOT_FOUND;
  }

  *out_size = offset;
  xbfs_stat_bump(XBFS_STAT_LIST);
  klog("xaibootfs: list path=%s bytes=%lu\n", normalized, offset);
  return XAIOS_OK;
}

/* The rename staging table's row count, so the self-test in xaiboot_fs.c can
   assert that a format's node maximum still fits it. */
uint64_t xbfs_dir_path_transaction_rows(void) {
  return (uint64_t)(sizeof(g_path_transaction) / sizeof(g_path_transaction[0]));
}
