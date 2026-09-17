/*
 * xaibootFS's snapshot and rollback group, split out of xaiboot_fs.c.
 *
 * xbfs_snapshot_commit copies each active node's identity and extents into its
 * snapshot half; xbfs_snapshot_restore_node puts one node back and is also what
 * mount calls to bring a snapshot-only root back; xbfs_snapshot_rollback drops
 * the nodes created since the last commit and restores the rest, directories
 * before files. The node table lives in xaiboot_fs.c and is reached through
 * xbfs_node_row, whose row pointer is good only for the duration of the call
 * that asked for it. Every entry point runs with the volume lock held, exactly
 * as the static functions it replaces did, and takes no lock itself.
 */

#include <xaios/klog.h>

#include "xbfs_internal.h"
#include "xbfs_file_io_internal.h"
#include "xbfs_volume_internal.h"

xaios_status_t xbfs_snapshot_commit(const char *label) {
  (void)label;
  if (xbfs_mounted() == 0 || (xbfs_mount_flags() & XBFS_MOUNT_READ_WRITE) == 0) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }
  for (uint32_t i = 0; i < xbfs_geometry_max_nodes(); ++i) {
    xaios_xbfs_node_t *node = xbfs_node_row(i);
    if (node->snapshot_active != 0 && node->snapshot_type == XBFS_NODE_FILE) {
      xbfs_free_extents(node->snapshot_extents, node->snapshot_extent_count);
    }
    node->snapshot_active = 0;
    node->snapshot_type = XBFS_NODE_FREE;
    node->snapshot_size = 0;
    node->snapshot_hash = 0;
    node->snapshot_generation = 0;
    node->snapshot_extent_count = 0;
    xbfs_bytes_zero(node->snapshot_extents, sizeof(node->snapshot_extents));
    if (node->active == 0) {
      continue;
    }
    node->snapshot_active = 1;
    node->snapshot_type = node->type;
    node->snapshot_size = node->size;
    node->snapshot_hash = node->content_hash;
    node->snapshot_generation = node->generation;
    if (node->type == XBFS_NODE_FILE) {
      xaios_xbfs_extent_t snapshot_extents[XBFS_V6_MAX_EXTENTS];
      uint32_t snapshot_extent_count = 0U;
      xbfs_bytes_zero(snapshot_extents, sizeof(snapshot_extents));
      if (xbfs_clone_extents(node->extents, node->extent_count, snapshot_extents,
                        &snapshot_extent_count) != XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
      node->snapshot_extent_count = snapshot_extent_count;
      xbfs_bytes_copy(node->snapshot_extents, snapshot_extents,
                 sizeof(snapshot_extents));
    }
  }
  xbfs_volume_committed_generation_set(xbfs_generation_get());
  xbfs_stat_bump(XBFS_STAT_COMMIT);
  klog("xaibootfs: snapshot committed generation=%lu files=%lu directories=%lu blocks=%lu\n",
       xbfs_volume_committed_generation_get(), xbfs_node_count_by_type(XBFS_NODE_FILE),
       xbfs_node_count_by_type(XBFS_NODE_DIR), xbfs_block_count_used());
  return xbfs_write_metadata();
}

xaios_status_t xbfs_snapshot_restore_node(xaios_xbfs_node_t *node) {
  if (node->snapshot_active == 0) {
    return XAIOS_OK;
  }
  if (node->active != 0 && node->type == XBFS_NODE_FILE) {
    xbfs_free_extents(node->extents, node->extent_count);
  }
  node->active = 1;
  node->type = node->snapshot_type;
  node->size = node->snapshot_size;
  node->content_hash = node->snapshot_hash;
  node->generation = node->snapshot_generation;
  node->extent_count = 0;
  xbfs_bytes_zero(node->extents, sizeof(node->extents));
  if (node->snapshot_type == XBFS_NODE_FILE) {
    xaios_xbfs_extent_t restored[XBFS_V6_MAX_EXTENTS];
    uint32_t restored_count = 0U;
    xbfs_bytes_zero(restored, sizeof(restored));
    if (xbfs_clone_extents(node->snapshot_extents, node->snapshot_extent_count,
                      restored, &restored_count) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
    node->extent_count = restored_count;
    xbfs_bytes_copy(node->extents, restored, sizeof(restored));
  }
  return XAIOS_OK;
}

xaios_status_t xbfs_snapshot_rollback(void) {
  if (xbfs_mounted() == 0 || (xbfs_mount_flags() & XBFS_MOUNT_READ_WRITE) == 0) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }
  for (uint32_t i = 0; i < xbfs_geometry_max_nodes(); ++i) {
    xaios_xbfs_node_t *node = xbfs_node_row(i);
    if (node->snapshot_active == 0 && node->active != 0 &&
        node->generation >= xbfs_volume_committed_generation_get()) {
      if (node->type == XBFS_NODE_FILE) {
        xbfs_free_extents(node->extents, node->extent_count);
      }
      node->active = 0;
      node->extent_count = 0;
      xbfs_bytes_zero(node->extents, sizeof(node->extents));
    }
  }
  for (uint32_t pass = 0; pass < 2U; ++pass) {
    for (uint32_t i = 0; i < xbfs_geometry_max_nodes(); ++i) {
      xaios_xbfs_node_t *node = xbfs_node_row(i);
      if (node->snapshot_active == 0) {
        continue;
      }
      if ((pass == 0 && node->snapshot_type == XBFS_NODE_DIR) ||
          (pass == 1 && node->snapshot_type == XBFS_NODE_FILE)) {
        if (xbfs_snapshot_restore_node(node) != XAIOS_OK) {
          return XAIOS_ERR_IO;
        }
      }
    }
  }
  xbfs_volume_generation_bump();
  xbfs_stat_bump(XBFS_STAT_ROLLBACK);
  klog("xaibootfs: snapshot rollback committed=%lu files=%lu directories=%lu blocks=%lu\n",
       xbfs_volume_committed_generation_get(), xbfs_node_count_by_type(XBFS_NODE_FILE),
       xbfs_node_count_by_type(XBFS_NODE_DIR), xbfs_block_count_used());
  return xbfs_write_metadata();
}
