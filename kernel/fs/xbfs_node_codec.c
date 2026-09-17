/*
 * The v3, v4 and v5 node codec, split out of xaiboot_fs.c.
 *
 * Older volumes keep their own on-disk encoding. In memory every version is
 * the extent-recorded node (xaios_xbfs_node_t), so a v3/v4 volume's direct
 * block list is converted to extents on the way in and back on the way out.
 * These six functions are the whole of that conversion and touch none of
 * xaiboot_fs.c's state, which is why they move without an accessor layer.
 *
 * The block loop that narrows a 32-bit extent start to the 16 bits an older
 * volume records stays in xaiboot_fs.c, as extents_to_blocks, because a
 * text-reading gate matches the two literals that guard the truncation.
 */

#include "xbfs_internal.h"

void import_legacy_node(xaios_xbfs_node_t *node,
                        const xaios_xbfs_node_v3_t *legacy) {
  xbfs_bytes_zero(node, sizeof(*node));
  node->active = legacy->active;
  node->snapshot_active = legacy->snapshot_active;
  node->type = legacy->type;
  node->snapshot_type = legacy->snapshot_type;
  node->size = legacy->size;
  node->content_hash = legacy->content_hash;
  node->generation = legacy->generation;
  node->snapshot_size = legacy->snapshot_size;
  node->snapshot_hash = legacy->snapshot_hash;
  node->snapshot_generation = legacy->snapshot_generation;
  node->extent_count =
      extents_from_blocks(legacy->blocks, legacy->block_count, node->extents);
  node->snapshot_extent_count = extents_from_blocks(
      legacy->snapshot_blocks, legacy->snapshot_block_count,
      node->snapshot_extents);
  for (uint32_t i = 0; i < XBFS_V3_PATH_MAX; ++i) {
    node->path[i] = legacy->path[i];
    if (legacy->path[i] == '\0') {
      return;
    }
  }
  node->path[XBFS_V3_PATH_MAX] = '\0';
}

void import_v4_node(xaios_xbfs_node_t *node,
                    const xaios_xbfs_node_v4_t *legacy) {
  xbfs_bytes_zero(node, sizeof(*node));
  node->active = legacy->active;
  node->snapshot_active = legacy->snapshot_active;
  node->type = legacy->type;
  node->snapshot_type = legacy->snapshot_type;
  node->size = legacy->size;
  node->content_hash = legacy->content_hash;
  node->generation = legacy->generation;
  node->snapshot_size = legacy->snapshot_size;
  node->snapshot_hash = legacy->snapshot_hash;
  node->snapshot_generation = legacy->snapshot_generation;
  node->extent_count =
      extents_from_blocks(legacy->blocks, legacy->block_count, node->extents);
  node->snapshot_extent_count = extents_from_blocks(
      legacy->snapshot_blocks, legacy->snapshot_block_count,
      node->snapshot_extents);
  xbfs_bytes_copy(node->path, legacy->path, sizeof(legacy->path));
}

void import_v5_node(xaios_xbfs_node_t *node,
                    const xaios_xbfs_node_v5_t *legacy) {
  xbfs_bytes_zero(node, sizeof(*node));
  node->active = legacy->active;
  node->snapshot_active = legacy->snapshot_active;
  node->type = legacy->type;
  node->snapshot_type = legacy->snapshot_type;
  node->size = legacy->size;
  node->content_hash = legacy->content_hash;
  node->generation = legacy->generation;
  node->snapshot_size = legacy->snapshot_size;
  node->snapshot_hash = legacy->snapshot_hash;
  node->snapshot_generation = legacy->snapshot_generation;
  node->extent_count =
      extents_from_blocks(legacy->blocks, legacy->block_count, node->extents);
  node->snapshot_extent_count = extents_from_blocks(
      legacy->snapshot_blocks, legacy->snapshot_block_count,
      node->snapshot_extents);
  xbfs_bytes_copy(node->path, legacy->path, sizeof(legacy->path));
}

void export_v5_node(xaios_xbfs_node_v5_t *legacy,
                    const xaios_xbfs_node_t *node) {
  xbfs_bytes_zero(legacy, sizeof(*legacy));
  legacy->active = node->active;
  legacy->snapshot_active = node->snapshot_active;
  legacy->type = node->type;
  legacy->snapshot_type = node->snapshot_type;
  legacy->size = node->size;
  legacy->content_hash = node->content_hash;
  legacy->generation = node->generation;
  legacy->snapshot_size = node->snapshot_size;
  legacy->snapshot_hash = node->snapshot_hash;
  legacy->snapshot_generation = node->snapshot_generation;
  uint32_t written = extents_to_blocks(node->extents, node->extent_count,
                                       legacy->blocks,
                                       XBFS_V5_FILE_MAX_BLOCKS);
  legacy->block_count = written == UINT32_MAX ? 0U : (uint16_t)written;
  written = extents_to_blocks(node->snapshot_extents,
                              node->snapshot_extent_count,
                              legacy->snapshot_blocks,
                              XBFS_V5_FILE_MAX_BLOCKS);
  legacy->snapshot_block_count = written == UINT32_MAX ? 0U : (uint16_t)written;
  xbfs_bytes_copy(legacy->path, node->path, sizeof(legacy->path));
}

void export_v4_node(xaios_xbfs_node_v4_t *legacy,
                    const xaios_xbfs_node_t *node) {
  xbfs_bytes_zero(legacy, sizeof(*legacy));
  legacy->active = node->active;
  legacy->snapshot_active = node->snapshot_active;
  legacy->type = node->type;
  legacy->snapshot_type = node->snapshot_type;
  legacy->size = node->size;
  legacy->content_hash = node->content_hash;
  legacy->generation = node->generation;
  legacy->snapshot_size = node->snapshot_size;
  legacy->snapshot_hash = node->snapshot_hash;
  legacy->snapshot_generation = node->snapshot_generation;
  uint32_t written = extents_to_blocks(node->extents, node->extent_count,
                                       legacy->blocks,
                                       (uint32_t)(sizeof(legacy->blocks) /
                                                  sizeof(legacy->blocks[0])));
  legacy->block_count = written == UINT32_MAX ? 0U : (uint16_t)written;
  written = extents_to_blocks(
      node->snapshot_extents, node->snapshot_extent_count,
      legacy->snapshot_blocks,
      (uint32_t)(sizeof(legacy->snapshot_blocks) /
                 sizeof(legacy->snapshot_blocks[0])));
  legacy->snapshot_block_count = written == UINT32_MAX ? 0U : (uint16_t)written;
  xbfs_bytes_copy(legacy->path, node->path, sizeof(legacy->path));
}

void export_legacy_node(xaios_xbfs_node_v3_t *legacy,
                        const xaios_xbfs_node_t *node) {
  xbfs_bytes_zero(legacy, sizeof(*legacy));
  legacy->active = node->active;
  legacy->snapshot_active = node->snapshot_active;
  legacy->type = node->type;
  legacy->snapshot_type = node->snapshot_type;
  legacy->size = node->size;
  legacy->content_hash = node->content_hash;
  legacy->generation = node->generation;
  legacy->snapshot_size = node->snapshot_size;
  legacy->snapshot_hash = node->snapshot_hash;
  legacy->snapshot_generation = node->snapshot_generation;
  uint32_t written = extents_to_blocks(node->extents, node->extent_count,
                                       legacy->blocks,
                                       (uint32_t)(sizeof(legacy->blocks) /
                                                  sizeof(legacy->blocks[0])));
  legacy->block_count = written == UINT32_MAX ? 0U : (uint16_t)written;
  written = extents_to_blocks(
      node->snapshot_extents, node->snapshot_extent_count,
      legacy->snapshot_blocks,
      (uint32_t)(sizeof(legacy->snapshot_blocks) /
                 sizeof(legacy->snapshot_blocks[0])));
  legacy->snapshot_block_count = written == UINT32_MAX ? 0U : (uint16_t)written;
  for (uint32_t i = 0; i + 1U < XBFS_V3_PATH_MAX && node->path[i] != '\0';
       ++i) {
    legacy->path[i] = node->path[i];
  }
}
