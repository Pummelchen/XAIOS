/*
 * xaibootFS's byte-level file data path, split out of xaiboot_fs.c.
 *
 * This is the layer between the node table and the block device: mapping a
 * data block to its absolute sector, writing and reading a run of extents,
 * writing a whole file, reading a whole file back and checking its hash, and
 * cloning a file's extents for a snapshot. Moving the file's bytes is all any
 * of it does; the node table, the mount state and the metadata commit stay in
 * xaiboot_fs.c and are reached through the accessors in xbfs_internal.h.
 *
 * The bodies are unchanged from xaiboot_fs.c. Only the names that cross a
 * translation unit gained the xbfs_ prefix, and the direct reads of the
 * volume's mount state, mount flags and generation became the accessor calls
 * declared in xbfs_internal.h. Every entry point runs with the volume lock
 * held, exactly as the static functions it replaces did.
 *
 * What is deliberately not here: the block<->extent conversion
 * (extents_from_blocks, extents_to_blocks) and the version metadata-sector
 * macros stay in xaiboot_fs.c because the text-reading gates match them there.
 */

#include <xaios/klog.h>
#include <xaios/xaiboot_fs.h>

#include "xbfs_internal.h"
#include "xbfs_metadata_internal.h"
#include "xbfs_file_io_internal.h"

/* The block index is 64-bit because the volume is.
 *
 * This took a uint16_t, which stops at 65535 -- block 65536 is 32 MiB in, and
 * a v6 volume is allowed a gibibyte. Every caller already passed a uint64_t
 * taken from an extent, so the conversion happened silently at the call and
 * the sector number wrapped: a read or a write past 32 MiB went to a sector
 * near the start of the data region instead, hitting whatever was there. No
 * error, no short count, the wrong bytes. Nothing reachable by the v5 volumes
 * anything currently boots, which is why it sat here; v6 volumes are the ones
 * that can grow into it. See B-49. */
uint64_t xbfs_absolute_data_sector(uint64_t block_index) {
  return xbfs_data_start_sector() + block_index;
}

static xaios_status_t write_extents(const xaios_xbfs_extent_t *extents,
                                    uint32_t extent_count, const void *data,
                                    uint64_t size) {
  const uint8_t *bytes = (const uint8_t *)data;
  uint8_t sector[XBFS_SECTOR_SIZE];
  uint64_t blocks = xbfs_extent_blocks(extents, extent_count);
  for (uint64_t i = 0; i < blocks; ++i) {
    uint64_t offset = i * XBFS_SECTOR_SIZE;
    uint64_t chunk = size > offset ? size - offset : 0U;
    if (chunk > XBFS_SECTOR_SIZE) chunk = XBFS_SECTOR_SIZE;
    xbfs_bytes_zero(sector, sizeof(sector));
    if (chunk != 0U) xbfs_bytes_copy(sector, bytes + offset, chunk);
    uint64_t block = xbfs_extent_block_at(extents, extent_count, i);
    if (block == UINT64_MAX ||
        xbfs_blk_write(xbfs_absolute_data_sector(block), sector,
                  XBFS_SECTOR_SIZE) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
  }
  return XAIOS_OK;
}

static xaios_status_t read_extents(const xaios_xbfs_extent_t *extents,
                                   uint32_t extent_count, void *buffer,
                                   uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  uint8_t sector[XBFS_SECTOR_SIZE];
  uint64_t blocks = xbfs_extent_blocks(extents, extent_count);
  for (uint64_t i = 0; i < blocks; ++i) {
    uint64_t block = xbfs_extent_block_at(extents, extent_count, i);
    if (block == UINT64_MAX ||
        xbfs_blk_read(xbfs_absolute_data_sector(block), sector,
                 XBFS_SECTOR_SIZE) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
    uint64_t offset = i * XBFS_SECTOR_SIZE;
    uint64_t chunk = size > offset ? size - offset : 0U;
    if (chunk > XBFS_SECTOR_SIZE) chunk = XBFS_SECTOR_SIZE;
    if (chunk != 0U) xbfs_bytes_copy(bytes + offset, sector, chunk);
  }
  return XAIOS_OK;
}

/* Copy a file's blocks into a freshly allocated set, for a snapshot. The
   destination is allocated as its own extents rather than sharing the
   source's: a snapshot that pointed at the same blocks would change whenever
   the file did, which is the opposite of what it is for. */
xaios_status_t xbfs_clone_extents(const xaios_xbfs_extent_t *source,
                                    uint32_t source_count,
                                    xaios_xbfs_extent_t *destination,
                                    uint32_t *destination_count) {
  uint8_t sector[XBFS_SECTOR_SIZE];
  uint64_t blocks = xbfs_extent_blocks(source, source_count);
  if (xbfs_allocate_extents(blocks, destination, destination_count) != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  for (uint64_t i = 0; i < blocks; ++i) {
    uint64_t from = xbfs_extent_block_at(source, source_count, i);
    uint64_t to = xbfs_extent_block_at(destination, *destination_count, i);
    if (from == UINT64_MAX || to == UINT64_MAX ||
        xbfs_blk_read(xbfs_absolute_data_sector(from), sector,
                 XBFS_SECTOR_SIZE) != XAIOS_OK ||
        xbfs_blk_write(xbfs_absolute_data_sector(to), sector,
                  XBFS_SECTOR_SIZE) != XAIOS_OK) {
      xbfs_free_extents(destination, *destination_count);
      *destination_count = 0U;
      return XAIOS_ERR_IO;
    }
  }
  return XAIOS_OK;
}

xaios_status_t xbfs_write_file_locked(const char *path, const void *data,
                                uint64_t size) {
  if (xbfs_mounted() == 0 || (xbfs_mount_flags() & XBFS_MOUNT_READ_WRITE) == 0 ||
      xbfs_validate_path(path) != XAIOS_OK || !xbfs_parent_exists_for(path) ||
      (data == 0 && size != 0) || size > xbfs_geometry_max_file_bytes()) {
    klog("xaibootfs: write rejected path=%s mounted=%u flags=0x%x parent=%u size=%lu\n",
         path == 0 ? "<null>" : path, xbfs_mounted(), xbfs_mount_flags(),
         path == 0 ? 0U : (uint32_t)xbfs_parent_exists_for(path), size);
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }

  uint64_t new_count = xbfs_blocks_for_size(size);
  xaios_xbfs_extent_t new_extents[XBFS_V6_MAX_EXTENTS];
  uint32_t new_extent_count = 0U;
  xbfs_bytes_zero(new_extents, sizeof(new_extents));
  if (xbfs_allocate_extents(new_count, new_extents, &new_extent_count) !=
      XAIOS_OK) {
    klog("xaibootfs: write allocation failed path=%s blocks=%lu used=%lu\n",
         path, new_count, xbfs_block_count_used());
    return XAIOS_ERR_NO_MEMORY;
  }
  if (write_extents(new_extents, new_extent_count, data, size) != XAIOS_OK) {
    klog("xaibootfs: write block IO failed path=%s blocks=%lu\n",
         path, new_count);
    xbfs_free_extents(new_extents, new_extent_count);
    return XAIOS_ERR_IO;
  }

  xaios_xbfs_node_t *node = xbfs_find_node(path, 1);
  if (node != 0 && node->active != 0 && node->type != XBFS_NODE_FILE) {
    klog("xaibootfs: write rejected existing non-file path=%s type=%u\n",
         path, node->type);
    xbfs_free_extents(new_extents, new_extent_count);
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }
  if (node == 0) {
    node = xbfs_find_free_node();
  }
  if (node == 0) {
    klog("xaibootfs: write no free node path=%s files=%lu directories=%lu\n",
         path, xbfs_node_count_by_type(XBFS_NODE_FILE),
         xbfs_node_count_by_type(XBFS_NODE_DIR));
    xbfs_free_extents(new_extents, new_extent_count);
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_NO_MEMORY;
  }

  if (node->active != 0 && node->type == XBFS_NODE_FILE) {
    xbfs_free_extents(node->extents, node->extent_count);
  }
  node->active = 1;
  node->type = XBFS_NODE_FILE;
  node->size = size;
  node->content_hash = xbfs_fnv1a64(data, size);
  node->generation = xbfs_generation_take();
  node->extent_count = new_extent_count;
  xbfs_copy_path(node->path, path);
  xbfs_bytes_zero(node->extents, sizeof(node->extents));
  xbfs_bytes_copy(node->extents, new_extents, sizeof(new_extents));
  if (new_count > 1U) {
    xbfs_stat_bump(XBFS_STAT_MULTI_SECTOR_FILE);
  }
  xbfs_stat_bump(XBFS_STAT_WRITE);
  klog("xaibootfs: write path=%s size=%lu blocks=%lu generation=%lu\n",
       node->path, node->size,
       (unsigned long)xbfs_extent_blocks(node->extents, node->extent_count),
       node->generation);
  return xbfs_write_metadata();
}

xaios_status_t xbfs_read_file(const char *path, void *buffer,
                               uint64_t buffer_size, uint64_t *out_size) {
  if (xbfs_mounted() == 0 || xbfs_validate_path(path) != XAIOS_OK || buffer == 0 ||
      out_size == 0) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }
  xaios_xbfs_node_t *node = xbfs_find_node(path, 0);
  if (node == 0 || node->active == 0 || node->type != XBFS_NODE_FILE ||
      node->size > buffer_size) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_NOT_FOUND;
  }
  if (read_extents(node->extents, node->extent_count, buffer, node->size) !=
      XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  if (xbfs_fnv1a64(buffer, node->size) != node->content_hash) {
    xbfs_stat_bump(XBFS_STAT_CHECKSUM_ERROR);
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }
  *out_size = node->size;
  xbfs_stat_bump(XBFS_STAT_READ);
  klog("xaibootfs: read path=%s size=%lu blocks=%lu generation=%lu\n",
       node->path, node->size,
       (unsigned long)xbfs_extent_blocks(node->extents, node->extent_count),
       node->generation);
  return XAIOS_OK;
}
