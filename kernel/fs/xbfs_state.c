/*
 * The state xaibootFS's translation units share.
 *
 * xaiboot_fs.c was 3434 lines and could not be cut further because two groups
 * of file-scope state are touched from nearly every function in it: the
 * counters and the mounted volume's geometry. Both move here behind the
 * accessors declared in xbfs_internal.h, so a function that only reads a
 * counter or a limit no longer has to live beside the variable.
 *
 * This file owns state and the trivial accessors over it. It has no policy:
 * nothing here decides when a counter moves or which geometry is right, only
 * where the value is kept. The locking, and the choice of which geometry to
 * select, stay with the callers in xaiboot_fs.c, exactly where they were.
 */

#include "xbfs_internal.h"

/* The counters. One array indexed by xbfs_stat_t rather than one global per
   counter, which is what makes a single reset and a single bump possible. The
   enum in xbfs_internal.h names every slot; XBFS_STAT_COUNT is the sentinel and
   is never a counter itself. */
static uint64_t g_xbfs_stats[XBFS_STAT_COUNT];

uint64_t xbfs_stat_get(xbfs_stat_t id) { return g_xbfs_stats[id]; }

void xbfs_stat_bump(xbfs_stat_t id) { ++g_xbfs_stats[id]; }

void xbfs_stat_add(xbfs_stat_t id, uint64_t delta) {
  g_xbfs_stats[id] += delta;
}

/* Zero every counter. Called from the self-test, which asserts on absolute
   figures rather than deltas, so the counters it reads have to start from a
   known floor. Nothing else resets them, matching the assignments this
   replaced. */
void xbfs_stat_reset_all(void) {
  for (uint32_t i = 0U; i < (uint32_t)XBFS_STAT_COUNT; ++i) {
    g_xbfs_stats[i] = 0U;
  }
}

/* The mounted volume's geometry. The initial value is the v2 layout, which is
   what the seven globals this replaced were initialised to at file scope, so a
   reader that runs before the first mount sees the same numbers it always
   did. */
static xbfs_geometry_t g_xbfs_geometry = {
    .metadata_sectors = XBFS_METADATA_SECTORS,
    .max_nodes = XBFS_MAX_NODES,
    .file_max_blocks = XBFS_FILE_MAX_BLOCKS,
    .data_sectors = XBFS_DATA_SECTORS,
    .version = XBFS_VERSION,
    .path_max = XBFS_V3_PATH_MAX,
    .max_file_bytes =
        (uint64_t)XBFS_FILE_MAX_BLOCKS * XBFS_SECTOR_SIZE,
};

uint32_t xbfs_geometry_metadata_sectors(void) {
  return g_xbfs_geometry.metadata_sectors;
}
uint32_t xbfs_geometry_max_nodes(void) { return g_xbfs_geometry.max_nodes; }
uint32_t xbfs_geometry_file_max_blocks(void) {
  return g_xbfs_geometry.file_max_blocks;
}
uint64_t xbfs_geometry_max_file_bytes(void) {
  return g_xbfs_geometry.max_file_bytes;
}
uint32_t xbfs_geometry_data_sectors(void) {
  return g_xbfs_geometry.data_sectors;
}
uint32_t xbfs_geometry_version(void) { return g_xbfs_geometry.version; }
uint32_t xbfs_geometry_path_max(void) { return g_xbfs_geometry.path_max; }

void xbfs_geometry_get(xbfs_geometry_t *out) { *out = g_xbfs_geometry; }

/* The one writer. This is the five set_active_v2..v6 functions' assignments
   collapsed into a single dispatch, with no value changed: v3 and v4 use their
   own path limit, v2 uses the v3 one, and every version from v4 on uses the
   full 256-byte path. Anything that is not v3..v6 -- the version dispatch's
   else branch, and mount's own reset to v2 -- takes the v2 layout. */
void xbfs_geometry_select(uint32_t version) {
  xbfs_geometry_t geometry;
  switch (version) {
    /* Version 6: the same filesystem, recorded so that it can grow.

       1 GiB of data against v5's 4 MiB, 1024 nodes against 256, and a file may
       be as large as the volume rather than 256 KiB. None of that costs
       proportional memory, because a node records extents rather than blocks
       and the bitmap holds a bit rather than a byte: about 850 KiB resident for
       256 times the capacity. */
    case XBFS_V6_VERSION:
      geometry.metadata_sectors = XBFS_V6_METADATA_SECTORS;
      geometry.max_nodes = XBFS_V6_MAX_NODES;
      geometry.file_max_blocks = XBFS_V6_DATA_SECTORS;
      geometry.max_file_bytes =
          (uint64_t)XBFS_V6_DATA_SECTORS * XBFS_SECTOR_SIZE;
      geometry.data_sectors = XBFS_V6_DATA_SECTORS;
      geometry.version = XBFS_V6_VERSION;
      geometry.path_max = XBFS_PATH_MAX;
      break;
    case XBFS_V5_VERSION:
      geometry.metadata_sectors = XBFS_V5_METADATA_SECTORS;
      geometry.max_nodes = XBFS_V5_MAX_NODES;
      geometry.file_max_blocks = XBFS_V5_FILE_MAX_BLOCKS;
      geometry.max_file_bytes =
          (uint64_t)XBFS_V5_FILE_MAX_BLOCKS * XBFS_SECTOR_SIZE;
      geometry.data_sectors = XBFS_V5_DATA_SECTORS;
      geometry.version = XBFS_V5_VERSION;
      geometry.path_max = XBFS_PATH_MAX;
      break;
    case XBFS_V4_VERSION:
      geometry.metadata_sectors = XBFS_V4_METADATA_SECTORS;
      geometry.max_nodes = XBFS_V4_MAX_NODES;
      geometry.file_max_blocks = XBFS_V4_FILE_MAX_BLOCKS;
      geometry.max_file_bytes =
          (uint64_t)XBFS_V4_FILE_MAX_BLOCKS * XBFS_SECTOR_SIZE;
      geometry.data_sectors = XBFS_V4_DATA_SECTORS;
      geometry.version = XBFS_V4_VERSION;
      geometry.path_max = XBFS_PATH_MAX;
      break;
    case XBFS_V3_VERSION:
      geometry.metadata_sectors = XBFS_V3_METADATA_SECTORS;
      geometry.max_nodes = XBFS_V3_MAX_NODES;
      geometry.file_max_blocks = XBFS_V3_FILE_MAX_BLOCKS;
      geometry.max_file_bytes =
          (uint64_t)XBFS_V3_FILE_MAX_BLOCKS * XBFS_SECTOR_SIZE;
      geometry.data_sectors = XBFS_V3_DATA_SECTORS;
      geometry.version = XBFS_V3_VERSION;
      geometry.path_max = XBFS_V3_PATH_MAX;
      break;
    default:
      geometry.metadata_sectors = XBFS_METADATA_SECTORS;
      geometry.max_nodes = XBFS_MAX_NODES;
      geometry.file_max_blocks = XBFS_FILE_MAX_BLOCKS;
      geometry.max_file_bytes =
          (uint64_t)XBFS_FILE_MAX_BLOCKS * XBFS_SECTOR_SIZE;
      geometry.data_sectors = XBFS_DATA_SECTORS;
      geometry.version = XBFS_VERSION;
      geometry.path_max = XBFS_V3_PATH_MAX;
      break;
  }
  g_xbfs_geometry = geometry;
}
