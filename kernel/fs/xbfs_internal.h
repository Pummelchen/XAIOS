/*
 * Shared declarations for xaibootFS's translation units: the path and sector
 * constants, and the small helpers every part of the filesystem uses.
 *
 * Split out of xaiboot_fs.c, which was 3890 lines. These helpers own none of
 * the filesystem's state -- no volume, no metadata buffer, no counters -- so
 * they move without an accessor layer, which the rest of that file will need
 * before it can be cut.
 */

#ifndef XAIOS_KERNEL_FS_XBFS_INTERNAL_H
#define XAIOS_KERNEL_FS_XBFS_INTERNAL_H

#include <xaios/status.h>
#include <xaios/xaiboot_fs.h>

#define XBFS_SECTOR_SIZE UINT64_C(512)
#define XBFS_PATH_MAX 256U
#define XBFS_CHECKSUM_OFFSET UINT64_C(80)
#define FNV1A64_OFFSET UINT64_C(14695981039346656037)
#define FNV1A64_PRIME UINT64_C(1099511628211)

/* Node layout: the v3 through v5 on-disk node shapes, the in-memory node every
   version is converted into, and the sizes that shape them. xaiboot_fs.c keeps
   the XBFS_*_METADATA_SECTORS defines, which the version dispatch and the
   text-reading gates both size from. */
#define XBFS_V3_PATH_MAX 96U
#define XBFS_FILE_MAX_BLOCKS 16U
#define XBFS_V4_FILE_MAX_BLOCKS 256U
#define XBFS_V5_FILE_MAX_BLOCKS 512U
/* How many runs of blocks one file may be scattered across.
 *
 * This was 16, and 16 is reachable. A volume written and rewritten for a while
 * breaks its free space into short runs, and a file that needs more of them
 * than this is refused with the volume mostly empty -- which also means it
 * cannot be snapshotted, which used to mean the machine stopped booting
 * (B-52). Taking the longest runs first made that far harder to reach; it did
 * not move the limit.
 *
 * 64 costs 768 bytes per node and about 0.75 MiB across the node table. That
 * was worth weighing when every commit rewrote the whole region; since B-48 a
 * commit writes only the sectors that changed, so a larger node table costs
 * space rather than write amplification.
 *
 * It is a raised ceiling and not a removed one, and the row says so. A 256 KiB
 * file -- the largest the whole-file path stages -- on a volume fragmented to
 * single blocks would need 512 extents, and 512 inline costs 25 MiB of
 * buffers. Removing the ceiling properly means indirect extents: a node that
 * points at an overflow block when it runs out of inline room. That is the
 * real fix and it is not this one.
 *
 * The on-disk node changes shape. Nothing migrates it: XAIOS is early enough
 * that breaking the format is cheaper than carrying a conversion, and a volume
 * written by an older build is reformatted rather than upgraded. */
#define XBFS_V6_MAX_EXTENTS 64U

typedef struct xaios_xbfs_extent {
  uint32_t start;
  uint32_t length;
} xaios_xbfs_extent_t;

typedef struct xaios_xbfs_node_v3 {
  uint32_t active;
  uint32_t snapshot_active;
  uint32_t type;
  uint32_t snapshot_type;
  uint64_t size;
  uint64_t content_hash;
  uint64_t generation;
  uint64_t snapshot_size;
  uint64_t snapshot_hash;
  uint64_t snapshot_generation;
  uint16_t block_count;
  uint16_t snapshot_block_count;
  uint16_t blocks[XBFS_FILE_MAX_BLOCKS];
  uint16_t snapshot_blocks[XBFS_FILE_MAX_BLOCKS];
  char path[XBFS_V3_PATH_MAX];
} xaios_xbfs_node_v3_t;

typedef struct xaios_xbfs_node_v4 {
  uint32_t active;
  uint32_t snapshot_active;
  uint32_t type;
  uint32_t snapshot_type;
  uint64_t size;
  uint64_t content_hash;
  uint64_t generation;
  uint64_t snapshot_size;
  uint64_t snapshot_hash;
  uint64_t snapshot_generation;
  uint16_t block_count;
  uint16_t snapshot_block_count;
  uint16_t blocks[XBFS_V4_FILE_MAX_BLOCKS];
  uint16_t snapshot_blocks[XBFS_V4_FILE_MAX_BLOCKS];
  char path[XBFS_PATH_MAX];
} xaios_xbfs_node_v4_t;

/* What a v5 volume records. Identical to what the in-memory node used to be,
   and kept because a v5 volume on a disk somewhere still has to be read: the
   live node now records extents, so v5 is a legacy layout like v3 and v4
   before it, converted on the way in and on the way out. */
typedef struct xaios_xbfs_node_v5 {
  uint32_t active;
  uint32_t snapshot_active;
  uint32_t type;
  uint32_t snapshot_type;
  uint64_t size;
  uint64_t content_hash;
  uint64_t generation;
  uint64_t snapshot_size;
  uint64_t snapshot_hash;
  uint64_t snapshot_generation;
  uint16_t block_count;
  uint16_t snapshot_block_count;
  uint16_t blocks[XBFS_V5_FILE_MAX_BLOCKS];
  uint16_t snapshot_blocks[XBFS_V5_FILE_MAX_BLOCKS];
  char path[XBFS_PATH_MAX];
} xaios_xbfs_node_v5_t;

/* What a node looks like on a v6 volume, and in memory for every version.
   Identity and integrity are unchanged from v5 -- type, size, hash,
   generation, and a snapshot copy of each. Only the record of where the bytes
   live is different. */
typedef struct xaios_xbfs_node {
  uint32_t active;
  uint32_t snapshot_active;
  uint32_t type;
  uint32_t snapshot_type;
  uint64_t size;
  uint64_t content_hash;
  uint64_t generation;
  uint64_t snapshot_size;
  uint64_t snapshot_hash;
  uint64_t snapshot_generation;
  uint32_t extent_count;
  uint32_t snapshot_extent_count;
  xaios_xbfs_extent_t extents[XBFS_V6_MAX_EXTENTS];
  xaios_xbfs_extent_t snapshot_extents[XBFS_V6_MAX_EXTENTS];
  char path[XBFS_PATH_MAX];
} xaios_xbfs_node_t;

void xbfs_bytes_zero(void *buffer, uint64_t size);
void xbfs_bytes_copy(void *dst, const void *src, uint64_t size);
int xbfs_bytes_eq(const void *a, const void *b, uint64_t size);
uint64_t xbfs_cstr_len(const char *value);
int xbfs_str_eq(const char *a, const char *b);
xaios_status_t xbfs_append_char(char *buffer, uint64_t capacity,
                                 uint64_t *offset, char value);
xaios_status_t xbfs_append_cstr(char *buffer, uint64_t capacity,
                                 uint64_t *offset, const char *value);
xaios_status_t xbfs_append_u32(char *buffer, uint64_t capacity,
                                uint64_t *offset, uint32_t value);
uint64_t xbfs_fnv1a64_extend(uint64_t hash, const void *buffer,
                               uint64_t size);
uint64_t xbfs_fnv1a64(const void *buffer, uint64_t size);
uint64_t xbfs_mfs_checksum(const void *data, uint64_t size);
void xbfs_copy_path(char dst[XBFS_PATH_MAX], const char *src);
const char *xbfs_basename_of(const char *path);
void xbfs_parent_path_of(const char *path, char parent[XBFS_PATH_MAX]);
uint64_t xbfs_blocks_for_size(uint64_t size);
int xbfs_path_is_at_or_below(const char *path, const char *root);
int xbfs_direct_child_of(const char *parent, const char *child,
                           const char **name);

/* Block-list <-> extent conversion. Both live in xaiboot_fs.c and stay there:
   the text-reading gates in tests/repository/check-code-scanning-contract.py
   match the two literals inside extents_to_blocks, which is where a block
   number is narrowed to the 16 bits an older volume records. */
uint32_t extents_from_blocks(const uint16_t *blocks, uint32_t count,
                             xaios_xbfs_extent_t *extents);
uint32_t extents_to_blocks(const xaios_xbfs_extent_t *extents, uint32_t count,
                           uint16_t *blocks, uint32_t capacity);

/* The v3/v4/v5 node codec, in xbfs_node_codec.c. Each converts between an
   older volume's node shape and the in-memory node, owns no filesystem state,
   and so needs no accessor layer. */
void import_legacy_node(xaios_xbfs_node_t *node,
                        const xaios_xbfs_node_v3_t *legacy);
void import_v4_node(xaios_xbfs_node_t *node,
                    const xaios_xbfs_node_v4_t *legacy);
void import_v5_node(xaios_xbfs_node_t *node,
                    const xaios_xbfs_node_v5_t *legacy);
void export_v5_node(xaios_xbfs_node_v5_t *legacy,
                    const xaios_xbfs_node_t *node);
void export_v4_node(xaios_xbfs_node_v4_t *legacy,
                    const xaios_xbfs_node_t *node);
void export_legacy_node(xaios_xbfs_node_v3_t *legacy,
                        const xaios_xbfs_node_t *node);

#endif /* XAIOS_KERNEL_FS_XBFS_INTERNAL_H */
