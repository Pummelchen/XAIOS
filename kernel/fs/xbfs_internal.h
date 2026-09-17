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

/* The append path switch and the node-type and mount-flag values the
   namespace code reads. These lived in xaiboot_fs.c; xbfs_dir.c and
   xbfs_alloc.c need them, so they are declared where every translation unit
   can see them. The default stays guarded so a build that sets
   -DXBFS_APPEND_IN_PLACE=0 still turns the append path off. */
#ifndef XBFS_APPEND_IN_PLACE
#define XBFS_APPEND_IN_PLACE 1
#endif
#define XBFS_NODE_FREE 0U
#define XBFS_NODE_DIR 1U
#define XBFS_NODE_FILE 2U
#define XBFS_MOUNT_READ_WRITE 1U

/* The geometry every on-disk version records.
 *
 * xbfs_state.c builds the mounted volume's geometry from these, so the values
 * have to be visible in that translation unit as well as in xaiboot_fs.c. The
 * XBFS_*_METADATA_SECTORS macros are deliberately repeated in xaiboot_fs.c:
 * two text-scanning gates read them out of that file. The two copies are the
 * same token sequence here, so an edit to one without the other is a
 * macro-redefinition error under -Werror rather than a silent drift. */
#define XBFS_VERSION 2U
#define XBFS_METADATA_SECTORS UINT64_C(16)
#define XBFS_DATA_SECTORS 96U
#define XBFS_MAX_NODES 32U
#define XBFS_V3_VERSION 3U
#define XBFS_V3_METADATA_SECTORS 32U
#define XBFS_V3_DATA_SECTORS 256U
#define XBFS_V3_MAX_NODES 64U
#define XBFS_V3_FILE_MAX_BLOCKS 16U
#define XBFS_V4_VERSION 4U
#define XBFS_V4_METADATA_SECTORS 384U
#define XBFS_V4_DATA_SECTORS 4096U
#define XBFS_V4_MAX_NODES 128U
#define XBFS_V5_VERSION 5U
#define XBFS_V5_METADATA_SECTORS 1280U
#define XBFS_V5_DATA_SECTORS 8192U
#define XBFS_V5_MAX_NODES 256U
#define XBFS_V6_VERSION 6U
#define XBFS_V6_METADATA_SECTORS 3584U
#define XBFS_V6_MAX_NODES 1024U
#define XBFS_V6_DATA_SECTORS 2097152U

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

/* The mounted volume's geometry, owned by xbfs_state.c.
 *
 * These were seven `g_active_*` globals written in exactly five places, one
 * per format (the v2..v6 `set_active_*` functions), and read in 26 functions.
 * The values are what the version dispatch decides on the mount path, so the
 * five writers collapse into one `select` and every reader goes through a
 * getter. `get` exists for the functions that read three or more fields at
 * once; the per-field getters keep a single-field call site mechanical. */
typedef struct xaios_xbfs_geometry {
  uint32_t metadata_sectors;
  uint32_t max_nodes;
  uint32_t file_max_blocks;
  uint32_t data_sectors;
  uint32_t version;
  uint32_t path_max;
  uint64_t max_file_bytes;
} xbfs_geometry_t;

/* Replace the five set_active_v* writers. Any version that is not v3..v6
   selects the v2 geometry, which is what those writers' else branch did. */
void xbfs_geometry_select(uint32_t version);
uint32_t xbfs_geometry_metadata_sectors(void);
uint32_t xbfs_geometry_max_nodes(void);
uint32_t xbfs_geometry_file_max_blocks(void);
uint64_t xbfs_geometry_max_file_bytes(void);
uint32_t xbfs_geometry_data_sectors(void);
uint32_t xbfs_geometry_version(void);
uint32_t xbfs_geometry_path_max(void);
void xbfs_geometry_get(xbfs_geometry_t *out);

/* The filesystem's counters, owned by xbfs_state.c.
 *
 * One enum-indexed interface rather than twenty-three named globals: these are
 * read from roughly forty functions, so a file cut cannot move them without
 * one. `bump` is the common case, a counter that only ever increments; `add`
 * covers the one site that folds in a total it already computed (delete_tree's
 * node count). Nothing here is reset on a mount, so a caller that wants the
 * since-test figures calls reset_all. */
typedef enum {
  XBFS_STAT_MOUNT = 0,
  XBFS_STAT_FORMAT,
  XBFS_STAT_BOOT_LOAD,
  XBFS_STAT_WRITE,
  XBFS_STAT_APPEND,
  XBFS_STAT_APPEND_FALLBACK,
  XBFS_STAT_READ,
  XBFS_STAT_DELETE,
  XBFS_STAT_COMMIT,
  XBFS_STAT_ROLLBACK,
  XBFS_STAT_REJECT,
  XBFS_STAT_CHECKSUM_ERROR,
  XBFS_STAT_ALLOCATION,
  XBFS_STAT_FREE,
  XBFS_STAT_REPLAY,
  XBFS_STAT_JOURNAL_WRITE,
  XBFS_STAT_MULTI_SECTOR_FILE,
  XBFS_STAT_STATE_RECORD,
  XBFS_STAT_RENAME,
  XBFS_STAT_LIST,
  XBFS_STAT_STAT,
  XBFS_STAT_OPEN,
  XBFS_STAT_CLOSE,
  XBFS_STAT_COUNT
} xbfs_stat_t;

uint64_t xbfs_stat_get(xbfs_stat_t id);
void xbfs_stat_bump(xbfs_stat_t id);
void xbfs_stat_add(xbfs_stat_t id, uint64_t delta);
void xbfs_stat_reset_all(void);

/* The record family, in xbfs_record.c.
 *
 * These are the builders for the small text records the commit path writes
 * under /state, and the canonical `k_*` descriptions the boot self-test
 * writes and compares those records against. The serialised entry points stay
 * in xaiboot_fs.c and still take the volume lock around each builder, so the
 * builders keep their `_locked` names and must be called with the lock held.
 *
 * They own no state. `write_file` was the one function they called back into,
 * so its linkage changed and it crosses as xbfs_write_file_locked; everything
 * else they need is an accessor above. Each description is declared with the
 * size of the literal it is defined from rather than as an incomplete array,
 * because the self-test still sizes them with `sizeof`. */
#define XBFS_RECORD_CONFIG_V1 "mode=full-os\nmutable=true\n"
#define XBFS_RECORD_SERVICE_RUNNING "service=/svc/source-index\nstate=running\n"
#define XBFS_RECORD_SERVICE_RESTARTING \
  "service=/svc/source-index\nstate=restarting\n"
#define XBFS_RECORD_UPDATE_STATE \
  "policy=signed-update-required\nrollback=enabled\n"
#define XBFS_RECORD_BOOT_LOG "boot=ok\n"
#define XBFS_RECORD_REPLAYED_STATE "service=/svc/replayed\nstate=recovered\n"

extern const char k_config_v1[sizeof(XBFS_RECORD_CONFIG_V1)];
extern const char k_service_running[sizeof(XBFS_RECORD_SERVICE_RUNNING)];
extern const char k_service_restarting[sizeof(XBFS_RECORD_SERVICE_RESTARTING)];
extern const char k_update_state[sizeof(XBFS_RECORD_UPDATE_STATE)];
extern const char k_boot_log[sizeof(XBFS_RECORD_BOOT_LOG)];
extern const char k_replayed_state[sizeof(XBFS_RECORD_REPLAYED_STATE)];

xaios_status_t xbfs_write_file_locked(const char *path, const void *data,
                                      uint64_t size);

xaios_status_t xaiboot_fs_record_service_state_locked(const char *name,
                                                      const char *state);
xaios_status_t xaiboot_fs_record_workspace_state_locked(uint32_t workspace_id,
                                                        const char *revision);
xaios_status_t xaiboot_fs_record_update_state_locked(const char *policy);
xaios_status_t xaiboot_fs_record_update_transaction_locked(
    uint32_t generation, const char *state, const char *target,
    const char *rollback_label);
xaios_status_t xaiboot_fs_record_admin_status_locked(
    const char *service, const char *state, uint32_t starts, uint32_t restarts,
    uint32_t logs);

/* The directory/namespace module, in xbfs_dir.c.
 *
 * Path validation and normalization, node lookup, and the create/delete/
 * rename/stat/list operations. The bodies are unchanged from xaiboot_fs.c;
 * only the names that cross a translation unit gained the xbfs_ prefix. Every
 * entry point runs with the volume lock held, exactly as the static functions
 * it replaces did, and none of them takes the lock itself. */
xaios_status_t xbfs_validate_path(const char *path);
xaios_status_t xbfs_normalize_path(const char *path,
                                   char normalized[XBFS_PATH_MAX]);
xaios_xbfs_node_t *xbfs_find_node(const char *path, uint32_t include_snapshot);
xaios_xbfs_node_t *xbfs_find_free_node(void);
/* Both return a pointer into the live node table, the same pointer
   xbfs_node_row hands back, and it is good only for the duration of the call
   that asked for it: the caller must not retain it. */
int xbfs_parent_exists_for(const char *path);
xaios_status_t xbfs_create_dir(const char *path);
xaios_status_t xbfs_ensure_base_directories(void);
xaios_status_t xbfs_delete_node(const char *path);
xaios_status_t xbfs_delete_tree(const char *path);
xaios_status_t xbfs_rename_node(const char *old_path, const char *new_path);
xaios_status_t xbfs_stat_node(const char *path, xaios_xbfs_stat_t *stat);
xaios_status_t xbfs_list_dir(const char *path, char *buffer,
                             uint64_t buffer_size, uint64_t *out_size);
/* How many rename-staging rows xbfs_dir.c holds, so the self-test in
   xaiboot_fs.c can assert a format's node maximum still fits it. */
uint64_t xbfs_dir_path_transaction_rows(void);

/* The volume state xbfs_dir.c and xbfs_alloc.c cannot reach directly.
 *
 * The node table, the block bitmap, the generation, the mount flags and the
 * open-file table all live in xaiboot_fs.c. Two of these hand back a pointer
 * into live mutable state -- xbfs_node_row into the node table, xbfs_block_bitmap
 * into the block bitmap -- and each is good only for the duration of the call
 * that asked for it: the caller must not retain it, cache it or hand it to
 * another translation unit. Everything else is a value in or out. None of
 * these takes the volume lock; every caller already holds it, as the static
 * code these replaced did. */
xaios_xbfs_node_t *xbfs_node_row(uint32_t index);
uint8_t *xbfs_block_bitmap(void);
uint64_t xbfs_block_bitmap_bytes(void);
uint64_t xbfs_generation_get(void);
uint64_t xbfs_generation_take(void);
uint32_t xbfs_mounted(void);
uint32_t xbfs_mount_flags(void);
xaios_status_t xbfs_write_metadata(void);
/* Forget the open handles under a deleted subtree, and move the ones under a
   renamed subtree to its new path. These are the loops over the open-file
   table that used to sit in delete_tree and rename_node. */
void xbfs_open_files_forget_tree(const char *root);
void xbfs_open_files_rebase(const char *old_path, const char *new_path);

/* The allocation/extent module, in xbfs_alloc.c. Each of these was a static
   function in xaiboot_fs.c and gains the xbfs_ prefix; the bodies are
   unchanged. */
uint32_t xbfs_block_used(uint64_t block);
void xbfs_block_release(uint64_t block);
void xbfs_bitmap_from_bytes(const uint8_t *source, uint64_t blocks);
void xbfs_bitmap_to_bytes(uint8_t *destination, uint64_t blocks);
uint64_t xbfs_block_count_used(void);
uint64_t xbfs_extent_blocks(const xaios_xbfs_extent_t *extents, uint32_t count);
uint64_t xbfs_extent_block_at(const xaios_xbfs_extent_t *extents,
                              uint32_t count, uint64_t index);
xaios_status_t xbfs_allocate_extents(uint64_t blocks_needed,
                                     xaios_xbfs_extent_t *extents,
                                     uint32_t *out_count);
void xbfs_free_extents(const xaios_xbfs_extent_t *extents, uint32_t count);
#if XBFS_APPEND_IN_PLACE
xaios_status_t xbfs_extend_extents(xaios_xbfs_extent_t *extents,
                                   uint32_t *extent_count,
                                   uint64_t blocks_needed);
#endif

#endif /* XAIOS_KERNEL_FS_XBFS_INTERNAL_H */
