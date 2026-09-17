#include <xaios/assert.h>
#include <xaios/block_device.h>
#include <xaios/klog.h>
#include <xaios/xaiboot_fs.h>

#include "xbfs_internal.h"
#include "xbfs_metadata_internal.h"
#include "xbfs_file_io_internal.h"
#include "xbfs_fd_internal.h"
#include "xbfs_volume_internal.h"
#include "xbfs_format_internal.h"
#include <xaios/spinlock.h>
#include <xaios/virtio_blk.h>

#define XBFS_VERSION 2U
#define XBFS_METADATA_SECTORS UINT64_C(16)
#define XBFS_DATA_SECTORS 96U
#define XBFS_MAX_NODES 32U
#define XBFS_V3_METADATA_SECTORS 32U
#define XBFS_V3_DATA_SECTORS 256U
#define XBFS_V3_MAX_NODES 64U
#define XBFS_V3_FILE_MAX_BLOCKS 16U
#define XBFS_V3_MAX_FILE_BYTES (XBFS_V3_FILE_MAX_BLOCKS * XBFS_SECTOR_SIZE)
#define XBFS_V3_VERSION 3U
#define XBFS_V4_METADATA_SECTORS 384U
#define XBFS_V4_DATA_SECTORS 4096U
#define XBFS_V4_MAX_NODES 128U
#define XBFS_V4_MAX_FILE_BYTES (XBFS_V4_FILE_MAX_BLOCKS * XBFS_SECTOR_SIZE)
#define XBFS_V4_VERSION 4U
#define XBFS_V5_METADATA_SECTORS 1280U
#define XBFS_V5_DATA_SECTORS 8192U
#define XBFS_V5_MAX_NODES 256U
#define XBFS_V5_MAX_FILE_BYTES (XBFS_V5_FILE_MAX_BLOCKS * XBFS_SECTOR_SIZE)
#define XBFS_V5_VERSION 5U

/* Version 6: extents instead of a direct block list.
 *
 * Every version up to v5 gives a node a fixed array of block numbers, and that
 * array is why the filesystem cannot grow. Two limits come out of it at once:
 * a 16-bit block number caps a volume at 32 MiB, and a file cannot exceed its
 * array -- 512 blocks, so 256 KiB. Widening both makes matters worse, because
 * a node carries its list and a snapshot copy inline and the whole table is
 * resident: 32-bit numbers with 8192 blocks across 4096 nodes is 257 MiB of
 * metadata in memory, on machines with two gigabytes.
 *
 * An extent -- a start and a length -- describes a run of blocks in eight
 * bytes however long the run is. Sixteen describe a file of any size the
 * volume holds, and shrink the node rather than growing it. A bit per block
 * rather than a byte costs 256 KiB for a gigabyte of data, so the resident
 * total is about 850 KiB for 256 times v5's capacity.
 *
 * Older volumes keep their own encoding. A v5 volume is read and written as
 * v5, with its block lists converted to extents in memory and back on the way
 * out; only a newly formatted volume is v6. That avoids rewriting a
 * filesystem in place, which is the one operation on this data nobody should
 * have to trust. */
#define XBFS_V6_VERSION 6U
#define XBFS_V6_MAX_NODES 1024U
#define XBFS_V6_DATA_SECTORS 2097152U
/* Sized for the node table above plus the block bitmap, with room to spare.
   Raising XBFS_V6_MAX_EXTENTS grows every node, so this grows with it; a
   region too small to hold the table it describes is a format that cannot be
   written. */
#define XBFS_V6_METADATA_SECTORS 3584U
#define XBFS_V6_MAX_FILE_BYTES \
  ((uint64_t)XBFS_V6_DATA_SECTORS * XBFS_SECTOR_SIZE)

/* The append path, and the switch that turns it off.
 *
 * Off, every write through a file descriptor goes back to reading the whole
 * file and writing all of it out again, which is what this filesystem did
 * before B-45. It exists so the gate can measure both behaviours from one
 * tree, one workload and one instrument, rather than comparing today's numbers
 * against numbers written down yesterday on a different build. Set through
 * XAIOS_KERNEL_CFLAGS_EXTRA; the shipped default is on. */


static xaios_xbfs_state_t g_xbfs;
/* The counter storage lives in xbfs_state.c behind xbfs_stat_*; see
   xbfs_internal.h. Appends served without rewriting the file are counted
   apart from XBFS_STAT_WRITE, which still counts both, so a gate can tell
   "the fast path ran" from "the fast path is there and never runs". */

/* The metadata buffer, its shadow, the slot/sequence/mirror scalars and the
   journal live in xbfs_metadata.c behind the accessors declared in
   xbfs_metadata_internal.h. */
static xaios_spinlock_t g_xaiboot_fs_lock = XAIOS_SPINLOCK_INIT;

/* The active geometry lives in xbfs_state.c behind xbfs_geometry_*; see
   xbfs_internal.h. The version dispatch selects it. The persistent device,
   its mount count and the mount flags live in xbfs_mount.c behind the setters
   declared in xbfs_volume_internal.h. */



/* The five set_active_v2..v6 writers are now the single
   xbfs_geometry_select call at each dispatch site. The metadata/journal sector
   arithmetic that used to sit here is in xbfs_metadata.c. */


/* The volume state an extracted module cannot reach directly.
 *
 * g_xbfs and the open-file table stay here; the mount flags and the persistent
 * device are in xbfs_mount.c. Two of these hand back a pointer into live
 * mutable state -- xbfs_node_row into the node table and xbfs_block_bitmap
 * into the block bitmap -- and each is good for the duration of the call that
 * asked for it and no longer: the caller must not retain it, cache it or hand
 * it to another translation unit. Everything else is a value in or out. None
 * of these takes the volume lock; every caller already holds it, exactly as
 * the static code these replaced did. */
xaios_xbfs_node_t *xbfs_node_row(uint32_t index) {
  return &g_xbfs.nodes[index];
}

uint8_t *xbfs_block_bitmap(void) { return g_xbfs.block_bitmap; }

uint64_t xbfs_block_bitmap_bytes(void) { return sizeof(g_xbfs.block_bitmap); }

uint64_t xbfs_generation_get(void) { return g_xbfs.generation; }

uint64_t xbfs_generation_take(void) { return g_xbfs.generation++; }

/* The volume state xbfs_mount.c and xbfs_snapshot.c read and write but do
   not own: the stored checksum, the last committed generation, and a bump of
   the live generation. All are values; none hands back a pointer into g_xbfs.
   None takes the volume lock; every caller already holds it. */
uint64_t xbfs_volume_checksum_get(void) { return g_xbfs.checksum; }

uint64_t xbfs_volume_committed_generation_get(void) {
  return g_xbfs.committed_generation;
}

void xbfs_volume_committed_generation_set(uint64_t generation) {
  g_xbfs.committed_generation = generation;
}

void xbfs_volume_generation_bump(void) { ++g_xbfs.generation; }
/* The scalar header of the volume state, for the codec in xbfs_format.c that
   serialises it field by field. get copies the scalars out, set copies them
   back, and reset zeroes the whole state -- bitmap and node table included,
   which the format and metadata-read paths need. None of them hands out a
   pointer into g_xbfs; the bitmap and the node rows keep their own
   call-scoped accessors above. */
void xbfs_volume_state_reset(void) {
  xbfs_bytes_zero(&g_xbfs, sizeof(g_xbfs));
}

void xbfs_volume_header_get(xbfs_volume_header_t *out) {
  xbfs_bytes_copy(out->magic, g_xbfs.magic, XBFS_MAGIC_LEN);
  out->version = g_xbfs.version;
  out->sector_size = g_xbfs.sector_size;
  out->metadata_sectors = g_xbfs.metadata_sectors;
  out->max_nodes = g_xbfs.max_nodes;
  out->start_sector = g_xbfs.start_sector;
  out->journal_header_sector = g_xbfs.journal_header_sector;
  out->journal_data_sector = g_xbfs.journal_data_sector;
  out->data_start_sector = g_xbfs.data_start_sector;
  out->data_sectors = g_xbfs.data_sectors;
  out->generation = g_xbfs.generation;
  out->committed_generation = g_xbfs.committed_generation;
  out->checksum = g_xbfs.checksum;
}

void xbfs_volume_header_set(const xbfs_volume_header_t *in) {
  xbfs_bytes_copy(g_xbfs.magic, in->magic, XBFS_MAGIC_LEN);
  g_xbfs.version = in->version;
  g_xbfs.sector_size = in->sector_size;
  g_xbfs.metadata_sectors = in->metadata_sectors;
  g_xbfs.max_nodes = in->max_nodes;
  g_xbfs.start_sector = in->start_sector;
  g_xbfs.journal_header_sector = in->journal_header_sector;
  g_xbfs.journal_data_sector = in->journal_data_sector;
  g_xbfs.data_start_sector = in->data_start_sector;
  g_xbfs.data_sectors = in->data_sectors;
  g_xbfs.generation = in->generation;
  g_xbfs.committed_generation = in->committed_generation;
  g_xbfs.checksum = in->checksum;
}

/* FNV-1a resumed from where it left off, which is what makes an append cheap.
 *
 * xbfs_fnv1a64(A followed by B) is xbfs_fnv1a64_extend(xbfs_fnv1a64(A), B). The fold starts
 * at a fixed basis, carries no length, and has no finalisation step, so the
 * state after the last byte of A is exactly the state the first byte of B
 * would be folded into. A file's recorded content_hash is therefore a
 * resumable position in its own hash, and adding to a file does not require
 * reading the file back to re-hash it. That property is the whole reason the
 * append path below can leave the rest of the file alone. */




uint64_t xbfs_node_count_by_type(uint32_t type) {
  uint64_t count = 0;
  for (uint32_t i = 0; i < xbfs_geometry_max_nodes(); ++i) {
    if (g_xbfs.nodes[i].active != 0 && g_xbfs.nodes[i].type == type) {
      ++count;
    }
  }
  return count;
}



/* Turn a list of block numbers into extents, joining consecutive blocks into
   one run. This is how a volume written by an older version is read: its nodes
   record a block at a time, and a file laid down in order becomes a single
   extent. A file scattered across the volume becomes several, and one too
   fragmented to describe in XBFS_V6_MAX_EXTENTS runs is refused rather than
   truncated -- losing the tail of a file quietly is worse than declining to
   open it. */
uint32_t extents_from_blocks(const uint16_t *blocks, uint32_t count,
                             xaios_xbfs_extent_t *extents) {
  uint32_t used = 0U;
  for (uint32_t index = 0U; index < count; ++index) {
    if (used != 0U &&
        extents[used - 1U].start + extents[used - 1U].length ==
            (uint32_t)blocks[index]) {
      ++extents[used - 1U].length;
      continue;
    }
    if (used >= XBFS_V6_MAX_EXTENTS) return 0U;
    extents[used].start = (uint32_t)blocks[index];
    extents[used].length = 1U;
    ++used;
  }
  return used;
}

/* And back again, for writing metadata to a volume that records blocks. A run
   that will not fit in the older format's array is refused here rather than
   written short. */
uint32_t extents_to_blocks(const xaios_xbfs_extent_t *extents,
                           uint32_t count, uint16_t *blocks,
                           uint32_t capacity) {
  uint32_t written = 0U;
  for (uint32_t e = 0U; e < count && e < XBFS_V6_MAX_EXTENTS; ++e) {
    for (uint32_t offset = 0U; offset < extents[e].length; ++offset) {
      if (written >= capacity) return UINT32_MAX;
      uint64_t block = (uint64_t)extents[e].start + offset;
      if (block > UINT16_MAX) return UINT32_MAX;
      blocks[written++] = (uint16_t)block;
    }
  }
  return written;
}



static xaios_status_t xaiboot_fs_commit_locked(const char *label) {
  return xbfs_snapshot_commit(label);
}

static xaios_status_t xaiboot_fs_rollback_locked(void) {
  return xbfs_snapshot_rollback();
}

static xaios_status_t xaiboot_fs_mkdir_locked(const char *path) {
  return xbfs_create_dir(path);
}

static xaios_status_t xaiboot_fs_write_locked(const char *path, const void *data, uint64_t size) {
  return xbfs_write_file_locked(path, data, size);
}

static xaios_status_t xaiboot_fs_read_locked(const char *path, void *buffer, uint64_t buffer_size, uint64_t *out_size) {
  return xbfs_read_file(path, buffer, buffer_size, out_size);
}

static xaios_status_t xaiboot_fs_delete_locked(const char *path) {
  return xbfs_delete_node(path);
}

static xaios_status_t xaiboot_fs_delete_tree_locked(const char *path) {
  return xbfs_delete_tree(path);
}

static xaios_status_t xaiboot_fs_rename_locked(const char *old_path, const char *new_path) {
  return xbfs_rename_node(old_path, new_path);
}

static xaios_status_t xaiboot_fs_stat_locked(const char *path, xaios_xbfs_stat_t *stat) {
  return xbfs_stat_node(path, stat);
}

static xaios_status_t xaiboot_fs_list_locked(const char *path, char *buffer, uint64_t buffer_size, uint64_t *out_size) {
  return xbfs_list_dir(path, buffer, buffer_size, out_size);
}


/* Serialised public entry points.
   The volume is reachable from every CPU through the filesystem syscalls and
   from kernel services, yet its node table, open-file table and block bitmap
   were mutated with no mutual exclusion at all. Each entry point now runs
   under one lock. The bodies above assume the lock is already held and must
   not be called directly. xaiboot_fs_self_test stays outside deliberately: it
   drives these same entry points and runs single threaded during boot. */
xaios_status_t xaiboot_fs_record_service_state(const char *name, const char *state) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_record_service_state_locked(name, state);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_record_workspace_state(uint32_t workspace_id, const char *revision) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_record_workspace_state_locked(workspace_id, revision);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_record_update_state(const char *policy) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_record_update_state_locked(policy);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_record_update_transaction(uint32_t generation, const char *state, const char *target, const char *rollback_label) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_record_update_transaction_locked(generation, state, target, rollback_label);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_record_admin_status(const char *service, const char *state, uint32_t starts, uint32_t restarts, uint32_t logs) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_record_admin_status_locked(service, state, starts, restarts, logs);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_commit(const char *label) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_commit_locked(label);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_rollback(void) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_rollback_locked();
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_mkdir(const char *path) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_mkdir_locked(path);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_write(const char *path, const void *data, uint64_t size) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_write_locked(path, data, size);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_read(const char *path, void *buffer, uint64_t buffer_size, uint64_t *out_size) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_read_locked(path, buffer, buffer_size, out_size);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_delete(const char *path) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_delete_locked(path);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_delete_tree(const char *path) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_delete_tree_locked(path);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_rename(const char *old_path, const char *new_path) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_rename_locked(old_path, new_path);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_stat(const char *path, xaios_xbfs_stat_t *stat) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_stat_locked(path, stat);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_list(const char *path, char *buffer, uint64_t buffer_size, uint64_t *out_size) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xaiboot_fs_list_locked(path, buffer, buffer_size, out_size);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

int64_t xaiboot_fs_open(const char *path, uint32_t flags) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  int64_t result = xbfs_fd_open_locked(path, flags);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

int64_t xaiboot_fs_read_fd(uint32_t fd, void *buffer, uint64_t size) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  int64_t result = xbfs_fd_read_locked(fd, buffer, size);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

int64_t xaiboot_fs_write_fd(uint32_t fd, const void *buffer, uint64_t size) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  int64_t result = xbfs_fd_write_locked(fd, buffer, size);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_seek(uint32_t fd, uint64_t offset) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xbfs_fd_seek_locked(fd, offset);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_close(uint32_t fd) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xbfs_fd_close_locked(fd);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_mount_device(const char *identifier) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xbfs_mount_device_locked(identifier);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

/* Release a mounted device, flushing first. The slot bookkeeping is reset so
   a later mount re-derives which copy is authoritative from the volume rather
   than from whatever the previous mount happened to leave behind. */
xaios_status_t xaiboot_fs_unmount(void) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xbfs_mount_unmount_locked();
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_status_t xaiboot_fs_mount_persistent(uint32_t slot) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_status_t result = xbfs_mount_persistent_locked(slot);
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}

xaios_xbfs_fsck_result_t xaiboot_fs_fsck(void) {
  xaios_spin_lock(&g_xaiboot_fs_lock);
  xaios_xbfs_fsck_result_t result = xaiboot_fs_fsck_locked();
  xaios_spin_unlock(&g_xaiboot_fs_lock);
  return result;
}
