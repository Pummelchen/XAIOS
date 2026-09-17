/*
 * Private declarations shared by the split of xaiboot_fs.c into
 * xaiboot_fs.c, xbfs_format.c and xbfs_selfcheck.c.
 *
 * The volume state g_xbfs stays in xaiboot_fs.c. Its shape is here so the boot
 * self-test in xbfs_selfcheck.c can still assert sizeof(xaios_xbfs_disk_t), and
 * its scalar header crosses as a caller-owned value: xbfs_volume_header_get
 * copies the header fields out, xbfs_volume_header_set copies them back, and
 * xbfs_volume_state_reset zeroes the whole state. None of them hands out a
 * pointer into g_xbfs. The block bitmap and the node table are large buffers
 * and keep their existing call-scoped accessors, xbfs_block_bitmap and
 * xbfs_node_row, declared in xbfs_internal.h. xaiboot_fs_fsck_locked crosses
 * so the serialised xaiboot_fs_fsck entry point can stay with the other lock
 * wrappers in xaiboot_fs.c while the check itself lives in xbfs_selfcheck.c.
 */

#ifndef XAIOS_KERNEL_FS_XBFS_FORMAT_INTERNAL_H
#define XAIOS_KERNEL_FS_XBFS_FORMAT_INTERNAL_H

#include "xbfs_internal.h"
#include "xbfs_metadata_internal.h"

/* One bit per block, rounded to whole bytes. */
#define XBFS_BITMAP_BYTES ((XBFS_V6_DATA_SECTORS + 7U) / 8U)

/* A/B metadata.

   The metadata region is written in place, so a write torn by power loss
   leaves it neither valid nor blank. Mount then refuses to continue, because
   formatting would destroy the volume, and the result is a filesystem that
   cannot be mounted or repaired. A second copy removes that: writes alternate
   between the two, so a tear can only ever damage the copy that is not
   currently authoritative, and mount falls back to the survivor.

   The mirror lives past the data region, so every existing offset is
   unchanged and an existing volume keeps mounting. The write sequence sits in
   the slack at the end of the region for the same reason: appending a header
   field would have shifted the bitmap and every node after it. A volume
   written before this reads sequence 0, which simply makes it the older copy.

   Alternating rather than writing both copies each time keeps the write cost
   identical to before. The trade is that a torn write falls back to the
   previous commit instead of the one being written, which is the same
   guarantee an interrupted commit already had. */
#define XBFS_METADATA_SLOTS 2U
#define XBFS_MAX_FILE_BYTES (XBFS_FILE_MAX_BLOCKS * XBFS_SECTOR_SIZE)

typedef struct xaios_xbfs_disk {
  char magic[XBFS_MAGIC_LEN];
  uint32_t version;
  uint32_t sector_size;
  uint32_t metadata_sectors;
  uint32_t max_nodes;
  uint64_t start_sector;
  uint64_t journal_header_sector;
  uint64_t journal_data_sector;
  uint64_t data_start_sector;
  uint64_t data_sectors;
  uint64_t generation;
  uint64_t committed_generation;
  uint64_t checksum;
  uint8_t block_bitmap[XBFS_DATA_SECTORS];
  xaios_xbfs_node_v3_t nodes[XBFS_MAX_NODES];
} xaios_xbfs_disk_t;

typedef struct xaios_xbfs_state {
  char magic[XBFS_MAGIC_LEN];
  uint32_t version;
  uint32_t sector_size;
  uint32_t metadata_sectors;
  uint32_t max_nodes;
  uint64_t start_sector;
  uint64_t journal_header_sector;
  uint64_t journal_data_sector;
  uint64_t data_start_sector;
  uint64_t data_sectors;
  uint64_t generation;
  uint64_t committed_generation;
  uint64_t checksum;
  /* A bit per block. Every version up to v5 spent a byte, which for a
     gigabyte of data would be two megabytes resident; a bit costs 256 KiB,
     and that eight-fold difference is what makes a volume this size
     affordable. */
  uint8_t block_bitmap[XBFS_BITMAP_BYTES];
  xaios_xbfs_node_t nodes[XBFS_V6_MAX_NODES];
} xaios_xbfs_state_t;

typedef struct xaios_xbfs_journal_v3 {
  char magic[XBFS_MAGIC_LEN];
  uint32_t version;
  uint32_t state;
  uint32_t op;
  uint32_t reserved;
  uint64_t size;
  uint64_t content_hash;
  uint64_t checksum;
  char path[XBFS_V3_PATH_MAX];
  uint8_t padding[368];
} xaios_xbfs_journal_v3_t;

/* The scalar header of the volume state, as a value in or out. get copies
   g_xbfs's header fields into the caller's local, set copies them back, and
   reset zeroes the whole state -- bitmap and node table included, which the
   format and metadata-read paths both need. */
typedef struct xbfs_volume_header {
  char magic[XBFS_MAGIC_LEN];
  uint32_t version;
  uint32_t sector_size;
  uint32_t metadata_sectors;
  uint32_t max_nodes;
  uint64_t start_sector;
  uint64_t journal_header_sector;
  uint64_t journal_data_sector;
  uint64_t data_start_sector;
  uint64_t data_sectors;
  uint64_t generation;
  uint64_t committed_generation;
  uint64_t checksum;
} xbfs_volume_header_t;

void xbfs_volume_state_reset(void);
void xbfs_volume_header_get(xbfs_volume_header_t *out);
void xbfs_volume_header_set(const xbfs_volume_header_t *in);

/* Defined in xbfs_selfcheck.c; the lock wrapper in xaiboot_fs.c calls it. */
xaios_xbfs_fsck_result_t xaiboot_fs_fsck_locked(void);

#endif /* XAIOS_KERNEL_FS_XBFS_FORMAT_INTERNAL_H */
