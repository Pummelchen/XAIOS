#include <xaios/assert.h>
#include <xaios/block_device.h>
#include <xaios/klog.h>
#include <xaios/xaiboot_fs.h>

#include "xbfs_internal.h"
#include "xbfs_metadata_internal.h"
#include "xbfs_file_io_internal.h"
#include "xbfs_fd_internal.h"
#include "xbfs_volume_internal.h"
#include <xaios/spinlock.h>
#include <xaios/virtio_blk.h>

#define XBFS_VERSION 2U
#define XBFS_METADATA_SECTORS UINT64_C(16)
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
#define XBFS_DATA_SECTORS 96U
#define XBFS_MAX_NODES 32U
#define XBFS_MAX_FILE_BYTES (XBFS_FILE_MAX_BLOCKS * XBFS_SECTOR_SIZE)
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
/* One bit per block, rounded to whole bytes. */
#define XBFS_BITMAP_BYTES ((XBFS_V6_DATA_SECTORS + 7U) / 8U)

/* The append path, and the switch that turns it off.
 *
 * Off, every write through a file descriptor goes back to reading the whole
 * file and writing all of it out again, which is what this filesystem did
 * before B-45. It exists so the gate can measure both behaviours from one
 * tree, one workload and one instrument, rather than comparing today's numbers
 * against numbers written down yesterday on a different build. Set through
 * XAIOS_KERNEL_CFLAGS_EXTRA; the shipped default is on. */


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


static xaios_status_t read_metadata_slot(uint32_t slot) {
  uint8_t first_sector[XBFS_SECTOR_SIZE];
  uint64_t start = xbfs_metadata_slot_start_sector(slot);
  if (xbfs_blk_read(start, first_sector, sizeof(first_sector)) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  uint32_t version = 0;
  xbfs_bytes_copy(&version, first_sector + XBFS_MAGIC_LEN, sizeof(version));
  if (version == XBFS_V6_VERSION) {
    xbfs_geometry_select(XBFS_V6_VERSION);
  } else if (version == XBFS_V5_VERSION) {
    xbfs_geometry_select(XBFS_V5_VERSION);
  } else if (version == XBFS_V4_VERSION) {
    xbfs_geometry_select(XBFS_V4_VERSION);
  } else if (version == XBFS_V3_VERSION) {
    xbfs_geometry_select(XBFS_V3_VERSION);
  } else {
    xbfs_geometry_select(XBFS_VERSION);
  }
  xbfs_geometry_t geometry;
  xbfs_geometry_get(&geometry);

  uint32_t sectors = geometry.metadata_sectors;
  uint8_t *metadata = xbfs_metadata_buffer();
  xbfs_bytes_zero(metadata, xbfs_metadata_buffer_bytes());
  xbfs_bytes_copy(metadata, first_sector, XBFS_SECTOR_SIZE);
  for (uint32_t i = 1; i < sectors; ++i) {
    if (xbfs_blk_read(start + i,
                 metadata + i * XBFS_SECTOR_SIZE,
                 XBFS_SECTOR_SIZE) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
  }
  uint64_t sequence = 0U;
  xbfs_bytes_copy(&sequence,
             metadata + xbfs_metadata_sequence_offset(), 8);
  xbfs_metadata_set_sequence(sequence);
  uint64_t total_bytes = (uint64_t)sectors * XBFS_SECTOR_SIZE;
  xbfs_metadata_set_verified_checksum(
      xbfs_mfs_checksum(metadata, total_bytes));
  xbfs_bytes_zero(&g_xbfs, sizeof(g_xbfs));
  uint64_t p = 0;
  xbfs_bytes_copy(g_xbfs.magic, metadata + p, XBFS_MAGIC_LEN); p += XBFS_MAGIC_LEN;
  xbfs_bytes_copy(&g_xbfs.version, metadata + p, 4); p += 4;
  xbfs_bytes_copy(&g_xbfs.sector_size, metadata + p, 4); p += 4;
  xbfs_bytes_copy(&g_xbfs.metadata_sectors, metadata + p, 4); p += 4;
  xbfs_bytes_copy(&g_xbfs.max_nodes, metadata + p, 4); p += 4;
  xbfs_bytes_copy(&g_xbfs.start_sector, metadata + p, 8); p += 8;
  xbfs_bytes_copy(&g_xbfs.journal_header_sector, metadata + p, 8); p += 8;
  xbfs_bytes_copy(&g_xbfs.journal_data_sector, metadata + p, 8); p += 8;
  xbfs_bytes_copy(&g_xbfs.data_start_sector, metadata + p, 8); p += 8;
  xbfs_bytes_copy(&g_xbfs.data_sectors, metadata + p, 8); p += 8;
  xbfs_bytes_copy(&g_xbfs.generation, metadata + p, 8); p += 8;
  xbfs_bytes_copy(&g_xbfs.committed_generation, metadata + p, 8); p += 8;
  xbfs_bytes_copy(&g_xbfs.checksum, metadata + p, 8); p += 8;
  if (version == XBFS_V6_VERSION) {
    xbfs_bytes_copy(g_xbfs.block_bitmap, metadata + p,
               (geometry.data_sectors + 7U) / 8U);
    p += (geometry.data_sectors + 7U) / 8U;
  } else {
    xbfs_bitmap_from_bytes(metadata + p, geometry.data_sectors);
    p += geometry.data_sectors;
  }
  if (version == XBFS_V6_VERSION) {
    for (uint32_t i = 0; i < geometry.max_nodes; ++i) {
      xbfs_bytes_copy(&g_xbfs.nodes[i], metadata + p,
                 sizeof(xaios_xbfs_node_t));
      p += sizeof(xaios_xbfs_node_t);
    }
  } else if (version == XBFS_V5_VERSION) {
    for (uint32_t i = 0; i < geometry.max_nodes; ++i) {
      xaios_xbfs_node_v5_t legacy;
      xbfs_bytes_copy(&legacy, metadata + p, sizeof(legacy));
      p += sizeof(legacy);
      import_v5_node(&g_xbfs.nodes[i], &legacy);
    }
  } else if (version == XBFS_V4_VERSION) {
    for (uint32_t i = 0; i < geometry.max_nodes; ++i) {
      xaios_xbfs_node_v4_t legacy;
      xbfs_bytes_copy(&legacy, metadata + p, sizeof(legacy));
      p += sizeof(legacy);
      import_v4_node(&g_xbfs.nodes[i], &legacy);
    }
  } else {
    for (uint32_t i = 0; i < geometry.max_nodes; ++i) {
      xaios_xbfs_node_v3_t legacy;
      xbfs_bytes_copy(&legacy, metadata + p, sizeof(legacy));
      p += sizeof(legacy);
      import_legacy_node(&g_xbfs.nodes[i], &legacy);
    }
  }
  if (p > total_bytes) {
    return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
}

/* A slot is usable when it parses and its stored checksum matches what its
   own bytes hash to. Structural validation stays with the caller, which
   applies it to whichever slot wins. */
static int metadata_slot_probe(uint32_t slot, uint64_t *out_sequence) {
  if (read_metadata_slot(slot) != XAIOS_OK) return 0;
  if (g_xbfs.checksum != xbfs_metadata_verified_checksum()) return 0;
  if (!xbfs_bytes_eq(g_xbfs.magic, XBFS_MAGIC, XBFS_MAGIC_LEN)) return 0;
  *out_sequence = xbfs_metadata_sequence();
  return 1;
}

/* Load the newer of the two copies that is intact. */
xaios_status_t xbfs_volume_read_metadata(void) {
  uint64_t sequence[XBFS_METADATA_SLOTS] = {0U, 0U};
  int usable[XBFS_METADATA_SLOTS] = {0, 0};
  uint32_t chosen;
  usable[0] = metadata_slot_probe(0U, &sequence[0]);
  if (xbfs_metadata_mirror_enabled() != 0U) {
    if (usable[0] != 0) {
      /* The primary read, so the geometry it declares is the volume's, and
         the mirror is where that geometry says. v5 and v6 both keep one, and
         both must be probed: checking only for v5 meant a v6 volume never
         looked at its second copy, and since writes alternate slots the
         reader took the older one every time -- one file short after a
         remount, with fsck reporting no errors, because nothing was wrong
         with what it read. It was simply the wrong copy. */
      if (xbfs_geometry_version() == XBFS_V5_VERSION ||
          xbfs_geometry_version() == XBFS_V6_VERSION) {
        usable[1] = metadata_slot_probe(1U, &sequence[1]);
      }
    } else {
      /* A torn primary is the case the mirror exists for, and it is exactly
         the case where the volume cannot say what shape it is: the version
         lives in the copy that is unreadable. The mirror sits immediately
         after the data region, so its sector follows from the format --
         sector 12546 on v5, 2102786 on v6 -- and guessing wrong reads an
         ordinary data block and concludes the volume has no second copy.

         This used to assume v5, which was true when v5 was the only format
         with a mirror and silently wrong afterwards: a v6 volume with a torn
         primary was refused while intact, about half the time a power cut
         landed on the wrong slot, because writes alternate.

         So each layout the device is large enough to hold is tried, largest
         first. Trying rather than deducing is deliberate -- a probe verifies
         a checksum over the region it read, so a layout that is not there
         fails to probe rather than being mistaken for one that is. */
      static const uint32_t k_mirror_layouts[] = {XBFS_V6_VERSION,
                                                  XBFS_V5_VERSION};
      uint64_t capacity = xbfs_blk_capacity();
      for (uint32_t i = 0U;
           i < sizeof(k_mirror_layouts) / sizeof(k_mirror_layouts[0]); ++i) {
        if (k_mirror_layouts[i] == XBFS_V6_VERSION) {
          xbfs_geometry_select(XBFS_V6_VERSION);
        } else {
          xbfs_geometry_select(XBFS_V5_VERSION);
        }
        if (capacity <
            xbfs_metadata_mirror_start_sector() + xbfs_geometry_metadata_sectors()) {
          continue; /* the device is too small to hold this layout's mirror */
        }
        usable[1] = metadata_slot_probe(1U, &sequence[1]);
        if (usable[1] != 0) break;
      }
    }
  }
  if (usable[0] == 0 && usable[1] == 0) {
    /* Neither copy is intact. Reload the primary so the caller sees the
       original bytes and can apply its own blank-versus-damaged judgement. */
    xbfs_metadata_shadow_set_valid(0U, 0U);
    xbfs_metadata_shadow_set_valid(1U, 0U);
    xbfs_metadata_set_slot(0U);
    return read_metadata_slot(0U);
  }
  if (usable[0] != 0 && usable[1] != 0) {
    chosen = sequence[1] > sequence[0] ? 1U : 0U;
  } else {
    chosen = usable[0] != 0 ? 0U : 1U;
  }
  if (usable[chosen ^ 1U] == 0) {
    xbfs_metadata_note_mirror_recovery();
    klog("xaibootfs: metadata slot %u unusable; continuing from slot %u seq=%lu\n",
         (unsigned)(chosen ^ 1U), (unsigned)chosen, sequence[chosen]);
  }
  xbfs_metadata_shadow_set_valid(0U, 0U);
  xbfs_metadata_shadow_set_valid(1U, 0U);
  xbfs_metadata_set_slot(chosen);
  return read_metadata_slot(chosen);
}

xaios_status_t xbfs_write_metadata(void) {
  uint8_t *metadata = xbfs_metadata_buffer();
  xbfs_bytes_zero(metadata, xbfs_metadata_buffer_bytes());
  uint64_t p = 0;
  xbfs_bytes_copy(metadata + p, g_xbfs.magic, XBFS_MAGIC_LEN); p += XBFS_MAGIC_LEN;
  xbfs_bytes_copy(metadata + p, &g_xbfs.version, 4); p += 4;
  xbfs_bytes_copy(metadata + p, &g_xbfs.sector_size, 4); p += 4;
  xbfs_bytes_copy(metadata + p, &g_xbfs.metadata_sectors, 4); p += 4;
  xbfs_bytes_copy(metadata + p, &g_xbfs.max_nodes, 4); p += 4;
  xbfs_bytes_copy(metadata + p, &g_xbfs.start_sector, 8); p += 8;
  xbfs_bytes_copy(metadata + p, &g_xbfs.journal_header_sector, 8); p += 8;
  xbfs_bytes_copy(metadata + p, &g_xbfs.journal_data_sector, 8); p += 8;
  xbfs_bytes_copy(metadata + p, &g_xbfs.data_start_sector, 8); p += 8;
  xbfs_bytes_copy(metadata + p, &g_xbfs.data_sectors, 8); p += 8;
  xbfs_bytes_copy(metadata + p, &g_xbfs.generation, 8); p += 8;
  xbfs_bytes_copy(metadata + p, &g_xbfs.committed_generation, 8); p += 8;
  uint64_t checksum_offset = p;
  uint64_t zero_cksum = 0;
  xbfs_bytes_copy(metadata + p, &zero_cksum, 8); p += 8;
  if (xbfs_geometry_version() == XBFS_V6_VERSION) {
    xbfs_bytes_copy(metadata + p, g_xbfs.block_bitmap,
               (xbfs_geometry_data_sectors() + 7U) / 8U);
    p += (xbfs_geometry_data_sectors() + 7U) / 8U;
  } else {
    xbfs_bitmap_to_bytes(metadata + p, xbfs_geometry_data_sectors());
    p += xbfs_geometry_data_sectors();
  }
  if (xbfs_geometry_version() == XBFS_V6_VERSION) {
    for (uint32_t i = 0; i < xbfs_geometry_max_nodes(); ++i) {
      xbfs_bytes_copy(metadata + p, &g_xbfs.nodes[i],
                 sizeof(xaios_xbfs_node_t));
      p += sizeof(xaios_xbfs_node_t);
    }
  } else if (xbfs_geometry_version() == XBFS_V5_VERSION) {
    for (uint32_t i = 0; i < xbfs_geometry_max_nodes(); ++i) {
      xaios_xbfs_node_v5_t legacy;
      export_v5_node(&legacy, &g_xbfs.nodes[i]);
      xbfs_bytes_copy(metadata + p, &legacy, sizeof(legacy));
      p += sizeof(legacy);
    }
  } else if (xbfs_geometry_version() == XBFS_V4_VERSION) {
    for (uint32_t i = 0; i < xbfs_geometry_max_nodes(); ++i) {
      xaios_xbfs_node_v4_t legacy;
      export_v4_node(&legacy, &g_xbfs.nodes[i]);
      xbfs_bytes_copy(metadata + p, &legacy, sizeof(legacy));
      p += sizeof(legacy);
    }
  } else {
    for (uint32_t i = 0; i < xbfs_geometry_max_nodes(); ++i) {
      xaios_xbfs_node_v3_t legacy;
      export_legacy_node(&legacy, &g_xbfs.nodes[i]);
      xbfs_bytes_copy(metadata + p, &legacy, sizeof(legacy));
      p += sizeof(legacy);
    }
  }
  uint64_t total_bytes = (uint64_t)xbfs_geometry_metadata_sectors() * XBFS_SECTOR_SIZE;
  if (p > total_bytes) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_NO_MEMORY;
  }
  /* Stamp the write sequence before hashing so the checksum covers it; a
     tear that damages the sequence therefore invalidates the copy too. */
  uint64_t next_sequence = xbfs_metadata_sequence() + 1U;
  xbfs_bytes_copy(metadata + xbfs_metadata_sequence_offset(), &next_sequence, 8);
  g_xbfs.checksum = xbfs_mfs_checksum(metadata, total_bytes);
  xbfs_bytes_copy(metadata + checksum_offset, &g_xbfs.checksum, 8);
  /* Alternate slots so the copy being overwritten is never the one mount
     would currently choose. Without a mirror this degrades to the previous
     in-place behaviour. */
  uint32_t target = xbfs_metadata_mirror_enabled() != 0U ? (xbfs_metadata_slot() ^ 1U)
                                                    : xbfs_metadata_slot();
  uint64_t start = xbfs_metadata_slot_start_sector(target);
  uint8_t sector[XBFS_SECTOR_SIZE];
  /* Only the sectors that differ from what this slot already holds. When the
     shadow is not trusted -- first commit to the slot since mount, or anything
     that failed part-way through -- every sector is written, which is what the
     code always did. */
  uint32_t known = xbfs_metadata_shadow_valid(target);
  uint64_t moved = 0U;
  for (uint32_t i = 0; i < xbfs_geometry_metadata_sectors(); ++i) {
    const uint8_t *source = metadata + (uint64_t)i * XBFS_SECTOR_SIZE;
    if (known != 0U &&
        xbfs_bytes_eq(source, xbfs_metadata_shadow(target) +
                             (uint64_t)i * XBFS_SECTOR_SIZE,
                 XBFS_SECTOR_SIZE) != 0) {
      continue;
    }
    xbfs_bytes_copy(sector, source, XBFS_SECTOR_SIZE);
    if (xbfs_blk_write(start + i, sector, sizeof(sector)) != XAIOS_OK) {
      klog("xaibootfs: metadata write failed sector=%lu capacity=%lu\n",
           start + i, xbfs_blk_capacity());
      xbfs_stat_bump(XBFS_STAT_REJECT);
      /* Part of the slot is new and part is old, and which is which is no
         longer known. Say so, so the next commit writes it whole. */
      xbfs_metadata_shadow_set_valid(target, 0U);
      return XAIOS_ERR_IO;
    }
    ++moved;
  }
  xaios_status_t flushed = xbfs_blk_flush();
  if (flushed != XAIOS_OK) {
    xbfs_metadata_shadow_set_valid(target, 0U);
    return flushed;
  }
  /* Durable now, so the shadow can be believed. */
  xbfs_bytes_copy(xbfs_metadata_shadow(target), metadata,
             (uint64_t)xbfs_geometry_metadata_sectors() * XBFS_SECTOR_SIZE);
  xbfs_metadata_shadow_set_valid(target, 1U);
  (void)moved;
  /* Only once the new copy is durable does it become the one to read, and
     the other becomes the next target. */
  xbfs_metadata_set_slot(target);
  xbfs_metadata_set_sequence(next_sequence);
  return XAIOS_OK;
}




xaios_status_t xbfs_volume_validate(uint64_t expected_checksum) {
  xbfs_geometry_t geometry;
  xbfs_geometry_get(&geometry);
  if (!xbfs_bytes_eq(g_xbfs.magic, XBFS_MAGIC, XBFS_MAGIC_LEN) ||
      g_xbfs.version != geometry.version ||
      g_xbfs.sector_size != XBFS_SECTOR_SIZE ||
      g_xbfs.metadata_sectors != geometry.metadata_sectors ||
      g_xbfs.max_nodes != geometry.max_nodes ||
      g_xbfs.start_sector != XBFS_START_SECTOR ||
      g_xbfs.journal_header_sector != xbfs_journal_header_sector() ||
      g_xbfs.journal_data_sector != xbfs_journal_data_sector() ||
      g_xbfs.data_start_sector != xbfs_data_start_sector() ||
      g_xbfs.data_sectors != geometry.data_sectors) {
    return XAIOS_ERR_INVALID;
  }
  if (g_xbfs.checksum != expected_checksum) {
    xbfs_stat_bump(XBFS_STAT_CHECKSUM_ERROR);
    return XAIOS_ERR_INVALID;
  }
  for (uint32_t i = 0; i < geometry.max_nodes; ++i) {
    xaios_xbfs_node_t *node = &g_xbfs.nodes[i];
    if ((node->active != 0 || node->snapshot_active != 0) &&
        xbfs_validate_path(node->path) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    if (node->active != 0 &&
        node->type != XBFS_NODE_DIR && node->type != XBFS_NODE_FILE) {
      return XAIOS_ERR_INVALID;
    }
    if (node->snapshot_active != 0 &&
        node->snapshot_type != XBFS_NODE_DIR &&
        node->snapshot_type != XBFS_NODE_FILE) {
      return XAIOS_ERR_INVALID;
    }
    if (xbfs_extent_blocks(node->extents, node->extent_count) >
            geometry.file_max_blocks ||
        xbfs_extent_blocks(node->snapshot_extents, node->snapshot_extent_count) >
            geometry.file_max_blocks ||
        node->extent_count > XBFS_V6_MAX_EXTENTS ||
        node->snapshot_extent_count > XBFS_V6_MAX_EXTENTS ||
        node->size > geometry.max_file_bytes ||
        node->snapshot_size > geometry.max_file_bytes) {
      return XAIOS_ERR_INVALID;
    }
  }
  return XAIOS_OK;
}

xaios_status_t xbfs_volume_format(void) {
  xbfs_geometry_t geometry;
  xbfs_geometry_get(&geometry);
  xbfs_bytes_zero(&g_xbfs, sizeof(g_xbfs));
  xbfs_bytes_copy(g_xbfs.magic, XBFS_MAGIC, XBFS_MAGIC_LEN);
  g_xbfs.version = geometry.version;
  g_xbfs.sector_size = (uint32_t)XBFS_SECTOR_SIZE;
  g_xbfs.metadata_sectors = geometry.metadata_sectors;
  g_xbfs.max_nodes = geometry.max_nodes;
  g_xbfs.start_sector = XBFS_START_SECTOR;
  g_xbfs.journal_header_sector = xbfs_journal_header_sector();
  g_xbfs.journal_data_sector = xbfs_journal_data_sector();
  g_xbfs.data_start_sector = xbfs_data_start_sector();
  g_xbfs.data_sectors = geometry.data_sectors;
  g_xbfs.generation = 1;
  g_xbfs.committed_generation = 0;
  xbfs_stat_bump(XBFS_STAT_FORMAT);
  xbfs_metadata_set_sequence(0U);
  xbfs_metadata_shadow_set_valid(0U, 0U);
  xbfs_metadata_shadow_set_valid(1U, 0U);
  xbfs_metadata_set_slot(0U);
  if (xbfs_clear_journal() != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  /* Fill both copies at format time. Writing only one would leave a fresh
     volume with a single valid copy until its second metadata write, which
     is exactly the window this is meant to remove. The two writes alternate
     slots, so both end up holding a complete, self-consistent image. */
  if (xbfs_write_metadata() != XAIOS_OK) return XAIOS_ERR_IO;
  if (xbfs_metadata_mirror_enabled() == 0U) return XAIOS_OK;
  return xbfs_write_metadata();
}

xaios_status_t xbfs_volume_migrate_to_v5(void) {
  if (xbfs_geometry_version() == XBFS_V5_VERSION) {
    return XAIOS_OK;
  }
  /* v6 is newer, not older. This exists to bring a v2, v3 or v4 volume
     forward, and running it on a v6 volume rewrites its superblock as v5 and
     loses everything past v5's limits -- which is what it did, silently,
     until the version was checked here rather than only against v5. */
  if (xbfs_geometry_version() == XBFS_V6_VERSION) {
    return XAIOS_OK;
  }
  uint32_t old_version = xbfs_geometry_version();
  uint64_t old_data_start = g_xbfs.data_start_sector;
  uint64_t new_data_start = XBFS_START_SECTOR + XBFS_V5_METADATA_SECTORS +
                            XBFS_JOURNAL_SECTORS;
  uint8_t sector[XBFS_SECTOR_SIZE];
  for (uint32_t remaining = xbfs_geometry_data_sectors(); remaining != 0U;
       --remaining) {
    uint32_t i = remaining - 1U;
    if (xbfs_block_used(i) == 0U) {
      continue;
    }
    if (xbfs_blk_read(old_data_start + i, sector, sizeof(sector)) != XAIOS_OK ||
        xbfs_blk_write(new_data_start + i, sector, sizeof(sector)) != XAIOS_OK) {
      xbfs_stat_bump(XBFS_STAT_REJECT);
      return XAIOS_ERR_IO;
    }
  }
  if (xbfs_blk_flush() != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  xbfs_geometry_select(XBFS_V5_VERSION);
  g_xbfs.version = XBFS_V5_VERSION;
  g_xbfs.metadata_sectors = XBFS_V5_METADATA_SECTORS;
  g_xbfs.max_nodes = XBFS_V5_MAX_NODES;
  g_xbfs.journal_header_sector = xbfs_journal_header_sector();
  g_xbfs.journal_data_sector = xbfs_journal_data_sector();
  g_xbfs.data_start_sector = xbfs_data_start_sector();
  g_xbfs.data_sectors = XBFS_V5_DATA_SECTORS;
  ++g_xbfs.generation;
  if (xbfs_clear_journal() != XAIOS_OK || xbfs_write_metadata() != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  klog("xaibootfs: migrated v%u to v5 nodes=%u sectors=%u\n", old_version,
       xbfs_geometry_max_nodes(), xbfs_geometry_data_sectors());
  return XAIOS_OK;
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


uint64_t xaiboot_fs_mount_count(void) { return xbfs_stat_get(XBFS_STAT_MOUNT); }
uint64_t xaiboot_fs_metadata_recoveries(void) {
  return xbfs_metadata_mirror_recoveries();
}

uint64_t xaiboot_fs_format_count(void) { return xbfs_stat_get(XBFS_STAT_FORMAT); }
uint64_t xaiboot_fs_boot_load_count(void) { return xbfs_stat_get(XBFS_STAT_BOOT_LOAD); }
uint64_t xaiboot_fs_file_count(void) { return xbfs_node_count_by_type(XBFS_NODE_FILE); }
uint64_t xaiboot_fs_directory_count(void) { return xbfs_node_count_by_type(XBFS_NODE_DIR); }
uint64_t xaiboot_fs_write_count(void) { return xbfs_stat_get(XBFS_STAT_WRITE); }
uint64_t xaiboot_fs_append_count(void) { return xbfs_stat_get(XBFS_STAT_APPEND); }
uint64_t xaiboot_fs_append_fallback_count(void) {
  return xbfs_stat_get(XBFS_STAT_APPEND_FALLBACK);
}
uint64_t xaiboot_fs_read_count(void) { return xbfs_stat_get(XBFS_STAT_READ); }
uint64_t xaiboot_fs_delete_count(void) { return xbfs_stat_get(XBFS_STAT_DELETE); }
uint64_t xaiboot_fs_commit_count(void) { return xbfs_stat_get(XBFS_STAT_COMMIT); }
uint64_t xaiboot_fs_rollback_count(void) { return xbfs_stat_get(XBFS_STAT_ROLLBACK); }
uint64_t xaiboot_fs_reject_count(void) { return xbfs_stat_get(XBFS_STAT_REJECT); }
uint64_t xaiboot_fs_checksum_error_count(void) { return xbfs_stat_get(XBFS_STAT_CHECKSUM_ERROR); }
uint64_t xaiboot_fs_allocation_count(void) { return xbfs_stat_get(XBFS_STAT_ALLOCATION); }
uint64_t xaiboot_fs_free_count(void) { return xbfs_stat_get(XBFS_STAT_FREE); }
uint64_t xaiboot_fs_replay_count(void) { return xbfs_stat_get(XBFS_STAT_REPLAY); }
uint64_t xaiboot_fs_journal_write_count(void) { return xbfs_stat_get(XBFS_STAT_JOURNAL_WRITE); }
uint64_t xaiboot_fs_multi_sector_file_count(void) { return xbfs_stat_get(XBFS_STAT_MULTI_SECTOR_FILE); }
uint64_t xaiboot_fs_state_record_count(void) { return xbfs_stat_get(XBFS_STAT_STATE_RECORD); }
uint64_t xaiboot_fs_rename_count(void) { return xbfs_stat_get(XBFS_STAT_RENAME); }
uint64_t xaiboot_fs_list_count(void) { return xbfs_stat_get(XBFS_STAT_LIST); }
uint64_t xaiboot_fs_stat_count(void) { return xbfs_stat_get(XBFS_STAT_STAT); }
uint64_t xaiboot_fs_open_count(void) { return xbfs_stat_get(XBFS_STAT_OPEN); }
uint64_t xaiboot_fs_close_count(void) { return xbfs_stat_get(XBFS_STAT_CLOSE); }


/* Mark every block a file claims, and complain if two files claim one.
   
   The reference array is one byte per block, which at v6 sizes would be two
   megabytes on the stack; it is a static instead. A check that cannot run
   because it needs more stack than exists is a check that does not run. */
static void fsck_count_file_extents(const xaios_xbfs_extent_t *extents,
                                    uint32_t extent_count,
                                    uint8_t *references,
                                    xaios_xbfs_fsck_result_t *result) {
  if (extent_count > XBFS_V6_MAX_EXTENTS ||
      xbfs_extent_blocks(extents, extent_count) > xbfs_geometry_file_max_blocks()) {
    ++result->errors;
    return;
  }
  for (uint32_t e = 0U; e < extent_count; ++e) {
    for (uint32_t offset = 0U; offset < extents[e].length; ++offset) {
      uint64_t block = (uint64_t)extents[e].start + offset;
      if (block >= xbfs_geometry_data_sectors() || references[block] != 0U) {
        ++result->errors;
      } else {
        references[block] = 1U;
      }
    }
  }
}

static xaios_xbfs_fsck_result_t xaiboot_fs_fsck_locked(void) {
  xbfs_geometry_t geometry;
  xbfs_geometry_get(&geometry);
  xaios_xbfs_fsck_result_t result;
  /* A byte per block, static rather than on the stack: at v6 sizes this is
     two megabytes, and a check that needs more stack than exists is a check
     that does not run. */
  static uint8_t references[XBFS_V6_DATA_SECTORS];
  xbfs_bytes_zero(&result, sizeof(result));
  xbfs_bytes_zero(references, sizeof(references));
  result.version = geometry.version;
  result.files = xbfs_node_count_by_type(XBFS_NODE_FILE);
  result.directories = xbfs_node_count_by_type(XBFS_NODE_DIR);
  result.blocks_used = xbfs_block_count_used();
  result.errors = 0;

  for (uint32_t n = 0; n < geometry.max_nodes; ++n) {
    xaios_xbfs_node_t *node = &g_xbfs.nodes[n];
    if (node->active != 0 && node->type == XBFS_NODE_FILE) {
      fsck_count_file_extents(node->extents, node->extent_count, references,
                              &result);
    }
    if (node->snapshot_active != 0 &&
        node->snapshot_type == XBFS_NODE_FILE) {
      fsck_count_file_extents(node->snapshot_extents,
                              node->snapshot_extent_count, references,
                              &result);
    }
  }

  for (uint32_t i = 0; i < geometry.data_sectors; ++i) {
    int in_use = xbfs_block_used(i) != 0U;
    int referenced = references[i] != 0U;
    if (in_use != referenced) {
      ++result.errors;
    }
  }
  result.valid = (result.errors == 0) ? 1U : 0U;
  klog("xaibootfs: fsck v%u files=%lu dirs=%lu blocks=%lu errors=%lu valid=%u\n",
       result.version, result.files, result.directories,
       result.blocks_used, result.errors, result.valid);
  return result;
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

void xaiboot_fs_self_test(void) {
  kassert(sizeof(xaios_xbfs_journal_t) == XBFS_SECTOR_SIZE);
  kassert(sizeof(xaios_xbfs_disk_t) <= XBFS_METADATA_SECTORS * XBFS_SECTOR_SIZE);
  xbfs_mount_set_mounted(0);
  xbfs_mount_set_flags(0);
  xbfs_mount_set_device(0);
  xbfs_geometry_select(XBFS_VERSION);
  xbfs_stat_reset_all();
  xbfs_reset_open_files();

  kassert(xbfs_mount_volume(XBFS_MOUNT_READ_WRITE) == XAIOS_OK);
  kassert(xbfs_volume_format() == XAIOS_OK);
  kassert(xbfs_ensure_base_directories() == XAIOS_OK);
  xaios_xbfs_node_t *base_node = xbfs_find_node("/tmp", 1);
  kassert(base_node != 0 && base_node->type == XBFS_NODE_DIR);
  base_node = xbfs_find_node("/home/admin", 1);
  kassert(base_node != 0 && base_node->type == XBFS_NODE_DIR);

  kassert(xaiboot_fs_record_service_state("/svc/source-index", "running") ==
          XAIOS_OK);
  kassert(xaiboot_fs_record_workspace_state(0, "boot") == XAIOS_OK);
  kassert(xaiboot_fs_record_update_state("signed-update-required") == XAIOS_OK);
  kassert(xaiboot_fs_record_admin_status("/svc/source-index", "running", 1, 0,
                                         0) == XAIOS_OK);
  kassert(xbfs_write_file_locked("/config/xaios.conf", k_config_v1,
                     sizeof(k_config_v1)) == XAIOS_OK);

  uint8_t large[XBFS_SECTOR_SIZE * 3U];
  for (uint64_t i = 0; i < sizeof(large); ++i) {
    large[i] = (uint8_t)('A' + (i % 23U));
  }
  kassert(xbfs_write_file_locked("/state/services/large.state", large, sizeof(large)) ==
          XAIOS_OK);

  uint8_t buffer[XBFS_MAX_FILE_BYTES];
  uint64_t size = 0;
  kassert(xbfs_read_file("/state/services/large.state", buffer, sizeof(buffer),
                    &size) == XAIOS_OK);
  kassert(size == sizeof(large));
  kassert(xbfs_bytes_eq(buffer, large, sizeof(large)) != 0);

  char listing[XAIOS_XBFS_MAX_LIST_BYTES];
  xaios_xbfs_stat_t stat;
  kassert(xbfs_list_dir("/state", listing, sizeof(listing), &size) == XAIOS_OK);
  kassert(size > 0);
  kassert(xbfs_stat_node("/state/services/large.state", &stat) == XAIOS_OK);
  kassert(stat.type == XBFS_NODE_FILE);
  kassert(stat.size == sizeof(large));
  kassert(xbfs_rename_node("/config/xaios.conf", "/config/xaios-renamed.conf") ==
          XAIOS_OK);
  kassert(xbfs_stat_node("/config/xaios-renamed.conf", &stat) == XAIOS_OK);
  kassert(xbfs_read_file("/config/xaios.conf", buffer, sizeof(buffer), &size) ==
          XAIOS_ERR_NOT_FOUND);

  static const char k_fd_payload[] = "fd-api=ok\n";
  int64_t fd = xaiboot_fs_open("/logs/fd-api.log",
                               XAIOS_XBFS_OPEN_READ | XAIOS_XBFS_OPEN_WRITE |
                                   XAIOS_XBFS_OPEN_CREATE);
  kassert(fd > 0);
  kassert(xaiboot_fs_write_fd((uint32_t)fd, k_fd_payload,
                              sizeof(k_fd_payload)) ==
          (int64_t)sizeof(k_fd_payload));
  kassert(xaiboot_fs_seek((uint32_t)fd, 3U) == XAIOS_OK);
  kassert(xbfs_fd_cursor((uint32_t)fd) == 3U);
  kassert(xaiboot_fs_seek((uint32_t)fd, 0U) == XAIOS_OK);
  kassert(xaiboot_fs_close((uint32_t)fd) == XAIOS_OK);
  fd = xaiboot_fs_open("/logs/fd-api.log", XAIOS_XBFS_OPEN_READ);
  kassert(fd > 0);
  kassert(xaiboot_fs_read_fd((uint32_t)fd, buffer, sizeof(k_fd_payload)) ==
          (int64_t)sizeof(k_fd_payload));
  kassert(xbfs_bytes_eq(buffer, k_fd_payload, sizeof(k_fd_payload)) != 0);
  kassert(xaiboot_fs_close((uint32_t)fd) == XAIOS_OK);
  fd = xaiboot_fs_open("/logs/fd-api.log",
                       XAIOS_XBFS_OPEN_READ | XAIOS_XBFS_OPEN_WRITE |
                           XAIOS_XBFS_OPEN_TRUNCATE);
  kassert(fd > 0);
  kassert(xbfs_stat_node("/logs/fd-api.log", &stat) == XAIOS_OK);
  kassert(stat.size == 0);
  kassert(xaiboot_fs_close((uint32_t)fd) == XAIOS_OK);
  kassert(xaiboot_fs_open("/missing/nope", XAIOS_XBFS_OPEN_READ) ==
          (int64_t)XAIOS_ERR_NOT_FOUND);
  kassert(xbfs_snapshot_commit("mfs-snapshot-v2") == XAIOS_OK);

  kassert(xbfs_write_file_locked("/state/services/source-index.state",
                     k_service_restarting,
                     sizeof(k_service_restarting)) == XAIOS_OK);
  kassert(xbfs_delete_node("/state/updates/update.state") == XAIOS_OK);
  kassert(xbfs_write_file_locked("/logs/boot.log", k_boot_log, sizeof(k_boot_log)) ==
          XAIOS_OK);
  kassert(xbfs_write_pending_journal_file("/state/services/replayed.state",
                                     k_replayed_state,
                                     sizeof(k_replayed_state)) == XAIOS_OK);
  xbfs_mount_set_mounted(0);
  kassert(xbfs_mount_volume(XBFS_MOUNT_READ_WRITE) == XAIOS_OK);
  kassert(xbfs_read_file("/state/services/replayed.state", buffer, sizeof(buffer),
                    &size) == XAIOS_OK);
  kassert(size == sizeof(k_replayed_state));
  kassert(xbfs_bytes_eq(buffer, k_replayed_state, sizeof(k_replayed_state)) != 0);
  xaios_xbfs_fsck_result_t snapshot_fsck = xaiboot_fs_fsck();
  kassert(snapshot_fsck.valid != 0);

  kassert(xbfs_snapshot_rollback() == XAIOS_OK);
  kassert(xbfs_read_file("/state/services/source-index.state", buffer,
                    sizeof(buffer), &size) == XAIOS_OK);
  kassert(size == sizeof(k_service_running));
  kassert(xbfs_bytes_eq(buffer, k_service_running, sizeof(k_service_running)) != 0);
  kassert(xbfs_read_file("/state/updates/update.state", buffer, sizeof(buffer),
                    &size) == XAIOS_OK);
  kassert(size == sizeof(k_update_state));
  kassert(xbfs_bytes_eq(buffer, k_update_state, sizeof(k_update_state)) != 0);
  kassert(xbfs_read_file("/logs/boot.log", buffer, sizeof(buffer), &size) ==
          XAIOS_ERR_NOT_FOUND);
  kassert(xbfs_read_file("/state/services/replayed.state", buffer, sizeof(buffer),
                    &size) == XAIOS_ERR_NOT_FOUND);

  kassert(xbfs_write_file_locked("/bad/missing-parent", k_config_v1,
                     sizeof(k_config_v1)) == XAIOS_ERR_INVALID);
  kassert(xbfs_create_dir("/state/services/bad") == XAIOS_OK);
  kassert(xbfs_delete_node("/state/services") == XAIOS_ERR_BUSY);
  uint8_t too_large[XBFS_MAX_FILE_BYTES + 1U];
  kassert(xbfs_write_file_locked("/state/services/too-large", too_large,
                     sizeof(too_large)) == XAIOS_ERR_INVALID);
  kassert(xbfs_read_file("/state/missing.state", buffer, sizeof(buffer), &size) ==
          XAIOS_ERR_NOT_FOUND);

  kassert(xaiboot_fs_mount_count() == 2);
  kassert(xaiboot_fs_format_count() >= 1);
  kassert(xaiboot_fs_format_count() <= 2);
  kassert(xaiboot_fs_file_count() >= 6);
  kassert(xaiboot_fs_directory_count() >= 11);
  kassert(xaiboot_fs_write_count() >= 12);
  kassert(xaiboot_fs_read_count() >= 5);
  kassert(xaiboot_fs_delete_count() == 1);
  kassert(xaiboot_fs_commit_count() == 1);
  kassert(xaiboot_fs_rollback_count() == 1);
  kassert(xaiboot_fs_replay_count() == 1);
  kassert(xaiboot_fs_journal_write_count() == 1);
  kassert(xaiboot_fs_multi_sector_file_count() >= 1);
  kassert(xaiboot_fs_state_record_count() == 4);
  kassert(xaiboot_fs_reject_count() >= 7);
  kassert(xaiboot_fs_checksum_error_count() == 0);
  kassert(xaiboot_fs_rename_count() == 1);
  kassert(xaiboot_fs_list_count() == 1);
  kassert(xaiboot_fs_stat_count() == 3);
  kassert(xaiboot_fs_open_count() == 3);
  kassert(xaiboot_fs_close_count() == 3);
  /* A write that would run off the end of the staging buffer must be refused,
     not staged. v6 raised the format's per-file limit to a gibibyte while the
     buffer this path copies through stayed at the v5 figure of 256 KiB, and
     for a while the guard checked only the former: on a v6 volume, a seek past
     256 KiB and a write corrupted whatever the linker had placed after a
     static array.

     The invariant is the check that holds whatever volume is mounted -- this
     self-test runs against a v2 volume, where the format's own limit is eight
     kibibytes and far below the buffer, so a probe at 256 KiB would prove
     nothing here. The probe that follows works at whatever the binding limit
     is. */
  kassert(xbfs_write_limit() <= xbfs_file_staging_bytes());
  /* The same question for the rename staging table, which walks every node
     the active format allows. */
  kassert((uint64_t)xbfs_geometry_max_nodes() <=
          xbfs_dir_path_transaction_rows());
  /* And for the two remaining buffers a format's own numbers index into.
     Both are sized for v6 today and neither has ever been wrong; they are
     asserted because the two that were wrong were wrong the same way -- a
     static sized for the format that existed when it was written, indexed
     by a later format's larger maximum -- and nothing else would catch the
     third instance of it. */
  kassert((uint64_t)xbfs_geometry_metadata_sectors() * XBFS_SECTOR_SIZE <=
          (uint64_t)xbfs_metadata_buffer_bytes());
  kassert((uint64_t)xbfs_geometry_path_max() <= (uint64_t)XBFS_PATH_MAX);
  {
    int64_t guard_fd = xaiboot_fs_open("/state/overflow-guard",
                                       XAIOS_XBFS_OPEN_WRITE |
                                           XAIOS_XBFS_OPEN_CREATE);
    kassert(guard_fd >= 0);
    uint8_t probe[64];
    for (uint32_t index = 0U; index < sizeof(probe); ++index) {
      probe[index] = (uint8_t)index;
    }
    uint64_t limit = xbfs_write_limit();
    /* One byte inside the limit, so the write would straddle it. */
    kassert(xaiboot_fs_seek((uint32_t)guard_fd, limit - 1U) == XAIOS_OK);
    kassert(xaiboot_fs_write_fd((uint32_t)guard_fd, probe, sizeof(probe)) ==
            (int64_t)XAIOS_ERR_INVALID);
    /* And exactly at it, which is the off-by-one on the other side. */
    kassert(xaiboot_fs_seek((uint32_t)guard_fd, limit) == XAIOS_OK);
    kassert(xaiboot_fs_write_fd((uint32_t)guard_fd, probe, 1U) ==
            (int64_t)XAIOS_ERR_INVALID);
    /* And the last byte that does fit still goes in, so the guard is a bound
       and not a blanket refusal. */
    kassert(xaiboot_fs_seek((uint32_t)guard_fd, limit - 1U) == XAIOS_OK);
    kassert(xaiboot_fs_write_fd((uint32_t)guard_fd, probe, 1U) == 1);
    kassert(xaiboot_fs_close((uint32_t)guard_fd) == XAIOS_OK);
    kassert(xaiboot_fs_delete("/state/overflow-guard") == XAIOS_OK);
  }
  {
    /* B-45. Three separate things have to hold, and the first is the one a
       green-and-useless version of this change would fail: the fast path has
       to actually run. Everything after it is content, and content would be
       right either way -- the whole-file path produces the same bytes, slowly.

       The records are deliberately not a divisor of the sector size, so the
       run crosses block boundaries at every offset within a block rather than
       always at the same one. An append that understood only the tail block,
       or that got the boundary off by one, has nowhere to hide in that. */
    static const char record[] = "[INFO] connection accepted\n";
    const uint64_t record_length = sizeof(record) - 1U;
    const uint32_t record_count = 200U;
    uint64_t appends_before = xaiboot_fs_append_count();
    uint64_t reads_before = xaiboot_fs_read_count();
    int64_t log_fd = xaiboot_fs_open("/state/append-probe",
                                     XAIOS_XBFS_OPEN_WRITE |
                                         XAIOS_XBFS_OPEN_CREATE |
                                         XAIOS_XBFS_OPEN_TRUNCATE);
    kassert(log_fd >= 0);
    for (uint32_t i = 0U; i < record_count; ++i) {
      kassert(xaiboot_fs_write_fd((uint32_t)log_fd, record, record_length) ==
              (int64_t)record_length);
    }
    kassert(xaiboot_fs_close((uint32_t)log_fd) == XAIOS_OK);
#if XBFS_APPEND_IN_PLACE
    kassert(xaiboot_fs_append_count() - appends_before ==
            (uint64_t)record_count);
    /* And not one file read among them, which is the defect itself. */
    kassert(xaiboot_fs_read_count() == reads_before);
#else
    (void)reads_before;
#endif

    /* The bytes, and by way of xbfs_read_file the content hash that was extended
       rather than recomputed: a wrong hash is XAIOS_ERR_INVALID here. */
    uint64_t probe_size = 0;
    kassert(xbfs_read_file("/state/append-probe", buffer, sizeof(buffer),
                      &probe_size) == XAIOS_OK);
    kassert(probe_size == record_length * (uint64_t)record_count);
    for (uint32_t i = 0U; i < record_count; ++i) {
      kassert(xbfs_bytes_eq(buffer + (uint64_t)i * record_length, record,
                       record_length) != 0);
    }

    /* A write that is not at the end is not an append, must not be treated as
       one, and must still be correct. */
    uint64_t fallbacks_before = xaiboot_fs_append_fallback_count();
    appends_before = xaiboot_fs_append_count();
    int64_t patch_fd = xaiboot_fs_open("/state/append-probe",
                                       XAIOS_XBFS_OPEN_WRITE);
    kassert(patch_fd >= 0);
    kassert(xaiboot_fs_seek((uint32_t)patch_fd, record_length) == XAIOS_OK);
    kassert(xaiboot_fs_write_fd((uint32_t)patch_fd, "XX", 2U) == 2);
    kassert(xaiboot_fs_close((uint32_t)patch_fd) == XAIOS_OK);
    kassert(xaiboot_fs_append_count() == appends_before);
#if XBFS_APPEND_IN_PLACE
    kassert(xaiboot_fs_append_fallback_count() == fallbacks_before + 1U);
#else
    (void)fallbacks_before;
#endif
    kassert(xbfs_read_file("/state/append-probe", buffer, sizeof(buffer),
                      &probe_size) == XAIOS_OK);
    kassert(probe_size == record_length * (uint64_t)record_count);
    kassert(buffer[record_length] == 'X' && buffer[record_length + 1U] == 'X');
    kassert(xbfs_bytes_eq(buffer, record, record_length) != 0);
    kassert(xbfs_bytes_eq(buffer + record_length * 2U, record, record_length) != 0);

    /* Failing when it should, one: an append that would take the file past
       what this volume's format allows is refused, and refused without
       changing the file. The bound is `xbfs_write_limit`, which on a v2 volume is
       the format's own eight kibibytes and on v6 is the staging buffer -- the
       .bss overflow that bound exists to stop. The append path does not stage
       through that buffer at all, and the bound still binds, because a path
       that quietly raised its own limit is how that overflow would come back. */
    uint64_t limit = xbfs_write_limit();
    int64_t bound_fd = xaiboot_fs_open("/state/append-probe",
                                       XAIOS_XBFS_OPEN_WRITE);
    kassert(bound_fd >= 0);
    kassert(xaiboot_fs_seek((uint32_t)bound_fd, limit - 1U) == XAIOS_OK);
    kassert(xaiboot_fs_write_fd((uint32_t)bound_fd, record,
                                record_length) ==
            (int64_t)XAIOS_ERR_INVALID);
    kassert(xaiboot_fs_close((uint32_t)bound_fd) == XAIOS_OK);
    kassert(xbfs_read_file("/state/append-probe", buffer, sizeof(buffer),
                      &probe_size) == XAIOS_OK);
    kassert(probe_size == record_length * (uint64_t)record_count);

    /* Failing when it should, two: a volume with no free block. The append
       needs one, cannot have one, and the file has to come back unchanged and
       still readable -- not longer, not shorter, and not corrupt. This is the
       case where a fast path that published its metadata before its blocks
       would be found out. */
    uint32_t filled = 0U;
    /* Fill to exactly full, sizing the last file to the free blocks that are
       left rather than writing whole files until one does not fit. Writing
       until failure stops with a few blocks still free, and an append that
       then succeeds would have proved nothing -- which is how this control
       would have passed while testing the opposite of what it says. */
    while (xbfs_block_count_used() < (uint64_t)xbfs_geometry_data_sectors() &&
           filled < XBFS_MAX_NODES) {
      uint64_t free_blocks =
          (uint64_t)xbfs_geometry_data_sectors() - xbfs_block_count_used();
      uint64_t chunk = free_blocks * XBFS_SECTOR_SIZE;
      if (chunk > (uint64_t)XBFS_MAX_FILE_BYTES) {
        chunk = (uint64_t)XBFS_MAX_FILE_BYTES;
      }
      char fill_path[XBFS_PATH_MAX];
      uint64_t offset = 0;
      kassert(xbfs_append_cstr(fill_path, sizeof(fill_path), &offset,
                          "/state/fill-") == XAIOS_OK);
      kassert(xbfs_append_u32(fill_path, sizeof(fill_path), &offset, filled) ==
              XAIOS_OK);
      if (xbfs_write_file_locked(fill_path, buffer, chunk) != XAIOS_OK) break;
      ++filled;
    }
    kassert(xbfs_block_count_used() == (uint64_t)xbfs_geometry_data_sectors());
    uint64_t blocked_size = 0;
    kassert(xbfs_read_file("/state/append-probe", buffer, sizeof(buffer),
                      &blocked_size) == XAIOS_OK);
    int64_t blocked_fd = xaiboot_fs_open("/state/append-probe",
                                         XAIOS_XBFS_OPEN_WRITE);
    kassert(blocked_fd >= 0);
    kassert(xaiboot_fs_seek((uint32_t)blocked_fd, blocked_size) == XAIOS_OK);
    /* A whole sector, so a block is needed whatever slack the tail had. */
    kassert(xaiboot_fs_write_fd((uint32_t)blocked_fd, buffer,
                                XBFS_SECTOR_SIZE) < 0);
    kassert(xaiboot_fs_close((uint32_t)blocked_fd) == XAIOS_OK);
    uint64_t after_size = 0;
    kassert(xbfs_read_file("/state/append-probe", buffer, sizeof(buffer),
                      &after_size) == XAIOS_OK);
    kassert(after_size == blocked_size);
    for (uint32_t i = 0U; i < filled; ++i) {
      char fill_path[XBFS_PATH_MAX];
      uint64_t offset = 0;
      kassert(xbfs_append_cstr(fill_path, sizeof(fill_path), &offset,
                          "/state/fill-") == XAIOS_OK);
      kassert(xbfs_append_u32(fill_path, sizeof(fill_path), &offset, i) == XAIOS_OK);
      kassert(xbfs_delete_node(fill_path) == XAIOS_OK);
    }
    kassert(xbfs_delete_node("/state/append-probe") == XAIOS_OK);
    klog("xaibootfs: append self-test passed appends=%lu fallbacks=%lu records=%lu filled=%u refused_full=%lu\n",
         xaiboot_fs_append_count(), xaiboot_fs_append_fallback_count(),
         (uint64_t)record_count, filled, blocked_size);
  }
  klog("xaibootfs: write bound self-test passed limit=%lu staging_buffer=%lu\n",
       xbfs_write_limit(), xbfs_file_staging_bytes());
  klog("xaibootfs: allocator self-test passed allocations=%lu frees=%lu blocks=%lu\n",
       xaiboot_fs_allocation_count(), xaiboot_fs_free_count(),
       xbfs_block_count_used());
  klog("xaibootfs: directory tree self-test passed directories=%lu\n",
       xaiboot_fs_directory_count());
  klog("xaibootfs: multi-sector file self-test passed files=%lu multi_sector=%lu\n",
       xaiboot_fs_file_count(), xaiboot_fs_multi_sector_file_count());
  klog("xaibootfs: journal replay self-test passed replays=%lu journal_writes=%lu\n",
       xaiboot_fs_replay_count(), xaiboot_fs_journal_write_count());
  klog("xaibootfs: public API self-test passed list=%lu stat=%lu rename=%lu open=%lu close=%lu\n",
       xaiboot_fs_list_count(), xaiboot_fs_stat_count(),
       xaiboot_fs_rename_count(), xaiboot_fs_open_count(),
       xaiboot_fs_close_count());
  klog("xaibootfs: subsystem records self-test passed records=%lu\n",
       xaiboot_fs_state_record_count());
  klog("xaibootfs: self-test passed files=%lu directories=%lu writes=%lu reads=%lu deletes=%lu commits=%lu rollbacks=%lu replays=%lu rejects=%lu checksum_errors=%lu\n",
       xaiboot_fs_file_count(), xaiboot_fs_directory_count(),
       xaiboot_fs_write_count(), xaiboot_fs_read_count(),
       xaiboot_fs_delete_count(), xaiboot_fs_commit_count(),
       xaiboot_fs_rollback_count(), xaiboot_fs_replay_count(),
       xaiboot_fs_reject_count(), xaiboot_fs_checksum_error_count());
}
