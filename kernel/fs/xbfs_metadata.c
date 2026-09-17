/*
 * xaibootFS's metadata buffer, its per-slot shadow, the slot/sequence/mirror
 * scalars, and the journal.
 *
 * Split out of xaiboot_fs.c, which keeps the codec that marshals the volume
 * state to and from the metadata buffer. The buffer and the shadow are large
 * static arrays that blk_read fills; that codec reaches them through
 * xbfs_metadata_buffer() and xbfs_metadata_shadow(), whose pointers are valid
 * for the duration of one call only, as xbfs_metadata_internal.h says. The
 * scalars this file owns are read and written through the get/set pairs there.
 *
 * The journal moved whole: the record checksum, the clear/read/write trio, the
 * pending record a write stages, the replay mount performs, and the sector
 * arithmetic that locates the journal and the mirror. Nothing here decides
 * when a commit happens; that policy stays with the callers.
 *
 * Block I/O and path validation stay in xaiboot_fs.c, so they cross back as
 * xbfs_blk_* and xbfs_validate_path.
 */

#include <xaios/klog.h>

#include "xbfs_metadata_internal.h"

static uint64_t g_metadata_verified_checksum;
/* Slot the live metadata was loaded from; the next write targets the other. */
static uint32_t g_metadata_slot;
static uint32_t g_metadata_mirror_enabled;
static uint64_t g_metadata_sequence;
static uint64_t g_metadata_mirror_recoveries;

/* Sized for the largest version, because one buffer serves them all and a
   v6 volume's metadata does not fit in v5's. */
static uint8_t g_metadata_buffer[XBFS_V6_METADATA_SECTORS * XBFS_SECTOR_SIZE];
/* What each metadata slot currently holds, so a commit can write only the
   sectors that changed.
 *
 * The whole region was written every time, however little moved: 1280 sectors
 * -- 640 KiB -- on a v5 volume and 2560 on v6. A 32-byte audit record
 * therefore cost 1281 sectors, measured, which is why B-45 took file bytes to
 * almost nothing and per-record time did not move. Nearly all of it is the
 * node table, and an append changes one node.
 *
 * Two copies because the slots alternate: a commit targets the slot that is
 * *not* the one mount would currently choose, so the content it is replacing
 * is what was written two commits ago, not one. Diffing against a single
 * previous buffer would compare the wrong slot and skip sectors that differ.
 *
 * A shadow is only believed after the write it describes has flushed, and any
 * failure marks it unknown so the next commit writes the region whole. The
 * cost of being wrong here is a metadata sector that silently keeps an old
 * value, so the conservative direction is the only acceptable one. B-48. */
static uint8_t g_metadata_shadow[2][XBFS_V6_METADATA_SECTORS *
                                    XBFS_SECTOR_SIZE];
static uint32_t g_metadata_shadow_valid[2];

/* The only state handed out by address, because it is far too large to copy
   into a caller local and blk_read fills it in place. The pointer is good for
   the duration of one call and no longer. */
uint8_t *xbfs_metadata_buffer(void) { return g_metadata_buffer; }

uint64_t xbfs_metadata_buffer_bytes(void) { return sizeof(g_metadata_buffer); }

uint8_t *xbfs_metadata_shadow(uint32_t slot) {
  return g_metadata_shadow[slot];
}

uint32_t xbfs_metadata_shadow_valid(uint32_t slot) {
  return g_metadata_shadow_valid[slot];
}

void xbfs_metadata_shadow_set_valid(uint32_t slot, uint32_t valid) {
  g_metadata_shadow_valid[slot] = valid;
}

uint64_t xbfs_metadata_verified_checksum(void) {
  return g_metadata_verified_checksum;
}

void xbfs_metadata_set_verified_checksum(uint64_t checksum) {
  g_metadata_verified_checksum = checksum;
}

uint32_t xbfs_metadata_slot(void) { return g_metadata_slot; }

void xbfs_metadata_set_slot(uint32_t slot) { g_metadata_slot = slot; }

uint32_t xbfs_metadata_mirror_enabled(void) {
  return g_metadata_mirror_enabled;
}

void xbfs_metadata_set_mirror_enabled(uint32_t enabled) {
  g_metadata_mirror_enabled = enabled;
}

uint64_t xbfs_metadata_sequence(void) { return g_metadata_sequence; }

void xbfs_metadata_set_sequence(uint64_t sequence) {
  g_metadata_sequence = sequence;
}

uint64_t xbfs_metadata_mirror_recoveries(void) {
  return g_metadata_mirror_recoveries;
}

void xbfs_metadata_note_mirror_recovery(void) {
  ++g_metadata_mirror_recoveries;
}

uint64_t xbfs_journal_header_sector(void) {
  return XBFS_START_SECTOR + xbfs_geometry_metadata_sectors();
}

uint64_t xbfs_journal_data_sector(void) {
  return xbfs_journal_header_sector() + 1U;
}

uint64_t xbfs_data_start_sector(void) {
  return xbfs_journal_header_sector() + XBFS_JOURNAL_SECTORS;
}

/* The mirror sits immediately after the data region, so nothing that an
   existing volume already uses moves. */
uint64_t xbfs_metadata_mirror_start_sector(void) {
  return xbfs_data_start_sector() + xbfs_geometry_data_sectors();
}

uint64_t xbfs_metadata_slot_start_sector(uint32_t slot) {
  return slot == 0U ? XBFS_START_SECTOR : xbfs_metadata_mirror_start_sector();
}

uint64_t xbfs_metadata_sequence_offset(void) {
  return (uint64_t)xbfs_geometry_metadata_sectors() * XBFS_SECTOR_SIZE -
         XBFS_SEQUENCE_TAIL_BYTES;
}

int xbfs_metadata_header_is_blank(void) {
  uint8_t *metadata = xbfs_metadata_buffer();
  for (uint32_t i = 0U; i < XBFS_SECTOR_SIZE; ++i) {
    if (metadata[i] != 0U) return 0;
  }
  return 1;
}

uint64_t xbfs_journal_checksum(xaios_xbfs_journal_t *journal) {
  uint64_t saved = journal->checksum;
  journal->checksum = 0;
  uint64_t checksum = xbfs_fnv1a64(journal, sizeof(*journal));
  journal->checksum = saved;
  return checksum;
}

xaios_status_t xbfs_clear_journal(void) {
  uint8_t sector[XBFS_SECTOR_SIZE];
  xbfs_bytes_zero(sector, sizeof(sector));
  if (xbfs_blk_write(xbfs_journal_header_sector(), sector,
                     sizeof(sector)) != XAIOS_OK ||
      xbfs_blk_write(xbfs_journal_data_sector(), sector,
                     sizeof(sector)) != XAIOS_OK) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}

xaios_status_t xbfs_read_journal(xaios_xbfs_journal_t *journal) {
  if (xbfs_blk_read(xbfs_journal_header_sector(), journal,
                    sizeof(*journal)) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}

xaios_status_t xbfs_write_journal(xaios_xbfs_journal_t *journal) {
  journal->checksum = xbfs_journal_checksum(journal);
  if (xbfs_blk_write(xbfs_journal_header_sector(), journal,
                     sizeof(*journal)) != XAIOS_OK) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_IO;
  }
  xbfs_stat_bump(XBFS_STAT_JOURNAL_WRITE);
  return XAIOS_OK;
}

xaios_status_t xbfs_replay_journal(void) {
  xaios_xbfs_journal_t journal;
  if (xbfs_read_journal(&journal) != XAIOS_OK) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_IO;
  }
  if (!xbfs_bytes_eq(journal.magic, XBFS_JOURNAL_MAGIC, XBFS_MAGIC_LEN) ||
      journal.state == XBFS_JOURNAL_EMPTY) {
    return XAIOS_OK;
  }
  uint64_t expected = journal.checksum;
  if (journal.version != XBFS_JOURNAL_VERSION ||
      journal.state != XBFS_JOURNAL_PENDING ||
      journal.op != XBFS_JOURNAL_OP_WRITE_FILE ||
      journal.size == 0 || journal.size > XBFS_SECTOR_SIZE ||
      xbfs_journal_checksum(&journal) != expected ||
      xbfs_validate_path(journal.path) != XAIOS_OK) {
    xbfs_stat_bump(XBFS_STAT_CHECKSUM_ERROR);
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return xbfs_clear_journal();
  }

  uint8_t sector[XBFS_SECTOR_SIZE];
  if (xbfs_blk_read(xbfs_journal_data_sector(), sector,
                    sizeof(sector)) != XAIOS_OK) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_IO;
  }
  if (xbfs_fnv1a64(sector, journal.size) != journal.content_hash) {
    xbfs_stat_bump(XBFS_STAT_CHECKSUM_ERROR);
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return xbfs_clear_journal();
  }
  if (xbfs_write_file_locked(journal.path, sector, journal.size) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  if (xbfs_clear_journal() != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  xbfs_stat_bump(XBFS_STAT_REPLAY);
  klog("xaibootfs: journal replay path=%s size=%lu\n",
       journal.path, journal.size);
  return XAIOS_OK;
}

xaios_status_t xbfs_write_pending_journal_file(const char *path,
                                               const void *data,
                                               uint64_t size) {
  if (xbfs_validate_path(path) != XAIOS_OK || data == 0 || size == 0 ||
      size > XBFS_SECTOR_SIZE) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }
  uint8_t sector[XBFS_SECTOR_SIZE];
  xbfs_bytes_zero(sector, sizeof(sector));
  xbfs_bytes_copy(sector, data, size);
  if (xbfs_blk_write(xbfs_journal_data_sector(), sector,
                     sizeof(sector)) != XAIOS_OK) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_IO;
  }
  xaios_xbfs_journal_t journal;
  xbfs_bytes_zero(&journal, sizeof(journal));
  xbfs_bytes_copy(journal.magic, XBFS_JOURNAL_MAGIC, XBFS_MAGIC_LEN);
  journal.version = XBFS_JOURNAL_VERSION;
  journal.state = XBFS_JOURNAL_PENDING;
  journal.op = XBFS_JOURNAL_OP_WRITE_FILE;
  journal.size = size;
  journal.content_hash = xbfs_fnv1a64(data, size);
  xbfs_copy_path(journal.path, path);
  klog("xaibootfs: journal pending path=%s size=%lu\n", path, size);
  return xbfs_write_journal(&journal);
}
