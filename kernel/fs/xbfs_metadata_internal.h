/*
 * Private interface for xbfs_metadata.c, the translation unit that owns
 * xaibootFS's metadata buffer, its per-slot shadow, the slot/sequence/mirror
 * scalars and the journal.
 *
 * Split out of xaiboot_fs.c, which keeps the codec between the metadata buffer
 * and the volume state (`g_xbfs`): read_metadata_slot, metadata_slot_probe,
 * read_metadata and write_metadata still live there, because they index that
 * state field by field and moving them would mean an accessor per field.
 *
 * The buffer and the shadow are large static arrays that blk_read fills and
 * the codec parses in place, so the honest accessor hands back their address
 * rather than a copy: xbfs_metadata_buffer() and xbfs_metadata_shadow() return
 * a pointer valid for the duration of the call that asked for it -- the next
 * metadata or journal call overwrites it -- and the caller must neither retain
 * it nor hand it to another translation unit. A copy into a caller-owned local
 * is not offered because the buffer is 1.75 MiB, far past any stack frame.
 * Every other value here is a scalar with a get and a set, or a named operation
 * (xbfs_metadata_note_mirror_recovery) where an increment is the only mutation.
 *
 * xaiboot_fs.c still defines the block I/O wrappers and the path validation
 * the journal calls, so they are declared here and cross back to it.
 */

#ifndef XAIOS_KERNEL_FS_XBFS_METADATA_INTERNAL_H
#define XAIOS_KERNEL_FS_XBFS_METADATA_INTERNAL_H

#include "xbfs_internal.h"

/* The volume header and the journal record. These lived in xaiboot_fs.c beside
   the code that reads them; the journal now lives here, so the shapes it
   serialises cross in this header. XBFS_VERSION, XBFS_METADATA_SECTORS and
   XBFS_METADATA_SLOTS stay in xaiboot_fs.c: only the codec there uses them. */
#define XBFS_MAGIC "XAIOSMFS2"
#define XBFS_MAGIC_LEN 8U
#define XBFS_START_SECTOR UINT64_C(3072)
#define XBFS_JOURNAL_MAGIC "XAIOSMFJ1"
#define XBFS_JOURNAL_VERSION 1U
#define XBFS_JOURNAL_SECTORS UINT64_C(2)
#define XBFS_SEQUENCE_TAIL_BYTES UINT64_C(16)
#define XBFS_JOURNAL_EMPTY 0U
#define XBFS_JOURNAL_PENDING 1U
#define XBFS_JOURNAL_OP_WRITE_FILE 1U

/* One journal header sector, exactly XBFS_SECTOR_SIZE bytes: the layout is
   unchanged and the self-test in xaiboot_fs.c still asserts the size. */
typedef struct xaios_xbfs_journal {
  char magic[XBFS_MAGIC_LEN];
  uint32_t version;
  uint32_t state;
  uint32_t op;
  uint32_t reserved;
  uint64_t size;
  uint64_t content_hash;
  uint64_t checksum;
  char path[XBFS_PATH_MAX];
  uint8_t padding[208];
} xaios_xbfs_journal_t;

/* The metadata buffer and the per-slot shadow. See the note above: each
   pointer is good for the duration of one call and no longer. */
uint8_t *xbfs_metadata_buffer(void);
uint64_t xbfs_metadata_buffer_bytes(void);
uint8_t *xbfs_metadata_shadow(uint32_t slot);
uint32_t xbfs_metadata_shadow_valid(uint32_t slot);
void xbfs_metadata_shadow_set_valid(uint32_t slot, uint32_t valid);

/* The slot/sequence/mirror scalars. */
uint64_t xbfs_metadata_verified_checksum(void);
void xbfs_metadata_set_verified_checksum(uint64_t checksum);
uint32_t xbfs_metadata_slot(void);
void xbfs_metadata_set_slot(uint32_t slot);
uint32_t xbfs_metadata_mirror_enabled(void);
void xbfs_metadata_set_mirror_enabled(uint32_t enabled);
uint64_t xbfs_metadata_sequence(void);
void xbfs_metadata_set_sequence(uint64_t sequence);
uint64_t xbfs_metadata_mirror_recoveries(void);
void xbfs_metadata_note_mirror_recovery(void);

/* The sector arithmetic the metadata layout and the journal share. */
uint64_t xbfs_journal_header_sector(void);
uint64_t xbfs_journal_data_sector(void);
uint64_t xbfs_data_start_sector(void);
uint64_t xbfs_metadata_mirror_start_sector(void);
uint64_t xbfs_metadata_slot_start_sector(uint32_t slot);
uint64_t xbfs_metadata_sequence_offset(void);
int xbfs_metadata_header_is_blank(void);

/* The journal: the record checksum, the clear/read/write triple, the pending
   record a write stages, and the replay mount performs. */
uint64_t xbfs_journal_checksum(xaios_xbfs_journal_t *journal);
xaios_status_t xbfs_clear_journal(void);
xaios_status_t xbfs_read_journal(xaios_xbfs_journal_t *journal);
xaios_status_t xbfs_write_journal(xaios_xbfs_journal_t *journal);
xaios_status_t xbfs_replay_journal(void);
xaios_status_t xbfs_write_pending_journal_file(const char *path,
                                               const void *data,
                                               uint64_t size);

/* Defined in xaiboot_fs.c and called from here. */
xaios_status_t xbfs_blk_read(uint64_t sector, void *buffer, uint64_t size);
xaios_status_t xbfs_blk_write(uint64_t sector, const void *buffer,
                              uint64_t size);
xaios_status_t xbfs_blk_flush(void);
uint64_t xbfs_blk_capacity(void);
xaios_status_t xbfs_validate_path(const char *path);

#endif /* XAIOS_KERNEL_FS_XBFS_METADATA_INTERNAL_H */
