/*
 * Private interface between fat.c, fat_dir.c and fat_file_io.c: the on-disk
 * layout constants, the one scratch sector every read-modify-write borrows, and
 * the directory walk and entry placement the file operations call.
 *
 * Split out of fat.c, which was 1238 lines. The volume, the sector scratch and
 * the FAT chain helpers stay in fat.c; the directory layer is fat_dir.c and the
 * file operations are fat_file_io.c. Nothing here owns state that the module
 * did not already own as a static: the scratch sector is defined once, in
 * fat.c, and declared here, so the three translation units share the one buffer
 * and the one-writer assumption that made it correct -- serialising an
 * installer on this buffer is still cheaper than discovering two writers later.
 */

#ifndef XAIOS_KERNEL_FS_FAT_VOLUME_INTERNAL_H
#define XAIOS_KERNEL_FS_FAT_VOLUME_INTERNAL_H

#include "fat_internal.h"

/* On-disk layout constants. All FAT structures are little-endian regardless of
   the machine, so every field goes through the codec's put/get helpers rather
   than being written as a struct. */
#define FAT_SECTOR_SIZE UINT64_C(512)
#define FAT_DIR_ENTRY_SIZE UINT64_C(32)
#define FAT_ROOT_ENTRIES UINT64_C(512)
#define FAT_RESERVED_SECTORS UINT64_C(1)
#define FAT_COPIES UINT64_C(2)
#define FAT_EOC UINT32_C(0xFFFF)
#define FAT_FREE UINT32_C(0)
/* FAT16 is defined by cluster count, not by anything in the boot sector: a
   volume with fewer than 4085 clusters is FAT12 and firmware will read it as
   FAT12 no matter what the file system type string says. Staying inside these
   bounds is what makes the volume actually be the thing it claims. */
#define FAT_MIN_CLUSTERS UINT64_C(4085)
#define FAT_MAX_CLUSTERS UINT64_C(65524)
/* What the format aims for when it can. Not a limit of the format -- a limit
   on how much work writing a file costs, since every cluster is an allocation
   and three FAT sector operations. */
#define FAT_PREFERRED_MAX_CLUSTERS UINT64_C(8192)

#define FAT_ATTR_READ_ONLY UINT8_C(0x01)
#define FAT_ATTR_VOLUME_ID UINT8_C(0x08)
#define FAT_ATTR_DIRECTORY UINT8_C(0x10)
#define FAT_ATTR_LONG_NAME UINT8_C(0x0F)
#define FAT_LFN_LAST UINT8_C(0x40)

/* 1980-01-01. Year is counted from 1980 in bits 15..9, month one-based in bits
   8..5, day one-based in bits 4..0. */
#define FAT_EPOCH_DATE UINT16_C(0x0021)

/* A directory is either the fixed-size root region or a cluster chain. The two
 * are addressed differently on disk and identically everywhere else, so this
 * pair of accessors is what keeps the rest of the module from caring.
 */
typedef struct directory_cursor {
  uint32_t is_root;
  uint32_t first_cluster;
} directory_cursor_t;

/* Passed as `existing_index` when a named entry is being placed for the first
   time rather than rewritten in place. */
#define FAT_NO_EXISTING_ENTRY UINT64_MAX

/* The one sector of scratch, defined in fat.c. Every read-modify-write in the
   module borrows it for the duration of one call; it is never returned to a
   caller and never held across a call. */
extern uint8_t g_fat_sector[FAT_SECTOR_SIZE];

xaios_status_t fat_read_sector(const xaios_fat_volume_t *volume,
                               uint64_t sector, void *buffer);
xaios_status_t fat_write_sector(const xaios_fat_volume_t *volume,
                                uint64_t sector, const void *buffer);
uint64_t fat_cluster_sector(const xaios_fat_volume_t *volume,
                            uint32_t cluster);
xaios_status_t fat_entry_get(const xaios_fat_volume_t *volume,
                             uint32_t cluster, uint32_t *out_value);
xaios_status_t fat_entry_set(const xaios_fat_volume_t *volume,
                             uint32_t cluster, uint32_t value);
xaios_status_t fat_allocate_cluster(const xaios_fat_volume_t *volume,
                                    uint32_t *out_cluster);
xaios_status_t fat_zero_cluster(const xaios_fat_volume_t *volume,
                                uint32_t cluster);
xaios_status_t fat_free_chain(const xaios_fat_volume_t *volume,
                              uint32_t first);

/* Defined in fat_dir.c. fat_find_entry reads `entry` from the directory the
   cursor names; the sector and offset it records are the ones the 8.3 entry
   occupies, good only until the next scratch-sector use. */
xaios_status_t fat_find_entry(const xaios_fat_volume_t *volume,
                              const directory_cursor_t *cursor,
                              const fat_name_t *name,
                              directory_entry_t *entry);
xaios_status_t fat_write_entry(const xaios_fat_volume_t *volume,
                               const directory_cursor_t *cursor,
                               uint64_t index,
                               const uint8_t name[FAT_NAME_LENGTH],
                               uint8_t attributes, uint32_t first_cluster,
                               uint32_t size);
xaios_status_t fat_write_named_entry(const xaios_fat_volume_t *volume,
                                     const directory_cursor_t *cursor,
                                     fat_name_t *name,
                                     uint64_t existing_index,
                                     uint8_t attributes,
                                     uint32_t first_cluster, uint32_t size);
xaios_status_t fat_resolve_parent(const xaios_fat_volume_t *volume,
                                  const char *path,
                                  directory_cursor_t *parent,
                                  fat_name_t *final_name);

#endif /* XAIOS_KERNEL_FS_FAT_VOLUME_INTERNAL_H */
