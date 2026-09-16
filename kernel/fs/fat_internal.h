/*
 * fatFS's on-disk codec: the entry layout, the 8.3 and long-name encoders, and
 * the byte-order helpers.
 *
 * Split out of fat.c, which was 1394 lines. Nothing here touches the mounted
 * volume -- these functions turn bytes into names and back -- so the codec
 * moves without an accessor layer for the sector buffer the driver holds.
 */

#ifndef XAIOS_KERNEL_FS_FAT_INTERNAL_H
#define XAIOS_KERNEL_FS_FAT_INTERNAL_H

#include <xaios/fat.h>
#include <xaios/status.h>

#define FAT_NAME_LENGTH 11U
#define FAT_LFN_MAX_ENTRIES 20U
#define FAT_LFN_CHARS 13U

typedef struct fat_name {
  uint8_t short_name[FAT_NAME_LENGTH];
  char text[XAIOS_FAT_PATH_MAX + 1U];
  uint32_t text_length;
  uint32_t needs_long;
} fat_name_t;

typedef struct directory_entry {
  uint8_t name[FAT_NAME_LENGTH];
  uint8_t attributes;
  uint32_t first_cluster;
  uint32_t size;
  uint64_t index;
  uint64_t sector;
  uint64_t offset;
} directory_entry_t;

void fat_bytes_zero(void *buffer, uint64_t length);
void fat_bytes_copy(void *destination, const void *source,
                       uint64_t length);
int fat_bytes_equal(const void *left, const void *right, uint64_t length);
void fat_put16(uint8_t *out, uint16_t value);
void fat_put32(uint8_t *out, uint32_t value);
uint16_t fat_get16(const uint8_t *in);
uint32_t fat_get32(const uint8_t *in);
char fat_upper(char value);
xaios_status_t fat_encode_name(const char *component, uint64_t length,
                                  uint8_t out[FAT_NAME_LENGTH]);
uint8_t fat_lfn_checksum(const uint8_t name[FAT_NAME_LENGTH]);
uint32_t fat_short_name_character(char value);
void fat_short_alias(const char *component, uint64_t length,
                        uint32_t ordinal, uint8_t out[FAT_NAME_LENGTH]);
void fat_decode_entry(const uint8_t *raw, directory_entry_t *entry);
uint32_t fat_lfn_gather(const uint8_t *raw, char *out, uint32_t capacity,
                           uint32_t *out_length);
uint32_t fat_names_equal_fold(const char *a, uint32_t a_length,
                                 const char *b, uint32_t b_length);

extern const uint8_t fat_k_lfn_offsets[FAT_LFN_CHARS];

#endif /* XAIOS_KERNEL_FS_FAT_INTERNAL_H */
