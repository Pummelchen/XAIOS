#ifndef XAIOS_GPT_H
#define XAIOS_GPT_H

#include <xaios/block_device.h>
#include <xaios/status.h>
#include <xaios/types.h>

/* What XAIOS writes when it creates a table. Reading is deliberately not
   pinned to it: the UEFI specification lets whoever made a table declare its
   own entry count, requiring only that the array reserve at least 16384 bytes
   -- 128 entries of 128 -- and tools do differ. xorriso writes 248, so a
   reader that insisted on exactly 128 rejected the GPT in XAIOS's own unified
   image, which is the table a machine booted from a USB stick has to read to
   find the partition an install copies from. */
#define XAIOS_GPT_ENTRY_COUNT 128U
/* The most a declared count may be before the table is refused as unreasonable
   rather than merely large. Bounds the array walk; the entries themselves are
   still capped by XAIOS_GPT_MAX_PARTITIONS. */
#define XAIOS_GPT_ENTRY_COUNT_MAX 1024U
#define XAIOS_GPT_ENTRY_SIZE 128U
#define XAIOS_GPT_MAX_PARTITIONS 128U
#define XAIOS_GPT_NAME_CODE_UNITS 36U
#define XAIOS_GPT_MAX_SECTOR_SIZE 4096U
#define XAIOS_GPT_READ_SCRATCH_BYTES XAIOS_GPT_MAX_SECTOR_SIZE
#define XAIOS_GPT_WRITE_SCRATCH_BYTES \
  (XAIOS_GPT_ENTRY_COUNT * XAIOS_GPT_ENTRY_SIZE + \
   XAIOS_GPT_MAX_SECTOR_SIZE)

typedef struct xaios_guid {
  uint8_t bytes[16];
} xaios_guid_t;

extern const xaios_guid_t XAIOS_GPT_TYPE_STATEFS;
extern const xaios_guid_t XAIOS_GPT_TYPE_MODELFS;
extern const xaios_guid_t XAIOS_GPT_TYPE_RECOVERY;
/* C12A7328-F81F-11D2-BA4B-00A0C93EC93B, the EFI System Partition. Not a XAIOS
   type: firmware looks for this exact value, so a partition XAIOS creates for
   its own loader has to carry the one everybody else uses. */
extern const xaios_guid_t XAIOS_GPT_TYPE_ESP;

typedef struct xaios_gpt_partition {
  xaios_guid_t type_guid;
  xaios_guid_t unique_guid;
  uint64_t first_lba;
  uint64_t last_lba;
  uint64_t attributes;
  uint16_t name[XAIOS_GPT_NAME_CODE_UNITS];
  uint32_t table_index;
  uint32_t table_index_valid;
} xaios_gpt_partition_t;

typedef enum xaios_gpt_selected_copy {
  XAIOS_GPT_COPY_NONE = 0,
  XAIOS_GPT_COPY_PRIMARY = 1,
  XAIOS_GPT_COPY_BACKUP = 2,
} xaios_gpt_selected_copy_t;

typedef struct xaios_gpt_table {
  xaios_guid_t disk_guid;
  uint64_t first_usable_lba;
  uint64_t last_usable_lba;
  uint64_t partition_count;
  uint32_t primary_valid;
  uint32_t backup_valid;
  uint32_t copies_consistent;
  uint32_t selected_copy;
  xaios_gpt_partition_t partitions[XAIOS_GPT_MAX_PARTITIONS];
} xaios_gpt_table_t;

typedef enum xaios_gpt_fault_stage {
  XAIOS_GPT_FAULT_NONE = 0,
  XAIOS_GPT_FAULT_AFTER_MBR = 1,
  XAIOS_GPT_FAULT_AFTER_BACKUP_ENTRIES = 2,
  XAIOS_GPT_FAULT_AFTER_BACKUP_HEADER = 3,
  XAIOS_GPT_FAULT_AFTER_BACKUP_FLUSH = 4,
  XAIOS_GPT_FAULT_AFTER_PRIMARY_ENTRIES = 5,
  XAIOS_GPT_FAULT_AFTER_PRIMARY_HEADER = 6,
  XAIOS_GPT_FAULT_AFTER_PRIMARY_FLUSH = 7,
} xaios_gpt_fault_stage_t;

int gpt_guid_equal(const xaios_guid_t *left, const xaios_guid_t *right);
int gpt_guid_is_zero(const xaios_guid_t *guid);
xaios_status_t gpt_guid_parse(const char *text, xaios_guid_t *guid);
xaios_status_t gpt_guid_format(const xaios_guid_t *guid, char output[37]);
xaios_status_t gpt_read(xaios_block_device_t *device,
                        xaios_gpt_table_t *table, void *scratch,
                        uint64_t scratch_size);
xaios_status_t gpt_write(xaios_block_device_t *device,
                         const xaios_guid_t *disk_guid,
                         const xaios_gpt_partition_t *partitions,
                         uint64_t partition_count, uint32_t dry_run,
                         xaios_gpt_fault_stage_t fault_stage, void *scratch,
                         uint64_t scratch_size);

#endif
