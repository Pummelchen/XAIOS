/*
 * The GPT write path: layout validation, the protective MBR, the entry array,
 * and the backup and primary headers in the order they are committed, with the
 * flushes and fault-injection points between them. See gpt_internal.h.
 *
 * Split out of a 625-line gpt.c. The GUID text API and the table reader stay
 * in gpt.c, which also defines the shared primitives this file calls. The move
 * is verbatim: the order of the writes, their flushes and the fault stages is
 * exactly as it was.
 */

#include <xaios/crc32.h>
#include <xaios/gpt.h>

#include "gpt_internal.h"

#define GPT_ALIGNMENT_BYTES UINT64_C(1048576)

static void write_u16(uint8_t *bytes, uint16_t value) {
  bytes[0] = (uint8_t)value;
  bytes[1] = (uint8_t)(value >> 8U);
}

static void write_u64(uint8_t *bytes, uint64_t value) {
  gpt_write_u32(bytes, (uint32_t)value);
  gpt_write_u32(bytes + 4U, (uint32_t)(value >> 32U));
}

static void guid_to_disk(uint8_t *disk, const xaios_guid_t *guid) {
  disk[0] = guid->bytes[3];
  disk[1] = guid->bytes[2];
  disk[2] = guid->bytes[1];
  disk[3] = guid->bytes[0];
  disk[4] = guid->bytes[5];
  disk[5] = guid->bytes[4];
  disk[6] = guid->bytes[7];
  disk[7] = guid->bytes[6];
  gpt_bytes_copy(disk + 8U, guid->bytes + 8U, 8U);
}

static xaios_status_t validate_layout(
    const xaios_block_device_info_t *info, const xaios_guid_t *disk_guid,
    const xaios_gpt_partition_t *partitions, uint64_t partition_count,
    uint64_t *first_usable, uint64_t *last_usable,
    uint64_t *entry_sectors) {
  if (!gpt_valid_geometry(info) || info->read_only != 0U ||
      info->flush_supported == 0U || gpt_guid_is_zero(disk_guid) ||
      partition_count > XAIOS_GPT_MAX_PARTITIONS ||
      (partition_count != 0U && partitions == 0)) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t entry_bytes = XAIOS_GPT_ENTRY_COUNT * XAIOS_GPT_ENTRY_SIZE;
  *entry_sectors =
      (entry_bytes + info->logical_sector_size - 1U) /
      info->logical_sector_size;
  if (info->capacity_logical_sectors <= 3U + 2U * *entry_sectors) {
    return XAIOS_ERR_INVALID;
  }
  *first_usable = 2U + *entry_sectors;
  *last_usable = info->capacity_logical_sectors - 2U - *entry_sectors;
  uint64_t alignment_lbas =
      GPT_ALIGNMENT_BYTES / info->logical_sector_size;
  if (alignment_lbas == 0U) alignment_lbas = 1U;
  for (uint64_t index = 0U; index < partition_count; ++index) {
    const xaios_gpt_partition_t *partition = &partitions[index];
    uint64_t table_index = partition->table_index_valid != 0U
                               ? partition->table_index
                               : index;
    if (gpt_guid_is_zero(&partition->type_guid) ||
        gpt_guid_is_zero(&partition->unique_guid) ||
        partition->first_lba < *first_usable ||
        partition->last_lba > *last_usable ||
        partition->first_lba > partition->last_lba ||
        partition->first_lba % alignment_lbas != 0U ||
        partition->table_index_valid > 1U ||
        table_index >= XAIOS_GPT_ENTRY_COUNT) {
      return XAIOS_ERR_INVALID;
    }
    for (uint64_t previous = 0U; previous < index; ++previous) {
      const xaios_gpt_partition_t *other = &partitions[previous];
      uint64_t other_table_index = other->table_index_valid != 0U
                                       ? other->table_index
                                       : previous;
      if (gpt_guid_equal(&partition->unique_guid, &other->unique_guid) ||
          table_index == other_table_index ||
          !(partition->last_lba < other->first_lba ||
            partition->first_lba > other->last_lba)) {
        return XAIOS_ERR_INVALID;
      }
    }
  }
  return XAIOS_OK;
}

static void encode_entries(uint8_t *entries,
                           const xaios_gpt_partition_t *partitions,
                           uint64_t partition_count) {
  gpt_bytes_zero(entries, XAIOS_GPT_ENTRY_COUNT * XAIOS_GPT_ENTRY_SIZE);
  for (uint64_t index = 0U; index < partition_count; ++index) {
    uint64_t table_index = partitions[index].table_index_valid != 0U
                               ? partitions[index].table_index
                               : index;
    uint8_t *entry = entries + table_index * XAIOS_GPT_ENTRY_SIZE;
    guid_to_disk(entry, &partitions[index].type_guid);
    guid_to_disk(entry + 16U, &partitions[index].unique_guid);
    write_u64(entry + 32U, partitions[index].first_lba);
    write_u64(entry + 40U, partitions[index].last_lba);
    write_u64(entry + 48U, partitions[index].attributes);
    for (uint32_t unit = 0U; unit < XAIOS_GPT_NAME_CODE_UNITS; ++unit) {
      write_u16(entry + 56U + unit * 2U, partitions[index].name[unit]);
    }
  }
}

static void encode_header(uint8_t *sector, uint64_t sector_size,
                          uint64_t current_lba, uint64_t backup_lba,
                          uint64_t first_usable, uint64_t last_usable,
                          const xaios_guid_t *disk_guid, uint64_t entries_lba,
                          uint32_t entries_crc) {
  gpt_bytes_zero(sector, sector_size);
  gpt_bytes_copy(sector, GPT_SIGNATURE, 8U);
  gpt_write_u32(sector + 8U, GPT_REVISION);
  gpt_write_u32(sector + 12U, GPT_HEADER_SIZE);
  write_u64(sector + 24U, current_lba);
  write_u64(sector + 32U, backup_lba);
  write_u64(sector + 40U, first_usable);
  write_u64(sector + 48U, last_usable);
  guid_to_disk(sector + 56U, disk_guid);
  write_u64(sector + 72U, entries_lba);
  gpt_write_u32(sector + 80U, XAIOS_GPT_ENTRY_COUNT);
  gpt_write_u32(sector + 84U, XAIOS_GPT_ENTRY_SIZE);
  gpt_write_u32(sector + 88U, entries_crc);
  gpt_write_u32(sector + 16U, xaios_crc32(sector, GPT_HEADER_SIZE));
}

static xaios_status_t write_protective_mbr(
    xaios_block_device_t *device, const xaios_block_device_info_t *info,
    uint8_t *sector) {
  if (block_read(device, 0U, sector, info->logical_sector_size) != XAIOS_OK) {
    gpt_bytes_zero(sector, info->logical_sector_size);
  }
  gpt_bytes_zero(sector + 446U, 64U);
  uint8_t *entry = sector + 446U;
  entry[1] = 0xffU;
  entry[2] = 0xffU;
  entry[3] = 0xffU;
  entry[4] = 0xeeU;
  entry[5] = 0xffU;
  entry[6] = 0xffU;
  entry[7] = 0xffU;
  gpt_write_u32(entry + 8U, 1U);
  uint64_t sectors = info->capacity_logical_sectors - 1U;
  gpt_write_u32(entry + 12U,
                sectors > UINT32_MAX ? UINT32_MAX : (uint32_t)sectors);
  sector[510] = 0x55U;
  sector[511] = 0xaaU;
  return block_write(device, 0U, sector, info->logical_sector_size);
}

static xaios_status_t write_entries(xaios_block_device_t *device,
                                    uint64_t entries_lba,
                                    const xaios_block_device_info_t *info,
                                    const uint8_t *entries,
                                    uint64_t entry_sectors) {
  uint64_t base = entries_lba * info->logical_sector_size;
  for (uint64_t index = 0U; index < entry_sectors; ++index) {
    xaios_status_t status = block_write(
        device, base + index * info->logical_sector_size,
        entries + index * info->logical_sector_size,
        info->logical_sector_size);
    if (status != XAIOS_OK) return status;
  }
  return XAIOS_OK;
}

xaios_status_t gpt_write(xaios_block_device_t *device,
                         const xaios_guid_t *disk_guid,
                         const xaios_gpt_partition_t *partitions,
                         uint64_t partition_count, uint32_t dry_run,
                         xaios_gpt_fault_stage_t fault_stage, void *scratch,
                         uint64_t scratch_size) {
  if (device == 0 || disk_guid == 0 || scratch == 0 || dry_run > 1U ||
      fault_stage > XAIOS_GPT_FAULT_AFTER_PRIMARY_FLUSH) {
    return XAIOS_ERR_INVALID;
  }
  xaios_block_device_info_t info;
  if (block_device_info(device, &info) != XAIOS_OK ||
      scratch_size < XAIOS_GPT_WRITE_SCRATCH_BYTES) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t first_usable = 0U;
  uint64_t last_usable = 0U;
  uint64_t entry_sectors = 0U;
  xaios_status_t status = validate_layout(
      &info, disk_guid, partitions, partition_count, &first_usable,
      &last_usable, &entry_sectors);
  if (status != XAIOS_OK || dry_run != 0U) return status;

  uint8_t *entries = (uint8_t *)scratch;
  uint8_t *sector = entries + XAIOS_GPT_ENTRY_COUNT * XAIOS_GPT_ENTRY_SIZE;
  encode_entries(entries, partitions, partition_count);
  uint32_t entries_crc = xaios_crc32(
      entries, XAIOS_GPT_ENTRY_COUNT * XAIOS_GPT_ENTRY_SIZE);
  uint64_t last_lba = info.capacity_logical_sectors - 1U;
  uint64_t backup_entries_lba = last_lba - entry_sectors;

  status = write_protective_mbr(device, &info, sector);
  if (status != XAIOS_OK || fault_stage == XAIOS_GPT_FAULT_AFTER_MBR) {
    return status != XAIOS_OK ? status : XAIOS_ERR_IO;
  }
  status = write_entries(device, backup_entries_lba, &info, entries,
                         entry_sectors);
  if (status != XAIOS_OK ||
      fault_stage == XAIOS_GPT_FAULT_AFTER_BACKUP_ENTRIES) {
    return status != XAIOS_OK ? status : XAIOS_ERR_IO;
  }
  encode_header(sector, info.logical_sector_size, last_lba, 1U, first_usable,
                last_usable, disk_guid, backup_entries_lba, entries_crc);
  status = block_write(device, last_lba * info.logical_sector_size, sector,
                       info.logical_sector_size);
  if (status != XAIOS_OK ||
      fault_stage == XAIOS_GPT_FAULT_AFTER_BACKUP_HEADER) {
    return status != XAIOS_OK ? status : XAIOS_ERR_IO;
  }
  status = block_flush(device);
  if (status != XAIOS_OK ||
      fault_stage == XAIOS_GPT_FAULT_AFTER_BACKUP_FLUSH) {
    return status != XAIOS_OK ? status : XAIOS_ERR_IO;
  }

  status = write_entries(device, 2U, &info, entries, entry_sectors);
  if (status != XAIOS_OK ||
      fault_stage == XAIOS_GPT_FAULT_AFTER_PRIMARY_ENTRIES) {
    return status != XAIOS_OK ? status : XAIOS_ERR_IO;
  }
  encode_header(sector, info.logical_sector_size, 1U, last_lba, first_usable,
                last_usable, disk_guid, 2U, entries_crc);
  status = block_write(device, info.logical_sector_size, sector,
                       info.logical_sector_size);
  if (status != XAIOS_OK ||
      fault_stage == XAIOS_GPT_FAULT_AFTER_PRIMARY_HEADER) {
    return status != XAIOS_OK ? status : XAIOS_ERR_IO;
  }
  status = block_flush(device);
  if (status != XAIOS_OK ||
      fault_stage == XAIOS_GPT_FAULT_AFTER_PRIMARY_FLUSH) {
    return status != XAIOS_OK ? status : XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}
