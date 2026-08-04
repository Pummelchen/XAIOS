#include <xaios/crc32.h>
#include <xaios/gpt.h>

#define GPT_HEADER_SIZE 92U
#define GPT_REVISION UINT32_C(0x00010000)
#define GPT_SIGNATURE "EFI PART"
#define GPT_ALIGNMENT_BYTES UINT64_C(1048576)

typedef struct parsed_header {
  uint64_t current_lba;
  uint64_t backup_lba;
  uint64_t first_usable_lba;
  uint64_t last_usable_lba;
  xaios_guid_t disk_guid;
  uint64_t entries_lba;
  uint32_t entry_count;
  uint32_t entry_size;
  uint32_t entry_crc;
  uint32_t valid;
} parsed_header_t;

const xaios_guid_t XAIOS_GPT_TYPE_STATEFS = {
    {0x1f, 0x3b, 0x2d, 0x7a, 0x6e, 0x91, 0x4a, 0x52,
     0x9c, 0x7d, 0x58, 0x41, 0x49, 0x4f, 0x53, 0x01}};
const xaios_guid_t XAIOS_GPT_TYPE_MODELFS = {
    {0x1f, 0x3b, 0x2d, 0x7a, 0x6e, 0x91, 0x4a, 0x52,
     0x9c, 0x7d, 0x58, 0x41, 0x49, 0x4f, 0x53, 0x02}};
const xaios_guid_t XAIOS_GPT_TYPE_RECOVERY = {
    {0x1f, 0x3b, 0x2d, 0x7a, 0x6e, 0x91, 0x4a, 0x52,
     0x9c, 0x7d, 0x58, 0x41, 0x49, 0x4f, 0x53, 0x03}};

static void bytes_zero(void *buffer, uint64_t length) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0U; i < length; ++i) bytes[i] = 0U;
}

static void bytes_copy(void *destination, const void *source, uint64_t length) {
  uint8_t *out = (uint8_t *)destination;
  const uint8_t *in = (const uint8_t *)source;
  for (uint64_t i = 0U; i < length; ++i) out[i] = in[i];
}

static int bytes_equal(const void *left, const void *right, uint64_t length) {
  const uint8_t *a = (const uint8_t *)left;
  const uint8_t *b = (const uint8_t *)right;
  for (uint64_t i = 0U; i < length; ++i) {
    if (a[i] != b[i]) return 0;
  }
  return 1;
}

static uint16_t read_u16(const uint8_t *bytes) {
  return (uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8U);
}

static uint32_t read_u32(const uint8_t *bytes) {
  return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8U) |
         ((uint32_t)bytes[2] << 16U) | ((uint32_t)bytes[3] << 24U);
}

static uint64_t read_u64(const uint8_t *bytes) {
  return (uint64_t)read_u32(bytes) | ((uint64_t)read_u32(bytes + 4U) << 32U);
}

static void write_u16(uint8_t *bytes, uint16_t value) {
  bytes[0] = (uint8_t)value;
  bytes[1] = (uint8_t)(value >> 8U);
}

static void write_u32(uint8_t *bytes, uint32_t value) {
  for (uint32_t i = 0U; i < 4U; ++i) {
    bytes[i] = (uint8_t)(value >> (8U * i));
  }
}

static void write_u64(uint8_t *bytes, uint64_t value) {
  write_u32(bytes, (uint32_t)value);
  write_u32(bytes + 4U, (uint32_t)(value >> 32U));
}

int gpt_guid_equal(const xaios_guid_t *left, const xaios_guid_t *right) {
  return left != 0 && right != 0 &&
         bytes_equal(left->bytes, right->bytes, sizeof(left->bytes));
}

int gpt_guid_is_zero(const xaios_guid_t *guid) {
  if (guid == 0) return 1;
  for (uint32_t i = 0U; i < sizeof(guid->bytes); ++i) {
    if (guid->bytes[i] != 0U) return 0;
  }
  return 1;
}

static int guid_hex_value(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

xaios_status_t gpt_guid_parse(const char *text, xaios_guid_t *guid) {
  if (text == 0 || guid == 0) return XAIOS_ERR_INVALID;
  uint32_t byte = 0U;
  uint32_t cursor = 0U;
  while (byte < 16U) {
    if (cursor == 8U || cursor == 13U || cursor == 18U || cursor == 23U) {
      if (text[cursor++] != '-') return XAIOS_ERR_INVALID;
    }
    int high = guid_hex_value(text[cursor++]);
    int low = guid_hex_value(text[cursor++]);
    if (high < 0 || low < 0) return XAIOS_ERR_INVALID;
    guid->bytes[byte++] = (uint8_t)((high << 4U) | low);
  }
  return cursor == 36U && text[cursor] == '\0' && !gpt_guid_is_zero(guid)
             ? XAIOS_OK
             : XAIOS_ERR_INVALID;
}

xaios_status_t gpt_guid_format(const xaios_guid_t *guid, char output[37]) {
  static const char digits[] = "0123456789abcdef";
  if (guid == 0 || output == 0 || gpt_guid_is_zero(guid)) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t cursor = 0U;
  for (uint32_t byte = 0U; byte < 16U; ++byte) {
    if (cursor == 8U || cursor == 13U || cursor == 18U || cursor == 23U) {
      output[cursor++] = '-';
    }
    output[cursor++] = digits[guid->bytes[byte] >> 4U];
    output[cursor++] = digits[guid->bytes[byte] & 0x0fU];
  }
  output[36] = '\0';
  return XAIOS_OK;
}

static void guid_from_disk(xaios_guid_t *guid, const uint8_t *disk) {
  guid->bytes[0] = disk[3];
  guid->bytes[1] = disk[2];
  guid->bytes[2] = disk[1];
  guid->bytes[3] = disk[0];
  guid->bytes[4] = disk[5];
  guid->bytes[5] = disk[4];
  guid->bytes[6] = disk[7];
  guid->bytes[7] = disk[6];
  bytes_copy(guid->bytes + 8U, disk + 8U, 8U);
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
  bytes_copy(disk + 8U, guid->bytes + 8U, 8U);
}

static int checked_add(uint64_t left, uint64_t right, uint64_t *result) {
  if (result == 0 || right > UINT64_MAX - left) return 0;
  *result = left + right;
  return 1;
}

static int checked_multiply(uint64_t left, uint64_t right, uint64_t *result) {
  if (result == 0 || (left != 0U && right > UINT64_MAX / left)) return 0;
  *result = left * right;
  return 1;
}

static int valid_geometry(const xaios_block_device_info_t *info) {
  return info->logical_sector_size >= 512U &&
         info->logical_sector_size <= XAIOS_GPT_MAX_SECTOR_SIZE &&
         (info->logical_sector_size == 512U ||
          info->logical_sector_size == 4096U) &&
         info->capacity_logical_sectors >= 64U;
}

static int valid_protective_mbr(xaios_block_device_t *device, uint8_t *sector,
                                uint64_t sector_size) {
  if (block_read(device, 0U, sector, sector_size) != XAIOS_OK ||
      sector[510] != 0x55U || sector[511] != 0xaaU) {
    return 0;
  }
  for (uint32_t index = 0U; index < 4U; ++index) {
    const uint8_t *entry = sector + 446U + index * 16U;
    if (entry[4] == 0xeeU && read_u32(entry + 8U) == 1U &&
        read_u32(entry + 12U) != 0U) {
      return 1;
    }
  }
  return 0;
}

static int entry_array_crc(xaios_block_device_t *device,
                           const parsed_header_t *header,
                           uint64_t sector_size, uint8_t *scratch) {
  uint64_t array_bytes = 0U;
  uint64_t byte_offset = 0U;
  if (!checked_multiply(header->entry_count, header->entry_size,
                        &array_bytes) ||
      !checked_multiply(header->entries_lba, sector_size, &byte_offset)) {
    return 0;
  }
  uint32_t crc = xaios_crc32_begin();
  uint64_t completed = 0U;
  while (completed < array_bytes) {
    if (block_read(device, byte_offset + completed, scratch, sector_size) !=
        XAIOS_OK) {
      return 0;
    }
    uint64_t count = array_bytes - completed;
    if (count > sector_size) count = sector_size;
    crc = xaios_crc32_update(crc, scratch, count);
    completed += count;
  }
  return xaios_crc32_finish(crc) == header->entry_crc;
}

static int parse_header(xaios_block_device_t *device, uint64_t header_lba,
                        uint64_t expected_other_lba, uint32_t primary,
                        const xaios_block_device_info_t *info,
                        parsed_header_t *header, uint8_t *scratch) {
  uint64_t header_offset = 0U;
  if (!checked_multiply(header_lba, info->logical_sector_size,
                        &header_offset) ||
      block_read(device, header_offset, scratch, info->logical_sector_size) !=
          XAIOS_OK ||
      !bytes_equal(scratch, GPT_SIGNATURE, 8U) ||
      read_u32(scratch + 8U) != GPT_REVISION) {
    return 0;
  }
  uint32_t header_size = read_u32(scratch + 12U);
  uint32_t stored_crc = read_u32(scratch + 16U);
  if (header_size < GPT_HEADER_SIZE ||
      header_size > info->logical_sector_size || read_u32(scratch + 20U) != 0U) {
    return 0;
  }
  write_u32(scratch + 16U, 0U);
  uint32_t calculated_crc = xaios_crc32(scratch, header_size);
  write_u32(scratch + 16U, stored_crc);
  if (calculated_crc != stored_crc) return 0;

  header->current_lba = read_u64(scratch + 24U);
  header->backup_lba = read_u64(scratch + 32U);
  header->first_usable_lba = read_u64(scratch + 40U);
  header->last_usable_lba = read_u64(scratch + 48U);
  guid_from_disk(&header->disk_guid, scratch + 56U);
  header->entries_lba = read_u64(scratch + 72U);
  header->entry_count = read_u32(scratch + 80U);
  header->entry_size = read_u32(scratch + 84U);
  header->entry_crc = read_u32(scratch + 88U);
  uint64_t array_bytes = 0U;
  uint64_t array_sectors = 0U;
  uint64_t array_end = 0U;
  if (header->current_lba != header_lba ||
      header->backup_lba != expected_other_lba ||
      header->first_usable_lba > header->last_usable_lba ||
      gpt_guid_is_zero(&header->disk_guid) ||
      header->entry_count != XAIOS_GPT_ENTRY_COUNT ||
      header->entry_size != XAIOS_GPT_ENTRY_SIZE ||
      !checked_multiply(header->entry_count, header->entry_size,
                        &array_bytes) ||
      !checked_add(array_bytes, info->logical_sector_size - 1U,
                   &array_sectors)) {
    return 0;
  }
  array_sectors /= info->logical_sector_size;
  if (!checked_add(header->entries_lba, array_sectors, &array_end) ||
      array_end > info->capacity_logical_sectors) {
    return 0;
  }
  if ((primary != 0U &&
       (header->entries_lba <= header_lba ||
        array_end > header->first_usable_lba)) ||
      (primary == 0U &&
       (header->entries_lba <= header->last_usable_lba ||
        array_end > header_lba))) {
    return 0;
  }
  if (!entry_array_crc(device, header, info->logical_sector_size, scratch)) {
    return 0;
  }
  header->valid = 1U;
  return 1;
}

static int headers_consistent(const parsed_header_t *primary,
                              const parsed_header_t *backup) {
  return primary->current_lba == backup->backup_lba &&
         primary->backup_lba == backup->current_lba &&
         primary->first_usable_lba == backup->first_usable_lba &&
         primary->last_usable_lba == backup->last_usable_lba &&
         gpt_guid_equal(&primary->disk_guid, &backup->disk_guid) &&
         primary->entry_count == backup->entry_count &&
         primary->entry_size == backup->entry_size &&
         primary->entry_crc == backup->entry_crc;
}

static xaios_status_t parse_partitions(
    xaios_block_device_t *device, const parsed_header_t *header,
    const xaios_block_device_info_t *info, xaios_gpt_table_t *table,
    uint8_t *scratch) {
  uint64_t array_offset = 0U;
  if (!checked_multiply(header->entries_lba, info->logical_sector_size,
                        &array_offset)) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t cached_lba = UINT64_MAX;
  for (uint32_t index = 0U; index < header->entry_count; ++index) {
    uint64_t entry_delta = (uint64_t)index * header->entry_size;
    uint64_t entry_offset = array_offset + entry_delta;
    uint64_t lba = entry_offset / info->logical_sector_size;
    uint64_t within = entry_offset % info->logical_sector_size;
    if (within + XAIOS_GPT_ENTRY_SIZE > info->logical_sector_size) {
      return XAIOS_ERR_UNSUPPORTED;
    }
    if (lba != cached_lba) {
      if (block_read(device, lba * info->logical_sector_size, scratch,
                     info->logical_sector_size) != XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
      cached_lba = lba;
    }
    const uint8_t *entry = scratch + within;
    xaios_guid_t type_guid;
    guid_from_disk(&type_guid, entry);
    if (gpt_guid_is_zero(&type_guid)) continue;
    if (table->partition_count >= XAIOS_GPT_MAX_PARTITIONS) {
      return XAIOS_ERR_NO_MEMORY;
    }
    xaios_gpt_partition_t *partition =
        &table->partitions[table->partition_count];
    bytes_zero(partition, sizeof(*partition));
    partition->type_guid = type_guid;
    guid_from_disk(&partition->unique_guid, entry + 16U);
    partition->first_lba = read_u64(entry + 32U);
    partition->last_lba = read_u64(entry + 40U);
    partition->attributes = read_u64(entry + 48U);
    partition->table_index = index;
    partition->table_index_valid = 1U;
    for (uint32_t unit = 0U; unit < XAIOS_GPT_NAME_CODE_UNITS; ++unit) {
      partition->name[unit] = read_u16(entry + 56U + unit * 2U);
    }
    if (gpt_guid_is_zero(&partition->unique_guid) ||
        partition->first_lba < header->first_usable_lba ||
        partition->last_lba > header->last_usable_lba ||
        partition->first_lba > partition->last_lba) {
      return XAIOS_ERR_INVALID;
    }
    for (uint64_t previous = 0U; previous < table->partition_count;
         ++previous) {
      const xaios_gpt_partition_t *other = &table->partitions[previous];
      if (gpt_guid_equal(&partition->unique_guid, &other->unique_guid) ||
          !(partition->last_lba < other->first_lba ||
            partition->first_lba > other->last_lba)) {
        return XAIOS_ERR_INVALID;
      }
    }
    ++table->partition_count;
  }
  return XAIOS_OK;
}

xaios_status_t gpt_read(xaios_block_device_t *device,
                        xaios_gpt_table_t *table, void *scratch,
                        uint64_t scratch_size) {
  if (device == 0 || table == 0 || scratch == 0) return XAIOS_ERR_INVALID;
  xaios_block_device_info_t info;
  if (block_device_info(device, &info) != XAIOS_OK || !valid_geometry(&info) ||
      scratch_size < info.logical_sector_size) {
    return XAIOS_ERR_INVALID;
  }
  bytes_zero(table, sizeof(*table));
  uint8_t *sector = (uint8_t *)scratch;
  if (!valid_protective_mbr(device, sector, info.logical_sector_size)) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t last_lba = info.capacity_logical_sectors - 1U;
  parsed_header_t primary;
  parsed_header_t backup;
  bytes_zero(&primary, sizeof(primary));
  bytes_zero(&backup, sizeof(backup));
  table->primary_valid =
      (uint32_t)parse_header(device, 1U, last_lba, 1U, &info, &primary, sector);
  table->backup_valid = (uint32_t)parse_header(
      device, last_lba, 1U, 0U, &info, &backup, sector);
  if (table->primary_valid == 0U && table->backup_valid == 0U) {
    return XAIOS_ERR_INVALID;
  }
  const parsed_header_t *selected = 0;
  if (table->primary_valid != 0U) {
    selected = &primary;
    table->selected_copy = XAIOS_GPT_COPY_PRIMARY;
  } else {
    selected = &backup;
    table->selected_copy = XAIOS_GPT_COPY_BACKUP;
  }
  table->copies_consistent =
      table->primary_valid != 0U && table->backup_valid != 0U &&
      headers_consistent(&primary, &backup);
  table->disk_guid = selected->disk_guid;
  table->first_usable_lba = selected->first_usable_lba;
  table->last_usable_lba = selected->last_usable_lba;
  return parse_partitions(device, selected, &info, table, sector);
}

static xaios_status_t validate_layout(
    const xaios_block_device_info_t *info, const xaios_guid_t *disk_guid,
    const xaios_gpt_partition_t *partitions, uint64_t partition_count,
    uint64_t *first_usable, uint64_t *last_usable,
    uint64_t *entry_sectors) {
  if (!valid_geometry(info) || info->read_only != 0U ||
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
  bytes_zero(entries, XAIOS_GPT_ENTRY_COUNT * XAIOS_GPT_ENTRY_SIZE);
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
  bytes_zero(sector, sector_size);
  bytes_copy(sector, GPT_SIGNATURE, 8U);
  write_u32(sector + 8U, GPT_REVISION);
  write_u32(sector + 12U, GPT_HEADER_SIZE);
  write_u64(sector + 24U, current_lba);
  write_u64(sector + 32U, backup_lba);
  write_u64(sector + 40U, first_usable);
  write_u64(sector + 48U, last_usable);
  guid_to_disk(sector + 56U, disk_guid);
  write_u64(sector + 72U, entries_lba);
  write_u32(sector + 80U, XAIOS_GPT_ENTRY_COUNT);
  write_u32(sector + 84U, XAIOS_GPT_ENTRY_SIZE);
  write_u32(sector + 88U, entries_crc);
  write_u32(sector + 16U, xaios_crc32(sector, GPT_HEADER_SIZE));
}

static xaios_status_t write_protective_mbr(
    xaios_block_device_t *device, const xaios_block_device_info_t *info,
    uint8_t *sector) {
  if (block_read(device, 0U, sector, info->logical_sector_size) != XAIOS_OK) {
    bytes_zero(sector, info->logical_sector_size);
  }
  bytes_zero(sector + 446U, 64U);
  uint8_t *entry = sector + 446U;
  entry[1] = 0xffU;
  entry[2] = 0xffU;
  entry[3] = 0xffU;
  entry[4] = 0xeeU;
  entry[5] = 0xffU;
  entry[6] = 0xffU;
  entry[7] = 0xffU;
  write_u32(entry + 8U, 1U);
  uint64_t sectors = info->capacity_logical_sectors - 1U;
  write_u32(entry + 12U,
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
