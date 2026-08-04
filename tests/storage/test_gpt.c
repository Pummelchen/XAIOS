#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <xaios/gpt.h>
#include <xaios/partition_device.h>

#define MOCK_RECORDS 96U
#define MOCK_SECTOR_MAX 4096U

typedef struct mock_record {
  uint64_t offset;
  uint64_t length;
  uint8_t bytes[MOCK_SECTOR_MAX];
  uint32_t valid;
} mock_record_t;

typedef struct mock_disk {
  mock_record_t records[MOCK_RECORDS];
  uint64_t writes;
  uint64_t reads;
  uint64_t flushes;
  uint64_t sector_size;
} mock_disk_t;

static mock_disk_t g_disk;
static uint8_t g_read_scratch[XAIOS_GPT_READ_SCRATCH_BYTES];
static uint8_t g_write_scratch[XAIOS_GPT_WRITE_SCRATCH_BYTES];

static mock_record_t *find_record(mock_disk_t *disk, uint64_t offset) {
  for (uint32_t i = 0U; i < MOCK_RECORDS; ++i) {
    if (disk->records[i].valid != 0U && disk->records[i].offset == offset) {
      return &disk->records[i];
    }
  }
  return 0;
}

static xaios_status_t mock_read(void *context, uint64_t offset, void *buffer,
                                uint64_t length) {
  mock_disk_t *disk = (mock_disk_t *)context;
  if (length != disk->sector_size || length > MOCK_SECTOR_MAX) {
    return XAIOS_ERR_INVALID;
  }
  ++disk->reads;
  memset(buffer, 0, (size_t)length);
  mock_record_t *record = find_record(disk, offset);
  if (record != 0) memcpy(buffer, record->bytes, (size_t)length);
  return XAIOS_OK;
}

static xaios_status_t mock_write(void *context, uint64_t offset,
                                 const void *buffer, uint64_t length) {
  mock_disk_t *disk = (mock_disk_t *)context;
  if (length != disk->sector_size || length > MOCK_SECTOR_MAX) {
    return XAIOS_ERR_INVALID;
  }
  ++disk->writes;
  mock_record_t *record = find_record(disk, offset);
  if (record == 0) {
    for (uint32_t i = 0U; i < MOCK_RECORDS; ++i) {
      if (disk->records[i].valid == 0U) {
        record = &disk->records[i];
        record->valid = 1U;
        record->offset = offset;
        record->length = length;
        break;
      }
    }
  }
  if (record == 0) return XAIOS_ERR_NO_MEMORY;
  memcpy(record->bytes, buffer, (size_t)length);
  return XAIOS_OK;
}

static xaios_status_t mock_flush(void *context) {
  ++((mock_disk_t *)context)->flushes;
  return XAIOS_OK;
}

static const xaios_block_backend_ops_t k_mock_ops = {
    mock_read, mock_write, mock_flush, 0, 0};

static xaios_guid_t guid(uint8_t suffix) {
  xaios_guid_t value = {{0x72, 0x31, 0x49, 0x58, 0x41, 0x49, 0x4f, 0x53,
                         0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, suffix}};
  return value;
}

static void set_name(xaios_gpt_partition_t *partition, const char *name) {
  for (uint32_t i = 0U; name[i] != '\0' && i < XAIOS_GPT_NAME_CODE_UNITS;
       ++i) {
    partition->name[i] = (uint16_t)(uint8_t)name[i];
  }
}

static xaios_block_device_info_t disk_info(uint64_t sector_size) {
  xaios_block_device_info_t info;
  memset(&info, 0, sizeof(info));
  memcpy(info.identifier, "/dev/gptmock", 13U);
  memcpy(info.backend, "mock", 5U);
  info.capacity_bytes = UINT64_C(128) << 30U;
  info.logical_sector_size = sector_size;
  info.capacity_logical_sectors = info.capacity_bytes / sector_size;
  info.physical_block_size = 4096U;
  info.max_transfer_bytes = sector_size;
  info.flush_supported = 1U;
  return info;
}

static void initialize_partitions(xaios_gpt_partition_t *partitions,
                                  uint64_t sector_size) {
  memset(partitions, 0, sizeof(*partitions) * 3U);
  uint64_t alignment = UINT64_C(1048576) / sector_size;
  partitions[0].type_guid = XAIOS_GPT_TYPE_STATEFS;
  partitions[0].unique_guid = guid(1U);
  partitions[0].first_lba = alignment;
  partitions[0].last_lba = alignment * 2U - 1U;
  set_name(&partitions[0], "state");
  partitions[1].type_guid = XAIOS_GPT_TYPE_MODELFS;
  partitions[1].unique_guid = guid(2U);
  partitions[1].first_lba = (UINT64_C(4) << 30U) / sector_size;
  partitions[1].last_lba = (UINT64_C(20) << 30U) / sector_size - 1U;
  set_name(&partitions[1], "models");
  partitions[2].type_guid = guid(0xa0U);
  partitions[2].unique_guid = guid(3U);
  partitions[2].first_lba = (UINT64_C(24) << 30U) / sector_size;
  partitions[2].last_lba = (UINT64_C(25) << 30U) / sector_size - 1U;
  set_name(&partitions[2], "unknown");
}

static void corrupt(uint64_t offset, uint32_t byte) {
  mock_record_t *record = find_record(&g_disk, offset);
  assert(record != 0);
  record->bytes[byte] ^= 0x80U;
}

static void test_sector_size(uint64_t sector_size) {
  xaios_block_device_t device;
  xaios_gpt_partition_t partitions[3];
  xaios_gpt_table_t table;
  memset(&device, 0, sizeof(device));
  memset(&g_disk, 0, sizeof(g_disk));
  g_disk.sector_size = sector_size;
  xaios_block_device_info_t info = disk_info(sector_size);
  assert(block_device_register(&device, &info, &k_mock_ops, &g_disk) ==
         XAIOS_OK);
  initialize_partitions(partitions, sector_size);
  xaios_guid_t disk_guid = guid(0xd1U);

  assert(gpt_write(&device, &disk_guid, partitions, 3U, 1U,
                   XAIOS_GPT_FAULT_NONE, g_write_scratch,
                   sizeof(g_write_scratch)) == XAIOS_OK);
  assert(g_disk.writes == 0U && g_disk.flushes == 0U);
  assert(gpt_write(&device, &disk_guid, partitions, 3U, 0U,
                   XAIOS_GPT_FAULT_NONE, g_write_scratch,
                   sizeof(g_write_scratch)) == XAIOS_OK);
  assert(gpt_read(&device, &table, g_read_scratch,
                  sizeof(g_read_scratch)) == XAIOS_OK);
  assert(table.primary_valid == 1U && table.backup_valid == 1U);
  assert(table.copies_consistent == 1U);
  assert(table.selected_copy == XAIOS_GPT_COPY_PRIMARY);
  assert(table.partition_count == 3U);
  assert(gpt_guid_equal(&table.partitions[2].type_guid,
                        &partitions[2].type_guid));
  assert(table.partitions[1].first_lba * sector_size ==
         (UINT64_C(4) << 30U));

  uint64_t last_header = info.capacity_bytes - sector_size;
  corrupt(sector_size, 0U);
  assert(gpt_read(&device, &table, g_read_scratch,
                  sizeof(g_read_scratch)) == XAIOS_OK);
  assert(table.primary_valid == 0U && table.backup_valid == 1U);
  assert(table.selected_copy == XAIOS_GPT_COPY_BACKUP);
  assert(gpt_write(&device, &disk_guid, partitions, 3U, 0U,
                   XAIOS_GPT_FAULT_NONE, g_write_scratch,
                   sizeof(g_write_scratch)) == XAIOS_OK);

  corrupt(last_header, 16U);
  assert(gpt_read(&device, &table, g_read_scratch,
                  sizeof(g_read_scratch)) == XAIOS_OK);
  assert(table.primary_valid == 1U && table.backup_valid == 0U);
  assert(table.selected_copy == XAIOS_GPT_COPY_PRIMARY);
  assert(gpt_write(&device, &disk_guid, partitions, 3U, 0U,
                   XAIOS_GPT_FAULT_NONE, g_write_scratch,
                   sizeof(g_write_scratch)) == XAIOS_OK);

  corrupt(2U * sector_size, 32U);
  assert(gpt_read(&device, &table, g_read_scratch,
                  sizeof(g_read_scratch)) == XAIOS_OK);
  assert(table.primary_valid == 0U && table.backup_valid == 1U);
  assert(gpt_write(&device, &disk_guid, partitions, 3U, 0U,
                   XAIOS_GPT_FAULT_NONE, g_write_scratch,
                   sizeof(g_write_scratch)) == XAIOS_OK);

  xaios_gpt_partition_t bad[3];
  memcpy(bad, partitions, sizeof(bad));
  bad[1].first_lba = bad[0].first_lba;
  uint64_t writes_before = g_disk.writes;
  assert(gpt_write(&device, &disk_guid, bad, 3U, 1U,
                   XAIOS_GPT_FAULT_NONE, g_write_scratch,
                   sizeof(g_write_scratch)) == XAIOS_ERR_INVALID);
  assert(g_disk.writes == writes_before);
  memcpy(bad, partitions, sizeof(bad));
  bad[1].unique_guid = bad[0].unique_guid;
  assert(gpt_write(&device, &disk_guid, bad, 3U, 1U,
                   XAIOS_GPT_FAULT_NONE, g_write_scratch,
                   sizeof(g_write_scratch)) == XAIOS_ERR_INVALID);
  memcpy(bad, partitions, sizeof(bad));
  bad[1].last_lba = UINT64_MAX;
  assert(gpt_write(&device, &disk_guid, bad, 3U, 1U,
                   XAIOS_GPT_FAULT_NONE, g_write_scratch,
                   sizeof(g_write_scratch)) == XAIOS_ERR_INVALID);

  if (sector_size == 512U) {
    for (uint32_t stage = XAIOS_GPT_FAULT_AFTER_MBR;
         stage <= XAIOS_GPT_FAULT_AFTER_PRIMARY_FLUSH; ++stage) {
      assert(gpt_write(&device, &disk_guid, partitions, 3U, 0U,
                       XAIOS_GPT_FAULT_NONE, g_write_scratch,
                       sizeof(g_write_scratch)) == XAIOS_OK);
      memcpy(bad, partitions, sizeof(bad));
      bad[1].last_lba -= 2048U;
      assert(gpt_write(&device, &disk_guid, bad, 3U, 0U,
                       (xaios_gpt_fault_stage_t)stage, g_write_scratch,
                       sizeof(g_write_scratch)) == XAIOS_ERR_IO);
      assert(gpt_read(&device, &table, g_read_scratch,
                      sizeof(g_read_scratch)) == XAIOS_OK);
      uint64_t observed = table.partitions[1].last_lba;
      assert(observed == partitions[1].last_lba ||
             observed == bad[1].last_lba);
    }
    assert(gpt_write(&device, &disk_guid, partitions, 3U, 0U,
                     XAIOS_GPT_FAULT_NONE, g_write_scratch,
                     sizeof(g_write_scratch)) == XAIOS_OK);

    xaios_partition_device_t partition;
    memset(&partition, 0, sizeof(partition));
    assert(partition_device_register(&partition, &device, "/dev/gptmockp2",
                                     &partitions[1], 0U) == XAIOS_OK);
    assert(block_device_unregister(&device) == XAIOS_ERR_BUSY);
    uint8_t marker[512];
    uint8_t result[512];
    memset(marker, 0x5a, sizeof(marker));
    uint64_t relative = (UINT64_C(4) << 30U) + 512U;
    assert(block_write(&partition.block_device, relative, marker,
                       sizeof(marker)) == XAIOS_OK);
    memset(result, 0, sizeof(result));
    assert(block_read(&partition.block_device, relative, result,
                      sizeof(result)) == XAIOS_OK);
    assert(memcmp(marker, result, sizeof(marker)) == 0);
    xaios_block_device_info_t partition_info;
    assert(block_device_info(&partition.block_device, &partition_info) ==
           XAIOS_OK);
    assert(block_write(&partition.block_device, partition_info.capacity_bytes,
                       marker, sizeof(marker)) == XAIOS_ERR_INVALID);
    assert(partition_device_unregister(&partition) == XAIOS_OK);
  }

  corrupt(0U, 510U);
  assert(gpt_read(&device, &table, g_read_scratch,
                  sizeof(g_read_scratch)) == XAIOS_ERR_INVALID);
  assert(block_device_unregister(&device) == XAIOS_OK);
}

static void test_guid_and_stable_slots(void) {
  xaios_guid_t expected = guid(0x7fU);
  xaios_guid_t parsed;
  char text[37];
  assert(gpt_guid_format(&expected, text) == XAIOS_OK);
  assert(strcmp(text, "72314958-4149-4f53-8000-00000000007f") == 0);
  assert(gpt_guid_parse(text, &parsed) == XAIOS_OK);
  assert(gpt_guid_equal(&expected, &parsed));
  assert(gpt_guid_parse("00000000-0000-0000-0000-000000000000", &parsed) ==
         XAIOS_ERR_INVALID);

  xaios_block_device_t device;
  xaios_gpt_partition_t partitions[3];
  xaios_gpt_table_t table;
  memset(&device, 0, sizeof(device));
  memset(&g_disk, 0, sizeof(g_disk));
  g_disk.sector_size = 512U;
  xaios_block_device_info_t info = disk_info(512U);
  assert(block_device_register(&device, &info, &k_mock_ops, &g_disk) ==
         XAIOS_OK);
  initialize_partitions(partitions, 512U);
  partitions[0].table_index = 7U;
  partitions[0].table_index_valid = 1U;
  partitions[1].table_index = 31U;
  partitions[1].table_index_valid = 1U;
  xaios_guid_t disk_guid = guid(0xe1U);
  assert(gpt_write(&device, &disk_guid, partitions, 2U, 0U,
                   XAIOS_GPT_FAULT_NONE, g_write_scratch,
                   sizeof(g_write_scratch)) == XAIOS_OK);
  assert(gpt_read(&device, &table, g_read_scratch,
                  sizeof(g_read_scratch)) == XAIOS_OK);
  assert(table.partition_count == 2U);
  assert(table.partitions[0].table_index == 7U);
  assert(table.partitions[1].table_index == 31U);
  assert(block_device_unregister(&device) == XAIOS_OK);
}

int main(void) {
  assert(block_device_test_reset() == XAIOS_OK);
  test_sector_size(512U);
  assert(block_device_test_reset() == XAIOS_OK);
  test_sector_size(4096U);
  assert(block_device_test_reset() == XAIOS_OK);
  test_guid_and_stable_slots();
  assert(block_device_test_reset() == XAIOS_OK);
  puts("gpt: redundant CRC copies, stable slots, fault recovery, and bounded partitions passed");
  return 0;
}
