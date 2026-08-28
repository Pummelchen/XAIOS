#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <xaios/storage_admin.h>

/* The kernel logs; a hosted test has no kernel log. Swallowing the output
   keeps this test linking against the same translation unit the kernel builds,
   which is the point of it. */
void klog(const char *fmt, ...) { (void)fmt; }

#define MOCK_RECORDS 96U
#define MOCK_SECTOR_SIZE 512U

typedef struct mock_record {
  uint64_t offset;
  uint8_t bytes[MOCK_SECTOR_SIZE];
  uint32_t valid;
} mock_record_t;

typedef struct mock_disk {
  mock_record_t records[MOCK_RECORDS];
  uint64_t reads;
  uint64_t writes;
  uint64_t flushes;
} mock_disk_t;

static mock_disk_t g_disk;

static mock_record_t *find_record(uint64_t offset) {
  for (uint32_t index = 0U; index < MOCK_RECORDS; ++index) {
    if (g_disk.records[index].valid != 0U &&
        g_disk.records[index].offset == offset) {
      return &g_disk.records[index];
    }
  }
  return 0;
}

static xaios_status_t mock_read(void *context, uint64_t offset, void *buffer,
                                uint64_t length) {
  (void)context;
  if (length != MOCK_SECTOR_SIZE) return XAIOS_ERR_INVALID;
  ++g_disk.reads;
  memset(buffer, 0, (size_t)length);
  mock_record_t *record = find_record(offset);
  if (record != 0) memcpy(buffer, record->bytes, (size_t)length);
  return XAIOS_OK;
}

static xaios_status_t mock_write(void *context, uint64_t offset,
                                 const void *buffer, uint64_t length) {
  (void)context;
  if (length != MOCK_SECTOR_SIZE) return XAIOS_ERR_INVALID;
  ++g_disk.writes;
  mock_record_t *record = find_record(offset);
  if (record == 0) {
    for (uint32_t index = 0U; index < MOCK_RECORDS; ++index) {
      if (g_disk.records[index].valid == 0U) {
        record = &g_disk.records[index];
        record->valid = 1U;
        record->offset = offset;
        break;
      }
    }
  }
  if (record == 0) return XAIOS_ERR_NO_MEMORY;
  memcpy(record->bytes, buffer, (size_t)length);
  return XAIOS_OK;
}

static xaios_status_t mock_flush(void *context) {
  (void)context;
  ++g_disk.flushes;
  return XAIOS_OK;
}

static const xaios_block_backend_ops_t k_mock_ops = {
    mock_read, mock_write, mock_flush, 0, 0};

static xaios_block_device_info_t mock_info(void) {
  xaios_block_device_info_t info;
  memset(&info, 0, sizeof(info));
  memcpy(info.identifier, "/dev/vblk5", 11U);
  memcpy(info.backend, "mock", 5U);
  info.capacity_bytes = UINT64_C(8) << 30U;
  info.capacity_logical_sectors = info.capacity_bytes / MOCK_SECTOR_SIZE;
  info.logical_sector_size = MOCK_SECTOR_SIZE;
  info.physical_block_size = 4096U;
  info.max_transfer_bytes = MOCK_SECTOR_SIZE;
  info.flush_supported = 1U;
  return info;
}

static xaios_storage_partition_request_t request(const char *target,
                                                 const char *name,
                                                 uint64_t size,
                                                 uint32_t type,
                                                 uint64_t operation_id) {
  xaios_storage_partition_request_t value;
  memset(&value, 0, sizeof(value));
  memcpy(value.target, target, strlen(target) + 1U);
  if (name != 0) memcpy(value.name, name, strlen(name) + 1U);
  value.size_bytes = size;
  value.partition_type = type;
  value.operation_id = operation_id;
  return value;
}

static void set_confirmation(xaios_storage_partition_request_t *request,
                             const char *confirmation) {
  memset(request->confirmation, 0, sizeof(request->confirmation));
  memcpy(request->confirmation, confirmation, strlen(confirmation) + 1U);
}

int main(void) {
  assert(block_device_test_reset() == XAIOS_OK);
  memset(&g_disk, 0, sizeof(g_disk));
  xaios_block_device_t device;
  memset(&device, 0, sizeof(device));
  xaios_block_device_info_t info = mock_info();
  assert(block_device_register(&device, &info, &k_mock_ops, &g_disk) ==
         XAIOS_OK);
  assert(storage_admin_attach(&device, 1U) == XAIOS_OK);

  xaios_storage_partition_report_t report;
  assert(storage_admin_partition_verify("/dev/vblk5", &report) ==
         XAIOS_ERR_INVALID);

  xaios_storage_partition_request_t create =
      request("/dev/vblk5", "models", UINT64_C(2) << 30U,
              XAIOS_STORAGE_PARTITION_MODEL, 101U);
  xaios_storage_partition_plan_t plan;
  g_disk.records[0].valid = 1U;
  g_disk.records[0].offset = 0U;
  g_disk.records[0].bytes[0] = 0xa5U;
  assert(storage_admin_partition_plan_create(&create, &plan) ==
         XAIOS_ERR_INVALID);
  memset(&g_disk.records[0], 0, sizeof(g_disk.records[0]));
  uint64_t writes_before = g_disk.writes;
  uint64_t flushes_before = g_disk.flushes;
  assert(storage_admin_partition_plan_create(&create, &plan) == XAIOS_OK);
  assert(g_disk.writes == writes_before && g_disk.flushes == flushes_before);
  assert(strcmp(plan.partition.identifier, "/dev/vblk5p1") == 0);
  assert(plan.partition.size_bytes == (UINT64_C(2) << 30U));
  assert(plan.partition.known_type == XAIOS_STORAGE_PARTITION_MODEL);
  set_confirmation(&create, "00000000-0000-0000-0000-000000000001");
  assert(storage_admin_partition_create(&create, &plan) == XAIOS_ERR_INVALID);
  assert(g_disk.writes == writes_before);
  assert(storage_admin_partition_plan_create(&create, &plan) == XAIOS_OK);
  set_confirmation(&create, plan.report.disk_guid);
  assert(storage_admin_partition_create(&create, &plan) == XAIOS_OK);
  assert(plan.dry_run == 0U && plan.changed == 1U);

  xaios_storage_partition_record_t records[4];
  uint64_t count = 0U;
  assert(storage_admin_partition_list("/dev/vblk5", records, 4U, &count,
                                      &report) == XAIOS_OK);
  assert(count == 1U && report.primary_valid == 1U &&
         report.backup_valid == 1U && report.copies_consistent == 1U);
  assert(strcmp(records[0].identifier, "/dev/vblk5p1") == 0);

  xaios_block_device_t *managed_device = 0;
  xaios_block_device_t *busy = 0;
  xaios_storage_partition_record_t managed_record;
  assert(storage_admin_partition_open(
             "/dev/vblk5p1", XAIOS_STORAGE_PARTITION_STATE, 1U,
             &managed_device, &managed_record) == XAIOS_ERR_UNSUPPORTED);
  assert(storage_admin_partition_open(
             "/dev/vblk5p1", XAIOS_STORAGE_PARTITION_MODEL, 1U,
             &managed_device, &managed_record) == XAIOS_OK);
  assert(strcmp(managed_record.unique_guid, records[0].unique_guid) == 0);
  assert(storage_admin_partition_open(
             "/dev/vblk5p1", XAIOS_STORAGE_PARTITION_MODEL, 1U,
             &busy, &managed_record) == XAIOS_ERR_BUSY);
  assert(storage_admin_partition_close(managed_device) == XAIOS_OK);

  assert(block_device_open("/dev/vblk5p1", &busy) == XAIOS_OK);
  xaios_storage_partition_request_t remove =
      request("/dev/vblk5p1", 0, 0U, 0U, 102U);
  set_confirmation(&remove, records[0].unique_guid);
  assert(storage_admin_partition_delete(&remove, &plan) == XAIOS_ERR_BUSY);
  assert(block_device_close(busy) == XAIOS_OK);

  xaios_storage_partition_request_t grow =
      request("/dev/vblk5p1", 0, UINT64_C(3) << 30U, 0U, 103U);
  assert(storage_admin_partition_plan_resize(&grow, &plan) == XAIOS_OK);
  assert(plan.partition.size_bytes == (UINT64_C(3) << 30U));
  set_confirmation(&grow, plan.partition.unique_guid);
  assert(storage_admin_partition_resize(&grow, &plan) == XAIOS_OK);
  assert(storage_admin_partition_plan_resize(&grow, &plan) ==
         XAIOS_ERR_UNSUPPORTED);

  xaios_storage_partition_request_t create_state =
      request("/dev/vblk5", "state", 0U, XAIOS_STORAGE_PARTITION_STATE,
              104U);
  assert(storage_admin_partition_plan_create(&create_state, &plan) ==
         XAIOS_OK);
  set_confirmation(&create_state, plan.report.disk_guid);
  assert(storage_admin_partition_create(&create_state, &plan) == XAIOS_OK);
  assert(strcmp(plan.partition.identifier, "/dev/vblk5p2") == 0);

  assert(storage_admin_partition_list("/dev/vblk5", records, 4U, &count,
                                      &report) == XAIOS_OK);
  assert(count == 2U);
  set_confirmation(&remove, records[0].unique_guid);
  assert(storage_admin_partition_delete(&remove, &plan) == XAIOS_OK);
  assert(storage_admin_partition_list("/dev/vblk5", records, 4U, &count,
                                      &report) == XAIOS_OK);
  assert(count == 1U);
  assert(strcmp(records[0].identifier, "/dev/vblk5p2") == 0);

  mock_record_t *primary = find_record(MOCK_SECTOR_SIZE);
  assert(primary != 0);
  primary->bytes[16] ^= 0x80U;
  assert(storage_admin_partition_verify("/dev/vblk5", &report) == XAIOS_OK);
  assert(report.primary_valid == 0U && report.backup_valid == 1U);
  xaios_storage_partition_request_t repair =
      request("/dev/vblk5", 0, 0U, 0U, 105U);
  set_confirmation(&repair, report.disk_guid);
  assert(storage_admin_partition_repair(&repair, &plan) == XAIOS_OK);
  assert(plan.report.primary_valid == 1U && plan.report.backup_valid == 1U &&
         plan.report.copies_consistent == 1U);

  assert(storage_admin_detach() == XAIOS_OK);
  assert(storage_admin_attach(&device, 0U) == XAIOS_OK);
  xaios_storage_partition_request_t denied =
      request("/dev/vblk5", "denied", UINT64_C(1) << 30U,
              XAIOS_STORAGE_PARTITION_MODEL, 106U);
  assert(storage_admin_partition_plan_create(&denied, &plan) == XAIOS_OK);
  set_confirmation(&denied, plan.report.disk_guid);
  assert(storage_admin_partition_create(&denied, &plan) == XAIOS_ERR_INVALID);
  assert(storage_admin_detach() == XAIOS_OK);
  assert(block_device_unregister(&device) == XAIOS_OK);
  assert(block_device_test_reset() == XAIOS_OK);
  puts("storage-admin: guarded GPT lifecycle and stable identity passed");
  return 0;
}
