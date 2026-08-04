#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <xaios/model_volume_admin.h>

typedef struct file_disk {
  FILE *file;
  uint64_t reads;
  uint64_t writes;
  uint64_t flushes;
} file_disk_t;

int xaios_random(void *buffer, uint64_t size) {
  (void)buffer;
  (void)size;
  return -1;
}

static xaios_status_t file_read(void *context, uint64_t offset, void *buffer,
                                uint64_t length) {
  file_disk_t *disk = (file_disk_t *)context;
  ++disk->reads;
  return offset <= (uint64_t)INT64_MAX && length <= (uint64_t)SIZE_MAX &&
                 fseeko(disk->file, (off_t)offset, SEEK_SET) == 0 &&
                 fread(buffer, 1U, (size_t)length, disk->file) ==
                     (size_t)length
             ? XAIOS_OK
             : XAIOS_ERR_IO;
}

static xaios_status_t file_write(void *context, uint64_t offset,
                                 const void *buffer, uint64_t length) {
  file_disk_t *disk = (file_disk_t *)context;
  ++disk->writes;
  return offset <= (uint64_t)INT64_MAX && length <= (uint64_t)SIZE_MAX &&
                 fseeko(disk->file, (off_t)offset, SEEK_SET) == 0 &&
                 fwrite(buffer, 1U, (size_t)length, disk->file) ==
                     (size_t)length
             ? XAIOS_OK
             : XAIOS_ERR_IO;
}

static xaios_status_t file_flush(void *context) {
  file_disk_t *disk = (file_disk_t *)context;
  ++disk->flushes;
  return fflush(disk->file) == 0 && fsync(fileno(disk->file)) == 0
             ? XAIOS_OK
             : XAIOS_ERR_IO;
}

static const xaios_block_backend_ops_t k_file_ops = {
    file_read, file_write, file_flush, 0, 0};

static xaios_storage_partition_request_t partition_request(
    const char *target, const char *name, uint64_t size,
    uint32_t partition_type, uint64_t operation_id) {
  xaios_storage_partition_request_t request;
  memset(&request, 0, sizeof(request));
  memcpy(request.target, target, strlen(target) + 1U);
  if (name != 0) memcpy(request.name, name, strlen(name) + 1U);
  request.size_bytes = size;
  request.partition_type = partition_type;
  request.operation_id = operation_id;
  return request;
}

static void confirm(xaios_storage_partition_request_t *request,
                    const char *uuid) {
  memset(request->confirmation, 0, sizeof(request->confirmation));
  memcpy(request->confirmation, uuid, strlen(uuid) + 1U);
}

int main(void) {
  const uint64_t disk_size = UINT64_C(256) << 20U;
  FILE *file = tmpfile();
  assert(file != NULL);
  assert(ftruncate(fileno(file), (off_t)disk_size) == 0);
  file_disk_t disk = {file, 0U, 0U, 0U};

  assert(block_device_test_reset() == XAIOS_OK);
  xaios_block_device_t device;
  memset(&device, 0, sizeof(device));
  xaios_block_device_info_t info;
  memset(&info, 0, sizeof(info));
  memcpy(info.identifier, "/dev/vblk5", 11U);
  memcpy(info.backend, "host-file", 10U);
  info.capacity_bytes = disk_size;
  info.capacity_logical_sectors = disk_size / 512U;
  info.logical_sector_size = 512U;
  info.physical_block_size = 4096U;
  info.max_transfer_bytes = 65536U;
  info.flush_supported = 1U;
  assert(block_device_register(&device, &info, &k_file_ops, &disk) ==
         XAIOS_OK);
  assert(storage_admin_attach(&device, 1U) == XAIOS_OK);

  xaios_storage_partition_request_t create = partition_request(
      "/dev/vblk5", "models", UINT64_C(64) << 20U,
      XAIOS_STORAGE_PARTITION_MODEL, 501U);
  xaios_storage_partition_plan_t partition_plan;
  assert(storage_admin_partition_plan_create(&create, &partition_plan) ==
         XAIOS_OK);
  confirm(&create, partition_plan.report.disk_guid);
  assert(storage_admin_partition_create(&create, &partition_plan) == XAIOS_OK);

  xaios_model_volume_admin_report_t report;
  uint64_t writes_before = disk.writes;
  assert(model_volume_admin_format_plan("/dev/vblk5p1", UINT64_C(2097152),
                                        &report) == XAIOS_OK);
  assert(report.dry_run == 1U && report.volume_bytes == (UINT64_C(64) << 20U));
  assert(disk.writes == writes_before);
  assert(model_volume_admin_format(
             "/dev/vblk5p1", "00000000-0000-0000-0000-000000000001",
             UINT64_C(2097152), &report) == XAIOS_ERR_INVALID);
  assert(disk.writes == writes_before);
  assert(model_volume_admin_format("/dev/vblk5p1", report.partition_uuid,
                                   UINT64_C(2097152), &report) == XAIOS_OK);
  assert(report.check_state == XAIOS_MODEL_VOLUME_CHECK_CLEAN &&
         report.first_superblock_valid == 1U &&
         report.second_superblock_valid == 1U && report.generation == 1U);

  assert(model_volume_admin_fsck("/dev/vblk5p1", 1U, &report) == XAIOS_OK);
  assert(report.check_state == XAIOS_MODEL_VOLUME_CHECK_CLEAN &&
         report.checked_bytes == 0U);

  xaios_block_device_t *busy = 0;
  assert(block_device_open("/dev/vblk5p1", &busy) == XAIOS_OK);
  assert(model_volume_admin_format_plan("/dev/vblk5p1", UINT64_C(2097152),
                                        &report) == XAIOS_ERR_BUSY);
  assert(block_device_close(busy) == XAIOS_OK);

  xaios_storage_partition_record_t records[2];
  xaios_storage_partition_report_t partition_report;
  uint64_t count = 0U;
  assert(storage_admin_partition_list("/dev/vblk5", records, 2U, &count,
                                      &partition_report) == XAIOS_OK);
  assert(count == 1U);
  uint64_t partition_offset = records[0].first_lba * 512U;
  uint8_t corrupt = 0xa5U;
  assert(fseeko(file, (off_t)partition_offset, SEEK_SET) == 0);
  assert(fwrite(&corrupt, 1U, 1U, file) == 1U);
  assert(fflush(file) == 0);
  assert(model_volume_admin_fsck("/dev/vblk5p1", 0U, &report) == XAIOS_OK);
  assert(report.check_state == XAIOS_MODEL_VOLUME_CHECK_REPAIRABLE &&
         report.first_superblock_valid == 0U &&
         report.second_superblock_valid == 1U);
  assert(model_volume_admin_repair(
             "/dev/vblk5p1", "00000000-0000-0000-0000-000000000001",
             &report) == XAIOS_ERR_INVALID);
  assert(model_volume_admin_repair("/dev/vblk5p1", records[0].unique_guid,
                                   &report) == XAIOS_OK);
  assert(report.check_state == XAIOS_MODEL_VOLUME_CHECK_REPAIRED &&
         report.first_superblock_valid == 1U &&
         report.second_superblock_valid == 1U);

  xaios_storage_partition_request_t resize = partition_request(
      "/dev/vblk5p1", 0, UINT64_C(96) << 20U, 0U, 502U);
  assert(storage_admin_partition_plan_resize(&resize, &partition_plan) ==
         XAIOS_OK);
  confirm(&resize, partition_plan.partition.unique_guid);
  assert(storage_admin_partition_resize(&resize, &partition_plan) == XAIOS_OK);
  assert(model_volume_admin_grow("/dev/vblk5p1",
                                 partition_plan.partition.unique_guid, 0U,
                                 &report) == XAIOS_OK);
  assert(report.volume_bytes == (UINT64_C(96) << 20U) &&
         report.generation == 2U);
  assert(model_volume_admin_grow("/dev/vblk5p1",
                                 partition_plan.partition.unique_guid,
                                 UINT64_C(64) << 20U,
                                 &report) == XAIOS_ERR_UNSUPPORTED);
  assert(model_volume_admin_fsck("/dev/vblk5p1", 1U, &report) == XAIOS_OK);
  assert(report.check_state == XAIOS_MODEL_VOLUME_CHECK_CLEAN &&
         report.volume_bytes == (UINT64_C(96) << 20U));

  assert(storage_admin_detach() == XAIOS_OK);
  assert(block_device_unregister(&device) == XAIOS_OK);
  assert(block_device_test_reset() == XAIOS_OK);
  fclose(file);
  puts("model-volume-admin: guarded format, fsck, repair, and grow passed");
  return 0;
}
