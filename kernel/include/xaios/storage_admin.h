#ifndef XAIOS_STORAGE_ADMIN_H
#define XAIOS_STORAGE_ADMIN_H

#include <xaios/block_device.h>
#include <xaios/gpt.h>
#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_STORAGE_PARTITION_NAME_MAX 37U
#define XAIOS_STORAGE_GUID_TEXT_MAX 37U

typedef enum xaios_storage_partition_type {
  XAIOS_STORAGE_PARTITION_STATE = 1,
  XAIOS_STORAGE_PARTITION_MODEL = 2,
  XAIOS_STORAGE_PARTITION_RECOVERY = 3,
} xaios_storage_partition_type_t;

typedef struct xaios_storage_partition_request {
  char target[XAIOS_BLOCK_DEVICE_ID_MAX];
  char confirmation[XAIOS_STORAGE_GUID_TEXT_MAX];
  char name[XAIOS_STORAGE_PARTITION_NAME_MAX];
  uint64_t size_bytes;
  uint64_t operation_id;
  uint32_t partition_type;
  uint32_t reserved;
} xaios_storage_partition_request_t;

typedef struct xaios_storage_partition_record {
  char identifier[XAIOS_BLOCK_DEVICE_ID_MAX];
  char name[XAIOS_STORAGE_PARTITION_NAME_MAX];
  char type_guid[XAIOS_STORAGE_GUID_TEXT_MAX];
  char unique_guid[XAIOS_STORAGE_GUID_TEXT_MAX];
  uint64_t first_lba;
  uint64_t last_lba;
  uint64_t size_bytes;
  uint64_t attributes;
  uint32_t table_index;
  uint32_t known_type;
} xaios_storage_partition_record_t;

typedef struct xaios_storage_partition_report {
  char device_identifier[XAIOS_BLOCK_DEVICE_ID_MAX];
  char disk_guid[XAIOS_STORAGE_GUID_TEXT_MAX];
  uint64_t capacity_bytes;
  uint64_t logical_sector_size;
  uint64_t first_usable_lba;
  uint64_t last_usable_lba;
  uint64_t partition_count;
  uint32_t primary_valid;
  uint32_t backup_valid;
  uint32_t copies_consistent;
  uint32_t selected_copy;
  uint32_t mutation_allowed;
  uint32_t reserved;
} xaios_storage_partition_report_t;

typedef struct xaios_storage_partition_plan {
  xaios_storage_partition_report_t report;
  xaios_storage_partition_record_t partition;
  uint64_t resulting_partition_count;
  uint64_t affected_bytes;
  uint32_t changed;
  uint32_t dry_run;
} xaios_storage_partition_plan_t;

xaios_status_t storage_admin_attach(xaios_block_device_t *device,
                                    uint32_t mutation_allowed);
xaios_status_t storage_admin_detach(void);
xaios_status_t storage_admin_partition_open(
    const char *partition_identifier, uint32_t required_type,
    uint32_t require_idle, xaios_block_device_t **out_device,
    xaios_storage_partition_record_t *record);
xaios_status_t storage_admin_partition_close(xaios_block_device_t *device);
xaios_status_t storage_admin_partition_list(
    const char *device_identifier, xaios_storage_partition_record_t *records,
    uint64_t capacity, uint64_t *out_count,
    xaios_storage_partition_report_t *report);
xaios_status_t storage_admin_partition_verify(
    const char *device_identifier, xaios_storage_partition_report_t *report);
xaios_status_t storage_admin_partition_plan_create(
    const xaios_storage_partition_request_t *request,
    xaios_storage_partition_plan_t *plan);
xaios_status_t storage_admin_partition_create(
    const xaios_storage_partition_request_t *request,
    xaios_storage_partition_plan_t *result);
xaios_status_t storage_admin_partition_plan_delete(
    const xaios_storage_partition_request_t *request,
    xaios_storage_partition_plan_t *plan);
xaios_status_t storage_admin_partition_delete(
    const xaios_storage_partition_request_t *request,
    xaios_storage_partition_plan_t *result);
xaios_status_t storage_admin_partition_plan_resize(
    const xaios_storage_partition_request_t *request,
    xaios_storage_partition_plan_t *plan);
xaios_status_t storage_admin_partition_resize(
    const xaios_storage_partition_request_t *request,
    xaios_storage_partition_plan_t *result);
xaios_status_t storage_admin_partition_repair(
    const xaios_storage_partition_request_t *request,
    xaios_storage_partition_plan_t *result);

/* Create, confirm and delete a partition on the attached scratch device, so
   that the partition table writer is exercised against a real disk on every
   boot rather than only by hosted tests of its arguments. Survivable: a
   machine with no scratch device says so and carries on. */
void storage_admin_self_test(void);

#endif
