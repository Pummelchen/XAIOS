#ifndef XAIOS_MODEL_VOLUME_ADMIN_H
#define XAIOS_MODEL_VOLUME_ADMIN_H

#include <xaios/status.h>
#include <xaios/storage_admin.h>
#include <xaios/types.h>

#define XAIOS_MODEL_VOLUME_PACKAGE_ID_TEXT_MAX 65U

typedef enum xaios_model_volume_check_state {
  XAIOS_MODEL_VOLUME_CHECK_UNKNOWN = 0,
  XAIOS_MODEL_VOLUME_CHECK_CLEAN = 1,
  XAIOS_MODEL_VOLUME_CHECK_REPAIRABLE = 2,
  XAIOS_MODEL_VOLUME_CHECK_CORRUPT_UNREPAIRABLE = 3,
  XAIOS_MODEL_VOLUME_CHECK_REPAIRED = 4,
} xaios_model_volume_check_state_t;

typedef struct xaios_model_volume_admin_report {
  char target[XAIOS_BLOCK_DEVICE_ID_MAX];
  char partition_uuid[XAIOS_STORAGE_GUID_TEXT_MAX];
  char volume_uuid[XAIOS_STORAGE_GUID_TEXT_MAX];
  char bad_package_id[XAIOS_MODEL_VOLUME_PACKAGE_ID_TEXT_MAX];
  uint64_t partition_bytes;
  uint64_t volume_bytes;
  uint64_t allocated_bytes;
  uint64_t free_bytes;
  uint64_t chunk_size;
  uint64_t generation;
  uint64_t package_count;
  uint64_t active_packages;
  uint64_t staging_packages;
  uint64_t quarantined_packages;
  uint64_t checked_bytes;
  uint64_t bad_logical_offset;
  uint32_t first_superblock_valid;
  uint32_t second_superblock_valid;
  uint32_t copies_compatible;
  uint32_t check_state;
  uint32_t discard_supported;
  uint32_t dry_run;
} xaios_model_volume_admin_report_t;

xaios_status_t model_volume_admin_format_plan(
    const char *partition_identifier, uint64_t chunk_size,
    xaios_model_volume_admin_report_t *report);
xaios_status_t model_volume_admin_format(
    const char *partition_identifier, const char *partition_confirmation,
    uint64_t chunk_size, xaios_model_volume_admin_report_t *report);
xaios_status_t model_volume_admin_fsck(
    const char *partition_identifier, uint32_t verify_data,
    xaios_model_volume_admin_report_t *report);
xaios_status_t model_volume_admin_repair(
    const char *partition_identifier, const char *partition_confirmation,
    xaios_model_volume_admin_report_t *report);
xaios_status_t model_volume_admin_grow(
    const char *partition_identifier, const char *partition_confirmation,
    uint64_t new_size, xaios_model_volume_admin_report_t *report);
xaios_status_t model_volume_admin_grow_plan(
    const char *partition_identifier, uint64_t new_size,
    xaios_model_volume_admin_report_t *report);

#endif
