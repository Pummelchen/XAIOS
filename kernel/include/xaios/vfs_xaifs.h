#ifndef XAIOS_VFS_MODEL_H
#define XAIOS_VFS_MODEL_H

#include <xaios/status.h>
#include <xaios/block_device.h>
#include <xaios/types.h>

typedef struct xaios_model_mount_status {
  xaios_block_device_info_t device;
  uint64_t generation;
  uint64_t package_count;
  uint64_t active_packages;
  uint64_t staging_packages;
  uint64_t quarantined_packages;
  uint32_t mounted;
} xaios_model_mount_status_t;

typedef struct xaios_model_registration {
  uint8_t model_uuid[16];
  uint8_t package_id[32];
  uint8_t signer_public_key[32];
  uint8_t signature[64];
  uint8_t source_revision[32];
  uint64_t logical_size;
  char architecture_id[33];
  char target_id[33];
} xaios_model_registration_t;

#define XAIOS_MODEL_MAINTENANCE_IDLE UINT32_C(0)
#define XAIOS_MODEL_MAINTENANCE_RUNNING UINT32_C(1)
#define XAIOS_MODEL_MAINTENANCE_PAUSED UINT32_C(2)
#define XAIOS_MODEL_MAINTENANCE_COMPLETE UINT32_C(3)
#define XAIOS_MODEL_MAINTENANCE_CANCELLED UINT32_C(4)
#define XAIOS_MODEL_MAINTENANCE_FAILED UINT32_C(5)

typedef struct xaios_model_scrub_status {
  uint8_t volume_uuid[16];
  uint8_t bad_package_id[32];
  uint64_t generation;
  uint64_t package_index;
  uint64_t chunk_index;
  uint64_t checked_bytes;
  uint64_t total_bytes;
  uint64_t error_count;
  uint64_t bad_logical_offset;
  uint32_t state;
} xaios_model_scrub_status_t;

typedef struct xaios_model_trim_status {
  uint8_t volume_uuid[16];
  uint64_t generation;
  uint64_t chunk_index;
  uint64_t cursor_offset;
  uint64_t requested_offset;
  uint64_t requested_length;
  uint64_t eligible_bytes;
  uint64_t trimmed_bytes;
  uint64_t trimmed_ranges;
  uint64_t error_count;
  uint32_t state;
  uint32_t dry_run;
  uint32_t all_free;
} xaios_model_trim_status_t;

xaios_status_t vfs_mount_xai_fs(uint32_t virtio_slot);
xaios_status_t vfs_mount_model_device(const char *device_identifier,
                                      const char *mount_path,
                                      uint32_t read_only);
xaios_status_t vfs_unmount_xai_fs(const char *mount_path);
xaios_status_t vfs_xaifs_target_mounted(const char *device_identifier,
                                        uint32_t *mounted);
xaios_status_t vfs_xaifs_verify_staging(const char *package_id,
                                        uint64_t *generation);
xaios_status_t vfs_xaifs_activate_staging(const char *package_id,
                                           uint64_t *generation);
xaios_status_t vfs_xaifs_register_staging(
    const xaios_model_registration_t *registration, uint64_t *generation);
xaios_status_t vfs_xaifs_cleanup_staging(const char *package_id,
                                          uint64_t *generation,
                                          uint64_t *reclaimed_bytes);
xaios_status_t vfs_xaifs_scrub_start(xaios_model_scrub_status_t *status);
xaios_status_t vfs_xaifs_scrub_step(xaios_model_scrub_status_t *status);
xaios_status_t vfs_xaifs_scrub_status(xaios_model_scrub_status_t *status);
xaios_status_t vfs_xaifs_scrub_pause(xaios_model_scrub_status_t *status);
xaios_status_t vfs_xaifs_scrub_resume(xaios_model_scrub_status_t *status);
xaios_status_t vfs_xaifs_scrub_cancel(xaios_model_scrub_status_t *status);
xaios_status_t vfs_xaifs_trim_start(uint32_t dry_run, uint32_t all_free,
                                    uint64_t offset, uint64_t length,
                                    xaios_model_trim_status_t *status);
xaios_status_t vfs_xaifs_trim_step(xaios_model_trim_status_t *status);
xaios_status_t vfs_xaifs_trim_status(xaios_model_trim_status_t *status);
xaios_status_t vfs_xaifs_trim_cancel(xaios_model_trim_status_t *status);
xaios_status_t vfs_xaifs_mount_status(xaios_model_mount_status_t *status);
void vfs_xaifs_self_test(void);

#endif
