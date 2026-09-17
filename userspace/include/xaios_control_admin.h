#ifndef XAIOS_USERSPACE_CONTROL_ADMIN_H
#define XAIOS_USERSPACE_CONTROL_ADMIN_H

/* Log, admin, configuration, audit, mutation, storage and model-register
   payloads. Private sub-header of xaios_control.h, included last so the
   declarations stay in their original order. */

typedef struct xaios_control_log_request_payload_user {
  u64 since_cursor;
  u32 limit;
  u32 follow;
  char component[XAIOS_CONTROL_LOG_COMPONENT_MAX];
} xaios_control_log_request_payload_user_t;

typedef struct xaios_control_logs_payload_user {
  u64 start_cursor;
  u64 next_cursor;
  u64 latest_cursor;
  u32 record_count;
  u32 redacted_count;
  u32 timed_out;
  u32 reserved;
} xaios_control_logs_payload_user_t;

typedef struct xaios_admin_config_user {
  u32 magic;
  u16 version;
  u16 size;
  u64 generation;
  u32 max_connections;
  u32 max_channels_per_connection;
  u32 max_auth_attempts;
  u32 command_rate_per_minute;
  u32 password_auth;
  u32 reserved;
  u64 checksum;
} xaios_admin_config_user_t;

typedef struct xaios_admin_key_record_user {
  unsigned char public_key[32];
  unsigned char fingerprint[32];
  char principal[XAIOS_ADMIN_PRINCIPAL_MAX];
  u32 role;
  u32 reserved;
} xaios_admin_key_record_user_t;

typedef struct xaios_admin_auth_database_user {
  u32 magic;
  u16 version;
  u16 header_size;
  u64 generation;
  u32 key_count;
  u32 revoked_count;
  u64 checksum;
  xaios_admin_key_record_user_t keys[XAIOS_ADMIN_MAX_KEYS];
  unsigned char revoked[XAIOS_ADMIN_MAX_REVOKED_KEYS][32];
} xaios_admin_auth_database_user_t;

typedef struct xaios_admin_key_view_user {
  unsigned char fingerprint[32];
  char principal[XAIOS_ADMIN_PRINCIPAL_MAX];
  u32 role;
  u32 reserved;
} xaios_admin_key_view_user_t;

typedef struct xaios_admin_audit_record_user {
  u64 sequence;
  u64 operation_id;
  unsigned char object_hash[32];
  char principal[XAIOS_ADMIN_PRINCIPAL_MAX];
  char operation[XAIOS_ADMIN_OPERATION_MAX];
  u32 role;
  u32 result;
} xaios_admin_audit_record_user_t;

typedef struct xaios_control_path_request_payload_user {
  char path[XAIOS_CONTROL_PATH_MAX];
} xaios_control_path_request_payload_user_t;

typedef struct xaios_control_mutation_request_payload_user {
  u64 operation_id;
  u32 assigned_role;
  u32 reserved;
  char actor[XAIOS_ADMIN_PRINCIPAL_MAX];
  char argument[XAIOS_CONTROL_PATH_MAX];
  char target_principal[XAIOS_ADMIN_PRINCIPAL_MAX];
} xaios_control_mutation_request_payload_user_t;

typedef struct xaios_control_audit_request_payload_user {
  u64 since_sequence;
  u32 limit;
  u32 reserved;
} xaios_control_audit_request_payload_user_t;

typedef struct xaios_control_config_payload_user {
  xaios_admin_config_user_t config;
  u32 change_mask;
  u32 validated;
} xaios_control_config_payload_user_t;

typedef struct xaios_control_auth_keys_payload_user {
  u64 generation;
  u32 key_count;
  u32 revoked_count;
} xaios_control_auth_keys_payload_user_t;

typedef struct xaios_control_mutation_payload_user {
  u64 operation_id;
  u64 generation;
  u32 changed;
  u32 reserved;
} xaios_control_mutation_payload_user_t;

typedef struct xaios_control_audit_payload_user {
  u64 next_sequence;
  u64 latest_sequence;
  u32 record_count;
  u32 reserved;
} xaios_control_audit_payload_user_t;

typedef struct xaios_control_storage_device_record_user {
  char identifier[48];
  char backend[24];
  u64 capacity_bytes;
  u64 capacity_logical_sectors;
  u64 logical_sector_size;
  u64 physical_block_size;
  u64 max_transfer_bytes;
  u64 discard_granularity;
  u64 max_discard_bytes;
  u64 read_bytes;
  u64 write_bytes;
  u64 discarded_bytes;
  u64 io_errors;
  u32 read_only;
  u32 flush_supported;
  u32 discard_supported;
  u32 write_zeroes_supported;
} xaios_control_storage_device_record_user_t;

typedef struct xaios_control_storage_devices_payload_user {
  u32 record_count;
  u32 total_count;
  u32 truncated;
  u32 reserved;
} xaios_control_storage_devices_payload_user_t;

typedef struct xaios_control_storage_filesystem_record_user {
  char mount_path[XAIOS_CONTROL_STORAGE_MOUNT_MAX];
  char filesystem[XAIOS_CONTROL_STORAGE_FILESYSTEM_MAX];
  char device_identifier[48];
  u64 total_bytes;
  u64 allocated_bytes;
  u64 free_bytes;
  u64 reserved_bytes;
  u64 file_count;
  u64 directory_count;
  u64 generation;
  u64 block_size;
  u64 package_count;
  u64 active_packages;
  u64 staging_packages;
  u64 quarantined_packages;
  u32 format_version;
  u32 mounted;
  u32 read_only;
  u32 staging_writable;
} xaios_control_storage_filesystem_record_user_t;

typedef struct xaios_control_storage_filesystems_payload_user {
  u32 record_count;
  u32 total_count;
  u32 truncated;
  u32 reserved;
} xaios_control_storage_filesystems_payload_user_t;

typedef struct xaios_storage_partition_request_user {
  char target[48];
  char confirmation[37];
  char name[37];
  u64 size_bytes;
  u64 operation_id;
  u32 partition_type;
  u32 reserved;
} xaios_storage_partition_request_user_t;

typedef struct xaios_control_storage_partition_request_payload_user {
  xaios_storage_partition_request_user_t request;
  char actor[XAIOS_ADMIN_PRINCIPAL_MAX];
} xaios_control_storage_partition_request_payload_user_t;

typedef struct xaios_control_storage_install_request_user {
  char target[48];
  char source[48];
  char confirmation[37];
  u64 operation_id;
} xaios_control_storage_install_request_user_t;

typedef struct xaios_control_storage_install_request_payload_user {
  xaios_control_storage_install_request_user_t request;
  char actor[XAIOS_ADMIN_PRINCIPAL_MAX];
} xaios_control_storage_install_request_payload_user_t;

typedef struct xaios_control_storage_install_result_user {
  char esp_identifier[48];
  char state_identifier[48];
  u64 files_copied;
  u64 bytes_copied;
  u64 esp_bytes;
  u64 state_bytes;
} xaios_control_storage_install_result_user_t;

typedef struct xaios_storage_partition_record_user {
  char identifier[48];
  char name[37];
  char type_guid[37];
  char unique_guid[37];
  u64 first_lba;
  u64 last_lba;
  u64 size_bytes;
  u64 attributes;
  u32 table_index;
  u32 known_type;
} xaios_storage_partition_record_user_t;

typedef struct xaios_storage_partition_report_user {
  char device_identifier[48];
  char disk_guid[37];
  u64 capacity_bytes;
  u64 logical_sector_size;
  u64 first_usable_lba;
  u64 last_usable_lba;
  u64 partition_count;
  u32 primary_valid;
  u32 backup_valid;
  u32 copies_consistent;
  u32 selected_copy;
  u32 mutation_allowed;
  u32 reserved;
} xaios_storage_partition_report_user_t;

typedef struct xaios_control_storage_partitions_payload_user {
  xaios_storage_partition_report_user_t report;
  u32 record_count;
  u32 total_count;
  u32 truncated;
  u32 reserved;
} xaios_control_storage_partitions_payload_user_t;

typedef struct xaios_storage_partition_plan_user {
  xaios_storage_partition_report_user_t report;
  xaios_storage_partition_record_user_t partition;
  u64 resulting_partition_count;
  u64 affected_bytes;
  u32 changed;
  u32 dry_run;
} xaios_storage_partition_plan_user_t;

typedef struct xaios_control_storage_volume_request_payload_user {
  char target[48];
  char confirmation[37];
  char mount_path[XAIOS_CONTROL_STORAGE_MOUNT_MAX];
  char actor[XAIOS_ADMIN_PRINCIPAL_MAX];
  u64 size_bytes;
  u64 chunk_size;
  u64 operation_id;
  u32 verify_data;
  u32 read_only;
  u32 reserved;
} xaios_control_storage_volume_request_payload_user_t;

typedef struct xaios_control_storage_replica_repair_request_payload_user {
  char target[48];
  char replica[48];
  char confirmation[37];
  char package_id[65];
  char actor[XAIOS_ADMIN_PRINCIPAL_MAX];
  u64 operation_id;
} xaios_control_storage_replica_repair_request_payload_user_t;

typedef struct xaios_control_model_register_request_payload_user {
  u64 operation_id;
  u64 logical_size;
  unsigned char model_uuid[16];
  unsigned char package_id[32];
  unsigned char signer_public_key[32];
  unsigned char signature[64];
  unsigned char source_revision[32];
  char architecture_id[33];
  char target_id[33];
  char actor[XAIOS_ADMIN_PRINCIPAL_MAX];
} xaios_control_model_register_request_payload_user_t;

typedef struct xaios_control_storage_scrub_report_user {
  unsigned char volume_uuid[16];
  unsigned char bad_package_id[32];
  u64 generation;
  u64 package_index;
  u64 chunk_index;
  u64 checked_bytes;
  u64 total_bytes;
  u64 error_count;
  u64 bad_logical_offset;
  u32 state;
} xaios_control_storage_scrub_report_user_t;

typedef struct xaios_control_storage_trim_request_payload_user {
  char target[XAIOS_CONTROL_STORAGE_MOUNT_MAX];
  char actor[XAIOS_ADMIN_PRINCIPAL_MAX];
  u64 offset;
  u64 length;
  u64 operation_id;
  u32 dry_run;
  u32 all_free;
} xaios_control_storage_trim_request_payload_user_t;

typedef struct xaios_control_storage_trim_report_user {
  unsigned char volume_uuid[16];
  u64 generation;
  u64 chunk_index;
  u64 cursor_offset;
  u64 requested_offset;
  u64 requested_length;
  u64 eligible_bytes;
  u64 trimmed_bytes;
  u64 trimmed_ranges;
  u64 error_count;
  u32 state;
  u32 dry_run;
  u32 all_free;
} xaios_control_storage_trim_report_user_t;

typedef struct xaios_control_model_cleanup_report_user {
  u64 operation_id;
  u64 generation;
  u64 reclaimed_bytes;
  u32 changed;
  u32 reserved;
} xaios_control_model_cleanup_report_user_t;

typedef struct xaios_xai_fs_admin_report_user {
  char target[48];
  char partition_uuid[37];
  char volume_uuid[37];
  char bad_package_id[65];
  u64 partition_bytes;
  u64 volume_bytes;
  u64 allocated_bytes;
  u64 free_bytes;
  u64 chunk_size;
  u64 generation;
  u64 package_count;
  u64 active_packages;
  u64 staging_packages;
  u64 quarantined_packages;
  u64 checked_bytes;
  u64 bad_logical_offset;
  u32 first_superblock_valid;
  u32 second_superblock_valid;
  u32 copies_compatible;
  u32 check_state;
  u32 discard_supported;
  u32 dry_run;
} xaios_xai_fs_admin_report_user_t;

#endif
