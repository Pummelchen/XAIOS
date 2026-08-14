#ifndef XAIOS_MUTABLE_FS_H
#define XAIOS_MUTABLE_FS_H

#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_MFS_PATH_MAX 256U
#define XAIOS_MFS_MAX_FILE_BYTES UINT64_C(3072)
#define XAIOS_MFS_MAX_FILE_BYTES_V3 UINT64_C(8192)
#define XAIOS_MFS_MAX_FILE_BYTES_V4 UINT64_C(131072)
#define XAIOS_MFS_MAX_FILE_BYTES_V5 UINT64_C(262144)
#define XAIOS_MFS_MAX_LIST_BYTES UINT64_C(16384)
#define XAIOS_MFS_OPEN_READ UINT32_C(1)
#define XAIOS_MFS_OPEN_WRITE UINT32_C(2)
#define XAIOS_MFS_OPEN_CREATE UINT32_C(4)
#define XAIOS_MFS_OPEN_TRUNCATE UINT32_C(8)

typedef struct xaios_mfs_stat {
  uint32_t type;
  uint32_t block_count;
  uint64_t size;
  uint64_t generation;
  uint64_t content_hash;
} xaios_mfs_stat_t;

typedef struct xaios_mfs_fsck_result {
  uint32_t valid;
  uint32_t version;
  uint64_t files;
  uint64_t directories;
  uint64_t blocks_used;
  uint64_t errors;
} xaios_mfs_fsck_result_t;

void mutable_fs_self_test(void);
xaios_status_t mutable_fs_mount_device(const char *identifier);
xaios_status_t mutable_fs_mount_persistent(uint32_t slot);
xaios_mfs_fsck_result_t mutable_fs_fsck(void);
uint64_t mutable_fs_persistent_mount_count(void);

uint64_t mutable_fs_mount_count(void);
uint64_t mutable_fs_format_count(void);
uint64_t mutable_fs_boot_load_count(void);
uint64_t mutable_fs_file_count(void);
uint64_t mutable_fs_directory_count(void);
uint64_t mutable_fs_write_count(void);
uint64_t mutable_fs_read_count(void);
uint64_t mutable_fs_delete_count(void);
uint64_t mutable_fs_commit_count(void);
uint64_t mutable_fs_rollback_count(void);
uint64_t mutable_fs_reject_count(void);
uint64_t mutable_fs_checksum_error_count(void);
uint64_t mutable_fs_allocation_count(void);
uint64_t mutable_fs_free_count(void);
uint64_t mutable_fs_replay_count(void);
uint64_t mutable_fs_journal_write_count(void);
uint64_t mutable_fs_multi_sector_file_count(void);
uint64_t mutable_fs_state_record_count(void);
uint64_t mutable_fs_rename_count(void);
uint64_t mutable_fs_list_count(void);
uint64_t mutable_fs_stat_count(void);
uint64_t mutable_fs_open_count(void);
uint64_t mutable_fs_close_count(void);

xaios_status_t mutable_fs_mkdir(const char *path);
xaios_status_t mutable_fs_write(const char *path, const void *data,
                               uint64_t size);
xaios_status_t mutable_fs_read(const char *path, void *buffer,
                              uint64_t buffer_size, uint64_t *out_size);
xaios_status_t mutable_fs_delete(const char *path);
xaios_status_t mutable_fs_delete_tree(const char *path);
xaios_status_t mutable_fs_rename(const char *old_path, const char *new_path);
xaios_status_t mutable_fs_stat(const char *path, xaios_mfs_stat_t *stat);
xaios_status_t mutable_fs_list(const char *path, char *buffer,
                              uint64_t buffer_size, uint64_t *out_size);
int64_t mutable_fs_open(const char *path, uint32_t flags);
int64_t mutable_fs_read_fd(uint32_t fd, void *buffer, uint64_t size);
int64_t mutable_fs_write_fd(uint32_t fd, const void *buffer, uint64_t size);
xaios_status_t mutable_fs_seek(uint32_t fd, uint64_t offset);
xaios_status_t mutable_fs_close(uint32_t fd);

xaios_status_t mutable_fs_record_service_state(const char *name,
                                              const char *state);
xaios_status_t mutable_fs_record_workspace_state(uint32_t workspace_id,
                                                const char *revision);
xaios_status_t mutable_fs_record_update_state(const char *policy);
xaios_status_t mutable_fs_record_update_transaction(uint32_t generation,
                                                   const char *state,
                                                   const char *target,
                                                   const char *rollback_label);
xaios_status_t mutable_fs_record_admin_status(const char *service,
                                             const char *state,
                                             uint32_t starts,
                                             uint32_t restarts,
                                             uint32_t logs);
xaios_status_t mutable_fs_commit(const char *label);
xaios_status_t mutable_fs_rollback(void);

#endif
