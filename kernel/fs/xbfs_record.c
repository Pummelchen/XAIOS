/*
 * xaibootFS's record family: the builders for the small text records the
 * commit path writes under /state, and the canonical record descriptions the
 * boot self-test writes and compares those records against.
 *
 * Split out of xaiboot_fs.c, which keeps the serialised public entry points
 * that take the volume lock and call these `_locked` builders. The builders
 * own no filesystem state -- they format a fixed local buffer and hand it to
 * xbfs_write_file_locked -- and the counters they bump cross through the
 * accessors declared in xbfs_internal.h.
 *
 * The descriptions moved with the builders because they are the same family:
 * they are the `k_*` literals that used to sit beside the builders in
 * xaiboot_fs.c. The staying self-test sizes each with `sizeof`, so the header
 * declares every array with the exact size of the literal it is initialised
 * from rather than leaving an incomplete type behind.
 */

#include "xbfs_internal.h"

const char k_config_v1[sizeof(XBFS_RECORD_CONFIG_V1)] = XBFS_RECORD_CONFIG_V1;
const char k_service_running[sizeof(XBFS_RECORD_SERVICE_RUNNING)] =
    XBFS_RECORD_SERVICE_RUNNING;
const char k_service_restarting[sizeof(XBFS_RECORD_SERVICE_RESTARTING)] =
    XBFS_RECORD_SERVICE_RESTARTING;
const char k_update_state[sizeof(XBFS_RECORD_UPDATE_STATE)] =
    XBFS_RECORD_UPDATE_STATE;
const char k_boot_log[sizeof(XBFS_RECORD_BOOT_LOG)] = XBFS_RECORD_BOOT_LOG;
const char k_replayed_state[sizeof(XBFS_RECORD_REPLAYED_STATE)] =
    XBFS_RECORD_REPLAYED_STATE;

xaios_status_t xaiboot_fs_record_service_state_locked(const char *name, const char *state) {
  char path[XBFS_PATH_MAX];
  char record[256];
  uint64_t path_offset = 0;
  uint64_t record_offset = 0;
  const char *base = xbfs_basename_of(name);
  xbfs_bytes_zero(path, sizeof(path));
  xbfs_bytes_zero(record, sizeof(record));
  if (base == 0 || *base == '\0' || state == 0 ||
      xbfs_append_cstr(path, sizeof(path), &path_offset, "/state/services/") !=
          XAIOS_OK ||
      xbfs_append_cstr(path, sizeof(path), &path_offset, base) != XAIOS_OK ||
      xbfs_append_cstr(path, sizeof(path), &path_offset, ".state") != XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset, "service=") !=
          XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset, name) != XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset, "\nstate=") !=
          XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset, state) != XAIOS_OK ||
      xbfs_append_char(record, sizeof(record), &record_offset, '\n') != XAIOS_OK) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = xbfs_write_file_locked(path, record, record_offset + 1U);
  if (status == XAIOS_OK) {
    xbfs_stat_bump(XBFS_STAT_STATE_RECORD);
  }
  return status;
}

xaios_status_t xaiboot_fs_record_workspace_state_locked(uint32_t workspace_id, const char *revision) {
  char path[XBFS_PATH_MAX];
  char record[256];
  uint64_t path_offset = 0;
  uint64_t record_offset = 0;
  xbfs_bytes_zero(path, sizeof(path));
  xbfs_bytes_zero(record, sizeof(record));
  if (revision == 0 ||
      xbfs_append_cstr(path, sizeof(path), &path_offset, "/state/workspaces/workspace-") !=
          XAIOS_OK ||
      xbfs_append_u32(path, sizeof(path), &path_offset, workspace_id) != XAIOS_OK ||
      xbfs_append_cstr(path, sizeof(path), &path_offset, ".state") != XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset, "workspace=") !=
          XAIOS_OK ||
      xbfs_append_u32(record, sizeof(record), &record_offset, workspace_id) !=
          XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset,
                  "\npath=/repo/workspaces/source-index\nrevision=") !=
          XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset, revision) !=
          XAIOS_OK ||
      xbfs_append_char(record, sizeof(record), &record_offset, '\n') != XAIOS_OK) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = xbfs_write_file_locked(path, record, record_offset + 1U);
  if (status == XAIOS_OK) {
    xbfs_stat_bump(XBFS_STAT_STATE_RECORD);
  }
  return status;
}

xaios_status_t xaiboot_fs_record_update_state_locked(const char *policy) {
  char record[256];
  uint64_t record_offset = 0;
  xbfs_bytes_zero(record, sizeof(record));
  if (policy == 0 ||
      xbfs_append_cstr(record, sizeof(record), &record_offset, "policy=") !=
          XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset, policy) != XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset,
                  "\nrollback=enabled\n") != XAIOS_OK) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = xbfs_write_file_locked("/state/updates/update.state",
                                    record, record_offset + 1U);
  if (status == XAIOS_OK) {
    xbfs_stat_bump(XBFS_STAT_STATE_RECORD);
  }
  return status;
}

xaios_status_t xaiboot_fs_record_update_transaction_locked(uint32_t generation, const char *state, const char *target, const char *rollback_label) {
  char record[256];
  uint64_t record_offset = 0;
  xbfs_bytes_zero(record, sizeof(record));
  if (state == 0 || target == 0 || rollback_label == 0 ||
      xbfs_append_cstr(record, sizeof(record), &record_offset,
                  "policy=signed-update-required\n") != XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset,
                  "transaction_generation=") != XAIOS_OK ||
      xbfs_append_u32(record, sizeof(record), &record_offset, generation) !=
          XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset, "\nstate=") !=
          XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset, state) != XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset, "\ntarget=") !=
          XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset, target) != XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset, "\nrollback=") !=
          XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset, rollback_label) !=
          XAIOS_OK ||
      xbfs_append_char(record, sizeof(record), &record_offset, '\n') != XAIOS_OK) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status = xbfs_write_file_locked("/state/updates/update.state",
                                    record, record_offset + 1U);
  if (status == XAIOS_OK) {
    xbfs_stat_bump(XBFS_STAT_STATE_RECORD);
  }
  return status;
}

xaios_status_t xaiboot_fs_record_admin_status_locked(const char *service, const char *state, uint32_t starts, uint32_t restarts, uint32_t logs) {
  char record[256];
  uint64_t record_offset = 0;
  xbfs_bytes_zero(record, sizeof(record));
  if (service == 0 || state == 0 ||
      xbfs_append_cstr(record, sizeof(record), &record_offset,
                  "admin=ssh-only\nservice=") != XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset, service) !=
          XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset, "\nstate=") !=
          XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset, state) != XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset, "\nstarts=") !=
          XAIOS_OK ||
      xbfs_append_u32(record, sizeof(record), &record_offset, starts) != XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset, "\nrestarts=") !=
          XAIOS_OK ||
      xbfs_append_u32(record, sizeof(record), &record_offset, restarts) !=
          XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset, "\nlogs=") !=
          XAIOS_OK ||
      xbfs_append_u32(record, sizeof(record), &record_offset, logs) != XAIOS_OK ||
      xbfs_append_cstr(record, sizeof(record), &record_offset,
                  "\nremote_safe=allowlist\n") != XAIOS_OK) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }
  xaios_status_t status =
      xbfs_write_file_locked("/state/services/admin.state", record, record_offset + 1U);
  if (status == XAIOS_OK) {
    xbfs_stat_bump(XBFS_STAT_STATE_RECORD);
  }
  return status;
}
