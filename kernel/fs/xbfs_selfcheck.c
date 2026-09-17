/*
 * xaibootFS's observability and self-check: the counters telemetry reads,
 * the consistency check, and the boot self-test itself.
 *
 * Split out of xaiboot_fs.c. Every counter is a value out of xbfs_state.c.
 * The fsck pass walks the node table through xbfs_node_row, the same
 * call-scoped accessor the namespace code uses. xaiboot_fs_fsck_locked
 * crosses back so the serialised xaiboot_fs_fsck entry point can stay with
 * the other lock wrappers in xaiboot_fs.c. The self-test stays outside the
 * volume lock deliberately: it drives those public entry points and runs
 * single threaded during boot.
 */

#include <xaios/assert.h>
#include <xaios/klog.h>

#include "xbfs_fd_internal.h"
#include "xbfs_file_io_internal.h"
#include "xbfs_format_internal.h"
#include "xbfs_internal.h"
#include "xbfs_metadata_internal.h"
#include "xbfs_volume_internal.h"

uint64_t xaiboot_fs_mount_count(void) { return xbfs_stat_get(XBFS_STAT_MOUNT); }
uint64_t xaiboot_fs_metadata_recoveries(void) {
  return xbfs_metadata_mirror_recoveries();
}

uint64_t xaiboot_fs_format_count(void) { return xbfs_stat_get(XBFS_STAT_FORMAT); }
uint64_t xaiboot_fs_boot_load_count(void) { return xbfs_stat_get(XBFS_STAT_BOOT_LOAD); }
uint64_t xaiboot_fs_file_count(void) { return xbfs_node_count_by_type(XBFS_NODE_FILE); }
uint64_t xaiboot_fs_directory_count(void) { return xbfs_node_count_by_type(XBFS_NODE_DIR); }
uint64_t xaiboot_fs_write_count(void) { return xbfs_stat_get(XBFS_STAT_WRITE); }
uint64_t xaiboot_fs_append_count(void) { return xbfs_stat_get(XBFS_STAT_APPEND); }
uint64_t xaiboot_fs_append_fallback_count(void) {
  return xbfs_stat_get(XBFS_STAT_APPEND_FALLBACK);
}
uint64_t xaiboot_fs_read_count(void) { return xbfs_stat_get(XBFS_STAT_READ); }
uint64_t xaiboot_fs_delete_count(void) { return xbfs_stat_get(XBFS_STAT_DELETE); }
uint64_t xaiboot_fs_commit_count(void) { return xbfs_stat_get(XBFS_STAT_COMMIT); }
uint64_t xaiboot_fs_rollback_count(void) { return xbfs_stat_get(XBFS_STAT_ROLLBACK); }
uint64_t xaiboot_fs_reject_count(void) { return xbfs_stat_get(XBFS_STAT_REJECT); }
uint64_t xaiboot_fs_checksum_error_count(void) { return xbfs_stat_get(XBFS_STAT_CHECKSUM_ERROR); }
uint64_t xaiboot_fs_allocation_count(void) { return xbfs_stat_get(XBFS_STAT_ALLOCATION); }
uint64_t xaiboot_fs_free_count(void) { return xbfs_stat_get(XBFS_STAT_FREE); }
uint64_t xaiboot_fs_replay_count(void) { return xbfs_stat_get(XBFS_STAT_REPLAY); }
uint64_t xaiboot_fs_journal_write_count(void) { return xbfs_stat_get(XBFS_STAT_JOURNAL_WRITE); }
uint64_t xaiboot_fs_multi_sector_file_count(void) { return xbfs_stat_get(XBFS_STAT_MULTI_SECTOR_FILE); }
uint64_t xaiboot_fs_state_record_count(void) { return xbfs_stat_get(XBFS_STAT_STATE_RECORD); }
uint64_t xaiboot_fs_rename_count(void) { return xbfs_stat_get(XBFS_STAT_RENAME); }
uint64_t xaiboot_fs_list_count(void) { return xbfs_stat_get(XBFS_STAT_LIST); }
uint64_t xaiboot_fs_stat_count(void) { return xbfs_stat_get(XBFS_STAT_STAT); }
uint64_t xaiboot_fs_open_count(void) { return xbfs_stat_get(XBFS_STAT_OPEN); }
uint64_t xaiboot_fs_close_count(void) { return xbfs_stat_get(XBFS_STAT_CLOSE); }


/* Mark every block a file claims, and complain if two files claim one.
   
   The reference array is one byte per block, which at v6 sizes would be two
   megabytes on the stack; it is a static instead. A check that cannot run
   because it needs more stack than exists is a check that does not run. */
static void fsck_count_file_extents(const xaios_xbfs_extent_t *extents,
                                    uint32_t extent_count,
                                    uint8_t *references,
                                    xaios_xbfs_fsck_result_t *result) {
  if (extent_count > XBFS_V6_MAX_EXTENTS ||
      xbfs_extent_blocks(extents, extent_count) > xbfs_geometry_file_max_blocks()) {
    ++result->errors;
    return;
  }
  for (uint32_t e = 0U; e < extent_count; ++e) {
    for (uint32_t offset = 0U; offset < extents[e].length; ++offset) {
      uint64_t block = (uint64_t)extents[e].start + offset;
      if (block >= xbfs_geometry_data_sectors() || references[block] != 0U) {
        ++result->errors;
      } else {
        references[block] = 1U;
      }
    }
  }
}

xaios_xbfs_fsck_result_t xaiboot_fs_fsck_locked(void) {
  xbfs_geometry_t geometry;
  xbfs_geometry_get(&geometry);
  xaios_xbfs_fsck_result_t result;
  /* A byte per block, static rather than on the stack: at v6 sizes this is
     two megabytes, and a check that needs more stack than exists is a check
     that does not run. */
  static uint8_t references[XBFS_V6_DATA_SECTORS];
  xbfs_bytes_zero(&result, sizeof(result));
  xbfs_bytes_zero(references, sizeof(references));
  result.version = geometry.version;
  result.files = xbfs_node_count_by_type(XBFS_NODE_FILE);
  result.directories = xbfs_node_count_by_type(XBFS_NODE_DIR);
  result.blocks_used = xbfs_block_count_used();
  result.errors = 0;

  for (uint32_t n = 0; n < geometry.max_nodes; ++n) {
    xaios_xbfs_node_t *node = xbfs_node_row(n);
    if (node->active != 0 && node->type == XBFS_NODE_FILE) {
      fsck_count_file_extents(node->extents, node->extent_count, references,
                              &result);
    }
    if (node->snapshot_active != 0 &&
        node->snapshot_type == XBFS_NODE_FILE) {
      fsck_count_file_extents(node->snapshot_extents,
                              node->snapshot_extent_count, references,
                              &result);
    }
  }

  for (uint32_t i = 0; i < geometry.data_sectors; ++i) {
    int in_use = xbfs_block_used(i) != 0U;
    int referenced = references[i] != 0U;
    if (in_use != referenced) {
      ++result.errors;
    }
  }
  result.valid = (result.errors == 0) ? 1U : 0U;
  klog("xaibootfs: fsck v%u files=%lu dirs=%lu blocks=%lu errors=%lu valid=%u\n",
       result.version, result.files, result.directories,
       result.blocks_used, result.errors, result.valid);
  return result;
}


void xaiboot_fs_self_test(void) {
  kassert(sizeof(xaios_xbfs_journal_t) == XBFS_SECTOR_SIZE);
  kassert(sizeof(xaios_xbfs_disk_t) <= XBFS_METADATA_SECTORS * XBFS_SECTOR_SIZE);
  xbfs_mount_set_mounted(0);
  xbfs_mount_set_flags(0);
  xbfs_mount_set_device(0);
  xbfs_geometry_select(XBFS_VERSION);
  xbfs_stat_reset_all();
  xbfs_reset_open_files();

  kassert(xbfs_mount_volume(XBFS_MOUNT_READ_WRITE) == XAIOS_OK);
  kassert(xbfs_volume_format() == XAIOS_OK);
  kassert(xbfs_ensure_base_directories() == XAIOS_OK);
  xaios_xbfs_node_t *base_node = xbfs_find_node("/tmp", 1);
  kassert(base_node != 0 && base_node->type == XBFS_NODE_DIR);
  base_node = xbfs_find_node("/home/admin", 1);
  kassert(base_node != 0 && base_node->type == XBFS_NODE_DIR);

  kassert(xaiboot_fs_record_service_state("/svc/source-index", "running") ==
          XAIOS_OK);
  kassert(xaiboot_fs_record_workspace_state(0, "boot") == XAIOS_OK);
  kassert(xaiboot_fs_record_update_state("signed-update-required") == XAIOS_OK);
  kassert(xaiboot_fs_record_admin_status("/svc/source-index", "running", 1, 0,
                                         0) == XAIOS_OK);
  kassert(xbfs_write_file_locked("/config/xaios.conf", k_config_v1,
                     sizeof(k_config_v1)) == XAIOS_OK);

  uint8_t large[XBFS_SECTOR_SIZE * 3U];
  for (uint64_t i = 0; i < sizeof(large); ++i) {
    large[i] = (uint8_t)('A' + (i % 23U));
  }
  kassert(xbfs_write_file_locked("/state/services/large.state", large, sizeof(large)) ==
          XAIOS_OK);

  uint8_t buffer[XBFS_MAX_FILE_BYTES];
  uint64_t size = 0;
  kassert(xbfs_read_file("/state/services/large.state", buffer, sizeof(buffer),
                    &size) == XAIOS_OK);
  kassert(size == sizeof(large));
  kassert(xbfs_bytes_eq(buffer, large, sizeof(large)) != 0);

  char listing[XAIOS_XBFS_MAX_LIST_BYTES];
  xaios_xbfs_stat_t stat;
  kassert(xbfs_list_dir("/state", listing, sizeof(listing), &size) == XAIOS_OK);
  kassert(size > 0);
  kassert(xbfs_stat_node("/state/services/large.state", &stat) == XAIOS_OK);
  kassert(stat.type == XBFS_NODE_FILE);
  kassert(stat.size == sizeof(large));
  kassert(xbfs_rename_node("/config/xaios.conf", "/config/xaios-renamed.conf") ==
          XAIOS_OK);
  kassert(xbfs_stat_node("/config/xaios-renamed.conf", &stat) == XAIOS_OK);
  kassert(xbfs_read_file("/config/xaios.conf", buffer, sizeof(buffer), &size) ==
          XAIOS_ERR_NOT_FOUND);

  static const char k_fd_payload[] = "fd-api=ok\n";
  int64_t fd = xaiboot_fs_open("/logs/fd-api.log",
                               XAIOS_XBFS_OPEN_READ | XAIOS_XBFS_OPEN_WRITE |
                                   XAIOS_XBFS_OPEN_CREATE);
  kassert(fd > 0);
  kassert(xaiboot_fs_write_fd((uint32_t)fd, k_fd_payload,
                              sizeof(k_fd_payload)) ==
          (int64_t)sizeof(k_fd_payload));
  kassert(xaiboot_fs_seek((uint32_t)fd, 3U) == XAIOS_OK);
  kassert(xbfs_fd_cursor((uint32_t)fd) == 3U);
  kassert(xaiboot_fs_seek((uint32_t)fd, 0U) == XAIOS_OK);
  kassert(xaiboot_fs_close((uint32_t)fd) == XAIOS_OK);
  fd = xaiboot_fs_open("/logs/fd-api.log", XAIOS_XBFS_OPEN_READ);
  kassert(fd > 0);
  kassert(xaiboot_fs_read_fd((uint32_t)fd, buffer, sizeof(k_fd_payload)) ==
          (int64_t)sizeof(k_fd_payload));
  kassert(xbfs_bytes_eq(buffer, k_fd_payload, sizeof(k_fd_payload)) != 0);
  kassert(xaiboot_fs_close((uint32_t)fd) == XAIOS_OK);
  fd = xaiboot_fs_open("/logs/fd-api.log",
                       XAIOS_XBFS_OPEN_READ | XAIOS_XBFS_OPEN_WRITE |
                           XAIOS_XBFS_OPEN_TRUNCATE);
  kassert(fd > 0);
  kassert(xbfs_stat_node("/logs/fd-api.log", &stat) == XAIOS_OK);
  kassert(stat.size == 0);
  kassert(xaiboot_fs_close((uint32_t)fd) == XAIOS_OK);
  kassert(xaiboot_fs_open("/missing/nope", XAIOS_XBFS_OPEN_READ) ==
          (int64_t)XAIOS_ERR_NOT_FOUND);
  kassert(xbfs_snapshot_commit("mfs-snapshot-v2") == XAIOS_OK);

  kassert(xbfs_write_file_locked("/state/services/source-index.state",
                     k_service_restarting,
                     sizeof(k_service_restarting)) == XAIOS_OK);
  kassert(xbfs_delete_node("/state/updates/update.state") == XAIOS_OK);
  kassert(xbfs_write_file_locked("/logs/boot.log", k_boot_log, sizeof(k_boot_log)) ==
          XAIOS_OK);
  kassert(xbfs_write_pending_journal_file("/state/services/replayed.state",
                                     k_replayed_state,
                                     sizeof(k_replayed_state)) == XAIOS_OK);
  xbfs_mount_set_mounted(0);
  kassert(xbfs_mount_volume(XBFS_MOUNT_READ_WRITE) == XAIOS_OK);
  kassert(xbfs_read_file("/state/services/replayed.state", buffer, sizeof(buffer),
                    &size) == XAIOS_OK);
  kassert(size == sizeof(k_replayed_state));
  kassert(xbfs_bytes_eq(buffer, k_replayed_state, sizeof(k_replayed_state)) != 0);
  xaios_xbfs_fsck_result_t snapshot_fsck = xaiboot_fs_fsck();
  kassert(snapshot_fsck.valid != 0);

  kassert(xbfs_snapshot_rollback() == XAIOS_OK);
  kassert(xbfs_read_file("/state/services/source-index.state", buffer,
                    sizeof(buffer), &size) == XAIOS_OK);
  kassert(size == sizeof(k_service_running));
  kassert(xbfs_bytes_eq(buffer, k_service_running, sizeof(k_service_running)) != 0);
  kassert(xbfs_read_file("/state/updates/update.state", buffer, sizeof(buffer),
                    &size) == XAIOS_OK);
  kassert(size == sizeof(k_update_state));
  kassert(xbfs_bytes_eq(buffer, k_update_state, sizeof(k_update_state)) != 0);
  kassert(xbfs_read_file("/logs/boot.log", buffer, sizeof(buffer), &size) ==
          XAIOS_ERR_NOT_FOUND);
  kassert(xbfs_read_file("/state/services/replayed.state", buffer, sizeof(buffer),
                    &size) == XAIOS_ERR_NOT_FOUND);

  kassert(xbfs_write_file_locked("/bad/missing-parent", k_config_v1,
                     sizeof(k_config_v1)) == XAIOS_ERR_INVALID);
  kassert(xbfs_create_dir("/state/services/bad") == XAIOS_OK);
  kassert(xbfs_delete_node("/state/services") == XAIOS_ERR_BUSY);
  uint8_t too_large[XBFS_MAX_FILE_BYTES + 1U];
  kassert(xbfs_write_file_locked("/state/services/too-large", too_large,
                     sizeof(too_large)) == XAIOS_ERR_INVALID);
  kassert(xbfs_read_file("/state/missing.state", buffer, sizeof(buffer), &size) ==
          XAIOS_ERR_NOT_FOUND);

  kassert(xaiboot_fs_mount_count() == 2);
  kassert(xaiboot_fs_format_count() >= 1);
  kassert(xaiboot_fs_format_count() <= 2);
  kassert(xaiboot_fs_file_count() >= 6);
  kassert(xaiboot_fs_directory_count() >= 11);
  kassert(xaiboot_fs_write_count() >= 12);
  kassert(xaiboot_fs_read_count() >= 5);
  kassert(xaiboot_fs_delete_count() == 1);
  kassert(xaiboot_fs_commit_count() == 1);
  kassert(xaiboot_fs_rollback_count() == 1);
  kassert(xaiboot_fs_replay_count() == 1);
  kassert(xaiboot_fs_journal_write_count() == 1);
  kassert(xaiboot_fs_multi_sector_file_count() >= 1);
  kassert(xaiboot_fs_state_record_count() == 4);
  kassert(xaiboot_fs_reject_count() >= 7);
  kassert(xaiboot_fs_checksum_error_count() == 0);
  kassert(xaiboot_fs_rename_count() == 1);
  kassert(xaiboot_fs_list_count() == 1);
  kassert(xaiboot_fs_stat_count() == 3);
  kassert(xaiboot_fs_open_count() == 3);
  kassert(xaiboot_fs_close_count() == 3);
  /* A write that would run off the end of the staging buffer must be refused,
     not staged. v6 raised the format's per-file limit to a gibibyte while the
     buffer this path copies through stayed at the v5 figure of 256 KiB, and
     for a while the guard checked only the former: on a v6 volume, a seek past
     256 KiB and a write corrupted whatever the linker had placed after a
     static array.

     The invariant is the check that holds whatever volume is mounted -- this
     self-test runs against a v2 volume, where the format's own limit is eight
     kibibytes and far below the buffer, so a probe at 256 KiB would prove
     nothing here. The probe that follows works at whatever the binding limit
     is. */
  kassert(xbfs_write_limit() <= xbfs_file_staging_bytes());
  /* The same question for the rename staging table, which walks every node
     the active format allows. */
  kassert((uint64_t)xbfs_geometry_max_nodes() <=
          xbfs_dir_path_transaction_rows());
  /* And for the two remaining buffers a format's own numbers index into.
     Both are sized for v6 today and neither has ever been wrong; they are
     asserted because the two that were wrong were wrong the same way -- a
     static sized for the format that existed when it was written, indexed
     by a later format's larger maximum -- and nothing else would catch the
     third instance of it. */
  kassert((uint64_t)xbfs_geometry_metadata_sectors() * XBFS_SECTOR_SIZE <=
          (uint64_t)xbfs_metadata_buffer_bytes());
  kassert((uint64_t)xbfs_geometry_path_max() <= (uint64_t)XBFS_PATH_MAX);
  {
    int64_t guard_fd = xaiboot_fs_open("/state/overflow-guard",
                                       XAIOS_XBFS_OPEN_WRITE |
                                           XAIOS_XBFS_OPEN_CREATE);
    kassert(guard_fd >= 0);
    uint8_t probe[64];
    for (uint32_t index = 0U; index < sizeof(probe); ++index) {
      probe[index] = (uint8_t)index;
    }
    uint64_t limit = xbfs_write_limit();
    /* One byte inside the limit, so the write would straddle it. */
    kassert(xaiboot_fs_seek((uint32_t)guard_fd, limit - 1U) == XAIOS_OK);
    kassert(xaiboot_fs_write_fd((uint32_t)guard_fd, probe, sizeof(probe)) ==
            (int64_t)XAIOS_ERR_INVALID);
    /* And exactly at it, which is the off-by-one on the other side. */
    kassert(xaiboot_fs_seek((uint32_t)guard_fd, limit) == XAIOS_OK);
    kassert(xaiboot_fs_write_fd((uint32_t)guard_fd, probe, 1U) ==
            (int64_t)XAIOS_ERR_INVALID);
    /* And the last byte that does fit still goes in, so the guard is a bound
       and not a blanket refusal. */
    kassert(xaiboot_fs_seek((uint32_t)guard_fd, limit - 1U) == XAIOS_OK);
    kassert(xaiboot_fs_write_fd((uint32_t)guard_fd, probe, 1U) == 1);
    kassert(xaiboot_fs_close((uint32_t)guard_fd) == XAIOS_OK);
    kassert(xaiboot_fs_delete("/state/overflow-guard") == XAIOS_OK);
  }
  {
    /* B-45. Three separate things have to hold, and the first is the one a
       green-and-useless version of this change would fail: the fast path has
       to actually run. Everything after it is content, and content would be
       right either way -- the whole-file path produces the same bytes, slowly.

       The records are deliberately not a divisor of the sector size, so the
       run crosses block boundaries at every offset within a block rather than
       always at the same one. An append that understood only the tail block,
       or that got the boundary off by one, has nowhere to hide in that. */
    static const char record[] = "[INFO] connection accepted\n";
    const uint64_t record_length = sizeof(record) - 1U;
    const uint32_t record_count = 200U;
    uint64_t appends_before = xaiboot_fs_append_count();
    uint64_t reads_before = xaiboot_fs_read_count();
    int64_t log_fd = xaiboot_fs_open("/state/append-probe",
                                     XAIOS_XBFS_OPEN_WRITE |
                                         XAIOS_XBFS_OPEN_CREATE |
                                         XAIOS_XBFS_OPEN_TRUNCATE);
    kassert(log_fd >= 0);
    for (uint32_t i = 0U; i < record_count; ++i) {
      kassert(xaiboot_fs_write_fd((uint32_t)log_fd, record, record_length) ==
              (int64_t)record_length);
    }
    kassert(xaiboot_fs_close((uint32_t)log_fd) == XAIOS_OK);
#if XBFS_APPEND_IN_PLACE
    kassert(xaiboot_fs_append_count() - appends_before ==
            (uint64_t)record_count);
    /* And not one file read among them, which is the defect itself. */
    kassert(xaiboot_fs_read_count() == reads_before);
#else
    (void)reads_before;
#endif

    /* The bytes, and by way of xbfs_read_file the content hash that was extended
       rather than recomputed: a wrong hash is XAIOS_ERR_INVALID here. */
    uint64_t probe_size = 0;
    kassert(xbfs_read_file("/state/append-probe", buffer, sizeof(buffer),
                      &probe_size) == XAIOS_OK);
    kassert(probe_size == record_length * (uint64_t)record_count);
    for (uint32_t i = 0U; i < record_count; ++i) {
      kassert(xbfs_bytes_eq(buffer + (uint64_t)i * record_length, record,
                       record_length) != 0);
    }

    /* A write that is not at the end is not an append, must not be treated as
       one, and must still be correct. */
    uint64_t fallbacks_before = xaiboot_fs_append_fallback_count();
    appends_before = xaiboot_fs_append_count();
    int64_t patch_fd = xaiboot_fs_open("/state/append-probe",
                                       XAIOS_XBFS_OPEN_WRITE);
    kassert(patch_fd >= 0);
    kassert(xaiboot_fs_seek((uint32_t)patch_fd, record_length) == XAIOS_OK);
    kassert(xaiboot_fs_write_fd((uint32_t)patch_fd, "XX", 2U) == 2);
    kassert(xaiboot_fs_close((uint32_t)patch_fd) == XAIOS_OK);
    kassert(xaiboot_fs_append_count() == appends_before);
#if XBFS_APPEND_IN_PLACE
    kassert(xaiboot_fs_append_fallback_count() == fallbacks_before + 1U);
#else
    (void)fallbacks_before;
#endif
    kassert(xbfs_read_file("/state/append-probe", buffer, sizeof(buffer),
                      &probe_size) == XAIOS_OK);
    kassert(probe_size == record_length * (uint64_t)record_count);
    kassert(buffer[record_length] == 'X' && buffer[record_length + 1U] == 'X');
    kassert(xbfs_bytes_eq(buffer, record, record_length) != 0);
    kassert(xbfs_bytes_eq(buffer + record_length * 2U, record, record_length) != 0);

    /* Failing when it should, one: an append that would take the file past
       what this volume's format allows is refused, and refused without
       changing the file. The bound is `xbfs_write_limit`, which on a v2 volume is
       the format's own eight kibibytes and on v6 is the staging buffer -- the
       .bss overflow that bound exists to stop. The append path does not stage
       through that buffer at all, and the bound still binds, because a path
       that quietly raised its own limit is how that overflow would come back. */
    uint64_t limit = xbfs_write_limit();
    int64_t bound_fd = xaiboot_fs_open("/state/append-probe",
                                       XAIOS_XBFS_OPEN_WRITE);
    kassert(bound_fd >= 0);
    kassert(xaiboot_fs_seek((uint32_t)bound_fd, limit - 1U) == XAIOS_OK);
    kassert(xaiboot_fs_write_fd((uint32_t)bound_fd, record,
                                record_length) ==
            (int64_t)XAIOS_ERR_INVALID);
    kassert(xaiboot_fs_close((uint32_t)bound_fd) == XAIOS_OK);
    kassert(xbfs_read_file("/state/append-probe", buffer, sizeof(buffer),
                      &probe_size) == XAIOS_OK);
    kassert(probe_size == record_length * (uint64_t)record_count);

    /* Failing when it should, two: a volume with no free block. The append
       needs one, cannot have one, and the file has to come back unchanged and
       still readable -- not longer, not shorter, and not corrupt. This is the
       case where a fast path that published its metadata before its blocks
       would be found out. */
    uint32_t filled = 0U;
    /* Fill to exactly full, sizing the last file to the free blocks that are
       left rather than writing whole files until one does not fit. Writing
       until failure stops with a few blocks still free, and an append that
       then succeeds would have proved nothing -- which is how this control
       would have passed while testing the opposite of what it says. */
    while (xbfs_block_count_used() < (uint64_t)xbfs_geometry_data_sectors() &&
           filled < XBFS_MAX_NODES) {
      uint64_t free_blocks =
          (uint64_t)xbfs_geometry_data_sectors() - xbfs_block_count_used();
      uint64_t chunk = free_blocks * XBFS_SECTOR_SIZE;
      if (chunk > (uint64_t)XBFS_MAX_FILE_BYTES) {
        chunk = (uint64_t)XBFS_MAX_FILE_BYTES;
      }
      char fill_path[XBFS_PATH_MAX];
      uint64_t offset = 0;
      kassert(xbfs_append_cstr(fill_path, sizeof(fill_path), &offset,
                          "/state/fill-") == XAIOS_OK);
      kassert(xbfs_append_u32(fill_path, sizeof(fill_path), &offset, filled) ==
              XAIOS_OK);
      if (xbfs_write_file_locked(fill_path, buffer, chunk) != XAIOS_OK) break;
      ++filled;
    }
    kassert(xbfs_block_count_used() == (uint64_t)xbfs_geometry_data_sectors());
    uint64_t blocked_size = 0;
    kassert(xbfs_read_file("/state/append-probe", buffer, sizeof(buffer),
                      &blocked_size) == XAIOS_OK);
    int64_t blocked_fd = xaiboot_fs_open("/state/append-probe",
                                         XAIOS_XBFS_OPEN_WRITE);
    kassert(blocked_fd >= 0);
    kassert(xaiboot_fs_seek((uint32_t)blocked_fd, blocked_size) == XAIOS_OK);
    /* A whole sector, so a block is needed whatever slack the tail had. */
    kassert(xaiboot_fs_write_fd((uint32_t)blocked_fd, buffer,
                                XBFS_SECTOR_SIZE) < 0);
    kassert(xaiboot_fs_close((uint32_t)blocked_fd) == XAIOS_OK);
    uint64_t after_size = 0;
    kassert(xbfs_read_file("/state/append-probe", buffer, sizeof(buffer),
                      &after_size) == XAIOS_OK);
    kassert(after_size == blocked_size);
    for (uint32_t i = 0U; i < filled; ++i) {
      char fill_path[XBFS_PATH_MAX];
      uint64_t offset = 0;
      kassert(xbfs_append_cstr(fill_path, sizeof(fill_path), &offset,
                          "/state/fill-") == XAIOS_OK);
      kassert(xbfs_append_u32(fill_path, sizeof(fill_path), &offset, i) == XAIOS_OK);
      kassert(xbfs_delete_node(fill_path) == XAIOS_OK);
    }
    kassert(xbfs_delete_node("/state/append-probe") == XAIOS_OK);
    klog("xaibootfs: append self-test passed appends=%lu fallbacks=%lu records=%lu filled=%u refused_full=%lu\n",
         xaiboot_fs_append_count(), xaiboot_fs_append_fallback_count(),
         (uint64_t)record_count, filled, blocked_size);
  }
  klog("xaibootfs: write bound self-test passed limit=%lu staging_buffer=%lu\n",
       xbfs_write_limit(), xbfs_file_staging_bytes());
  klog("xaibootfs: allocator self-test passed allocations=%lu frees=%lu blocks=%lu\n",
       xaiboot_fs_allocation_count(), xaiboot_fs_free_count(),
       xbfs_block_count_used());
  klog("xaibootfs: directory tree self-test passed directories=%lu\n",
       xaiboot_fs_directory_count());
  klog("xaibootfs: multi-sector file self-test passed files=%lu multi_sector=%lu\n",
       xaiboot_fs_file_count(), xaiboot_fs_multi_sector_file_count());
  klog("xaibootfs: journal replay self-test passed replays=%lu journal_writes=%lu\n",
       xaiboot_fs_replay_count(), xaiboot_fs_journal_write_count());
  klog("xaibootfs: public API self-test passed list=%lu stat=%lu rename=%lu open=%lu close=%lu\n",
       xaiboot_fs_list_count(), xaiboot_fs_stat_count(),
       xaiboot_fs_rename_count(), xaiboot_fs_open_count(),
       xaiboot_fs_close_count());
  klog("xaibootfs: subsystem records self-test passed records=%lu\n",
       xaiboot_fs_state_record_count());
  klog("xaibootfs: self-test passed files=%lu directories=%lu writes=%lu reads=%lu deletes=%lu commits=%lu rollbacks=%lu replays=%lu rejects=%lu checksum_errors=%lu\n",
       xaiboot_fs_file_count(), xaiboot_fs_directory_count(),
       xaiboot_fs_write_count(), xaiboot_fs_read_count(),
       xaiboot_fs_delete_count(), xaiboot_fs_commit_count(),
       xaiboot_fs_rollback_count(), xaiboot_fs_replay_count(),
       xaiboot_fs_reject_count(), xaiboot_fs_checksum_error_count());
}
