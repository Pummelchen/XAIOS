/* The interface kernel/fs/xai_fs_admin.c and kernel/fs/xai_fs_admin_support.c
 * share after the split.
 *
 * xai_fs_admin_support.c owns the block-device scratch context, the
 * read/write/flush adapters the engine calls, partition and volume open and
 * close, package-id parsing and lookup, and the report-filling helpers.
 * xai_fs_admin.c keeps the seven public admin commands -- format plan and
 * format, fsck, repair, repair from replica, grow plan and grow -- and calls
 * into the support unit. The model_admin_io_t context, the MODEL_ADMIN_*
 * geometry, the one shared scratch context and the helper prototypes below
 * are declared here once, so neither unit restates them; every helper is
 * defined in exactly one of the two files.
 */
#ifndef XAIOS_KERNEL_FS_XAI_FS_ADMIN_INTERNAL_H
#define XAIOS_KERNEL_FS_XAI_FS_ADMIN_INTERNAL_H

#include <xaios/xai_fs_admin.h>

#include <xaios_engine/xai_fs.h>

#define MODEL_ADMIN_SCRATCH_SIZE UINT64_C(65536)
#define MODEL_ADMIN_MAX_SECTOR_SIZE UINT64_C(4096)
#define MODEL_ADMIN_DEFAULT_CHUNK_SIZE UINT64_C(4194304)

typedef struct model_admin_io {
  xaios_block_device_t *device;
  xaios_block_device_info_t info;
  uint8_t bounce[MODEL_ADMIN_MAX_SECTOR_SIZE];
  uint8_t scratch[MODEL_ADMIN_SCRATCH_SIZE];
} model_admin_io_t;

extern model_admin_io_t xai_fs_admin_io;

xaios_engine_status_t xai_fs_admin_verify_signature(
    void *context, const uint8_t public_key[32], const uint8_t signature[64],
    const uint8_t message[32]);
xaios_status_t xai_fs_admin_map_engine_status(xaios_engine_status_t status);
xaios_engine_status_t xai_fs_admin_read_at(void *context, uint64_t offset,
                                           void *destination, size_t length);
xaios_engine_status_t xai_fs_admin_write_at(void *context, uint64_t offset,
                                            const void *source, size_t length);
xaios_engine_status_t xai_fs_admin_flush(void *context);
xaios_status_t xai_fs_admin_confirmation_matches(const char *confirmation,
                                                 const char *expected);
void xai_fs_admin_derive_volume_uuid(const char *partition_uuid,
                                     uint8_t volume_uuid[16]);
xaios_status_t xai_fs_admin_open_partition_into(
    model_admin_io_t *io, const char *identifier, uint32_t require_idle,
    uint32_t require_writable, xaios_storage_partition_record_t *partition);
xaios_status_t xai_fs_admin_open_partition(
    const char *identifier, uint32_t require_idle,
    xaios_storage_partition_record_t *partition);
void xai_fs_admin_close_partition_io(model_admin_io_t *io);
void xai_fs_admin_close_partition(void);
void xai_fs_admin_hex_id(const uint8_t id[32], char output[65]);
void xai_fs_admin_fill_base_report(
    const xaios_storage_partition_record_t *partition,
    xaios_xai_fs_admin_report_t *report);
xaios_status_t xai_fs_admin_fill_volume_report(
    const xaios_storage_partition_record_t *partition,
    const xaios_xai_fs_t *volume, const xaios_xai_fs_probe_t *probe,
    xaios_xai_fs_admin_report_t *report);
xaios_status_t xai_fs_admin_open_volume_into(model_admin_io_t *io,
                                             xaios_xai_fs_t *volume,
                                             xaios_xai_fs_probe_t *probe);
xaios_status_t xai_fs_admin_open_volume(xaios_xai_fs_t *volume,
                                        xaios_xai_fs_probe_t *probe);
int xai_fs_admin_parse_package_id(const char *text, uint8_t package_id[32]);
xaios_status_t xai_fs_admin_find_package(const xaios_xai_fs_t *volume,
                                         const uint8_t package_id[32],
                                         xaios_xai_fs_package_t *package);

#endif
