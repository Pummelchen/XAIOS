#ifndef XAIOS_PERSISTENCE_H
#define XAIOS_PERSISTENCE_H

#include <xaios/status.h>
#include <xaios/types.h>
#include <xaios/virtio_blk.h>

typedef enum xaios_snapshot_kind {
  XAIOS_SNAPSHOT_BOOT_CONFIG = 1,
  XAIOS_SNAPSHOT_SERVICE = 2,
  XAIOS_SNAPSHOT_WORKSPACE = 3,
  XAIOS_SNAPSHOT_SANDBOX = 4,
  XAIOS_SNAPSHOT_UPDATE = 5,
} xaios_snapshot_kind_t;

/* Bind the durable volume that snapshot state is written to. Without this
   the default block device is used, which on QEMU is the snapshot-backed
   test image whose writes never survive a restart. */
void persistence_bind_block_device(virtio_block_handle_t *handle);
void persistence_runtime_init(void);
xaios_status_t persistence_snapshot_create(xaios_snapshot_kind_t kind,
                                          uint32_t owner_id,
                                          const char *label);
xaios_status_t persistence_rollback(xaios_snapshot_kind_t kind,
                                   uint32_t owner_id);
uint64_t persistence_snapshot_count(void);
uint64_t persistence_rollback_count(void);
uint64_t persistence_reject_count(void);
uint64_t persistence_disk_write_count(void);
uint64_t persistence_disk_load_count(void);
uint64_t persistence_disk_boot_load_count(void);
uint64_t persistence_checksum_error_count(void);
void persistence_self_test(void);

#endif
