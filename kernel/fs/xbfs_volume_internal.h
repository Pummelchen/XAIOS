/*
 * Private declarations shared by the split of xaiboot_fs.c into
 * xaiboot_fs.c, xbfs_mount.c and xbfs_snapshot.c.
 *
 * xaiboot_fs.c keeps the volume state (g_xbfs) and the codec/format routines
 * that index it field by field; those cross as xbfs_volume_* and are defined
 * there. The persistent device, the mount-state globals and the block I/O
 * wrappers live in xbfs_mount.c, which exports the setters the self-test in
 * xaiboot_fs.c needs. The snapshot group lives in xbfs_snapshot.c and also
 * serves the one call mount makes into it. Every declaration here has exactly
 * one definition; nothing is defined twice.
 */

#ifndef XAIOS_KERNEL_FS_XBFS_VOLUME_INTERNAL_H
#define XAIOS_KERNEL_FS_XBFS_VOLUME_INTERNAL_H

#include <xaios/block_device.h>

#include "xbfs_internal.h"

/* Defined in xaiboot_fs.c with the volume state they index. All are values in
   or out; none hands back a pointer into g_xbfs. None takes the volume lock;
   every caller already holds it. */
xaios_status_t xbfs_volume_read_metadata(void);
xaios_status_t xbfs_volume_validate(uint64_t expected_checksum);
xaios_status_t xbfs_volume_format(void);
xaios_status_t xbfs_volume_migrate_to_v5(void);
uint64_t xbfs_volume_checksum_get(void);
uint64_t xbfs_volume_committed_generation_get(void);
void xbfs_volume_committed_generation_set(uint64_t generation);
void xbfs_volume_generation_bump(void);

/* Defined in xbfs_mount.c. The setters are for xaiboot_fs.c's self-test, which
   resets the mount state directly; everything else here is the mount path. */
void xbfs_mount_set_mounted(uint32_t mounted);
void xbfs_mount_set_flags(uint32_t flags);
void xbfs_mount_set_device(xaios_block_device_t *device);
xaios_status_t xbfs_mount_volume(uint32_t mount_flags);
xaios_status_t xbfs_mount_device_locked(const char *identifier);
xaios_status_t xbfs_mount_persistent_locked(uint32_t slot);
xaios_status_t xbfs_mount_unmount_locked(void);

/* Defined in xbfs_snapshot.c: the commit/restore/rollback group. */
xaios_status_t xbfs_snapshot_commit(const char *label);
xaios_status_t xbfs_snapshot_restore_node(xaios_xbfs_node_t *node);
xaios_status_t xbfs_snapshot_rollback(void);

#endif /* XAIOS_KERNEL_FS_XBFS_VOLUME_INTERNAL_H */
