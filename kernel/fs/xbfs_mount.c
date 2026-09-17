/*
 * xaibootFS's persistent-device layer: the block I/O every translation unit
 * reaches the volume through, the mount-state globals, and the two mount
 * paths plus unmount.
 *
 * Split out of xaiboot_fs.c. The volume codec and the format/validation
 * routines stay in xaiboot_fs.c, because they index the volume state (g_xbfs)
 * field by field; they cross as xbfs_volume_* through xbfs_volume_internal.h.
 * Every entry point here runs with the volume lock held, exactly as the static
 * functions it replaces did, and takes no lock itself -- the lock-taking
 * public wrappers stay in xaiboot_fs.c.
 */

#include <xaios/block_device.h>
#include <xaios/klog.h>
#include <xaios/virtio_blk.h>

#include "xbfs_internal.h"
#include "xbfs_metadata_internal.h"
#include "xbfs_file_io_internal.h"
#include "xbfs_volume_internal.h"

/* The mount state. g_mounted and g_mount_flags are the two values every
   namespace operation checks through xbfs_mounted and xbfs_mount_flags; the
   persistent device and its mount count belong to the same device layer. */
static uint32_t g_mounted;
static uint32_t g_mount_flags;
static xaios_block_device_t *g_persistent_device;
static uint64_t g_persistent_mount_count;

/* The setters xaiboot_fs.c's self-test needs after the state moved here. Each
   is a plain assignment, and the test calls them in the same order the three
   assignments it replaced appeared in. */
void xbfs_mount_set_mounted(uint32_t mounted) { g_mounted = mounted; }

void xbfs_mount_set_flags(uint32_t flags) { g_mount_flags = flags; }

void xbfs_mount_set_device(xaios_block_device_t *device) {
  g_persistent_device = device;
}

xaios_status_t xbfs_blk_read(uint64_t sector, void *buf, uint64_t sz) {
  if (g_persistent_device != 0) {
    if (sector > UINT64_MAX / XBFS_SECTOR_SIZE) return XAIOS_ERR_INVALID;
    return block_read(g_persistent_device, sector * XBFS_SECTOR_SIZE, buf, sz);
  }
  return virtio_block_read_sector(sector, buf, sz);
}

xaios_status_t xbfs_blk_write(uint64_t sector, const void *buf, uint64_t sz) {
  if (g_persistent_device != 0) {
    if (sector > UINT64_MAX / XBFS_SECTOR_SIZE) return XAIOS_ERR_INVALID;
    return block_write(g_persistent_device, sector * XBFS_SECTOR_SIZE, buf, sz);
  }
  return virtio_block_write_sector(sector, buf, sz);
}

xaios_status_t xbfs_blk_flush(void) {
  if (g_persistent_device != 0) {
    return block_flush(g_persistent_device);
  }
  return virtio_block_flush();
}

uint64_t xbfs_blk_capacity(void) {
  if (g_persistent_device != 0) {
    return g_persistent_device->info.capacity_bytes / XBFS_SECTOR_SIZE;
  }
  return virtio_block_capacity_sectors();
}

uint32_t xbfs_mounted(void) { return g_mounted; }

uint32_t xbfs_mount_flags(void) { return g_mount_flags; }

xaios_status_t xbfs_mount_volume(uint32_t mount_flags) {
  xbfs_geometry_select(XBFS_VERSION);
  /* The in-image volume is sized to the boot image and has no room for a
     mirror. Clear it explicitly: this global outlives a previous device
     mount, and inheriting its setting here would send writes to a slot that
     does not exist on this volume. */
  xbfs_metadata_set_mirror_enabled(0U);
  xbfs_metadata_shadow_set_valid(0U, 0U);
  xbfs_metadata_shadow_set_valid(1U, 0U);
  xbfs_metadata_set_slot(0U);
  if (xbfs_blk_capacity() < xbfs_data_start_sector() + xbfs_geometry_data_sectors()) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_IO;
  }

  g_mount_flags = mount_flags;
  if (xbfs_volume_read_metadata() != XAIOS_OK) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_IO;
  }
  uint64_t saved_checksum = xbfs_volume_checksum_get();
  if (xbfs_volume_validate(xbfs_metadata_verified_checksum()) == XAIOS_OK &&
      saved_checksum == xbfs_metadata_verified_checksum()) {
    xbfs_stat_bump(XBFS_STAT_BOOT_LOAD);
    klog("xaibootfs: existing state loaded files=%lu directories=%lu blocks=%lu generation=%lu committed=%lu\n",
         xbfs_node_count_by_type(XBFS_NODE_FILE), xbfs_node_count_by_type(XBFS_NODE_DIR),
         xbfs_block_count_used(), xbfs_generation_get(),
         xbfs_volume_committed_generation_get());
  } else {
    klog("xaibootfs: no valid filesystem at sector=%lu; formatting\n",
         XBFS_START_SECTOR);
    if (xbfs_volume_format() != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
  }

  g_mounted = 1;
  xbfs_stat_bump(XBFS_STAT_MOUNT);
  if (xbfs_replay_journal() != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }

  if ((g_mount_flags & XBFS_MOUNT_READ_WRITE) != 0U) {
    xaios_xbfs_node_t *root = xbfs_find_node("/", 1);
    if (root == 0) {
      if (xbfs_create_dir("/") != XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
    } else if (root->active == 0) {
      if (xbfs_snapshot_restore_node(root) != XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
    } else if (root->type != XBFS_NODE_DIR) {
      xbfs_stat_bump(XBFS_STAT_REJECT);
      return XAIOS_ERR_INVALID;
    }
  }

  klog("xaibootfs: mounted start=%lu metadata=%lu journal=%lu data=%lu sectors=%u nodes=%u policy=%s\n",
       XBFS_START_SECTOR, (uint64_t)xbfs_geometry_metadata_sectors(), XBFS_JOURNAL_SECTORS,
       xbfs_data_start_sector(), xbfs_geometry_data_sectors(), xbfs_geometry_max_nodes(),
       (g_mount_flags & XBFS_MOUNT_READ_WRITE) != 0 ? "rw" : "ro");
  return XAIOS_OK;
}

uint64_t xaiboot_fs_persistent_mount_count(void) { return g_persistent_mount_count; }

static xaios_status_t xbfs_mount_failure(xaios_block_device_t *device,
                                         xaios_status_t status) {
  g_persistent_device = 0;
  g_mounted = 0;
  g_mount_flags = 0;
  xbfs_geometry_select(XBFS_VERSION);
  (void)block_device_close(device);
  return status;
}

xaios_status_t xbfs_mount_device_locked(const char *identifier) {
  if (g_persistent_device != 0) return XAIOS_ERR_BUSY;
  xaios_block_device_t *device = 0;
  xaios_status_t status = block_device_open(identifier, &device);
  if (status != XAIOS_OK) {
    klog("xaibootfs: persistent block device not found id=%s\n",
         identifier != 0 ? identifier : "(null)");
    return status;
  }
  xaios_block_device_info_t info;
  if (block_device_info(device, &info) != XAIOS_OK) {
    (void)block_device_close(device);
    return XAIOS_ERR_IO;
  }
  if (info.read_only != 0U ||
      info.logical_sector_size != XBFS_SECTOR_SIZE ||
      info.capacity_bytes % XBFS_SECTOR_SIZE != 0U ||
      info.flush_supported == 0U) {
    klog("xaibootfs: device rejected id=%s sector=%lu read_only=%u flush=%u\n",
         identifier, info.logical_sector_size, info.read_only,
         info.flush_supported);
    (void)block_device_close(device);
    return XAIOS_ERR_UNSUPPORTED;
  }
  xbfs_geometry_select(XBFS_V5_VERSION);
  xbfs_metadata_shadow_set_valid(0U, 0U);
  xbfs_metadata_shadow_set_valid(1U, 0U);
  xbfs_metadata_set_slot(0U);
  xbfs_metadata_set_sequence(0U);
  /* The mirror is optional: a volume sized exactly for the old layout keeps
     working single-copy rather than being refused. */
  xbfs_metadata_set_mirror_enabled(
      info.capacity_bytes / XBFS_SECTOR_SIZE >=
              xbfs_metadata_mirror_start_sector() + xbfs_geometry_metadata_sectors()
          ? 1U
          : 0U);
  if (info.capacity_bytes / XBFS_SECTOR_SIZE <
      xbfs_data_start_sector() + XBFS_V5_DATA_SECTORS) {
    klog("xaibootfs: persistent disk too small capacity=%lu needed=%lu\n",
         info.capacity_bytes / XBFS_SECTOR_SIZE,
         xbfs_data_start_sector() + XBFS_V5_DATA_SECTORS);
    xbfs_geometry_select(XBFS_VERSION);
    (void)block_device_close(device);
    return XAIOS_ERR_IO;
  }
  g_persistent_device = device;
  g_mounted = 0;
  g_mount_flags = 0;
  if (xbfs_volume_read_metadata() != XAIOS_OK) {
    return xbfs_mount_failure(device, XAIOS_ERR_IO);
  }
  uint64_t saved_checksum = xbfs_volume_checksum_get();
  uint32_t loaded_version = xbfs_geometry_version();
  int valid_existing =
      xbfs_volume_validate(xbfs_metadata_verified_checksum()) == XAIOS_OK &&
      saved_checksum == xbfs_metadata_verified_checksum();
  if (valid_existing) {
    xbfs_stat_bump(XBFS_STAT_BOOT_LOAD);
    klog("xaibootfs: persistent loaded files=%lu dirs=%lu blocks=%lu gen=%lu\n",
         xbfs_node_count_by_type(XBFS_NODE_FILE), xbfs_node_count_by_type(XBFS_NODE_DIR),
         xbfs_block_count_used(), xbfs_generation_get());
  } else {
    if (!xbfs_metadata_header_is_blank()) {
      klog("xaibootfs: persistent metadata invalid; refusing destructive format\n");
      return xbfs_mount_failure(device, XAIOS_ERR_INVALID);
    }
    /* Which version a new volume gets follows the disk rather than a flag
       day. A device with room for v6 is formatted as v6 and gets a gigabyte
       of data, a thousand nodes and files as large as the volume; a smaller
       one is formatted as v5 exactly as before. Nothing existing changes
       format, and no volume is rewritten in place -- the one operation on
       this data nobody should have to trust. */
    uint64_t sectors = info.capacity_bytes / XBFS_SECTOR_SIZE;
    uint64_t v6_needed = XBFS_START_SECTOR + XBFS_V6_METADATA_SECTORS * 2U +
                         XBFS_JOURNAL_SECTORS + 1U + XBFS_V6_DATA_SECTORS;
    if (sectors >= v6_needed) {
      xbfs_geometry_select(XBFS_V6_VERSION);
      klog("xaibootfs: persistent disk no valid fs; formatting v6 "
           "nodes=%u data_sectors=%u\n",
           XBFS_V6_MAX_NODES, XBFS_V6_DATA_SECTORS);
    } else {
      xbfs_geometry_select(XBFS_V5_VERSION);
      klog("xaibootfs: persistent disk no valid fs; formatting v5\n");
    }
    if (xbfs_volume_format() != XAIOS_OK) {
      return xbfs_mount_failure(device, XAIOS_ERR_IO);
    }
  }
  g_mounted = 1;
  g_mount_flags = XBFS_MOUNT_READ_WRITE;
  xbfs_stat_bump(XBFS_STAT_MOUNT);
  ++g_persistent_mount_count;
  if (xbfs_replay_journal() != XAIOS_OK) {
    return xbfs_mount_failure(device, XAIOS_ERR_IO);
  }
  if (valid_existing && loaded_version != XBFS_V5_VERSION &&
      xbfs_volume_migrate_to_v5() != XAIOS_OK) {
    return xbfs_mount_failure(device, XAIOS_ERR_IO);
  }
  xaios_xbfs_node_t *root = xbfs_find_node("/", 1);
  if (root == 0) {
    if (xbfs_create_dir("/") != XAIOS_OK) {
      return xbfs_mount_failure(device, XAIOS_ERR_IO);
    }
  }
  if (xbfs_ensure_base_directories() != XAIOS_OK) {
    return xbfs_mount_failure(device, XAIOS_ERR_IO);
  }
  klog("xaibootfs: persistent mounted v5 nodes=%u sectors=%u\n",
       xbfs_geometry_max_nodes(), xbfs_geometry_data_sectors());
  return XAIOS_OK;
}

xaios_status_t xbfs_mount_persistent_locked(uint32_t slot) {
  char identifier[16] = "/dev/vblk";
  uint32_t value = slot;
  uint32_t digits = 1U;
  while (value >= 10U) {
    value /= 10U;
    ++digits;
  }
  if (9U + digits + 1U > sizeof(identifier)) return XAIOS_ERR_INVALID;
  identifier[9U + digits] = '\0';
  for (uint32_t index = 0U; index < digits; ++index) {
    identifier[9U + digits - 1U - index] = (char)('0' + slot % 10U);
    slot /= 10U;
  }
  return xbfs_mount_device_locked(identifier);
}

/*
 * Unmount: flush, then drop the device and every piece of mount bookkeeping.
 *
 * The public xaiboot_fs_unmount takes the volume lock and calls this; the body
 * runs entirely inside that critical section, exactly as it did when it was
 * part of the lock-taking wrapper. The slot bookkeeping is reset so a later
 * mount re-derives which copy is authoritative from the volume rather than
 * from whatever the previous mount happened to leave behind.
 */
xaios_status_t xbfs_mount_unmount_locked(void) {
  if (g_persistent_device == 0) {
    return XAIOS_ERR_INVALID;
  }
  (void)xbfs_blk_flush();
  xaios_block_device_t *device = g_persistent_device;
  g_persistent_device = 0;
  g_mounted = 0;
  g_mount_flags = 0;
  xbfs_metadata_shadow_set_valid(0U, 0U);
  xbfs_metadata_shadow_set_valid(1U, 0U);
  xbfs_metadata_set_slot(0U);
  xbfs_metadata_set_sequence(0U);
  xbfs_metadata_set_mirror_enabled(0U);
  xbfs_geometry_select(XBFS_VERSION);
  (void)block_device_close(device);
  return XAIOS_OK;
}
