/* Handle lifecycle for virtio block devices.
 *
 * Split out of virtio_blk.c so no source file exceeds 500 lines. What lives
 * here is everything that opens, uses and closes a device that is not the
 * primary one: transfers on a handle, the taken-device registry, handle
 * allocation and bring-up, and the slot/ordinal/PCI-ordinal entry points.
 * The device bring-up, request engine and block backend stay in
 * virtio_blk.c, and the two files share the driver layout and helpers through
 * virtio_blk_internal.h.
 *
 * The primary driver pointer is reached through virtio_blk_primary_driver(),
 * which copies its value out; `g_blk' itself is not exported.
 */

#include "virtio_blk_internal.h"

#include <xaios/kheap.h>
#include <xaios/klog.h>

static xaios_status_t transfer_sector_h(virtio_block_driver_t *drv,
                                        uint64_t sector, void *buffer,
                                        uint64_t buffer_size, uint32_t type) {
  if (drv == 0 || drv->initialized == 0 || buffer == 0 ||
      buffer_size < SECTOR_SIZE) {
    return XAIOS_ERR_INVALID;
  }
  if (type != VIRTIO_BLK_T_IN && type != VIRTIO_BLK_T_OUT) {
    return XAIOS_ERR_INVALID;
  }
  if (sector >= drv->capacity_sectors) return XAIOS_ERR_IO;
  if (type == VIRTIO_BLK_T_OUT && drv->read_only != 0U) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  virtio_block_sync_wait_t wait = {0U, XAIOS_ERR_IO};
  uint64_t token = 0U;
  xaios_status_t status;
  do {
    /* One sector, whatever the buffer holds. This is the single-sector API
       and its callers size their buffers generously; taking more than a
       sector here would write past what they meant. Callers that want a
       whole span go through the block backend. */
    status = submit_sector_h(drv, sector, buffer,
                             buffer_size < SECTOR_SIZE ? buffer_size
                                                       : SECTOR_SIZE,
                             type,
                             sync_completion, &wait, &token, 0);
    if (status == XAIOS_ERR_BUSY) (void)virtio_block_poll_h(drv);
  } while (status == XAIOS_ERR_BUSY);
  if (status != XAIOS_OK) return status;
  (void)token;
  return wait_sync(drv, &wait);
}

static xaios_status_t virtio_block_transfer_sector(uint64_t sector, void *buffer,
                                                  uint64_t buffer_size,
                                                  uint32_t type) {
  virtio_block_driver_t *drv = virtio_blk_primary_driver();
  if (drv == 0 || drv->initialized == 0) {
    return XAIOS_ERR_INVALID;
  }
  return transfer_sector_h(drv, sector, buffer, buffer_size, type);
}

xaios_status_t virtio_block_read_sector(uint64_t sector, void *buffer,
                                       uint64_t buffer_size) {
  return virtio_block_transfer_sector(sector, buffer, buffer_size,
                                      VIRTIO_BLK_T_IN);
}

xaios_status_t virtio_block_write_sector(uint64_t sector, const void *buffer,
                                        uint64_t buffer_size) {
  return virtio_block_transfer_sector(sector, (void *)buffer, buffer_size,
                                      VIRTIO_BLK_T_OUT);
}

xaios_status_t virtio_block_flush(void) {
  return flush_h(virtio_blk_primary_driver());
}

/* Everything a handle owns, in one place, so that a probe that finds no device
   gives it all back. The scan below calls this once per ordinal and stops on
   the first miss, and a leak per miss would be a leak on every boot. */
static void release_handle(virtio_block_driver_t *drv) {
  if (drv == 0) return;
  for (uint32_t i = 0U; i < VIRTIO_BLK_MAX_ASYNC_DEPTH; ++i) {
    kheap_free(drv->async_slots[i]);
  }
  kheap_free(drv->status);
  kheap_free(drv->dma_sector);
  kheap_free(drv->request);
  kheap_free(drv->used);
  kheap_free(drv->avail);
  kheap_free(drv->desc);
  kheap_free(drv);
}

/* Which physical devices this driver has already taken.
 *
 * Opening a device twice is not refused by the device and not checked here:
 * each open configures a queue and registers a completion, so a second one
 * fights the first for the same virtqueue. Nothing needed to know which devices
 * were in use until the storage-administration window had to *find* one instead
 * of being told where to look -- the window used to be a fixed position in a
 * test bench's device order, which no machine with fewer disks than the bench
 * can satisfy (B-113).
 *
 * A device is identified by its transport and the address of its common
 * configuration structure, which is unique per device on both transports. An
 * ordinal would not do: the same device is reached by different ordinals
 * depending on which lookup is used to find it. */
#define VIRTIO_BLOCK_MAX_TAKEN 8U
typedef struct {
  uint32_t backend;
  uint64_t common_config;
} virtio_block_taken_t;

static virtio_block_taken_t g_taken[VIRTIO_BLOCK_MAX_TAKEN];
static uint32_t g_taken_count;

static int block_device_taken(const virtio_mmio_device_t *device) {
  for (uint32_t i = 0U; i < g_taken_count; ++i) {
    if (g_taken[i].backend == device->backend &&
        g_taken[i].common_config == device->common_config) {
      return 1;
    }
  }
  return 0;
}

void block_device_note_taken(const virtio_mmio_device_t *device) {
  if (g_taken_count >= VIRTIO_BLOCK_MAX_TAKEN) return;
  g_taken[g_taken_count].backend = device->backend;
  g_taken[g_taken_count].common_config = device->common_config;
  ++g_taken_count;
}

static virtio_block_driver_t *allocate_handle(void) {
  virtio_block_driver_t *drv =
      (virtio_block_driver_t *)kheap_calloc(sizeof(*drv), 16);
  if (drv == 0) return 0;
  drv->desc = (virtq_desc_t *)kheap_calloc(
      sizeof(virtq_desc_t) * VIRTQ_SIZE, DMA_ALIGNMENT);
  drv->avail = (virtq_avail_t *)kheap_calloc(
      sizeof(virtq_avail_t), DMA_ALIGNMENT);
  drv->used = (virtq_used_t *)kheap_calloc(
      sizeof(virtq_used_t), DMA_ALIGNMENT);
  drv->request = (virtio_blk_req_t *)kheap_calloc(
      sizeof(virtio_blk_req_t), DMA_ALIGNMENT);
  drv->dma_sector =
      (uint8_t *)kheap_calloc(SECTOR_SIZE, DMA_ALIGNMENT);
  drv->status = (uint8_t *)kheap_calloc(1, DMA_ALIGNMENT);
  if (drv->desc == 0 || drv->avail == 0 || drv->used == 0 ||
      drv->request == 0 || drv->dma_sector == 0 || drv->status == 0) {
    release_handle(drv);
    return 0;
  }
  for (uint32_t i = 0U; i < VIRTIO_BLK_MAX_ASYNC_DEPTH; ++i) {
    drv->async_slots[i] = (virtio_blk_async_slot_t *)kheap_calloc(
        sizeof(virtio_blk_async_slot_t), DMA_ALIGNMENT);
    if (drv->async_slots[i] == 0) {
      release_handle(drv);
      return 0;
    }
  }
  xaios_spin_init(&drv->queue_lock);
  return drv;
}

/* Bring up a device the caller has already located. Shared by both entry
   points below so that a disk found by ordinal is configured, checked and
   registered exactly the way a disk found by slot is. */
static xaios_status_t start_handle(virtio_block_driver_t *drv, uint32_t slot) {
  if (configure_queue(drv) != XAIOS_OK) {
    klog("virtio-blk-h: slot=%u queue configuration failed\n", slot);
    return XAIOS_ERR_IO;
  }
  drv->capacity_sectors = read_capacity(&drv->device);
  if (read_device_geometry(drv) != XAIOS_OK) return XAIOS_ERR_INVALID;
  drv->initialized = 1;
  /* Completion is polled through the used ring on every submission path, so
     a transport with no message-signalled interrupt still serves requests.
     Losing a whole volume over a missing notification would leave the
     machine without persistent storage for no reason. */
  if (virtio_transport_register_interrupt(
          &drv->device, virtio_block_interrupt, drv) != XAIOS_OK) {
    klog("virtio-blk-h: slot=%u no interrupt available; completions are "
         "polled\n",
         slot);
  }
  if (register_block_device(drv) != XAIOS_OK) {
    klog("virtio-blk-h: slot=%u registration failed\n", slot);
    drv->initialized = 0U;
    return XAIOS_ERR_INVALID;
  }
  klog("virtio-blk-h: slot=%u capacity_sectors=%lu event_idx=%u\n", slot,
       drv->capacity_sectors, drv->uses_event_idx);
  return XAIOS_OK;
}

/* The storage-administration window: the disk an operator installs onto.
 *
 * The window has a configured address on the test bench, where every volume is
 * attached in a known order, and that address is tried first so the bench
 * behaves exactly as it did. What it could not do is work anywhere else. The
 * configured window is logical slot 5, which the PCI transport carries to
 * enumeration ordinal 4 -- the fifth block device, in the order the bench
 * attaches five. A machine XAIOS has been installed onto has two, so the
 * window did not resolve and the spare disk was never opened: the install
 * phase of the x86-64 and RISC-V gates could only be skipped, and on a real
 * two-disk machine installing was impossible rather than merely unproven
 * (B-113).
 *
 * So if the configured window is absent, take the first block device nothing
 * else has taken. On a one-disk machine that is nothing, which is right: there
 * is no spare and the caller is told so. On a machine with a spare it is the
 * spare, whatever order the firmware happened to enumerate the bus in. The
 * device keeps the caller's logical slot, so it is named /dev/vblk5 wherever
 * it was found -- a device's name is a name, not a position.
 *
 * `scan_limit` bounds the search; the caller passes the same ceiling the rest
 * of this file uses for "how many disks could there possibly be". */
xaios_status_t virtio_block_open_administration_window(
    uint32_t slot, uint32_t scan_limit, virtio_block_handle_t **out_handle) {
  if (out_handle == 0) return XAIOS_ERR_INVALID;
  if (virtio_block_open_slot(slot, out_handle) == XAIOS_OK) {
    return XAIOS_OK;
  }
  for (uint32_t ordinal = 0U; ordinal < scan_limit; ++ordinal) {
    virtio_mmio_device_t probe;
    if (virtio_transport_find_nth(VIRTIO_DEVICE_BLOCK, "virtio-blk-admin",
                                  ordinal, ordinal, &probe) != XAIOS_OK) {
      continue;
    }
    if (block_device_taken(&probe) != 0) continue;
    if (virtio_block_open_ordinal(ordinal, slot, out_handle) == XAIOS_OK) {
      klog("storage-admin: window slot=%u is not attached; using the first "
           "unclaimed block device, ordinal=%u\n", slot, ordinal);
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t virtio_block_open_slot(uint32_t start_slot,
                                     virtio_block_handle_t **out_handle) {
  if (out_handle == 0) {
    return XAIOS_ERR_INVALID;
  }
  virtio_block_driver_t *drv = allocate_handle();
  if (drv == 0) return XAIOS_ERR_NO_MEMORY;
  if (virtio_transport_find_at(VIRTIO_DEVICE_BLOCK, "virtio-blk-h",
                               start_slot, &drv->device) != XAIOS_OK) {
    release_handle(drv);
    return XAIOS_ERR_NOT_FOUND;
  }
  /* A device another handle already owns is never opened, whatever the caller
     asked for and whatever the registry happens to contain: opening it
     re-negotiates the features, which resets the device and moves its queue to
     this handle's rings, and the owner is left with a disk that silently stops
     answering (B-121). The caller is told which device and why. */
  if (block_device_taken(&drv->device) != 0) {
    klog("virtio-blk-h: slot=%u base=0x%lx already belongs to another "
         "handle\n",
         start_slot, (unsigned long)drv->device.base);
    release_handle(drv);
    return XAIOS_ERR_BUSY;
  }
  xaios_status_t status = start_handle(drv, start_slot);
  if (status != XAIOS_OK) {
    release_handle(drv);
    return status;
  }
  block_device_note_taken(&drv->device);
  *out_handle = drv;
  return XAIOS_OK;
}

/* How many virtio block devices this machine presents, counted without
   claiming any of them.

   The distinction this answers is the one between an installed machine and a
   test bench. An installed machine has one disk, and its durable state is a
   partition of that disk because there is nowhere else for it to be. A test
   bench has a disk per volume, each pinned to a known window, and every one of
   them already belongs to a driver. Scanning and opening devices on a test
   bench takes volumes away from the drivers that own them -- which is exactly
   what happened when this scan first ran there, and the machine came up
   without a working shell.

   Finding a device is a read of its identity registers and does not configure
   or claim it, so asking this question costs nothing. */
uint32_t virtio_block_present_count(uint32_t limit) {
  virtio_mmio_device_t probe;
  uint32_t count = 0U;
  while (count < limit) {
    if (virtio_transport_find_nth(VIRTIO_DEVICE_BLOCK, "virtio-blk-count",
                                  count, count, &probe) != XAIOS_OK) {
      break;
    }
    ++count;
  }
  return count;
}

xaios_status_t virtio_block_open_pci_ordinal(
    uint32_t ordinal, uint32_t slot, virtio_block_handle_t **out_handle) {
  if (out_handle == 0) {
    return XAIOS_ERR_INVALID;
  }
  virtio_block_driver_t *drv = allocate_handle();
  if (drv == 0) return XAIOS_ERR_NO_MEMORY;
  if (virtio_transport_find_nth_pci(VIRTIO_DEVICE_BLOCK, "virtio-blk-h",
                                    ordinal, slot,
                                    &drv->device) != XAIOS_OK) {
    release_handle(drv);
    return XAIOS_ERR_NOT_FOUND;
  }
  /* A device another handle already owns is never opened, whatever the caller
     asked for and whatever the registry happens to contain: opening it
     re-negotiates the features, which resets the device and moves its queue to
     this handle's rings, and the owner is left with a disk that silently stops
     answering (B-121). The caller is told which device and why. */
  if (block_device_taken(&drv->device) != 0) {
    klog("virtio-blk-h: slot=%u base=0x%lx already belongs to another "
         "handle\n",
         slot, (unsigned long)drv->device.base);
    release_handle(drv);
    return XAIOS_ERR_BUSY;
  }
  xaios_status_t status = start_handle(drv, slot);
  if (status != XAIOS_OK) {
    release_handle(drv);
    return status;
  }
  block_device_note_taken(&drv->device);
  *out_handle = drv;
  return XAIOS_OK;
}

xaios_status_t virtio_block_open_ordinal(uint32_t ordinal, uint32_t slot,
                                        virtio_block_handle_t **out_handle) {
  if (out_handle == 0) {
    return XAIOS_ERR_INVALID;
  }
  virtio_block_driver_t *drv = allocate_handle();
  if (drv == 0) return XAIOS_ERR_NO_MEMORY;
  if (virtio_transport_find_nth(VIRTIO_DEVICE_BLOCK, "virtio-blk-h", ordinal,
                                slot, &drv->device) != XAIOS_OK) {
    release_handle(drv);
    return XAIOS_ERR_NOT_FOUND;
  }
  /* A device another handle already owns is never opened, whatever the caller
     asked for and whatever the registry happens to contain: opening it
     re-negotiates the features, which resets the device and moves its queue to
     this handle's rings, and the owner is left with a disk that silently stops
     answering (B-121). The caller is told which device and why. */
  if (block_device_taken(&drv->device) != 0) {
    klog("virtio-blk-h: slot=%u base=0x%lx already belongs to another "
         "handle\n",
         slot, (unsigned long)drv->device.base);
    release_handle(drv);
    return XAIOS_ERR_BUSY;
  }
  xaios_status_t status = start_handle(drv, slot);
  if (status != XAIOS_OK) {
    release_handle(drv);
    return status;
  }
  block_device_note_taken(&drv->device);
  *out_handle = drv;
  return XAIOS_OK;
}

xaios_status_t virtio_block_read_sector_h(virtio_block_handle_t *handle,
                                         uint64_t sector, void *buffer,
                                         uint64_t buffer_size) {
  return transfer_sector_h(handle, sector, buffer, buffer_size, VIRTIO_BLK_T_IN);
}

xaios_status_t virtio_block_write_sector_h(virtio_block_handle_t *handle,
                                          uint64_t sector, const void *buffer,
                                          uint64_t buffer_size) {
  return transfer_sector_h(handle, sector, (void *)buffer, buffer_size,
                           VIRTIO_BLK_T_OUT);
}

xaios_status_t virtio_block_submit_read_h(
    virtio_block_handle_t *handle, uint64_t sector, void *buffer,
    uint64_t buffer_size, virtio_block_completion_t completion, void *context,
    uint64_t *token) {
  /* One sector, as this entry point has always meant, but a buffer smaller
     than that still has to be rejected rather than clamped into range. */
  return submit_sector_h(handle, sector, buffer,
                         buffer_size < SECTOR_SIZE ? buffer_size : SECTOR_SIZE,
                         VIRTIO_BLK_T_IN, completion, context, token, 0);
}

xaios_status_t virtio_block_submit_write_h(
    virtio_block_handle_t *handle, uint64_t sector, const void *buffer,
    uint64_t buffer_size, virtio_block_completion_t completion, void *context,
    uint64_t *token) {
  return submit_sector_h(handle, sector, (void *)(uintptr_t)buffer,
                         buffer_size < SECTOR_SIZE ? buffer_size : SECTOR_SIZE,
                         VIRTIO_BLK_T_OUT, completion, context, token, 0);
}

xaios_status_t virtio_block_flush_h(virtio_block_handle_t *handle) {
  return flush_h(handle);
}

uint64_t virtio_block_capacity_sectors_h(virtio_block_handle_t *handle) {
  if (handle == 0 || handle->initialized == 0) {
    return 0;
  }
  return handle->capacity_sectors;
}

xaios_block_device_t *virtio_block_device_h(virtio_block_handle_t *handle) {
  if (handle == 0 || handle->initialized == 0U ||
      handle->block_registered == 0U) {
    return 0;
  }
  return &handle->block_device;
}

void virtio_block_close(virtio_block_handle_t *handle) {
  if (handle != 0 && handle->initialized != 0) {
    (void)wait_idle(handle);
    if (handle->block_registered != 0U &&
        block_device_unregister(&handle->block_device) == XAIOS_OK) {
      handle->block_registered = 0U;
    }
    if (handle->memory_backed == 0U) {
      (void)virtio_transport_unregister_interrupt(
          &handle->device, virtio_block_interrupt, handle);
      virtio_transport_reset(&handle->device);
    }
    handle->initialized = 0;
  }
}
