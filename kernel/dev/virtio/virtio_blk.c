#include <xaios/arch_cpu.h>
#include <xaios/assert.h>
#include <xaios/block_device.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/spinlock.h>
#include <xaios/timer.h>
#include <xaios/virtio_blk.h>
#include <xaios/virtio_transport.h>
#include <xaios/vmm.h>

#include "virtio_blk_internal.h"


/* Device bring-up for the virtio block driver.
 *
 * Split three ways so no source file exceeds 500 lines. This file keeps
 * the driver state, feature negotiation, the queue and geometry bring-up,
 * the interrupt entry point, device registration and the block-device
 * entry points the kernel calls. The request engine lives in
 * virtio_blk_request.c, the block backend and power-on self-test in
 * virtio_blk_backend.c, and the handle lifecycle in virtio_blk_handles.c;
 * all four share the layout, the macros and the cross-file helpers through
 * virtio_blk_internal.h.
 */

static virtio_block_driver_t *g_blk;
static volatile uint32_t g_interrupt_canary_complete = 1U;
static xaios_status_t g_interrupt_canary_status;
static uint64_t g_interrupt_canary_baseline;
static uint8_t *g_boot_memory_base;
static uint64_t g_boot_memory_size;

/* Handles in virtio_blk_handles.c reach the primary device through this
   copied-out pointer; `g_blk' stays private to this file. */
virtio_block_driver_t *virtio_blk_primary_driver(void) { return g_blk; }

uint64_t read_capacity(const virtio_mmio_device_t *device) {
  uint32_t low = virtio_mmio_read32(device->base, VIRTIO_MMIO_CONFIG);
  uint32_t high = virtio_mmio_read32(device->base, VIRTIO_MMIO_CONFIG + 4U);
  return ((uint64_t)high << 32U) | low;
}

static int multiply_u64(uint64_t left, uint64_t right, uint64_t *result) {
  if (result == 0 || (left != 0U && right > UINT64_MAX / left)) return 0;
  *result = left * right;
  return 1;
}

static uint32_t physical_slot(const virtio_mmio_device_t *device) {
  return virtio_transport_slot(device);
}

static void set_device_identifier(char *identifier, uint64_t capacity,
                                  uint32_t slot) {
  static const char prefix[] = "/dev/vblk";
  uint64_t offset = 0U;
  while (prefix[offset] != '\0' && offset + 1U < capacity) {
    identifier[offset] = prefix[offset];
    ++offset;
  }
  char digits[10];
  uint32_t count = 0U;
  do {
    digits[count++] = (char)('0' + (slot % 10U));
    slot /= 10U;
  } while (slot != 0U && count < sizeof(digits));
  while (count != 0U && offset + 1U < capacity) {
    identifier[offset++] = digits[--count];
  }
  identifier[offset] = '\0';
}

static xaios_status_t allocate_driver(void) {
  if (g_blk != 0) {
    return XAIOS_OK;
  }

  g_blk = (virtio_block_driver_t *)kheap_calloc(sizeof(*g_blk), 16);
  if (g_blk == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }
  g_blk->desc = (virtq_desc_t *)kheap_calloc(
      sizeof(virtq_desc_t) * VIRTQ_SIZE, DMA_ALIGNMENT);
  g_blk->avail = (virtq_avail_t *)kheap_calloc(
      sizeof(virtq_avail_t), DMA_ALIGNMENT);
  g_blk->used = (virtq_used_t *)kheap_calloc(
      sizeof(virtq_used_t), DMA_ALIGNMENT);
  g_blk->request = (virtio_blk_req_t *)kheap_calloc(
      sizeof(virtio_blk_req_t), DMA_ALIGNMENT);
  g_blk->dma_sector =
      (uint8_t *)kheap_calloc(SECTOR_SIZE, DMA_ALIGNMENT);
  g_blk->status = (uint8_t *)kheap_calloc(1, DMA_ALIGNMENT);
  if (g_blk->desc == 0 || g_blk->avail == 0 || g_blk->used == 0 ||
      g_blk->request == 0 || g_blk->dma_sector == 0 || g_blk->status == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }
  for (uint32_t i = 0U; i < VIRTIO_BLK_MAX_ASYNC_DEPTH; ++i) {
    g_blk->async_slots[i] = (virtio_blk_async_slot_t *)kheap_calloc(
        sizeof(virtio_blk_async_slot_t), DMA_ALIGNMENT);
    if (g_blk->async_slots[i] == 0) return XAIOS_ERR_NO_MEMORY;
  }
  xaios_spin_init(&g_blk->queue_lock);
  return XAIOS_OK;
}

xaios_status_t configure_queue(virtio_block_driver_t *drv) {
  uint32_t accepted_low = 0U;
  uint32_t accepted_high = 0U;
  if (virtio_transport_negotiate_features(
          &drv->device,
          VIRTIO_BLK_F_RO | VIRTIO_BLK_F_BLK_SIZE | VIRTIO_BLK_F_FLUSH |
              VIRTIO_BLK_F_TOPOLOGY | VIRTIO_BLK_F_DISCARD |
              VIRTIO_BLK_F_WRITE_ZEROES | VIRTIO_F_RING_INDIRECT_DESC,
          VIRTIO_F_VERSION_1_HIGH,
          &accepted_low, &accepted_high) != XAIOS_OK ||
      (accepted_high & VIRTIO_F_VERSION_1_HIGH) == 0U) {
    return XAIOS_ERR_IO;
  }
  drv->accepted_features = accepted_low;
  drv->read_only = (accepted_low & VIRTIO_BLK_F_RO) != 0U;
  drv->supports_flush = (accepted_low & VIRTIO_BLK_F_FLUSH) != 0U;
  drv->supports_discard = (accepted_low & VIRTIO_BLK_F_DISCARD) != 0U;
  drv->supports_write_zeroes =
      (accepted_low & VIRTIO_BLK_F_WRITE_ZEROES) != 0U;
  drv->uses_indirect =
      (accepted_low & VIRTIO_F_RING_INDIRECT_DESC) != 0U;
  drv->uses_event_idx =
      (accepted_low & VIRTIO_F_RING_EVENT_IDX) != 0U;
  drv->queue_depth = drv->uses_indirect != 0U ? VIRTIO_BLK_MAX_ASYNC_DEPTH
                                               : VIRTIO_BLK_DIRECT_DEPTH;

  virtio_blk_bytes_zero(drv->desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  virtio_blk_bytes_zero(drv->avail, sizeof(*drv->avail));
  virtio_blk_bytes_zero(drv->used, sizeof(*drv->used));
  if (virtio_transport_setup_queue(&drv->device, 0, VIRTQ_SIZE, drv->desc,
                                   drv->avail, drv->used) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }

  drv->next_avail = 0;
  drv->used_last = 0U;
  if (drv->uses_event_idx != 0U) drv->avail->used_event = 0U;
  drv->outstanding = 0U;
  drv->special_active = 0U;
  for (uint32_t i = 0U; i < VIRTIO_BLK_MAX_ASYNC_DEPTH; ++i) {
    if (drv->async_slots[i] != 0) drv->async_slots[i]->active = 0U;
  }
  return virtio_transport_set_driver_ok_checked(&drv->device);
}

xaios_status_t read_device_geometry(virtio_block_driver_t *drv) {
  drv->logical_sector_size = SECTOR_SIZE;
  if ((drv->accepted_features & VIRTIO_BLK_F_BLK_SIZE) != 0U) {
    drv->logical_sector_size =
        virtio_mmio_read32(drv->device.base, VIRTIO_MMIO_CONFIG +
                                                VIRTIO_BLK_CONFIG_BLK_SIZE);
  }
  if (drv->logical_sector_size < SECTOR_SIZE ||
      drv->logical_sector_size % SECTOR_SIZE != 0U ||
      (drv->logical_sector_size & (drv->logical_sector_size - 1U)) != 0U) {
    klog("virtio-blk: unusable logical sector size %lu\n",
         drv->logical_sector_size);
    return XAIOS_ERR_INVALID;
  }
  drv->physical_block_size = drv->logical_sector_size;
  if ((drv->accepted_features & VIRTIO_BLK_F_TOPOLOGY) != 0U) {
    uint8_t exponent = virtio_mmio_read8(
        drv->device.base,
        VIRTIO_MMIO_CONFIG + VIRTIO_BLK_CONFIG_PHYSICAL_BLOCK_EXP);
    if (exponent >= 64U ||
        drv->logical_sector_size > (UINT64_MAX >> exponent)) {
      klog("virtio-blk: unusable physical block exponent %u\n",
           (unsigned)exponent);
      return XAIOS_ERR_INVALID;
    }
    drv->physical_block_size = drv->logical_sector_size << exponent;
  }
  if (drv->supports_discard != 0U) {
    drv->max_discard_sectors = virtio_mmio_read32(
        drv->device.base,
        VIRTIO_MMIO_CONFIG + VIRTIO_BLK_CONFIG_MAX_DISCARD_SECTORS);
    drv->max_discard_ranges = virtio_mmio_read32(
        drv->device.base,
        VIRTIO_MMIO_CONFIG + VIRTIO_BLK_CONFIG_MAX_DISCARD_SEG);
    drv->discard_sector_alignment = virtio_mmio_read32(
        drv->device.base,
        VIRTIO_MMIO_CONFIG + VIRTIO_BLK_CONFIG_DISCARD_ALIGNMENT);
    if (drv->max_discard_sectors == 0U || drv->max_discard_ranges == 0U) {
      drv->supports_discard = 0U;
    }
  }
  if (drv->supports_write_zeroes != 0U) {
    drv->max_write_zeroes_sectors = virtio_mmio_read32(
        drv->device.base,
        VIRTIO_MMIO_CONFIG + VIRTIO_BLK_CONFIG_MAX_WRITE_ZEROES_SECTORS);
    if (drv->max_write_zeroes_sectors == 0U) {
      drv->supports_write_zeroes = 0U;
    }
  }
  return XAIOS_OK;
}

void virtio_block_interrupt(uint32_t intid, void *context) {
  virtio_block_driver_t *drv = (virtio_block_driver_t *)context;
  (void)intid;
  if (drv == 0 || drv->initialized == 0U) return;
  ++drv->interrupt_count;
  (void)virtio_block_poll_h(drv);
  virtio_transport_ack_interrupts(&drv->device);
}

uint32_t virtio_block_outstanding_h(const virtio_block_handle_t *handle) {
  return handle == 0 ? 0U : handle->outstanding;
}

void virtio_block_suspend_completions_h(virtio_block_handle_t *handle,
                                        uint32_t suspended) {
  if (handle == 0) return;
  handle->completions_suspended = suspended != 0U ? 1U : 0U;
}

void virtio_block_report_transfers(void) {
  if (g_blk == 0) return;
  klog("virtio-blk: transfers direct=%lu bounced=%lu\n",
       g_blk->direct_transfers, g_blk->bounce_transfers);
}

uint32_t virtio_block_queue_depth_h(const virtio_block_handle_t *handle) {
  return handle == 0 ? 0U : handle->queue_depth;
}

uint64_t virtio_block_interrupt_count_h(const virtio_block_handle_t *handle) {
  return handle == 0 ? 0U : handle->interrupt_count;
}

static void interrupt_canary_completion(uint64_t token,
                                        xaios_status_t status,
                                        void *context) {
  (void)token;
  (void)context;
  g_interrupt_canary_status = status;
  __atomic_store_n(&g_interrupt_canary_complete, 1U, __ATOMIC_RELEASE);
}

xaios_status_t register_block_device(virtio_block_driver_t *drv) {
  if (drv->block_registered != 0U) return XAIOS_OK;
  uint64_t capacity_bytes = 0U;
  if (!multiply_u64(drv->capacity_sectors, SECTOR_SIZE, &capacity_bytes) ||
      capacity_bytes == 0U ||
      capacity_bytes % drv->logical_sector_size != 0U) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t slot = drv->memory_backed != 0U ? 0U : physical_slot(&drv->device);
  if (slot == UINT32_MAX) return XAIOS_ERR_INVALID;
  xaios_block_device_info_t info;
  virtio_blk_bytes_zero(&info, sizeof(info));
  set_device_identifier(info.identifier, sizeof(info.identifier), slot);
  if (drv->memory_backed != 0U) {
    static const char backend[] = "boot-memory";
    virtio_blk_bytes_copy(info.backend, backend, sizeof(backend));
  } else {
    static const char backend[] = "virtio-blk";
    virtio_blk_bytes_copy(info.backend, backend, sizeof(backend));
  }
  info.capacity_bytes = capacity_bytes;
  info.capacity_logical_sectors = capacity_bytes / drv->logical_sector_size;
  info.logical_sector_size = drv->logical_sector_size;
  info.physical_block_size = drv->physical_block_size;
  /* What the block layer may hand down in one call. It used to be one sector,
     which meant a four-megabyte read was eight thousand round trips and ran at
     seven megabytes a second. The driver splits anything larger itself and
     falls back to a sector when the memory is not contiguous, so this is a
     preference rather than a promise. */
  info.max_transfer_bytes = VIRTIO_BLK_MAX_TRANSFER;
  info.read_only = drv->read_only;
  info.flush_supported = drv->supports_flush;
  info.discard_supported = drv->supports_discard;
  info.write_zeroes_supported = drv->supports_write_zeroes;
  if (drv->supports_discard != 0U) {
    info.discard_granularity = drv->logical_sector_size;
    uint64_t alignment =
        (uint64_t)drv->discard_sector_alignment * SECTOR_SIZE;
    info.discard_alignment = alignment % info.discard_granularity;
    info.max_discard_bytes =
        ((uint64_t)drv->max_discard_sectors * SECTOR_SIZE /
         info.discard_granularity) *
        info.discard_granularity;
    info.max_discard_ranges = drv->max_discard_ranges;
    if (info.max_discard_bytes == 0U) info.discard_supported = 0U;
  }
  if (drv->supports_write_zeroes != 0U) {
    info.max_write_zeroes_bytes =
        ((uint64_t)drv->max_write_zeroes_sectors * SECTOR_SIZE /
         info.logical_sector_size) *
        info.logical_sector_size;
    if (info.max_write_zeroes_bytes == 0U) {
      info.write_zeroes_supported = 0U;
    }
  }
  xaios_status_t status = block_device_register(
      &drv->block_device, &info, &k_virtio_blk_backend_ops, drv);
  if (status == XAIOS_OK) drv->block_registered = 1U;
  return status;
}

xaios_status_t virtio_block_init(void) {
  if (allocate_driver() != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }
  if (g_boot_memory_base != 0 && g_boot_memory_size != 0U) {
    g_blk->memory_backed = 1U;
    g_blk->memory_base = g_boot_memory_base;
    g_blk->memory_size = g_boot_memory_size;
    g_blk->capacity_sectors = g_boot_memory_size / SECTOR_SIZE;
    g_blk->logical_sector_size = SECTOR_SIZE;
    g_blk->physical_block_size = SECTOR_SIZE;
    g_blk->queue_depth = 1U;
    g_blk->read_only = 1U;
    g_blk->supports_flush = 1U;
    g_blk->initialized = 1U;
    if (register_block_device(g_blk) != XAIOS_OK) {
      g_blk->initialized = 0U;
      return XAIOS_ERR_INVALID;
    }
    klog("boot-memory: capacity_sectors=%lu source=uefi-initfs\n",
         g_blk->capacity_sectors);
    return XAIOS_OK;
  }
  /* The QEMU runner pins the deterministic test disk to MMIO slot 0. The
   * boot FAT image is a PCI device and is not visible to this transport. */
  if (virtio_transport_find(VIRTIO_DEVICE_BLOCK, "virtio-blk",
                            &g_blk->device) != XAIOS_OK) {
    return XAIOS_ERR_NOT_FOUND;
  }
  if (configure_queue(g_blk) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }

  g_blk->capacity_sectors = read_capacity(&g_blk->device);
  if (read_device_geometry(g_blk) != XAIOS_OK) return XAIOS_ERR_INVALID;
  g_blk->initialized = 1;
  /* Completion is polled through the used ring on every submission path, so
     a transport with no message-signalled interrupt still serves requests.
     Losing a whole volume over a missing notification would leave the
     machine without persistent storage for no reason. */
  if (virtio_transport_register_interrupt(
          &g_blk->device, virtio_block_interrupt, g_blk) != XAIOS_OK) {
    klog("virtio-blk: no interrupt available; completions are polled\n");
  }
  if (register_block_device(g_blk) != XAIOS_OK) {
    g_blk->initialized = 0U;
    return XAIOS_ERR_INVALID;
  }
  /* This device now belongs to a driver, and the registry has to say so.
   *
   * It did not, and B-121 is what that cost. The storage-administration
   * window's scan takes "the first block device nothing else has taken", and
   * the disk the machine had just booted from did not look taken, so the
   * window opened it: `start_handle` re-negotiates the features, which resets
   * the device and clears its queue, and then programs *its own* rings into it.
   * The machine's own handle is left writing to rings the device no longer
   * reads -- every later request from it, including the flush a reboot depends
   * on, times out -- and on an installed machine the disk seized that way is
   * the one holding the running filesystem. */
  block_device_note_taken(&g_blk->device);
  klog("virtio-blk: capacity_sectors=%lu\n", g_blk->capacity_sectors);
  return XAIOS_OK;
}

xaios_status_t virtio_block_set_boot_memory(void *base, uint64_t size) {
  if (g_blk != 0 || base == 0 || size < SECTOR_SIZE * UINT64_C(4) ||
      size % SECTOR_SIZE != 0U ||
      (uint64_t)(uintptr_t)base > UINT64_MAX - size) {
    return XAIOS_ERR_INVALID;
  }
  g_boot_memory_base = (uint8_t *)base;
  g_boot_memory_size = size;
  return XAIOS_OK;
}

uint64_t virtio_block_capacity_sectors(void) {
  if (g_blk == 0 || g_blk->initialized == 0) {
    return 0;
  }
  return g_blk->capacity_sectors;
}

uint64_t virtio_block_interrupt_count(void) {
  return g_blk == 0 ? 0U : g_blk->interrupt_count;
}

uint32_t virtio_block_is_read_only(void) {
  return g_blk != 0 && g_blk->initialized != 0U && g_blk->read_only != 0U;
}

/* Whether the block device is a real virtio device or a region of memory the
   loader handed over. The interrupt canary asks a device to complete a request
   and raise an interrupt; there is nothing to ask when the "device" is memory,
   so callers have to be able to tell the difference rather than assert. */
uint32_t virtio_block_is_memory_backed(void) {
  return g_blk != 0 && g_blk->memory_backed != 0U ? 1U : 0U;
}

xaios_status_t virtio_block_interrupt_canary_arm(uint64_t sector,
                                                 void *buffer,
                                                 uint64_t buffer_size) {
  uint64_t token = 0U;
  if (g_blk == 0 || g_blk->initialized == 0U || g_blk->memory_backed != 0U ||
      buffer == 0 || buffer_size < SECTOR_SIZE ||
      __atomic_load_n(&g_interrupt_canary_complete, __ATOMIC_ACQUIRE) == 0U)
    return XAIOS_ERR_INVALID;
  if (virtio_blk_recover_queue(g_blk) != XAIOS_OK) return XAIOS_ERR_IO;
  g_interrupt_canary_baseline = g_blk->interrupt_count;
  g_interrupt_canary_status = XAIOS_ERR_IO;
  __atomic_store_n(&g_interrupt_canary_complete, 0U, __ATOMIC_RELEASE);
  xaios_status_t status = submit_sector_h(
      g_blk, sector, buffer, buffer_size, VIRTIO_BLK_T_IN,
      interrupt_canary_completion, 0, &token, 0);
  if (status != XAIOS_OK)
    __atomic_store_n(&g_interrupt_canary_complete, 1U, __ATOMIC_RELEASE);
  (void)token;
  return status;
}

xaios_status_t virtio_block_interrupt_canary_wait(uint64_t timeout_ns) {
  uint64_t started = timer_now_ns();
  if (g_blk == 0 || timeout_ns == 0U ||
      __atomic_load_n(&g_interrupt_canary_complete, __ATOMIC_ACQUIRE) != 0U)
    return XAIOS_ERR_INVALID;
  while (__atomic_load_n(&g_interrupt_canary_complete,
                         __ATOMIC_ACQUIRE) == 0U) {
    if (timer_now_ns() - started >= timeout_ns) {
      (void)virtio_blk_recover_queue(g_blk);
      return XAIOS_ERR_IO;
    }
    xaios_cpu_relax();
  }
  if (g_interrupt_canary_status != XAIOS_OK ||
      g_blk->interrupt_count <= g_interrupt_canary_baseline)
    return XAIOS_ERR_IO;
  return XAIOS_OK;
}
