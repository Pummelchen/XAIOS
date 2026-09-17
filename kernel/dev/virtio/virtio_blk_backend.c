/* Block-layer backend and power-on self-test for the virtio block driver.
 *
 * Split out of virtio_blk.c so no source file exceeds 500 lines. What lives
 * here is everything the block device registry reaches through
 * xaios_block_backend_ops_t -- the read/write span walker that keeps the queue
 * full, the flush and range commands that use the special descriptor slot, and
 * the ops table itself -- plus the read/write/error/reset self-test that
 * drives them. Device bring-up and the request engine stay in virtio_blk.c and
 * virtio_blk_request.c; the driver layout, the macros and the helpers that
 * cross a file boundary are in virtio_blk_internal.h.
 *
 * The ops table is non-static because register_block_device() in virtio_blk.c
 * passes it to the registry, so the backend entry points behind it stay
 * private to this file.
 */

#include <xaios/assert.h>
#include <xaios/block_device.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/spinlock.h>
#include <xaios/virtio_blk.h>
#include <xaios/virtio_transport.h>

#include "virtio_blk_internal.h"

xaios_status_t flush_h(virtio_block_driver_t *drv) {
  if (drv == 0 || drv->initialized == 0 || drv->supports_flush == 0U) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  virtio_blk_io_trace(drv, "flush", 0U, 0U);
  if (drv->memory_backed != 0U) return XAIOS_OK;
  if (wait_idle(drv) != XAIOS_OK) return XAIOS_ERR_BUSY;
  xaios_spin_lock(&drv->queue_lock);
  if (drv->special_active != 0U || drv->outstanding != 0U) {
    xaios_spin_unlock(&drv->queue_lock);
    return XAIOS_ERR_BUSY;
  }
  drv->special_active = 1U;
  virtio_blk_bytes_zero(drv->desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  *drv->status = 0xffU;
  drv->request->type = VIRTIO_BLK_T_FLUSH;
  drv->request->reserved = 0U;
  drv->request->sector = 0U;
  drv->desc[0].addr = virtio_blk_dma_address(drv->request);
  drv->desc[0].len = sizeof(*drv->request);
  drv->desc[0].flags = VRING_DESC_F_NEXT;
  drv->desc[0].next = 1U;
  drv->desc[1].addr = virtio_blk_dma_address(drv->status);
  drv->desc[1].len = 1U;
  drv->desc[1].flags = VRING_DESC_F_WRITE;
  drv->desc[1].next = 0U;
  uint16_t used_target = (uint16_t)(drv->used->idx + 1U);
  drv->avail->ring[drv->next_avail % VIRTQ_SIZE] = 0U;
  virtio_mmio_barrier();
  ++drv->next_avail;
  drv->avail->idx = drv->next_avail;
  xaios_spin_unlock(&drv->queue_lock);
  virtio_transport_notify(&drv->device, 0U);
  if (virtio_transport_wait_used_notifying(&drv->device, 0U, &drv->used->idx, used_target) != XAIOS_OK) {
    /* The device and its state, not just the ring indices: B-121's flush
       timeouts arrived from two devices at once, and nothing in this line said
       which devices they were or whether the device was still alive. */
    klog("virtio-blk: flush completion timeout device=%s base=0x%lx "
         "backend=%u slot=%u capacity=%lu read_only=%u flush_ok=%u "
         "avail=%u used=%u target=%u next_avail=%u used_last=%u special=%u "
         "outstanding=%u device_status=0x%x\n",
         drv->device.name != 0 ? drv->device.name : "?",
         (unsigned long)drv->device.base, (unsigned)drv->device.backend,
         (unsigned)drv->device.transport_slot,
         (unsigned long)drv->capacity_sectors, (unsigned)drv->read_only,
         (unsigned)drv->supports_flush, (unsigned)drv->avail->idx,
         (unsigned)drv->used->idx, (unsigned)used_target,
         (unsigned)drv->next_avail, (unsigned)drv->used_last,
         (unsigned)drv->special_active, (unsigned)drv->outstanding,
         (unsigned)virtio_transport_device_status(&drv->device));
    (void)virtio_blk_recover_queue(drv);
    return XAIOS_ERR_IO;
  }
  xaios_spin_lock(&drv->queue_lock);
  drv->used_last = used_target;
  drv->special_active = 0U;
  xaios_spin_unlock(&drv->queue_lock);
  virtio_transport_ack_interrupts(&drv->device);
  if (*drv->status == 2U) return XAIOS_ERR_UNSUPPORTED;
  if (*drv->status != 0U) {
    klog("virtio-blk: flush device error status=%u\n", *drv->status);
    return XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}

static xaios_status_t range_command_h(virtio_block_driver_t *drv,
                                      uint32_t type, uint64_t sector,
                                      uint32_t sector_count) {
  if (drv == 0 || drv->initialized == 0U || sector_count == 0U ||
      (type != VIRTIO_BLK_T_DISCARD &&
       type != VIRTIO_BLK_T_WRITE_ZEROES)) {
    return XAIOS_ERR_INVALID;
  }
  if ((type == VIRTIO_BLK_T_DISCARD && drv->supports_discard == 0U) ||
      (type == VIRTIO_BLK_T_WRITE_ZEROES &&
       drv->supports_write_zeroes == 0U)) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  if (sector >= drv->capacity_sectors ||
      sector_count > drv->capacity_sectors - sector) {
    return XAIOS_ERR_INVALID;
  }
  if (wait_idle(drv) != XAIOS_OK) return XAIOS_ERR_BUSY;
  xaios_spin_lock(&drv->queue_lock);
  if (drv->special_active != 0U || drv->outstanding != 0U) {
    xaios_spin_unlock(&drv->queue_lock);
    return XAIOS_ERR_BUSY;
  }
  drv->special_active = 1U;
  virtio_blk_bytes_zero(drv->desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  virtio_blk_bytes_zero(drv->dma_sector, SECTOR_SIZE);
  *drv->status = 0xffU;
  drv->request->type = type;
  drv->request->reserved = 0U;
  drv->request->sector = 0U;
  virtio_blk_range_t *range = (virtio_blk_range_t *)(void *)drv->dma_sector;
  range->sector = sector;
  range->num_sectors = sector_count;
  range->flags = 0U;
  drv->desc[0].addr = virtio_blk_dma_address(drv->request);
  drv->desc[0].len = sizeof(*drv->request);
  drv->desc[0].flags = VRING_DESC_F_NEXT;
  drv->desc[0].next = 1U;
  drv->desc[1].addr = virtio_blk_dma_address(range);
  drv->desc[1].len = sizeof(*range);
  drv->desc[1].flags = VRING_DESC_F_NEXT;
  drv->desc[1].next = 2U;
  drv->desc[2].addr = virtio_blk_dma_address(drv->status);
  drv->desc[2].len = 1U;
  drv->desc[2].flags = VRING_DESC_F_WRITE;
  drv->desc[2].next = 0U;
  uint16_t used_target = (uint16_t)(drv->used->idx + 1U);
  drv->avail->ring[drv->next_avail % VIRTQ_SIZE] = 0U;
  virtio_mmio_barrier();
  ++drv->next_avail;
  drv->avail->idx = drv->next_avail;
  xaios_spin_unlock(&drv->queue_lock);
  virtio_transport_notify(&drv->device, 0U);
  if (virtio_transport_wait_used_notifying(&drv->device, 0U, &drv->used->idx, used_target) != XAIOS_OK) {
    klog("virtio-blk: range completion timeout device=%s type=%u sector=%lu "
         "count=%u next_avail=%u used_last=%u outstanding=%u "
         "device_status=0x%x\n",
         drv->device.name != 0 ? drv->device.name : "?", (unsigned)type,
         (unsigned long)sector, (unsigned)sector_count,
         (unsigned)drv->next_avail, (unsigned)drv->used_last,
         (unsigned)drv->outstanding,
         (unsigned)virtio_transport_device_status(&drv->device));
    (void)virtio_blk_recover_queue(drv);
    return XAIOS_ERR_IO;
  }
  xaios_spin_lock(&drv->queue_lock);
  drv->used_last = used_target;
  drv->special_active = 0U;
  xaios_spin_unlock(&drv->queue_lock);
  virtio_transport_ack_interrupts(&drv->device);
  if (*drv->status == 2U) return XAIOS_ERR_UNSUPPORTED;
  if (*drv->status != 0U) {
    klog("virtio-blk: range device error type=%u status=%u\n", type,
         *drv->status);
    return XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}

/* Move a span in as few requests as the device and the memory allow.
 *
 * Each submission takes whatever remains, up to the driver's ceiling; the
 * driver clamps to what is physically contiguous and reports back how much it
 * actually took, so a run of pages that stops being contiguous costs one
 * short request rather than a wrong one. Requests are issued up to the queue
 * depth before waiting, which is what turns latency into throughput. */
static xaios_status_t backend_transfer(virtio_block_driver_t *drv,
                                       uint64_t byte_offset, void *buffer,
                                       uint64_t length, uint32_t type) {
  uint8_t *bytes = (uint8_t *)buffer;
  uint64_t completed = 0U;
  while (completed < length) {
    virtio_block_sync_wait_t waits[VIRTIO_BLK_MAX_ASYNC_DEPTH];
    uint64_t issued[VIRTIO_BLK_MAX_ASYNC_DEPTH];
    uint32_t submitted = 0U;
    uint64_t batch = 0U;
    while (submitted < drv->queue_depth && completed + batch < length) {
      uint64_t remaining = length - (completed + batch);
      waits[submitted].complete = 0U;
      waits[submitted].status = XAIOS_ERR_IO;
      uint64_t token = 0U;
      uint64_t moved = 0U;
      xaios_status_t status = submit_sector_h(
          drv, (byte_offset + completed + batch) / SECTOR_SIZE,
          bytes + completed + batch, remaining, type, sync_completion,
          &waits[submitted], &token, &moved);
      if (status == XAIOS_ERR_BUSY) {
        /* No free queue slot, or the driver is in the middle of a special
           request. If this batch already has work in flight, stop filling it
           and go wait -- draining is what frees a slot. If it has nothing in
           flight there is nothing to wait for, so poll the queue and try
           again, which is what the single-sector path has always done. */
        if (submitted != 0U) break;
        (void)virtio_block_poll_h(drv);
        continue;
      }
      if (status != XAIOS_OK) {
        for (uint32_t i = 0U; i < submitted; ++i) {
          (void)wait_sync(drv, &waits[i]);
        }
        return status;
      }
      issued[submitted] = moved;
      batch += moved;
      ++submitted;
    }
    if (submitted == 0U) return XAIOS_ERR_IO;
    for (uint32_t i = 0U; i < submitted; ++i) {
      xaios_status_t status = wait_sync(drv, &waits[i]);
      if (status != XAIOS_OK) {
        for (uint32_t j = i + 1U; j < submitted; ++j) {
          (void)wait_sync(drv, &waits[j]);
        }
        return status;
      }
    }
    for (uint32_t i = 0U; i < submitted; ++i) completed += issued[i];
  }
  return XAIOS_OK;
}

static xaios_status_t block_backend_read(void *context, uint64_t byte_offset,
                                         void *buffer, uint64_t length) {
  virtio_block_driver_t *drv = (virtio_block_driver_t *)context;
  if (byte_offset % SECTOR_SIZE != 0U || length % SECTOR_SIZE != 0U) {
    return XAIOS_ERR_INVALID;
  }
  return backend_transfer(drv, byte_offset, buffer, length, VIRTIO_BLK_T_IN);
}

static xaios_status_t block_backend_write(void *context, uint64_t byte_offset,
                                          const void *buffer,
                                          uint64_t length) {
  virtio_block_driver_t *drv = (virtio_block_driver_t *)context;
  if (byte_offset % SECTOR_SIZE != 0U || length % SECTOR_SIZE != 0U) {
    return XAIOS_ERR_INVALID;
  }
  /* The device does not write through this pointer; the const is the block
     layer's promise to the caller, not a property of the buffer. */
  return backend_transfer(drv, byte_offset, (void *)(uintptr_t)buffer, length,
                          VIRTIO_BLK_T_OUT);
}

static xaios_status_t block_backend_flush(void *context) {
  return flush_h((virtio_block_driver_t *)context);
}

static xaios_status_t block_backend_discard(void *context,
                                            uint64_t byte_offset,
                                            uint64_t length) {
  if (byte_offset % SECTOR_SIZE != 0U || length % SECTOR_SIZE != 0U ||
      length / SECTOR_SIZE > UINT32_MAX) {
    return XAIOS_ERR_INVALID;
  }
  return range_command_h((virtio_block_driver_t *)context,
                         VIRTIO_BLK_T_DISCARD,
                         byte_offset / SECTOR_SIZE,
                         (uint32_t)(length / SECTOR_SIZE));
}

static xaios_status_t block_backend_write_zeroes(void *context,
                                                 uint64_t byte_offset,
                                                 uint64_t length) {
  if (byte_offset % SECTOR_SIZE != 0U || length % SECTOR_SIZE != 0U ||
      length / SECTOR_SIZE > UINT32_MAX) {
    return XAIOS_ERR_INVALID;
  }
  return range_command_h((virtio_block_driver_t *)context,
                         VIRTIO_BLK_T_WRITE_ZEROES,
                         byte_offset / SECTOR_SIZE,
                         (uint32_t)(length / SECTOR_SIZE));
}

/* Declared in virtio_blk_internal.h; virtio_blk.c hands it to the block
   device registry from register_block_device(). */
const xaios_block_backend_ops_t k_virtio_blk_backend_ops = {
    block_backend_read, block_backend_write, block_backend_flush,
    block_backend_discard, block_backend_write_zeroes};

void virtio_block_self_test(void) {
  uint8_t *sector = (uint8_t *)kheap_calloc(DMA_ALIGNMENT, 16);
  uint8_t *write_sector = (uint8_t *)kheap_calloc(SECTOR_SIZE, 16);
  uint8_t *original_sector = (uint8_t *)kheap_calloc(SECTOR_SIZE, 16);
  uint8_t *async_sectors[VIRTIO_BLK_MAX_ASYNC_DEPTH];
  kassert(sector != 0);
  kassert(write_sector != 0);
  kassert(original_sector != 0);
  for (uint32_t i = 0U; i < VIRTIO_BLK_MAX_ASYNC_DEPTH; ++i) {
    async_sectors[i] = (uint8_t *)kheap_calloc(SECTOR_SIZE, 16);
    kassert(async_sectors[i] != 0);
  }
  kassert(virtio_block_init() == XAIOS_OK);
  virtio_block_driver_t *drv = virtio_blk_primary_driver();
  kassert(virtio_block_read_sector(0, sector, SECTOR_SIZE) == XAIOS_OK);
  kassert(sector[0] == 'X');
  kassert(sector[1] == 'A');
  kassert(sector[2] == 'I');
  kassert(sector[3] == 'O');
  klog("virtio-blk: sector0 magic='%s'\n", (const char *)sector);
  kassert(virtio_block_read_sector(virtio_block_capacity_sectors(), sector,
                                   SECTOR_SIZE) == XAIOS_ERR_IO);
  for (uint64_t i = 0; i < SECTOR_SIZE; ++i) {
    write_sector[i] = (uint8_t)(i & 0xffU);
  }
  kassert(virtio_block_capacity_sectors() > VIRTIO_BLK_SELF_TEST_SECTOR);
  uint64_t write_test_sector = VIRTIO_BLK_SELF_TEST_SECTOR;
  if (drv->memory_backed != 0U) {
    kassert(virtio_block_write_sector(write_test_sector, write_sector,
                                      SECTOR_SIZE) == XAIOS_ERR_UNSUPPORTED);
    virtio_block_sync_wait_t wait = {0U, XAIOS_ERR_IO};
    uint64_t token = 0U;
    virtio_blk_bytes_zero(sector, SECTOR_SIZE);
    kassert(virtio_block_submit_read_h(
                drv, 0U, sector, SECTOR_SIZE, sync_completion, &wait,
                &token) == XAIOS_OK);
    kassert(token != 0U && wait.complete != 0U && wait.status == XAIOS_OK);
    kassert(sector[0] == 'X' && sector[1] == 'A');
    xaios_block_device_t *block = 0;
    xaios_block_device_info_t info;
    kassert(block_device_open("/dev/vblk0", &block) == XAIOS_OK);
    kassert(block_device_info(block, &info) == XAIOS_OK);
    kassert(info.capacity_bytes == drv->memory_size);
    kassert(info.read_only != 0U);
    kassert(info.flush_supported != 0U);
    kassert(block_device_close(block) == XAIOS_OK);
    klog("boot-memory: read-only/async/flush self-test passed capacity_sectors=%lu\n",
         drv->capacity_sectors);
    return;
  }
  /* A device that says it is read-only is asked to prove it refuses writes,
     and is not asked to accept one.
     
     This test wrote to the device the machine booted from. That is harmless
     where the boot medium is a writable disk image, which is every emulator
     configuration here, and it is not harmless generally: a machine booting a
     CD or a write-protected stick would panic on this assertion rather than
     skip it, and testing a release image modified the artifact under test.
     The driver has always refused writes to a read-only device; the self-test
     simply never asked whether this one was. */
  uint32_t writable = drv->read_only == 0U ? 1U : 0U;
  kassert(virtio_block_read_sector(write_test_sector, original_sector,
                                   SECTOR_SIZE) == XAIOS_OK);
  if (writable == 0U) {
    /* A device that says it is read-only is asked to prove it refuses a write,
       and is not asked to accept one. Everything below that does not depend on
       having written still runs, so the device is exercised either way. */
    kassert(virtio_block_write_sector(write_test_sector, write_sector,
                                      SECTOR_SIZE) == XAIOS_ERR_UNSUPPORTED);
  } else {
    kassert(virtio_block_write_sector(write_test_sector, write_sector,
                                      SECTOR_SIZE) == XAIOS_OK);
    kassert(virtio_block_flush() == XAIOS_OK);
    virtio_blk_bytes_zero(sector, SECTOR_SIZE);
    kassert(virtio_block_read_sector(write_test_sector, sector, SECTOR_SIZE) ==
            XAIOS_OK);
    for (uint64_t i = 0; i < SECTOR_SIZE; ++i) {
      kassert(sector[i] == (uint8_t)(i & 0xffU));
    }
  }
  kassert(drv->uses_indirect != 0U);
  kassert(virtio_block_queue_depth_h(drv) ==
          VIRTIO_BLK_MAX_ASYNC_DEPTH);
  virtio_block_sync_wait_t waits[VIRTIO_BLK_MAX_ASYNC_DEPTH];
  uint64_t tokens[VIRTIO_BLK_MAX_ASYNC_DEPTH];
  /* Nothing may drain the queue while its capacity is being measured. On a
     machine whose device completes by interrupt, requests finish during the
     loop below and the two assertions after it -- that the queue is full and
     that one more is refused -- stop being about capacity at all. */
  virtio_block_suspend_completions_h(drv, 1U);
  for (uint32_t i = 0U; i < drv->queue_depth; ++i) {
    waits[i].complete = 0U;
    waits[i].status = XAIOS_ERR_IO;
    uint64_t read_sector = i == 1U ? write_test_sector : i;
    kassert(virtio_block_submit_read_h(
                drv, read_sector, async_sectors[i], SECTOR_SIZE,
                sync_completion, &waits[i], &tokens[i]) == XAIOS_OK);
    if (i != 0U) kassert(tokens[i] != tokens[i - 1U]);
  }
  uint64_t rejected_token = 0U;
  kassert(virtio_block_outstanding_h(drv) == drv->queue_depth);
  kassert(virtio_block_submit_read_h(
              drv, 0U, sector, SECTOR_SIZE, sync_completion, &waits[0],
              &rejected_token) == XAIOS_ERR_BUSY);
  virtio_block_suspend_completions_h(drv, 0U);
  for (uint32_t i = 0U; i < drv->queue_depth; ++i) {
    kassert(wait_sync(drv, &waits[i]) == XAIOS_OK);
  }
  kassert(virtio_block_outstanding_h(drv) == 0U);
  kassert(async_sectors[0][0] == 'X' && async_sectors[0][1] == 'A');
  if (writable != 0U) {
    kassert(async_sectors[1][0] == 0U && async_sectors[1][1] == 1U);
    /* Put back what was there. Nothing was changed on a read-only device, so
       there is nothing to restore. */
    kassert(virtio_block_write_sector(write_test_sector, original_sector,
                                      SECTOR_SIZE) == XAIOS_OK);
    kassert(virtio_block_flush() == XAIOS_OK);
    virtio_blk_bytes_zero(sector, SECTOR_SIZE);
    kassert(virtio_block_read_sector(write_test_sector, sector, SECTOR_SIZE) ==
            XAIOS_OK);
    for (uint64_t i = 0U; i < SECTOR_SIZE; ++i) {
      kassert(sector[i] == original_sector[i]);
    }
  }
  klog("virtio-blk: asynchronous queue self-test passed depth=%u indirect=%u "
       "direct-or-bounce=verified direct=%lu bounced=%lu\n",
       virtio_block_queue_depth_h(drv), drv->uses_indirect,
       drv->direct_transfers, drv->bounce_transfers);
  uint64_t resets_before = drv->reset_count;
  kassert(virtio_blk_recover_queue(drv) == XAIOS_OK);
  kassert(drv->reset_count == resets_before + 1U);
  virtio_blk_bytes_zero(sector, SECTOR_SIZE);
  kassert(virtio_block_read_sector(0U, sector, SECTOR_SIZE) == XAIOS_OK);
  kassert(sector[0] == 'X' && sector[1] == 'A');
  xaios_block_device_t *block = 0;
  xaios_block_device_info_t info;
  kassert(block_device_open("/dev/vblk0", &block) == XAIOS_OK);
  kassert(block == virtio_block_device_h(drv));
  kassert(block_device_info(block, &info) == XAIOS_OK);
  kassert(info.capacity_bytes ==
          virtio_block_capacity_sectors() * SECTOR_SIZE);
  kassert(info.logical_sector_size >= SECTOR_SIZE &&
          info.logical_sector_size <= DMA_ALIGNMENT);
  virtio_blk_bytes_zero(sector, DMA_ALIGNMENT);
  kassert(block_read(block, 0U, sector, info.logical_sector_size) == XAIOS_OK);
  kassert(sector[0] == 'X' && sector[1] == 'A' && sector[2] == 'I' &&
          sector[3] == 'O');
  kassert(block_device_close(block) == XAIOS_OK);
  klog("virtio-blk: read/write/error/reset self-test passed discovery=1 ");
  klog("medium=%s ", writable != 0U ? "writable" : "read-only");
  klog("logical=%lu physical=%lu flush=%u discard=%u zeroes=%u\n",
       info.logical_sector_size, info.physical_block_size,
       info.flush_supported, info.discard_supported,
       info.write_zeroes_supported);
}
