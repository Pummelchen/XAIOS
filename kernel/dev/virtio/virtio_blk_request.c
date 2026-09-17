/* Request engine for the virtio block driver.
 *
 * Split out of virtio_blk.c so no source file exceeds 500 lines. What lives
 * here is the path every request takes once the device is up: the byte and DMA
 * helpers the ring setup needs, the optional write-ordering trace, one
 * submission filling a descriptor chain or an indirect one, completion
 * polling through the used ring, and the recovery and wait loops a caller uses
 * when a request stalls. Device bring-up, the block backend and the power-on
 * self-test stay in virtio_blk.c and virtio_blk_backend.c.
 *
 * submit_sector_h(), virtio_block_poll_h() and sync_completion() keep their
 * names because the handle code calls them; the helpers introduced by this
 * split carry the virtio_blk_ prefix. All of it is declared in
 * virtio_blk_internal.h.
 */

#include <xaios/arch_cpu.h>
#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/spinlock.h>
#include <xaios/timer.h>
#include <xaios/virtio_blk.h>
#include <xaios/virtio_transport.h>
#include <xaios/vmm.h>

#include "virtio_blk_internal.h"

void virtio_blk_bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

void virtio_blk_bytes_copy(void *dst, const void *src, uint64_t size) {
  uint8_t *out = (uint8_t *)dst;
  const uint8_t *in = (const uint8_t *)src;
  for (uint64_t i = 0; i < size; ++i) {
    out[i] = in[i];
  }
}

uint64_t virtio_blk_dma_address(const void *ptr) {
  uint64_t physical = 0;
  uint32_t flags = 0;
  kassert(vmm_translate((uint64_t)(uintptr_t)ptr, &physical, &flags) == XAIOS_OK);
  kassert((flags & XAIOS_VMM_PRESENT) != 0);
  return physical;
}

static int dma_range(const void *ptr, uint64_t length, int writable,
                     uint64_t *physical) {
  if (ptr == 0 || length == 0U || physical == 0) return 0;
  uint64_t first = 0U;
  uint64_t last = 0U;
  uint32_t first_flags = 0U;
  uint32_t last_flags = 0U;
  uint64_t start = (uint64_t)(uintptr_t)ptr;
  if (start + length < start ||
      vmm_translate(start, &first, &first_flags) != XAIOS_OK ||
      vmm_translate(start + length - 1U, &last, &last_flags) != XAIOS_OK ||
      last != first + length - 1U ||
      (first_flags & XAIOS_VMM_PRESENT) == 0U ||
      (last_flags & XAIOS_VMM_PRESENT) == 0U ||
      (writable != 0 &&
       ((first_flags & XAIOS_VMM_WRITABLE) == 0U ||
        (last_flags & XAIOS_VMM_WRITABLE) == 0U))) {
    return 0;
  }
  *physical = first;
  return 1;
}

/* A trace of what was written and when it was flushed.
 *
 * The crash gate proves that an interrupted write leaves nothing broken, and
 * it proves it against an emulator that never loses a write it has
 * acknowledged. A device with a volatile write cache does lose those, and what
 * makes xaiFS safe on one is ordering: chunk data is flushed before the
 * catalog that refers to it, and the catalog is flushed before the superblock
 * that points at it. If any of those flushes went missing, the emulator would
 * not notice and neither would any gate.
 *
 * So the driver says what it did, in order, and a gate reads the log back and
 * checks that no superblock write appears without a flush between it and the
 * catalog write before it. That is not a proof that a real disk behaves; it is
 * a proof that the ordering the proof depends on is actually being issued.
 *
 * Built only under XAIOS_IO_TRACE=1, because it is one klog line per request
 * and an ordinary boot should not pay for that. */
#if XAIOS_IO_TRACE
void virtio_blk_io_trace(virtio_block_driver_t *drv, const char *what,
                     uint64_t sector, uint64_t bytes) {
  klog("io-trace: seq=%lu op=%s sector=%lu bytes=%lu\n", ++drv->io_sequence,
       what, sector, bytes);
}
#else
void virtio_blk_io_trace(virtio_block_driver_t *drv, const char *what,
                     uint64_t sector, uint64_t bytes) {
  (void)drv;
  (void)what;
  (void)sector;
  (void)bytes;
}
#endif

/* Submit one request. `moved`, when given, receives how many bytes the request
   actually covers, which is at most buffer_size and may be less -- the device
   ceiling, the end of the disk, or memory that stops being contiguous all
   shorten it. A caller walking a large span must advance by that figure and
   not by what it asked for. */
xaios_status_t submit_sector_h(
    virtio_block_driver_t *drv, uint64_t sector, void *buffer,
    uint64_t buffer_size, uint32_t type,
    virtio_block_completion_t completion, void *context, uint64_t *token,
    uint64_t *moved) {
  if (drv == 0 || drv->initialized == 0U || buffer == 0 ||
      buffer_size < SECTOR_SIZE || completion == 0 || token == 0 ||
      sector >= drv->capacity_sectors ||
      (type != VIRTIO_BLK_T_IN && type != VIRTIO_BLK_T_OUT)) {
    return XAIOS_ERR_INVALID;
  }
  /* Refused, but not as a malformed request.
   *
   * This used to sit in the condition above and answer XAIOS_ERR_INVALID,
   * while the synchronous path a few hundred lines down answered
   * XAIOS_ERR_UNSUPPORTED for the same device and the same reason. Two
   * refusals in one driver disagreeing about what a read-only medium is: a
   * write to one is a well-formed request the device cannot perform, which is
   * what UNSUPPORTED means, and is nothing like a null buffer or a sector
   * past the end of the disk. Nothing caught the disagreement because no gate
   * had ever attached a read-only device, so neither branch had run. */
  if (type == VIRTIO_BLK_T_OUT && drv->read_only != 0U) {
    return XAIOS_ERR_UNSUPPORTED;
  }

  /* How much this request actually moves.
     
     buffer_size has always been a parameter here and was always ignored: every
     descriptor carried exactly one sector, so a four-megabyte read cost eight
     thousand round trips and ran at seven megabytes a second. The device will
     take as much as the descriptor says, and the only real constraint is that
     the memory be physically contiguous across the whole span -- which is
     checked below rather than assumed.
     
     A request that cannot go directly to the caller's memory still moves one
     sector, because the bounce buffer is one sector. That path is the
     exception now rather than the rule. */
  uint64_t transfer = buffer_size - (buffer_size % SECTOR_SIZE);
  if (transfer == 0U) return XAIOS_ERR_INVALID;
  if (transfer > VIRTIO_BLK_MAX_TRANSFER) transfer = VIRTIO_BLK_MAX_TRANSFER;
  uint64_t remaining_sectors = drv->capacity_sectors - sector;
  if (transfer / SECTOR_SIZE > remaining_sectors) {
    transfer = remaining_sectors * SECTOR_SIZE;
  }

  if (drv->memory_backed != 0U) {
    uint64_t offset = sector * SECTOR_SIZE;
    if (offset + transfer > drv->memory_size) return XAIOS_ERR_INVALID;
    if (type == VIRTIO_BLK_T_IN) {
      virtio_blk_bytes_copy(buffer, drv->memory_base + offset, transfer);
    } else {
      virtio_blk_bytes_copy(drv->memory_base + offset, buffer, transfer);
    }
    *token = ++drv->next_token;
    if (*token == 0U) *token = ++drv->next_token;
    if (moved != 0) *moved = transfer;
    completion(*token, XAIOS_OK, context);
    return XAIOS_OK;
  }

  xaios_spin_lock(&drv->queue_lock);
  if (drv->special_active != 0U) {
    xaios_spin_unlock(&drv->queue_lock);
    return XAIOS_ERR_BUSY;
  }
  uint32_t slot_index = drv->queue_depth;
  for (uint32_t i = 0U; i < drv->queue_depth; ++i) {
    if (drv->async_slots[i]->active == 0U) {
      slot_index = i;
      break;
    }
  }
  if (slot_index == drv->queue_depth) {
    xaios_spin_unlock(&drv->queue_lock);
    return XAIOS_ERR_BUSY;
  }

  virtio_blk_async_slot_t *slot = drv->async_slots[slot_index];
  uint64_t data_physical = 0U;
  int direct = dma_range(buffer, transfer, type == VIRTIO_BLK_T_IN,
                         &data_physical);
  if (direct == 0) {
    /* Not one physically contiguous span, so it cannot be handed to the
       device whole. Fall back to a single sector through the bounce buffer,
       which is what every request used to do. */
    transfer = SECTOR_SIZE;
    data_physical = virtio_blk_dma_address(slot->dma_sector);
    if (type == VIRTIO_BLK_T_OUT) {
      virtio_blk_bytes_copy(slot->dma_sector, buffer, SECTOR_SIZE);
    } else {
      virtio_blk_bytes_zero(slot->dma_sector, SECTOR_SIZE);
    }
  }
  slot->request.type = type;
  slot->request.reserved = 0U;
  slot->request.sector = sector;
  slot->status = 0xffU;
  slot->type = (uint8_t)type;
  slot->direct_dma = direct != 0 ? 1U : 0U;
  if (direct != 0) {
    ++drv->direct_transfers;
  } else {
    ++drv->bounce_transfers;
  }
  slot->transfer = transfer;
  if (moved != 0) *moved = transfer;
  if (type == VIRTIO_BLK_T_OUT) virtio_blk_io_trace(drv, "write", sector, transfer);
  slot->buffer = buffer;
  slot->completion = completion;
  slot->completion_context = context;
  slot->token = ++drv->next_token;
  if (slot->token == 0U) slot->token = ++drv->next_token;
  slot->active = 1U;

  virtq_desc_t *chain = slot->indirect;
  uint16_t head = (uint16_t)slot_index;
  if (drv->uses_indirect == 0U) {
    head = (uint16_t)(slot_index * 3U);
    chain = &drv->desc[head];
  }
  chain[0].addr = virtio_blk_dma_address(&slot->request);
  chain[0].len = sizeof(slot->request);
  chain[0].flags = VRING_DESC_F_NEXT;
  chain[0].next = drv->uses_indirect != 0U ? 1U : (uint16_t)(head + 1U);
  chain[1].addr = data_physical;
  chain[1].len = (uint32_t)transfer;
  chain[1].flags = VRING_DESC_F_NEXT;
  if (type == VIRTIO_BLK_T_IN) {
    chain[1].flags |= VRING_DESC_F_WRITE;
  }
  chain[1].next = drv->uses_indirect != 0U ? 2U : (uint16_t)(head + 2U);
  chain[2].addr = virtio_blk_dma_address(&slot->status);
  chain[2].len = 1U;
  chain[2].flags = VRING_DESC_F_WRITE;
  chain[2].next = 0U;
  if (drv->uses_indirect != 0U) {
    drv->desc[head].addr = virtio_blk_dma_address(chain);
    drv->desc[head].len = sizeof(slot->indirect);
    drv->desc[head].flags = VRING_DESC_F_INDIRECT;
    drv->desc[head].next = 0U;
  }

  drv->avail->ring[drv->next_avail % VIRTQ_SIZE] = head;
  virtio_mmio_barrier();
  ++drv->next_avail;
  drv->avail->idx = drv->next_avail;
  ++drv->outstanding;
  *token = slot->token;
  xaios_spin_unlock(&drv->queue_lock);
  virtio_transport_notify(&drv->device, 0U);
  return XAIOS_OK;
}

uint32_t virtio_block_poll_h(virtio_block_handle_t *handle) {
  virtio_block_driver_t *drv = handle;
  if (drv != 0 && drv->memory_backed != 0U) return 0U;
  if (drv == 0 || drv->initialized == 0U ||
      xaios_spin_trylock(&drv->queue_lock) == 0) {
    return 0U;
  }
  if (drv->completions_suspended != 0U) {
    xaios_spin_unlock(&drv->queue_lock);
    virtio_transport_ack_interrupts(&drv->device);
    return 0U;
  }
  uint32_t completed = 0U;
  for (;;) {
    virtio_mmio_barrier();
    uint16_t used_idx = *(volatile uint16_t *)(void *)&drv->used->idx;
    if (drv->used_last == used_idx) break;
    virtq_used_elem_t *element =
        &drv->used->ring[drv->used_last % VIRTQ_SIZE];
    uint32_t head = element->id;
    uint32_t slot_index = drv->uses_indirect != 0U ? head : head / 3U;
    if ((drv->uses_indirect != 0U && head >= drv->queue_depth) ||
        (drv->uses_indirect == 0U &&
         (head >= drv->queue_depth * 3U || head % 3U != 0U))) {
      ++drv->used_last;
      continue;
    }
    virtio_blk_async_slot_t *slot = drv->async_slots[slot_index];
    if (slot->active == 0U) {
      ++drv->used_last;
      continue;
    }
    xaios_status_t status = slot->status == 0U ? XAIOS_OK : XAIOS_ERR_IO;
    if (status == XAIOS_OK && slot->type == VIRTIO_BLK_T_IN &&
        slot->direct_dma == 0U) {
      virtio_blk_bytes_copy(slot->buffer, slot->dma_sector,
                 slot->transfer < SECTOR_SIZE ? slot->transfer : SECTOR_SIZE);
    }
    virtio_block_completion_t callback = slot->completion;
    void *callback_context = slot->completion_context;
    uint64_t callback_token = slot->token;
    slot->active = 0U;
    slot->completion = 0;
    slot->completion_context = 0;
    if (drv->outstanding != 0U) --drv->outstanding;
    ++drv->used_last;
    ++completed;
    if (drv->uses_event_idx != 0U) {
      drv->avail->used_event = drv->used_last;
    }
    xaios_spin_unlock(&drv->queue_lock);
    if (callback != 0) callback(callback_token, status, callback_context);
    if (xaios_spin_trylock(&drv->queue_lock) == 0) return completed;
  }
  xaios_spin_unlock(&drv->queue_lock);
  if (completed != 0U) virtio_transport_ack_interrupts(&drv->device);
  return completed;
}

xaios_status_t virtio_blk_recover_queue(virtio_block_driver_t *drv) {
  if (drv == 0) return XAIOS_ERR_INVALID;
  if (drv->memory_backed != 0U) {
    ++drv->reset_count;
    return XAIOS_OK;
  }
  virtio_block_completion_t callbacks[VIRTIO_BLK_MAX_ASYNC_DEPTH];
  void *contexts[VIRTIO_BLK_MAX_ASYNC_DEPTH];
  uint64_t tokens[VIRTIO_BLK_MAX_ASYNC_DEPTH];
  uint32_t callback_count = 0U;

  xaios_spin_lock(&drv->queue_lock);
  drv->initialized = 0U;
  for (uint32_t i = 0U; i < VIRTIO_BLK_MAX_ASYNC_DEPTH; ++i) {
    virtio_blk_async_slot_t *slot = drv->async_slots[i];
    if (slot != 0 && slot->active != 0U) {
      callbacks[callback_count] = slot->completion;
      contexts[callback_count] = slot->completion_context;
      tokens[callback_count] = slot->token;
      ++callback_count;
      slot->active = 0U;
      slot->completion = 0;
      slot->completion_context = 0;
    }
  }
  drv->outstanding = 0U;
  drv->special_active = 0U;
  xaios_spin_unlock(&drv->queue_lock);

  for (uint32_t i = 0U; i < callback_count; ++i) {
    if (callbacks[i] != 0) {
      callbacks[i](tokens[i], XAIOS_ERR_IO, contexts[i]);
    }
  }
  if (configure_queue(drv) != XAIOS_OK) return XAIOS_ERR_IO;
  drv->capacity_sectors = read_capacity(&drv->device);
  if (read_device_geometry(drv) != XAIOS_OK) return XAIOS_ERR_IO;
  drv->initialized = 1U;
  ++drv->reset_count;
  klog("virtio-blk: queue recovered resets=%lu failed_requests=%u depth=%u indirect=%u\n",
       drv->reset_count, callback_count, drv->queue_depth,
       drv->uses_indirect);
  return XAIOS_OK;
}

void sync_completion(uint64_t token, xaios_status_t status,
                            void *context) {
  virtio_block_sync_wait_t *wait = (virtio_block_sync_wait_t *)context;
  (void)token;
  wait->status = status;
  __atomic_store_n(&wait->complete, 1U, __ATOMIC_RELEASE);
}

xaios_status_t wait_sync(virtio_block_driver_t *drv,
                                virtio_block_sync_wait_t *wait) {
  uint64_t started = timer_now_ns();
  while (__atomic_load_n(&wait->complete, __ATOMIC_ACQUIRE) == 0U) {
    (void)virtio_block_poll_h(drv);
    if (timer_now_ns() - started >= VIRTIO_BLK_WAIT_TIMEOUT_NS) {
      (void)virtio_blk_recover_queue(drv);
      return XAIOS_ERR_IO;
    }
    xaios_cpu_relax();
  }
  return wait->status;
}

xaios_status_t wait_idle(virtio_block_driver_t *drv) {
  uint64_t started = timer_now_ns();
  while (drv->outstanding != 0U) {
    (void)virtio_block_poll_h(drv);
    if (timer_now_ns() - started >= VIRTIO_BLK_WAIT_TIMEOUT_NS) {
      (void)virtio_blk_recover_queue(drv);
      return XAIOS_ERR_IO;
    }
    xaios_cpu_relax();
  }
  return XAIOS_OK;
}
