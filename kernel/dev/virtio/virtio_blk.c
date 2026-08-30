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

#define VIRTIO_MMIO_CONFIG 0x100U
#define VRING_DESC_F_NEXT UINT16_C(1)
#define VRING_DESC_F_WRITE UINT16_C(2)
#define VRING_DESC_F_INDIRECT UINT16_C(4)
#define VIRTIO_BLK_T_IN UINT32_C(0)
#define VIRTIO_BLK_T_OUT UINT32_C(1)
#define VIRTIO_BLK_T_FLUSH UINT32_C(4)
#define VIRTIO_BLK_T_DISCARD UINT32_C(11)
#define VIRTIO_BLK_T_WRITE_ZEROES UINT32_C(13)
#define VIRTIO_BLK_F_RO (UINT32_C(1) << 5U)
#define VIRTIO_BLK_F_BLK_SIZE (UINT32_C(1) << 6U)
#define VIRTIO_BLK_F_FLUSH (UINT32_C(1) << 9U)
#define VIRTIO_BLK_F_TOPOLOGY (UINT32_C(1) << 10U)
#define VIRTIO_BLK_F_DISCARD (UINT32_C(1) << 13U)
#define VIRTIO_BLK_F_WRITE_ZEROES (UINT32_C(1) << 14U)
#define VIRTIO_F_RING_INDIRECT_DESC (UINT32_C(1) << 28U)
#define VIRTIO_F_RING_EVENT_IDX (UINT32_C(1) << 29U)
#define VIRTIO_F_VERSION_1_HIGH UINT32_C(1)
#define SECTOR_SIZE UINT64_C(512)
#define DMA_ALIGNMENT UINT64_C(4096)
#define VIRTIO_BLK_CONFIG_BLK_SIZE 20U
#define VIRTIO_BLK_CONFIG_PHYSICAL_BLOCK_EXP 24U
#define VIRTIO_BLK_CONFIG_MAX_DISCARD_SECTORS 36U
#define VIRTIO_BLK_CONFIG_MAX_DISCARD_SEG 40U
#define VIRTIO_BLK_CONFIG_DISCARD_ALIGNMENT 44U
#define VIRTIO_BLK_CONFIG_MAX_WRITE_ZEROES_SECTORS 48U
#define VIRTIO_BLK_DIRECT_DEPTH 2U
#define VIRTIO_BLK_MAX_ASYNC_DEPTH VIRTQ_SIZE
/* The largest span one request may carry.
   
   Bounded rather than unlimited: a descriptor length is 32 bits, the buffer
   has to be physically contiguous across the whole of it, and a single
   enormous request occupies a queue slot for as long as it takes. One
   mebibyte is large enough that the per-request cost stops mattering --
   4 MiB becomes four requests instead of eight thousand -- and small enough
   that several fit in the queue at once.

   Overridable at build time so the old one-sector behaviour can be rebuilt
   and measured against, which is the only way a claim about the improvement
   is checkable rather than asserted. */
#ifndef VIRTIO_BLK_MAX_TRANSFER
#define VIRTIO_BLK_MAX_TRANSFER UINT64_C(1048576)
#endif
#define VIRTIO_BLK_WAIT_TIMEOUT_NS UINT64_C(5000000000)
#define VIRTIO_BLK_SELF_TEST_SECTOR UINT64_C(2999)

typedef struct virtio_blk_req {
  uint32_t type;
  uint32_t reserved;
  uint64_t sector;
} virtio_blk_req_t;

typedef struct virtio_blk_range {
  uint64_t sector;
  uint32_t num_sectors;
  uint32_t flags;
} virtio_blk_range_t;

typedef struct virtio_blk_async_slot {
  virtq_desc_t indirect[3];
  virtio_blk_req_t request;
  uint8_t dma_sector[SECTOR_SIZE];
  uint8_t status;
  uint8_t active;
  uint8_t type;
  uint8_t direct_dma;
  uint8_t reserved;
  /* How much this request moved. The completion has to copy exactly that
     much back out of the bounce buffer, and a caller asking how far it got
     needs the real figure rather than the one it requested. */
  uint64_t transfer;
  void *buffer;
  virtio_block_completion_t completion;
  void *completion_context;
  uint64_t token;
} virtio_blk_async_slot_t;

typedef struct virtio_block_driver {
  virtio_mmio_device_t device;
  virtq_desc_t *desc;
  virtq_avail_t *avail;
  virtq_used_t *used;
  virtio_blk_req_t *request;
  uint8_t *dma_sector;
  uint8_t *status;
  uint16_t next_avail;
  uint16_t used_last;
  uint32_t outstanding;
  uint32_t special_active;
  uint32_t queue_depth;
  /* How the data actually reached the device. A direct request handed the
     caller's own memory to it; a bounce request copied a sector through the
     driver's staging buffer because the caller's memory was not one
     physically contiguous span. The second is correct and slow, and it used
     to be every request; counting both is what turns "reads land in the
     consumer's buffer" from a claim into a number. */
  uint64_t direct_transfers;
  uint64_t bounce_transfers;
  /* A monotonic count of every write and every flush this device has issued,
     used only when the write-ordering trace is built in. */
  uint64_t io_sequence;
  uint32_t uses_indirect;
  uint32_t uses_event_idx;
  uint64_t reset_count;
  uint64_t next_token;
  uint64_t interrupt_count;
  xaios_spinlock_t queue_lock;
  virtio_blk_async_slot_t *async_slots[VIRTIO_BLK_MAX_ASYNC_DEPTH];
  uint64_t capacity_sectors;
  uint64_t logical_sector_size;
  uint64_t physical_block_size;
  uint32_t accepted_features;
  uint32_t read_only;
  uint32_t supports_flush;
  uint32_t supports_discard;
  uint32_t supports_write_zeroes;
  uint32_t max_discard_sectors;
  uint32_t max_discard_ranges;
  uint32_t discard_sector_alignment;
  uint32_t max_write_zeroes_sectors;
  uint32_t initialized;
  uint32_t block_registered;
  uint32_t memory_backed;
  uint8_t *memory_base;
  uint64_t memory_size;
  xaios_block_device_t block_device;
} virtio_block_driver_t;

static virtio_block_driver_t *g_blk;
static volatile uint32_t g_interrupt_canary_complete = 1U;
static xaios_status_t g_interrupt_canary_status;
static uint64_t g_interrupt_canary_baseline;
static uint8_t *g_boot_memory_base;
static uint64_t g_boot_memory_size;

static xaios_status_t block_backend_read(void *context, uint64_t byte_offset,
                                         void *buffer, uint64_t length);
static xaios_status_t block_backend_write(void *context, uint64_t byte_offset,
                                          const void *buffer,
                                          uint64_t length);
static xaios_status_t block_backend_flush(void *context);
static xaios_status_t block_backend_discard(void *context,
                                            uint64_t byte_offset,
                                            uint64_t length);
static xaios_status_t block_backend_write_zeroes(void *context,
                                                 uint64_t byte_offset,
                                                 uint64_t length);

static const xaios_block_backend_ops_t k_block_backend_ops = {
    block_backend_read, block_backend_write, block_backend_flush,
    block_backend_discard, block_backend_write_zeroes};

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

static void bytes_copy(void *dst, const void *src, uint64_t size) {
  uint8_t *out = (uint8_t *)dst;
  const uint8_t *in = (const uint8_t *)src;
  for (uint64_t i = 0; i < size; ++i) {
    out[i] = in[i];
  }
}

static uint64_t dma_address(const void *ptr) {
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

static uint64_t read_capacity(const virtio_mmio_device_t *device) {
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

static xaios_status_t configure_queue(virtio_block_driver_t *drv) {
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

  bytes_zero(drv->desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  bytes_zero(drv->avail, sizeof(*drv->avail));
  bytes_zero(drv->used, sizeof(*drv->used));
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

static xaios_status_t read_device_geometry(virtio_block_driver_t *drv) {
  drv->logical_sector_size = SECTOR_SIZE;
  if ((drv->accepted_features & VIRTIO_BLK_F_BLK_SIZE) != 0U) {
    drv->logical_sector_size =
        virtio_mmio_read32(drv->device.base, VIRTIO_MMIO_CONFIG +
                                                VIRTIO_BLK_CONFIG_BLK_SIZE);
  }
  if (drv->logical_sector_size < SECTOR_SIZE ||
      drv->logical_sector_size % SECTOR_SIZE != 0U ||
      (drv->logical_sector_size & (drv->logical_sector_size - 1U)) != 0U) {
    klog("virtio-blk: unusable logical sector size %u\n",
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

static void virtio_block_interrupt(uint32_t intid, void *context) {
  virtio_block_driver_t *drv = (virtio_block_driver_t *)context;
  (void)intid;
  if (drv == 0 || drv->initialized == 0U) return;
  ++drv->interrupt_count;
  (void)virtio_block_poll_h(drv);
  virtio_transport_ack_interrupts(&drv->device);
}

/* Submit one request. `moved`, when given, receives how many bytes the request
   actually covers, which is at most buffer_size and may be less -- the device
   ceiling, the end of the disk, or memory that stops being contiguous all
   shorten it. A caller walking a large span must advance by that figure and
   not by what it asked for. */
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
static void io_trace(virtio_block_driver_t *drv, const char *what,
                     uint64_t sector, uint64_t bytes) {
  klog("io-trace: seq=%lu op=%s sector=%lu bytes=%lu\n", ++drv->io_sequence,
       what, sector, bytes);
}
#else
static void io_trace(virtio_block_driver_t *drv, const char *what,
                     uint64_t sector, uint64_t bytes) {
  (void)drv;
  (void)what;
  (void)sector;
  (void)bytes;
}
#endif

static xaios_status_t submit_sector_h(
    virtio_block_driver_t *drv, uint64_t sector, void *buffer,
    uint64_t buffer_size, uint32_t type,
    virtio_block_completion_t completion, void *context, uint64_t *token,
    uint64_t *moved) {
  if (drv == 0 || drv->initialized == 0U || buffer == 0 ||
      buffer_size < SECTOR_SIZE || completion == 0 || token == 0 ||
      sector >= drv->capacity_sectors ||
      (type != VIRTIO_BLK_T_IN && type != VIRTIO_BLK_T_OUT) ||
      (type == VIRTIO_BLK_T_OUT && drv->read_only != 0U)) {
    return XAIOS_ERR_INVALID;
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
      bytes_copy(buffer, drv->memory_base + offset, transfer);
    } else {
      bytes_copy(drv->memory_base + offset, buffer, transfer);
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
    data_physical = dma_address(slot->dma_sector);
    if (type == VIRTIO_BLK_T_OUT) {
      bytes_copy(slot->dma_sector, buffer, SECTOR_SIZE);
    } else {
      bytes_zero(slot->dma_sector, SECTOR_SIZE);
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
  if (type == VIRTIO_BLK_T_OUT) io_trace(drv, "write", sector, transfer);
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
  chain[0].addr = dma_address(&slot->request);
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
  chain[2].addr = dma_address(&slot->status);
  chain[2].len = 1U;
  chain[2].flags = VRING_DESC_F_WRITE;
  chain[2].next = 0U;
  if (drv->uses_indirect != 0U) {
    drv->desc[head].addr = dma_address(chain);
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
      bytes_copy(slot->buffer, slot->dma_sector,
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

uint32_t virtio_block_outstanding_h(const virtio_block_handle_t *handle) {
  return handle == 0 ? 0U : handle->outstanding;
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

static xaios_status_t recover_queue(virtio_block_driver_t *drv) {
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

typedef struct virtio_block_sync_wait {
  volatile uint32_t complete;
  xaios_status_t status;
} virtio_block_sync_wait_t;

static void sync_completion(uint64_t token, xaios_status_t status,
                            void *context) {
  virtio_block_sync_wait_t *wait = (virtio_block_sync_wait_t *)context;
  (void)token;
  wait->status = status;
  __atomic_store_n(&wait->complete, 1U, __ATOMIC_RELEASE);
}

static void interrupt_canary_completion(uint64_t token,
                                        xaios_status_t status,
                                        void *context) {
  (void)token;
  (void)context;
  g_interrupt_canary_status = status;
  __atomic_store_n(&g_interrupt_canary_complete, 1U, __ATOMIC_RELEASE);
}

static xaios_status_t wait_sync(virtio_block_driver_t *drv,
                                virtio_block_sync_wait_t *wait) {
  uint64_t started = timer_now_ns();
  while (__atomic_load_n(&wait->complete, __ATOMIC_ACQUIRE) == 0U) {
    (void)virtio_block_poll_h(drv);
    if (timer_now_ns() - started >= VIRTIO_BLK_WAIT_TIMEOUT_NS) {
      (void)recover_queue(drv);
      return XAIOS_ERR_IO;
    }
    xaios_cpu_relax();
  }
  return wait->status;
}

static xaios_status_t wait_idle(virtio_block_driver_t *drv) {
  uint64_t started = timer_now_ns();
  while (drv->outstanding != 0U) {
    (void)virtio_block_poll_h(drv);
    if (timer_now_ns() - started >= VIRTIO_BLK_WAIT_TIMEOUT_NS) {
      (void)recover_queue(drv);
      return XAIOS_ERR_IO;
    }
    xaios_cpu_relax();
  }
  return XAIOS_OK;
}


static xaios_status_t flush_h(virtio_block_driver_t *drv) {
  if (drv == 0 || drv->initialized == 0 || drv->supports_flush == 0U) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  io_trace(drv, "flush", 0U, 0U);
  if (drv->memory_backed != 0U) return XAIOS_OK;
  if (wait_idle(drv) != XAIOS_OK) return XAIOS_ERR_BUSY;
  xaios_spin_lock(&drv->queue_lock);
  if (drv->special_active != 0U || drv->outstanding != 0U) {
    xaios_spin_unlock(&drv->queue_lock);
    return XAIOS_ERR_BUSY;
  }
  drv->special_active = 1U;
  bytes_zero(drv->desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  *drv->status = 0xffU;
  drv->request->type = VIRTIO_BLK_T_FLUSH;
  drv->request->reserved = 0U;
  drv->request->sector = 0U;
  drv->desc[0].addr = dma_address(drv->request);
  drv->desc[0].len = sizeof(*drv->request);
  drv->desc[0].flags = VRING_DESC_F_NEXT;
  drv->desc[0].next = 1U;
  drv->desc[1].addr = dma_address(drv->status);
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
    klog("virtio-blk: flush completion timeout avail=%u used=%u target=%u\n",
         drv->next_avail, drv->used->idx, used_target);
    (void)recover_queue(drv);
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
  bytes_zero(drv->desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  bytes_zero(drv->dma_sector, SECTOR_SIZE);
  *drv->status = 0xffU;
  drv->request->type = type;
  drv->request->reserved = 0U;
  drv->request->sector = 0U;
  virtio_blk_range_t *range = (virtio_blk_range_t *)(void *)drv->dma_sector;
  range->sector = sector;
  range->num_sectors = sector_count;
  range->flags = 0U;
  drv->desc[0].addr = dma_address(drv->request);
  drv->desc[0].len = sizeof(*drv->request);
  drv->desc[0].flags = VRING_DESC_F_NEXT;
  drv->desc[0].next = 1U;
  drv->desc[1].addr = dma_address(range);
  drv->desc[1].len = sizeof(*range);
  drv->desc[1].flags = VRING_DESC_F_NEXT;
  drv->desc[1].next = 2U;
  drv->desc[2].addr = dma_address(drv->status);
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
    klog("virtio-blk: range completion timeout type=%u sector=%lu count=%u\n",
         type, sector, sector_count);
    (void)recover_queue(drv);
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

static xaios_status_t register_block_device(virtio_block_driver_t *drv) {
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
  bytes_zero(&info, sizeof(info));
  set_device_identifier(info.identifier, sizeof(info.identifier), slot);
  if (drv->memory_backed != 0U) {
    static const char backend[] = "boot-memory";
    bytes_copy(info.backend, backend, sizeof(backend));
  } else {
    static const char backend[] = "virtio-blk";
    bytes_copy(info.backend, backend, sizeof(backend));
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
      &drv->block_device, &info, &k_block_backend_ops, drv);
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
  if (recover_queue(g_blk) != XAIOS_OK) return XAIOS_ERR_IO;
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
      (void)recover_queue(g_blk);
      return XAIOS_ERR_IO;
    }
    xaios_cpu_relax();
  }
  if (g_interrupt_canary_status != XAIOS_OK ||
      g_blk->interrupt_count <= g_interrupt_canary_baseline)
    return XAIOS_ERR_IO;
  return XAIOS_OK;
}

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
  if (g_blk == 0 || g_blk->initialized == 0) {
    return XAIOS_ERR_INVALID;
  }
  return transfer_sector_h(g_blk, sector, buffer, buffer_size, type);
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
  return flush_h(g_blk);
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
  xaios_status_t status = start_handle(drv, start_slot);
  if (status != XAIOS_OK) {
    release_handle(drv);
    return status;
  }
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
  xaios_status_t status = start_handle(drv, slot);
  if (status != XAIOS_OK) {
    release_handle(drv);
    return status;
  }
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
  xaios_status_t status = start_handle(drv, slot);
  if (status != XAIOS_OK) {
    release_handle(drv);
    return status;
  }
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
  if (g_blk->memory_backed != 0U) {
    kassert(virtio_block_write_sector(write_test_sector, write_sector,
                                      SECTOR_SIZE) == XAIOS_ERR_UNSUPPORTED);
    virtio_block_sync_wait_t wait = {0U, XAIOS_ERR_IO};
    uint64_t token = 0U;
    bytes_zero(sector, SECTOR_SIZE);
    kassert(virtio_block_submit_read_h(
                g_blk, 0U, sector, SECTOR_SIZE, sync_completion, &wait,
                &token) == XAIOS_OK);
    kassert(token != 0U && wait.complete != 0U && wait.status == XAIOS_OK);
    kassert(sector[0] == 'X' && sector[1] == 'A');
    xaios_block_device_t *block = 0;
    xaios_block_device_info_t info;
    kassert(block_device_open("/dev/vblk0", &block) == XAIOS_OK);
    kassert(block_device_info(block, &info) == XAIOS_OK);
    kassert(info.capacity_bytes == g_blk->memory_size);
    kassert(info.read_only != 0U);
    kassert(info.flush_supported != 0U);
    kassert(block_device_close(block) == XAIOS_OK);
    klog("boot-memory: read-only/async/flush self-test passed capacity_sectors=%lu\n",
         g_blk->capacity_sectors);
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
  uint32_t writable = g_blk->read_only == 0U ? 1U : 0U;
  kassert(virtio_block_read_sector(write_test_sector, original_sector,
                                   SECTOR_SIZE) == XAIOS_OK);
  if (writable == 0U) {
    /* A device that says it is read-only is asked to prove it refuses a write,
       and is not asked to accept one. Everything below that does not depend on
       having written still runs, so the device is exercised either way. */
    kassert(virtio_block_write_sector(write_test_sector, write_sector,
                                      SECTOR_SIZE) == XAIOS_ERR_INVALID);
  } else {
    kassert(virtio_block_write_sector(write_test_sector, write_sector,
                                      SECTOR_SIZE) == XAIOS_OK);
    kassert(virtio_block_flush() == XAIOS_OK);
    bytes_zero(sector, SECTOR_SIZE);
    kassert(virtio_block_read_sector(write_test_sector, sector, SECTOR_SIZE) ==
            XAIOS_OK);
    for (uint64_t i = 0; i < SECTOR_SIZE; ++i) {
      kassert(sector[i] == (uint8_t)(i & 0xffU));
    }
  }
  kassert(g_blk->uses_indirect != 0U);
  kassert(virtio_block_queue_depth_h(g_blk) ==
          VIRTIO_BLK_MAX_ASYNC_DEPTH);
  virtio_block_sync_wait_t waits[VIRTIO_BLK_MAX_ASYNC_DEPTH];
  uint64_t tokens[VIRTIO_BLK_MAX_ASYNC_DEPTH];
  for (uint32_t i = 0U; i < g_blk->queue_depth; ++i) {
    waits[i].complete = 0U;
    waits[i].status = XAIOS_ERR_IO;
    uint64_t read_sector = i == 1U ? write_test_sector : i;
    kassert(virtio_block_submit_read_h(
                g_blk, read_sector, async_sectors[i], SECTOR_SIZE,
                sync_completion, &waits[i], &tokens[i]) == XAIOS_OK);
    if (i != 0U) kassert(tokens[i] != tokens[i - 1U]);
  }
  uint64_t rejected_token = 0U;
  kassert(virtio_block_outstanding_h(g_blk) == g_blk->queue_depth);
  kassert(virtio_block_submit_read_h(
              g_blk, 0U, sector, SECTOR_SIZE, sync_completion, &waits[0],
              &rejected_token) == XAIOS_ERR_BUSY);
  for (uint32_t i = 0U; i < g_blk->queue_depth; ++i) {
    kassert(wait_sync(g_blk, &waits[i]) == XAIOS_OK);
  }
  kassert(virtio_block_outstanding_h(g_blk) == 0U);
  kassert(async_sectors[0][0] == 'X' && async_sectors[0][1] == 'A');
  if (writable != 0U) {
    kassert(async_sectors[1][0] == 0U && async_sectors[1][1] == 1U);
    /* Put back what was there. Nothing was changed on a read-only device, so
       there is nothing to restore. */
    kassert(virtio_block_write_sector(write_test_sector, original_sector,
                                      SECTOR_SIZE) == XAIOS_OK);
    kassert(virtio_block_flush() == XAIOS_OK);
    bytes_zero(sector, SECTOR_SIZE);
    kassert(virtio_block_read_sector(write_test_sector, sector, SECTOR_SIZE) ==
            XAIOS_OK);
    for (uint64_t i = 0U; i < SECTOR_SIZE; ++i) {
      kassert(sector[i] == original_sector[i]);
    }
  }
  klog("virtio-blk: asynchronous queue self-test passed depth=%u indirect=%u "
       "direct-or-bounce=verified direct=%lu bounced=%lu\n",
       virtio_block_queue_depth_h(g_blk), g_blk->uses_indirect,
       g_blk->direct_transfers, g_blk->bounce_transfers);
  uint64_t resets_before = g_blk->reset_count;
  kassert(recover_queue(g_blk) == XAIOS_OK);
  kassert(g_blk->reset_count == resets_before + 1U);
  bytes_zero(sector, SECTOR_SIZE);
  kassert(virtio_block_read_sector(0U, sector, SECTOR_SIZE) == XAIOS_OK);
  kassert(sector[0] == 'X' && sector[1] == 'A');
  xaios_block_device_t *block = 0;
  xaios_block_device_info_t info;
  kassert(block_device_open("/dev/vblk0", &block) == XAIOS_OK);
  kassert(block == virtio_block_device_h(g_blk));
  kassert(block_device_info(block, &info) == XAIOS_OK);
  kassert(info.capacity_bytes ==
          virtio_block_capacity_sectors() * SECTOR_SIZE);
  kassert(info.logical_sector_size >= SECTOR_SIZE &&
          info.logical_sector_size <= DMA_ALIGNMENT);
  bytes_zero(sector, DMA_ALIGNMENT);
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
