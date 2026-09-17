/* Private interface shared by the two halves of the virtio block driver.
 *
 * virtio_blk.c keeps the device bring-up, the request engine and the block
 * backend; the handle lifecycle -- opening, transferring on and closing a
 * device found by slot, ordinal or PCI ordinal -- lives in
 * virtio_blk_handles.c. Both halves need the driver's layout, so the type
 * block lives here. The primary driver pointer `g_blk' does not: the handle
 * code asks for its value through virtio_blk_primary_driver() and never names
 * the variable itself.
 *
 * Following remote_login_internal.h, the helpers shared between the two files
 * keep their plain names; this header, not a public one, is where they are
 * declared.
 */
#ifndef XAIOS_DEV_VIRTIO_VIRTIO_BLK_INTERNAL_H
#define XAIOS_DEV_VIRTIO_VIRTIO_BLK_INTERNAL_H

#include <xaios/block_device.h>
#include <xaios/spinlock.h>
#include <xaios/types.h>
#include <xaios/virtio_blk.h>
#include <xaios/virtio_transport.h>

#define SECTOR_SIZE UINT64_C(512)
#define DMA_ALIGNMENT UINT64_C(4096)
#define VIRTIO_BLK_T_IN UINT32_C(0)
#define VIRTIO_BLK_T_OUT UINT32_C(1)
#define VIRTIO_BLK_MAX_ASYNC_DEPTH VIRTQ_SIZE

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
  /* When set, completions are acknowledged but not processed.
   *
   * The queue-depth checks in the self-test below fill the ring and then
   * assert that everything they submitted is still outstanding and that one
   * more request is refused. Both statements are about the queue's capacity,
   * and both are only observable while nothing is draining it -- which is
   * true when completions are polled and false the moment the device can
   * interrupt. Rather than write assertions that are weaker on the machines
   * that complete faster, the test suspends processing for exactly the window
   * it is measuring. The interrupt is still acknowledged while suspended,
   * because a device left asserting a level-triggered line re-raises it
   * immediately and the machine spends the window in its own handler. */
  uint32_t completions_suspended;
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

typedef struct virtio_block_sync_wait {
  volatile uint32_t complete;
  xaios_status_t status;
} virtio_block_sync_wait_t;

/* Defined in virtio_blk.c. The pointer's value is copied out; the variable
   `g_blk' itself stays private to that file. */
virtio_block_driver_t *virtio_blk_primary_driver(void);

/* Defined in virtio_blk.c and used by the handle code. */
uint64_t read_capacity(const virtio_mmio_device_t *device);
xaios_status_t configure_queue(virtio_block_driver_t *drv);
xaios_status_t read_device_geometry(virtio_block_driver_t *drv);
void virtio_block_interrupt(uint32_t intid, void *context);
xaios_status_t submit_sector_h(
    virtio_block_driver_t *drv, uint64_t sector, void *buffer,
    uint64_t buffer_size, uint32_t type,
    virtio_block_completion_t completion, void *context, uint64_t *token,
    uint64_t *moved);
void sync_completion(uint64_t token, xaios_status_t status, void *context);
xaios_status_t wait_sync(virtio_block_driver_t *drv,
                         virtio_block_sync_wait_t *wait);
xaios_status_t wait_idle(virtio_block_driver_t *drv);
xaios_status_t flush_h(virtio_block_driver_t *drv);
xaios_status_t register_block_device(virtio_block_driver_t *drv);

/* Defined in virtio_blk_handles.c and used by virtio_blk.c's bring-up. */
void block_device_note_taken(const virtio_mmio_device_t *device);

#endif /* XAIOS_DEV_VIRTIO_VIRTIO_BLK_INTERNAL_H */
