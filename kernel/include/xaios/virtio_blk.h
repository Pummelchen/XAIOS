#ifndef XAIOS_VIRTIO_BLK_H
#define XAIOS_VIRTIO_BLK_H

#include <xaios/block_device.h>
#include <xaios/status.h>
#include <xaios/types.h>

typedef struct virtio_block_driver virtio_block_handle_t;
typedef void (*virtio_block_completion_t)(uint64_t token,
                                          xaios_status_t status,
                                          void *context);

xaios_status_t virtio_block_init(void);
xaios_status_t virtio_block_set_boot_memory(void *base, uint64_t size);
xaios_status_t virtio_block_read_sector(uint64_t sector, void *buffer,
                                       uint64_t buffer_size);
xaios_status_t virtio_block_write_sector(uint64_t sector, const void *buffer,
                                        uint64_t buffer_size);
xaios_status_t virtio_block_flush(void);
uint64_t virtio_block_capacity_sectors(void);
uint64_t virtio_block_interrupt_count(void);
uint32_t virtio_block_is_read_only(void);
/* Non-zero when the block device is memory supplied by the loader rather than
   a virtio device. See virtio_blk.c. */
uint32_t virtio_block_is_memory_backed(void);

xaios_status_t virtio_block_interrupt_canary_arm(uint64_t sector,
                                                 void *buffer,
                                                 uint64_t buffer_size);
xaios_status_t virtio_block_interrupt_canary_wait(uint64_t timeout_ns);
void virtio_block_self_test(void);

xaios_status_t virtio_block_open_slot(uint32_t start_slot,
                                     virtio_block_handle_t **out_handle);

/* Open the nth virtio block device present, rather than the one pinned to a
   given slot. An installed machine has one disk and no fixed layout, so the
   slot map the test bench relies on -- which reserves ordinal zero for the
   firmware's boot disk -- finds nothing there. slot names the device. */
xaios_status_t virtio_block_open_ordinal(uint32_t ordinal, uint32_t slot,
                                        virtio_block_handle_t **out_handle);

/* The nth PCI block device, ignoring the MMIO window. A machine boots from a
   PCI disk; counting across both transports cannot reach it when an MMIO
   device is present, which is the case as soon as a spare disk is attached. */
xaios_status_t virtio_block_open_pci_ordinal(uint32_t ordinal, uint32_t slot,
                                            virtio_block_handle_t **out_handle);

/* How many virtio block devices are present, up to limit, without claiming
   any. One disk means an installed machine whose state is a partition of it;
   several mean volumes attached separately, each already owned. */
uint32_t virtio_block_present_count(uint32_t limit);
xaios_status_t virtio_block_read_sector_h(virtio_block_handle_t *handle,
                                         uint64_t sector, void *buffer,
                                         uint64_t buffer_size);
xaios_status_t virtio_block_write_sector_h(virtio_block_handle_t *handle,
                                          uint64_t sector, const void *buffer,
                                          uint64_t buffer_size);
xaios_status_t virtio_block_submit_read_h(
    virtio_block_handle_t *handle, uint64_t sector, void *buffer,
    uint64_t buffer_size, virtio_block_completion_t completion, void *context,
    uint64_t *token);
xaios_status_t virtio_block_submit_write_h(
    virtio_block_handle_t *handle, uint64_t sector, const void *buffer,
    uint64_t buffer_size, virtio_block_completion_t completion, void *context,
    uint64_t *token);
uint32_t virtio_block_poll_h(virtio_block_handle_t *handle);
uint32_t virtio_block_outstanding_h(const virtio_block_handle_t *handle);
uint32_t virtio_block_queue_depth_h(const virtio_block_handle_t *handle);
uint64_t virtio_block_interrupt_count_h(const virtio_block_handle_t *handle);
xaios_status_t virtio_block_flush_h(virtio_block_handle_t *handle);
uint64_t virtio_block_capacity_sectors_h(virtio_block_handle_t *handle);
xaios_block_device_t *virtio_block_device_h(virtio_block_handle_t *handle);
void virtio_block_close(virtio_block_handle_t *handle);

#endif
