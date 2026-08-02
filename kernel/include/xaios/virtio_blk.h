#ifndef XAIOS_VIRTIO_BLK_H
#define XAIOS_VIRTIO_BLK_H

#include <xaios/status.h>
#include <xaios/types.h>

typedef struct virtio_block_driver virtio_block_handle_t;

xaios_status_t virtio_block_init(void);
xaios_status_t virtio_block_read_sector(uint64_t sector, void *buffer,
                                       uint64_t buffer_size);
xaios_status_t virtio_block_write_sector(uint64_t sector, const void *buffer,
                                        uint64_t buffer_size);
xaios_status_t virtio_block_flush(void);
uint64_t virtio_block_capacity_sectors(void);
void virtio_block_self_test(void);

xaios_status_t virtio_block_open_slot(uint32_t start_slot,
                                     virtio_block_handle_t **out_handle);
xaios_status_t virtio_block_read_sector_h(virtio_block_handle_t *handle,
                                         uint64_t sector, void *buffer,
                                         uint64_t buffer_size);
xaios_status_t virtio_block_write_sector_h(virtio_block_handle_t *handle,
                                          uint64_t sector, const void *buffer,
                                          uint64_t buffer_size);
xaios_status_t virtio_block_flush_h(virtio_block_handle_t *handle);
uint64_t virtio_block_capacity_sectors_h(virtio_block_handle_t *handle);
void virtio_block_close(virtio_block_handle_t *handle);

#endif
