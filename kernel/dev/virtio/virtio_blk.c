#include <xaios/assert.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/virtio_blk.h>
#include <xaios/virtio_transport.h>
#include <xaios/vmm.h>

#define VIRTIO_MMIO_CONFIG 0x100U
#define VRING_DESC_F_NEXT UINT16_C(1)
#define VRING_DESC_F_WRITE UINT16_C(2)
#define VIRTIO_BLK_T_IN UINT32_C(0)
#define VIRTIO_BLK_T_OUT UINT32_C(1)
#define VIRTIO_BLK_T_FLUSH UINT32_C(4)
#define VIRTIO_BLK_F_FLUSH (UINT32_C(1) << 9U)
#define VIRTIO_F_VERSION_1_HIGH UINT32_C(1)
#define SECTOR_SIZE UINT64_C(512)
#define DMA_ALIGNMENT UINT64_C(4096)

typedef struct virtio_blk_req {
  uint32_t type;
  uint32_t reserved;
  uint64_t sector;
} virtio_blk_req_t;

typedef struct virtio_block_driver {
  virtio_mmio_device_t device;
  virtq_desc_t *desc;
  virtq_avail_t *avail;
  virtq_used_t *used;
  virtio_blk_req_t *request;
  uint8_t *dma_sector;
  uint8_t *status;
  uint16_t next_avail;
  uint64_t capacity_sectors;
  uint32_t supports_flush;
  uint32_t initialized;
} virtio_block_driver_t;

static virtio_block_driver_t *g_blk;

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

static uint64_t read_capacity(const virtio_mmio_device_t *device) {
  uint32_t low = virtio_mmio_read32(device->base, VIRTIO_MMIO_CONFIG);
  uint32_t high = virtio_mmio_read32(device->base, VIRTIO_MMIO_CONFIG + 4U);
  return ((uint64_t)high << 32U) | low;
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
  return XAIOS_OK;
}

static xaios_status_t configure_queue(virtio_block_driver_t *drv) {
  uint32_t accepted_low = 0U;
  uint32_t accepted_high = 0U;
  if (virtio_transport_negotiate_features(
          &drv->device, VIRTIO_BLK_F_FLUSH, VIRTIO_F_VERSION_1_HIGH,
          &accepted_low, &accepted_high) != XAIOS_OK ||
      (accepted_high & VIRTIO_F_VERSION_1_HIGH) == 0U) {
    return XAIOS_ERR_IO;
  }
  drv->supports_flush = (accepted_low & VIRTIO_BLK_F_FLUSH) != 0U;

  bytes_zero(drv->desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  bytes_zero(drv->avail, sizeof(*drv->avail));
  bytes_zero(drv->used, sizeof(*drv->used));
  if (virtio_transport_setup_queue(&drv->device, 0, VIRTQ_SIZE, drv->desc,
                                   drv->avail, drv->used) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }

  drv->next_avail = 0;
  virtio_transport_set_driver_ok(&drv->device);
  return XAIOS_OK;
}

static xaios_status_t flush_h(virtio_block_driver_t *drv) {
  if (drv == 0 || drv->initialized == 0 || drv->supports_flush == 0U) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  if (drv->next_avail == VIRTQ_SIZE && configure_queue(drv) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
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
  virtio_transport_notify(&drv->device, 0U);
  if (virtio_transport_wait_used(&drv->used->idx, used_target) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  virtio_transport_ack_interrupts(&drv->device);
  return *drv->status == 0U ? XAIOS_OK : XAIOS_ERR_IO;
}

xaios_status_t virtio_block_init(void) {
  if (allocate_driver() != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
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
  g_blk->initialized = 1;
  klog("virtio-blk: capacity_sectors=%lu\n", g_blk->capacity_sectors);
  return XAIOS_OK;
}

uint64_t virtio_block_capacity_sectors(void) {
  if (g_blk == 0 || g_blk->initialized == 0) {
    return 0;
  }
  return g_blk->capacity_sectors;
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
  if (sector >= drv->capacity_sectors) {
    return XAIOS_ERR_IO;
  }

  /* This synchronous prototype has one descriptor chain and no descriptor
   * free-list. Reinitialize its bounded queue before an available-ring slot is
   * reused; production asynchronous I/O will replace this lifecycle. */
  if (drv->next_avail == VIRTQ_SIZE && configure_queue(drv) != XAIOS_OK) {
    klog("virtio-blk: queue recycle failed sector=%lu type=%u\n", sector, type);
    return XAIOS_ERR_IO;
  }

  bytes_zero(drv->desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  bytes_zero(drv->dma_sector, SECTOR_SIZE);
  *drv->status = 0xffU;
  if (type == VIRTIO_BLK_T_OUT) {
    bytes_copy(drv->dma_sector, buffer, SECTOR_SIZE);
  }

  drv->request->type = type;
  drv->request->reserved = 0;
  drv->request->sector = sector;
  drv->desc[0].addr = dma_address(drv->request);
  drv->desc[0].len = sizeof(*drv->request);
  drv->desc[0].flags = VRING_DESC_F_NEXT;
  drv->desc[0].next = 1;
  drv->desc[1].addr = dma_address(drv->dma_sector);
  drv->desc[1].len = SECTOR_SIZE;
  drv->desc[1].flags = VRING_DESC_F_NEXT;
  if (type == VIRTIO_BLK_T_IN) {
    drv->desc[1].flags |= VRING_DESC_F_WRITE;
  }
  drv->desc[1].next = 2;
  drv->desc[2].addr = dma_address(drv->status);
  drv->desc[2].len = 1;
  drv->desc[2].flags = VRING_DESC_F_WRITE;
  drv->desc[2].next = 0;

  uint16_t used_target = (uint16_t)(drv->used->idx + 1U);
  drv->avail->ring[drv->next_avail % VIRTQ_SIZE] = 0;
  virtio_mmio_barrier();
  ++drv->next_avail;
  drv->avail->idx = drv->next_avail;
  virtio_transport_notify(&drv->device, 0);

  if (virtio_transport_wait_used(&drv->used->idx, used_target) != XAIOS_OK) {
    klog("virtio-blk: completion timeout sector=%lu type=%u avail=%u used=%u "
         "target=%u\n",
         sector, type, drv->next_avail, drv->used->idx, used_target);
    return XAIOS_ERR_IO;
  }
  virtio_transport_ack_interrupts(&drv->device);
  if (*drv->status != 0) {
    klog("virtio-blk: device error sector=%lu type=%u status=%u\n", sector,
         type, *drv->status);
    return XAIOS_ERR_IO;
  }

  if (type == VIRTIO_BLK_T_IN) {
    bytes_copy(buffer, drv->dma_sector, SECTOR_SIZE);
  }
  return XAIOS_OK;
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

xaios_status_t virtio_block_open_slot(uint32_t start_slot,
                                     virtio_block_handle_t **out_handle) {
  if (out_handle == 0) {
    return XAIOS_ERR_INVALID;
  }
  virtio_block_driver_t *drv =
      (virtio_block_driver_t *)kheap_calloc(sizeof(*drv), 16);
  if (drv == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }
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
    return XAIOS_ERR_NO_MEMORY;
  }

  if (virtio_transport_find_from(VIRTIO_DEVICE_BLOCK, "virtio-blk-h",
                                 start_slot, &drv->device) != XAIOS_OK) {
    return XAIOS_ERR_NOT_FOUND;
  }
  if (configure_queue(drv) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  drv->capacity_sectors = read_capacity(&drv->device);
  drv->initialized = 1;
  klog("virtio-blk-h: slot=%u capacity_sectors=%lu\n",
       start_slot, drv->capacity_sectors);
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

xaios_status_t virtio_block_flush_h(virtio_block_handle_t *handle) {
  return flush_h(handle);
}

uint64_t virtio_block_capacity_sectors_h(virtio_block_handle_t *handle) {
  if (handle == 0 || handle->initialized == 0) {
    return 0;
  }
  return handle->capacity_sectors;
}

void virtio_block_close(virtio_block_handle_t *handle) {
  if (handle != 0 && handle->initialized != 0) {
    virtio_transport_reset(&handle->device);
    handle->initialized = 0;
  }
}

void virtio_block_self_test(void) {
  uint8_t *sector = (uint8_t *)kheap_calloc(SECTOR_SIZE, 16);
  uint8_t *write_sector = (uint8_t *)kheap_calloc(SECTOR_SIZE, 16);
  kassert(sector != 0);
  kassert(write_sector != 0);
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
  uint64_t write_test_sector = virtio_block_capacity_sectors() - 2U;
  kassert(virtio_block_write_sector(write_test_sector, write_sector,
                                    SECTOR_SIZE) == XAIOS_OK);
  kassert(virtio_block_flush() == XAIOS_OK);
  bytes_zero(sector, SECTOR_SIZE);
  kassert(virtio_block_read_sector(write_test_sector, sector, SECTOR_SIZE) ==
          XAIOS_OK);
  for (uint64_t i = 0; i < SECTOR_SIZE; ++i) {
    kassert(sector[i] == (uint8_t)(i & 0xffU));
  }
  virtio_transport_reset(&g_blk->device);
  kassert(virtio_block_init() == XAIOS_OK);
  klog("virtio-blk: read/write/error/reset self-test passed\n");
}
