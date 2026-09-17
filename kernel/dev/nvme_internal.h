/* Private interface shared by the two halves of the NVMe driver.
 *
 * nvme.c keeps the controller, its bring-up, the admin path, the block-device
 * registration and the self-test. nvme_queue.c owns the I/O queue machinery:
 * the ring allocation and reset, the request slots and their data pointers, and
 * the submission and polling loops that the ordinary I/O path and the
 * interrupt handler share.
 *
 * The controller's layout crosses, so it lives here. The driver pointer
 * `g_nvme_controller' does not: nothing in the queue machinery names it, and a
 * queue reaches its controller through the pointer its caller already holds, so
 * no accessor is needed and no file-scope state is handed out.
 *
 * As in virtio_blk_internal.h, the helpers shared between the two files are
 * declared here rather than in a public header; the symbols this module defines
 * carry the `nvme_' prefix so two modules cannot collide at link time.
 */
#ifndef XAIOS_KERNEL_DEV_NVME_INTERNAL_H
#define XAIOS_KERNEL_DEV_NVME_INTERNAL_H

#include <xaios/block_device.h>
#include <xaios/types.h>

#include "nvme_completion.h"

/* Geometry and opcodes the queue machinery and the driver both name. */
#define NVME_MAX_IO_QUEUES 4U
#define NVME_PAGE_SIZE UINT64_C(4096)
#define NVME_MAX_TRANSFER_BYTES UINT32_C(16384)
#define NVME_REG_DOORBELL UINT32_C(0x1000)
#define NVME_PSDT_SGL ((uint8_t)(UINT8_C(1) << 6U))
#define NVME_IO_FLUSH UINT8_C(0x00)
#define NVME_IO_WRITE UINT8_C(0x01)
#define NVME_IO_READ UINT8_C(0x02)

typedef struct nvme_controller {
  volatile uint8_t *bar;
  uint64_t cap;
  uint32_t doorbell_stride;
  uint16_t next_cid;
  nvme_queue_t admin;
  nvme_queue_t io[NVME_MAX_IO_QUEUES];
  uint32_t io_queue_count;
  uint32_t next_queue;
  uint32_t namespace_id;
  uint32_t block_size;
  uint64_t namespace_blocks;
  uint32_t sgl_supported;
  uint64_t async_operations;
  uint64_t cancelled_operations;
  uint64_t sgl_operations;
  uint64_t direct_operations;
  uint32_t pci_index;
  uint32_t msix_queue_count;
  uint8_t *interrupt_test_buffer;
  uint8_t *identify;
  xaios_block_device_t block_device;
} nvme_controller_t;

/* Controller access and request identity, defined in nvme_queue.c. */
uint16_t nvme_allocate_cid(nvme_controller_t *controller);
void nvme_mmio_write32(const nvme_controller_t *controller, uint32_t offset,
                       uint32_t value);
uint32_t nvme_doorbell_offset(const nvme_controller_t *controller, uint16_t qid,
                              uint32_t completion);
uint64_t nvme_dma_address(const void *buffer);

/* The queue machinery, defined in nvme_queue.c. */
xaios_status_t nvme_allocate_queue(nvme_queue_t *queue, uint16_t qid,
                                   uint32_t assigned_cpu,
                                   nvme_controller_t *controller);
void nvme_reset_queue(nvme_queue_t *queue);
xaios_status_t nvme_prepare_data_pointer(nvme_controller_t *controller,
                                         nvme_request_slot_t *slot,
                                         nvme_command_t *command, void *buffer,
                                         uint32_t length, uint32_t use_sgl);
nvme_request_slot_t *nvme_free_slot(nvme_queue_t *queue);
nvme_request_slot_t *nvme_slot_for_cid(nvme_queue_t *queue, uint16_t cid);
xaios_status_t nvme_submit_io(nvme_controller_t *controller,
                              uint32_t queue_index,
                              xaios_block_async_request_t *request,
                              uint32_t use_sgl);
uint32_t nvme_poll_queue(nvme_controller_t *controller, nvme_queue_t *queue,
                         uint32_t budget);
uint32_t nvme_poll_controller(nvme_controller_t *controller, uint32_t budget);

#endif /* XAIOS_KERNEL_DEV_NVME_INTERNAL_H */
