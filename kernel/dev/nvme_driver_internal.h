/* The interface the NVMe driver's translation units share after this split.
 *
 * nvme_admin.c owns the controller bring-up and the admin command path;
 * nvme_selftest.c owns the polled waits and the block self-test; nvme.c keeps
 * the block backend, the block-device registration, the interrupt programming
 * and the MSI-X canary. nvme_internal.h still carries the controller layout,
 * the queue geometry and the queue machinery, and this header includes it
 * rather than repeating any of it.
 *
 * The register accessors below are `static inline' rather than one definition
 * in a .c file: each is a two-line volatile access that holds no state, so a
 * copy per translation unit cannot duplicate a symbol, and the module that
 * programs the registers keeps the original inline shape. Nothing here can
 * force a symbol to be emitted in a configuration that does not call it.
 */
#ifndef XAIOS_KERNEL_DEV_NVME_DRIVER_INTERNAL_H
#define XAIOS_KERNEL_DEV_NVME_DRIVER_INTERNAL_H

#include "nvme_internal.h"

/* The poll budget every wait in the driver shares. It lived in nvme.c until
 * the waits were split out, and the admin path, the I/O wait and the canary
 * all have to name the same value. */
#define NVME_TIMEOUT_NS UINT64_C(5000000000)

static inline uint32_t nvme_mmio_read32(const nvme_controller_t *controller,
                                        uint32_t offset) {
  return *(volatile uint32_t *)(void *)(controller->bar + offset);
}

static inline uint64_t nvme_mmio_read64(const nvme_controller_t *controller,
                                        uint32_t offset) {
  uint32_t low = nvme_mmio_read32(controller, offset);
  uint32_t high = nvme_mmio_read32(controller, offset + 4U);
  return ((uint64_t)high << 32U) | low;
}

static inline void nvme_mmio_write64(const nvme_controller_t *controller,
                                     uint32_t offset, uint64_t value) {
  nvme_mmio_write32(controller, offset, (uint32_t)value);
  nvme_mmio_write32(controller, offset + 4U, (uint32_t)(value >> 32U));
}

/* The controller the block self-test registered. nvme_self_test writes it once
 * and nvme_interrupt_self_test, which runs later and takes no argument, reads
 * it. It is defined in nvme.c; this is the one piece of file-scope state that
 * crosses the split, and it crosses as a definition of the same object rather
 * than as a pointer handed out by an accessor. */
extern nvme_controller_t *nvme_registered_controller;

/* Zeroing is used by all three files. It was the file-local `bytes_zero' in
 * nvme.c before the split and is defined once there under the module prefix;
 * nvme_queue.c keeps its own file-local copy and is not a caller. */
void nvme_bytes_zero(void *buffer, uint64_t size);

/* Controller bring-up and the admin command path, defined in nvme_admin.c. */
xaios_status_t nvme_initialize_controller(nvme_controller_t *controller,
                                          uint32_t pci_index);
xaios_status_t nvme_identify(nvme_controller_t *controller, uint32_t nsid,
                             uint32_t cns);
xaios_status_t nvme_negotiate_io_queues(nvme_controller_t *controller);
xaios_status_t nvme_create_io_queues(nvme_controller_t *controller);
xaios_status_t nvme_restart_controller(nvme_controller_t *controller);

/* The ordinary block path and the registration, defined in nvme.c. */
xaios_status_t nvme_synchronous_io(nvme_controller_t *controller,
                                   xaios_block_async_operation_t operation,
                                   uint64_t offset, void *buffer,
                                   uint64_t length);
xaios_status_t nvme_register_block_device(nvme_controller_t *controller);
xaios_status_t nvme_backend_cancel(void *context,
                                   xaios_block_async_request_t *request);
xaios_status_t nvme_configure_queue_interrupts(nvme_controller_t *controller);

/* The single polled wait. It lives in nvme_selftest.c because the margin it
 * records is the self-test's, and it crosses because the ordinary read, write
 * and flush in nvme.c call it too. */
xaios_status_t nvme_wait_request(nvme_controller_t *controller,
                                 xaios_block_async_request_t *request);

#endif /* XAIOS_KERNEL_DEV_NVME_DRIVER_INTERNAL_H */
