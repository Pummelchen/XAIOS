#ifndef XAIOS_VIRTIO_TRANSPORT_BACKEND_H
#define XAIOS_VIRTIO_TRANSPORT_BACKEND_H

#include <xaios/virtio_transport.h>

/* Both backends expose the transport API under a private prefix so the
   dispatcher can own the public names and pick between them. */
uint32_t virtio_mmio_backend_mmio_read32(uint64_t base, uint32_t offset);
uint8_t virtio_mmio_backend_mmio_read8(uint64_t base, uint32_t offset);
void virtio_mmio_backend_mmio_write32(uint64_t base, uint32_t offset, uint32_t value);
void virtio_mmio_backend_mmio_barrier(void);
xaios_status_t virtio_mmio_backend_transport_find(uint32_t device_id, const char *name,
                                    virtio_mmio_device_t *device);
xaios_status_t virtio_mmio_backend_transport_find_from(uint32_t device_id, const char *name,
                                         uint32_t start_slot,
                                         virtio_mmio_device_t *device);
xaios_status_t virtio_mmio_backend_transport_find_at(uint32_t device_id, const char *name,
                                       uint32_t slot,
                                       virtio_mmio_device_t *device);
void virtio_mmio_backend_transport_reset(const virtio_mmio_device_t *device);
xaios_status_t virtio_mmio_backend_transport_reset_checked(
    const virtio_mmio_device_t *device);
xaios_status_t virtio_mmio_backend_transport_negotiate_no_features(
    const virtio_mmio_device_t *device);
xaios_status_t virtio_mmio_backend_transport_negotiate_features(
    const virtio_mmio_device_t *device, uint32_t requested_low,
    uint32_t requested_high, uint32_t *accepted_low,
    uint32_t *accepted_high);
xaios_status_t virtio_mmio_backend_transport_setup_queue(virtio_mmio_device_t *device,
                                           uint32_t queue_index,
                                           uint32_t queue_size,
                                           virtq_desc_t *desc,
                                           virtq_avail_t *avail,
                                           virtq_used_t *used);
void virtio_mmio_backend_transport_set_driver_ok(const virtio_mmio_device_t *device);
xaios_status_t virtio_mmio_backend_transport_set_driver_ok_checked(
    const virtio_mmio_device_t *device);
void virtio_mmio_backend_transport_notify(const virtio_mmio_device_t *device,
                             uint32_t queue_index);
uint32_t virtio_mmio_backend_transport_device_status(
    const virtio_mmio_device_t *device);
xaios_status_t virtio_mmio_backend_transport_wait_used(volatile uint16_t *used_idx,
                                         uint16_t expected);
void virtio_mmio_backend_transport_ack_interrupts(const virtio_mmio_device_t *device);
uint32_t virtio_mmio_backend_transport_interrupt_id(const virtio_mmio_device_t *device);
xaios_status_t virtio_mmio_backend_transport_register_interrupt(
    const virtio_mmio_device_t *device, virtio_interrupt_handler_t handler,
    void *context);
xaios_status_t virtio_mmio_backend_transport_unregister_interrupt(
    const virtio_mmio_device_t *device, virtio_interrupt_handler_t handler,
    void *context);
uint32_t virtio_mmio_backend_transport_slot(const virtio_mmio_device_t *device);


uint32_t virtio_pci_backend_mmio_read32(uint64_t base, uint32_t offset);
uint8_t virtio_pci_backend_mmio_read8(uint64_t base, uint32_t offset);
void virtio_pci_backend_mmio_write32(uint64_t base, uint32_t offset, uint32_t value);
void virtio_pci_backend_mmio_barrier(void);
xaios_status_t virtio_pci_backend_transport_find(uint32_t device_id, const char *name,
                                    virtio_mmio_device_t *device);
xaios_status_t virtio_pci_backend_transport_find_from(uint32_t device_id, const char *name,
                                         uint32_t start_slot,
                                         virtio_mmio_device_t *device);
xaios_status_t virtio_pci_backend_transport_find_at(uint32_t device_id, const char *name,
                                       uint32_t slot,
                                       virtio_mmio_device_t *device);
void virtio_pci_backend_transport_reset(const virtio_mmio_device_t *device);
xaios_status_t virtio_pci_backend_transport_reset_checked(
    const virtio_mmio_device_t *device);
xaios_status_t virtio_pci_backend_transport_negotiate_no_features(
    const virtio_mmio_device_t *device);
xaios_status_t virtio_pci_backend_transport_negotiate_features(
    const virtio_mmio_device_t *device, uint32_t requested_low,
    uint32_t requested_high, uint32_t *accepted_low,
    uint32_t *accepted_high);
xaios_status_t virtio_pci_backend_transport_setup_queue(virtio_mmio_device_t *device,
                                           uint32_t queue_index,
                                           uint32_t queue_size,
                                           virtq_desc_t *desc,
                                           virtq_avail_t *avail,
                                           virtq_used_t *used);
void virtio_pci_backend_transport_set_driver_ok(const virtio_mmio_device_t *device);
xaios_status_t virtio_pci_backend_transport_set_driver_ok_checked(
    const virtio_mmio_device_t *device);
void virtio_pci_backend_transport_notify(const virtio_mmio_device_t *device,
                             uint32_t queue_index);
uint32_t virtio_pci_backend_transport_device_status(
    const virtio_mmio_device_t *device);
xaios_status_t virtio_pci_backend_transport_wait_used(volatile uint16_t *used_idx,
                                         uint16_t expected);
void virtio_pci_backend_transport_ack_interrupts(const virtio_mmio_device_t *device);
uint32_t virtio_pci_backend_transport_interrupt_id(const virtio_mmio_device_t *device);
xaios_status_t virtio_pci_backend_transport_register_interrupt(
    const virtio_mmio_device_t *device, virtio_interrupt_handler_t handler,
    void *context);
xaios_status_t virtio_pci_backend_transport_unregister_interrupt(
    const virtio_mmio_device_t *device, virtio_interrupt_handler_t handler,
    void *context);
uint32_t virtio_pci_backend_transport_slot(const virtio_mmio_device_t *device);


#endif