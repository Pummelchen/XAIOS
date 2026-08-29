#include <xaios/virtio_transport.h>
#include <xaios/virtio_transport_backend.h>

/* aarch64 can meet virtio over either transport. QEMU's virt machine presents
   it on the MMIO window at a fixed address; Virtualization.framework, and
   real PCIe hardware, present it on the PCI bus and offer no MMIO window at
   all. Probe MMIO first so the QEMU path is unchanged, and fall back to PCI,
   which is what a machine with no MMIO window will match. */

static xaios_status_t find_with_fallback(uint32_t device_id, const char *name,
                                         virtio_mmio_device_t *device,
                                         uint32_t mode, uint32_t slot) {
  if (device == 0) return XAIOS_ERR_INVALID;
  xaios_status_t status;
  switch (mode) {
    case 1U:
      status = virtio_mmio_backend_transport_find_from(device_id, name, slot,
                                                       device);
      break;
    case 2U:
      status =
          virtio_mmio_backend_transport_find_at(device_id, name, slot, device);
      break;
    default:
      status = virtio_mmio_backend_transport_find(device_id, name, device);
      break;
  }
  if (status == XAIOS_OK) {
    device->backend = VIRTIO_BACKEND_MMIO;
    return status;
  }
  switch (mode) {
    case 1U:
      status = virtio_pci_backend_transport_find_from(device_id, name, slot,
                                                      device);
      break;
    case 2U:
      status =
          virtio_pci_backend_transport_find_at(device_id, name, slot, device);
      break;
    default:
      status = virtio_pci_backend_transport_find(device_id, name, device);
      break;
  }
  if (status == XAIOS_OK) device->backend = VIRTIO_BACKEND_PCI;
  return status;
}

xaios_status_t virtio_transport_find(uint32_t device_id, const char *name,
                                     virtio_mmio_device_t *device) {
  return find_with_fallback(device_id, name, device, 0U, 0U);
}

xaios_status_t virtio_transport_find_from(uint32_t device_id, const char *name,
                                          uint32_t start_slot,
                                          virtio_mmio_device_t *device) {
  return find_with_fallback(device_id, name, device, 1U, start_slot);
}

xaios_status_t virtio_transport_find_at(uint32_t device_id, const char *name,
                                        uint32_t slot,
                                        virtio_mmio_device_t *device) {
  return find_with_fallback(device_id, name, device, 2U, slot);
}

/* The nth PCI device of this type, skipping the MMIO window entirely.
 *
 * find_nth below counts every MMIO device before it looks at PCI at all, which
 * makes a machine with one of each unable to reach the PCI one: ordinal zero is
 * the MMIO device, and ordinal one finds nothing because neither transport has
 * a second. That is not hypothetical -- it is the shape of an installed machine
 * with a spare disk attached, where the boot disk is PCI and the spare is MMIO,
 * and the kernel opened the spare and never saw the disk it had booted from.
 *
 * A machine's boot disk is on PCI. Firmware boots from it, so asking for a PCI
 * device by ordinal says what is meant rather than counting past whatever else
 * happens to be plugged in. */
xaios_status_t virtio_transport_find_nth_pci(uint32_t device_id,
                                             const char *name,
                                             uint32_t ordinal,
                                             uint32_t logical_slot,
                                             virtio_mmio_device_t *device) {
  if (device == 0) return XAIOS_ERR_INVALID;
  xaios_status_t status = virtio_pci_backend_transport_find_nth(
      device_id, name, ordinal, logical_slot, device);
  if (status == XAIOS_OK) device->backend = VIRTIO_BACKEND_PCI;
  return status;
}

xaios_status_t virtio_transport_find_nth(uint32_t device_id, const char *name,
                                         uint32_t ordinal,
                                         uint32_t logical_slot,
                                         virtio_mmio_device_t *device) {
  if (device == 0) return XAIOS_ERR_INVALID;
  xaios_status_t status = virtio_mmio_backend_transport_find_nth(
      device_id, name, ordinal, logical_slot, device);
  if (status == XAIOS_OK) {
    device->backend = VIRTIO_BACKEND_MMIO;
    return status;
  }
  status = virtio_pci_backend_transport_find_nth(device_id, name, ordinal,
                                                 logical_slot, device);
  if (status == XAIOS_OK) device->backend = VIRTIO_BACKEND_PCI;
  return status;
}

#define DISPATCH(device, call, args)                     \
  ((device) != 0 && (device)->backend == VIRTIO_BACKEND_PCI \
       ? virtio_pci_backend_##call args                  \
       : virtio_mmio_backend_##call args)

void virtio_transport_reset(const virtio_mmio_device_t *device) {
  DISPATCH(device, transport_reset, (device));
}

xaios_status_t virtio_transport_reset_checked(
    const virtio_mmio_device_t *device) {
  return DISPATCH(device, transport_reset_checked, (device));
}

xaios_status_t virtio_transport_negotiate_no_features(
    const virtio_mmio_device_t *device) {
  return DISPATCH(device, transport_negotiate_no_features, (device));
}

xaios_status_t virtio_transport_negotiate_features(
    const virtio_mmio_device_t *device, uint32_t requested_low,
    uint32_t requested_high, uint32_t *accepted_low, uint32_t *accepted_high) {
  return DISPATCH(device, transport_negotiate_features,
                  (device, requested_low, requested_high, accepted_low,
                   accepted_high));
}

xaios_status_t virtio_transport_setup_queue(virtio_mmio_device_t *device,
                                            uint32_t queue_index,
                                            uint32_t queue_size,
                                            virtq_desc_t *desc,
                                            virtq_avail_t *avail,
                                            virtq_used_t *used) {
  return DISPATCH(device, transport_setup_queue,
                  (device, queue_index, queue_size, desc, avail, used));
}

void virtio_transport_set_driver_ok(const virtio_mmio_device_t *device) {
  DISPATCH(device, transport_set_driver_ok, (device));
}

xaios_status_t virtio_transport_set_driver_ok_checked(
    const virtio_mmio_device_t *device) {
  return DISPATCH(device, transport_set_driver_ok_checked, (device));
}

void virtio_transport_notify(const virtio_mmio_device_t *device,
                             uint32_t queue_index) {
  DISPATCH(device, transport_notify, (device, queue_index));
}

void virtio_transport_ack_interrupts(const virtio_mmio_device_t *device) {
  DISPATCH(device, transport_ack_interrupts, (device));
}

uint32_t virtio_transport_interrupt_id(const virtio_mmio_device_t *device) {
  return DISPATCH(device, transport_interrupt_id, (device));
}

xaios_status_t virtio_transport_register_interrupt(
    const virtio_mmio_device_t *device, virtio_interrupt_handler_t handler,
    void *context) {
  return DISPATCH(device, transport_register_interrupt,
                  (device, handler, context));
}

xaios_status_t virtio_transport_unregister_interrupt(
    const virtio_mmio_device_t *device, virtio_interrupt_handler_t handler,
    void *context) {
  return DISPATCH(device, transport_unregister_interrupt,
                  (device, handler, context));
}

uint32_t virtio_transport_slot(const virtio_mmio_device_t *device) {
  return DISPATCH(device, transport_slot, (device));
}

/* Register access takes a raw address rather than a device, and is a plain
   memory access in both backends, so it needs no dispatch. */
uint32_t virtio_mmio_read32(uint64_t base, uint32_t offset) {
  return virtio_mmio_backend_mmio_read32(base, offset);
}

uint8_t virtio_mmio_read8(uint64_t base, uint32_t offset) {
  return virtio_mmio_backend_mmio_read8(base, offset);
}

void virtio_mmio_write32(uint64_t base, uint32_t offset, uint32_t value) {
  virtio_mmio_backend_mmio_write32(base, offset, value);
}

void virtio_mmio_barrier(void) { virtio_mmio_backend_mmio_barrier(); }

uint32_t virtio_transport_device_status(const virtio_mmio_device_t *device) {
  if (device != 0 && device->backend == VIRTIO_BACKEND_PCI) {
    return virtio_pci_backend_transport_device_status(device);
  }
  return virtio_mmio_backend_transport_device_status(device);
}

xaios_status_t virtio_transport_wait_used(volatile uint16_t *used_idx,
                                          uint16_t expected) {
  return virtio_mmio_backend_transport_wait_used(used_idx, expected);
}

xaios_status_t virtio_transport_setup_queue_vectored(
    virtio_mmio_device_t *device, uint32_t queue_index, uint32_t queue_size,
    virtq_desc_t *desc, virtq_avail_t *avail, virtq_used_t *used) {
  return DISPATCH(device, transport_setup_queue_vectored,
                  (device, queue_index, queue_size, desc, avail, used));
}

uint32_t virtio_transport_queue_has_vector(const virtio_mmio_device_t *device,
                                           uint32_t queue_index) {
  return DISPATCH(device, transport_queue_has_vector, (device, queue_index));
}

xaios_status_t virtio_transport_register_queue_interrupt(
    const virtio_mmio_device_t *device, uint32_t queue_index,
    virtio_interrupt_handler_t handler, void *context) {
  return DISPATCH(device, transport_register_queue_interrupt,
                  (device, queue_index, handler, context));
}
