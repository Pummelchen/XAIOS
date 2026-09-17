#include "virtio_transport_pci_internal.h"

uint8_t virtio_pci_mmio_read8(uint64_t address) {
  return *(volatile uint8_t *)(uintptr_t)address;
}

uint16_t virtio_pci_mmio_read16(uint64_t address) {
  return *(volatile uint16_t *)(uintptr_t)address;
}

uint32_t virtio_pci_mmio_read32(uint64_t address) {
  return *(volatile uint32_t *)(uintptr_t)address;
}

void virtio_pci_mmio_write8(uint64_t address, uint8_t value) {
  *(volatile uint8_t *)(uintptr_t)address = value;
}

void virtio_pci_mmio_write16(uint64_t address, uint16_t value) {
  *(volatile uint16_t *)(uintptr_t)address = value;
}

void virtio_pci_mmio_write32(uint64_t address, uint32_t value) {
  *(volatile uint32_t *)(uintptr_t)address = value;
}

void virtio_pci_mmio_write64(uint64_t address, uint64_t value) {
  *(volatile uint64_t *)(uintptr_t)address = value;
}

uint32_t virtio_mmio_read32(uint64_t base, uint32_t offset) {
  return virtio_pci_mmio_read32(base + offset);
}

uint8_t virtio_mmio_read8(uint64_t base, uint32_t offset) {
  return virtio_pci_mmio_read8(base + offset);
}

void virtio_mmio_write32(uint64_t base, uint32_t offset, uint32_t value) {
  virtio_pci_mmio_write32(base + offset, value);
}

void virtio_mmio_barrier(void) { xaios_cpu_io_barrier(); }

static void set_status(const virtio_mmio_device_t *device, uint8_t status) {
  virtio_pci_mmio_write8(device->common_config + 20U, status);
  virtio_mmio_barrier();
}

xaios_status_t virtio_transport_reset_checked(
    const virtio_mmio_device_t *device) {
  if (device == 0 || device->common_config == 0U) return XAIOS_ERR_INVALID;
  set_status(device, 0U);
  uint64_t started = timer_now_ns();
  for (uint64_t spins = 0U;; ++spins) {
    if (virtio_pci_mmio_read8(device->common_config + 20U) == 0U) return XAIOS_OK;
    if ((spins & UINT64_C(0x3ff)) == 0U &&
        ((started != 0U && timer_now_ns() - started >= VIRTIO_RESET_TIMEOUT_NS) ||
         (started == 0U && spins >= VIRTIO_WAIT_FALLBACK_SPINS))) {
      return XAIOS_ERR_IO;
    }
    xaios_cpu_relax();
  }
}

void virtio_transport_reset(const virtio_mmio_device_t *device) {
  (void)virtio_transport_reset_checked(device);
}

xaios_status_t virtio_transport_negotiate_features(
    const virtio_mmio_device_t *device, uint32_t requested_low,
    uint32_t requested_high, uint32_t *accepted_low,
    uint32_t *accepted_high) {
  if (device == 0 || accepted_low == 0 || accepted_high == 0 ||
      virtio_transport_reset_checked(device) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  set_status(device, VIRTIO_PCI_STATUS_ACKNOWLEDGE);
  set_status(device, VIRTIO_PCI_STATUS_ACKNOWLEDGE | VIRTIO_PCI_STATUS_DRIVER);
  virtio_pci_mmio_write32(device->common_config + 0U, 0U);
  uint32_t available_low = virtio_pci_mmio_read32(device->common_config + 4U);
  virtio_pci_mmio_write32(device->common_config + 0U, 1U);
  uint32_t available_high = virtio_pci_mmio_read32(device->common_config + 4U);
  *accepted_low = available_low & requested_low;
  *accepted_high = available_high &
                   (requested_high | VIRTIO_PCI_VERSION_1_HIGH);
  if ((*accepted_high & VIRTIO_PCI_VERSION_1_HIGH) == 0U) {
    set_status(device, VIRTIO_PCI_STATUS_FAILED);
    return XAIOS_ERR_UNSUPPORTED;
  }
  virtio_pci_mmio_write32(device->common_config + 8U, 0U);
  virtio_pci_mmio_write32(device->common_config + 12U, *accepted_low);
  virtio_pci_mmio_write32(device->common_config + 8U, 1U);
  virtio_pci_mmio_write32(device->common_config + 12U, *accepted_high);
  set_status(device, VIRTIO_PCI_STATUS_ACKNOWLEDGE | VIRTIO_PCI_STATUS_DRIVER |
                         VIRTIO_PCI_STATUS_FEATURES_OK);
  if ((virtio_pci_mmio_read8(device->common_config + 20U) &
       VIRTIO_PCI_STATUS_FEATURES_OK) == 0U) {
    /* The device cleared FEATURES_OK, meaning it will not run with the set
       the driver chose. Report both sides: what it offered is the only way
       to tell which bit it insists on. */
    klog("%s: device rejected feature selection offered=0x%x:0x%x "
         "selected=0x%x:0x%x\n",
         device->name == 0 ? "virtio" : device->name, available_high,
         available_low, *accepted_high, *accepted_low);
    set_status(device, VIRTIO_PCI_STATUS_FAILED);
    return XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}

xaios_status_t virtio_transport_negotiate_no_features(
    const virtio_mmio_device_t *device) {
  uint32_t low = 0U;
  uint32_t high = 0U;
  return virtio_transport_negotiate_features(device, 0U,
                                             VIRTIO_PCI_VERSION_1_HIGH,
                                             &low, &high);
}

xaios_status_t virtio_transport_set_driver_ok_checked(
    const virtio_mmio_device_t *device) {
  if (device == 0) return XAIOS_ERR_INVALID;
  set_status(device, VIRTIO_PCI_STATUS_ACKNOWLEDGE | VIRTIO_PCI_STATUS_DRIVER |
                         VIRTIO_PCI_STATUS_FEATURES_OK |
                         VIRTIO_PCI_STATUS_DRIVER_OK);
  uint8_t status = virtio_pci_mmio_read8(device->common_config + 20U);
  return (status & (VIRTIO_PCI_STATUS_FEATURES_OK |
                    VIRTIO_PCI_STATUS_DRIVER_OK)) ==
                 (VIRTIO_PCI_STATUS_FEATURES_OK | VIRTIO_PCI_STATUS_DRIVER_OK)
             ? XAIOS_OK
             : XAIOS_ERR_IO;
}

void virtio_transport_set_driver_ok(const virtio_mmio_device_t *device) {
  (void)virtio_transport_set_driver_ok_checked(device);
}

uint32_t virtio_transport_device_status(const virtio_mmio_device_t *device) {
  if (device == 0 || device->common_config == 0U) return 0U;
  return virtio_pci_mmio_read8(device->common_config + 20U);
}

void virtio_transport_notify(const virtio_mmio_device_t *device,
                             uint32_t queue_index) {
  if (device == 0 || queue_index > UINT16_MAX) return;
  uint16_t offset;
  if (queue_index < VIRTIO_NOTIFY_SLOTS &&
      (device->notify_offset_valid & (UINT32_C(1) << queue_index)) != 0U) {
    offset = device->notify_offset[queue_index];
  } else {
    /* No cached offset, so fall back to asking. This touches the shared queue
       selector and is safe only while nothing else notifies this device. */
    virtio_pci_mmio_write16(device->common_config + 22U, (uint16_t)queue_index);
    offset = virtio_pci_mmio_read16(device->common_config + 30U);
  }
  virtio_mmio_barrier();
  virtio_pci_mmio_write16(device->notify_base +
                   (uint64_t)offset * device->notify_multiplier,
               (uint16_t)queue_index);
}

xaios_status_t virtio_transport_wait_used(volatile uint16_t *used_idx,
                                         uint16_t expected) {
  if (used_idx == 0) return XAIOS_ERR_INVALID;
  uint64_t started = timer_now_ns();
  for (uint64_t spins = 0U;; ++spins) {
    if (__atomic_load_n(used_idx, __ATOMIC_ACQUIRE) >= expected) {
      virtio_mmio_barrier();
      return XAIOS_OK;
    }
    if ((spins & UINT64_C(0x3ff)) == 0U &&
        ((started != 0U && timer_now_ns() - started >= VIRTIO_WAIT_TIMEOUT_NS) ||
         (started == 0U && spins >= VIRTIO_WAIT_FALLBACK_SPINS))) {
      return XAIOS_ERR_IO;
    }
    xaios_cpu_relax();
  }
}

void virtio_transport_ack_interrupts(const virtio_mmio_device_t *device) {
  if (device != 0 && device->isr_config != 0U) {
    (void)virtio_pci_mmio_read8(device->isr_config);
  }
}

uint32_t virtio_transport_interrupt_id(const virtio_mmio_device_t *device) {
  return device == 0 ? UINT32_MAX : device->interrupt_id;
}

xaios_status_t virtio_transport_register_interrupt(
    const virtio_mmio_device_t *device, virtio_interrupt_handler_t handler,
    void *context) {
  if (device == 0 || handler == 0) return XAIOS_ERR_INVALID;
  if (device->interrupt_configured == 0U) return XAIOS_ERR_UNSUPPORTED;
  uint32_t intid = virtio_transport_interrupt_id(device);
#if !defined(__x86_64__)
  /* An interrupt raised through the ITS arrives as an LPI, which is routed
     per CPU rather than through the distributor. The vector is left masked
     until a handler exists, so unmask it once one does. */
  xaios_status_t status = gic_register_lpi(intid, smp_cpu_id(), handler,
                                           context);
  if (status != XAIOS_OK) return status;
  status = pci_unmask_msix(device->transport_index, 0U);
  if (status != XAIOS_OK) {
    (void)gic_unregister_interrupt(intid, handler, context);
    return status;
  }
  return XAIOS_OK;
#else
  return gic_register_interrupt(intid, handler, context);
#endif
}

xaios_status_t virtio_transport_unregister_interrupt(
    const virtio_mmio_device_t *device, virtio_interrupt_handler_t handler,
    void *context) {
  if (device == 0 || handler == 0) return XAIOS_ERR_INVALID;
  return gic_unregister_interrupt(virtio_transport_interrupt_id(device),
                                  handler, context);
}

uint32_t virtio_transport_slot(const virtio_mmio_device_t *device) {
  return device == 0 ? UINT32_MAX : device->transport_slot;
}
