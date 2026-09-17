#include "virtio_transport_internal.h"

/* The device status / reset / feature-negotiation sequence of the virtio-MMIO
   transport, split out of virtio_transport.c. Every entry point here was
   already exported to the dispatcher; the register map and the backend rename
   block that make those names private live in virtio_transport_internal.h.
   The bodies are unchanged and the order of the status transitions they write
   is exactly what it was. */

static void set_status(const virtio_mmio_device_t *device, uint32_t status) {
  virtio_mmio_write32(device->base, VIRTIO_MMIO_STATUS, status);
  virtio_mmio_barrier();
}

void virtio_transport_reset(const virtio_mmio_device_t *device) {
  (void)virtio_transport_reset_checked(device);
}

xaios_status_t virtio_transport_reset_checked(
    const virtio_mmio_device_t *device) {
  if (device == 0 || device->base == 0U) return XAIOS_ERR_INVALID;
  set_status(device, 0U);
  uint64_t started = timer_now_ns();
  for (uint64_t spins = 0U;; ++spins) {
    if (virtio_mmio_read32(device->base, VIRTIO_MMIO_STATUS) == 0U) {
      return XAIOS_OK;
    }
    if ((spins & UINT64_C(0x3ff)) == 0U &&
        ((started != 0U && timer_now_ns() - started >= VIRTIO_RESET_TIMEOUT_NS) ||
         (started == 0U && spins >= VIRTIO_WAIT_FALLBACK_SPINS))) {
      return XAIOS_ERR_IO;
    }
    xaios_cpu_relax();
  }
}

xaios_status_t virtio_transport_negotiate_no_features(
    const virtio_mmio_device_t *device) {
  if (virtio_transport_reset_checked(device) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  set_status(device, VIRTIO_STATUS_ACKNOWLEDGE);
  set_status(device, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);

  virtio_mmio_write32(device->base, VIRTIO_MMIO_DEVICE_FEATURES_SEL, 0);
  virtio_mmio_write32(device->base, VIRTIO_MMIO_DRIVER_FEATURES_SEL, 0);
  virtio_mmio_write32(device->base, VIRTIO_MMIO_DRIVER_FEATURES, 0);
  set_status(device, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER |
                         VIRTIO_STATUS_FEATURES_OK);
  uint32_t status = virtio_mmio_read32(device->base, VIRTIO_MMIO_STATUS);
  if ((status & VIRTIO_STATUS_FEATURES_OK) == 0) {
    set_status(device, status | VIRTIO_STATUS_FAILED);
    return XAIOS_ERR_IO;
  }

  return XAIOS_OK;
}

xaios_status_t virtio_transport_negotiate_features(
    const virtio_mmio_device_t *device, uint32_t requested_low,
    uint32_t requested_high, uint32_t *accepted_low,
    uint32_t *accepted_high) {
  if (device == 0 || accepted_low == 0 || accepted_high == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (virtio_transport_reset_checked(device) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  set_status(device, VIRTIO_STATUS_ACKNOWLEDGE);
  set_status(device, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER);
  virtio_mmio_write32(device->base, VIRTIO_MMIO_DEVICE_FEATURES_SEL, 0U);
  uint32_t available_low =
      virtio_mmio_read32(device->base, VIRTIO_MMIO_DEVICE_FEATURES);
  virtio_mmio_write32(device->base, VIRTIO_MMIO_DEVICE_FEATURES_SEL, 1U);
  uint32_t available_high =
      virtio_mmio_read32(device->base, VIRTIO_MMIO_DEVICE_FEATURES);
  *accepted_low = available_low & requested_low;
  *accepted_high = available_high & requested_high;
  virtio_mmio_write32(device->base, VIRTIO_MMIO_DRIVER_FEATURES_SEL, 0U);
  virtio_mmio_write32(device->base, VIRTIO_MMIO_DRIVER_FEATURES,
                      *accepted_low);
  virtio_mmio_write32(device->base, VIRTIO_MMIO_DRIVER_FEATURES_SEL, 1U);
  virtio_mmio_write32(device->base, VIRTIO_MMIO_DRIVER_FEATURES,
                      *accepted_high);
  set_status(device, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER |
                         VIRTIO_STATUS_FEATURES_OK);
  uint32_t status = virtio_mmio_read32(device->base, VIRTIO_MMIO_STATUS);
  if ((status & VIRTIO_STATUS_FEATURES_OK) == 0U) {
    set_status(device, status | VIRTIO_STATUS_FAILED);
    return XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}

void virtio_transport_set_driver_ok(const virtio_mmio_device_t *device) {
  (void)virtio_transport_set_driver_ok_checked(device);
}

xaios_status_t virtio_transport_set_driver_ok_checked(
    const virtio_mmio_device_t *device) {
  if (device == 0) return XAIOS_ERR_INVALID;
  set_status(device, VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER |
                         VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK);
  uint32_t status = virtio_mmio_read32(device->base, VIRTIO_MMIO_STATUS);
  return (status & (VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK)) ==
                 (VIRTIO_STATUS_FEATURES_OK | VIRTIO_STATUS_DRIVER_OK)
             ? XAIOS_OK
             : XAIOS_ERR_IO;
}
