#ifndef XAIOS_VIRTIO_TRANSPORT_H
#define XAIOS_VIRTIO_TRANSPORT_H

#include <xaios/status.h>
#include <xaios/types.h>

#define VIRTQ_SIZE 8U

#define VIRTIO_DEVICE_NET UINT32_C(1)
#define VIRTIO_DEVICE_BLOCK UINT32_C(2)
#define VIRTIO_DEVICE_RNG UINT32_C(4)

typedef struct virtq_desc {
  uint64_t addr;
  uint32_t len;
  uint16_t flags;
  uint16_t next;
} virtq_desc_t;

typedef struct virtq_avail {
  uint16_t flags;
  uint16_t idx;
  uint16_t ring[VIRTQ_SIZE];
  uint16_t used_event;
} virtq_avail_t;

typedef struct virtq_used_elem {
  uint32_t id;
  uint32_t len;
} virtq_used_elem_t;

typedef struct virtq_used {
  uint16_t flags;
  uint16_t idx;
  virtq_used_elem_t ring[VIRTQ_SIZE];
  uint16_t avail_event;
} virtq_used_t;

typedef struct virtio_mmio_device {
  uint64_t base;
  uint64_t common_config;
  uint64_t notify_base;
  uint64_t isr_config;
  uint32_t notify_multiplier;
  uint32_t transport_slot;
  uint32_t transport_index;
  uint32_t interrupt_id;
  uint32_t interrupt_configured;
  uint32_t device_id;
  const char *name;
} virtio_mmio_device_t;

typedef void (*virtio_interrupt_handler_t)(uint32_t intid, void *context);

uint32_t virtio_mmio_read32(uint64_t base, uint32_t offset);
uint8_t virtio_mmio_read8(uint64_t base, uint32_t offset);
void virtio_mmio_write32(uint64_t base, uint32_t offset, uint32_t value);
void virtio_mmio_barrier(void);
xaios_status_t virtio_transport_find(uint32_t device_id, const char *name,
                                    virtio_mmio_device_t *device);
xaios_status_t virtio_transport_find_from(uint32_t device_id, const char *name,
                                         uint32_t start_slot,
                                         virtio_mmio_device_t *device);
xaios_status_t virtio_transport_find_at(uint32_t device_id, const char *name,
                                       uint32_t slot,
                                       virtio_mmio_device_t *device);
void virtio_transport_reset(const virtio_mmio_device_t *device);
xaios_status_t virtio_transport_reset_checked(
    const virtio_mmio_device_t *device);
xaios_status_t virtio_transport_negotiate_no_features(
    const virtio_mmio_device_t *device);
xaios_status_t virtio_transport_negotiate_features(
    const virtio_mmio_device_t *device, uint32_t requested_low,
    uint32_t requested_high, uint32_t *accepted_low,
    uint32_t *accepted_high);
xaios_status_t virtio_transport_setup_queue(virtio_mmio_device_t *device,
                                           uint32_t queue_index,
                                           uint32_t queue_size,
                                           virtq_desc_t *desc,
                                           virtq_avail_t *avail,
                                           virtq_used_t *used);
void virtio_transport_set_driver_ok(const virtio_mmio_device_t *device);
xaios_status_t virtio_transport_set_driver_ok_checked(
    const virtio_mmio_device_t *device);
void virtio_transport_notify(const virtio_mmio_device_t *device,
                             uint32_t queue_index);
xaios_status_t virtio_transport_wait_used(volatile uint16_t *used_idx,
                                         uint16_t expected);
void virtio_transport_ack_interrupts(const virtio_mmio_device_t *device);
uint32_t virtio_transport_interrupt_id(const virtio_mmio_device_t *device);
xaios_status_t virtio_transport_register_interrupt(
    const virtio_mmio_device_t *device, virtio_interrupt_handler_t handler,
    void *context);
xaios_status_t virtio_transport_unregister_interrupt(
    const virtio_mmio_device_t *device, virtio_interrupt_handler_t handler,
    void *context);
uint32_t virtio_transport_slot(const virtio_mmio_device_t *device);

#endif
