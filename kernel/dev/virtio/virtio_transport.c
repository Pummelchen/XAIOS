#include <xaios/arch_cpu.h>
#include <xaios/assert.h>
#include <xaios/gic.h>
#include <xaios/klog.h>
#include <xaios/timer.h>
#include <xaios/virtio_transport.h>
#include <xaios/vmm.h>

#define VIRTIO_MMIO_BASE UINT64_C(0x0a000000)
#define VIRTIO_MMIO_STRIDE UINT64_C(0x200)
#define VIRTIO_MMIO_SLOTS 32U
#define VIRTIO_MMIO_FIRST_INTID 48U
#define VIRTIO_WAIT_TIMEOUT_NS UINT64_C(5000000000)
#define VIRTIO_WAIT_FALLBACK_SPINS UINT64_C(100000000)
#define VIRTIO_RESET_TIMEOUT_NS UINT64_C(1000000000)

#define VIRTIO_MMIO_MAGIC 0x000U
#define VIRTIO_MMIO_VERSION 0x004U
#define VIRTIO_MMIO_DEVICE_ID 0x008U
#define VIRTIO_MMIO_VENDOR_ID 0x00cU
#define VIRTIO_MMIO_DEVICE_FEATURES 0x010U
#define VIRTIO_MMIO_DEVICE_FEATURES_SEL 0x014U
#define VIRTIO_MMIO_DRIVER_FEATURES 0x020U
#define VIRTIO_MMIO_DRIVER_FEATURES_SEL 0x024U
#define VIRTIO_MMIO_QUEUE_SEL 0x030U
#define VIRTIO_MMIO_QUEUE_NUM_MAX 0x034U
#define VIRTIO_MMIO_QUEUE_NUM 0x038U
#define VIRTIO_MMIO_QUEUE_READY 0x044U
#define VIRTIO_MMIO_QUEUE_NOTIFY 0x050U
#define VIRTIO_MMIO_INTERRUPT_STATUS 0x060U
#define VIRTIO_MMIO_INTERRUPT_ACK 0x064U
#define VIRTIO_MMIO_STATUS 0x070U
#define VIRTIO_MMIO_QUEUE_DESC_LOW 0x080U
#define VIRTIO_MMIO_QUEUE_DESC_HIGH 0x084U
#define VIRTIO_MMIO_QUEUE_DRIVER_LOW 0x090U
#define VIRTIO_MMIO_QUEUE_DRIVER_HIGH 0x094U
#define VIRTIO_MMIO_QUEUE_DEVICE_LOW 0x0a0U
#define VIRTIO_MMIO_QUEUE_DEVICE_HIGH 0x0a4U

#define VIRTIO_MAGIC UINT32_C(0x74726976)

#define VIRTIO_STATUS_ACKNOWLEDGE UINT32_C(1)
#define VIRTIO_STATUS_DRIVER UINT32_C(2)
#define VIRTIO_STATUS_DRIVER_OK UINT32_C(4)
#define VIRTIO_STATUS_FEATURES_OK UINT32_C(8)
#define VIRTIO_STATUS_FAILED UINT32_C(128)

uint32_t virtio_mmio_read32(uint64_t base, uint32_t offset) {
  volatile uint32_t *reg = (volatile uint32_t *)(uintptr_t)(base + offset);
  return *reg;
}

uint8_t virtio_mmio_read8(uint64_t base, uint32_t offset) {
  volatile uint8_t *reg = (volatile uint8_t *)(uintptr_t)(base + offset);
  return *reg;
}

void virtio_mmio_write32(uint64_t base, uint32_t offset, uint32_t value) {
  volatile uint32_t *reg = (volatile uint32_t *)(uintptr_t)(base + offset);
  *reg = value;
}

void virtio_mmio_barrier(void) {
  xaios_cpu_io_barrier();
}

static void write_addr_pair(uint64_t base, uint32_t low_offset,
                            uint32_t high_offset, uint64_t address) {
  virtio_mmio_write32(base, low_offset,
                      (uint32_t)(address & UINT64_C(0xffffffff)));
  virtio_mmio_write32(base, high_offset, (uint32_t)(address >> 32U));
}

static uint64_t dma_address(const void *ptr) {
  uint64_t physical = 0;
  uint32_t flags = 0;
  kassert(vmm_translate((uint64_t)(uintptr_t)ptr, &physical, &flags) == XAIOS_OK);
  kassert((flags & XAIOS_VMM_PRESENT) != 0);
  return physical;
}

static void set_status(const virtio_mmio_device_t *device, uint32_t status) {
  virtio_mmio_write32(device->base, VIRTIO_MMIO_STATUS, status);
  virtio_mmio_barrier();
}

xaios_status_t virtio_transport_find(uint32_t device_id, const char *name,
                                    virtio_mmio_device_t *device) {
  return virtio_transport_find_from(device_id, name, 0, device);
}

xaios_status_t virtio_transport_find_from(uint32_t device_id, const char *name,
                                         uint32_t start_slot,
                                         virtio_mmio_device_t *device) {
  if (device == 0 || name == 0) {
    return XAIOS_ERR_INVALID;
  }

  for (uint32_t slot = start_slot; slot < VIRTIO_MMIO_SLOTS; ++slot) {
    uint64_t base = VIRTIO_MMIO_BASE + (slot * VIRTIO_MMIO_STRIDE);
    uint32_t magic = virtio_mmio_read32(base, VIRTIO_MMIO_MAGIC);
    uint32_t version = virtio_mmio_read32(base, VIRTIO_MMIO_VERSION);
    uint32_t found_id = virtio_mmio_read32(base, VIRTIO_MMIO_DEVICE_ID);
    if (magic == VIRTIO_MAGIC && version >= 2 && found_id == device_id) {
      device->base = base;
      device->device_id = device_id;
      device->name = name;
      klog("%s: mmio base=0x%lx version=%u vendor=0x%x\n",
           name, base, version,
           virtio_mmio_read32(base, VIRTIO_MMIO_VENDOR_ID));
      return XAIOS_OK;
    }
  }

  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t virtio_transport_find_at(uint32_t device_id, const char *name,
                                       uint32_t slot,
                                       virtio_mmio_device_t *device) {
  if (device == 0 || name == 0 || slot >= VIRTIO_MMIO_SLOTS) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t base = VIRTIO_MMIO_BASE + (slot * VIRTIO_MMIO_STRIDE);
  uint32_t magic = virtio_mmio_read32(base, VIRTIO_MMIO_MAGIC);
  uint32_t version = virtio_mmio_read32(base, VIRTIO_MMIO_VERSION);
  uint32_t found_id = virtio_mmio_read32(base, VIRTIO_MMIO_DEVICE_ID);
  if (magic != VIRTIO_MAGIC || version < 2U || found_id != device_id) {
    return XAIOS_ERR_NOT_FOUND;
  }
  device->base = base;
  device->device_id = device_id;
  device->name = name;
  klog("%s: mmio slot=%u base=0x%lx version=%u vendor=0x%x\n", name, slot,
       base, version, virtio_mmio_read32(base, VIRTIO_MMIO_VENDOR_ID));
  return XAIOS_OK;
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

xaios_status_t virtio_transport_setup_queue(const virtio_mmio_device_t *device,
                                           uint32_t queue_index,
                                           uint32_t queue_size,
                                           virtq_desc_t *desc,
                                           virtq_avail_t *avail,
                                           virtq_used_t *used) {
  if (device == 0 || queue_size == 0 || queue_size > VIRTQ_SIZE ||
      (queue_size & (queue_size - 1U)) != 0U || desc == 0 || avail == 0 ||
      used == 0) {
    return XAIOS_ERR_INVALID;
  }

  virtio_mmio_write32(device->base, VIRTIO_MMIO_QUEUE_SEL, queue_index);
  uint32_t queue_max = virtio_mmio_read32(device->base,
                                          VIRTIO_MMIO_QUEUE_NUM_MAX);
  if (queue_max < queue_size ||
      virtio_mmio_read32(device->base, VIRTIO_MMIO_QUEUE_READY) != 0U) {
    return XAIOS_ERR_INVALID;
  }

  virtio_mmio_write32(device->base, VIRTIO_MMIO_QUEUE_NUM, queue_size);
  write_addr_pair(device->base, VIRTIO_MMIO_QUEUE_DESC_LOW,
                  VIRTIO_MMIO_QUEUE_DESC_HIGH, dma_address(desc));
  write_addr_pair(device->base, VIRTIO_MMIO_QUEUE_DRIVER_LOW,
                  VIRTIO_MMIO_QUEUE_DRIVER_HIGH, dma_address(avail));
  write_addr_pair(device->base, VIRTIO_MMIO_QUEUE_DEVICE_LOW,
                  VIRTIO_MMIO_QUEUE_DEVICE_HIGH, dma_address(used));
  virtio_mmio_write32(device->base, VIRTIO_MMIO_QUEUE_READY, 1);
  virtio_mmio_barrier();
  return virtio_mmio_read32(device->base, VIRTIO_MMIO_QUEUE_READY) == 1U
             ? XAIOS_OK
             : XAIOS_ERR_IO;
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

void virtio_transport_notify(const virtio_mmio_device_t *device,
                             uint32_t queue_index) {
  virtio_mmio_barrier();
  virtio_mmio_write32(device->base, VIRTIO_MMIO_QUEUE_NOTIFY, queue_index);
}

xaios_status_t virtio_transport_wait_used(volatile uint16_t *used_idx,
                                         uint16_t expected) {
  uint64_t started_ns = timer_now_ns();
  for (uint64_t spin = 0;; ++spin) {
    if (*used_idx >= expected) {
      /* Device writes to the used ring and request buffers precede idx. */
      virtio_mmio_barrier();
      return XAIOS_OK;
    }
    if ((spin & UINT64_C(0x3ff)) == 0U) {
      if (started_ns != 0U) {
        if (timer_now_ns() - started_ns >= VIRTIO_WAIT_TIMEOUT_NS) {
          return XAIOS_ERR_IO;
        }
      } else if (spin >= VIRTIO_WAIT_FALLBACK_SPINS) {
        return XAIOS_ERR_IO;
      }
    }
    xaios_cpu_relax();
  }
}

void virtio_transport_ack_interrupts(const virtio_mmio_device_t *device) {
  uint32_t interrupt_status = virtio_mmio_read32(device->base,
                                                 VIRTIO_MMIO_INTERRUPT_STATUS);
  if (interrupt_status != 0) {
    virtio_mmio_write32(device->base, VIRTIO_MMIO_INTERRUPT_ACK,
                        interrupt_status);
  }
}

uint32_t virtio_transport_interrupt_id(const virtio_mmio_device_t *device) {
  if (device == 0 || device->base < VIRTIO_MMIO_BASE ||
      (device->base - VIRTIO_MMIO_BASE) % VIRTIO_MMIO_STRIDE != 0U) {
    return UINT32_MAX;
  }
  uint64_t slot = (device->base - VIRTIO_MMIO_BASE) / VIRTIO_MMIO_STRIDE;
  if (slot >= VIRTIO_MMIO_SLOTS) return UINT32_MAX;
  return VIRTIO_MMIO_FIRST_INTID + (uint32_t)slot;
}

xaios_status_t virtio_transport_register_interrupt(
    const virtio_mmio_device_t *device, virtio_interrupt_handler_t handler,
    void *context) {
  uint32_t intid = virtio_transport_interrupt_id(device);
  if (intid == UINT32_MAX) return XAIOS_ERR_INVALID;
  return gic_register_interrupt(intid, handler, context);
}

xaios_status_t virtio_transport_unregister_interrupt(
    const virtio_mmio_device_t *device, virtio_interrupt_handler_t handler,
    void *context) {
  uint32_t intid = virtio_transport_interrupt_id(device);
  if (intid == UINT32_MAX) return XAIOS_ERR_INVALID;
  return gic_unregister_interrupt(intid, handler, context);
}
