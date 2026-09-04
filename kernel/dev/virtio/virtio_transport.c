#ifdef XAIOS_VIRTIO_MMIO_BACKEND
/* Built as one of two backends behind virtio_transport_dispatch.c.
   The public names belong to the dispatcher, so take private ones. */
#define virtio_mmio_read32 virtio_mmio_backend_mmio_read32
#define virtio_mmio_read8 virtio_mmio_backend_mmio_read8
#define virtio_mmio_write32 virtio_mmio_backend_mmio_write32
#define virtio_mmio_barrier virtio_mmio_backend_mmio_barrier
#define virtio_transport_find virtio_mmio_backend_transport_find
#define virtio_transport_find_from virtio_mmio_backend_transport_find_from
#define virtio_transport_find_at virtio_mmio_backend_transport_find_at
#define virtio_transport_find_nth virtio_mmio_backend_transport_find_nth
#define virtio_transport_setup_queue_vectored virtio_mmio_backend_transport_setup_queue_vectored
#define virtio_transport_queue_has_vector virtio_mmio_backend_transport_queue_has_vector
#define virtio_transport_register_queue_interrupt virtio_mmio_backend_transport_register_queue_interrupt
#define virtio_transport_reset virtio_mmio_backend_transport_reset
#define virtio_transport_reset_checked virtio_mmio_backend_transport_reset_checked
#define virtio_transport_negotiate_no_features virtio_mmio_backend_transport_negotiate_no_features
#define virtio_transport_negotiate_features virtio_mmio_backend_transport_negotiate_features
#define virtio_transport_setup_queue virtio_mmio_backend_transport_setup_queue
#define virtio_transport_set_driver_ok virtio_mmio_backend_transport_set_driver_ok
#define virtio_transport_set_driver_ok_checked virtio_mmio_backend_transport_set_driver_ok_checked
#define virtio_transport_notify virtio_mmio_backend_transport_notify
#define virtio_transport_wait_used virtio_mmio_backend_transport_wait_used
#define virtio_transport_device_status virtio_mmio_backend_transport_device_status
#define virtio_transport_ack_interrupts virtio_mmio_backend_transport_ack_interrupts
#define virtio_transport_interrupt_id virtio_mmio_backend_transport_interrupt_id
#define virtio_transport_register_interrupt virtio_mmio_backend_transport_register_interrupt
#define virtio_transport_unregister_interrupt virtio_mmio_backend_transport_unregister_interrupt
#define virtio_transport_slot virtio_mmio_backend_transport_slot
#endif

#include <xaios/arch_cpu.h>
#include <xaios/assert.h>
#include <xaios/gic.h>
#include <xaios/klog.h>
#include <xaios/timer.h>
#include <xaios/virtio_transport.h>
#include <xaios/vmm.h>

/* Where the virtio-mmio slots are, and how far apart.
 *
 * These were constants naming one board's layout: 0x0a000000 with a 0x200
 * stride is QEMU's AArch64 `virt`. QEMU's RISC-V `virt` puts them at
 * 0x10001000 with a 0x1000 stride, so a kernel carrying the constant took a
 * load access fault the first time it probed for a device -- on hardware
 * that has virtio, at an address that does not.
 *
 * A default keeps every existing caller unchanged, and an architecture that
 * knows better says so before probing. This is the same rule the rest of the
 * codebase follows and this file had quietly opted out of: firmware supplies
 * the address, the driver does not assume it. */
#define VIRTIO_MMIO_DEFAULT_BASE UINT64_C(0x0a000000)
#define VIRTIO_MMIO_DEFAULT_STRIDE UINT64_C(0x200)
#define VIRTIO_MMIO_SLOT_LIMIT 32U
#define VIRTIO_MMIO_SLOTS g_virtio_mmio_slots

static uint64_t g_virtio_mmio_base = VIRTIO_MMIO_DEFAULT_BASE;
static uint64_t g_virtio_mmio_stride = VIRTIO_MMIO_DEFAULT_STRIDE;
static uint32_t g_virtio_mmio_slots = VIRTIO_MMIO_SLOT_LIMIT;

/* The slot count matters as much as the base. Probing a slot that does not
   exist reads an unassigned physical address, and a machine that faults on
   those -- RISC-V does -- takes a load access fault instead of reading the
   zero an absent device would give. AArch64's board happens to present all
   thirty-two, which is why a fixed count survived this long. */
void virtio_transport_set_mmio_window(uint64_t base, uint64_t stride,
                                      uint32_t slots) {
  /* Zero slots means this machine has no MMIO virtio window, which is a
     different statement from "leave the default alone" and has to be
     expressible: firmware that publishes no device tree leaves a caller
     unable to discover a window, and the compiled-in default belongs to
     another board. Scanning it there is a load access fault, not an empty
     slot. */
  if (slots == 0U) {
    g_virtio_mmio_slots = 0U;
    return;
  }
  if (base == 0U || stride == 0U) return;
  g_virtio_mmio_base = base;
  g_virtio_mmio_stride = stride;
  g_virtio_mmio_slots = slots > VIRTIO_MMIO_SLOT_LIMIT ? VIRTIO_MMIO_SLOT_LIMIT
                                                       : slots;
}

#define VIRTIO_MMIO_BASE g_virtio_mmio_base
#define VIRTIO_MMIO_STRIDE g_virtio_mmio_stride
/* Where this board's virtio-mmio interrupts start.
 *
 * 48 is the first shared peripheral interrupt on AArch64's GIC, and it was
 * compiled in as though every machine numbered them that way. RISC-V's PLIC
 * starts them at 1, so a driver that registered at 48 asked the controller
 * about a source that does not exist, got nothing, and fell back to polling
 * every completion -- which works, says so, and is several times slower than
 * the machine can go. */
static uint32_t g_virtio_mmio_first_intid = 48U;

void virtio_transport_set_mmio_interrupt_base(uint32_t first_intid) {
  g_virtio_mmio_first_intid = first_intid;
}

#define VIRTIO_MMIO_FIRST_INTID g_virtio_mmio_first_intid
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
      device->common_config = base;
      device->notify_base = base;
      device->isr_config = base;
      device->notify_multiplier = 0U;
      device->transport_slot = slot;
      device->interrupt_id = VIRTIO_MMIO_FIRST_INTID + slot;
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

/* The nth device of this type that is actually present, counted over the
   windows that answer rather than over the address space. The slot-addressed
   lookups above ask "what is in this window", which is the right question on a
   machine whose layout is fixed and known -- the test bench pins each volume
   to a window on purpose. It is the wrong question on a machine XAIOS has been
   installed onto, where the only thing known about the disk is that it exists.

   The caller names the device through logical_slot; the interrupt still comes
   from the window the device really occupies. */
xaios_status_t virtio_transport_find_nth(uint32_t device_id, const char *name,
                                         uint32_t ordinal,
                                         uint32_t logical_slot,
                                         virtio_mmio_device_t *device) {
  if (device == 0 || name == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t seen = 0U;
  for (uint32_t slot = 0U; slot < VIRTIO_MMIO_SLOTS; ++slot) {
    uint64_t base = VIRTIO_MMIO_BASE + (slot * VIRTIO_MMIO_STRIDE);
    if (virtio_mmio_read32(base, VIRTIO_MMIO_MAGIC) != VIRTIO_MAGIC ||
        virtio_mmio_read32(base, VIRTIO_MMIO_VERSION) < 2U ||
        virtio_mmio_read32(base, VIRTIO_MMIO_DEVICE_ID) != device_id) {
      continue;
    }
    if (seen++ != ordinal) continue;
    device->base = base;
    device->common_config = base;
    device->notify_base = base;
    device->isr_config = base;
    device->notify_multiplier = 0U;
    device->transport_slot = logical_slot;
    device->interrupt_id = VIRTIO_MMIO_FIRST_INTID + slot;
    device->device_id = device_id;
    device->name = name;
    klog("%s: mmio ordinal=%u window=%u slot=%u base=0x%lx\n", name, ordinal,
         slot, logical_slot, base);
    return XAIOS_OK;
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
  device->common_config = base;
  device->notify_base = base;
  device->isr_config = base;
  device->notify_multiplier = 0U;
  device->transport_slot = slot;
  device->interrupt_id = VIRTIO_MMIO_FIRST_INTID + slot;
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

xaios_status_t virtio_transport_setup_queue(virtio_mmio_device_t *device,
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

uint32_t virtio_transport_device_status(const virtio_mmio_device_t *device) {
  if (device == 0) return 0U;
  return virtio_mmio_read32(device->base, VIRTIO_MMIO_STATUS);
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
  return device == 0 ? UINT32_MAX : device->interrupt_id;
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

uint32_t virtio_transport_slot(const virtio_mmio_device_t *device) {
  return device == 0 ? UINT32_MAX : device->transport_slot;
}

/* virtio-MMIO has one interrupt line for the whole device, so a queue cannot
   have a vector of its own here. Setting up such a queue is the ordinary setup;
   asking whether it has its own interrupt is answered no, and registering one
   is refused. A driver that wants steering has to be on PCI, and finds that out
   by asking rather than by an interrupt that never arrives. */
xaios_status_t virtio_transport_setup_queue_vectored(
    virtio_mmio_device_t *device, uint32_t queue_index, uint32_t queue_size,
    virtq_desc_t *desc, virtq_avail_t *avail, virtq_used_t *used) {
  return virtio_transport_setup_queue(device, queue_index, queue_size, desc,
                                      avail, used);
}

uint32_t virtio_transport_queue_has_vector(const virtio_mmio_device_t *device,
                                           uint32_t queue_index) {
  (void)device;
  (void)queue_index;
  return 0U;
}

xaios_status_t virtio_transport_register_queue_interrupt(
    const virtio_mmio_device_t *device, uint32_t queue_index,
    virtio_interrupt_handler_t handler, void *context) {
  (void)device;
  (void)queue_index;
  (void)handler;
  (void)context;
  return XAIOS_ERR_UNSUPPORTED;
}
