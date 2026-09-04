#ifndef XAIOS_VIRTIO_TRANSPORT_H
#define XAIOS_VIRTIO_TRANSPORT_H

#include <xaios/arch_cpu.h>
#include <xaios/status.h>
#include <xaios/timer.h>
#include <xaios/types.h>

#define VIRTQ_SIZE 8U

#define VIRTIO_DEVICE_NET UINT32_C(1)
#define VIRTIO_DEVICE_BLOCK UINT32_C(2)
#define VIRTIO_DEVICE_CONSOLE UINT32_C(3)
#define VIRTIO_DEVICE_RNG UINT32_C(4)
#define VIRTIO_DEVICE_GPU UINT32_C(16)

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

/* Queue indices any driver here uses. virtio-net asks for a receive and a
   transmit queue per pair plus a control queue; the rest use one. */
#define VIRTIO_NOTIFY_SLOTS 16U

/* How many receive/transmit pairs a driver may ask this transport to steer
   independently. Each pair costs an MSI-X table entry and, on aarch64, an LPI,
   so this is a ceiling on what a device may consume rather than a target. */
#define VIRTIO_MAX_QUEUE_PAIRS 4U

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
  /* Which transport found this device. aarch64 can see both: QEMU presents
     virtio over MMIO, Virtualization.framework and real PCIe hardware over
     PCI. Set by virtio_transport_find and honoured by every later call. */
  uint32_t backend;
  /* queue_notify_off per queue, captured while the queue is selected during
     setup. Notification used to select the queue and read this back on every
     call, but queue_select is shared device state: two CPUs notifying
     different queues of the same device can interleave there, and the loser
     reads an offset belonging to the other queue. Nothing could reach that
     before secondary CPUs actually ran. */
  uint16_t notify_offset[VIRTIO_NOTIFY_SLOTS];
  uint32_t notify_offset_valid;
  /* One interrupt per queue, for a device that asked for them.

     interrupt_id above is the device's single vector, which is what every
     driver here used and what a device with one queue pair needs. Steering
     traffic across queues needs each queue to raise its own interrupt: one
     vector shared by four queues tells a handler that something happened
     somewhere, which is exactly what multiple queues exist to avoid.

     Empty unless a driver called the vectored setup, so nothing that did not
     ask for this pays for it -- an LPI per queue is a real cost on a machine
     with several devices. */
  uint32_t queue_interrupt_id[VIRTIO_NOTIFY_SLOTS];
  uint32_t queue_interrupt_configured;
  const char *name;
} virtio_mmio_device_t;

#define VIRTIO_BACKEND_MMIO UINT32_C(0)
#define VIRTIO_BACKEND_PCI UINT32_C(1)

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
/* The nth device of this type that is present on either transport, named by
   logical_slot. Use this when the machine's disk layout is not known ahead of
   time; the slot-addressed lookups above assume the test bench's. */
xaios_status_t virtio_transport_find_nth(uint32_t device_id, const char *name,
                                        uint32_t ordinal,
                                        uint32_t logical_slot,
                                        virtio_mmio_device_t *device);
/* The nth PCI device of this type, ignoring the MMIO window. A machine boots
   from a PCI disk, and counting across both transports cannot address it when
   an MMIO device is also present. */
xaios_status_t virtio_transport_find_nth_pci(uint32_t device_id,
                                            const char *name,
                                            uint32_t ordinal,
                                            uint32_t logical_slot,
                                            virtio_mmio_device_t *device);

/*
 * Set up a queue that raises its own interrupt, rather than sharing the
 * device's single vector.
 *
 * Identical to virtio_transport_setup_queue except for the MSI-X table entry
 * it programs. Falls back to the shared vector when per-queue vectors are not
 * available -- a device with fewer table entries than queues, or a transport
 * with no MSI-X at all -- so a driver that asks for this still works where it
 * cannot be given, and can ask afterwards what it got.
 */
xaios_status_t virtio_transport_setup_queue_vectored(
    virtio_mmio_device_t *device, uint32_t queue_index, uint32_t queue_size,
    virtq_desc_t *desc, virtq_avail_t *avail, virtq_used_t *used);

/* Whether that queue ended up with an interrupt of its own. */
uint32_t virtio_transport_queue_has_vector(const virtio_mmio_device_t *device,
                                           uint32_t queue_index);

/* Register a handler for one queue's own interrupt. */
xaios_status_t virtio_transport_register_queue_interrupt(
    const virtio_mmio_device_t *device, uint32_t queue_index,
    virtio_interrupt_handler_t handler, void *context);
void virtio_transport_reset(const virtio_mmio_device_t *device);
/* The device's own status byte. Worth reading when a queue stops completing:
   bit 6, DEVICE_NEEDS_RESET, is the device saying it has given up, which
   distinguishes a device that failed from a notification that never landed.
   Reads nothing that clears on read. */
uint32_t virtio_transport_device_status(const virtio_mmio_device_t *device);
xaios_status_t virtio_transport_reset_checked(
    const virtio_mmio_device_t *device);
/* Tell the MMIO transport where this board's virtio slots are, before
   anything probes. Unset means QEMU's AArch64 layout, which is what every
   caller assumed when it was a constant. */
/* The interrupt the first MMIO slot is wired to. Boards number these
   differently and the default is AArch64's; a board that starts elsewhere
   must say so or its drivers fall back to polling. */
void virtio_transport_set_mmio_interrupt_base(uint32_t first_intid);

void virtio_transport_set_mmio_window(uint64_t base, uint64_t stride,
                                      uint32_t slots);
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

/*
 * Wait for a queue to complete, ringing its doorbell again while waiting.
 *
 * A driver that notifies once and then polls has no way back if that
 * notification does not register: the device is never told again, and the wait
 * can only expire. That is not theoretical. It wedged virtio-net about one boot
 * in eighteen, caught with the device reporting DRIVER_OK, no NEEDS_RESET, and
 * a buffer offered on each queue that it never consumed -- a device with
 * nothing to react to rather than a device that failed. The same shape in the
 * block driver lost a filesystem metadata write under load.
 *
 * The specification lets a driver notify whenever it likes, so a redundant ring
 * costs one MMIO write while a lost one costs a request. Every virtio wait here
 * uses this.
 */
#define VIRTIO_RENOTIFY_NS UINT64_C(200000000)
#define VIRTIO_WAIT_NS UINT64_C(5000000000)

static inline xaios_status_t virtio_transport_wait_used_notifying(
    const virtio_mmio_device_t *device, uint32_t queue_index,
    volatile uint16_t *used_idx, uint16_t expected) {
  uint64_t started = timer_now_ns();
  if (started == 0U) {
    /* No usable clock, so the cadence cannot be paced; the transport's own
       spin-bounded wait is the honest fallback. */
    return virtio_transport_wait_used(used_idx, expected);
  }
  uint64_t last_notify = started;
  for (;;) {
    if (__atomic_load_n(used_idx, __ATOMIC_ACQUIRE) >= expected) {
      virtio_mmio_barrier();
      return XAIOS_OK;
    }
    uint64_t now = timer_now_ns();
    if (now - started >= VIRTIO_WAIT_NS) return XAIOS_ERR_IO;
    if (now - last_notify >= VIRTIO_RENOTIFY_NS) {
      virtio_transport_notify(device, queue_index);
      last_notify = now;
    }
    xaios_cpu_relax();
  }
}

#endif
