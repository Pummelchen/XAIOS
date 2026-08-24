#ifdef XAIOS_VIRTIO_PCI_BACKEND
/* Built as one of two backends behind virtio_transport_dispatch.c.
   The public names belong to the dispatcher, so take private ones. */
#define virtio_mmio_read32 virtio_pci_backend_mmio_read32
#define virtio_mmio_read8 virtio_pci_backend_mmio_read8
#define virtio_mmio_write32 virtio_pci_backend_mmio_write32
#define virtio_mmio_barrier virtio_pci_backend_mmio_barrier
#define virtio_transport_find virtio_pci_backend_transport_find
#define virtio_transport_find_from virtio_pci_backend_transport_find_from
#define virtio_transport_find_at virtio_pci_backend_transport_find_at
#define virtio_transport_reset virtio_pci_backend_transport_reset
#define virtio_transport_reset_checked virtio_pci_backend_transport_reset_checked
#define virtio_transport_negotiate_no_features virtio_pci_backend_transport_negotiate_no_features
#define virtio_transport_negotiate_features virtio_pci_backend_transport_negotiate_features
#define virtio_transport_setup_queue virtio_pci_backend_transport_setup_queue
#define virtio_transport_set_driver_ok virtio_pci_backend_transport_set_driver_ok
#define virtio_transport_set_driver_ok_checked virtio_pci_backend_transport_set_driver_ok_checked
#define virtio_transport_notify virtio_pci_backend_transport_notify
#define virtio_transport_wait_used virtio_pci_backend_transport_wait_used
#define virtio_transport_ack_interrupts virtio_pci_backend_transport_ack_interrupts
#define virtio_transport_interrupt_id virtio_pci_backend_transport_interrupt_id
#define virtio_transport_register_interrupt virtio_pci_backend_transport_register_interrupt
#define virtio_transport_unregister_interrupt virtio_pci_backend_transport_unregister_interrupt
#define virtio_transport_slot virtio_pci_backend_transport_slot
#endif

#include <xaios/arch_cpu.h>
#include <xaios/gic.h>
#include <xaios/klog.h>
#include <xaios/pci.h>
#include <xaios/timer.h>
#include <xaios/virtio_transport.h>
#include <xaios/vmm.h>

#define VIRTIO_PCI_CAP_VENDOR UINT8_C(0x09)
#define VIRTIO_PCI_CAP_COMMON UINT8_C(1)
#define VIRTIO_PCI_CAP_NOTIFY UINT8_C(2)
#define VIRTIO_PCI_CAP_ISR UINT8_C(3)
#define VIRTIO_PCI_CAP_DEVICE UINT8_C(4)
#define VIRTIO_PCI_DEVICE_BASE UINT16_C(0x1040)
#define VIRTIO_PCI_CAP_MSIX UINT8_C(0x11)
#define VIRTIO_PCI_MSIX_ENABLE UINT16_C(0x8000)
#define VIRTIO_PCI_MSIX_FUNCTION_MASK UINT16_C(0x4000)
#define VIRTIO_PCI_MSIX_ENTRY_MASK UINT32_C(1)
#define VIRTIO_PCI_MSIX_MESSAGE_BASE UINT32_C(0xfee00000)
#define VIRTIO_PCI_STATUS_ACKNOWLEDGE UINT8_C(1)
#define VIRTIO_PCI_STATUS_DRIVER UINT8_C(2)
#define VIRTIO_PCI_STATUS_DRIVER_OK UINT8_C(4)
#define VIRTIO_PCI_STATUS_FEATURES_OK UINT8_C(8)
#define VIRTIO_PCI_STATUS_FAILED UINT8_C(128)
#define VIRTIO_PCI_VERSION_1_HIGH UINT32_C(1)
#define VIRTIO_WAIT_TIMEOUT_NS UINT64_C(5000000000)
#define VIRTIO_RESET_TIMEOUT_NS UINT64_C(1000000000)
#define VIRTIO_WAIT_FALLBACK_SPINS UINT64_C(100000000)

static uint8_t mmio_read8(uint64_t address) {
  return *(volatile uint8_t *)(uintptr_t)address;
}

static uint16_t mmio_read16(uint64_t address) {
  return *(volatile uint16_t *)(uintptr_t)address;
}

static uint32_t mmio_read32(uint64_t address) {
  return *(volatile uint32_t *)(uintptr_t)address;
}

static void mmio_write8(uint64_t address, uint8_t value) {
  *(volatile uint8_t *)(uintptr_t)address = value;
}

static void mmio_write16(uint64_t address, uint16_t value) {
  *(volatile uint16_t *)(uintptr_t)address = value;
}

static void mmio_write32(uint64_t address, uint32_t value) {
  *(volatile uint32_t *)(uintptr_t)address = value;
}

static void mmio_write64(uint64_t address, uint64_t value) {
  *(volatile uint64_t *)(uintptr_t)address = value;
}

uint32_t virtio_mmio_read32(uint64_t base, uint32_t offset) {
  return mmio_read32(base + offset);
}

uint8_t virtio_mmio_read8(uint64_t base, uint32_t offset) {
  return mmio_read8(base + offset);
}

void virtio_mmio_write32(uint64_t base, uint32_t offset, uint32_t value) {
  mmio_write32(base + offset, value);
}

void virtio_mmio_barrier(void) { xaios_cpu_io_barrier(); }

static xaios_status_t map_register(uint64_t address, uint64_t length) {
  if (address == 0U || length == 0U || address > UINT64_MAX - length) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t page = address & ~UINT64_C(0xfff);
  uint64_t end = (address + length + UINT64_C(0xfff)) & ~UINT64_C(0xfff);
  while (page < end) {
    uint64_t physical = 0U;
    uint32_t flags = 0U;
    if (vmm_translate(page, &physical, &flags) != XAIOS_OK ||
        physical != page || (flags & XAIOS_VMM_DEVICE) == 0U) {
      xaios_status_t status = vmm_map_page(
          page, page,
          XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE | XAIOS_VMM_DEVICE);
      if (status != XAIOS_OK) return status;
    }
    page += UINT64_C(4096);
  }
  return XAIOS_OK;
}

static uint32_t matching_ordinal_for_slot(uint32_t slot) {
  switch (slot) {
  case 0U:
    return 1U; /* deterministic test volume; ordinal zero is the EFI disk */
  case 1U:
    return 2U; /* persistent MutableFS */
  case 4U:
    return 3U; /* model volume */
  case 5U:
    return 4U; /* storage administration scratch volume */
  case 6U:
    return 6U; /* kernel-visible A/B system volume */
  default:
    return slot;
  }
}

static xaios_status_t probe_device(uint32_t pci_index, uint32_t device_id,
                                   const char *name, uint32_t logical_slot,
                                   virtio_mmio_device_t *result) {
  const xaios_pci_device_t *pci = pci_device(pci_index);
  if (pci == 0 || pci->vendor_id != XAIOS_PCI_VENDOR_VIRTIO ||
      pci->device_id != VIRTIO_PCI_DEVICE_BASE + device_id) {
    return XAIOS_ERR_NOT_FOUND;
  }

  uint64_t common = 0U;
  uint64_t notify = 0U;
  uint64_t isr = 0U;
  uint64_t config = 0U;
  uint32_t notify_multiplier = 0U;
  uint8_t pointer = pci_config_read8(pci_index, XAIOS_PCI_CAP_PTR) & 0xfcU;
  for (uint32_t count = 0U; count < 48U && pointer >= 0x40U; ++count) {
    uint8_t capability = pci_config_read8(pci_index, pointer);
    uint8_t next = pci_config_read8(pci_index, pointer + 1U) & 0xfcU;
    uint8_t length = pci_config_read8(pci_index, pointer + 2U);
    if (capability == VIRTIO_PCI_CAP_VENDOR && length >= 16U) {
      uint8_t type = pci_config_read8(pci_index, pointer + 3U);
      uint8_t bar = pci_config_read8(pci_index, pointer + 4U);
      uint64_t bar_address = pci_bar_address(pci_index, bar);
      uint32_t offset = pci_config_read32(pci_index, pointer + 8U);
      uint32_t region_length = pci_config_read32(pci_index, pointer + 12U);
      if (bar_address != 0U && bar_address <= UINT64_MAX - offset &&
          region_length != 0U) {
        uint64_t address = bar_address + offset;
        if (map_register(address, region_length) != XAIOS_OK) {
          return XAIOS_ERR_IO;
        }
        if (type == VIRTIO_PCI_CAP_COMMON) common = address;
        if (type == VIRTIO_PCI_CAP_NOTIFY) {
          notify = address;
          if (length >= 20U) {
            notify_multiplier = pci_config_read32(pci_index, pointer + 16U);
          }
        }
        if (type == VIRTIO_PCI_CAP_ISR) isr = address;
        if (type == VIRTIO_PCI_CAP_DEVICE) config = address;
      }
    }
    if (next == 0U || next == pointer) break;
    pointer = next;
  }
  /* A device-specific config region is optional: virtio-rng has none at all,
     and a console without MULTIPORT need not publish one either. QEMU exposes
     one regardless, which is why requiring it went unnoticed. Only the common,
     notify and ISR structures are actually needed to drive a queue. */
  if (common == 0U || notify == 0U || notify_multiplier == 0U) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  if (pci_enable_device(pci_index) != XAIOS_OK) return XAIOS_ERR_IO;
  *result = (virtio_mmio_device_t){
      .base = config != 0U ? config - UINT64_C(0x100) : 0U,
      .common_config = common,
      .notify_base = notify,
      .isr_config = isr,
      .notify_multiplier = notify_multiplier,
      .transport_slot = logical_slot,
      .transport_index = pci_index,
      .interrupt_id = 64U + pci_index,
      .interrupt_configured = 0U,
      .device_id = device_id,
      .name = name,
  };
  klog("%s: modern PCI transport index=%u slot=%u common=0x%lx config=0x%lx\n",
       name, pci_index, logical_slot, common, config);
  return XAIOS_OK;
}

static xaios_status_t find_ordinal(uint32_t device_id, const char *name,
                                   uint32_t ordinal, uint32_t logical_slot,
                                   virtio_mmio_device_t *device) {
  if (name == 0 || device == 0) return XAIOS_ERR_INVALID;
  uint32_t found = 0U;
  for (uint32_t index = 0U; index < pci_device_count(); ++index) {
    const xaios_pci_device_t *candidate = pci_device(index);
    if (candidate == 0 || candidate->vendor_id != XAIOS_PCI_VENDOR_VIRTIO ||
        candidate->device_id != VIRTIO_PCI_DEVICE_BASE + device_id) {
      continue;
    }
    if (found++ == ordinal) {
      return probe_device(index, device_id, name, logical_slot, device);
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

xaios_status_t virtio_transport_find(uint32_t device_id, const char *name,
                                    virtio_mmio_device_t *device) {
  /* The EFI boot disk is the first PCI block function. The common block
   * driver starts at the deterministic data disk, matching ARM MMIO slot 0. */
  uint32_t ordinal = device_id == VIRTIO_DEVICE_BLOCK ? 1U : 0U;
  return find_ordinal(device_id, name, ordinal, 0U, device);
}

xaios_status_t virtio_transport_find_from(uint32_t device_id, const char *name,
                                         uint32_t start_slot,
                                         virtio_mmio_device_t *device) {
  return find_ordinal(device_id, name, start_slot, start_slot, device);
}

xaios_status_t virtio_transport_find_at(uint32_t device_id, const char *name,
                                       uint32_t slot,
                                       virtio_mmio_device_t *device) {
  return find_ordinal(device_id, name, matching_ordinal_for_slot(slot), slot,
                      device);
}

static void set_status(const virtio_mmio_device_t *device, uint8_t status) {
  mmio_write8(device->common_config + 20U, status);
  virtio_mmio_barrier();
}

xaios_status_t virtio_transport_reset_checked(
    const virtio_mmio_device_t *device) {
  if (device == 0 || device->common_config == 0U) return XAIOS_ERR_INVALID;
  set_status(device, 0U);
  uint64_t started = timer_now_ns();
  for (uint64_t spins = 0U;; ++spins) {
    if (mmio_read8(device->common_config + 20U) == 0U) return XAIOS_OK;
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
  mmio_write32(device->common_config + 0U, 0U);
  uint32_t available_low = mmio_read32(device->common_config + 4U);
  mmio_write32(device->common_config + 0U, 1U);
  uint32_t available_high = mmio_read32(device->common_config + 4U);
  *accepted_low = available_low & requested_low;
  *accepted_high = available_high &
                   (requested_high | VIRTIO_PCI_VERSION_1_HIGH);
  if ((*accepted_high & VIRTIO_PCI_VERSION_1_HIGH) == 0U) {
    set_status(device, VIRTIO_PCI_STATUS_FAILED);
    return XAIOS_ERR_UNSUPPORTED;
  }
  mmio_write32(device->common_config + 8U, 0U);
  mmio_write32(device->common_config + 12U, *accepted_low);
  mmio_write32(device->common_config + 8U, 1U);
  mmio_write32(device->common_config + 12U, *accepted_high);
  set_status(device, VIRTIO_PCI_STATUS_ACKNOWLEDGE | VIRTIO_PCI_STATUS_DRIVER |
                         VIRTIO_PCI_STATUS_FEATURES_OK);
  if ((mmio_read8(device->common_config + 20U) &
       VIRTIO_PCI_STATUS_FEATURES_OK) == 0U) {
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

static uint64_t dma_address(const void *pointer) {
  uint64_t physical = 0U;
  uint32_t flags = 0U;
  if (vmm_translate((uint64_t)(uintptr_t)pointer, &physical, &flags) !=
          XAIOS_OK ||
      (flags & XAIOS_VMM_PRESENT) == 0U) {
    return 0U;
  }
  return physical;
}

static xaios_status_t configure_msix(virtio_mmio_device_t *device,
                                    uint16_t table_entry) {
#if !defined(__x86_64__)
  /* MSI-X message addressing is architecture specific: x86 encodes an APIC
     destination in the message address, while aarch64 targets a GIC ITS
     translator register with an event ID. Only the x86 form is implemented
     here, so report no MSI-X elsewhere. The caller writes NO_VECTOR and the
     queue runs polled, which every driver in this tree supports. */
  (void)device;
  (void)table_entry;
  return XAIOS_ERR_UNSUPPORTED;
#else
  uint32_t pci_index = device->transport_index;
  uint8_t pointer = pci_config_read8(pci_index, XAIOS_PCI_CAP_PTR) & 0xfcU;
  for (uint32_t count = 0U; count < 48U && pointer >= 0x40U; ++count) {
    uint8_t capability = pci_config_read8(pci_index, pointer);
    uint8_t next = pci_config_read8(pci_index, pointer + 1U) & 0xfcU;
    if (capability == VIRTIO_PCI_CAP_MSIX) {
      uint16_t control = pci_config_read16(pci_index, pointer + 2U);
      uint16_t table_size = (control & UINT16_C(0x07ff)) + 1U;
      if (table_entry >= table_size) return XAIOS_ERR_UNSUPPORTED;

      uint32_t table = pci_config_read32(pci_index, pointer + 4U);
      uint32_t bar = table & UINT32_C(7);
      uint64_t table_base = pci_bar_address(pci_index, bar);
      uint64_t table_offset = table & UINT32_C(0xfffffff8);
      if (table_base == 0U || table_base > UINT64_MAX - table_offset) {
        return XAIOS_ERR_INVALID;
      }
      uint64_t entry = table_base + table_offset;
      if (entry > UINT64_MAX - (uint64_t)table_entry * 16U) {
        return XAIOS_ERR_INVALID;
      }
      entry += (uint64_t)table_entry * 16U;
      if (map_register(entry, 16U) != XAIOS_OK) return XAIOS_ERR_IO;

      uint32_t ordinal = x86_64_platform_current_ordinal();
      uint32_t destination = x86_64_platform_cpu_apic_id(ordinal);
      if (destination > UINT32_C(0xfffff)) return XAIOS_ERR_UNSUPPORTED;
      mmio_write32(entry + 12U, VIRTIO_PCI_MSIX_ENTRY_MASK);
      mmio_write32(entry + 0U,
                   VIRTIO_PCI_MSIX_MESSAGE_BASE | (destination << 12U));
      mmio_write32(entry + 4U, 0U);
      mmio_write32(entry + 8U, device->interrupt_id);
      mmio_write32(entry + 12U, 0U);
      control = (control | VIRTIO_PCI_MSIX_ENABLE) &
                (uint16_t)~VIRTIO_PCI_MSIX_FUNCTION_MASK;
      if (pci_config_write16(pci_index, pointer + 2U, control) != XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
      device->interrupt_configured = 1U;
      return XAIOS_OK;
    }
    if (next == 0U || next == pointer) break;
    pointer = next;
  }
  return XAIOS_ERR_UNSUPPORTED;
#endif
}

xaios_status_t virtio_transport_setup_queue(virtio_mmio_device_t *device,
                                           uint32_t queue_index,
                                           uint32_t queue_size,
                                           virtq_desc_t *desc,
                                           virtq_avail_t *avail,
                                           virtq_used_t *used) {
  if (device == 0 || queue_index > UINT16_MAX || queue_size == 0U ||
      queue_size > VIRTQ_SIZE || (queue_size & (queue_size - 1U)) != 0U ||
      desc == 0 || avail == 0 || used == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t desc_address = dma_address(desc);
  uint64_t avail_address = dma_address(avail);
  uint64_t used_address = dma_address(used);
  if (desc_address == 0U || avail_address == 0U || used_address == 0U) {
    return XAIOS_ERR_INVALID;
  }
  mmio_write16(device->common_config + 22U, (uint16_t)queue_index);
  uint16_t maximum = mmio_read16(device->common_config + 24U);
  if (maximum < queue_size ||
      mmio_read16(device->common_config + 28U) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  mmio_write16(device->common_config + 24U, (uint16_t)queue_size);
  xaios_status_t interrupt_status = configure_msix(device, 0U);
  mmio_write16(device->common_config + 26U,
               interrupt_status == XAIOS_OK ? 0U : UINT16_MAX);
  if (interrupt_status == XAIOS_OK &&
      mmio_read16(device->common_config + 26U) == UINT16_MAX) {
    return XAIOS_ERR_IO;
  }
  mmio_write64(device->common_config + 32U, desc_address);
  mmio_write64(device->common_config + 40U, avail_address);
  mmio_write64(device->common_config + 48U, used_address);
  mmio_write16(device->common_config + 28U, 1U);
  virtio_mmio_barrier();
  if (mmio_read16(device->common_config + 28U) != 1U) return XAIOS_ERR_IO;
  if (interrupt_status == XAIOS_OK) {
    klog("%s: MSI-X queue=%u vector=%u enabled\n", device->name, queue_index,
         device->interrupt_id);
  } else {
    klog("%s: MSI-X unavailable; queue=%u uses bounded polling\n",
         device->name, queue_index);
  }
  return XAIOS_OK;
}

xaios_status_t virtio_transport_set_driver_ok_checked(
    const virtio_mmio_device_t *device) {
  if (device == 0) return XAIOS_ERR_INVALID;
  set_status(device, VIRTIO_PCI_STATUS_ACKNOWLEDGE | VIRTIO_PCI_STATUS_DRIVER |
                         VIRTIO_PCI_STATUS_FEATURES_OK |
                         VIRTIO_PCI_STATUS_DRIVER_OK);
  uint8_t status = mmio_read8(device->common_config + 20U);
  return (status & (VIRTIO_PCI_STATUS_FEATURES_OK |
                    VIRTIO_PCI_STATUS_DRIVER_OK)) ==
                 (VIRTIO_PCI_STATUS_FEATURES_OK | VIRTIO_PCI_STATUS_DRIVER_OK)
             ? XAIOS_OK
             : XAIOS_ERR_IO;
}

void virtio_transport_set_driver_ok(const virtio_mmio_device_t *device) {
  (void)virtio_transport_set_driver_ok_checked(device);
}

void virtio_transport_notify(const virtio_mmio_device_t *device,
                             uint32_t queue_index) {
  if (device == 0 || queue_index > UINT16_MAX) return;
  mmio_write16(device->common_config + 22U, (uint16_t)queue_index);
  uint16_t offset = mmio_read16(device->common_config + 30U);
  virtio_mmio_barrier();
  mmio_write16(device->notify_base +
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
    (void)mmio_read8(device->isr_config);
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
  return gic_register_interrupt(virtio_transport_interrupt_id(device), handler,
                                context);
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
