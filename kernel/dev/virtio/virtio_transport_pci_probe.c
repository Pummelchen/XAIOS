#include "virtio_transport_pci_internal.h"

/* A transitional device -- one that can be driven by a legacy driver as well
   as a modern one -- carries a PCI device ID from the 0x1000 block instead of
   0x1040 + type, and the two blocks are not in the same order, so the mapping
   is a table rather than an offset. QEMU's virtio-blk-pci is transitional
   unless it is asked not to be, which means a disk attached the way a person
   would attach one identifies itself as 0x1001 and was, until this table
   existed, simply not found. The gates never showed it: their durable volumes
   are all MMIO, and the one PCI disk they attach belongs to the firmware.

   Matching the ID says only that the type is right. Whether the device can
   actually be driven is decided below, by looking for the modern capability
   structures -- a transitional device has them, a purely legacy one does not
   and is rejected there with a reason. */
static uint32_t matches_device_type(uint16_t pci_device_id,
                                    uint32_t virtio_device_id) {
  if (pci_device_id == VIRTIO_PCI_DEVICE_BASE + virtio_device_id) return 1U;
  uint16_t transitional;
  switch (virtio_device_id) {
    case 1U: transitional = 0x1000U; break; /* network */
    case 2U: transitional = 0x1001U; break; /* block */
    case 3U: transitional = 0x1003U; break; /* console */
    case 4U: transitional = 0x1005U; break; /* entropy source */
    case 5U: transitional = 0x1002U; break; /* memory balloon */
    case 8U: transitional = 0x1004U; break; /* SCSI host */
    case 9U: transitional = 0x1009U; break; /* 9P transport */
    default: return 0U;
  }
  return pci_device_id == transitional ? 1U : 0U;
}

xaios_status_t virtio_pci_map_register(uint64_t address, uint64_t length) {
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
    return 2U; /* persistent xaibootFS */
  case 4U:
    return 3U; /* xaiFS volume */
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
      matches_device_type(pci->device_id, device_id) == 0U) {
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
        if (virtio_pci_map_register(address, region_length) != XAIOS_OK) {
          klog("%s: pci index=%u cannot map capability type=%u at 0x%lx\n",
               name, pci_index, (unsigned)type, address);
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
    /* A device that publishes no modern capability structures is legacy-only
       and cannot be driven here. Saying so is the difference between a machine
       that explains why it found no disk and one that just has none. */
    klog("%s: pci index=%u id=0x%x not usable: common=0x%lx notify=0x%lx "
         "multiplier=%u\n",
         name, pci_index, (unsigned)pci->device_id, common, notify,
         notify_multiplier);
    return XAIOS_ERR_UNSUPPORTED;
  }
  if (pci_enable_device(pci_index) != XAIOS_OK) {
    klog("%s: pci index=%u cannot be enabled\n", name, pci_index);
    return XAIOS_ERR_IO;
  }
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
        matches_device_type(candidate->device_id, device_id) == 0U) {
      continue;
    }
    if (found++ == ordinal) {
      return probe_device(index, device_id, name, logical_slot, device);
    }
  }
  klog("%s: no pci device of type %u at ordinal %u; %u present\n", name,
       device_id, ordinal, found);
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

/* The nth virtio function of this type on the bus, with no slot map applied.
   Every other entry point here goes through matching_ordinal_for_slot, which
   encodes the test bench's disk order -- and its first rule is that ordinal
   zero is the firmware's boot disk and belongs to nobody. On a machine XAIOS
   has been installed onto there is one disk, it is ordinal zero, and it is the
   one being looked for. */
xaios_status_t virtio_transport_find_nth(uint32_t device_id, const char *name,
                                         uint32_t ordinal,
                                         uint32_t logical_slot,
                                         virtio_mmio_device_t *device) {
  return find_ordinal(device_id, name, ordinal, logical_slot, device);
}

#ifndef XAIOS_VIRTIO_PCI_BACKEND
/* Where PCI is the only transport, there is no dispatcher and the names in
   this file are already the public ones. "The nth PCI device" and "the nth
   device" are then the same question, so the PCI-specific entry point is a
   thin alias rather than absent.

   Code shared with aarch64 calls it -- the boot disk is addressed on PCI
   because counting across both transports cannot reach it when an MMIO device
   is present, and a machine that has only ever seen PCI should not have to
   know why that distinction exists. Leaving it out failed the x86_64 link
   with an undefined symbol, which a per-file compile check cannot see. */
xaios_status_t virtio_transport_find_nth_pci(uint32_t device_id,
                                             const char *name,
                                             uint32_t ordinal,
                                             uint32_t logical_slot,
                                             virtio_mmio_device_t *device) {
  return virtio_transport_find_nth(device_id, name, ordinal, logical_slot,
                                   device);
}
#endif
