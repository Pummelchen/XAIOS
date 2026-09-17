#include "virtio_transport_pci_internal.h"

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
  /* Queue setup asks for the same vector once per queue, so configuring it
     again would allocate a second identifier for an interrupt that is already
     wired up. */
  if (device != 0 && device->interrupt_configured != 0U) return XAIOS_OK;
#if !defined(__x86_64__)
  /* MSI-X message addressing is architecture specific: x86 encodes an APIC
     destination in the message address, while aarch64 targets a GIC ITS
     translator with an event identifier, and only the ITS can say what that
     address and data are. Without an ITS there is no way to raise one here,
     so report no MSI-X and let the caller write NO_VECTOR and run the queue
     polled, which every driver in this tree supports. */
  if (device == 0) return XAIOS_ERR_INVALID;
  /* The ITS initialises lazily inside the first configure call, so asking
     whether it is available before ever calling one always answers no. */
  uint32_t its_device_id = pci_stream_id(device->transport_index);
  uint32_t lpi = 0U;
  if (gic_allocate_lpi(&lpi) != XAIOS_OK) return XAIOS_ERR_UNSUPPORTED;
  uint64_t message_address = 0U;
  uint32_t message_data = 0U;
  if (gic_its_configure_msi(its_device_id, table_entry, lpi, smp_cpu_id(),
                            &message_address, &message_data) != XAIOS_OK) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  if (pci_configure_msix(device->transport_index, table_entry,
                         message_address, message_data) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  device->interrupt_id = lpi;
  device->interrupt_configured = 1U;
  return XAIOS_OK;
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
      if (virtio_pci_map_register(entry, 16U) != XAIOS_OK) return XAIOS_ERR_IO;

      uint32_t ordinal = x86_64_platform_current_ordinal();
      uint32_t destination = x86_64_platform_cpu_apic_id(ordinal);
      if (destination > UINT32_C(0xfffff)) return XAIOS_ERR_UNSUPPORTED;
      virtio_pci_mmio_write32(entry + 12U, VIRTIO_PCI_MSIX_ENTRY_MASK);
      virtio_pci_mmio_write32(entry + 0U,
                   VIRTIO_PCI_MSIX_MESSAGE_BASE | (destination << 12U));
      virtio_pci_mmio_write32(entry + 4U, 0U);
      virtio_pci_mmio_write32(entry + 8U, device->interrupt_id);
      virtio_pci_mmio_write32(entry + 12U, 0U);
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

/* Configure one MSI-X table entry for a queue of its own.
 *
 * configure_msix above returns early once the device has any interrupt, which
 * is right for a device driven through a single vector and wrong here: every
 * queue needs its own entry, its own LPI, and its own message. Sharing one
 * vector across four queues tells a handler that something happened somewhere,
 * which is the thing multiple queues exist to avoid. */
static xaios_status_t configure_queue_msix(virtio_mmio_device_t *device,
                                           uint32_t queue_index) {
  if (device == 0 || queue_index >= VIRTIO_NOTIFY_SLOTS) {
    return XAIOS_ERR_INVALID;
  }
  if ((device->queue_interrupt_configured & (UINT32_C(1) << queue_index)) !=
      0U) {
    return XAIOS_OK;
  }
#if !defined(__x86_64__)
  uint32_t its_device_id = pci_stream_id(device->transport_index);
  uint32_t lpi = 0U;
  if (gic_allocate_lpi(&lpi) != XAIOS_OK) return XAIOS_ERR_UNSUPPORTED;
  uint64_t message_address = 0U;
  uint32_t message_data = 0U;
  if (gic_its_configure_msi(its_device_id, (uint16_t)queue_index, lpi,
                            smp_cpu_id(), &message_address,
                            &message_data) != XAIOS_OK) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  if (pci_configure_msix(device->transport_index, (uint16_t)queue_index,
                         message_address, message_data) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  device->queue_interrupt_id[queue_index] = lpi;
  device->queue_interrupt_configured |= UINT32_C(1) << queue_index;
  return XAIOS_OK;
#else
  /* x86 routes MSI-X through the APIC rather than an ITS, and the shared-vector
     path already programs that. Per-queue vectors there are the same mechanism
     with a different table entry, and are not wired up here: nothing in this
     tree steers queues on x86 yet, and an untested second interrupt path is
     worse than one honest refusal. */
  (void)queue_index;
  return XAIOS_ERR_UNSUPPORTED;
#endif
}

/* Hand one queue's rings to the board's IOMMU (B-130).
 *
 * Every PCI function starts with a pass-through context, so without this the
 * device's DMA reaches these pages without a table being walked. With it, the
 * first descriptor the device fetches is translated. A refusal is logged and
 * does not stop the queue -- a board with no IOMMU has to boot -- but it is
 * never silent, because "unmediated" is exactly the state this call exists to
 * leave. */
static void mediate_queue_rings(const virtio_mmio_device_t *device,
                                uint32_t queue_index, uint32_t queue_size,
                                uint64_t desc_address, uint64_t avail_address,
                                uint64_t used_address) {
#if defined(__riscv)
  /* A board with no IOMMU is not a board whose driver refused: the call
     answers 0 and there is nothing to say. Only a refusal on a board that HAS
     one is worth a line, and it is worth one because the queue is about to be
     handed over unmediated. */
  if (riscv64_iommu_ready() != 0) {
    uint32_t stream_id = pci_stream_id(device->transport_index);
    uint64_t desc_bytes = (uint64_t)sizeof(virtq_desc_t) * (uint64_t)queue_size;
    if (riscv64_iommu_mediate_dma(stream_id, desc_address, desc_bytes) == 0 ||
        riscv64_iommu_mediate_dma(stream_id, avail_address,
                                  (uint64_t)sizeof(virtq_avail_t)) == 0 ||
        riscv64_iommu_mediate_dma(stream_id, used_address,
                                  (uint64_t)sizeof(virtq_used_t)) == 0) {
      klog("virtio-pci: queue %u rings are not mediated for stream_id=%u\n",
           (unsigned)queue_index, (unsigned)stream_id);
    }
  }
#else
  (void)device;
  (void)queue_index;
  (void)queue_size;
  (void)desc_address;
  (void)avail_address;
  (void)used_address;
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
  mediate_queue_rings(device, queue_index, queue_size, desc_address,
                      avail_address, used_address);
  virtio_pci_mmio_write16(device->common_config + 22U, (uint16_t)queue_index);
  uint16_t maximum = virtio_pci_mmio_read16(device->common_config + 24U);
  if (maximum < queue_size ||
      virtio_pci_mmio_read16(device->common_config + 28U) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  virtio_pci_mmio_write16(device->common_config + 24U, (uint16_t)queue_size);
  xaios_status_t interrupt_status = configure_msix(device, 0U);
  virtio_pci_mmio_write16(device->common_config + 26U,
               interrupt_status == XAIOS_OK ? 0U : UINT16_MAX);
  if (interrupt_status == XAIOS_OK &&
      virtio_pci_mmio_read16(device->common_config + 26U) == UINT16_MAX) {
    return XAIOS_ERR_IO;
  }
  virtio_pci_mmio_write64(device->common_config + 32U, desc_address);
  virtio_pci_mmio_write64(device->common_config + 40U, avail_address);
  virtio_pci_mmio_write64(device->common_config + 48U, used_address);
  virtio_pci_mmio_write16(device->common_config + 28U, 1U);
  virtio_mmio_barrier();
  if (virtio_pci_mmio_read16(device->common_config + 28U) != 1U) return XAIOS_ERR_IO;
  /* This queue is selected right now, which is the only safe moment to read
     its notify offset: it is fixed for the life of the queue, so notifying
     later needs no access to the shared selector at all. */
  if (queue_index < VIRTIO_NOTIFY_SLOTS) {
    device->notify_offset[queue_index] =
        virtio_pci_mmio_read16(device->common_config + 30U);
    device->notify_offset_valid |= UINT32_C(1) << queue_index;
  }
  if (interrupt_status == XAIOS_OK) {
    klog("%s: MSI-X queue=%u vector=%u enabled\n", device->name, queue_index,
         device->interrupt_id);
  } else {
    klog("%s: MSI-X unavailable; queue=%u uses bounded polling\n",
         device->name, queue_index);
  }
  return XAIOS_OK;
}

xaios_status_t virtio_transport_setup_queue_vectored(
    virtio_mmio_device_t *device, uint32_t queue_index, uint32_t queue_size,
    virtq_desc_t *desc, virtq_avail_t *avail, virtq_used_t *used) {
  if (device == 0 || queue_index >= VIRTIO_NOTIFY_SLOTS) {
    return XAIOS_ERR_INVALID;
  }
  /* Ask for a vector of this queue's own first. If the device cannot give one
     -- too few table entries, no ITS, an architecture this is not wired for --
     fall back to the shared vector rather than refusing: a driver that wanted
     several queues still works with one interrupt between them, more slowly,
     and can ask which it got. */
  if (configure_queue_msix(device, queue_index) != XAIOS_OK) {
    return virtio_transport_setup_queue(device, queue_index, queue_size, desc,
                                        avail, used);
  }
  if (queue_size == 0U || queue_size > VIRTQ_SIZE ||
      (queue_size & (queue_size - 1U)) != 0U || desc == 0 || avail == 0 ||
      used == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t desc_address = dma_address(desc);
  uint64_t avail_address = dma_address(avail);
  uint64_t used_address = dma_address(used);
  if (desc_address == 0U || avail_address == 0U || used_address == 0U) {
    return XAIOS_ERR_INVALID;
  }
  mediate_queue_rings(device, queue_index, queue_size, desc_address,
                      avail_address, used_address);
  virtio_pci_mmio_write16(device->common_config + 22U, (uint16_t)queue_index);
  uint16_t maximum = virtio_pci_mmio_read16(device->common_config + 24U);
  if (maximum < queue_size ||
      virtio_pci_mmio_read16(device->common_config + 28U) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  virtio_pci_mmio_write16(device->common_config + 24U, (uint16_t)queue_size);
  virtio_pci_mmio_write16(device->common_config + 26U, (uint16_t)queue_index);
  if (virtio_pci_mmio_read16(device->common_config + 26U) != (uint16_t)queue_index) {
    /* The device declined the vector. Undo the claim so the fallback does not
       believe this queue has one. */
    device->queue_interrupt_configured &= ~(UINT32_C(1) << queue_index);
    return virtio_transport_setup_queue(device, queue_index, queue_size, desc,
                                        avail, used);
  }
  virtio_pci_mmio_write64(device->common_config + 32U, desc_address);
  virtio_pci_mmio_write64(device->common_config + 40U, avail_address);
  virtio_pci_mmio_write64(device->common_config + 48U, used_address);
  virtio_pci_mmio_write16(device->common_config + 28U, 1U);
  virtio_mmio_barrier();
  if (virtio_pci_mmio_read16(device->common_config + 28U) != 1U) return XAIOS_ERR_IO;
  device->notify_offset[queue_index] =
      virtio_pci_mmio_read16(device->common_config + 30U);
  device->notify_offset_valid |= UINT32_C(1) << queue_index;
  klog("%s: queue=%u has its own MSI-X vector=%u\n", device->name,
       queue_index, device->queue_interrupt_id[queue_index]);
  return XAIOS_OK;
}

uint32_t virtio_transport_queue_has_vector(const virtio_mmio_device_t *device,
                                           uint32_t queue_index) {
  if (device == 0 || queue_index >= VIRTIO_NOTIFY_SLOTS) return 0U;
  return (device->queue_interrupt_configured &
          (UINT32_C(1) << queue_index)) != 0U ? 1U : 0U;
}

xaios_status_t virtio_transport_register_queue_interrupt(
    const virtio_mmio_device_t *device, uint32_t queue_index,
    virtio_interrupt_handler_t handler, void *context) {
  if (device == 0 || handler == 0 || queue_index >= VIRTIO_NOTIFY_SLOTS) {
    return XAIOS_ERR_INVALID;
  }
  if (virtio_transport_queue_has_vector(device, queue_index) == 0U) {
    return XAIOS_ERR_UNSUPPORTED;
  }
#if !defined(__x86_64__)
  uint32_t intid = device->queue_interrupt_id[queue_index];
  xaios_status_t status = gic_register_lpi(intid, smp_cpu_id(), handler,
                                           context);
  if (status != XAIOS_OK) return status;
  status = pci_unmask_msix(device->transport_index, (uint16_t)queue_index);
  if (status != XAIOS_OK) {
    (void)gic_unregister_interrupt(intid, handler, context);
    return status;
  }
  return XAIOS_OK;
#else
  (void)context;
  return XAIOS_ERR_UNSUPPORTED;
#endif
}
