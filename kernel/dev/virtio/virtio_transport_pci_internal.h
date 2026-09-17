#ifndef XAIOS_VIRTIO_TRANSPORT_PCI_INTERNAL_H
#define XAIOS_VIRTIO_TRANSPORT_PCI_INTERNAL_H

/* Declarations shared by virtio_transport_pci.c and the two files split
   out of it: virtio_transport_pci_probe.c parses the PCI capabilities
   and finds a device, and virtio_transport_pci_queue.c sets up queues
   and their interrupts. The rename block below comes first, before the
   includes that declare the public transport entry points, because it
   renames those declarations too. */
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
#define virtio_transport_find_nth virtio_pci_backend_transport_find_nth
#define virtio_transport_setup_queue_vectored virtio_pci_backend_transport_setup_queue_vectored
#define virtio_transport_queue_has_vector virtio_pci_backend_transport_queue_has_vector
#define virtio_transport_register_queue_interrupt virtio_pci_backend_transport_register_queue_interrupt
#define virtio_transport_reset virtio_pci_backend_transport_reset
#define virtio_transport_reset_checked virtio_pci_backend_transport_reset_checked
#define virtio_transport_negotiate_no_features virtio_pci_backend_transport_negotiate_no_features
#define virtio_transport_negotiate_features virtio_pci_backend_transport_negotiate_features
#define virtio_transport_setup_queue virtio_pci_backend_transport_setup_queue
#define virtio_transport_set_driver_ok virtio_pci_backend_transport_set_driver_ok
#define virtio_transport_set_driver_ok_checked virtio_pci_backend_transport_set_driver_ok_checked
#define virtio_transport_notify virtio_pci_backend_transport_notify
#define virtio_transport_wait_used virtio_pci_backend_transport_wait_used
#define virtio_transport_device_status virtio_pci_backend_transport_device_status
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
#include <xaios/smmu.h>
#include <xaios/smp.h>
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

/* MMIO accessors shared by more than one of those files. Defined once,
   in virtio_transport_pci.c. */
uint8_t virtio_pci_mmio_read8(uint64_t address);
uint16_t virtio_pci_mmio_read16(uint64_t address);
uint32_t virtio_pci_mmio_read32(uint64_t address);
void virtio_pci_mmio_write8(uint64_t address, uint8_t value);
void virtio_pci_mmio_write16(uint64_t address, uint16_t value);
void virtio_pci_mmio_write32(uint64_t address, uint32_t value);
void virtio_pci_mmio_write64(uint64_t address, uint64_t value);

/* Map a device register region page by page. Defined in
   virtio_transport_pci_probe.c, where the capabilities are parsed. */
xaios_status_t virtio_pci_map_register(uint64_t address, uint64_t length);

#endif /* XAIOS_VIRTIO_TRANSPORT_PCI_INTERNAL_H */
