#ifndef XAIOS_PCI_H
#define XAIOS_PCI_H

#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_PCI_ECAM_BASE UINT64_C(0x4010000000)
#define XAIOS_PCI_ECAM_BUS0_SIZE UINT64_C(0x100000)
#define XAIOS_PCI_MAX_DEVICES 64U
#define XAIOS_PCI_MAX_BARS 6U

/* Standard PCI config space offsets */
#define XAIOS_PCI_VENDOR_ID UINT16_C(0x00)
#define XAIOS_PCI_DEVICE_ID UINT16_C(0x02)
#define XAIOS_PCI_COMMAND UINT16_C(0x04)
#define XAIOS_PCI_STATUS UINT16_C(0x06)
#define XAIOS_PCI_CLASS_REV UINT16_C(0x08)
#define XAIOS_PCI_HEADER_TYPE UINT16_C(0x0C)
#define XAIOS_PCI_BAR0 UINT16_C(0x10)
#define XAIOS_PCI_INTERRUPT_LINE UINT16_C(0x3C)
#define XAIOS_PCI_INTERRUPT_PIN UINT16_C(0x3D)
#define XAIOS_PCI_CAP_PTR UINT16_C(0x34)

/* Vendor IDs */
#define XAIOS_PCI_VENDOR_VIRTIO UINT16_C(0x1AF4)
#define XAIOS_PCI_VENDOR_REDHAT UINT16_C(0x1B36)
#define XAIOS_PCI_VENDOR_INVALID UINT16_C(0xFFFF)

/* Class codes */
#define XAIOS_PCI_CLASS_BRIDGE UINT8_C(0x06)
#define XAIOS_PCI_CLASS_NETWORK UINT8_C(0x02)
#define XAIOS_PCI_CLASS_STORAGE UINT8_C(0x01)

typedef struct xaios_pci_device {
  uint8_t bus;
  uint8_t device;
  uint8_t function;
  uint16_t vendor_id;
  uint16_t device_id;
  uint8_t class_code;
  uint8_t subclass;
  uint8_t prog_if;
  uint8_t header_type;
  uint32_t bars[XAIOS_PCI_MAX_BARS];
  uint8_t interrupt_line;
  uint8_t interrupt_pin;
  uint32_t is_pcie;
  uint32_t is_virtio;
} xaios_pci_device_t;

void pci_init(void);
uint32_t pci_ecam_mapped(void);
uint32_t pci_device_count(void);
const xaios_pci_device_t *pci_device(uint32_t index);
uint32_t pci_virtio_count(void);
uint32_t pci_network_count(void);
uint32_t pci_bridge_count(void);
uint32_t pci_find_device(uint16_t vendor_id, uint16_t device_id);
xaios_status_t pci_enable_device(uint32_t index);
uint64_t pci_bar_address(uint32_t index, uint32_t bar_index);
uint32_t pci_stream_id(uint32_t index);
void pci_self_test(void);

#endif
