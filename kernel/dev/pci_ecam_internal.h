/* Private interface shared by the PCI ECAM translation units.
 *
 * pci_ecam.c keeps the ECAM root map, the breadth-first bus walk, the device
 * registry and the self-test. pci_ecam_bars.c owns base-address sizing and
 * assignment for boards whose firmware left it undone. pci_ecam_msix.c owns
 * the MSI-X table programming and reaches the device only through the public
 * accessors in <xaios/pci.h>, so it shares nothing here.
 *
 * The five configuration-space accessors cross from pci_ecam.c into
 * pci_ecam_bars.c, and the assignment entry point crosses back; both are
 * declared here, defined once, and carry the module prefix. The ECAM window
 * state stays file-scope in pci_ecam.c and is never handed out.
 */
#ifndef XAIOS_KERNEL_DEV_PCI_ECAM_INTERNAL_H
#define XAIOS_KERNEL_DEV_PCI_ECAM_INTERNAL_H

#include <xaios/types.h>

/* Configuration-space access, defined in pci_ecam.c. */
uint8_t pci_ecam_read8(uint8_t bus, uint8_t dev, uint8_t func, uint16_t offset);
uint16_t pci_ecam_read16(uint8_t bus, uint8_t dev, uint8_t func,
                         uint16_t offset);
uint32_t pci_ecam_read32(uint8_t bus, uint8_t dev, uint8_t func,
                         uint16_t offset);
void pci_ecam_write16(uint8_t bus, uint8_t dev, uint8_t func, uint16_t offset,
                      uint16_t value);
void pci_ecam_write32(uint8_t bus, uint8_t dev, uint8_t func, uint16_t offset,
                      uint32_t value);

/* Base-address sizing and assignment, defined in pci_ecam_bars.c. */
void pci_ecam_assign_bars(uint8_t bus, uint8_t dev, uint8_t func);

#endif /* XAIOS_KERNEL_DEV_PCI_ECAM_INTERNAL_H */
