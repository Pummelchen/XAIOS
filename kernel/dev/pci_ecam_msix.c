/* Programming the MSI-X table of a PCI function.
 *
 * Split out of pci_ecam.c, which keeps the bus walk and the device
 * registry: neither touches the MSI-X table, and this half reaches the
 * device only through the public configuration accessors and
 * pci_bar_address, so it shares no state with the enumerator.
 */
#include <xaios/arch_cpu.h>
#include <xaios/pci.h>
#include <xaios/types.h>
#include <xaios/vmm.h>

xaios_status_t pci_configure_msix(uint32_t index, uint16_t table_entry,
                                  uint64_t message_address,
                                  uint32_t message_data) {
  uint8_t pointer = pci_config_read8(index, XAIOS_PCI_CAP_PTR) & UINT8_C(0xfc);
  for (uint32_t count = 0U; count < 48U && pointer >= 0x40U; ++count) {
    uint8_t capability = pci_config_read8(index, pointer);
    uint8_t next = pci_config_read8(index, pointer + 1U) & UINT8_C(0xfc);
    if (capability == UINT8_C(0x11)) {
      uint16_t control = pci_config_read16(index, pointer + 2U);
      uint16_t table_size = (control & UINT16_C(0x07ff)) + 1U;
      if (table_entry >= table_size) return XAIOS_ERR_UNSUPPORTED;
      uint32_t table = pci_config_read32(index, pointer + 4U);
      uint32_t bar_index = table & UINT32_C(7);
      uint64_t table_base = pci_bar_address(index, bar_index);
      uint64_t table_offset = table & UINT32_C(0xfffffff8);
      if (table_base == 0U || table_base > UINT64_MAX - table_offset ||
          table_base + table_offset >
              UINT64_MAX - (uint64_t)table_entry * 16U) {
        return XAIOS_ERR_INVALID;
      }
      uint64_t physical_entry = table_base + table_offset +
                                (uint64_t)table_entry * 16U;
      uint64_t physical_page = physical_entry & ~UINT64_C(0xfff);
      uint64_t virtual_page = UINT64_C(0x310000000) +
                              (uint64_t)index * UINT64_C(0x10000) +
                              ((uint64_t)table_entry / 256U) *
                                  UINT64_C(0x1000);
      uint64_t mapped = 0U;
      uint32_t flags = 0U;
      if (vmm_translate(virtual_page, &mapped, &flags) != XAIOS_OK ||
          mapped != physical_page || (flags & XAIOS_VMM_DEVICE) == 0U) {
        if (vmm_map_page(virtual_page, physical_page,
                         XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                             XAIOS_VMM_DEVICE) != XAIOS_OK) {
          return XAIOS_ERR_IO;
        }
      }
      uint64_t virtual_entry =
          virtual_page + (physical_entry & UINT64_C(0xfff));
      volatile uint32_t *words =
          (volatile uint32_t *)(uintptr_t)virtual_entry;
      words[3] = 1U;
      words[0] = (uint32_t)message_address;
      words[1] = (uint32_t)(message_address >> 32U);
      words[2] = message_data;
      xaios_cpu_io_barrier();
      control = (control | UINT16_C(0x8000)) &
                (uint16_t)~UINT16_C(0x4000);
      if (pci_config_write16(index, pointer + 2U, control) != XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
      return words[0] == (uint32_t)message_address &&
                     words[1] == (uint32_t)(message_address >> 32U) &&
                     words[2] == message_data && words[3] == 1U
                 ? XAIOS_OK
                 : XAIOS_ERR_IO;
    }
    if (next == 0U || next == pointer) break;
    pointer = next;
  }
  return XAIOS_ERR_UNSUPPORTED;
}

xaios_status_t pci_unmask_msix(uint32_t index, uint16_t table_entry) {
  uint8_t pointer = pci_config_read8(index, XAIOS_PCI_CAP_PTR) & UINT8_C(0xfc);
  for (uint32_t count = 0U; count < 48U && pointer >= 0x40U; ++count) {
    uint8_t capability = pci_config_read8(index, pointer);
    uint8_t next = pci_config_read8(index, pointer + 1U) & UINT8_C(0xfc);
    if (capability == UINT8_C(0x11)) {
      uint16_t control = pci_config_read16(index, pointer + 2U);
      uint16_t table_size = (control & UINT16_C(0x07ff)) + 1U;
      if (table_entry >= table_size) return XAIOS_ERR_UNSUPPORTED;
      uint32_t table = pci_config_read32(index, pointer + 4U);
      uint64_t table_base = pci_bar_address(index, table & UINT32_C(7));
      uint64_t table_offset = table & UINT32_C(0xfffffff8);
      if (table_base == 0U || table_base > UINT64_MAX - table_offset ||
          table_base + table_offset >
              UINT64_MAX - (uint64_t)table_entry * 16U) {
        return XAIOS_ERR_INVALID;
      }
      uint64_t physical_entry = table_base + table_offset +
                                (uint64_t)table_entry * 16U;
      uint64_t physical_page = physical_entry & ~UINT64_C(0xfff);
      uint64_t virtual_page = UINT64_C(0x310000000) +
                              (uint64_t)index * UINT64_C(0x10000) +
                              ((uint64_t)table_entry / 256U) *
                                  UINT64_C(0x1000);
      uint64_t mapped = 0U;
      uint32_t flags = 0U;
      if (vmm_translate(virtual_page, &mapped, &flags) != XAIOS_OK ||
          mapped != physical_page || (flags & XAIOS_VMM_DEVICE) == 0U) {
        if (vmm_map_page(virtual_page, physical_page,
                         XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                             XAIOS_VMM_DEVICE) != XAIOS_OK) {
          return XAIOS_ERR_IO;
        }
      }
      volatile uint32_t *words = (volatile uint32_t *)(uintptr_t)(
          virtual_page + (physical_entry & UINT64_C(0xfff)));
      words[3] = 0U;
      xaios_cpu_io_barrier();
      return words[3] == 0U ? XAIOS_OK : XAIOS_ERR_IO;
    }
    if (next == 0U || next == pointer) break;
    pointer = next;
  }
  return XAIOS_ERR_UNSUPPORTED;
}
