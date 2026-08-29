#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/pci.h>
#include <xaios/vmm.h>

#define PCI_CONFIG_ADDRESS UINT16_C(0x0cf8)
#define PCI_CONFIG_DATA UINT16_C(0x0cfc)
#define PCI_COMMAND_IO UINT16_C(1)
#define PCI_COMMAND_MEMORY UINT16_C(1 << 1)
#define PCI_COMMAND_BUS_MASTER UINT16_C(1 << 2)

static xaios_pci_device_t g_devices[XAIOS_PCI_MAX_DEVICES];
static uint32_t g_device_count;
static uint32_t g_virtio_count;
static uint32_t g_network_count;
static uint32_t g_bridge_count;

static inline void outl(uint16_t port, uint32_t value) {
  __asm__ volatile("outl %0, %1" : : "a"(value), "Nd"(port) : "memory");
}

static inline uint32_t inl(uint16_t port) {
  uint32_t value;
  __asm__ volatile("inl %1, %0" : "=a"(value) : "Nd"(port) : "memory");
  return value;
}

static uint32_t config_address(uint8_t bus, uint8_t device, uint8_t function,
                               uint16_t offset) {
  return UINT32_C(0x80000000) | ((uint32_t)bus << 16U) |
         ((uint32_t)device << 11U) | ((uint32_t)function << 8U) |
         ((uint32_t)offset & UINT32_C(0xfc));
}

static uint32_t config_read32(uint8_t bus, uint8_t device, uint8_t function,
                              uint16_t offset) {
  outl(PCI_CONFIG_ADDRESS, config_address(bus, device, function, offset));
  return inl(PCI_CONFIG_DATA);
}

static void config_write32(uint8_t bus, uint8_t device, uint8_t function,
                           uint16_t offset, uint32_t value) {
  outl(PCI_CONFIG_ADDRESS, config_address(bus, device, function, offset));
  outl(PCI_CONFIG_DATA, value);
}

static uint16_t config_read16(uint8_t bus, uint8_t device, uint8_t function,
                              uint16_t offset) {
  uint32_t value = config_read32(bus, device, function, offset);
  return (uint16_t)(value >> ((offset & 2U) * 8U));
}

static uint8_t config_read8(uint8_t bus, uint8_t device, uint8_t function,
                            uint16_t offset) {
  uint32_t value = config_read32(bus, device, function, offset);
  return (uint8_t)(value >> ((offset & 3U) * 8U));
}

static void config_write16(uint8_t bus, uint8_t device, uint8_t function,
                           uint16_t offset, uint16_t value) {
  uint32_t aligned = config_read32(bus, device, function, offset);
  uint32_t shift = (offset & 2U) * 8U;
  aligned = (aligned & ~(UINT32_C(0xffff) << shift)) |
            ((uint32_t)value << shift);
  config_write32(bus, device, function, offset, aligned);
}

static uint32_t has_pcie_capability(uint8_t bus, uint8_t device,
                                    uint8_t function) {
  uint8_t pointer = config_read8(bus, device, function, XAIOS_PCI_CAP_PTR);
  for (uint32_t count = 0U; count < 48U && pointer >= 0x40U; ++count) {
    uint8_t id = config_read8(bus, device, function, pointer);
    if (id == UINT8_C(0x10)) return 1U;
    uint8_t next = config_read8(bus, device, function, pointer + 1U);
    if (next == pointer) break;
    pointer = next;
  }
  return 0U;
}

static void add_device(uint8_t bus, uint8_t device, uint8_t function) {
  if (g_device_count >= XAIOS_PCI_MAX_DEVICES) return;
  xaios_pci_device_t *entry = &g_devices[g_device_count];
  *entry = (xaios_pci_device_t){0};
  entry->bus = bus;
  entry->device = device;
  entry->function = function;
  entry->vendor_id =
      config_read16(bus, device, function, XAIOS_PCI_VENDOR_ID);
  entry->device_id =
      config_read16(bus, device, function, XAIOS_PCI_DEVICE_ID);
  uint32_t class_revision =
      config_read32(bus, device, function, XAIOS_PCI_CLASS_REV);
  entry->class_code = (uint8_t)(class_revision >> 24U);
  entry->subclass = (uint8_t)(class_revision >> 16U);
  entry->prog_if = (uint8_t)(class_revision >> 8U);
  entry->header_type =
      config_read8(bus, device, function, XAIOS_PCI_HEADER_TYPE) & 0x7fU;
  for (uint32_t bar = 0U; bar < XAIOS_PCI_MAX_BARS; ++bar) {
    entry->bars[bar] = config_read32(
        bus, device, function,
        (uint16_t)(XAIOS_PCI_BAR0 + (uint16_t)(bar * 4U)));
  }
  entry->interrupt_line =
      config_read8(bus, device, function, XAIOS_PCI_INTERRUPT_LINE);
  entry->interrupt_pin =
      config_read8(bus, device, function, XAIOS_PCI_INTERRUPT_PIN);
  entry->is_virtio = entry->vendor_id == XAIOS_PCI_VENDOR_VIRTIO ? 1U : 0U;
  entry->is_pcie = has_pcie_capability(bus, device, function);
  if (entry->is_virtio != 0U) ++g_virtio_count;
  if (entry->class_code == XAIOS_PCI_CLASS_NETWORK) ++g_network_count;
  if (entry->class_code == XAIOS_PCI_CLASS_BRIDGE) ++g_bridge_count;
  ++g_device_count;
}

void pci_init(void) {
  g_device_count = 0U;
  g_virtio_count = 0U;
  g_network_count = 0U;
  g_bridge_count = 0U;
  for (uint32_t bus = 0U; bus < 256U; ++bus) {
    for (uint32_t device = 0U; device < 32U; ++device) {
      uint16_t vendor = config_read16((uint8_t)bus, (uint8_t)device, 0U,
                                      XAIOS_PCI_VENDOR_ID);
      if (vendor == XAIOS_PCI_VENDOR_INVALID) continue;
      add_device((uint8_t)bus, (uint8_t)device, 0U);
      uint8_t header = config_read8((uint8_t)bus, (uint8_t)device, 0U,
                                    XAIOS_PCI_HEADER_TYPE);
      if ((header & UINT8_C(0x80)) != 0U) {
        for (uint32_t function = 1U; function < 8U; ++function) {
          vendor = config_read16((uint8_t)bus, (uint8_t)device,
                                 (uint8_t)function, XAIOS_PCI_VENDOR_ID);
          if (vendor != XAIOS_PCI_VENDOR_INVALID) {
            add_device((uint8_t)bus, (uint8_t)device, (uint8_t)function);
          }
        }
      }
    }
  }
  klog("PCI: x86 enumerated %u devices virtio=%u net=%u bridge=%u\n",
       g_device_count, g_virtio_count, g_network_count, g_bridge_count);
}

void pci_configure_ecam(uint64_t base, uint32_t start_bus, uint32_t end_bus) {
  (void)base;
  (void)start_bus;
  (void)end_bus;
}

uint32_t pci_ecam_mapped(void) { return 1U; }
uint32_t pci_device_count(void) { return g_device_count; }

const xaios_pci_device_t *pci_device(uint32_t index) {
  return index < g_device_count ? &g_devices[index] : 0;
}

uint32_t pci_virtio_count(void) { return g_virtio_count; }
uint32_t pci_network_count(void) { return g_network_count; }
uint32_t pci_bridge_count(void) { return g_bridge_count; }

uint32_t pci_find_device(uint16_t vendor_id, uint16_t device_id) {
  for (uint32_t index = 0U; index < g_device_count; ++index) {
    if (g_devices[index].vendor_id == vendor_id &&
        (device_id == 0U || g_devices[index].device_id == device_id)) {
      return index;
    }
  }
  return UINT32_MAX;
}

xaios_status_t pci_enable_device(uint32_t index) {
  const xaios_pci_device_t *device = pci_device(index);
  if (device == 0) return XAIOS_ERR_INVALID;
  uint16_t command = config_read16(device->bus, device->device,
                                   device->function, XAIOS_PCI_COMMAND);
  command |= PCI_COMMAND_IO | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER;
  config_write16(device->bus, device->device, device->function,
                 XAIOS_PCI_COMMAND, command);
  return XAIOS_OK;
}

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
      uint64_t entry = table_base + table_offset +
                       (uint64_t)table_entry * 16U;
      uint64_t page = entry & ~UINT64_C(0xfff);
      if (vmm_map_page(page, page, XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                                      XAIOS_VMM_DEVICE) != XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
      volatile uint32_t *words = (volatile uint32_t *)(uintptr_t)entry;
      words[3] = 1U;
      words[0] = (uint32_t)message_address;
      words[1] = (uint32_t)(message_address >> 32U);
      words[2] = message_data;
      xaios_status_t status =
          pci_config_write16(index, pointer + 2U,
                             (control | UINT16_C(0x8000)) &
                                 (uint16_t)~UINT16_C(0x4000));
      if (status != XAIOS_OK) return status;
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
      uint64_t entry = table_base + table_offset +
                       (uint64_t)table_entry * 16U;
      uint64_t page = entry & ~UINT64_C(0xfff);
      if (vmm_map_page(page, page, XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                                      XAIOS_VMM_DEVICE) != XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
      volatile uint32_t *words = (volatile uint32_t *)(uintptr_t)entry;
      words[3] = 0U;
      __asm__ volatile("mfence" ::: "memory");
      return words[3] == 0U ? XAIOS_OK : XAIOS_ERR_IO;
    }
    if (next == 0U || next == pointer) break;
    pointer = next;
  }
  return XAIOS_ERR_UNSUPPORTED;
}

uint64_t pci_bar_address(uint32_t index, uint32_t bar_index) {
  const xaios_pci_device_t *device = pci_device(index);
  if (device == 0 || bar_index >= XAIOS_PCI_MAX_BARS) return 0U;
  uint32_t low = config_read32(
      device->bus, device->device, device->function,
      (uint16_t)(XAIOS_PCI_BAR0 + (uint16_t)(bar_index * 4U)));
  if ((low & 1U) != 0U) return low & ~UINT32_C(3);
  uint64_t address = low & ~UINT32_C(0xf);
  if ((low & UINT32_C(0x6)) == UINT32_C(0x4) &&
      bar_index + 1U < XAIOS_PCI_MAX_BARS) {
    uint32_t high = config_read32(
        device->bus, device->device, device->function,
        (uint16_t)(XAIOS_PCI_BAR0 + (uint16_t)((bar_index + 1U) * 4U)));
    address |= (uint64_t)high << 32U;
  }
  return address;
}

uint32_t pci_stream_id(uint32_t index) {
  const xaios_pci_device_t *device = pci_device(index);
  if (device == 0) return UINT32_MAX;
  return ((uint32_t)device->bus << 8U) | ((uint32_t)device->device << 3U) |
         device->function;
}

uint8_t pci_config_read8(uint32_t index, uint16_t offset) {
  const xaios_pci_device_t *device = pci_device(index);
  return device == 0
             ? UINT8_MAX
             : config_read8(device->bus, device->device, device->function,
                            offset);
}

uint16_t pci_config_read16(uint32_t index, uint16_t offset) {
  const xaios_pci_device_t *device = pci_device(index);
  return device == 0
             ? UINT16_MAX
             : config_read16(device->bus, device->device, device->function,
                             offset);
}

uint32_t pci_config_read32(uint32_t index, uint16_t offset) {
  const xaios_pci_device_t *device = pci_device(index);
  return device == 0
             ? UINT32_MAX
             : config_read32(device->bus, device->device, device->function,
                             offset);
}

xaios_status_t pci_config_write16(uint32_t index, uint16_t offset,
                                  uint16_t value) {
  const xaios_pci_device_t *device = pci_device(index);
  if (device == 0) return XAIOS_ERR_INVALID;
  config_write16(device->bus, device->device, device->function, offset,
                 value);
  return XAIOS_OK;
}

xaios_status_t pci_config_write32(uint32_t index, uint16_t offset,
                                  uint32_t value) {
  const xaios_pci_device_t *device = pci_device(index);
  if (device == 0) return XAIOS_ERR_INVALID;
  config_write32(device->bus, device->device, device->function, offset,
                 value);
  return XAIOS_OK;
}

void pci_self_test(void) {
  /* That enumeration works is a property of this code. How many virtio
     devices a machine has is a property of the machine, and asserting on it
     halts a machine that is working.

     This required two, which every profile in this tree happens to provide,
     and which a machine booted over the network does not: firmware fetched one
     file and the machine has an e1000 and no virtio devices at all. It came up
     correctly and then panicked on the count -- a kernel refusing to run on a
     machine because of what is plugged into it.

     Enumeration having found nothing at all is still a fault: the bus exists,
     and a scan of it that returns nothing did not work. */
  kassert(g_device_count != 0U);
  klog("PCI: x86 enumeration self-test passed devices=%u virtio=%u\n",
       g_device_count, g_virtio_count);
}
