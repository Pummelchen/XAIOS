#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/pci.h>
#include <xaios/vmm.h>

#define PAGE_SIZE UINT64_C(4096)

static xaios_pci_device_t g_devices[XAIOS_PCI_MAX_DEVICES];
static uint32_t g_device_count;
static uint32_t g_virtio_count;
static uint32_t g_network_count;
static uint32_t g_bridge_count;
static uint32_t g_ecam_mapped;

static volatile uint8_t *ecam_addr(uint8_t bus, uint8_t dev, uint8_t func,
                                   uint16_t offset) {
  uint64_t addr = XAIOS_PCI_ECAM_BASE | ((uint64_t)bus << 20) |
                  ((uint64_t)dev << 15) | ((uint64_t)func << 12) |
                  (uint64_t)offset;
  return (volatile uint8_t *)(uintptr_t)addr;
}

static uint32_t ecam_read32(uint8_t bus, uint8_t dev, uint8_t func,
                            uint16_t offset) {
  volatile uint32_t *p =
      (volatile uint32_t *)(uintptr_t)ecam_addr(bus, dev, func, offset);
  return *p;
}

static uint16_t ecam_read16(uint8_t bus, uint8_t dev, uint8_t func,
                            uint16_t offset) {
  volatile uint16_t *p =
      (volatile uint16_t *)(uintptr_t)ecam_addr(bus, dev, func, offset);
  return *p;
}

static uint8_t ecam_read8(uint8_t bus, uint8_t dev, uint8_t func,
                          uint16_t offset) {
  return *ecam_addr(bus, dev, func, offset);
}

static void ecam_write16(uint8_t bus, uint8_t dev, uint8_t func,
                         uint16_t offset, uint16_t value) {
  volatile uint16_t *p =
      (volatile uint16_t *)(uintptr_t)ecam_addr(bus, dev, func, offset);
  *p = value;
  __asm__ volatile("dsb sy" ::: "memory");
}

static void map_ecam_bus0(void) {
  uint64_t page = 0;
  while (page < XAIOS_PCI_ECAM_BUS0_SIZE) {
    uint64_t phys = XAIOS_PCI_ECAM_BASE + page;
    if (vmm_map_page(phys, phys,
                     XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                         XAIOS_VMM_DEVICE) != XAIOS_OK) {
      klog("PCI: failed to map ECAM page 0x%lx\n", phys);
      return;
    }
    page += PAGE_SIZE;
  }
  g_ecam_mapped = 1;
}

static int walk_pcie_caps(uint8_t bus, uint8_t dev, uint8_t func) {
  uint8_t cap_ptr = ecam_read8(bus, dev, func, XAIOS_PCI_CAP_PTR);
  if (cap_ptr == 0 || cap_ptr == 0xFF) {
    return 0;
  }
  /* Walk capability list (max 16 entries to avoid infinite loops) */
  for (uint32_t i = 0; i < 16; ++i) {
    if (cap_ptr >= 252) {
      break; /* Prevent OOB read beyond 256-byte config space */
    }
    uint8_t cap_id = ecam_read8(bus, dev, func, cap_ptr);
    if (cap_id == 0 || cap_id == 0xFF) {
      break;
    }
    /* Cap ID 0x10 = PCIe capability */
    if (cap_id == 0x10) {
      return 1;
    }
    cap_ptr = ecam_read8(bus, dev, func, cap_ptr + 1);
    if (cap_ptr == 0 || cap_ptr == 0xFF) {
      break;
    }
  }
  return 0;
}

static void add_device(uint8_t bus, uint8_t dev, uint8_t func) {
  if (g_device_count >= XAIOS_PCI_MAX_DEVICES) {
    return;
  }

  xaios_pci_device_t *d = &g_devices[g_device_count];
  d->bus = bus;
  d->device = dev;
  d->function = func;
  d->vendor_id = ecam_read16(bus, dev, func, XAIOS_PCI_VENDOR_ID);
  d->device_id = ecam_read16(bus, dev, func, XAIOS_PCI_DEVICE_ID);

  uint32_t class_rev = ecam_read32(bus, dev, func, XAIOS_PCI_CLASS_REV);
  d->class_code = (uint8_t)((class_rev >> 24) & 0xFF);
  d->subclass = (uint8_t)((class_rev >> 16) & 0xFF);
  d->prog_if = (uint8_t)((class_rev >> 8) & 0xFF);

  uint8_t hdr = ecam_read8(bus, dev, func, XAIOS_PCI_HEADER_TYPE);
  d->header_type = hdr & 0x7F;

  /* Read BARs for type 0 headers */
  if (d->header_type == 0) {
    for (uint32_t bar = 0; bar < XAIOS_PCI_MAX_BARS; ++bar) {
      d->bars[bar] =
          ecam_read32(bus, dev, func, XAIOS_PCI_BAR0 + (uint16_t)(bar * 4));
    }
  }

  d->interrupt_line = ecam_read8(bus, dev, func, XAIOS_PCI_INTERRUPT_LINE);
  d->interrupt_pin = ecam_read8(bus, dev, func, XAIOS_PCI_INTERRUPT_PIN);

  d->is_virtio = (d->vendor_id == XAIOS_PCI_VENDOR_VIRTIO) ? 1 : 0;
  d->is_pcie = walk_pcie_caps(bus, dev, func);

  if (d->is_virtio) {
    ++g_virtio_count;
  }
  if (d->class_code == XAIOS_PCI_CLASS_NETWORK) {
    ++g_network_count;
  }
  if (d->class_code == XAIOS_PCI_CLASS_BRIDGE) {
    ++g_bridge_count;
  }

  ++g_device_count;
}

void pci_init(void) {
  g_device_count = 0;
  g_virtio_count = 0;
  g_network_count = 0;
  g_bridge_count = 0;
  g_ecam_mapped = 0;

  for (uint32_t i = 0; i < XAIOS_PCI_MAX_DEVICES; ++i) {
    xaios_pci_device_t *d = &g_devices[i];
    d->bus = 0;
    d->device = 0;
    d->function = 0;
    d->vendor_id = 0;
    d->device_id = 0;
    d->class_code = 0;
    d->subclass = 0;
    d->prog_if = 0;
    d->header_type = 0;
    d->interrupt_line = 0;
    d->interrupt_pin = 0;
    d->is_pcie = 0;
    d->is_virtio = 0;
    for (uint32_t b = 0; b < XAIOS_PCI_MAX_BARS; ++b) {
      d->bars[b] = 0;
    }
  }

  /* Map ECAM bus 0 (1MB) */
  map_ecam_bus0();
  if (g_ecam_mapped == 0) {
    klog("PCI: ECAM mapping failed\n");
    return;
  }

  /* Verify ECAM accessibility: read bus 0 device 0 function 0 */
  uint32_t bdf0 = ecam_read32(0, 0, 0, 0);
  if (bdf0 == UINT32_C(0xFFFFFFFF)) {
    klog("PCI: ECAM reads all-ones, PCIe host not present\n");
    g_ecam_mapped = 0;
    return;
  }

  klog("PCI: ECAM mapped bus0 at 0x%lx BDF[0,0,0]=0x%x\n",
       XAIOS_PCI_ECAM_BASE, bdf0);

  /* Enumerate bus 0 */
  for (uint8_t dev = 0; dev < 32; ++dev) {
    uint16_t vendor = ecam_read16(0, dev, 0, XAIOS_PCI_VENDOR_ID);
    if (vendor == XAIOS_PCI_VENDOR_INVALID) {
      continue;
    }

    add_device(0, dev, 0);

    /* Check multi-function bit */
    uint8_t hdr = ecam_read8(0, dev, 0, XAIOS_PCI_HEADER_TYPE);
    if ((hdr & 0x80) != 0) {
      for (uint8_t func = 1; func < 8; ++func) {
        uint16_t v = ecam_read16(0, dev, func, XAIOS_PCI_VENDOR_ID);
        if (v != XAIOS_PCI_VENDOR_INVALID) {
          add_device(0, dev, func);
        }
      }
    }
  }

  klog("PCI: enumerated %u devices (virtio=%u net=%u bridge=%u)\n",
       g_device_count, g_virtio_count, g_network_count, g_bridge_count);

  /* Log each device */
  for (uint32_t i = 0; i < g_device_count; ++i) {
    const xaios_pci_device_t *d = &g_devices[i];
    klog("PCI: [%u:%u.%u] vendor=0x%x device=0x%x class=0x%x.%x hdr=%u pcie=%u virtio=%u\n",
         d->bus, d->device, d->function, d->vendor_id, d->device_id,
         d->class_code, d->subclass, d->header_type, d->is_pcie, d->is_virtio);
  }
}

uint32_t pci_ecam_mapped(void) { return g_ecam_mapped; }

uint32_t pci_device_count(void) { return g_device_count; }

const xaios_pci_device_t *pci_device(uint32_t index) {
  if (index >= g_device_count) {
    return 0;
  }
  return &g_devices[index];
}

uint32_t pci_virtio_count(void) { return g_virtio_count; }

uint32_t pci_network_count(void) { return g_network_count; }

uint32_t pci_bridge_count(void) { return g_bridge_count; }

uint32_t pci_find_device(uint16_t vendor_id, uint16_t device_id) {
  for (uint32_t i = 0; i < g_device_count; ++i) {
    if (g_devices[i].vendor_id == vendor_id &&
        (device_id == 0 || g_devices[i].device_id == device_id)) {
      return i;
    }
  }
  return UINT32_C(0xFFFFFFFF);
}

xaios_status_t pci_enable_device(uint32_t index) {
  const xaios_pci_device_t *device = pci_device(index);
  if (device == 0) return XAIOS_ERR_INVALID;
  uint16_t command = ecam_read16(device->bus, device->device,
                                 device->function, XAIOS_PCI_COMMAND);
  command |= UINT16_C(0x0006); /* memory space and bus mastering */
  ecam_write16(device->bus, device->device, device->function,
               XAIOS_PCI_COMMAND, command);
  return (ecam_read16(device->bus, device->device, device->function,
                      XAIOS_PCI_COMMAND) & UINT16_C(0x0006)) ==
                 UINT16_C(0x0006)
             ? XAIOS_OK
             : XAIOS_ERR_IO;
}

uint64_t pci_bar_address(uint32_t index, uint32_t bar_index) {
  const xaios_pci_device_t *device = pci_device(index);
  if (device == 0 || bar_index >= XAIOS_PCI_MAX_BARS) return 0U;
  uint32_t low = device->bars[bar_index];
  if ((low & 1U) != 0U) return 0U;
  uint64_t address = (uint64_t)(low & UINT32_C(0xfffffff0));
  if ((low & UINT32_C(0x6)) == UINT32_C(0x4)) {
    if (bar_index + 1U >= XAIOS_PCI_MAX_BARS) return 0U;
    address |= (uint64_t)device->bars[bar_index + 1U] << 32U;
  }
  return address;
}

uint32_t pci_stream_id(uint32_t index) {
  const xaios_pci_device_t *device = pci_device(index);
  if (device == 0) return UINT32_MAX;
  return ((uint32_t)device->bus << 8U) |
         ((uint32_t)device->device << 3U) | device->function;
}

void pci_self_test(void) {
  if (g_ecam_mapped == 0) {
    klog("PCI: self-test skipped (ECAM not mapped)\n");
    return;
  }

  /* At least one device (host bridge) should be found */
  kassert(g_device_count >= 1);

  /* First device on bus 0 dev 0 should exist */
  const xaios_pci_device_t *d0 = pci_device(0);
  kassert(d0 != 0);
  kassert(d0->vendor_id != XAIOS_PCI_VENDOR_INVALID);

  /* Verify host bridge or known device */
  kassert(d0->class_code == XAIOS_PCI_CLASS_BRIDGE ||
          d0->class_code == XAIOS_PCI_CLASS_NETWORK ||
          d0->class_code == XAIOS_PCI_CLASS_STORAGE ||
          d0->vendor_id == XAIOS_PCI_VENDOR_REDHAT ||
          d0->vendor_id == XAIOS_PCI_VENDOR_VIRTIO);

  /* If virtio-net-pci is present, verify it */
  if (g_virtio_count > 0) {
    uint32_t idx = pci_find_device(XAIOS_PCI_VENDOR_VIRTIO, 0);
    kassert(idx != UINT32_C(0xFFFFFFFF));
    const xaios_pci_device_t *vd = pci_device(idx);
    kassert(vd != 0);
    kassert(vd->is_virtio == 1);
  }

  /* Out-of-range should return NULL */
  kassert(pci_device(XAIOS_PCI_MAX_DEVICES) == 0);

  klog("PCI: self-test passed devices=%u virtio=%u\n", g_device_count,
       g_virtio_count);
}
