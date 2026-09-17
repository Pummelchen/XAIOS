/* Enumerating PCI Express through the configuration space the firmware
 * describes.
 *
 * This lived under arch/aarch64 until RISC-V needed it, and moving it is the
 * point rather than a tidy-up: nothing in it was ever specific to AArch64.
 * ECAM is memory-mapped configuration space -- a bus, device and function
 * shifted into an address and read -- and the only architecture-dependent
 * thing here was four barriers, now the shared one. A generic mechanism
 * filed under one architecture's name is the same identity-versus-capability
 * confusion this codebase has a rule against; it just happened to be inside
 * the codebase rather than coming from firmware.
 */
#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/arch_cpu.h>
#include <xaios/exception.h>
#include <xaios/pci.h>
#include <xaios/vmm.h>

#include "pci_ecam_internal.h"

#define PAGE_SIZE UINT64_C(4096)

static xaios_pci_device_t g_devices[XAIOS_PCI_MAX_DEVICES];
static uint32_t g_device_count;
static uint32_t g_virtio_count;
static uint32_t g_network_count;
static uint32_t g_bridge_count;
static uint32_t g_ecam_mapped;
static uint64_t g_ecam_base = XAIOS_PCI_ECAM_BASE;
static uint8_t g_ecam_start_bus;
static uint8_t g_ecam_end_bus;
static uint8_t g_ecam_bus_mapped[UINT8_MAX + 1U];

static volatile uint8_t *ecam_addr(uint8_t bus, uint8_t dev, uint8_t func,
                                   uint16_t offset) {
  uint64_t addr = g_ecam_base + ((uint64_t)(bus - g_ecam_start_bus) << 20) |
                  ((uint64_t)dev << 15) | ((uint64_t)func << 12) |
                  (uint64_t)offset;
  return (volatile uint8_t *)(uintptr_t)addr;
}

uint32_t pci_ecam_read32(uint8_t bus, uint8_t dev, uint8_t func,
                          uint16_t offset) {
  volatile uint32_t *p =
      (volatile uint32_t *)(uintptr_t)ecam_addr(bus, dev, func, offset);
  return *p;
}

uint16_t pci_ecam_read16(uint8_t bus, uint8_t dev, uint8_t func,
                          uint16_t offset) {
  volatile uint16_t *p =
      (volatile uint16_t *)(uintptr_t)ecam_addr(bus, dev, func, offset);
  return *p;
}

uint8_t pci_ecam_read8(uint8_t bus, uint8_t dev, uint8_t func,
                         uint16_t offset) {
  return *ecam_addr(bus, dev, func, offset);
}

void pci_ecam_write16(uint8_t bus, uint8_t dev, uint8_t func,
                       uint16_t offset, uint16_t value) {
  volatile uint16_t *p =
      (volatile uint16_t *)(uintptr_t)ecam_addr(bus, dev, func, offset);
  *p = value;
  xaios_cpu_io_barrier();
}

void pci_ecam_write32(uint8_t bus, uint8_t dev, uint8_t func,
                       uint16_t offset, uint32_t value) {
  volatile uint32_t *p =
      (volatile uint32_t *)(uintptr_t)ecam_addr(bus, dev, func, offset);
  *p = value;
  xaios_cpu_io_barrier();
}

static int map_ecam_bus(uint8_t bus) {
  if (bus < g_ecam_start_bus || bus > g_ecam_end_bus) {
    return 0;
  }
  if (g_ecam_bus_mapped[bus] != 0U) {
    return 1;
  }

  uint64_t bus_offset = (uint64_t)(bus - g_ecam_start_bus) << 20;
  uint64_t page = 0;
  while (page < XAIOS_PCI_ECAM_BUS0_SIZE) {
    uint64_t phys = g_ecam_base + bus_offset + page;
    if (vmm_map_page(phys, phys,
                     XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                         XAIOS_VMM_DEVICE) != XAIOS_OK) {
      klog("PCI: failed to map ECAM bus=%u page=0x%lx\n", bus, phys);
      return 0;
    }
    page += PAGE_SIZE;
  }
  g_ecam_bus_mapped[bus] = 1U;
  return 1;
}

void pci_configure_ecam(uint64_t base, uint32_t start_bus, uint32_t end_bus) {
  if (base == 0U || (base & UINT64_C(0xfffff)) != 0U ||
      start_bus > UINT8_MAX || end_bus > UINT8_MAX || end_bus < start_bus) {
    return;
  }
  g_ecam_base = base;
  g_ecam_start_bus = (uint8_t)start_bus;
  g_ecam_end_bus = (uint8_t)end_bus;
}

static int walk_pcie_caps(uint8_t bus, uint8_t dev, uint8_t func) {
  uint8_t cap_ptr = pci_ecam_read8(bus, dev, func, XAIOS_PCI_CAP_PTR);
  if (cap_ptr == 0 || cap_ptr == 0xFF) {
    return 0;
  }
  /* Walk capability list (max 16 entries to avoid infinite loops) */
  for (uint32_t i = 0; i < 16; ++i) {
    if (cap_ptr >= 252) {
      break; /* Prevent OOB read beyond 256-byte config space */
    }
    uint8_t cap_id = pci_ecam_read8(bus, dev, func, cap_ptr);
    if (cap_id == 0 || cap_id == 0xFF) {
      break;
    }
    /* Cap ID 0x10 = PCIe capability */
    if (cap_id == 0x10) {
      return 1;
    }
    cap_ptr = pci_ecam_read8(bus, dev, func, cap_ptr + 1);
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
  d->vendor_id = pci_ecam_read16(bus, dev, func, XAIOS_PCI_VENDOR_ID);
  d->device_id = pci_ecam_read16(bus, dev, func, XAIOS_PCI_DEVICE_ID);

  uint32_t class_rev = pci_ecam_read32(bus, dev, func, XAIOS_PCI_CLASS_REV);
  d->class_code = (uint8_t)((class_rev >> 24) & 0xFF);
  d->subclass = (uint8_t)((class_rev >> 16) & 0xFF);
  d->prog_if = (uint8_t)((class_rev >> 8) & 0xFF);

  uint8_t hdr = pci_ecam_read8(bus, dev, func, XAIOS_PCI_HEADER_TYPE);
  d->header_type = hdr & 0x7F;

  /* Read BARs for type 0 headers, assigning any the firmware left empty. */
  if (d->header_type == 0) {
    pci_ecam_assign_bars(bus, dev, func);
    for (uint32_t bar = 0; bar < XAIOS_PCI_MAX_BARS; ++bar) {
      d->bars[bar] =
          pci_ecam_read32(bus, dev, func,
                          XAIOS_PCI_BAR0 + (uint16_t)(bar * 4));
    }
  }

  d->interrupt_line = pci_ecam_read8(bus, dev, func, XAIOS_PCI_INTERRUPT_LINE);
  d->interrupt_pin = pci_ecam_read8(bus, dev, func, XAIOS_PCI_INTERRUPT_PIN);

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

static void queue_bridge_buses(uint8_t bus, uint8_t dev, uint8_t func,
                               uint8_t *seen, uint8_t *queue,
                               uint32_t *queue_count) {
  uint8_t secondary = pci_ecam_read8(bus, dev, func, XAIOS_PCI_SECONDARY_BUS);
  uint8_t subordinate =
      pci_ecam_read8(bus, dev, func, XAIOS_PCI_SUBORDINATE_BUS);
  if (secondary == 0U || secondary < g_ecam_start_bus ||
      secondary > subordinate || subordinate > g_ecam_end_bus) {
    return;
  }

  for (uint32_t candidate = secondary; candidate <= subordinate;
       ++candidate) {
    if (seen[candidate] != 0U || *queue_count >= UINT8_MAX + 1U) {
      continue;
    }
    seen[candidate] = 1U;
    queue[*queue_count] = (uint8_t)candidate;
    ++*queue_count;
  }
}

static void scan_bus(uint8_t bus, uint8_t *seen, uint8_t *queue,
                     uint32_t *queue_count) {
  for (uint8_t dev = 0; dev < 32; ++dev) {
    uint16_t vendor = pci_ecam_read16(bus, dev, 0, XAIOS_PCI_VENDOR_ID);
    if (vendor == XAIOS_PCI_VENDOR_INVALID) {
      continue;
    }

    add_device(bus, dev, 0);
    uint32_t class_rev = pci_ecam_read32(bus, dev, 0, XAIOS_PCI_CLASS_REV);
    if (((class_rev >> 24) & 0xFFU) == XAIOS_PCI_CLASS_BRIDGE &&
        ((class_rev >> 16) & 0xFFU) == XAIOS_PCI_SUBCLASS_PCI_TO_PCI) {
      queue_bridge_buses(bus, dev, 0, seen, queue, queue_count);
    }

    uint8_t hdr = pci_ecam_read8(bus, dev, 0, XAIOS_PCI_HEADER_TYPE);
    if ((hdr & 0x80U) == 0U) {
      continue;
    }
    for (uint8_t func = 1; func < 8; ++func) {
      uint16_t function_vendor =
          pci_ecam_read16(bus, dev, func, XAIOS_PCI_VENDOR_ID);
      if (function_vendor == XAIOS_PCI_VENDOR_INVALID) {
        continue;
      }
      add_device(bus, dev, func);
      class_rev = pci_ecam_read32(bus, dev, func, XAIOS_PCI_CLASS_REV);
      if (((class_rev >> 24) & 0xFFU) == XAIOS_PCI_CLASS_BRIDGE &&
          ((class_rev >> 16) & 0xFFU) == XAIOS_PCI_SUBCLASS_PCI_TO_PCI) {
        queue_bridge_buses(bus, dev, func, seen, queue, queue_count);
      }
    }
  }
}

void pci_init(void) {
  g_device_count = 0;
  g_virtio_count = 0;
  g_network_count = 0;
  g_bridge_count = 0;
  g_ecam_mapped = 0;
  for (uint32_t i = 0; i <= UINT8_MAX; ++i) {
    g_ecam_bus_mapped[i] = 0U;
  }

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

  /* Map and validate the root ECAM bus before discovering bridge buses. */
  if (map_ecam_bus(g_ecam_start_bus) == 0) {
    klog("PCI: ECAM mapping failed\n");
    return;
  }
  g_ecam_mapped = 1;

  /* Verify ECAM accessibility before probing a firmware device range.
   *
   * Guarded, because "not present" has two shapes and only one of them is a
   * value. A machine whose firmware describes no window leaves this pointing
   * at a compiled-in default belonging to another board, and reading there
   * faults rather than returning all-ones -- which killed a RISC-V boot at
   * the address AArch64's QEMU uses for its host bridge. A read that faults
   * and a read of all-ones mean the same thing here, and neither is fatal. */
  exception_mmio_probe_begin();
  uint32_t bdf0 = pci_ecam_read32(g_ecam_start_bus, 0, 0, 0);
  exception_mmio_probe_end();
  if (exception_mmio_probe_faulted() != 0) {
    klog("PCI: no host bridge answers at 0x%lx\n", g_ecam_base);
    g_ecam_mapped = 0;
    return;
  }
  if (bdf0 == UINT32_C(0xFFFFFFFF)) {
    klog("PCI: ECAM reads all-ones, PCIe host not present\n");
    g_ecam_mapped = 0;
    return;
  }

  klog("PCI: ECAM mapped bus=%u at 0x%lx BDF[%u,0,0]=0x%x\n",
       g_ecam_start_bus, g_ecam_base, g_ecam_start_bus, bdf0);

  uint8_t seen[UINT8_MAX + 1U] = {0};
  uint8_t queue[UINT8_MAX + 1U];
  uint32_t queue_head = 0;
  uint32_t queue_count = 1;
  seen[g_ecam_start_bus] = 1U;
  queue[0] = g_ecam_start_bus;

  while (queue_head < queue_count) {
    uint8_t bus = queue[queue_head++];
    if (map_ecam_bus(bus) == 0) {
      klog("PCI: skipped inaccessible ECAM bus=%u\n", bus);
      continue;
    }
    scan_bus(bus, seen, queue, &queue_count);
  }

  klog("PCI: enumerated %u devices (virtio=%u net=%u bridge=%u)\n",
       g_device_count, g_virtio_count, g_network_count, g_bridge_count);

  /* Log each device */
  for (uint32_t i = 0; i < g_device_count; ++i) {
    const xaios_pci_device_t *d = &g_devices[i];
    klog("PCI: [%u:%u.%u] vendor=0x%x device=0x%x class=0x%x.%x hdr=%u pcie=%u virtio=%u\n",
         d->bus, d->device, d->function, d->vendor_id, d->device_id,
         d->class_code, d->subclass, d->header_type, d->is_pcie, d->is_virtio);
    klog("PCI: [%u:%u.%u] bar0=0x%x bar1=0x%x bar4=0x%x\n", d->bus,
         d->device, d->function, d->bars[0], d->bars[1], d->bars[4]);
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
  uint16_t command = pci_ecam_read16(device->bus, device->device,
                                     device->function, XAIOS_PCI_COMMAND);
  command |= UINT16_C(0x0006); /* memory space and bus mastering */
  pci_ecam_write16(device->bus, device->device, device->function,
                   XAIOS_PCI_COMMAND, command);
  return (pci_ecam_read16(device->bus, device->device, device->function,
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

uint8_t pci_config_read8(uint32_t index, uint16_t offset) {
  const xaios_pci_device_t *device = pci_device(index);
  return device == 0
             ? UINT8_MAX
             : pci_ecam_read8(device->bus, device->device, device->function,
                              offset);
}

uint16_t pci_config_read16(uint32_t index, uint16_t offset) {
  const xaios_pci_device_t *device = pci_device(index);
  return device == 0
             ? UINT16_MAX
             : pci_ecam_read16(device->bus, device->device, device->function,
                               offset);
}

uint32_t pci_config_read32(uint32_t index, uint16_t offset) {
  const xaios_pci_device_t *device = pci_device(index);
  return device == 0
             ? UINT32_MAX
             : pci_ecam_read32(device->bus, device->device, device->function,
                               offset);
}

xaios_status_t pci_config_write16(uint32_t index, uint16_t offset,
                                  uint16_t value) {
  const xaios_pci_device_t *device = pci_device(index);
  if (device == 0) return XAIOS_ERR_INVALID;
  pci_ecam_write16(device->bus, device->device, device->function, offset,
                   value);
  return XAIOS_OK;
}

xaios_status_t pci_config_write32(uint32_t index, uint16_t offset,
                                  uint32_t value) {
  const xaios_pci_device_t *device = pci_device(index);
  if (device == 0) return XAIOS_ERR_INVALID;
  pci_ecam_write32(device->bus, device->device, device->function, offset,
                   value);
  return XAIOS_OK;
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
