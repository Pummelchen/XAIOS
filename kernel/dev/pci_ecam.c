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
#include <xaios/pci.h>
#include <xaios/vmm.h>

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
  xaios_cpu_io_barrier();
}

static void ecam_write32(uint8_t bus, uint8_t dev, uint8_t func,
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


/* Giving devices somewhere to live, when nothing else has.
 *
 * On every machine this kernel ran on before, firmware assigned PCI base
 * addresses before handing over: UEFI does it, and so does the firmware in a
 * hypervisor's virtual machine. A board booted straight from a supervisor-mode
 * SBI has no such stage, and its devices arrive with every base address still
 * zero -- present, enumerable, correctly identified, and unreachable. The
 * symptom is precise and misleading: a virtio device found by vendor and
 * device id whose capability structures all resolve to address zero, which
 * reads as a broken driver rather than an unfinished bus.
 *
 * Assignment only touches a base address that is zero, so a machine whose
 * firmware did this work keeps that firmware's layout untouched. Sizing is the
 * architectural method: write all-ones, read back, and the lowest bit still
 * set is the size, because the bits below it are hardwired to zero.
 */
static uint64_t g_mmio_next;
static uint64_t g_mmio_limit;
static uint64_t g_mmio64_next;
static uint64_t g_mmio64_limit;

void pci_configure_mmio_window(uint64_t base, uint64_t size, uint64_t base64,
                               uint64_t size64) {
  g_mmio_next = base;
  g_mmio_limit = base + size;
  g_mmio64_next = base64;
  g_mmio64_limit = base64 + size64;
}

static uint64_t allocate_window(uint64_t size, int wide) {
  if (size == 0U) return 0U;
  uint64_t *next = wide != 0 ? &g_mmio64_next : &g_mmio_next;
  uint64_t limit = wide != 0 ? g_mmio64_limit : g_mmio_limit;
  /* Naturally aligned, which the specification requires and which a device
     silently ignores rather than reporting: an unaligned base has its low
     bits read back as zero and the device answers somewhere else. */
  uint64_t aligned = (*next + size - 1U) & ~(size - 1U);
  if (aligned + size > limit || limit == 0U) return 0U;
  *next = aligned + size;
  return aligned;
}

static void assign_bars(uint8_t bus, uint8_t dev, uint8_t func) {
  if (g_mmio_limit == 0U && g_mmio64_limit == 0U) return;
  for (uint32_t bar = 0; bar < XAIOS_PCI_MAX_BARS; ++bar) {
    uint16_t offset = (uint16_t)(XAIOS_PCI_BAR0 + bar * 4U);
    uint32_t low = ecam_read32(bus, dev, func, offset);
    if ((low & 1U) != 0U) continue; /* an I/O port range, not memory */
    uint32_t type = (low >> 1U) & 3U;
    int wide = type == 2U ? 1 : 0;
    if (wide != 0 && bar + 1U >= XAIOS_PCI_MAX_BARS) break;

    uint64_t assigned = low & ~UINT64_C(0xf);
    if (wide != 0) {
      assigned |= (uint64_t)ecam_read32(bus, dev, func,
                                        (uint16_t)(offset + 4U)) << 32U;
    }
    if (assigned != 0U) {
      /* Already placed by firmware. Left exactly where it was. */
      if (wide != 0) ++bar;
      continue;
    }

    ecam_write32(bus, dev, func, offset, UINT32_C(0xffffffff));
    uint32_t probe_low = ecam_read32(bus, dev, func, offset);
    uint64_t mask = (uint64_t)(probe_low & ~UINT32_C(0xf));
    if (wide != 0) {
      ecam_write32(bus, dev, func, (uint16_t)(offset + 4U),
                   UINT32_C(0xffffffff));
      mask |= (uint64_t)ecam_read32(bus, dev, func, (uint16_t)(offset + 4U))
              << 32U;
    } else {
      mask |= ~UINT64_C(0xffffffff); /* sign-extend so ~mask+1 is the size */
    }
    uint64_t size = (~mask) + 1U;
    if (size == 0U || mask == ~UINT64_C(0)) {
      /* An unimplemented BAR reads back as all-zero once masked. Restored to
         zero rather than left holding the probe pattern. */
      ecam_write32(bus, dev, func, offset, 0U);
      if (wide != 0) {
        ecam_write32(bus, dev, func, (uint16_t)(offset + 4U), 0U);
        ++bar;
      }
      continue;
    }

    uint64_t address = allocate_window(size, wide);
    if (address == 0U) {
      klog("PCI: [%u:%u.%u] bar%u wants 0x%lx and the window is exhausted\n",
           bus, dev, func, bar, size);
      ecam_write32(bus, dev, func, offset, 0U);
      if (wide != 0) ecam_write32(bus, dev, func, (uint16_t)(offset + 4U), 0U);
      if (wide != 0) ++bar;
      continue;
    }
    ecam_write32(bus, dev, func, offset,
                 (uint32_t)(address & UINT64_C(0xffffffff)) | (low & 0xfU));
    if (wide != 0) {
      ecam_write32(bus, dev, func, (uint16_t)(offset + 4U),
                   (uint32_t)(address >> 32U));
      ++bar;
    }
  }

  /* Decoding has to be switched on, or every one of those addresses answers
     with all-ones exactly as an absent device would. */
  uint16_t command = ecam_read16(bus, dev, func, XAIOS_PCI_COMMAND);
  ecam_write16(bus, dev, func, XAIOS_PCI_COMMAND,
               (uint16_t)(command | XAIOS_PCI_COMMAND_MEMORY |
                          XAIOS_PCI_COMMAND_BUS_MASTER));
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

  /* Read BARs for type 0 headers, assigning any the firmware left empty. */
  if (d->header_type == 0) {
    assign_bars(bus, dev, func);
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

static void queue_bridge_buses(uint8_t bus, uint8_t dev, uint8_t func,
                               uint8_t *seen, uint8_t *queue,
                               uint32_t *queue_count) {
  uint8_t secondary = ecam_read8(bus, dev, func, XAIOS_PCI_SECONDARY_BUS);
  uint8_t subordinate = ecam_read8(bus, dev, func, XAIOS_PCI_SUBORDINATE_BUS);
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
    uint16_t vendor = ecam_read16(bus, dev, 0, XAIOS_PCI_VENDOR_ID);
    if (vendor == XAIOS_PCI_VENDOR_INVALID) {
      continue;
    }

    add_device(bus, dev, 0);
    uint32_t class_rev = ecam_read32(bus, dev, 0, XAIOS_PCI_CLASS_REV);
    if (((class_rev >> 24) & 0xFFU) == XAIOS_PCI_CLASS_BRIDGE &&
        ((class_rev >> 16) & 0xFFU) == XAIOS_PCI_SUBCLASS_PCI_TO_PCI) {
      queue_bridge_buses(bus, dev, 0, seen, queue, queue_count);
    }

    uint8_t hdr = ecam_read8(bus, dev, 0, XAIOS_PCI_HEADER_TYPE);
    if ((hdr & 0x80U) == 0U) {
      continue;
    }
    for (uint8_t func = 1; func < 8; ++func) {
      uint16_t function_vendor =
          ecam_read16(bus, dev, func, XAIOS_PCI_VENDOR_ID);
      if (function_vendor == XAIOS_PCI_VENDOR_INVALID) {
        continue;
      }
      add_device(bus, dev, func);
      class_rev = ecam_read32(bus, dev, func, XAIOS_PCI_CLASS_REV);
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

  /* Verify ECAM accessibility before probing a firmware device range. */
  uint32_t bdf0 = ecam_read32(g_ecam_start_bus, 0, 0, 0);
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
    klog("PCI: [%u:%u.%u] bar0=0x%lx bar1=0x%lx bar4=0x%lx\n", d->bus,
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
             : ecam_read8(device->bus, device->device, device->function,
                          offset);
}

uint16_t pci_config_read16(uint32_t index, uint16_t offset) {
  const xaios_pci_device_t *device = pci_device(index);
  return device == 0
             ? UINT16_MAX
             : ecam_read16(device->bus, device->device, device->function,
                           offset);
}

uint32_t pci_config_read32(uint32_t index, uint16_t offset) {
  const xaios_pci_device_t *device = pci_device(index);
  return device == 0
             ? UINT32_MAX
             : ecam_read32(device->bus, device->device, device->function,
                           offset);
}

xaios_status_t pci_config_write16(uint32_t index, uint16_t offset,
                                  uint16_t value) {
  const xaios_pci_device_t *device = pci_device(index);
  if (device == 0) return XAIOS_ERR_INVALID;
  ecam_write16(device->bus, device->device, device->function, offset, value);
  return XAIOS_OK;
}

xaios_status_t pci_config_write32(uint32_t index, uint16_t offset,
                                  uint32_t value) {
  const xaios_pci_device_t *device = pci_device(index);
  if (device == 0) return XAIOS_ERR_INVALID;
  ecam_write32(device->bus, device->device, device->function, offset, value);
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
