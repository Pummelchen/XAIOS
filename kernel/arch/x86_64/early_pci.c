/* The x86-64 PCI scan and VirtIO transport validation, split out of early.c.
 * early_module.h is the shared seam; early_mmio.h holds the MMIO accessors. */
#include <xaios/types.h>

#include "early_mmio.h"
#include "early_module.h"
#include "early_serial.h"

#ifndef XAIOS_X86_COMMON_RUNTIME
#define XAIOS_X86_COMMON_RUNTIME 0
#endif

#if XAIOS_X86_COMMON_RUNTIME
#define X86_BRINGUP_ONLY __attribute__((unused))
#else
#define X86_BRINGUP_ONLY
#endif

#define PAGE_SIZE UINT64_C(4096)
#define PCI_CONFIG_ADDRESS UINT16_C(0x0cf8)
#define PCI_CONFIG_DATA UINT16_C(0x0cfc)

#define serial_puts xaios_x86_early_serial_puts
#define serial_dec xaios_x86_early_serial_dec
#define serial_hex64 xaios_x86_early_serial_hex64
#define panic_halt xaios_x86_early_panic_halt
#define early_alloc xaios_x86_mem_alloc
#define map_high_mmio_gib xaios_x86_mem_map_mmio_gib
#define lapic_id xaios_x86_early_lapic_id
#define rdtsc xaios_x86_early_rdtsc

typedef struct x86_64_pci_state {
  uint32_t devices;
  uint32_t functions;
  uint32_t bridges;
  uint32_t virtio_devices;
  uint32_t network_devices;
  uint32_t nvme_devices;
  uint32_t pcie_devices;
  uint32_t msi_devices;
  uint32_t msix_devices;
  uint32_t modern_virtio_devices;
} x86_64_pci_state_t;

typedef struct x86_64_virtio_pci_device {
  uint8_t bus;
  uint8_t device;
  uint8_t function;
  uint8_t valid;
  uint16_t device_id;
  uint16_t reserved;
  uint64_t common_config;
  uint64_t notify_base;
  uint64_t isr_config;
  uint64_t device_config;
  uint32_t notify_multiplier;
} x86_64_virtio_pci_device_t;

typedef struct virtq_descriptor {
  uint64_t address;
  uint32_t length;
  uint16_t flags;
  uint16_t next;
} __attribute__((packed)) virtq_descriptor_t;

static x86_64_pci_state_t g_pci;
static volatile uint64_t g_virtio_msix_interrupts;
static uint64_t g_virtio_msix_isr;

void xaios_x86_pci_note_msix_interrupt(void) {
  if (g_virtio_msix_isr != 0U) (void)mmio_read8(g_virtio_msix_isr);
  ++g_virtio_msix_interrupts;
}

static uint32_t pci_read_config(uint8_t bus, uint8_t device, uint8_t function,
                                uint8_t offset) {
  uint32_t address = UINT32_C(0x80000000) | ((uint32_t)bus << 16) |
                     ((uint32_t)device << 11) | ((uint32_t)function << 8) |
                     ((uint32_t)offset & UINT32_C(0xfc));
  outl(PCI_CONFIG_ADDRESS, address);
  return inl(PCI_CONFIG_DATA);
}

static void pci_write_config(uint8_t bus, uint8_t device, uint8_t function,
                             uint8_t offset, uint32_t value) {
  uint32_t address = UINT32_C(0x80000000) | ((uint32_t)bus << 16) |
                     ((uint32_t)device << 11) | ((uint32_t)function << 8) |
                     ((uint32_t)offset & UINT32_C(0xfc));
  outl(PCI_CONFIG_ADDRESS, address);
  outl(PCI_CONFIG_DATA, value);
}

static uint8_t pci_read_config8(uint8_t bus, uint8_t device, uint8_t function,
                                uint8_t offset) {
  uint32_t value = pci_read_config(bus, device, function, offset);
  return (uint8_t)(value >> ((offset & 3U) * 8U));
}

static uint64_t pci_bar_address(uint8_t bus, uint8_t device,
                                uint8_t function, uint8_t bar) {
  if (bar >= 6U) return 0U;
  uint8_t offset = (uint8_t)(0x10U + bar * 4U);
  uint32_t low = pci_read_config(bus, device, function, offset);
  if ((low & 1U) != 0U) return 0U;
  uint64_t address = low & UINT32_C(0xfffffff0);
  if ((low & UINT32_C(6)) == UINT32_C(4) && bar + 1U < 6U) {
    address |= (uint64_t)pci_read_config(bus, device, function,
                                         (uint8_t)(offset + 4U))
               << 32U;
  }
  return address;
}

static int find_virtio_pci_device(uint16_t wanted_device_id,
                                  x86_64_virtio_pci_device_t *result) {
  if (result == 0) return 0;
  *result = (x86_64_virtio_pci_device_t){0};
  for (uint16_t bus = 0U; bus < 256U; ++bus) {
    for (uint8_t device = 0U; device < 32U; ++device) {
      uint32_t header = pci_read_config((uint8_t)bus, device, 0U, 0x0cU);
      uint8_t functions = ((header >> 16U) & UINT32_C(0x80)) != 0U ? 8U : 1U;
      for (uint8_t function = 0U; function < functions; ++function) {
        uint32_t id =
            pci_read_config((uint8_t)bus, device, function, 0x00U);
        if ((uint16_t)id != UINT16_C(0x1af4) ||
            (uint16_t)(id >> 16U) != wanted_device_id) {
          continue;
        }
        result->bus = (uint8_t)bus;
        result->device = device;
        result->function = function;
        result->device_id = wanted_device_id;
        uint8_t pointer =
            pci_read_config8((uint8_t)bus, device, function, 0x34U) & 0xfcU;
        uint32_t visited = 0U;
        while (pointer >= 0x40U && pointer <= 0xfcU && visited++ < 48U) {
          uint8_t capability = pci_read_config8(
              (uint8_t)bus, device, function, pointer);
          uint8_t next = pci_read_config8(
              (uint8_t)bus, device, function, (uint8_t)(pointer + 1U)) &
                         0xfcU;
          if (capability == 0x09U &&
              pci_read_config8((uint8_t)bus, device, function,
                               (uint8_t)(pointer + 2U)) >= 16U) {
            uint8_t type = pci_read_config8(
                (uint8_t)bus, device, function, (uint8_t)(pointer + 3U));
            uint8_t bar = pci_read_config8(
                (uint8_t)bus, device, function, (uint8_t)(pointer + 4U));
            uint64_t bar_address =
                pci_bar_address((uint8_t)bus, device, function, bar);
            uint32_t offset = pci_read_config(
                (uint8_t)bus, device, function, (uint8_t)(pointer + 8U));
            uint64_t address = bar_address + offset;
            if (bar_address != 0U && address >= bar_address) {
              if (type == 1U) result->common_config = address;
              if (type == 2U) {
                result->notify_base = address;
                result->notify_multiplier = pci_read_config(
                    (uint8_t)bus, device, function,
                    (uint8_t)(pointer + 16U));
              }
              if (type == 3U) result->isr_config = address;
              if (type == 4U) result->device_config = address;
            }
          }
          if (next == 0U || next == pointer) break;
          pointer = next;
        }
        if (result->common_config != 0U && result->notify_base != 0U &&
            result->notify_multiplier != 0U) {
          uint32_t command = pci_read_config(
              (uint8_t)bus, device, function, 0x04U);
          pci_write_config((uint8_t)bus, device, function, 0x04U,
                           command | UINT32_C(6));
          result->valid = 1U;
          return 1;
        }
        return 0;
      }
    }
  }
  return 0;
}

static void inspect_pci_capabilities(uint8_t bus, uint8_t device,
                                     uint8_t function) {
  uint32_t status_command = pci_read_config(bus, device, function, 0x04U);
  if ((status_command & UINT32_C(1 << 20)) == 0U) return;
  uint8_t pointer = pci_read_config8(bus, device, function, 0x34U) & 0xfcU;
  uint32_t visited = 0U;
  while (pointer >= 0x40U && pointer <= 0xfcU && visited++ < 48U) {
    uint8_t capability = pci_read_config8(bus, device, function, pointer);
    if (capability == 0x05U) ++g_pci.msi_devices;
    if (capability == 0x10U) ++g_pci.pcie_devices;
    if (capability == 0x11U) ++g_pci.msix_devices;
    uint8_t next =
        pci_read_config8(bus, device, function, (uint8_t)(pointer + 1U)) &
        0xfcU;
    if (next == pointer) break;
    pointer = next;
  }
}

void X86_BRINGUP_ONLY xaios_x86_pci_discover(uint16_t serial_base) {
  g_pci = (x86_64_pci_state_t){0};
  for (uint16_t bus = 0; bus < 256; ++bus) {
    for (uint8_t device = 0; device < 32; ++device) {
      uint32_t header0 = pci_read_config((uint8_t)bus, device, 0, 0);
      if (header0 == UINT32_C(0xffffffff)) {
        continue;
      }
      uint32_t header_type_reg = pci_read_config((uint8_t)bus, device, 0, 0x0c);
      uint8_t header_type = (uint8_t)((header_type_reg >> 16) & 0xffU);
      uint8_t functions = (header_type & 0x80U) != 0U ? 8U : 1U;
      for (uint8_t function = 0; function < functions; ++function) {
        uint32_t id = pci_read_config((uint8_t)bus, device, function, 0);
        if (id == UINT32_C(0xffffffff)) {
          continue;
        }
        uint16_t vendor = (uint16_t)(id & UINT32_C(0xffff));
        uint16_t device_id = (uint16_t)((id >> 16) & UINT32_C(0xffff));
        uint32_t class_reg =
            pci_read_config((uint8_t)bus, device, function, 0x08);
        uint8_t class_code = (uint8_t)(class_reg >> 24);
        uint8_t subclass = (uint8_t)((class_reg >> 16) & UINT32_C(0xff));
        g_pci.functions++;
        if (function == 0) {
          g_pci.devices++;
        }
        if (class_code == 0x06U && subclass == 0x04U) {
          g_pci.bridges++;
        }
        if (vendor == 0x1af4U) {
          g_pci.virtio_devices++;
          if (device_id >= 0x1040U && device_id <= 0x107fU) {
            ++g_pci.modern_virtio_devices;
          }
        }
        if (class_code == 0x02U) {
          g_pci.network_devices++;
        }
        if (class_code == 0x01U && subclass == 0x08U) {
          g_pci.nvme_devices++;
        }
        inspect_pci_capabilities((uint8_t)bus, device, function);
      }
    }
  }

  if (g_pci.devices == 0) {
    panic_halt(serial_base, "PCI enumeration found no devices");
  }

  serial_puts(serial_base, "x86_64: PCI discovery devices=");
  serial_dec(serial_base, g_pci.devices);
  serial_puts(serial_base, " functions=");
  serial_dec(serial_base, g_pci.functions);
  serial_puts(serial_base, " virtio=");
  serial_dec(serial_base, g_pci.virtio_devices);
  serial_puts(serial_base, " net=");
  serial_dec(serial_base, g_pci.network_devices);
  serial_puts(serial_base, " nvme=");
  serial_dec(serial_base, g_pci.nvme_devices);
  serial_puts(serial_base, " pcie=");
  serial_dec(serial_base, g_pci.pcie_devices);
  serial_puts(serial_base, " msi=");
  serial_dec(serial_base, g_pci.msi_devices);
  serial_puts(serial_base, " msix=");
  serial_dec(serial_base, g_pci.msix_devices);
  serial_puts(serial_base, " modern_virtio=");
  serial_dec(serial_base, g_pci.modern_virtio_devices);
  serial_puts(serial_base, "\n");
}

static int virtio_begin(const x86_64_virtio_pci_device_t *device) {
  uint64_t common = device->common_config;
  mmio_write8(common + 20U, 0U);
  for (uint32_t spin = 0U; spin < 1000000U; ++spin) {
    if (mmio_read8(common + 20U) == 0U) break;
  }
  if (mmio_read8(common + 20U) != 0U) return 0;
  mmio_write8(common + 20U, 1U);
  mmio_write8(common + 20U, 3U);
  mmio_write32(common + 0U, 1U);
  uint32_t high_features = mmio_read32(common + 4U);
  if ((high_features & 1U) == 0U) return 0;
  mmio_write32(common + 8U, 0U);
  mmio_write32(common + 12U, 0U);
  mmio_write32(common + 8U, 1U);
  mmio_write32(common + 12U, 1U);
  mmio_write8(common + 20U, 11U);
  if ((mmio_read8(common + 20U) & 8U) == 0U) return 0;
  return 1;
}

static int virtio_setup_queue(const x86_64_virtio_pci_device_t *device,
                              uint16_t queue_index, uint8_t *queue_memory,
                              uint16_t msix_vector,
                              uint16_t *notify_offset) {
  uint64_t common = device->common_config;
  mmio_write16(common + 22U, queue_index);
  uint16_t maximum = mmio_read16(common + 24U);
  if (maximum == 0U || queue_memory == 0 || notify_offset == 0) return 0;
  uint16_t size = maximum < 8U ? maximum : 8U;
  for (uint32_t i = 0U; i < PAGE_SIZE; ++i) queue_memory[i] = 0U;
  uint64_t descriptor_address = (uint64_t)(uintptr_t)queue_memory;
  uint64_t available_address = descriptor_address + UINT64_C(256);
  uint64_t used_address = descriptor_address + UINT64_C(512);
  mmio_write16(common + 24U, size);
  mmio_write16(common + 26U, msix_vector);
  mmio_write64(common + 32U, descriptor_address);
  mmio_write64(common + 40U, available_address);
  mmio_write64(common + 48U, used_address);
  *notify_offset = mmio_read16(common + 30U);
  mmio_write16(common + 28U, 1U);
  return mmio_read16(common + 28U) == 1U;
}

static void virtio_notify(const x86_64_virtio_pci_device_t *device,
                          uint16_t queue_index, uint16_t notify_offset) {
  uint64_t address = device->notify_base +
                     (uint64_t)notify_offset * device->notify_multiplier;
  __atomic_thread_fence(__ATOMIC_RELEASE);
  mmio_write16(address, queue_index);
}

static int configure_msix(const x86_64_virtio_pci_device_t *device,
                          uint16_t table_entry, uint8_t vector) {
  uint8_t pointer = pci_read_config8(device->bus, device->device,
                                     device->function, 0x34U) &
                    0xfcU;
  uint32_t visited = 0U;
  while (pointer >= 0x40U && pointer <= 0xfcU && visited++ < 48U) {
    uint32_t header = pci_read_config(device->bus, device->device,
                                      device->function, pointer);
    if ((header & UINT32_C(0xff)) == UINT32_C(0x11)) {
      uint16_t control = (uint16_t)(header >> 16U);
      uint16_t table_size = (uint16_t)((control & UINT16_C(0x07ff)) + 1U);
      if (table_entry >= table_size) return 0;
      uint32_t table = pci_read_config(device->bus, device->device,
                                       device->function,
                                       (uint8_t)(pointer + 4U));
      uint8_t bar = (uint8_t)(table & 7U);
      uint64_t table_base =
          pci_bar_address(device->bus, device->device, device->function, bar) +
          (table & UINT32_C(0xfffffff8));
      uint64_t entry = table_base + (uint64_t)table_entry * 16U;
      if (table_base == 0U || entry < table_base ||
          !map_high_mmio_gib(entry)) {
        return 0;
      }
      mmio_write32(entry + 12U, 1U);
      mmio_write32(entry + 0U,
                   UINT32_C(0xfee00000) | (lapic_id() << 12U));
      mmio_write32(entry + 4U, 0U);
      mmio_write32(entry + 8U, vector);
      mmio_write32(entry + 12U, 0U);
      control = (uint16_t)((control | UINT16_C(0x8000)) &
                           ~UINT16_C(0x4000));
      pci_write_config(device->bus, device->device, device->function, pointer,
                       (header & UINT32_C(0xffff)) |
                           ((uint32_t)control << 16U));
      return 1;
    }
    uint8_t next = (uint8_t)((header >> 8U) & UINT32_C(0xfc));
    if (next == 0U || next == pointer) break;
    pointer = next;
  }
  return 0;
}

static int virtio_wait_used(volatile uint16_t *used_index,
                            uint16_t expected) {
  uint64_t deadline = rdtsc() + UINT64_C(2000000000);
  while (__atomic_load_n(used_index, __ATOMIC_ACQUIRE) != expected &&
         (int64_t)(rdtsc() - deadline) < 0) {
    __asm__ volatile("pause");
  }
  return *used_index == expected;
}

void X86_BRINGUP_ONLY xaios_x86_pci_validate_virtio_block(uint16_t serial_base) {
  x86_64_virtio_pci_device_t device;
  int found = find_virtio_pci_device(UINT16_C(0x1042), &device);
  serial_puts(serial_base, "x86_64: VirtIO block PCI transport found=");
  serial_dec(serial_base, found != 0);
  serial_puts(serial_base, " common=");
  serial_hex64(serial_base, device.common_config);
  serial_puts(serial_base, " notify=");
  serial_hex64(serial_base, device.notify_base);
  serial_puts(serial_base, " multiplier=");
  serial_dec(serial_base, device.notify_multiplier);
  serial_puts(serial_base, "\n");
  if (!found || !map_high_mmio_gib(device.common_config) ||
      !map_high_mmio_gib(device.notify_base) || !virtio_begin(&device)) {
    panic_halt(serial_base, "modern VirtIO block negotiation");
  }
  uint8_t *queue = (uint8_t *)early_alloc(PAGE_SIZE, PAGE_SIZE);
  uint8_t *request = (uint8_t *)early_alloc(PAGE_SIZE, PAGE_SIZE);
  uint16_t notify_offset = 0U;
  if (request == 0 || !configure_msix(&device, 0U, 34U) ||
      !virtio_setup_queue(&device, 0U, queue, 0U, &notify_offset)) {
    panic_halt(serial_base, "VirtIO block queue");
  }
  for (uint32_t i = 0U; i < PAGE_SIZE; ++i) request[i] = 0U;
  virtq_descriptor_t *descriptors = (virtq_descriptor_t *)(void *)queue;
  volatile uint16_t *available_index =
      (volatile uint16_t *)(void *)(queue + 258U);
  volatile uint16_t *available_ring =
      (volatile uint16_t *)(void *)(queue + 260U);
  volatile uint16_t *used_index =
      (volatile uint16_t *)(void *)(queue + 514U);
  uint8_t *data = request + 16U;
  uint8_t *status = request + 528U;
  *status = UINT8_C(0xff);
  descriptors[0] = (virtq_descriptor_t){
      (uint64_t)(uintptr_t)request, 16U, 1U, 1U};
  descriptors[1] = (virtq_descriptor_t){
      (uint64_t)(uintptr_t)data, 512U, 3U, 2U};
  descriptors[2] = (virtq_descriptor_t){
      (uint64_t)(uintptr_t)status, 1U, 2U, 0U};
  available_ring[0] = 0U;
  *available_index = 1U;
  g_virtio_msix_isr = device.isr_config;
  g_virtio_msix_interrupts = 0U;
  mmio_write8(device.common_config + 20U, 15U);
  virtio_notify(&device, 0U, notify_offset);
  __asm__ volatile("sti" ::: "memory");
  int completed = virtio_wait_used(used_index, 1U);
  __asm__ volatile("cli" ::: "memory");
  if (!completed || g_virtio_msix_interrupts == 0U || *status != 0U ||
      data[510] != UINT8_C(0x55) || data[511] != UINT8_C(0xaa)) {
    panic_halt(serial_base, "VirtIO block DMA read");
  }
  serial_puts(serial_base,
              "x86_64: modern VirtIO block DMA read passed sector=0 bytes=512\n");
  serial_puts(serial_base,
              "x86_64: VirtIO block MSI-X completion interrupt passed vector=34\n");
}

void X86_BRINGUP_ONLY xaios_x86_pci_validate_virtio_network(uint16_t serial_base) {
  x86_64_virtio_pci_device_t device;
  if (!find_virtio_pci_device(UINT16_C(0x1041), &device) ||
      !map_high_mmio_gib(device.common_config) ||
      !map_high_mmio_gib(device.notify_base) || !virtio_begin(&device)) {
    panic_halt(serial_base, "modern VirtIO network negotiation");
  }
  uint8_t *queue = (uint8_t *)early_alloc(PAGE_SIZE, PAGE_SIZE);
  uint8_t *packet = (uint8_t *)early_alloc(PAGE_SIZE, PAGE_SIZE);
  uint16_t notify_offset = 0U;
  if (packet == 0 ||
      !virtio_setup_queue(&device, 1U, queue, UINT16_C(0xffff),
                          &notify_offset)) {
    panic_halt(serial_base, "VirtIO network queue");
  }
  for (uint32_t i = 0U; i < PAGE_SIZE; ++i) packet[i] = 0U;
  uint8_t *frame = packet + 10U;
  for (uint32_t i = 0U; i < 6U; ++i) frame[i] = UINT8_C(0xff);
  const uint8_t source[6] = {0x52U, 0x54U, 0x00U, 0x12U, 0x34U, 0x56U};
  for (uint32_t i = 0U; i < 6U; ++i) frame[6U + i] = source[i];
  frame[12] = 0x08U;
  frame[13] = 0x06U;
  frame[14] = 0x00U;
  frame[15] = 0x01U;
  frame[16] = 0x08U;
  frame[17] = 0x00U;
  frame[18] = 0x06U;
  frame[19] = 0x04U;
  frame[20] = 0x00U;
  frame[21] = 0x01U;
  for (uint32_t i = 0U; i < 6U; ++i) frame[22U + i] = source[i];
  frame[28] = 10U;
  frame[29] = 0U;
  frame[30] = 2U;
  frame[31] = 15U;
  frame[38] = 10U;
  frame[39] = 0U;
  frame[40] = 2U;
  frame[41] = 2U;
  virtq_descriptor_t *descriptors = (virtq_descriptor_t *)(void *)queue;
  volatile uint16_t *available_index =
      (volatile uint16_t *)(void *)(queue + 258U);
  volatile uint16_t *available_ring =
      (volatile uint16_t *)(void *)(queue + 260U);
  volatile uint16_t *used_index =
      (volatile uint16_t *)(void *)(queue + 514U);
  descriptors[0] = (virtq_descriptor_t){
      (uint64_t)(uintptr_t)packet, 52U, 0U, 0U};
  available_ring[0] = 0U;
  *available_index = 1U;
  mmio_write8(device.common_config + 20U, 15U);
  virtio_notify(&device, 1U, notify_offset);
  if (!virtio_wait_used(used_index, 1U)) {
    panic_halt(serial_base, "VirtIO network DMA TX");
  }
  serial_puts(serial_base,
              "x86_64: modern VirtIO network DMA TX passed bytes=42\n");
}
