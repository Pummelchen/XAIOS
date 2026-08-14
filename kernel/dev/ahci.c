#include <xaios/ahci.h>
#include <xaios/arch_cpu.h>
#include <xaios/block_device.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/pci.h>
#include <xaios/spinlock.h>
#include <xaios/timer.h>
#include <xaios/vmm.h>

#define AHCI_CLASS_STORAGE UINT8_C(0x01)
#define AHCI_SUBCLASS_SATA UINT8_C(0x06)
#define AHCI_PROGIF_AHCI UINT8_C(0x01)
#define AHCI_BAR_INDEX 5U
#define AHCI_MMIO_VIRTUAL_BASE UINT64_C(0x330000000)
#define AHCI_MMIO_BYTES UINT64_C(0x2000)
#define AHCI_PAGE_BYTES UINT64_C(4096)
#define AHCI_SECTOR_BYTES UINT64_C(512)
#define AHCI_MAX_TRANSFER_BYTES UINT64_C(4096)
#define AHCI_TIMEOUT_NS UINT64_C(5000000000)

#define AHCI_REG_CAP UINT32_C(0x00)
#define AHCI_REG_GHC UINT32_C(0x04)
#define AHCI_REG_PI UINT32_C(0x0c)
#define AHCI_GHC_HR UINT32_C(0x00000001)
#define AHCI_GHC_AE UINT32_C(0x80000000)

#define AHCI_PORT_BASE UINT32_C(0x100)
#define AHCI_PORT_BYTES UINT32_C(0x80)
#define AHCI_PXCLB UINT32_C(0x00)
#define AHCI_PXCLBU UINT32_C(0x04)
#define AHCI_PXFB UINT32_C(0x08)
#define AHCI_PXFBU UINT32_C(0x0c)
#define AHCI_PXIS UINT32_C(0x10)
#define AHCI_PXCMD UINT32_C(0x18)
#define AHCI_PXTFD UINT32_C(0x20)
#define AHCI_PXSIG UINT32_C(0x24)
#define AHCI_PXSSTS UINT32_C(0x28)
#define AHCI_PXSERR UINT32_C(0x30)
#define AHCI_PXCI UINT32_C(0x38)
#define AHCI_PXCMD_ST UINT32_C(0x00000001)
#define AHCI_PXCMD_FRE UINT32_C(0x00000010)
#define AHCI_PXCMD_FR UINT32_C(0x00004000)
#define AHCI_PXCMD_CR UINT32_C(0x00008000)
#define AHCI_PXTFD_ERR UINT32_C(0x00000001)
#define AHCI_PXTFD_DRQ UINT32_C(0x00000008)
#define AHCI_PXTFD_BSY UINT32_C(0x00000080)
#define AHCI_PXIS_TFES UINT32_C(0x40000000)
#define AHCI_SSTS_DET_MASK UINT32_C(0x0000000f)
#define AHCI_SSTS_DET_PRESENT UINT32_C(0x00000003)
#define AHCI_SSTS_IPM_MASK UINT32_C(0x00000f00)
#define AHCI_SSTS_IPM_ACTIVE UINT32_C(0x00000100)
#define AHCI_SATA_SIG_ATA UINT32_C(0x00000101)

#define ATA_CMD_IDENTIFY UINT8_C(0xec)
#define ATA_CMD_READ_DMA_EXT UINT8_C(0x25)
#define ATA_CMD_WRITE_DMA_EXT UINT8_C(0x35)
#define ATA_CMD_FLUSH_CACHE_EXT UINT8_C(0xea)
#define ATA_FIS_TYPE_REG_H2D UINT8_C(0x27)
#define ATA_FIS_COMMAND UINT8_C(0x80)
#define ATA_DEVICE_LBA UINT8_C(0x40)

typedef struct ahci_cmd_header {
  uint16_t flags;
  uint16_t prdt_length;
  uint32_t transferred;
  uint32_t table_base_low;
  uint32_t table_base_high;
  uint32_t reserved[4];
} __attribute__((packed)) ahci_cmd_header_t;

typedef struct ahci_prdt {
  uint32_t data_base_low;
  uint32_t data_base_high;
  uint32_t reserved;
  uint32_t byte_count;
} __attribute__((packed)) ahci_prdt_t;

typedef struct ahci_cmd_table {
  uint8_t cfis[64];
  uint8_t acmd[16];
  uint8_t reserved[48];
  ahci_prdt_t prdt[1];
} __attribute__((packed)) ahci_cmd_table_t;

typedef struct ahci_driver {
  volatile uint8_t *mmio;
  uint32_t pci_index;
  uint32_t port;
  uint64_t sectors;
  ahci_cmd_header_t *commands;
  uint8_t *received_fis;
  ahci_cmd_table_t *table;
  xaios_block_device_t block_device;
  xaios_spinlock_t lock;
  uint32_t ready;
} ahci_driver_t;

static ahci_driver_t *g_ahci;

typedef char ahci_command_header_must_be_32[
    sizeof(ahci_cmd_header_t) == 32U ? 1 : -1];
typedef char ahci_command_table_must_fit_page[
    sizeof(ahci_cmd_table_t) <= AHCI_PAGE_BYTES ? 1 : -1];

static void bytes_zero(void *destination, uint64_t size) {
  uint8_t *out = (uint8_t *)destination;
  for (uint64_t index = 0U; index < size; ++index) out[index] = 0U;
}

static void copy_string(char *destination, uint64_t capacity,
                        const char *source) {
  uint64_t index = 0U;
  while (index + 1U < capacity && source[index] != '\0') {
    destination[index] = source[index];
    ++index;
  }
  if (capacity != 0U) destination[index] = '\0';
}

static uint64_t dma_address(const void *pointer, uint64_t length) {
  uint64_t physical = 0U;
  uint64_t last_physical = 0U;
  uint32_t flags = 0U;
  uint32_t last_flags = 0U;
  uint64_t start = (uint64_t)(uintptr_t)pointer;
  if (pointer == 0 || length == 0U || start > UINT64_MAX - (length - 1U) ||
      vmm_translate(start, &physical, &flags) != XAIOS_OK ||
      vmm_translate(start + length - 1U, &last_physical, &last_flags) !=
          XAIOS_OK ||
      (flags & XAIOS_VMM_PRESENT) == 0U ||
      (last_flags & XAIOS_VMM_PRESENT) == 0U ||
      last_physical != physical + length - 1U) {
    return 0U;
  }
  return physical;
}

static uint32_t read32(uint32_t offset) {
  return *(volatile uint32_t *)(void *)(g_ahci->mmio + offset);
}

static void write32(uint32_t offset, uint32_t value) {
  *(volatile uint32_t *)(void *)(g_ahci->mmio + offset) = value;
  xaios_cpu_io_barrier();
}

static uint32_t port_offset(uint32_t register_offset) {
  return AHCI_PORT_BASE + g_ahci->port * AHCI_PORT_BYTES + register_offset;
}

static int supported_controller(const xaios_pci_device_t *device) {
  return device != 0 && device->class_code == AHCI_CLASS_STORAGE &&
         device->subclass == AHCI_SUBCLASS_SATA &&
         device->prog_if == AHCI_PROGIF_AHCI;
}

static xaios_status_t wait_port_idle(void) {
  uint64_t started = timer_now_ns();
  for (;;) {
    uint32_t command = read32(port_offset(AHCI_PXCMD));
    if ((command & (AHCI_PXCMD_CR | AHCI_PXCMD_FR)) == 0U) return XAIOS_OK;
    if (timer_now_ns() - started >= AHCI_TIMEOUT_NS) return XAIOS_ERR_IO;
    xaios_cpu_relax();
  }
}

static xaios_status_t wait_port_running(uint32_t flag) {
  uint64_t started = timer_now_ns();
  for (;;) {
    if ((read32(port_offset(AHCI_PXCMD)) & flag) != 0U) return XAIOS_OK;
    if (timer_now_ns() - started >= AHCI_TIMEOUT_NS) return XAIOS_ERR_IO;
    xaios_cpu_relax();
  }
}

static xaios_status_t map_controller(uint32_t pci_index) {
  if (pci_enable_device(pci_index) != XAIOS_OK) return XAIOS_ERR_IO;
  uint64_t physical = pci_bar_address(pci_index, AHCI_BAR_INDEX);
  if (physical == 0U || (physical & (AHCI_PAGE_BYTES - 1U)) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t offset = 0U; offset < AHCI_MMIO_BYTES;
       offset += AHCI_PAGE_BYTES) {
    if (vmm_map_page(AHCI_MMIO_VIRTUAL_BASE + offset, physical + offset,
                     XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                         XAIOS_VMM_DEVICE) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
  }
  g_ahci->mmio = (volatile uint8_t *)(uintptr_t)AHCI_MMIO_VIRTUAL_BASE;
  return XAIOS_OK;
}

static xaios_status_t reset_controller(void) {
  write32(AHCI_REG_GHC, read32(AHCI_REG_GHC) | AHCI_GHC_AE | AHCI_GHC_HR);
  uint64_t started = timer_now_ns();
  for (;;) {
    if ((read32(AHCI_REG_GHC) & AHCI_GHC_HR) == 0U) {
      write32(AHCI_REG_GHC, read32(AHCI_REG_GHC) | AHCI_GHC_AE);
      return XAIOS_OK;
    }
    if (timer_now_ns() - started >= AHCI_TIMEOUT_NS) return XAIOS_ERR_IO;
    xaios_cpu_relax();
  }
}

static xaios_status_t select_port(void) {
  uint32_t implemented = read32(AHCI_REG_PI);
  for (uint32_t port = 0U; port < 32U; ++port) {
    if ((implemented & (UINT32_C(1) << port)) == 0U) continue;
    uint32_t ssts = read32(AHCI_PORT_BASE + port * AHCI_PORT_BYTES + AHCI_PXSSTS);
    const uint32_t base = AHCI_PORT_BASE + port * AHCI_PORT_BYTES;
    const uint32_t signature = read32(base + AHCI_PXSIG);
    if ((ssts & AHCI_SSTS_DET_MASK) == AHCI_SSTS_DET_PRESENT &&
        (ssts & AHCI_SSTS_IPM_MASK) == AHCI_SSTS_IPM_ACTIVE &&
        signature == AHCI_SATA_SIG_ATA) {
      g_ahci->port = port;
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

static xaios_status_t configure_port(void) {
  uint32_t command = read32(port_offset(AHCI_PXCMD));
  write32(port_offset(AHCI_PXCMD), command &
                                      ~(AHCI_PXCMD_ST | AHCI_PXCMD_FRE));
  if (wait_port_idle() != XAIOS_OK) return XAIOS_ERR_IO;
  g_ahci->commands = (ahci_cmd_header_t *)kheap_calloc(
      sizeof(ahci_cmd_header_t) * 32U, AHCI_PAGE_BYTES);
  g_ahci->received_fis = (uint8_t *)kheap_calloc(256U, AHCI_PAGE_BYTES);
  g_ahci->table = (ahci_cmd_table_t *)kheap_calloc(
      AHCI_PAGE_BYTES, AHCI_PAGE_BYTES);
  uint64_t commands_dma = dma_address(g_ahci->commands,
                                      sizeof(ahci_cmd_header_t) * 32U);
  uint64_t fis_dma = dma_address(g_ahci->received_fis, 256U);
  uint64_t table_dma = dma_address(g_ahci->table, sizeof(*g_ahci->table));
  if (g_ahci->commands == 0 || g_ahci->received_fis == 0 ||
      g_ahci->table == 0 || commands_dma == 0U || fis_dma == 0U ||
      table_dma == 0U) return XAIOS_ERR_NO_MEMORY;
  g_ahci->commands[0].table_base_low = (uint32_t)table_dma;
  g_ahci->commands[0].table_base_high = (uint32_t)(table_dma >> 32U);
  write32(port_offset(AHCI_PXCLB), (uint32_t)commands_dma);
  write32(port_offset(AHCI_PXCLBU), (uint32_t)(commands_dma >> 32U));
  write32(port_offset(AHCI_PXFB), (uint32_t)fis_dma);
  write32(port_offset(AHCI_PXFBU), (uint32_t)(fis_dma >> 32U));
  write32(port_offset(AHCI_PXIS), UINT32_MAX);
  write32(port_offset(AHCI_PXSERR), UINT32_MAX);
  command = read32(port_offset(AHCI_PXCMD));
  write32(port_offset(AHCI_PXCMD), command | AHCI_PXCMD_FRE);
  if (wait_port_running(AHCI_PXCMD_FR) != XAIOS_OK) return XAIOS_ERR_IO;
  write32(port_offset(AHCI_PXCMD),
          read32(port_offset(AHCI_PXCMD)) | AHCI_PXCMD_ST);
  if (wait_port_running(AHCI_PXCMD_CR) != XAIOS_OK) return XAIOS_ERR_IO;
  return XAIOS_OK;
}

static xaios_status_t issue_command(uint8_t command, uint64_t lba,
                                    void *buffer, uint64_t length,
                                    uint32_t write) {
  if ((length != 0U && (buffer == 0 || length > AHCI_MAX_TRANSFER_BYTES ||
                        length % AHCI_SECTOR_BYTES != 0U)) ||
      lba > UINT64_C(0x0000ffffffffffff)) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t data_dma = length == 0U ? 0U : dma_address(buffer, length);
  if (length != 0U && data_dma == 0U) return XAIOS_ERR_INVALID;
  uint64_t started = timer_now_ns();
  while ((read32(port_offset(AHCI_PXTFD)) &
          (AHCI_PXTFD_BSY | AHCI_PXTFD_DRQ)) != 0U) {
    if (timer_now_ns() - started >= AHCI_TIMEOUT_NS) return XAIOS_ERR_IO;
    xaios_cpu_relax();
  }
  ahci_cmd_header_t *header = &g_ahci->commands[0];
  uint64_t table_dma = dma_address(g_ahci->table, sizeof(*g_ahci->table));
  if (table_dma == 0U) return XAIOS_ERR_IO;
  bytes_zero(header, sizeof(*header));
  bytes_zero(g_ahci->table, sizeof(*g_ahci->table));
  header->flags = 5U | (write != 0U ? UINT16_C(0x0040) : 0U);
  header->prdt_length = length == 0U ? 0U : 1U;
  header->table_base_low = (uint32_t)table_dma;
  header->table_base_high = (uint32_t)(table_dma >> 32U);
  g_ahci->table->cfis[0] = ATA_FIS_TYPE_REG_H2D;
  g_ahci->table->cfis[1] = ATA_FIS_COMMAND;
  g_ahci->table->cfis[2] = command;
  g_ahci->table->cfis[4] = (uint8_t)lba;
  g_ahci->table->cfis[5] = (uint8_t)(lba >> 8U);
  g_ahci->table->cfis[6] = (uint8_t)(lba >> 16U);
  g_ahci->table->cfis[7] = ATA_DEVICE_LBA;
  g_ahci->table->cfis[8] = (uint8_t)(lba >> 24U);
  g_ahci->table->cfis[9] = (uint8_t)(lba >> 32U);
  g_ahci->table->cfis[10] = (uint8_t)(lba >> 40U);
  if (length != 0U) {
    uint16_t sectors = (uint16_t)(length / AHCI_SECTOR_BYTES);
    g_ahci->table->cfis[12] = (uint8_t)sectors;
    g_ahci->table->cfis[13] = (uint8_t)(sectors >> 8U);
    g_ahci->table->prdt[0].data_base_low = (uint32_t)data_dma;
    g_ahci->table->prdt[0].data_base_high = (uint32_t)(data_dma >> 32U);
    g_ahci->table->prdt[0].byte_count = (uint32_t)(length - 1U) |
                                       UINT32_C(0x80000000);
  }
  xaios_cpu_io_barrier();
  write32(port_offset(AHCI_PXIS), UINT32_MAX);
  write32(port_offset(AHCI_PXCI), UINT32_C(1));
  started = timer_now_ns();
  for (;;) {
    uint32_t interrupt_status = read32(port_offset(AHCI_PXIS));
    uint32_t task_file = read32(port_offset(AHCI_PXTFD));
    if ((interrupt_status & AHCI_PXIS_TFES) != 0U ||
        (task_file & AHCI_PXTFD_ERR) != 0U) return XAIOS_ERR_IO;
    if ((read32(port_offset(AHCI_PXCI)) & UINT32_C(1)) == 0U) return XAIOS_OK;
    if (timer_now_ns() - started >= AHCI_TIMEOUT_NS) return XAIOS_ERR_IO;
    xaios_cpu_relax();
  }
}

static xaios_status_t identify_device(void) {
  uint8_t *identify = (uint8_t *)kheap_calloc(AHCI_SECTOR_BYTES, AHCI_PAGE_BYTES);
  if (identify == 0) return XAIOS_ERR_NO_MEMORY;
  xaios_status_t status = issue_command(ATA_CMD_IDENTIFY, 0U, identify,
                                        AHCI_SECTOR_BYTES, 0U);
  if (status != XAIOS_OK) return status;
  uint64_t sectors = 0U;
  for (uint32_t index = 0U; index < 4U; ++index) {
    uint16_t word = (uint16_t)identify[(100U + index) * 2U] |
                    ((uint16_t)identify[(100U + index) * 2U + 1U] << 8U);
    sectors |= (uint64_t)word << (16U * index);
  }
  if (sectors == 0U) {
    sectors = (uint64_t)((uint16_t)identify[120U] |
                         ((uint16_t)identify[121U] << 8U)) |
              ((uint64_t)((uint16_t)identify[122U] |
                          ((uint16_t)identify[123U] << 8U)) << 16U);
  }
  if (sectors == 0U || sectors > UINT64_MAX / AHCI_SECTOR_BYTES) {
    return XAIOS_ERR_INVALID;
  }
  g_ahci->sectors = sectors;
  return XAIOS_OK;
}

static xaios_status_t transfer(void *context, uint64_t offset, void *buffer,
                               uint64_t length, uint32_t write) {
  ahci_driver_t *driver = (ahci_driver_t *)context;
  if (driver != g_ahci || driver->ready == 0U || buffer == 0 ||
      length == 0U || offset % AHCI_SECTOR_BYTES != 0U ||
      length % AHCI_SECTOR_BYTES != 0U || offset > UINT64_MAX - length ||
      offset + length > driver->sectors * AHCI_SECTOR_BYTES) {
    return XAIOS_ERR_INVALID;
  }
  uint8_t *cursor = (uint8_t *)buffer;
  uint64_t remaining = length;
  uint64_t lba = offset / AHCI_SECTOR_BYTES;
  xaios_spin_lock(&driver->lock);
  while (remaining != 0U) {
    uint64_t chunk = remaining > AHCI_MAX_TRANSFER_BYTES
                         ? AHCI_MAX_TRANSFER_BYTES : remaining;
    xaios_status_t status = issue_command(
        write != 0U ? ATA_CMD_WRITE_DMA_EXT : ATA_CMD_READ_DMA_EXT,
        lba, cursor, chunk, write);
    if (status != XAIOS_OK) {
      xaios_spin_unlock(&driver->lock);
      return status;
    }
    cursor += chunk;
    remaining -= chunk;
    lba += chunk / AHCI_SECTOR_BYTES;
  }
  xaios_spin_unlock(&driver->lock);
  return XAIOS_OK;
}

static xaios_status_t ahci_read(void *context, uint64_t offset, void *buffer,
                                uint64_t length) {
  return transfer(context, offset, buffer, length, 0U);
}

static xaios_status_t ahci_write(void *context, uint64_t offset,
                                 const void *buffer, uint64_t length) {
  return transfer(context, offset, (void *)buffer, length, 1U);
}

static xaios_status_t ahci_flush(void *context) {
  ahci_driver_t *driver = (ahci_driver_t *)context;
  if (driver != g_ahci || driver->ready == 0U) return XAIOS_ERR_INVALID;
  xaios_spin_lock(&driver->lock);
  xaios_status_t status = issue_command(ATA_CMD_FLUSH_CACHE_EXT, 0U, 0, 0U, 0U);
  xaios_spin_unlock(&driver->lock);
  return status;
}

static const xaios_block_backend_ops_t k_ahci_ops = {
    .read = ahci_read,
    .write = ahci_write,
    .flush = ahci_flush,
    .discard = 0,
    .write_zeroes = 0,
};

static xaios_status_t register_block_device(void) {
  xaios_block_device_info_t info;
  bytes_zero(&info, sizeof(info));
  copy_string(info.identifier, sizeof(info.identifier), "/dev/ahci0p0");
  copy_string(info.backend, sizeof(info.backend), "ahci");
  info.capacity_logical_sectors = g_ahci->sectors;
  info.logical_sector_size = AHCI_SECTOR_BYTES;
  info.physical_block_size = AHCI_SECTOR_BYTES;
  info.capacity_bytes = g_ahci->sectors * AHCI_SECTOR_BYTES;
  info.max_transfer_bytes = AHCI_MAX_TRANSFER_BYTES;
  info.flush_supported = 1U;
  return block_device_register(&g_ahci->block_device, &info, &k_ahci_ops,
                               g_ahci);
}

xaios_status_t ahci_init(void) {
  if (g_ahci != 0) return g_ahci->ready != 0U ? XAIOS_OK : XAIOS_ERR_IO;
  uint32_t index = UINT32_MAX;
  for (uint32_t candidate = 0U; candidate < pci_device_count(); ++candidate) {
    if (supported_controller(pci_device(candidate)) != 0) {
      index = candidate;
      break;
    }
  }
  if (index == UINT32_MAX) return XAIOS_ERR_NOT_FOUND;
  g_ahci = (ahci_driver_t *)kheap_calloc(sizeof(*g_ahci), AHCI_PAGE_BYTES);
  if (g_ahci == 0) return XAIOS_ERR_NO_MEMORY;
  g_ahci->pci_index = index;
  xaios_spin_init(&g_ahci->lock);
  klog("ahci: probing pci=%u bar5=0x%lx\n", index,
       pci_bar_address(index, AHCI_BAR_INDEX));
  xaios_status_t status = map_controller(index);
  if (status != XAIOS_OK) {
    klog("ahci: BAR mapping failed status=%d\n", (int)status);
    return XAIOS_ERR_IO;
  }
  klog("ahci: mapped signature=0x%x\n", read32(AHCI_PORT_BASE + AHCI_PXSIG));
  status = reset_controller();
  if (status != XAIOS_OK) {
    klog("ahci: controller reset failed status=%d\n", (int)status);
    return XAIOS_ERR_IO;
  }
  status = select_port();
  if (status != XAIOS_OK) {
    klog("ahci: no active SATA port status=%d pi=0x%x\n", (int)status,
         read32(AHCI_REG_PI));
    return XAIOS_ERR_IO;
  }
  status = configure_port();
  if (status != XAIOS_OK) {
    klog("ahci: port configuration failed status=%d\n", (int)status);
    return XAIOS_ERR_IO;
  }
  status = identify_device();
  if (status != XAIOS_OK) {
    klog("ahci: ATA identify failed status=%d tfd=0x%x is=0x%x\n",
         (int)status, read32(port_offset(AHCI_PXTFD)),
         read32(port_offset(AHCI_PXIS)));
    return XAIOS_ERR_IO;
  }
  status = register_block_device();
  if (status != XAIOS_OK) {
    klog("ahci: block registration failed status=%d\n", (int)status);
    return XAIOS_ERR_IO;
  }
  g_ahci->ready = 1U;
  klog("ahci: ready pci=%u port=%u sectors=%lu cap=0x%x\n", index,
       g_ahci->port, g_ahci->sectors, read32(AHCI_REG_CAP));
  return XAIOS_OK;
}
