#include <xaios/arch_cpu.h>
#include <xaios/e1000e.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/pci.h>
#include <xaios/timer.h>
#include <xaios/vmm.h>

#define E1000_VENDOR_INTEL UINT16_C(0x8086)
#define E1000_DEVICE_82574L UINT16_C(0x10d3)
#define E1000_DEVICE_82540EM UINT16_C(0x100e)
#define E1000_DEVICE_82545EM UINT16_C(0x100f)
#define E1000_DEVICE_82545GM UINT16_C(0x10d9)

#define E1000_MMIO_VIRTUAL_BASE UINT64_C(0x320000000)
#define E1000_MMIO_BYTES UINT64_C(0x6000)
#define E1000_PAGE_SIZE UINT64_C(4096)
#define E1000_RING_SIZE 32U
#define E1000_FRAME_BYTES 2048U
#define E1000_TX_TIMEOUT_NS UINT64_C(100000000)

#define E1000_REG_CTRL UINT32_C(0x0000)
#define E1000_REG_STATUS UINT32_C(0x0008)
#define E1000_REG_ICR UINT32_C(0x00c0)
#define E1000_REG_IMC UINT32_C(0x00d8)
#define E1000_REG_RCTL UINT32_C(0x0100)
#define E1000_REG_TCTL UINT32_C(0x0400)
#define E1000_REG_TIPG UINT32_C(0x0410)
#define E1000_REG_RDBAL UINT32_C(0x2800)
#define E1000_REG_RDBAH UINT32_C(0x2804)
#define E1000_REG_RDLEN UINT32_C(0x2808)
#define E1000_REG_RDH UINT32_C(0x2810)
#define E1000_REG_RDT UINT32_C(0x2818)
#define E1000_REG_TDBAL UINT32_C(0x3800)
#define E1000_REG_TDBAH UINT32_C(0x3804)
#define E1000_REG_TDLEN UINT32_C(0x3808)
#define E1000_REG_TDH UINT32_C(0x3810)
#define E1000_REG_TDT UINT32_C(0x3818)
#define E1000_REG_RAL0 UINT32_C(0x5400)
#define E1000_REG_RAH0 UINT32_C(0x5404)

#define E1000_CTRL_SLU UINT32_C(0x00000040)
#define E1000_CTRL_ASDE UINT32_C(0x00000020)
#define E1000_CTRL_RST UINT32_C(0x04000000)
#define E1000_RCTL_EN UINT32_C(0x00000002)
#define E1000_RCTL_BAM UINT32_C(0x00008000)
#define E1000_RCTL_SECRC UINT32_C(0x04000000)
#define E1000_TCTL_EN UINT32_C(0x00000002)
#define E1000_TCTL_PSP UINT32_C(0x00000008)
#define E1000_TXD_CMD_EOP UINT8_C(0x01)
#define E1000_TXD_CMD_IFCS UINT8_C(0x02)
#define E1000_TXD_CMD_RS UINT8_C(0x08)
#define E1000_TXD_STAT_DD UINT8_C(0x01)
#define E1000_RXD_STAT_DD UINT8_C(0x01)
#define E1000_RXD_STAT_EOP UINT8_C(0x02)

typedef struct e1000_rx_desc {
  uint64_t address;
  uint16_t length;
  uint16_t checksum;
  uint8_t status;
  uint8_t errors;
  uint16_t special;
} __attribute__((packed)) e1000_rx_desc_t;

typedef struct e1000_tx_desc {
  uint64_t address;
  uint16_t length;
  uint8_t cso;
  uint8_t command;
  uint8_t status;
  uint8_t css;
  uint16_t special;
} __attribute__((packed)) e1000_tx_desc_t;

typedef struct e1000_driver {
  volatile uint8_t *mmio;
  uint32_t pci_index;
  e1000_rx_desc_t *rx_desc;
  e1000_tx_desc_t *tx_desc;
  uint8_t *rx_buffers[E1000_RING_SIZE];
  uint8_t *tx_buffers[E1000_RING_SIZE];
  uint8_t mac[6];
  uint32_t rx_next;
  uint32_t tx_next;
  uint32_t ready;
} e1000_driver_t;

static e1000_driver_t *g_e1000;

typedef char e1000_rx_desc_must_be_16[(sizeof(e1000_rx_desc_t) == 16U) ? 1 : -1];
typedef char e1000_tx_desc_must_be_16[(sizeof(e1000_tx_desc_t) == 16U) ? 1 : -1];

static void bytes_copy(void *destination, const void *source, uint64_t length) {
  uint8_t *out = (uint8_t *)destination;
  const uint8_t *in = (const uint8_t *)source;
  for (uint64_t index = 0U; index < length; ++index) out[index] = in[index];
}

static uint64_t dma_address(const void *pointer, uint64_t length) {
  uint64_t physical = 0U;
  uint32_t flags = 0U;
  uint64_t start = (uint64_t)(uintptr_t)pointer;
  uint64_t last_physical = 0U;
  uint32_t last_flags = 0U;
  if (pointer == 0 || length == 0U || start > UINT64_MAX - (length - 1U) ||
      vmm_translate(start, &physical, &flags) != XAIOS_OK ||
      vmm_translate(start + length - 1U, &last_physical, &last_flags) != XAIOS_OK ||
      (flags & XAIOS_VMM_PRESENT) == 0U ||
      (last_flags & XAIOS_VMM_PRESENT) == 0U ||
      last_physical != physical + length - 1U) {
    return 0U;
  }
  return physical;
}

static uint32_t read32(uint32_t offset) {
  return *(volatile uint32_t *)(void *)(g_e1000->mmio + offset);
}

static void write32(uint32_t offset, uint32_t value) {
  *(volatile uint32_t *)(void *)(g_e1000->mmio + offset) = value;
  xaios_cpu_io_barrier();
}

static int supported_device(const xaios_pci_device_t *device) {
  if (device == 0 || device->vendor_id != E1000_VENDOR_INTEL ||
      device->class_code != XAIOS_PCI_CLASS_NETWORK) {
    return 0;
  }
  return device->device_id == E1000_DEVICE_82574L ||
         device->device_id == E1000_DEVICE_82540EM ||
         device->device_id == E1000_DEVICE_82545EM ||
         device->device_id == E1000_DEVICE_82545GM;
}

static xaios_status_t map_controller(uint32_t pci_index) {
  if (pci_enable_device(pci_index) != XAIOS_OK) return XAIOS_ERR_IO;
  uint64_t physical = pci_bar_address(pci_index, 0U);
  if (physical == 0U || (physical & (E1000_PAGE_SIZE - 1U)) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t offset = 0U; offset < E1000_MMIO_BYTES;
       offset += E1000_PAGE_SIZE) {
    if (vmm_map_page(E1000_MMIO_VIRTUAL_BASE + offset, physical + offset,
                     XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                         XAIOS_VMM_DEVICE) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
  }
  g_e1000->mmio = (volatile uint8_t *)(uintptr_t)E1000_MMIO_VIRTUAL_BASE;
  return XAIOS_OK;
}

static xaios_status_t reset_controller(void) {
  write32(E1000_REG_IMC, UINT32_MAX);
  (void)read32(E1000_REG_ICR);
  write32(E1000_REG_CTRL, read32(E1000_REG_CTRL) | E1000_CTRL_RST);
  uint64_t started = timer_now_ns();
  for (uint64_t spins = 0U; spins < UINT64_C(1000000); ++spins) {
    if ((read32(E1000_REG_CTRL) & E1000_CTRL_RST) == 0U) return XAIOS_OK;
    if (started != 0U && timer_now_ns() - started >= E1000_TX_TIMEOUT_NS) {
      return XAIOS_ERR_IO;
    }
    xaios_cpu_relax();
  }
  klog("e1000e: transmit timed out tdh=%u tdt=%u status=0x%x\n",
       read32(E1000_REG_TDH), read32(E1000_REG_TDT), read32(E1000_REG_STATUS));
  return XAIOS_ERR_IO;
}

static xaios_status_t allocate_rings(void) {
  g_e1000->rx_desc = (e1000_rx_desc_t *)kheap_calloc(
      sizeof(e1000_rx_desc_t) * E1000_RING_SIZE, E1000_PAGE_SIZE);
  g_e1000->tx_desc = (e1000_tx_desc_t *)kheap_calloc(
      sizeof(e1000_tx_desc_t) * E1000_RING_SIZE, E1000_PAGE_SIZE);
  if (g_e1000->rx_desc == 0 || g_e1000->tx_desc == 0) return XAIOS_ERR_NO_MEMORY;
  for (uint32_t index = 0U; index < E1000_RING_SIZE; ++index) {
    g_e1000->rx_buffers[index] =
        (uint8_t *)kheap_calloc(E1000_FRAME_BYTES, E1000_PAGE_SIZE);
    g_e1000->tx_buffers[index] =
        (uint8_t *)kheap_calloc(E1000_FRAME_BYTES, E1000_PAGE_SIZE);
    if (g_e1000->rx_buffers[index] == 0 || g_e1000->tx_buffers[index] == 0) {
      return XAIOS_ERR_NO_MEMORY;
    }
    uint64_t rx_dma = dma_address(g_e1000->rx_buffers[index], E1000_FRAME_BYTES);
    uint64_t tx_dma = dma_address(g_e1000->tx_buffers[index], E1000_FRAME_BYTES);
    if (rx_dma == 0U || tx_dma == 0U) return XAIOS_ERR_IO;
    g_e1000->rx_desc[index].address = rx_dma;
    g_e1000->tx_desc[index].address = tx_dma;
    g_e1000->tx_desc[index].status = E1000_TXD_STAT_DD;
  }
  return XAIOS_OK;
}

static xaios_status_t configure_controller(void) {
  uint64_t rx_dma = dma_address(g_e1000->rx_desc,
                                sizeof(e1000_rx_desc_t) * E1000_RING_SIZE);
  uint64_t tx_dma = dma_address(g_e1000->tx_desc,
                                sizeof(e1000_tx_desc_t) * E1000_RING_SIZE);
  if (rx_dma == 0U || tx_dma == 0U) return XAIOS_ERR_IO;

  uint32_t ral = read32(E1000_REG_RAL0);
  uint32_t rah = read32(E1000_REG_RAH0);
  if ((rah & UINT32_C(0x80000000)) == 0U) return XAIOS_ERR_IO;
  g_e1000->mac[0] = (uint8_t)ral;
  g_e1000->mac[1] = (uint8_t)(ral >> 8U);
  g_e1000->mac[2] = (uint8_t)(ral >> 16U);
  g_e1000->mac[3] = (uint8_t)(ral >> 24U);
  g_e1000->mac[4] = (uint8_t)rah;
  g_e1000->mac[5] = (uint8_t)(rah >> 8U);

  write32(E1000_REG_RDBAL, (uint32_t)rx_dma);
  write32(E1000_REG_RDBAH, (uint32_t)(rx_dma >> 32U));
  write32(E1000_REG_RDLEN, sizeof(e1000_rx_desc_t) * E1000_RING_SIZE);
  write32(E1000_REG_RDH, 0U);
  write32(E1000_REG_RDT, E1000_RING_SIZE - 1U);
  write32(E1000_REG_TDBAL, (uint32_t)tx_dma);
  write32(E1000_REG_TDBAH, (uint32_t)(tx_dma >> 32U));
  write32(E1000_REG_TDLEN, sizeof(e1000_tx_desc_t) * E1000_RING_SIZE);
  write32(E1000_REG_TDH, 0U);
  write32(E1000_REG_TDT, 0U);
  write32(E1000_REG_TIPG, UINT32_C(10) | (UINT32_C(8) << 10U) |
                                 (UINT32_C(6) << 20U));
  write32(E1000_REG_TCTL, E1000_TCTL_EN | E1000_TCTL_PSP |
                                (UINT32_C(0x10) << 4U) |
                                (UINT32_C(0x40) << 12U));
  write32(E1000_REG_RCTL, E1000_RCTL_EN | E1000_RCTL_BAM | E1000_RCTL_SECRC);
  write32(E1000_REG_CTRL, read32(E1000_REG_CTRL) | E1000_CTRL_SLU |
                               E1000_CTRL_ASDE);
  return XAIOS_OK;
}

xaios_status_t e1000e_init(void) {
  if (g_e1000 != 0) {
    return g_e1000->ready != 0U ? XAIOS_OK : XAIOS_ERR_IO;
  }
  uint32_t pci_index = UINT32_MAX;
  for (uint32_t index = 0U; index < pci_device_count(); ++index) {
    if (supported_device(pci_device(index)) != 0) {
      pci_index = index;
      break;
    }
  }
  if (pci_index == UINT32_MAX) return XAIOS_ERR_NOT_FOUND;
  g_e1000 = (e1000_driver_t *)kheap_calloc(sizeof(*g_e1000), E1000_PAGE_SIZE);
  if (g_e1000 == 0) return XAIOS_ERR_NO_MEMORY;
  g_e1000->pci_index = pci_index;
  if (map_controller(pci_index) != XAIOS_OK || reset_controller() != XAIOS_OK ||
      allocate_rings() != XAIOS_OK || configure_controller() != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  g_e1000->ready = 1U;
  klog("e1000e: ready pci=%u mac=%02x:%02x:%02x:%02x:%02x:%02x status=0x%x\n",
       pci_index, g_e1000->mac[0], g_e1000->mac[1], g_e1000->mac[2],
       g_e1000->mac[3], g_e1000->mac[4], g_e1000->mac[5],
       read32(E1000_REG_STATUS));
  return XAIOS_OK;
}

xaios_status_t e1000e_tx(const uint8_t *data, uint64_t length) {
  if (g_e1000 == 0 || g_e1000->ready == 0U || data == 0 || length < 14U ||
      length > E1000_FRAME_BYTES) return XAIOS_ERR_INVALID;
  uint32_t slot = g_e1000->tx_next;
  e1000_tx_desc_t *descriptor = &g_e1000->tx_desc[slot];
  if ((descriptor->status & E1000_TXD_STAT_DD) == 0U) return XAIOS_ERR_BUSY;
  bytes_copy(g_e1000->tx_buffers[slot], data, length);
  descriptor->length = (uint16_t)length;
  descriptor->cso = 0U;
  descriptor->css = 0U;
  descriptor->special = 0U;
  descriptor->status = 0U;
  descriptor->command = E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS |
                        E1000_TXD_CMD_RS;
  xaios_cpu_io_barrier();
  g_e1000->tx_next = (slot + 1U) % E1000_RING_SIZE;
  write32(E1000_REG_TDT, g_e1000->tx_next);
  uint64_t started = timer_now_ns();
  for (uint64_t spins = 0U; spins < UINT64_C(1000000); ++spins) {
    if ((descriptor->status & E1000_TXD_STAT_DD) != 0U) return XAIOS_OK;
    if (started != 0U && timer_now_ns() - started >= E1000_TX_TIMEOUT_NS) {
      return XAIOS_ERR_IO;
    }
    xaios_cpu_relax();
  }
  return XAIOS_ERR_IO;
}

uint32_t e1000e_rx_poll(uint8_t *buffer, uint64_t capacity) {
  if (g_e1000 == 0 || g_e1000->ready == 0U || buffer == 0 || capacity == 0U) {
    return 0U;
  }
  uint32_t slot = g_e1000->rx_next;
  e1000_rx_desc_t *descriptor = &g_e1000->rx_desc[slot];
  if ((descriptor->status & E1000_RXD_STAT_DD) == 0U) return 0U;
  uint32_t length = descriptor->length;
  uint32_t valid = (descriptor->status & E1000_RXD_STAT_EOP) != 0U &&
                   descriptor->errors == 0U && length >= 14U &&
                   length <= E1000_FRAME_BYTES && length <= capacity;
  if (valid != 0U) bytes_copy(buffer, g_e1000->rx_buffers[slot], length);
  descriptor->length = 0U;
  descriptor->checksum = 0U;
  descriptor->errors = 0U;
  descriptor->status = 0U;
  xaios_cpu_io_barrier();
  write32(E1000_REG_RDT, slot);
  g_e1000->rx_next = (slot + 1U) % E1000_RING_SIZE;
  return valid != 0U ? length : 0U;
}

xaios_status_t e1000e_get_mac(uint8_t mac[6]) {
  if (g_e1000 == 0 || g_e1000->ready == 0U || mac == 0) return XAIOS_ERR_NOT_FOUND;
  bytes_copy(mac, g_e1000->mac, 6U);
  return XAIOS_OK;
}

uint32_t e1000e_is_ready(void) {
  return g_e1000 != 0 && g_e1000->ready != 0U ? 1U : 0U;
}
