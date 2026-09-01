/* VMXNET3 discovery and identity.
 *
 * F-02: VMware Fusion's qualified profile uses PCI E1000E, which works and is
 * the slowest thing the platform offers. VMXNET3 is the paravirtual device
 * Fusion actually wants a guest to use, and nothing here has ever spoken to
 * one.
 *
 * This is the first part of that and only the first: find the device, map its
 * two register windows, agree a revision with it, and read back the identity
 * it reports. No queues, no DMA rings, no frames. The reason for stopping
 * here rather than pressing on is that everything after this point hangs off
 * a structure the device reads out of guest memory itself -- the driver-shared
 * area, a nest of configuration records at fixed offsets -- and a byte wrong
 * in it produces a device that activates and then behaves oddly, which is the
 * hardest kind of fault to tell from a driver bug. Getting discovery and the
 * register offsets confirmed against a real Fusion device first means that
 * when the rings do go in, a failure is about the rings.
 *
 * `network_device` does not know this file exists, so nothing can select a
 * driver that cannot yet carry a frame.
 *
 * The register layout is VMware's published one. Two windows: BAR0 carries
 * the doorbells a driver rings to hand descriptors over, BAR1 the control
 * registers. Commands are written to one register and their answer read back
 * from the same one, which is why `command_result` writes and then reads
 * rather than assuming a separate status word.
 */

#include <xaios/arch_cpu.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/pci.h>
#include <xaios/timer.h>
#include <xaios/vmm.h>
#include <xaios/vmxnet3.h>

#define VMXNET3_VENDOR_VMWARE UINT16_C(0x15ad)
#define VMXNET3_DEVICE_ID UINT16_C(0x07b0)

/* Two windows, mapped where nothing else is. E1000E takes 0x320000000 and
   0x6000 bytes; these sit above it with a gap rather than immediately after,
   so a mistake in either mapping faults instead of landing in the other. */
#define VMXNET3_BAR0_VIRTUAL_BASE UINT64_C(0x330000000)
#define VMXNET3_BAR1_VIRTUAL_BASE UINT64_C(0x331000000)
#define VMXNET3_BAR0_BYTES UINT64_C(0x1000)
#define VMXNET3_BAR1_BYTES UINT64_C(0x1000)
#define VMXNET3_PAGE_SIZE UINT64_C(4096)

/* BAR1: control. */
#define VMXNET3_REG_VRRS UINT32_C(0x000) /* revisions the device supports */
#define VMXNET3_REG_UVRS UINT32_C(0x008) /* UPT versions it supports */
#define VMXNET3_REG_DSAL UINT32_C(0x010) /* driver-shared address, low */
#define VMXNET3_REG_DSAH UINT32_C(0x018) /* and high */
#define VMXNET3_REG_CMD UINT32_C(0x020)
#define VMXNET3_REG_MACL UINT32_C(0x028)
#define VMXNET3_REG_MACH UINT32_C(0x030)

/* Commands. The device distinguishes those that set something from those that
   ask, by the constant they start from. */
#define VMXNET3_CMD_FIRST_GET UINT32_C(0xf00d0000)
#define VMXNET3_CMD_GET_LINK (VMXNET3_CMD_FIRST_GET + 2U)
#define VMXNET3_CMD_GET_PERM_MAC_LO (VMXNET3_CMD_FIRST_GET + 3U)
#define VMXNET3_CMD_GET_PERM_MAC_HI (VMXNET3_CMD_FIRST_GET + 4U)

/* ---------------------------------------------------------------------------
 * Rings.
 *
 * Everything below is a memory layout the device reads and writes directly,
 * so every field is at an offset VMware chose and none of it is negotiable.
 * It is written with explicit shifts and masks rather than C bitfields on
 * purpose: bitfield allocation order within a unit is implementation-defined,
 * so a struct that looks like the specification can still be laid out
 * differently by a different compiler, and the failure would be a device that
 * misreads a length rather than anything that looks like a bug here.
 *
 * The sizes are asserted at compile time for the same reason. A padded
 * structure is the kind of mistake that produces a ring the device walks at
 * the wrong stride, which reads as corruption rather than as a wrong size.
 */

#define VMXNET3_RING_SIZE 32U
/* Both receive rings complete into one ring. */
#define VMXNET3_RX_COMP_SIZE (VMXNET3_RING_SIZE * 2U)
#define VMXNET3_FRAME_BYTES 2048U
#define VMXNET3_DRIVER_SHARED_MAGIC UINT32_C(0xbabefee1)

/* BAR0: the doorbells. */
#define VMXNET3_REG_IMR UINT32_C(0x000)
#define VMXNET3_REG_TXPROD UINT32_C(0x600)
#define VMXNET3_REG_RXPROD UINT32_C(0x800)
#define VMXNET3_REG_RXPROD2 UINT32_C(0xa00)

#define VMXNET3_CMD_FIRST_SET UINT32_C(0xcafe0000)
#define VMXNET3_CMD_ACTIVATE_DEV (VMXNET3_CMD_FIRST_SET + 0U)
#define VMXNET3_CMD_QUIESCE_DEV (VMXNET3_CMD_FIRST_SET + 1U)
#define VMXNET3_CMD_RESET_DEV (VMXNET3_CMD_FIRST_SET + 2U)
#define VMXNET3_CMD_UPDATE_RX_MODE (VMXNET3_CMD_FIRST_SET + 3U)

/* Receive modes, as a bitmap in the shared area's filter configuration. */
#define VMXNET3_RXM_UCAST UINT32_C(0x01)
#define VMXNET3_RXM_BCAST UINT32_C(0x04)
#define VMXNET3_RXM_ALL_MULTI UINT32_C(0x08)

/* Descriptor word fields. Bit numbering is the specification's. */
#define VMXNET3_TXD_W2_LEN_MASK UINT32_C(0x00003fff) /* bits 0..13 */
#define VMXNET3_TXD_W2_GEN_SHIFT 14U
#define VMXNET3_TXD_W3_EOP_SHIFT 12U
#define VMXNET3_TXD_W3_CQ_SHIFT 13U
#define VMXNET3_TXCD_W3_GEN_SHIFT 31U

#define VMXNET3_RXD_W2_LEN_MASK UINT32_C(0x00003fff)
#define VMXNET3_RXD_W2_BTYPE_SHIFT 14U
#define VMXNET3_RXD_W2_GEN_SHIFT 31U
#define VMXNET3_RXCD_W2_LEN_MASK UINT32_C(0x00003fff)
#define VMXNET3_RXCD_W2_ERR_SHIFT 14U
#define VMXNET3_RXCD_W0_EOP_SHIFT 25U
#define VMXNET3_RXCD_W0_SOP_SHIFT 24U
#define VMXNET3_RXCD_W3_GEN_SHIFT 31U

typedef struct vmxnet3_tx_desc {
  uint64_t address;
  uint32_t word2;
  uint32_t word3;
} vmxnet3_tx_desc_t;

typedef struct vmxnet3_tx_comp_desc {
  uint32_t word0;
  uint32_t word1;
  uint32_t word2;
  uint32_t word3;
} vmxnet3_tx_comp_desc_t;

typedef struct vmxnet3_rx_desc {
  uint64_t address;
  uint32_t word2;
  uint32_t word3;
} vmxnet3_rx_desc_t;

typedef struct vmxnet3_rx_comp_desc {
  uint32_t word0;
  uint32_t word1;
  uint32_t word2;
  uint32_t word3;
} vmxnet3_rx_comp_desc_t;

/* Each descriptor is sixteen bytes; anything else means the compiler padded a
   structure the device walks at a fixed stride. */
typedef char vmxnet3_size_check[(sizeof(vmxnet3_tx_desc_t) == 16U &&
                                 sizeof(vmxnet3_tx_comp_desc_t) == 16U &&
                                 sizeof(vmxnet3_rx_desc_t) == 16U &&
                                 sizeof(vmxnet3_rx_comp_desc_t) == 16U)
                                    ? 1
                                    : -1];

/* The driver-shared area, which the device parses out of guest memory.
 *
 * This is the structure the file's opening comment warns about. Its offsets
 * are the specification's and the device reads them literally, so it is
 * written as one flat byte array with named offsets rather than as nested C
 * structures. Nested structures would express the same layout only if every
 * one of them happened to be padded the way the specification assumes, and
 * when that goes wrong the symptom is a device that activates and then
 * behaves strangely -- there is no diagnostic, because from the device's side
 * nothing is malformed. A flat array with explicit offsets cannot be padded.
 *
 * Only the fields this driver needs are written. The rest stays zero, which
 * is what the specification asks of a driver that does not use a feature. */
#define VMXNET3_DS_BYTES 768U

#define VMXNET3_DS_MAGIC 0x000U
#define VMXNET3_DS_VERSION 0x008U   /* driverInfo.version */
#define VMXNET3_DS_GUEST 0x00cU     /* driverInfo.gos */
#define VMXNET3_DS_VMXNET3_REV 0x010U
#define VMXNET3_DS_UPT_VER 0x014U
#define VMXNET3_DS_UPT_FEATURES 0x018U
#define VMXNET3_DS_DRIVER_DATA_PA 0x020U
#define VMXNET3_DS_QUEUE_DESC_PA 0x028U
#define VMXNET3_DS_DRIVER_DATA_LEN 0x030U
#define VMXNET3_DS_QUEUE_DESC_LEN 0x034U
/* `mtu` is a full word, not a half one. Reading it as sixteen bits moves
   everything after it two bytes early, which puts the queue counts where the
   device reads padding -- it then sees a driver asking for no queues at all
   and refuses to activate. This cost a round: the first version had these
   right and a later "correction" broke them. */
#define VMXNET3_DS_MTU 0x038U
#define VMXNET3_DS_MAX_NUM_RX_SG 0x03cU
#define VMXNET3_DS_NUM_TX_QUEUES 0x03eU
#define VMXNET3_DS_NUM_RX_QUEUES 0x03fU
/* The interrupt block follows the miscellaneous one, which ends after four
   reserved words at 0x40. Its own shape is a byte each for the mask mode, the
   interrupt count and the event index, then twenty-five moderation levels --
   which is what puts the control word at 0x6c and not anywhere tidier. */
#define VMXNET3_DS_INTR_MASK_MODE 0x050U
#define VMXNET3_DS_INTR_NUM_INTRS 0x051U
#define VMXNET3_DS_INTR_EVENT_INTR 0x052U
#define VMXNET3_DS_INTR_CTRL 0x06cU
#define VMXNET3_DS_RX_MODE 0x078U

/* Queue descriptors, one transmit and one receive, in one allocation.
 *
 * Each is 256 bytes, not the 128 its alignment comment suggests: after the
 * control block and the configuration come a status word and a statistics
 * block the device writes, and then padding. The receive descriptor therefore
 * begins 256 bytes in. Putting it at 128 -- where the configuration alone
 * would end -- has the device read its receive rings out of the transmit
 * descriptor's statistics, which it refuses. */
#define VMXNET3_TQD_BYTES 256U
#define VMXNET3_RQD_BYTES 256U
/* Both queue descriptors begin with a sixteen-byte control block the device
   owns, so every address the driver writes sits sixteen bytes further in than
   the configuration's own first field suggests. Writing them from zero puts
   the ring addresses into the control block, which is how the first version
   of this got activation refused. */
#define VMXNET3_TQD_NUM_DEFERRED 0x000U
#define VMXNET3_TQD_THRESHOLD 0x004U
#define VMXNET3_TQD_TX_RING_PA 0x010U
#define VMXNET3_TQD_DATA_RING_PA 0x018U
#define VMXNET3_TQD_COMP_RING_PA 0x020U
#define VMXNET3_TQD_DRIVER_DATA_PA 0x028U
#define VMXNET3_TQD_TX_RING_SIZE 0x038U
#define VMXNET3_TQD_DATA_RING_SIZE 0x03cU
#define VMXNET3_TQD_COMP_RING_SIZE 0x040U
#define VMXNET3_TQD_DRIVER_DATA_LEN 0x044U
#define VMXNET3_TQD_INTR_INDEX 0x048U

#define VMXNET3_RQD_RX_RING1_PA 0x010U
#define VMXNET3_RQD_RX_RING2_PA 0x018U
#define VMXNET3_RQD_COMP_RING_PA 0x020U
#define VMXNET3_RQD_DRIVER_DATA_PA 0x028U
#define VMXNET3_RQD_RX_RING1_SIZE 0x038U
#define VMXNET3_RQD_RX_RING2_SIZE 0x03cU
#define VMXNET3_RQD_COMP_RING_SIZE 0x040U
#define VMXNET3_RQD_DRIVER_DATA_LEN 0x044U
#define VMXNET3_RQD_INTR_INDEX 0x048U

static void put32(uint8_t *base, uint32_t offset, uint32_t value) {
  base[offset] = (uint8_t)(value & 0xffU);
  base[offset + 1U] = (uint8_t)((value >> 8U) & 0xffU);
  base[offset + 2U] = (uint8_t)((value >> 16U) & 0xffU);
  base[offset + 3U] = (uint8_t)((value >> 24U) & 0xffU);
}

static void put64(uint8_t *base, uint32_t offset, uint64_t value) {
  put32(base, offset, (uint32_t)(value & UINT32_C(0xffffffff)));
  put32(base, offset + 4U, (uint32_t)(value >> 32U));
}

static void put16(uint8_t *base, uint32_t offset, uint16_t value) {
  base[offset] = (uint8_t)(value & 0xffU);
  base[offset + 1U] = (uint8_t)((value >> 8U) & 0xffU);
}

typedef struct vmxnet3_driver {
  volatile uint8_t *bar0;
  volatile uint8_t *bar1;
  uint32_t present;
  uint32_t revision;
  uint32_t upt_version;
  uint8_t mac[6];
  uint32_t link_up;
  uint32_t link_speed_mbps;
  uint32_t active;
  uint8_t *shared;
  uint8_t *queues;
  uint8_t *tqd;
  vmxnet3_tx_desc_t *tx_ring;
  vmxnet3_tx_comp_desc_t *tx_comp;
  vmxnet3_rx_desc_t *rx_ring;
  vmxnet3_rx_desc_t *rx_ring2;
  vmxnet3_rx_comp_desc_t *rx_comp;
  uint8_t *tx_buffers[VMXNET3_RING_SIZE];
  uint8_t *rx_buffers[VMXNET3_RING_SIZE];
  uint32_t tx_produce;
  uint32_t tx_gen;
  uint32_t tx_comp_consume;
  uint32_t tx_comp_gen;
  uint32_t rx_produce;
  uint32_t rx_gen;
  uint32_t rx_comp_consume;
  uint32_t rx_comp_gen;
} vmxnet3_driver_t;

static vmxnet3_driver_t *g_vmxnet3;

static uint32_t read_bar1(uint32_t offset) {
  return *(volatile uint32_t *)(void *)(g_vmxnet3->bar1 + offset);
}

static void write_bar1(uint32_t offset, uint32_t value) {
  *(volatile uint32_t *)(void *)(g_vmxnet3->bar1 + offset) = value;
}

/* A command's answer comes back through the register it was written to. */
static uint32_t command_result(uint32_t command) {
  write_bar1(VMXNET3_REG_CMD, command);
  return read_bar1(VMXNET3_REG_CMD);
}

static int supported_device(const xaios_pci_device_t *device) {
  return device != 0 && device->vendor_id == VMXNET3_VENDOR_VMWARE &&
         device->device_id == VMXNET3_DEVICE_ID &&
         device->class_code == XAIOS_PCI_CLASS_NETWORK;
}

static xaios_status_t map_window(uint32_t pci_index, uint32_t bar,
                                 uint64_t virtual_base, uint64_t bytes,
                                 volatile uint8_t **out) {
  uint64_t physical = pci_bar_address(pci_index, bar);
  if (physical == 0U || (physical & (VMXNET3_PAGE_SIZE - 1U)) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t offset = 0U; offset < bytes; offset += VMXNET3_PAGE_SIZE) {
    if (vmm_map_page(virtual_base + offset, physical + offset,
                     XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                         XAIOS_VMM_DEVICE) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
  }
  *out = (volatile uint8_t *)(uintptr_t)virtual_base;
  return XAIOS_OK;
}

/* The highest revision both sides know.
 *
 * VRRS reports a bitmap of what the device supports rather than a number, and
 * a driver picks one and writes it back. Taking the highest bit set is what
 * makes this forward-compatible: a newer device offering revisions this
 * driver has never heard of still has bit 0, and refusing everything but an
 * exact match would turn a working device into an absent one. */
static uint32_t highest_supported(uint32_t bitmap) {
  uint32_t chosen = 0U;
  for (uint32_t bit = 0U; bit < 32U; ++bit) {
    if ((bitmap & (UINT32_C(1) << bit)) != 0U) chosen = bit + 1U;
  }
  return chosen;
}

xaios_status_t vmxnet3_probe(void) {
  if (g_vmxnet3 != 0) {
    return g_vmxnet3->present != 0U ? XAIOS_OK : XAIOS_ERR_NOT_FOUND;
  }
  g_vmxnet3 = (vmxnet3_driver_t *)kheap_calloc(sizeof(*g_vmxnet3), 16);
  if (g_vmxnet3 == 0) return XAIOS_ERR_NO_MEMORY;

  uint32_t index = 0U;
  const xaios_pci_device_t *found = 0;
  for (uint32_t candidate = 0U; candidate < XAIOS_PCI_MAX_DEVICES;
       ++candidate) {
    const xaios_pci_device_t *device = pci_device(candidate);
    if (device == 0) continue;
    if (supported_device(device)) {
      found = device;
      index = candidate;
      break;
    }
  }
  if (found == 0) return XAIOS_ERR_NOT_FOUND;

  if (pci_enable_device(index) != XAIOS_OK) return XAIOS_ERR_IO;
  xaios_status_t status =
      map_window(index, 0U, VMXNET3_BAR0_VIRTUAL_BASE, VMXNET3_BAR0_BYTES,
                 &g_vmxnet3->bar0);
  if (status != XAIOS_OK) {
    klog("vmxnet3: BAR0 mapping failed status=%d\n", (int)status);
    return status;
  }
  status = map_window(index, 1U, VMXNET3_BAR1_VIRTUAL_BASE, VMXNET3_BAR1_BYTES,
                      &g_vmxnet3->bar1);
  if (status != XAIOS_OK) {
    klog("vmxnet3: BAR1 mapping failed status=%d\n", (int)status);
    return status;
  }

  uint32_t revisions = read_bar1(VMXNET3_REG_VRRS);
  g_vmxnet3->revision = highest_supported(revisions);
  if (g_vmxnet3->revision == 0U) {
    klog("vmxnet3: device reports no usable revision (vrrs=0x%x)\n",
         revisions);
    return XAIOS_ERR_UNSUPPORTED;
  }
  write_bar1(VMXNET3_REG_VRRS, UINT32_C(1) << (g_vmxnet3->revision - 1U));
  uint32_t upt = read_bar1(VMXNET3_REG_UVRS);
  g_vmxnet3->upt_version = highest_supported(upt);
  if (g_vmxnet3->upt_version == 0U) {
    klog("vmxnet3: device reports no usable UPT version (uvrs=0x%x)\n", upt);
    return XAIOS_ERR_UNSUPPORTED;
  }
  write_bar1(VMXNET3_REG_UVRS, UINT32_C(1) << (g_vmxnet3->upt_version - 1U));

  /* The permanent address, asked for rather than read out of MACL/MACH: those
     hold whatever a driver last wrote, which before activation is nothing. */
  uint32_t low = command_result(VMXNET3_CMD_GET_PERM_MAC_LO);
  uint32_t high = command_result(VMXNET3_CMD_GET_PERM_MAC_HI);
  g_vmxnet3->mac[0] = (uint8_t)(low & 0xffU);
  g_vmxnet3->mac[1] = (uint8_t)((low >> 8U) & 0xffU);
  g_vmxnet3->mac[2] = (uint8_t)((low >> 16U) & 0xffU);
  g_vmxnet3->mac[3] = (uint8_t)((low >> 24U) & 0xffU);
  g_vmxnet3->mac[4] = (uint8_t)(high & 0xffU);
  g_vmxnet3->mac[5] = (uint8_t)((high >> 8U) & 0xffU);

  /* GET_LINK answers with the state in bit 0 and the speed above it. */
  uint32_t link = command_result(VMXNET3_CMD_GET_LINK);
  g_vmxnet3->link_up = (link & 1U) != 0U ? 1U : 0U;
  g_vmxnet3->link_speed_mbps = link >> 16U;

  g_vmxnet3->present = 1U;
  klog("vmxnet3: found revision=%u upt=%u link=%u speed=%u mac=%x:%x:%x:%x:%x:%x\n",
       g_vmxnet3->revision, g_vmxnet3->upt_version, g_vmxnet3->link_up,
       g_vmxnet3->link_speed_mbps, g_vmxnet3->mac[0], g_vmxnet3->mac[1],
       g_vmxnet3->mac[2], g_vmxnet3->mac[3], g_vmxnet3->mac[4],
       g_vmxnet3->mac[5]);
  return XAIOS_OK;
}

static uint64_t dma_address(const void *pointer, uint64_t length) {
  uint64_t physical = 0U;
  uint32_t flags = 0U;
  uint64_t last_physical = 0U;
  uint32_t last_flags = 0U;
  uint64_t start = (uint64_t)(uintptr_t)pointer;
  if (pointer == 0 || length == 0U ||
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

static void write_bar0(uint32_t offset, uint32_t value) {
  *(volatile uint32_t *)(void *)(g_vmxnet3->bar0 + offset) = value;
}

/* Rings, buffers, the shared area and the queue descriptors.
 *
 * Both rings start with the generation bit at one and the device's own copy at
 * zero, so the first pass round each ring is unambiguously the driver's work
 * rather than stale contents. Receive descriptors are handed over full of
 * empty buffers immediately; transmit ones are handed over as frames arrive. */
static xaios_status_t build_rings(void) {
  g_vmxnet3->shared = (uint8_t *)kheap_calloc(VMXNET3_DS_BYTES, VMXNET3_PAGE_SIZE);
  g_vmxnet3->queues =
      (uint8_t *)kheap_calloc(VMXNET3_TQD_BYTES + VMXNET3_RQD_BYTES,
                              VMXNET3_PAGE_SIZE);
  g_vmxnet3->tx_ring = (vmxnet3_tx_desc_t *)kheap_calloc(
      sizeof(vmxnet3_tx_desc_t) * VMXNET3_RING_SIZE, VMXNET3_PAGE_SIZE);
  g_vmxnet3->tx_comp = (vmxnet3_tx_comp_desc_t *)kheap_calloc(
      sizeof(vmxnet3_tx_comp_desc_t) * VMXNET3_RING_SIZE, VMXNET3_PAGE_SIZE);
  g_vmxnet3->rx_ring = (vmxnet3_rx_desc_t *)kheap_calloc(
      sizeof(vmxnet3_rx_desc_t) * VMXNET3_RING_SIZE, VMXNET3_PAGE_SIZE);
  /* A second receive ring, which the device requires even when a driver has
     no use for it: the pair exists so a large frame can have its header in
     one ring and its body in the other. This one is handed over empty, with
     the generation bit left clear so the device owns nothing in it. */
  g_vmxnet3->rx_ring2 = (vmxnet3_rx_desc_t *)kheap_calloc(
      sizeof(vmxnet3_rx_desc_t) * VMXNET3_RING_SIZE, VMXNET3_PAGE_SIZE);
  /* One completion ring serves both receive rings, so it has to be as long as
     the two of them together. A ring sized for one is the length the device
     is told, and it will run off the end of what was allocated. */
  g_vmxnet3->rx_comp = (vmxnet3_rx_comp_desc_t *)kheap_calloc(
      sizeof(vmxnet3_rx_comp_desc_t) * VMXNET3_RX_COMP_SIZE,
      VMXNET3_PAGE_SIZE);
  if (g_vmxnet3->shared == 0 || g_vmxnet3->queues == 0 ||
      g_vmxnet3->tx_ring == 0 || g_vmxnet3->tx_comp == 0 ||
      g_vmxnet3->rx_ring == 0 || g_vmxnet3->rx_ring2 == 0 ||
      g_vmxnet3->rx_comp == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }
  for (uint32_t i = 0U; i < VMXNET3_RING_SIZE; ++i) {
    g_vmxnet3->tx_buffers[i] =
        (uint8_t *)kheap_calloc(VMXNET3_FRAME_BYTES, VMXNET3_PAGE_SIZE);
    g_vmxnet3->rx_buffers[i] =
        (uint8_t *)kheap_calloc(VMXNET3_FRAME_BYTES, VMXNET3_PAGE_SIZE);
    if (g_vmxnet3->tx_buffers[i] == 0 || g_vmxnet3->rx_buffers[i] == 0) {
      return XAIOS_ERR_NO_MEMORY;
    }
  }

  g_vmxnet3->tx_gen = 1U;
  g_vmxnet3->rx_gen = 1U;
  g_vmxnet3->tx_comp_gen = 1U;
  g_vmxnet3->rx_comp_gen = 1U;

  /* Every receive descriptor points at a buffer and carries the driver's
     generation, which is what tells the device it may write there. */
  for (uint32_t i = 0U; i < VMXNET3_RING_SIZE; ++i) {
    uint64_t physical =
        dma_address(g_vmxnet3->rx_buffers[i], VMXNET3_FRAME_BYTES);
    if (physical == 0U) return XAIOS_ERR_IO;
    g_vmxnet3->rx_ring[i].address = physical;
    g_vmxnet3->rx_ring[i].word2 =
        (VMXNET3_FRAME_BYTES & VMXNET3_RXD_W2_LEN_MASK) |
        (UINT32_C(0) << VMXNET3_RXD_W2_BTYPE_SHIFT) |
        (g_vmxnet3->rx_gen << VMXNET3_RXD_W2_GEN_SHIFT);
    g_vmxnet3->rx_ring[i].word3 = 0U;
  }
  g_vmxnet3->rx_produce = 0U;
  return XAIOS_OK;
}

static xaios_status_t activate_device(void) {
  uint8_t *shared = g_vmxnet3->shared;
  uint8_t *tqd = g_vmxnet3->queues;
  g_vmxnet3->tqd = tqd;
  uint8_t *rqd = g_vmxnet3->queues + VMXNET3_TQD_BYTES;

  uint64_t tx_ring_pa =
      dma_address(g_vmxnet3->tx_ring,
                  sizeof(vmxnet3_tx_desc_t) * VMXNET3_RING_SIZE);
  uint64_t tx_comp_pa =
      dma_address(g_vmxnet3->tx_comp,
                  sizeof(vmxnet3_tx_comp_desc_t) * VMXNET3_RING_SIZE);
  uint64_t rx_ring_pa =
      dma_address(g_vmxnet3->rx_ring,
                  sizeof(vmxnet3_rx_desc_t) * VMXNET3_RING_SIZE);
  uint64_t rx_ring2_pa =
      dma_address(g_vmxnet3->rx_ring2,
                  sizeof(vmxnet3_rx_desc_t) * VMXNET3_RING_SIZE);
  uint64_t rx_comp_pa =
      dma_address(g_vmxnet3->rx_comp,
                  sizeof(vmxnet3_rx_comp_desc_t) * VMXNET3_RX_COMP_SIZE);
  uint64_t queues_pa =
      dma_address(g_vmxnet3->queues, VMXNET3_TQD_BYTES + VMXNET3_RQD_BYTES);
  uint64_t shared_pa = dma_address(shared, VMXNET3_DS_BYTES);
  if (tx_ring_pa == 0U || tx_comp_pa == 0U || rx_ring_pa == 0U ||
      rx_ring2_pa == 0U || rx_comp_pa == 0U || queues_pa == 0U ||
      shared_pa == 0U) {
    return XAIOS_ERR_IO;
  }

  put64(tqd, VMXNET3_TQD_TX_RING_PA, tx_ring_pa);
  put64(tqd, VMXNET3_TQD_COMP_RING_PA, tx_comp_pa);
  put32(tqd, VMXNET3_TQD_TX_RING_SIZE, VMXNET3_RING_SIZE);
  put32(tqd, VMXNET3_TQD_COMP_RING_SIZE, VMXNET3_RING_SIZE);
  put32(tqd, VMXNET3_TQD_DATA_RING_SIZE, 0U);
  put32(tqd, VMXNET3_TQD_INTR_INDEX, 0U);
  /* Ring the doorbell for a single descriptor. */
  put32(tqd, VMXNET3_TQD_NUM_DEFERRED, 0U);
  put32(tqd, VMXNET3_TQD_THRESHOLD, 1U);

  put64(rqd, VMXNET3_RQD_RX_RING1_PA, rx_ring_pa);
  put64(rqd, VMXNET3_RQD_RX_RING2_PA, rx_ring2_pa);
  put64(rqd, VMXNET3_RQD_COMP_RING_PA, rx_comp_pa);
  put32(rqd, VMXNET3_RQD_RX_RING1_SIZE, VMXNET3_RING_SIZE);
  put32(rqd, VMXNET3_RQD_RX_RING2_SIZE, VMXNET3_RING_SIZE);
  put32(rqd, VMXNET3_RQD_COMP_RING_SIZE, VMXNET3_RX_COMP_SIZE);
  put32(rqd, VMXNET3_RQD_INTR_INDEX, 0U);

  put32(shared, VMXNET3_DS_MAGIC, VMXNET3_DRIVER_SHARED_MAGIC);
  put32(shared, VMXNET3_DS_VERSION, 1U);
  /* gosBits = 64-bit, gosType = unknown. Zero leaves the device with a
     guest that claims no word size at all. */
  put32(shared, VMXNET3_DS_GUEST, 2U);
  put32(shared, VMXNET3_DS_VMXNET3_REV, UINT32_C(1) << (g_vmxnet3->revision - 1U));
  put32(shared, VMXNET3_DS_UPT_VER, UINT32_C(1) << (g_vmxnet3->upt_version - 1U));
  put64(shared, VMXNET3_DS_UPT_FEATURES, 0U);
  put64(shared, VMXNET3_DS_DRIVER_DATA_PA, 0U);
  put64(shared, VMXNET3_DS_QUEUE_DESC_PA, queues_pa);
  put32(shared, VMXNET3_DS_DRIVER_DATA_LEN, 0U);
  put32(shared, VMXNET3_DS_QUEUE_DESC_LEN,
        VMXNET3_TQD_BYTES + VMXNET3_RQD_BYTES);
  put32(shared, VMXNET3_DS_MTU, 1500U);
  put16(shared, VMXNET3_DS_MAX_NUM_RX_SG, 1U);
  shared[VMXNET3_DS_NUM_TX_QUEUES] = 1U;
  shared[VMXNET3_DS_NUM_RX_QUEUES] = 1U;
  /* Masking is the driver's job, and no interrupt is used yet: the receive
     path polls, exactly as the e1000e path does on this platform. */
  shared[VMXNET3_DS_INTR_MASK_MODE] = 0U;
  shared[VMXNET3_DS_INTR_NUM_INTRS] = 1U;
  shared[VMXNET3_DS_INTR_EVENT_INTR] = 0U;
  put32(shared, VMXNET3_DS_INTR_CTRL, 1U); /* disable interrupt delivery */
  put32(shared, VMXNET3_DS_RX_MODE,
        VMXNET3_RXM_UCAST | VMXNET3_RXM_BCAST | VMXNET3_RXM_ALL_MULTI);

  write_bar1(VMXNET3_REG_DSAL, (uint32_t)(shared_pa & UINT32_C(0xffffffff)));
  write_bar1(VMXNET3_REG_DSAH, (uint32_t)(shared_pa >> 32U));
  uint32_t result = command_result(VMXNET3_CMD_ACTIVATE_DEV);
  if (result != 0U) {
    klog("vmxnet3: activation refused result=0x%x\n", result);
    return XAIOS_ERR_IO;
  }
  /* Tell the device where the receive ring has been filled to. The producer
     index wraps at the ring size, so handing over the whole ring means
     writing the last slot rather than the count. */
  write_bar0(VMXNET3_REG_RXPROD, VMXNET3_RING_SIZE - 1U);
  g_vmxnet3->active = 1U;
  klog("vmxnet3: activated tx_ring=%u rx_ring=%u mtu=1500\n",
       VMXNET3_RING_SIZE, VMXNET3_RING_SIZE);
  return XAIOS_OK;
}

xaios_status_t vmxnet3_activate(void) {
  if (vmxnet3_is_present() == 0U) return XAIOS_ERR_NOT_FOUND;
  if (g_vmxnet3->active != 0U) return XAIOS_OK;
  xaios_status_t status = build_rings();
  if (status != XAIOS_OK) {
    klog("vmxnet3: ring setup failed status=%d\n", (int)status);
    return status;
  }
  return activate_device();
}

/* Send one frame and wait for the device to say it took it.
 *
 * The generation bit is what hands a descriptor over: the driver writes the
 * whole descriptor first and sets the generation last, so a device reading
 * concurrently either sees a descriptor it does not own or a complete one,
 * never a half-written one. That ordering is the entire handover protocol,
 * which is why the write of word2 is separated from the rest rather than
 * being one assignment. */
xaios_status_t vmxnet3_tx(const uint8_t *data, uint64_t length) {
  if (g_vmxnet3 == 0 || g_vmxnet3->active == 0U || data == 0 ||
      length == 0U || length > VMXNET3_FRAME_BYTES) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t slot = g_vmxnet3->tx_produce;
  uint8_t *buffer = g_vmxnet3->tx_buffers[slot];
  for (uint64_t i = 0U; i < length; ++i) buffer[i] = data[i];
  uint64_t physical = dma_address(buffer, VMXNET3_FRAME_BYTES);
  if (physical == 0U) return XAIOS_ERR_IO;

  vmxnet3_tx_desc_t *desc = &g_vmxnet3->tx_ring[slot];
  desc->address = physical;
  /* End of packet, and ask for a completion so the ring can be reclaimed. */
  desc->word3 = (UINT32_C(1) << VMXNET3_TXD_W3_EOP_SHIFT) |
                (UINT32_C(1) << VMXNET3_TXD_W3_CQ_SHIFT);
  xaios_cpu_io_barrier();
  desc->word2 = ((uint32_t)length & VMXNET3_TXD_W2_LEN_MASK) |
                (g_vmxnet3->tx_gen << VMXNET3_TXD_W2_GEN_SHIFT);
  xaios_cpu_io_barrier();

  g_vmxnet3->tx_produce = slot + 1U;
  if (g_vmxnet3->tx_produce >= VMXNET3_RING_SIZE) {
    g_vmxnet3->tx_produce = 0U;
    g_vmxnet3->tx_gen ^= 1U; /* the ring wrapped, so the sense flips */
  }
  /* The queue's control block, which the driver writes and the device reads.
     `txNumDeferred` is how many descriptors have been added since the device
     was last told, and `txThreshold` is how many it wants before being told.
     Leaving the count at zero says nothing is pending however many
     descriptors are actually there, and the device is entitled to believe it:
     the ring filled, the doorbell rang, and every send timed out waiting for
     a completion that was never going to come. */
  /* One descriptor pending, and say so every time.
     `txThreshold` is how many the driver will let accumulate before ringing,
     and it belongs to the driver -- it is written at activation, not read
     back. Reading it instead meant obeying whatever the device had left in
     that word: any value above one and a lone DHCP discover sits in the ring
     with the doorbell never rung, which is a send that times out while
     everything about the descriptor is correct. Batching buys nothing at this
     traffic rate, so the count is set and the doorbell rung on every frame. */
  put32(g_vmxnet3->tqd, VMXNET3_TQD_NUM_DEFERRED, 0U);
  xaios_cpu_io_barrier();
  write_bar0(VMXNET3_REG_TXPROD, g_vmxnet3->tx_produce);

  /* Wait for the completion carrying the driver's current sense. Bounded,
     because a device that never answers must not take the machine with it. */
  uint64_t started = timer_now_ns();
  for (;;) {
    vmxnet3_tx_comp_desc_t *comp =
        &g_vmxnet3->tx_comp[g_vmxnet3->tx_comp_consume];
    uint32_t generation = comp->word3 >> VMXNET3_TXCD_W3_GEN_SHIFT;
    if (generation == g_vmxnet3->tx_comp_gen) {
      g_vmxnet3->tx_comp_consume++;
      if (g_vmxnet3->tx_comp_consume >= VMXNET3_RING_SIZE) {
        g_vmxnet3->tx_comp_consume = 0U;
        g_vmxnet3->tx_comp_gen ^= 1U;
      }
      return XAIOS_OK;
    }
    if (started != 0U && timer_now_ns() - started >= UINT64_C(100000000)) {
      klog("vmxnet3: transmit timed out\n");
      return XAIOS_ERR_IO;
    }
    xaios_cpu_relax();
  }
}

/* Take one frame if the device has left one.
 *
 * The completion ring is what says a frame arrived; the descriptor ring only
 * says where it was put. Reading them the other way round -- looking for a
 * used receive descriptor -- would find buffers the device has not written
 * yet, because it owns them from the moment they are handed over. */
uint32_t vmxnet3_rx_poll(uint8_t *buffer, uint64_t capacity) {
  if (g_vmxnet3 == 0 || g_vmxnet3->active == 0U || buffer == 0 ||
      capacity == 0U) {
    return 0U;
  }
  vmxnet3_rx_comp_desc_t *comp = &g_vmxnet3->rx_comp[g_vmxnet3->rx_comp_consume];
  uint32_t generation = comp->word3 >> VMXNET3_RXCD_W3_GEN_SHIFT;
  if (generation != g_vmxnet3->rx_comp_gen) return 0U;
  xaios_cpu_io_barrier();

  uint32_t index = comp->word0 & UINT32_C(0xfff);
  uint32_t length = comp->word2 & VMXNET3_RXCD_W2_LEN_MASK;
  uint32_t error = (comp->word2 >> VMXNET3_RXCD_W2_ERR_SHIFT) & 1U;
  uint32_t copied = 0U;
  if (error == 0U && length != 0U && index < VMXNET3_RING_SIZE) {
    uint32_t take = length;
    if ((uint64_t)take > capacity) take = (uint32_t)capacity;
    const uint8_t *source = g_vmxnet3->rx_buffers[index];
    for (uint32_t i = 0U; i < take; ++i) buffer[i] = source[i];
    copied = take;
  }

  /* Hand the descriptor back whatever happened to the frame: a receive ring
     that keeps a slot after a bad packet shrinks by one every time. */
  if (index < VMXNET3_RING_SIZE) {
    uint64_t physical =
        dma_address(g_vmxnet3->rx_buffers[index], VMXNET3_FRAME_BYTES);
    if (physical != 0U) {
      vmxnet3_rx_desc_t *desc = &g_vmxnet3->rx_ring[index];
      desc->address = physical;
      xaios_cpu_io_barrier();
      desc->word2 = (VMXNET3_FRAME_BYTES & VMXNET3_RXD_W2_LEN_MASK) |
                    (g_vmxnet3->rx_gen << VMXNET3_RXD_W2_GEN_SHIFT);
    }
  }
  g_vmxnet3->rx_comp_consume++;
  if (g_vmxnet3->rx_comp_consume >= VMXNET3_RX_COMP_SIZE) {
    g_vmxnet3->rx_comp_consume = 0U;
    g_vmxnet3->rx_comp_gen ^= 1U;
  }
  write_bar0(VMXNET3_REG_RXPROD, index);
  return copied;
}

uint32_t vmxnet3_is_present(void) {
  return g_vmxnet3 != 0 && g_vmxnet3->present != 0U ? 1U : 0U;
}

xaios_status_t vmxnet3_get_mac(uint8_t mac[6]) {
  if (vmxnet3_is_present() == 0U || mac == 0) return XAIOS_ERR_NOT_FOUND;
  for (uint32_t i = 0U; i < 6U; ++i) mac[i] = g_vmxnet3->mac[i];
  return XAIOS_OK;
}

uint32_t vmxnet3_link_up(void) {
  return vmxnet3_is_present() != 0U && g_vmxnet3->link_up != 0U ? 1U : 0U;
}

/* Says what it found, including finding nothing.
 *
 * A machine with no VMXNET3 is the ordinary case -- QEMU has none and Fusion
 * only presents one when its configuration asks for it -- so absence is
 * reported and is not a failure. What would be a failure is a device that is
 * present and answers nonsense, which is why the address is checked for being
 * an address at all rather than merely being read. */
void vmxnet3_self_test(void) {
  if (vmxnet3_probe() != XAIOS_OK) {
    klog("vmxnet3: no device present; this platform uses another NIC\n");
    return;
  }
  uint8_t mac[6];
  if (vmxnet3_get_mac(mac) != XAIOS_OK) {
    klog("vmxnet3: present but reported no address\n");
    return;
  }
  uint32_t all_zero = 1U;
  uint32_t all_ones = 1U;
  for (uint32_t i = 0U; i < 6U; ++i) {
    if (mac[i] != 0x00U) all_zero = 0U;
    if (mac[i] != 0xffU) all_ones = 0U;
  }
  if (all_zero != 0U || all_ones != 0U || (mac[0] & 1U) != 0U) {
    /* All zeroes is an unwritten register, all ones is a window that reads
       back nothing, and a set low bit in the first byte is a multicast
       address, which no interface owns. Each says the read did not reach the
       device rather than that the device has an odd address. */
    klog("vmxnet3: implausible hardware address; the register window is "
         "probably wrong\n");
    return;
  }
  klog("vmxnet3: self-test passed revision=%u link=%u\n", g_vmxnet3->revision,
       g_vmxnet3->link_up);
}
