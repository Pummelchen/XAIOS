/* VMXNET3 ring construction and device activation.
 *
 * Everything that has to exist in guest memory before the device is told to
 * go: the receive and transmit rings, their buffers, the completion ring, the
 * driver-shared area and the two queue descriptors. Split out of vmxnet3.c so
 * the layout code sits next to the offsets it writes rather than beside the
 * probe and frame paths; the body is unchanged, including the order in which
 * `vmxnet3_activate` runs `build_rings` and then `activate_device`.
 */
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/vmxnet3.h>

#include "vmxnet3_internal.h"

/* Rings, buffers, the shared area and the queue descriptors.
 *
 * Both rings start with the generation bit at one and the device's own copy at
 * zero, so the first pass round each ring is unambiguously the driver's work
 * rather than stale contents. Receive descriptors are handed over full of
 * empty buffers immediately; transmit ones are handed over as frames arrive. */
static xaios_status_t build_rings(void) {
  vmxnet3_instance->shared = (uint8_t *)kheap_calloc(VMXNET3_DS_BYTES, VMXNET3_PAGE_SIZE);
  vmxnet3_instance->queues =
      (uint8_t *)kheap_calloc(VMXNET3_TQD_BYTES + VMXNET3_RQD_BYTES,
                              VMXNET3_PAGE_SIZE);
  vmxnet3_instance->tx_ring = (vmxnet3_tx_desc_t *)kheap_calloc(
      sizeof(vmxnet3_tx_desc_t) * VMXNET3_RING_SIZE, VMXNET3_PAGE_SIZE);
  vmxnet3_instance->tx_comp = (vmxnet3_tx_comp_desc_t *)kheap_calloc(
      sizeof(vmxnet3_tx_comp_desc_t) * VMXNET3_RING_SIZE, VMXNET3_PAGE_SIZE);
  vmxnet3_instance->rx_ring = (vmxnet3_rx_desc_t *)kheap_calloc(
      sizeof(vmxnet3_rx_desc_t) * VMXNET3_RING_SIZE, VMXNET3_PAGE_SIZE);
  /* A second receive ring, which the device requires even when a driver has
     no use for it: the pair exists so a large frame can have its header in
     one ring and its body in the other. This one is handed over empty, with
     the generation bit left clear so the device owns nothing in it. */
  vmxnet3_instance->rx_ring2 = (vmxnet3_rx_desc_t *)kheap_calloc(
      sizeof(vmxnet3_rx_desc_t) * VMXNET3_RING_SIZE, VMXNET3_PAGE_SIZE);
  /* One completion ring serves both receive rings, so it has to be as long as
     the two of them together. A ring sized for one is the length the device
     is told, and it will run off the end of what was allocated. */
  vmxnet3_instance->rx_comp = (vmxnet3_rx_comp_desc_t *)kheap_calloc(
      sizeof(vmxnet3_rx_comp_desc_t) * VMXNET3_RX_COMP_SIZE,
      VMXNET3_PAGE_SIZE);
  if (vmxnet3_instance->shared == 0 || vmxnet3_instance->queues == 0 ||
      vmxnet3_instance->tx_ring == 0 || vmxnet3_instance->tx_comp == 0 ||
      vmxnet3_instance->rx_ring == 0 || vmxnet3_instance->rx_ring2 == 0 ||
      vmxnet3_instance->rx_comp == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }
  for (uint32_t i = 0U; i < VMXNET3_RING_SIZE; ++i) {
    vmxnet3_instance->tx_buffers[i] =
        (uint8_t *)kheap_calloc(VMXNET3_FRAME_BYTES, VMXNET3_PAGE_SIZE);
    vmxnet3_instance->rx_buffers[i] =
        (uint8_t *)kheap_calloc(VMXNET3_FRAME_BYTES, VMXNET3_PAGE_SIZE);
    vmxnet3_instance->rx_body_buffers[i] =
        (uint8_t *)kheap_calloc(VMXNET3_FRAME_BYTES, VMXNET3_PAGE_SIZE);
    if (vmxnet3_instance->tx_buffers[i] == 0 || vmxnet3_instance->rx_buffers[i] == 0 ||
        vmxnet3_instance->rx_body_buffers[i] == 0) {
      return XAIOS_ERR_NO_MEMORY;
    }
  }

  vmxnet3_instance->tx_gen = 1U;
  vmxnet3_instance->rx_gen = 1U;
  vmxnet3_instance->tx_comp_gen = 1U;
  vmxnet3_instance->rx_comp_gen = 1U;

  /* Every receive descriptor points at a buffer and carries the driver's
     generation, which is what tells the device it may write there.
   *
     One short of the ring, deliberately, and the same as the reference
     driver does it. The producer index means "the next slot I will fill",
     so a ring with every slot filled has nowhere for that index to point
     that does not also mean something else. Leaving the last slot empty
     makes the index unambiguous for the whole of the first lap. */
  for (uint32_t i = 0U; i + 1U < VMXNET3_RING_SIZE; ++i) {
    uint64_t physical =
        vmxnet3_dma_address(vmxnet3_instance->rx_buffers[i], VMXNET3_FRAME_BYTES);
    if (physical == 0U) return XAIOS_ERR_IO;
    vmxnet3_instance->rx_ring[i].address = physical;
    vmxnet3_instance->rx_ring[i].word2 =
        (VMXNET3_FRAME_BYTES & VMXNET3_RXD_W2_LEN_MASK) |
        (UINT32_C(0) << VMXNET3_RXD_W2_BTYPE_SHIFT) |
        (vmxnet3_instance->rx_gen << VMXNET3_RXD_W2_GEN_SHIFT);
    vmxnet3_instance->rx_ring[i].word3 = 0U;

    /* The body ring, with the same shape and btype 1. A device told it has
       thirty-one of these must find thirty-one of these. */
    uint64_t body = vmxnet3_dma_address(vmxnet3_instance->rx_body_buffers[i],
                                VMXNET3_FRAME_BYTES);
    if (body == 0U) return XAIOS_ERR_IO;
    vmxnet3_instance->rx_ring2[i].address = body;
    vmxnet3_instance->rx_ring2[i].word2 =
        (VMXNET3_FRAME_BYTES & VMXNET3_RXD_W2_LEN_MASK) |
        (UINT32_C(1) << VMXNET3_RXD_W2_BTYPE_SHIFT) |
        (vmxnet3_instance->rx_gen << VMXNET3_RXD_W2_GEN_SHIFT);
    vmxnet3_instance->rx_ring2[i].word3 = 0U;
  }
  /* The slot left empty above is the next one to fill, on this same lap. */
  vmxnet3_instance->rx_produce = VMXNET3_RING_SIZE - 1U;
  return XAIOS_OK;
}

static xaios_status_t activate_device(void) {
  uint8_t *shared = vmxnet3_instance->shared;
  uint8_t *tqd = vmxnet3_instance->queues;
  vmxnet3_instance->tqd = tqd;
  uint8_t *rqd = vmxnet3_instance->queues + VMXNET3_TQD_BYTES;

  uint64_t tx_ring_pa =
      vmxnet3_dma_address(vmxnet3_instance->tx_ring,
                  sizeof(vmxnet3_tx_desc_t) * VMXNET3_RING_SIZE);
  uint64_t tx_comp_pa =
      vmxnet3_dma_address(vmxnet3_instance->tx_comp,
                  sizeof(vmxnet3_tx_comp_desc_t) * VMXNET3_RING_SIZE);
  uint64_t rx_ring_pa =
      vmxnet3_dma_address(vmxnet3_instance->rx_ring,
                  sizeof(vmxnet3_rx_desc_t) * VMXNET3_RING_SIZE);
  uint64_t rx_ring2_pa =
      vmxnet3_dma_address(vmxnet3_instance->rx_ring2,
                  sizeof(vmxnet3_rx_desc_t) * VMXNET3_RING_SIZE);
  uint64_t rx_comp_pa =
      vmxnet3_dma_address(vmxnet3_instance->rx_comp,
                  sizeof(vmxnet3_rx_comp_desc_t) * VMXNET3_RX_COMP_SIZE);
  uint64_t queues_pa =
      vmxnet3_dma_address(vmxnet3_instance->queues, VMXNET3_TQD_BYTES + VMXNET3_RQD_BYTES);
  uint64_t shared_pa = vmxnet3_dma_address(shared, VMXNET3_DS_BYTES);
  if (tx_ring_pa == 0U || tx_comp_pa == 0U || rx_ring_pa == 0U ||
      rx_ring2_pa == 0U || rx_comp_pa == 0U || queues_pa == 0U ||
      shared_pa == 0U) {
    return XAIOS_ERR_IO;
  }

  klog("vmxnet3: dma tx_ring=0x%lx tx_comp=0x%lx rx_ring=0x%lx rx_ring2=0x%lx "
       "rx_comp=0x%lx queues=0x%lx shared=0x%lx\n",
       tx_ring_pa, tx_comp_pa, rx_ring_pa, rx_ring2_pa, rx_comp_pa, queues_pa,
       shared_pa);
  vmxnet3_put64(tqd, VMXNET3_TQD_TX_RING_PA, tx_ring_pa);
  vmxnet3_put64(tqd, VMXNET3_TQD_COMP_RING_PA, tx_comp_pa);
  vmxnet3_put32(tqd, VMXNET3_TQD_TX_RING_SIZE, VMXNET3_RING_SIZE);
  vmxnet3_put32(tqd, VMXNET3_TQD_COMP_RING_SIZE, VMXNET3_RING_SIZE);
  vmxnet3_put32(tqd, VMXNET3_TQD_DATA_RING_SIZE, 0U);
  /* "No driver data here" is all-ones, not zero. Zero is a valid physical
     address and a device entitled to read it will. */
  vmxnet3_put64(tqd, VMXNET3_TQD_DRIVER_DATA_PA, UINT64_C(0xffffffffffffffff));
  vmxnet3_put32(tqd, VMXNET3_TQD_DRIVER_DATA_LEN, 0U);
  vmxnet3_put32(tqd, VMXNET3_TQD_INTR_INDEX, 0U);
  /* Ring the doorbell for a single descriptor. */
  vmxnet3_put32(tqd, VMXNET3_TQD_NUM_DEFERRED, 0U);
  vmxnet3_put32(tqd, VMXNET3_TQD_THRESHOLD, 1U);

  vmxnet3_put64(rqd, VMXNET3_RQD_RX_RING1_PA, rx_ring_pa);
  vmxnet3_put64(rqd, VMXNET3_RQD_RX_RING2_PA, rx_ring2_pa);
  vmxnet3_put64(rqd, VMXNET3_RQD_COMP_RING_PA, rx_comp_pa);
  vmxnet3_put32(rqd, VMXNET3_RQD_RX_RING1_SIZE, VMXNET3_RING_SIZE);
  vmxnet3_put32(rqd, VMXNET3_RQD_RX_RING2_SIZE, VMXNET3_RING_SIZE);
  vmxnet3_put32(rqd, VMXNET3_RQD_COMP_RING_SIZE, VMXNET3_RX_COMP_SIZE);
  vmxnet3_put32(rqd, VMXNET3_RQD_INTR_INDEX, 0U);
  vmxnet3_put64(rqd, VMXNET3_RQD_DRIVER_DATA_PA, UINT64_C(0xffffffffffffffff));
  vmxnet3_put32(rqd, VMXNET3_RQD_DRIVER_DATA_LEN, 0U);
  /* No receive data ring. Zero is a physical address a device is entitled to
     read, so this says "none" the way the driver-data pointers do. */
  vmxnet3_put64(rqd, VMXNET3_RQD_DATA_RING_PA, UINT64_C(0xffffffffffffffff));

  vmxnet3_put32(shared, VMXNET3_DS_MAGIC, VMXNET3_DRIVER_SHARED_MAGIC);
  vmxnet3_put32(shared, VMXNET3_DS_VERSION, 1U);
  /* gosBits = 64-bit, gosType = unknown. Zero leaves the device with a
     guest that claims no word size at all. */
  vmxnet3_put32(shared, VMXNET3_DS_GUEST, 2U);
  vmxnet3_put32(shared, VMXNET3_DS_VMXNET3_REV, UINT32_C(1) << (vmxnet3_instance->revision - 1U));
  vmxnet3_put32(shared, VMXNET3_DS_UPT_VER, UINT32_C(1) << (vmxnet3_instance->upt_version - 1U));
  vmxnet3_put64(shared, VMXNET3_DS_UPT_FEATURES, 0U);
  vmxnet3_put64(shared, VMXNET3_DS_DRIVER_DATA_PA, 0U);
  vmxnet3_put64(shared, VMXNET3_DS_QUEUE_DESC_PA, queues_pa);
  vmxnet3_put32(shared, VMXNET3_DS_DRIVER_DATA_LEN, 0U);
  vmxnet3_put32(shared, VMXNET3_DS_QUEUE_DESC_LEN,
        VMXNET3_TQD_BYTES + VMXNET3_RQD_BYTES);
  vmxnet3_put32(shared, VMXNET3_DS_MTU, 1500U);
  vmxnet3_put16(shared, VMXNET3_DS_MAX_NUM_RX_SG, 1U);
  shared[VMXNET3_DS_NUM_TX_QUEUES] = 1U;
  shared[VMXNET3_DS_NUM_RX_QUEUES] = 1U;
  /* Masking is the driver's job, and no interrupt is used yet: the receive
     path polls, exactly as the e1000e path does on this platform. */
  shared[VMXNET3_DS_INTR_MASK_MODE] = 0U;
  shared[VMXNET3_DS_INTR_NUM_INTRS] = 1U;
  shared[VMXNET3_DS_INTR_EVENT_INTR] = 0U;
  vmxnet3_put32(shared, VMXNET3_DS_INTR_CTRL, 1U); /* disable interrupt delivery */
  vmxnet3_put32(shared, VMXNET3_DS_RX_MODE,
        VMXNET3_RXM_UCAST | VMXNET3_RXM_BCAST | VMXNET3_RXM_ALL_MULTI);

  vmxnet3_write_bar1(VMXNET3_REG_DSAL, (uint32_t)(shared_pa & UINT32_C(0xffffffff)));
  vmxnet3_write_bar1(VMXNET3_REG_DSAH, (uint32_t)(shared_pa >> 32U));
  uint32_t result = vmxnet3_command_result(VMXNET3_CMD_ACTIVATE_DEV);
  if (result != 0U) {
    klog("vmxnet3: activation refused result=0x%x\n", result);
    return XAIOS_ERR_IO;
  }
  /* Tell the device where the receive ring has been filled to. The producer
     index wraps at the ring size, so handing over the whole ring means
     writing the last slot rather than the count. */
  vmxnet3_write_bar0(VMXNET3_REG_RXPROD, vmxnet3_instance->rx_produce);
  /* The second receive ring has a producer index of its own, and a device
     given a ring it is never told the fill level of has nowhere to put a
     frame that lands on it. */
  vmxnet3_write_bar0(VMXNET3_REG_RXPROD2, VMXNET3_RING_SIZE - 1U);
  vmxnet3_instance->active = 1U;
  /* What the device actually reads for the transmit queue, read back from the
     bytes rather than from the values that were meant to be written. */
  klog("vmxnet3: tqd conf ring_pa=0x%lx data_pa=0x%lx comp_pa=0x%lx "
       "dd_pa=0x%lx\n",
       vmxnet3_get64(tqd, VMXNET3_TQD_TX_RING_PA), vmxnet3_get64(tqd, VMXNET3_TQD_DATA_RING_PA),
       vmxnet3_get64(tqd, VMXNET3_TQD_COMP_RING_PA),
       vmxnet3_get64(tqd, VMXNET3_TQD_DRIVER_DATA_PA));
  klog("vmxnet3: tqd sizes tx=%u data=%u comp=%u ddlen=%u intr=%u "
       "deferred=%u threshold=%u\n",
       vmxnet3_get32(tqd, VMXNET3_TQD_TX_RING_SIZE),
       vmxnet3_get32(tqd, VMXNET3_TQD_DATA_RING_SIZE),
       vmxnet3_get32(tqd, VMXNET3_TQD_COMP_RING_SIZE),
       vmxnet3_get32(tqd, VMXNET3_TQD_DRIVER_DATA_LEN),
       vmxnet3_get32(tqd, VMXNET3_TQD_INTR_INDEX) & 0xffU,
       vmxnet3_get32(tqd, VMXNET3_TQD_NUM_DEFERRED),
       vmxnet3_get32(tqd, VMXNET3_TQD_THRESHOLD));
  klog("vmxnet3: ds numTx=%u numRx=%u qdesc_pa=0x%lx qdesc_len=%u mtu=%u\n",
       shared[VMXNET3_DS_NUM_TX_QUEUES], shared[VMXNET3_DS_NUM_RX_QUEUES],
       vmxnet3_get64(shared, VMXNET3_DS_QUEUE_DESC_PA),
       vmxnet3_get32(shared, VMXNET3_DS_QUEUE_DESC_LEN),
       vmxnet3_get32(shared, VMXNET3_DS_MTU));

  klog("vmxnet3: activated tx_ring=%u rx_ring=%u mtu=1500\n",
       VMXNET3_RING_SIZE, VMXNET3_RING_SIZE);
  return XAIOS_OK;
}

xaios_status_t vmxnet3_activate(void) {
  if (vmxnet3_is_present() == 0U) return XAIOS_ERR_NOT_FOUND;
  if (vmxnet3_instance->active != 0U) return XAIOS_OK;
  xaios_status_t status = build_rings();
  if (status != XAIOS_OK) {
    klog("vmxnet3: ring setup failed status=%d\n", (int)status);
    return status;
  }
  return activate_device();
}
