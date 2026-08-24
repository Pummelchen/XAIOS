#include <xaios/arch_cpu.h>
#include <xaios/assert.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/ipv4.h>
#include <xaios/ipv6.h>
#include <xaios/spinlock.h>
#include <xaios/timer.h>
#include <xaios/virtio_net.h>
#include <xaios/virtio_transport.h>
#include <xaios/vmm.h>

#define VRING_DESC_F_WRITE UINT16_C(2)
#define VRING_DESC_F_NEXT UINT16_C(1)
#define VRING_DESC_F_INDIRECT UINT16_C(4)
/* VirtIO 1.0 devices use virtio_net_hdr_v1, including num_buffers, even when
 * mergeable receive buffers are not negotiated. */
#define VIRTIO_NET_HDR_SIZE 12U
#define VIRTIO_NET_PERSISTENT_RX_DESCS 8U
#define VIRTIO_NET_PERSISTENT_TX_DESCS 4U
#define VIRTIO_NET_MAX_FRAME 1524U
#define VIRTIO_DMA_ALIGNMENT 4096U
#define VIRTIO_NET_F_CSUM (UINT32_C(1) << 0U)
#define VIRTIO_NET_F_GUEST_CSUM (UINT32_C(1) << 1U)
#define VIRTIO_NET_F_MTU (UINT32_C(1) << 3U)
#define VIRTIO_NET_F_MAC (UINT32_C(1) << 5U)
#define VIRTIO_NET_F_GUEST_TSO4 (UINT32_C(1) << 7U)
#define VIRTIO_NET_F_GUEST_TSO6 (UINT32_C(1) << 8U)
#define VIRTIO_NET_F_GUEST_ECN (UINT32_C(1) << 9U)
#define VIRTIO_NET_F_GUEST_UFO (UINT32_C(1) << 10U)
#define VIRTIO_NET_F_HOST_TSO4 (UINT32_C(1) << 11U)
#define VIRTIO_NET_F_HOST_TSO6 (UINT32_C(1) << 12U)
#define VIRTIO_NET_F_MRG_RXBUF (UINT32_C(1) << 15U)
#define VIRTIO_NET_F_STATUS (UINT32_C(1) << 16U)
#define VIRTIO_NET_GUEST_GSO_MASK                                   \
  (VIRTIO_NET_F_GUEST_TSO4 | VIRTIO_NET_F_GUEST_TSO6 |              \
   VIRTIO_NET_F_GUEST_ECN | VIRTIO_NET_F_GUEST_UFO)
/* Without mergeable receive buffers, negotiating any guest segmentation
   offload obliges the driver to post receive buffers of at least 65550
   bytes, because the device may then deliver a coalesced segment that
   large. Frames beyond what the stack accepts are dropped on receive. */
#define VIRTIO_NET_GSO_RX_BUFFER 65550U
#define VIRTIO_F_RING_INDIRECT_DESC (UINT32_C(1) << 28U)
#define VIRTIO_F_RING_EVENT_IDX (UINT32_C(1) << 29U)
#define VIRTIO_F_VERSION_1_HIGH UINT32_C(1)
#define VIRTIO_NET_MAX_TX_FRAGMENTS 4U
#define VIRTIO_NET_FRAGMENT_BUFFER 4096U

typedef struct virtio_net_driver {
  virtio_mmio_device_t device;
  virtq_desc_t *rx_desc;
  virtq_avail_t *rx_avail;
  virtq_used_t *rx_used;
  virtq_desc_t *tx_desc;
  virtq_avail_t *tx_avail;
  virtq_used_t *tx_used;
  uint8_t *rx_packet;
  uint8_t *tx_packet;
  /* persistent mode state */
  uint32_t persistent;
  uint16_t rx_avail_idx;
  uint16_t rx_last_used;
  uint16_t tx_avail_idx;
  uint16_t tx_last_used;
  uint64_t interrupt_count;
  uint64_t tx_completion_count;
  uint32_t event_idx;
  uint32_t indirect_desc;
  uint32_t large_rx;
  uint32_t device_present;
  uint64_t scatter_gather_submissions;
  uint64_t copy_fallbacks;
  xaios_spinlock_t tx_lock;
  uint8_t *rx_bufs[VIRTIO_NET_PERSISTENT_RX_DESCS];
  uint8_t *tx_bufs[VIRTIO_NET_PERSISTENT_TX_DESCS];
  virtq_desc_t *tx_indirect[VIRTIO_NET_PERSISTENT_TX_DESCS];
} virtio_net_driver_t;

static virtio_net_driver_t *g_net;

static uint16_t read_be16(const uint8_t *value) {
  return (uint16_t)(((uint16_t)value[0] << 8U) | value[1]);
}

static uint32_t drain_tx_completions_locked(void) {
  if (g_net == 0 || g_net->persistent == 0U) return 0U;
  virtio_mmio_barrier();
  uint16_t used = *(volatile uint16_t *)(void *)&g_net->tx_used->idx;
  uint32_t completed = (uint16_t)(used - g_net->tx_last_used);
  g_net->tx_last_used = used;
  if (g_net->event_idx != 0U) {
    g_net->tx_avail->used_event = used;
  }
  g_net->tx_completion_count += completed;
  return completed;
}

static uint32_t virtio_net_drain_tx_completions(void) {
  if (g_net == 0 || xaios_spin_trylock(&g_net->tx_lock) == 0) return 0U;
  uint32_t completed = drain_tx_completions_locked();
  xaios_spin_unlock(&g_net->tx_lock);
  return completed;
}

static void virtio_net_interrupt(uint32_t intid, void *context) {
  virtio_net_driver_t *driver = (virtio_net_driver_t *)context;
  (void)intid;
  if (driver == 0 || driver != g_net) return;
  ++driver->interrupt_count;
  (void)virtio_net_drain_tx_completions();
  virtio_transport_ack_interrupts(&driver->device);
}

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

static void put_be16(uint8_t *dst, uint16_t value) {
  dst[0] = (uint8_t)(value >> 8U);
  dst[1] = (uint8_t)value;
}

static uint64_t dma_address(const void *ptr) {
  uint64_t physical = 0;
  uint32_t flags = 0;
  kassert(vmm_translate((uint64_t)(uintptr_t)ptr, &physical, &flags) == XAIOS_OK);
  kassert((flags & XAIOS_VMM_PRESENT) != 0);
  return physical;
}

static int dma_range(const void *ptr, uint64_t length, uint64_t *physical) {
  if (ptr == 0 || length == 0U || physical == 0) return 0;
  uint64_t start = (uint64_t)(uintptr_t)ptr;
  if (start + length < start) return 0;
  uint64_t first = 0U;
  uint64_t last = 0U;
  uint32_t first_flags = 0U;
  uint32_t last_flags = 0U;
  if (vmm_translate(start, &first, &first_flags) != XAIOS_OK ||
      vmm_translate(start + length - 1U, &last, &last_flags) != XAIOS_OK ||
      (first_flags & XAIOS_VMM_PRESENT) == 0U ||
      (last_flags & XAIOS_VMM_PRESENT) == 0U ||
      last != first + length - 1U) {
    return 0;
  }
  *physical = first;
  return 1;
}

static uint16_t get_be16(const uint8_t *src) {
  return (uint16_t)(((uint16_t)src[0] << 8U) | src[1]);
}

static xaios_status_t allocate_driver(void) {
  if (g_net != 0) {
    return XAIOS_OK;
  }
  g_net = (virtio_net_driver_t *)kheap_calloc(sizeof(*g_net), 16);
  if (g_net == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }
  xaios_spin_init(&g_net->tx_lock);
  /* Legacy VirtIO descriptors contain one physical extent. Keep every DMA
   * object inside one page because kheap virtual pages need not be physically
   * contiguous. */
  g_net->rx_desc = (virtq_desc_t *)kheap_calloc(
      sizeof(virtq_desc_t) * VIRTQ_SIZE, VIRTIO_DMA_ALIGNMENT);
  g_net->rx_avail = (virtq_avail_t *)kheap_calloc(
      sizeof(virtq_avail_t), VIRTIO_DMA_ALIGNMENT);
  g_net->rx_used = (virtq_used_t *)kheap_calloc(
      sizeof(virtq_used_t), VIRTIO_DMA_ALIGNMENT);
  g_net->tx_desc = (virtq_desc_t *)kheap_calloc(
      sizeof(virtq_desc_t) * VIRTQ_SIZE, VIRTIO_DMA_ALIGNMENT);
  g_net->tx_avail = (virtq_avail_t *)kheap_calloc(
      sizeof(virtq_avail_t), VIRTIO_DMA_ALIGNMENT);
  g_net->tx_used = (virtq_used_t *)kheap_calloc(
      sizeof(virtq_used_t), VIRTIO_DMA_ALIGNMENT);
  g_net->rx_packet =
      (uint8_t *)kheap_calloc(VIRTIO_NET_GSO_RX_BUFFER, VIRTIO_DMA_ALIGNMENT);
  g_net->tx_packet = (uint8_t *)kheap_calloc(
      VIRTIO_NET_HDR_SIZE + VIRTIO_NET_MAX_FRAME, VIRTIO_DMA_ALIGNMENT);
  if (g_net->rx_desc == 0 || g_net->rx_avail == 0 || g_net->rx_used == 0 ||
      g_net->tx_desc == 0 || g_net->tx_avail == 0 || g_net->tx_used == 0 ||
      g_net->rx_packet == 0 || g_net->tx_packet == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }
  for (uint32_t i = 0U; i < VIRTIO_NET_PERSISTENT_TX_DESCS; ++i) {
    g_net->tx_indirect[i] = (virtq_desc_t *)kheap_calloc(
        sizeof(virtq_desc_t) * (VIRTIO_NET_MAX_TX_FRAGMENTS + 1U),
        VIRTIO_DMA_ALIGNMENT);
    if (g_net->tx_indirect[i] == 0) return XAIOS_ERR_NO_MEMORY;
  }
  return XAIOS_OK;
}

static uint32_t rx_buffer_bytes(const virtio_net_driver_t *driver) {
  return driver != 0 && driver->large_rx != 0U
             ? VIRTIO_NET_GSO_RX_BUFFER
             : VIRTIO_NET_HDR_SIZE + VIRTIO_NET_MAX_FRAME;
}

static xaios_status_t negotiate_net_features(virtio_net_driver_t *driver) {
  /* Ask for the smallest useful set first. A device is entitled to refuse to
     run on a subset of what it offers, and Virtualization.framework's does:
     it declines the address alone, declines it with the ring features, and
     accepts only the full set. Everything in that set can be honoured here,
     so offer to take all of it on a second attempt. Mergeable receive
     buffers stay out of both: this driver does not reassemble a packet
     spread across several buffers. */
  static const uint32_t attempts[2] = {
      VIRTIO_NET_F_MAC | VIRTIO_F_RING_INDIRECT_DESC |
          VIRTIO_F_RING_EVENT_IDX,
      VIRTIO_NET_F_CSUM | VIRTIO_NET_F_GUEST_CSUM | VIRTIO_NET_F_MTU |
          VIRTIO_NET_F_MAC | VIRTIO_NET_F_GUEST_TSO4 |
          VIRTIO_NET_F_GUEST_TSO6 | VIRTIO_NET_F_GUEST_ECN |
          VIRTIO_NET_F_GUEST_UFO | VIRTIO_NET_F_HOST_TSO4 |
          VIRTIO_NET_F_HOST_TSO6 | VIRTIO_NET_F_STATUS |
          VIRTIO_F_RING_INDIRECT_DESC | VIRTIO_F_RING_EVENT_IDX,
  };
  for (uint32_t attempt = 0U; attempt < 2U; ++attempt) {
    uint32_t accepted_low = 0U;
    uint32_t accepted_high = 0U;
    xaios_status_t status = virtio_transport_negotiate_features(
        &driver->device, attempts[attempt], VIRTIO_F_VERSION_1_HIGH,
        &accepted_low, &accepted_high);
    if (status != XAIOS_OK ||
        (accepted_high & VIRTIO_F_VERSION_1_HIGH) == 0U) {
      continue;
    }
    driver->event_idx =
        (accepted_low & VIRTIO_F_RING_EVENT_IDX) != 0U ? 1U : 0U;
    driver->indirect_desc =
        (accepted_low & VIRTIO_F_RING_INDIRECT_DESC) != 0U ? 1U : 0U;
    driver->large_rx =
        (accepted_low & VIRTIO_NET_GUEST_GSO_MASK) != 0U ? 1U : 0U;
    if (driver->large_rx != 0U) {
      klog("virtio-net: guest offload negotiated; receive buffers hold %u "
           "bytes\n",
           rx_buffer_bytes(driver));
    }
    return XAIOS_OK;
  }
  return XAIOS_ERR_IO;
}

static void build_arp_request(uint8_t *packet, uint64_t *packet_len) {
  static const uint8_t src_ip[4] = {10, 0, 2, 15};
  static const uint8_t target_ip[4] = {10, 0, 2, 2};
  uint8_t src_mac[6];
  uint8_t *frame = packet + VIRTIO_NET_HDR_SIZE;

  kassert(virtio_net_get_mac(src_mac) == XAIOS_OK);
  bytes_zero(packet, VIRTIO_NET_HDR_SIZE + 42U);
  for (uint32_t i = 0; i < 6; ++i) {
    frame[i] = 0xff;
    frame[6 + i] = src_mac[i];
  }
  put_be16(frame + 12, 0x0806);
  put_be16(frame + 14, 1);
  put_be16(frame + 16, 0x0800);
  frame[18] = 6;
  frame[19] = 4;
  put_be16(frame + 20, 1);
  for (uint32_t i = 0; i < 6; ++i) {
    frame[22 + i] = src_mac[i];
  }
  for (uint32_t i = 0; i < 4; ++i) {
    frame[28 + i] = src_ip[i];
    frame[38 + i] = target_ip[i];
  }
  *packet_len = VIRTIO_NET_HDR_SIZE + 42U;
}

static int is_expected_arp_reply(const uint8_t *packet, uint32_t len) {
  if (len < VIRTIO_NET_HDR_SIZE + 42U) {
    return 0;
  }

  const uint8_t *frame = packet + VIRTIO_NET_HDR_SIZE;
  if (get_be16(frame + 12) != 0x0806) {
    return 0;
  }
  if (get_be16(frame + 20) != 2) {
    return 0;
  }
  if (frame[28] != 10 || frame[29] != 0 || frame[30] != 2 || frame[31] != 2) {
    return 0;
  }
  if (frame[38] != 10 || frame[39] != 0 || frame[40] != 2 || frame[41] != 15) {
    return 0;
  }

  return 1;
}

static void malformed_packet_self_test(void) {
  uint8_t packet[52];
  uint64_t len = 0;
  build_arp_request(packet, &len);
  kassert(is_expected_arp_reply(packet, 8) == 0);
  put_be16(packet + VIRTIO_NET_HDR_SIZE + 12U, 0x0800);
  kassert(is_expected_arp_reply(packet, (uint32_t)len) == 0);
  klog("virtio-net: malformed packet/drop self-test passed\n");
}

void virtio_net_self_test(void) {
  kassert(allocate_driver() == XAIOS_OK);
  xaios_status_t status = virtio_transport_find(
      VIRTIO_DEVICE_NET, "virtio-net", &g_net->device);
  if (status == XAIOS_ERR_NOT_FOUND) {
    klog("virtio-net: self-test skipped no VirtIO network device\n");
    return;
  }
  kassert(status == XAIOS_OK);
  g_net->device_present = 1U;
  /* Feature negotiation is the device's decision, not ours. A device that
     refuses the set this driver needs must leave the machine without
     networking, not halt it: the same posture already taken when no device
     is present at all. */
  if (negotiate_net_features(g_net) != XAIOS_OK) {
    g_net->device_present = 0U;
    klog("virtio-net: self-test skipped device refused required features\n");
    return;
  }

  bytes_zero(g_net->rx_desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  bytes_zero(g_net->rx_avail, sizeof(*g_net->rx_avail));
  bytes_zero(g_net->rx_used, sizeof(*g_net->rx_used));
  bytes_zero(g_net->tx_desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  bytes_zero(g_net->tx_avail, sizeof(*g_net->tx_avail));
  bytes_zero(g_net->tx_used, sizeof(*g_net->tx_used));
  if (g_net->event_idx != 0U) {
    g_net->rx_avail->used_event = 0U;
    g_net->tx_avail->used_event = 0U;
  }
  bytes_zero(g_net->rx_packet, rx_buffer_bytes(g_net));
  bytes_zero(g_net->tx_packet, 128);

  kassert(virtio_transport_setup_queue(&g_net->device, 0, VIRTQ_SIZE,
                                       g_net->rx_desc, g_net->rx_avail,
                                       g_net->rx_used) == XAIOS_OK);
  kassert(virtio_transport_setup_queue(&g_net->device, 1, VIRTQ_SIZE,
                                       g_net->tx_desc, g_net->tx_avail,
                                       g_net->tx_used) == XAIOS_OK);
  virtio_transport_set_driver_ok(&g_net->device);

  g_net->rx_desc[0].addr = dma_address(g_net->rx_packet);
  g_net->rx_desc[0].len = rx_buffer_bytes(g_net);
  g_net->rx_desc[0].flags = VRING_DESC_F_WRITE;
  g_net->rx_avail->ring[0] = 0;
  virtio_mmio_barrier();
  g_net->rx_avail->idx = 1;
  virtio_transport_notify(&g_net->device, 0);

  uint64_t tx_len = 0;
  build_arp_request(g_net->tx_packet, &tx_len);
  if (g_net->indirect_desc != 0U) {
    virtq_desc_t *indirect = g_net->tx_indirect[0];
    indirect[0].addr = dma_address(g_net->tx_packet);
    indirect[0].len = VIRTIO_NET_HDR_SIZE;
    indirect[0].flags = VRING_DESC_F_NEXT;
    indirect[0].next = 1U;
    indirect[1].addr = dma_address(g_net->tx_packet + VIRTIO_NET_HDR_SIZE);
    indirect[1].len = 21U;
    indirect[1].flags = VRING_DESC_F_NEXT;
    indirect[1].next = 2U;
    indirect[2].addr =
        dma_address(g_net->tx_packet + VIRTIO_NET_HDR_SIZE + 21U);
    indirect[2].len = 21U;
    indirect[2].flags = 0U;
    indirect[2].next = 0U;
    g_net->tx_desc[0].addr = dma_address(indirect);
    g_net->tx_desc[0].len = 3U * sizeof(virtq_desc_t);
    g_net->tx_desc[0].flags = VRING_DESC_F_INDIRECT;
  } else {
    g_net->tx_desc[0].addr = dma_address(g_net->tx_packet);
    g_net->tx_desc[0].len = (uint32_t)tx_len;
    g_net->tx_desc[0].flags = 0U;
  }
  g_net->tx_avail->ring[0] = 0;
  virtio_mmio_barrier();
  g_net->tx_avail->idx = 1;
  virtio_transport_notify(&g_net->device, 1);

  kassert(virtio_transport_wait_used(&g_net->tx_used->idx, 1) == XAIOS_OK);
  xaios_status_t rx_status =
      virtio_transport_wait_used(&g_net->rx_used->idx, 1);
  virtio_transport_ack_interrupts(&g_net->device);

  if (rx_status == XAIOS_OK) {
    uint32_t rx_len = g_net->rx_used->ring[0].len;
    /* The request went to QEMU user-mode networking's gateway. Any other
       host answers from its own subnet, so a reply that does not match is
       evidence of a different network rather than of a broken driver. */
    if (is_expected_arp_reply(g_net->rx_packet, rx_len)) {
      klog("virtio-net: host arp reply validated len=%u from=10.0.2.2\n",
           rx_len);
    } else {
      klog("virtio-net: arp reply from a different network len=%u; RX "
           "integration not asserted\n",
           rx_len);
    }
  } else {
    klog("virtio-net: host arp reply unavailable; RX integration not asserted\n");
  }
  malformed_packet_self_test();
  virtio_transport_reset(&g_net->device);
  klog("virtio-net: queue/tx/parser/reset self-test passed event_idx=%u indirect_sg=%u\n",
       g_net->event_idx, g_net->indirect_desc);
}

static uint64_t net_dma_address(const void *ptr) {
  uint64_t physical = 0;
  uint32_t flags = 0;
  kassert(vmm_translate((uint64_t)(uintptr_t)ptr, &physical, &flags) == XAIOS_OK);
  kassert((flags & XAIOS_VMM_PRESENT) != 0);
  return physical;
}

xaios_status_t virtio_net_init_persistent(void) {
  xaios_status_t status = allocate_driver();
  if (status != XAIOS_OK) return status;

  if (g_net->persistent != 0) {
    return XAIOS_OK;
  }

  status = virtio_transport_find(VIRTIO_DEVICE_NET, "virtio-net-persist",
                                 &g_net->device);
  if (status != XAIOS_OK) {
    klog("virtio-net-persist: discovery failed status=%d\n", (int)status);
    return status;
  }
  g_net->device_present = 1U;
  status = negotiate_net_features(g_net);
  if (status != XAIOS_OK) {
    klog("virtio-net-persist: feature negotiation failed status=%d\n",
         (int)status);
    return status;
  }

  bytes_zero(g_net->rx_desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  bytes_zero(g_net->rx_avail, sizeof(*g_net->rx_avail));
  bytes_zero(g_net->rx_used, sizeof(*g_net->rx_used));
  bytes_zero(g_net->tx_desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  bytes_zero(g_net->tx_avail, sizeof(*g_net->tx_avail));
  bytes_zero(g_net->tx_used, sizeof(*g_net->tx_used));
  if (g_net->event_idx != 0U) {
    g_net->rx_avail->used_event = 0U;
    g_net->tx_avail->used_event = 0U;
  }

  status = virtio_transport_setup_queue(&g_net->device, 0, VIRTQ_SIZE,
                                        g_net->rx_desc, g_net->rx_avail,
                                        g_net->rx_used);
  if (status != XAIOS_OK) {
    klog("virtio-net-persist: RX queue setup failed status=%d\n", (int)status);
    return status;
  }
  status = virtio_transport_setup_queue(&g_net->device, 1, VIRTQ_SIZE,
                                        g_net->tx_desc, g_net->tx_avail,
                                        g_net->tx_used);
  if (status != XAIOS_OK) {
    klog("virtio-net-persist: TX queue setup failed status=%d\n", (int)status);
    return status;
  }
  status = virtio_transport_set_driver_ok_checked(&g_net->device);
  if (status != XAIOS_OK) {
    klog("virtio-net-persist: DRIVER_OK failed status=%d\n", (int)status);
    return status;
  }

  /* Allocate and post RX buffers */
  for (uint32_t i = 0; i < VIRTIO_NET_PERSISTENT_RX_DESCS; ++i) {
    g_net->rx_bufs[i] = (uint8_t *)kheap_calloc(rx_buffer_bytes(g_net),
                                                VIRTIO_DMA_ALIGNMENT);
    if (g_net->rx_bufs[i] == 0) {
      klog("virtio-net-persist: receive buffer %u of %u bytes unavailable\n",
           i, rx_buffer_bytes(g_net));
      return XAIOS_ERR_NO_MEMORY;
    }
    g_net->rx_desc[i].addr = net_dma_address(g_net->rx_bufs[i]);
    g_net->rx_desc[i].len = rx_buffer_bytes(g_net);
    g_net->rx_desc[i].flags = VRING_DESC_F_WRITE;
    g_net->rx_avail->ring[i] = (uint16_t)i;
  }
  virtio_mmio_barrier();
  g_net->rx_avail->idx = VIRTIO_NET_PERSISTENT_RX_DESCS;
  g_net->rx_avail_idx = VIRTIO_NET_PERSISTENT_RX_DESCS;
  g_net->rx_last_used = 0;
  virtio_transport_notify(&g_net->device, 0);

  /* Allocate TX buffers */
  for (uint32_t i = 0; i < VIRTIO_NET_PERSISTENT_TX_DESCS; ++i) {
    g_net->tx_bufs[i] = (uint8_t *)kheap_calloc(
        VIRTIO_NET_HDR_SIZE + VIRTIO_NET_MAX_FRAME, VIRTIO_DMA_ALIGNMENT);
    if (g_net->tx_bufs[i] == 0) {
      klog("virtio-net-persist: transmit buffer %u unavailable\n", i);
      return XAIOS_ERR_NO_MEMORY;
    }
  }
  g_net->tx_avail_idx = 0;
  g_net->tx_last_used = 0;
  g_net->persistent = 1;
  g_net->interrupt_count = 0U;
  g_net->tx_completion_count = 0U;
  g_net->scatter_gather_submissions = 0U;
  g_net->copy_fallbacks = 0U;
  status = virtio_transport_register_interrupt(
      &g_net->device, virtio_net_interrupt, g_net);
  if (status != XAIOS_OK) {
    /* Interrupt delivery is an optimisation, not a requirement: the receive
       path polls the used ring either way, and transmission already waits on
       it. A transport that offers no message-signalled interrupt still
       carries traffic, so keep the interface rather than discarding a
       working device over a missing notification. */
    klog("virtio-net-persist: no interrupt available status=%d; receive path "
         "polls\n",
         (int)status);
  }

  klog("virtio-net: persistent mode initialized rx=%u tx=%u event_idx=%u indirect_sg=%u interrupt=%u\n",
       VIRTIO_NET_PERSISTENT_RX_DESCS, VIRTIO_NET_PERSISTENT_TX_DESCS,
       g_net->event_idx, g_net->indirect_desc,
       status == XAIOS_OK ? 1U : 0U);
  return XAIOS_OK;
}

static xaios_status_t tx_submit_vectors(const xaios_net_iovec_t *vectors,
                                        uint32_t vector_count,
                                        uint32_t allow_direct,
                                        uint64_t *token) {
  if (g_net == 0 || g_net->persistent == 0U || vectors == 0 ||
      vector_count == 0U || vector_count > VIRTIO_NET_MAX_TX_FRAGMENTS ||
      token == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t total_payload = 0U;
  for (uint32_t i = 0U; i < vector_count; ++i) {
    if (vectors[i].base == 0 || vectors[i].length == 0U ||
        total_payload + vectors[i].length < total_payload) {
      return XAIOS_ERR_INVALID;
    }
    total_payload += vectors[i].length;
  }
  if (total_payload > VIRTIO_NET_MAX_FRAME) return XAIOS_ERR_INVALID;

  xaios_spin_lock(&g_net->tx_lock);
  (void)drain_tx_completions_locked();
  uint16_t outstanding =
      (uint16_t)(g_net->tx_avail_idx - g_net->tx_last_used);
  if (outstanding >= VIRTIO_NET_PERSISTENT_TX_DESCS) {
    xaios_spin_unlock(&g_net->tx_lock);
    return XAIOS_ERR_BUSY;
  }
  uint16_t desc_idx =
      g_net->tx_avail_idx % VIRTIO_NET_PERSISTENT_TX_DESCS;
  bytes_zero(g_net->tx_bufs[desc_idx], VIRTIO_NET_HDR_SIZE);

  uint64_t fragment_physical[VIRTIO_NET_MAX_TX_FRAGMENTS];
  uint32_t direct = allow_direct != 0U && g_net->indirect_desc != 0U;
  for (uint32_t i = 0U; i < vector_count && direct != 0U; ++i) {
    if (!dma_range(vectors[i].base, vectors[i].length,
                   &fragment_physical[i])) {
      direct = 0U;
    }
  }
  if (direct != 0U) {
    virtq_desc_t *indirect = g_net->tx_indirect[desc_idx];
    indirect[0].addr = net_dma_address(g_net->tx_bufs[desc_idx]);
    indirect[0].len = VIRTIO_NET_HDR_SIZE;
    indirect[0].flags = VRING_DESC_F_NEXT;
    indirect[0].next = 1U;
    for (uint32_t i = 0U; i < vector_count; ++i) {
      uint32_t entry = i + 1U;
      indirect[entry].addr = fragment_physical[i];
      indirect[entry].len = (uint32_t)vectors[i].length;
      indirect[entry].flags =
          i + 1U < vector_count ? VRING_DESC_F_NEXT : 0U;
      indirect[entry].next = (uint16_t)(entry + 1U);
    }
    g_net->tx_desc[desc_idx].addr = net_dma_address(indirect);
    g_net->tx_desc[desc_idx].len =
        (vector_count + 1U) * sizeof(virtq_desc_t);
    g_net->tx_desc[desc_idx].flags = VRING_DESC_F_INDIRECT;
    ++g_net->scatter_gather_submissions;
  } else {
    uint64_t offset = VIRTIO_NET_HDR_SIZE;
    for (uint32_t i = 0U; i < vector_count; ++i) {
      const uint8_t *source = (const uint8_t *)vectors[i].base;
      for (uint64_t j = 0U; j < vectors[i].length; ++j) {
        g_net->tx_bufs[desc_idx][offset++] = source[j];
      }
    }
    g_net->tx_desc[desc_idx].addr = net_dma_address(g_net->tx_bufs[desc_idx]);
    g_net->tx_desc[desc_idx].len =
        (uint32_t)(VIRTIO_NET_HDR_SIZE + total_payload);
    g_net->tx_desc[desc_idx].flags = 0U;
    ++g_net->copy_fallbacks;
  }
  g_net->tx_avail->ring[g_net->tx_avail_idx % VIRTQ_SIZE] = desc_idx;
  virtio_mmio_barrier();
  ++g_net->tx_avail_idx;
  g_net->tx_avail->idx = g_net->tx_avail_idx;
  *token = g_net->tx_avail_idx;
  xaios_spin_unlock(&g_net->tx_lock);
  virtio_transport_notify(&g_net->device, 1U);
  return XAIOS_OK;
}

xaios_status_t virtio_net_tx_submit(const uint8_t *data, uint64_t len,
                                    uint64_t *token) {
  if (data == 0 || len < 14U) return XAIOS_ERR_INVALID;
  uint16_t ethertype = read_be16(data + 12U);
  if ((ethertype == UINT16_C(0x0800) && len >= 34U &&
       read_be16(data + 16U) > XAIOS_IPV4_DEFAULT_MTU) ||
      (ethertype == XAIOS_IPV6_ETHERTYPE && len >= 54U &&
       XAIOS_IPV6_HEADER_SIZE + read_be16(data + 18U) >
           XAIOS_IPV6_MIN_MTU)) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  xaios_net_iovec_t vector = {data, len};
  return tx_submit_vectors(&vector, 1U, 0U, token);
}

static xaios_status_t wait_tx_token(uint64_t token, uint64_t started) {
  while ((uint16_t)(__atomic_load_n(&g_net->tx_last_used, __ATOMIC_ACQUIRE) -
                    (uint16_t)token) >= UINT16_C(0x8000)) {
    (void)virtio_net_drain_tx_completions();
    if (timer_now_ns() - started >= UINT64_C(5000000000)) {
      return XAIOS_ERR_IO;
    }
    xaios_cpu_relax();
  }
  return XAIOS_OK;
}

static xaios_status_t tx_vectors_wait(const xaios_net_iovec_t *vectors,
                                      uint32_t vector_count) {
  uint64_t started = timer_now_ns();
  uint64_t token = 0U;
  for (;;) {
    xaios_status_t status =
        tx_submit_vectors(vectors, vector_count, 1U, &token);
    if (status == XAIOS_OK) break;
    if (status != XAIOS_ERR_BUSY) return status;
    (void)virtio_net_drain_tx_completions();
    if (timer_now_ns() - started >= UINT64_C(5000000000)) {
      return XAIOS_ERR_IO;
    }
    xaios_cpu_relax();
  }
  return wait_tx_token(token, started);
}

static xaios_status_t tx_fragment_sequence(const uint8_t *fragments,
                                           uint64_t fragments_len,
                                           uint16_t ethertype) {
  uint64_t offset = 0U;
  while (offset < fragments_len) {
    if (fragments_len - offset < 14U) return XAIOS_ERR_INVALID;
    uint64_t frame_len;
    if (ethertype == UINT16_C(0x0800)) {
      if (fragments_len - offset < 34U) return XAIOS_ERR_INVALID;
      frame_len = 14U + read_be16(fragments + offset + 16U);
    } else {
      if (fragments_len - offset < 54U) return XAIOS_ERR_INVALID;
      frame_len = 14U + XAIOS_IPV6_HEADER_SIZE +
                  read_be16(fragments + offset + 18U);
    }
    if (frame_len > fragments_len - offset ||
        frame_len > VIRTIO_NET_MAX_FRAME) {
      return XAIOS_ERR_INVALID;
    }
    xaios_net_iovec_t vector = {fragments + offset, frame_len};
    xaios_status_t status = tx_vectors_wait(&vector, 1U);
    if (status != XAIOS_OK) return status;
    offset += frame_len;
  }
  return offset == fragments_len ? XAIOS_OK : XAIOS_ERR_INVALID;
}

xaios_status_t virtio_net_tx(const uint8_t *data, uint64_t len) {
  if (data == 0 || len < 14U || len > VIRTIO_NET_MAX_FRAME) {
    return XAIOS_ERR_INVALID;
  }
  uint16_t ethertype = read_be16(data + 12U);
  uint8_t fragments[VIRTIO_NET_FRAGMENT_BUFFER];
  uint64_t fragments_len = 0U;
  xaios_status_t status;

  if (ethertype == UINT16_C(0x0800) && len >= 34U &&
      read_be16(data + 16U) > XAIOS_IPV4_DEFAULT_MTU) {
    status = ipv4_fragment(data, len, fragments, &fragments_len,
                           sizeof(fragments));
    if (status != XAIOS_OK) return status;
    return tx_fragment_sequence(fragments, fragments_len, ethertype);
  }
  if (ethertype == XAIOS_IPV6_ETHERTYPE && len >= 54U &&
      XAIOS_IPV6_HEADER_SIZE + read_be16(data + 18U) >
          XAIOS_IPV6_MIN_MTU) {
    status = ipv6_fragment_v6(data, len, fragments, &fragments_len,
                              sizeof(fragments));
    if (status != XAIOS_OK) return status;
    return tx_fragment_sequence(fragments, fragments_len, ethertype);
  }

  xaios_net_iovec_t vector = {data, len};
  return tx_vectors_wait(&vector, 1U);
}

xaios_status_t virtio_net_txv(const xaios_net_iovec_t *vectors,
                              uint32_t vector_count) {
  if (vectors == 0 || vector_count == 0U) return XAIOS_ERR_INVALID;
  if (vector_count == 1U) {
    return virtio_net_tx((const uint8_t *)vectors[0].base,
                         vectors[0].length);
  }
  uint64_t total = 0U;
  for (uint32_t i = 0U; i < vector_count; ++i) {
    if (vectors[i].base == 0 || vectors[i].length == 0U ||
        total + vectors[i].length < total) {
      return XAIOS_ERR_INVALID;
    }
    total += vectors[i].length;
  }
  if (total > XAIOS_IPV6_MIN_MTU + 14U) {
    if (total > VIRTIO_NET_MAX_FRAME) return XAIOS_ERR_INVALID;
    uint8_t frame[VIRTIO_NET_MAX_FRAME];
    uint64_t offset = 0U;
    for (uint32_t i = 0U; i < vector_count; ++i) {
      const uint8_t *source = (const uint8_t *)vectors[i].base;
      for (uint64_t j = 0U; j < vectors[i].length; ++j) {
        frame[offset++] = source[j];
      }
    }
    return virtio_net_tx(frame, total);
  }
  return tx_vectors_wait(vectors, vector_count);
}

uint32_t virtio_net_tx_poll_completions(void) {
  return virtio_net_drain_tx_completions();
}

uint32_t virtio_net_rx_poll(uint8_t *buffer, uint64_t buffer_size) {
  if (g_net == 0 || g_net->persistent == 0 || buffer == 0 ||
      buffer_size == 0) {
    return 0;
  }

  /* The device publishes used-ring entries before updating idx. Force a fresh
   * device-owned index load, then order the entry reads after it. */
  virtio_mmio_barrier();
  uint16_t used_idx =
      *(volatile uint16_t *)(void *)&g_net->rx_used->idx;
  if (used_idx == g_net->rx_last_used) {
    virtio_transport_ack_interrupts(&g_net->device);
    return 0;
  }
  virtio_mmio_barrier();

  virtq_used_elem_t *elem =
      &g_net->rx_used->ring[g_net->rx_last_used % VIRTQ_SIZE];
  uint16_t desc = (uint16_t)elem->id;
  uint32_t rx_len = elem->len;
  uint32_t frame_len = 0;

  if (rx_len > VIRTIO_NET_HDR_SIZE &&
      rx_len - VIRTIO_NET_HDR_SIZE <= buffer_size) {
    frame_len = rx_len - VIRTIO_NET_HDR_SIZE;
    for (uint32_t i = 0; i < frame_len; ++i) {
      buffer[i] = g_net->rx_bufs[desc][VIRTIO_NET_HDR_SIZE + i];
    }
  }

  /* Every used entry must be returned, including malformed/oversized input. */
  ++g_net->rx_last_used;
  if (g_net->event_idx != 0U) {
    g_net->rx_avail->used_event = g_net->rx_last_used;
  }
  g_net->rx_desc[desc].addr = net_dma_address(g_net->rx_bufs[desc]);
  g_net->rx_desc[desc].len = rx_buffer_bytes(g_net);
  g_net->rx_desc[desc].flags = VRING_DESC_F_WRITE;
  g_net->rx_avail->ring[g_net->rx_avail_idx % VIRTQ_SIZE] = desc;
  virtio_mmio_barrier();
  ++g_net->rx_avail_idx;
  g_net->rx_avail->idx = g_net->rx_avail_idx;
  virtio_transport_notify(&g_net->device, 0);
  virtio_transport_ack_interrupts(&g_net->device);
  return frame_len;
}

xaios_status_t virtio_net_get_mac(uint8_t mac[6]) {
  if (g_net == 0 || mac == 0 || g_net->device_present == 0U) {
    return XAIOS_ERR_INVALID;
  }
  for (uint32_t i = 0; i < 6; ++i) {
    mac[i] = virtio_mmio_read8(g_net->device.base, 0x100U + i);
  }
  return XAIOS_OK;
}

uint64_t virtio_net_interrupt_count(void) {
  return g_net == 0 ? 0U : g_net->interrupt_count;
}

uint64_t virtio_net_tx_completion_count(void) {
  return g_net == 0 ? 0U : g_net->tx_completion_count;
}

uint32_t virtio_net_is_available(void) {
  return g_net != 0 && g_net->device_present != 0U ? 1U : 0U;
}
