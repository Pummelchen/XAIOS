#include <xaios/assert.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/virtio_net.h>
#include <xaios/virtio_transport.h>
#include <xaios/vmm.h>

#define VRING_DESC_F_WRITE UINT16_C(2)
#define VIRTIO_NET_HDR_SIZE 10U
#define VIRTIO_NET_PERSISTENT_RX_DESCS 8U
#define VIRTIO_NET_PERSISTENT_TX_DESCS 4U
#define VIRTIO_NET_MAX_FRAME 1524U
#define VIRTIO_DMA_ALIGNMENT 4096U

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
  uint8_t *rx_bufs[VIRTIO_NET_PERSISTENT_RX_DESCS];
  uint8_t *tx_bufs[VIRTIO_NET_PERSISTENT_TX_DESCS];
} virtio_net_driver_t;

static virtio_net_driver_t *g_net;

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
  g_net->rx_packet = (uint8_t *)kheap_calloc(2048, VIRTIO_DMA_ALIGNMENT);
  g_net->tx_packet = (uint8_t *)kheap_calloc(
      VIRTIO_NET_HDR_SIZE + VIRTIO_NET_MAX_FRAME, VIRTIO_DMA_ALIGNMENT);
  if (g_net->rx_desc == 0 || g_net->rx_avail == 0 || g_net->rx_used == 0 ||
      g_net->tx_desc == 0 || g_net->tx_avail == 0 || g_net->tx_used == 0 ||
      g_net->rx_packet == 0 || g_net->tx_packet == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }
  return XAIOS_OK;
}

static void build_arp_request(uint8_t *packet, uint64_t *packet_len) {
  static const uint8_t src_mac[6] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x15};
  static const uint8_t src_ip[4] = {10, 0, 2, 15};
  static const uint8_t target_ip[4] = {10, 0, 2, 2};
  uint8_t *frame = packet + 10;

  bytes_zero(packet, 10 + 42);
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
  *packet_len = 10 + 42;
}

static int is_expected_arp_reply(const uint8_t *packet, uint32_t len) {
  if (len < 10 + 42) {
    return 0;
  }

  const uint8_t *frame = packet + 10;
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
  put_be16(packet + 10 + 12, 0x0800);
  kassert(is_expected_arp_reply(packet, (uint32_t)len) == 0);
  klog("virtio-net: malformed packet/drop self-test passed\n");
}

void virtio_net_self_test(void) {
  kassert(allocate_driver() == XAIOS_OK);
  kassert(virtio_transport_find(VIRTIO_DEVICE_NET, "virtio-net",
                                &g_net->device) == XAIOS_OK);
  kassert(virtio_transport_negotiate_no_features(&g_net->device) == XAIOS_OK);

  bytes_zero(g_net->rx_desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  bytes_zero(g_net->rx_avail, sizeof(*g_net->rx_avail));
  bytes_zero(g_net->rx_used, sizeof(*g_net->rx_used));
  bytes_zero(g_net->tx_desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  bytes_zero(g_net->tx_avail, sizeof(*g_net->tx_avail));
  bytes_zero(g_net->tx_used, sizeof(*g_net->tx_used));
  bytes_zero(g_net->rx_packet, 2048);
  bytes_zero(g_net->tx_packet, 128);

  kassert(virtio_transport_setup_queue(&g_net->device, 0, VIRTQ_SIZE,
                                       g_net->rx_desc, g_net->rx_avail,
                                       g_net->rx_used) == XAIOS_OK);
  kassert(virtio_transport_setup_queue(&g_net->device, 1, VIRTQ_SIZE,
                                       g_net->tx_desc, g_net->tx_avail,
                                       g_net->tx_used) == XAIOS_OK);
  virtio_transport_set_driver_ok(&g_net->device);

  g_net->rx_desc[0].addr = dma_address(g_net->rx_packet);
  g_net->rx_desc[0].len = 2048;
  g_net->rx_desc[0].flags = VRING_DESC_F_WRITE;
  g_net->rx_avail->ring[0] = 0;
  virtio_mmio_barrier();
  g_net->rx_avail->idx = 1;
  virtio_transport_notify(&g_net->device, 0);

  uint64_t tx_len = 0;
  build_arp_request(g_net->tx_packet, &tx_len);
  g_net->tx_desc[0].addr = dma_address(g_net->tx_packet);
  g_net->tx_desc[0].len = (uint32_t)tx_len;
  g_net->tx_desc[0].flags = 0;
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
    kassert(is_expected_arp_reply(g_net->rx_packet, rx_len));
    klog("virtio-net: host arp reply validated len=%u from=10.0.2.2\n",
         rx_len);
  } else {
    klog("virtio-net: host arp reply unavailable; RX integration not asserted\n");
  }
  malformed_packet_self_test();
  virtio_transport_reset(&g_net->device);
  klog("virtio-net: queue/tx/parser/reset self-test passed\n");
}

static uint64_t net_dma_address(const void *ptr) {
  uint64_t physical = 0;
  uint32_t flags = 0;
  kassert(vmm_translate((uint64_t)(uintptr_t)ptr, &physical, &flags) == XAIOS_OK);
  kassert((flags & XAIOS_VMM_PRESENT) != 0);
  return physical;
}

xaios_status_t virtio_net_init_persistent(void) {
  kassert(allocate_driver() == XAIOS_OK);

  if (g_net->persistent != 0) {
    return XAIOS_OK;
  }

  kassert(virtio_transport_find(VIRTIO_DEVICE_NET, "virtio-net-persist",
                                &g_net->device) == XAIOS_OK);
  kassert(virtio_transport_negotiate_no_features(&g_net->device) == XAIOS_OK);

  bytes_zero(g_net->rx_desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  bytes_zero(g_net->rx_avail, sizeof(*g_net->rx_avail));
  bytes_zero(g_net->rx_used, sizeof(*g_net->rx_used));
  bytes_zero(g_net->tx_desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  bytes_zero(g_net->tx_avail, sizeof(*g_net->tx_avail));
  bytes_zero(g_net->tx_used, sizeof(*g_net->tx_used));

  kassert(virtio_transport_setup_queue(&g_net->device, 0, VIRTQ_SIZE,
                                       g_net->rx_desc, g_net->rx_avail,
                                       g_net->rx_used) == XAIOS_OK);
  kassert(virtio_transport_setup_queue(&g_net->device, 1, VIRTQ_SIZE,
                                       g_net->tx_desc, g_net->tx_avail,
                                       g_net->tx_used) == XAIOS_OK);
  virtio_transport_set_driver_ok(&g_net->device);

  /* Allocate and post RX buffers */
  for (uint32_t i = 0; i < VIRTIO_NET_PERSISTENT_RX_DESCS; ++i) {
    g_net->rx_bufs[i] = (uint8_t *)kheap_calloc(
        VIRTIO_NET_HDR_SIZE + VIRTIO_NET_MAX_FRAME, VIRTIO_DMA_ALIGNMENT);
    if (g_net->rx_bufs[i] == 0) {
      return XAIOS_ERR_NO_MEMORY;
    }
    g_net->rx_desc[i].addr = net_dma_address(g_net->rx_bufs[i]);
    g_net->rx_desc[i].len = VIRTIO_NET_HDR_SIZE + VIRTIO_NET_MAX_FRAME;
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
      return XAIOS_ERR_NO_MEMORY;
    }
  }
  g_net->tx_avail_idx = 0;
  g_net->tx_last_used = 0;
  g_net->persistent = 1;

  klog("virtio-net: persistent mode initialized rx=%u tx=%u\n",
       VIRTIO_NET_PERSISTENT_RX_DESCS, VIRTIO_NET_PERSISTENT_TX_DESCS);
  return XAIOS_OK;
}

xaios_status_t virtio_net_tx(const uint8_t *data, uint64_t len) {
  if (g_net == 0 || g_net->persistent == 0 || data == 0 ||
      len == 0 || len > VIRTIO_NET_MAX_FRAME) {
    return XAIOS_ERR_INVALID;
  }

  virtio_mmio_barrier();
  g_net->tx_last_used = g_net->tx_used->idx;
  uint16_t outstanding =
      (uint16_t)(g_net->tx_avail_idx - g_net->tx_last_used);
  if (outstanding >= VIRTIO_NET_PERSISTENT_TX_DESCS) {
    if (virtio_transport_wait_used(&g_net->tx_used->idx,
                                   (uint16_t)(g_net->tx_last_used + 1)) !=
        XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
    virtio_mmio_barrier();
    g_net->tx_last_used = g_net->tx_used->idx;
  }

  uint16_t desc_idx = g_net->tx_avail_idx % VIRTIO_NET_PERSISTENT_TX_DESCS;

  /* Build virtio-net header (10 bytes, all zeros) + frame */
  bytes_zero(g_net->tx_bufs[desc_idx], VIRTIO_NET_HDR_SIZE);
  for (uint64_t i = 0; i < len; ++i) {
    g_net->tx_bufs[desc_idx][VIRTIO_NET_HDR_SIZE + i] = data[i];
  }

  uint64_t total = VIRTIO_NET_HDR_SIZE + len;
  g_net->tx_desc[desc_idx].addr = net_dma_address(g_net->tx_bufs[desc_idx]);
  g_net->tx_desc[desc_idx].len = (uint32_t)total;
  g_net->tx_desc[desc_idx].flags = 0;
  g_net->tx_avail->ring[g_net->tx_avail_idx % VIRTQ_SIZE] = desc_idx;
  virtio_mmio_barrier();
  ++g_net->tx_avail_idx;
  g_net->tx_avail->idx = g_net->tx_avail_idx;
  virtio_transport_notify(&g_net->device, 1);

  if (virtio_transport_wait_used(&g_net->tx_used->idx,
                                 g_net->tx_avail_idx) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  virtio_mmio_barrier();
  g_net->tx_last_used = g_net->tx_used->idx;
  return XAIOS_OK;
}

uint32_t virtio_net_rx_poll(uint8_t *buffer, uint64_t buffer_size) {
  if (g_net == 0 || g_net->persistent == 0 || buffer == 0 ||
      buffer_size == 0) {
    return 0;
  }

  if (g_net->rx_used->idx == g_net->rx_last_used) {
    virtio_transport_ack_interrupts(&g_net->device);
    return 0;
  }

  virtq_used_elem_t *elem =
      &g_net->rx_used->ring[g_net->rx_last_used % VIRTQ_SIZE];
  uint16_t desc = (uint16_t)elem->id;
  uint32_t rx_len = elem->len;

  if (rx_len > VIRTIO_NET_HDR_SIZE &&
      rx_len - VIRTIO_NET_HDR_SIZE <= buffer_size) {
    uint32_t frame_len = rx_len - VIRTIO_NET_HDR_SIZE;
    for (uint32_t i = 0; i < frame_len; ++i) {
      buffer[i] = g_net->rx_bufs[desc][VIRTIO_NET_HDR_SIZE + i];
    }
    ++g_net->rx_last_used;

    /* Re-post the RX buffer */
    g_net->rx_desc[desc].addr = net_dma_address(g_net->rx_bufs[desc]);
    g_net->rx_desc[desc].len = VIRTIO_NET_HDR_SIZE + VIRTIO_NET_MAX_FRAME;
    g_net->rx_desc[desc].flags = VRING_DESC_F_WRITE;
    g_net->rx_avail->ring[g_net->rx_avail_idx % VIRTQ_SIZE] = desc;
    virtio_mmio_barrier();
    ++g_net->rx_avail_idx;
    g_net->rx_avail->idx = g_net->rx_avail_idx;
    virtio_transport_notify(&g_net->device, 0);

    virtio_transport_ack_interrupts(&g_net->device);
    return frame_len;
  }

  ++g_net->rx_last_used;
  virtio_transport_ack_interrupts(&g_net->device);
  return 0;
}

xaios_status_t virtio_net_get_mac(uint8_t mac[6]) {
  if (g_net == 0 || mac == 0) {
    return XAIOS_ERR_INVALID;
  }
  for (uint32_t i = 0; i < 6; ++i) {
    mac[i] = virtio_mmio_read8(g_net->device.base, 0x100U + i);
  }
  return XAIOS_OK;
}
