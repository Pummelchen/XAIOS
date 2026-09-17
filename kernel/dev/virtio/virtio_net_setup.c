/* Virtio network driver: pair/queue bring-up, feature negotiation and RSS.
 *
 * Split out of virtio_net.c. This is everything that has to happen before a
 * frame can move: allocating one pair's rings and scratch buffers, negotiating
 * the feature set (including the RSS parameters read from device
 * configuration), setting a queue up and posting its buffers, the control-queue
 * commands that put the pairs into service, and the indirection table and hash
 * key that make the device steer by four-tuple. Ordering is unchanged:
 * virtio_net_init_persistent() in virtio_net.c still calls these in the same
 * sequence, and VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET is still sent only after every
 * pair it names has buffers posted.
 *
 * The driver pointer is read into a caller-owned local through
 * virtio_net_primary_driver(); the variable stays private to virtio_net.c.
 * virtio_net_dma_address() lives here because the queue setup code is what
 * mostly translates addresses, and both other files call it for their own
 * descriptors.
 */
#include <xaios/assert.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/vmm.h>

#include "virtio_net_internal.h"

/* One pair's rings and scratch buffers. Pair zero is allocated with the
   driver; the rest only once a device says it has them, so a single-queue
   device costs exactly what it did before. */
xaios_status_t virtio_net_allocate_pair(uint32_t index) {
  virtio_net_driver_t *g_net = virtio_net_primary_driver();
  virtio_net_queue_pair_t *pair = &g_net->pairs[index];
  if (pair->rx_desc != 0) return XAIOS_OK;
  xaios_spin_init(&pair->tx_lock);
  /* Legacy VirtIO descriptors contain one physical extent. Keep every DMA
   * object inside one page because kheap virtual pages need not be physically
   * contiguous. */
  pair->rx_desc = (virtq_desc_t *)kheap_calloc(
      sizeof(virtq_desc_t) * VIRTQ_SIZE, VIRTIO_DMA_ALIGNMENT);
  pair->rx_avail = (virtq_avail_t *)kheap_calloc(
      sizeof(virtq_avail_t), VIRTIO_DMA_ALIGNMENT);
  pair->rx_used = (virtq_used_t *)kheap_calloc(
      sizeof(virtq_used_t), VIRTIO_DMA_ALIGNMENT);
  pair->tx_desc = (virtq_desc_t *)kheap_calloc(
      sizeof(virtq_desc_t) * VIRTQ_SIZE, VIRTIO_DMA_ALIGNMENT);
  pair->tx_avail = (virtq_avail_t *)kheap_calloc(
      sizeof(virtq_avail_t), VIRTIO_DMA_ALIGNMENT);
  pair->tx_used = (virtq_used_t *)kheap_calloc(
      sizeof(virtq_used_t), VIRTIO_DMA_ALIGNMENT);
  pair->rx_packet =
      (uint8_t *)kheap_calloc(VIRTIO_NET_GSO_RX_BUFFER, VIRTIO_DMA_ALIGNMENT);
  pair->tx_packet = (uint8_t *)kheap_calloc(
      VIRTIO_NET_HDR_SIZE + VIRTIO_NET_MAX_FRAME, VIRTIO_DMA_ALIGNMENT);
  if (pair->rx_desc == 0 || pair->rx_avail == 0 || pair->rx_used == 0 ||
      pair->tx_desc == 0 || pair->tx_avail == 0 || pair->tx_used == 0 ||
      pair->rx_packet == 0 || pair->tx_packet == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }
  for (uint32_t i = 0U; i < VIRTIO_NET_PERSISTENT_TX_DESCS; ++i) {
    pair->tx_indirect[i] = (virtq_desc_t *)kheap_calloc(
        sizeof(virtq_desc_t) * (VIRTIO_NET_MAX_TX_FRAGMENTS + 1U),
        VIRTIO_DMA_ALIGNMENT);
    if (pair->tx_indirect[i] == 0) return XAIOS_ERR_NO_MEMORY;
  }
  return XAIOS_OK;
}

uint32_t virtio_net_rx_buffer_bytes(const virtio_net_driver_t *driver) {
  return driver != 0 && driver->large_rx != 0U
             ? VIRTIO_NET_GSO_RX_BUFFER
             : VIRTIO_NET_HDR_SIZE + VIRTIO_NET_MAX_FRAME;
}

xaios_status_t virtio_net_negotiate_features(virtio_net_driver_t *driver) {
  /* Ask for the smallest useful set first. A device is entitled to refuse to
     run on a subset of what it offers, and Virtualization.framework's does:
     it declines the address alone, declines it with the ring features, and
     accepts only the full set. Everything in that set can be honoured here,
     so offer to take all of it on a second attempt. Mergeable receive
     buffers stay out of both: this driver does not reassemble a packet
     spread across several buffers. */
  /* The high word each attempt asks for, alongside `attempts` below. RSS is
     the first feature this driver wants that lives above bit 31, so the high
     word stopped being a constant. */
  static const uint32_t attempts_high[4] = {
      VIRTIO_F_VERSION_1_HIGH | VIRTIO_NET_F_RSS_HIGH,
      VIRTIO_F_VERSION_1_HIGH,
      VIRTIO_F_VERSION_1_HIGH,
      VIRTIO_F_VERSION_1_HIGH,
  };
  static const uint32_t attempts[4] = {
      /* Multiqueue with hashing. Tried first because a device that steers by
         hash makes the queues after the first carry traffic; without it they
         exist and may stay empty, which looks the same from here. */
      VIRTIO_NET_F_MAC | VIRTIO_F_RING_INDIRECT_DESC |
          VIRTIO_F_RING_EVENT_IDX | VIRTIO_NET_F_MQ | VIRTIO_NET_F_CTRL_VQ,
      /* Tried first, and only a device offering multiple queue pairs accepts
         it. Everything below is what this driver asked for before, so a device
         without multiqueue negotiates exactly as it always did -- the first
         attempt simply fails and the second is the old first. */
      VIRTIO_NET_F_MAC | VIRTIO_F_RING_INDIRECT_DESC |
          VIRTIO_F_RING_EVENT_IDX | VIRTIO_NET_F_MQ | VIRTIO_NET_F_CTRL_VQ,
      VIRTIO_NET_F_MAC | VIRTIO_F_RING_INDIRECT_DESC |
          VIRTIO_F_RING_EVENT_IDX,
      VIRTIO_NET_F_CSUM | VIRTIO_NET_F_GUEST_CSUM | VIRTIO_NET_F_MTU |
          VIRTIO_NET_F_MAC | VIRTIO_NET_F_GUEST_TSO4 |
          VIRTIO_NET_F_GUEST_TSO6 | VIRTIO_NET_F_GUEST_ECN |
          VIRTIO_NET_F_GUEST_UFO | VIRTIO_NET_F_HOST_TSO4 |
          VIRTIO_NET_F_HOST_TSO6 | VIRTIO_NET_F_STATUS |
          VIRTIO_F_RING_INDIRECT_DESC | VIRTIO_F_RING_EVENT_IDX,
  };
  for (uint32_t attempt = 0U; attempt < 4U; ++attempt) {
    uint32_t accepted_low = 0U;
    uint32_t accepted_high = 0U;
    xaios_status_t status = virtio_transport_negotiate_features(
        &driver->device, attempts[attempt], attempts_high[attempt],
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
    driver->pairs[0].rx_chained =
        driver->large_rx != 0U && driver->indirect_desc != 0U ? 1U : 0U;
    driver->multiqueue =
        (accepted_low & VIRTIO_NET_F_MQ) != 0U &&
        (accepted_low & VIRTIO_NET_F_CTRL_VQ) != 0U ? 1U : 0U;
    /* Read from what the device accepted, not from what was asked for. The
       first attempt requests RSS and a device that has no hashing simply
       does not return the bit, which is the same negotiation as any other
       optional feature and needs no special case beyond looking. */
    driver->rss = (accepted_high & VIRTIO_NET_F_RSS_HIGH) != 0U &&
                  driver->multiqueue != 0U ? 1U : 0U;
    if (driver->multiqueue != 0U) {
      /* max_virtqueue_pairs sits at offset 8 of the device configuration,
         after the six MAC bytes and the two status bytes. */
      /* Device configuration begins at 0x100 from base on both transports:
         the PCI probe sets base so that this offset lands on the device
         configuration structure, which is what the MAC read below relies on
         too. max_virtqueue_pairs is at offset 8, after six MAC bytes and two
         status bytes, little-endian. */
      driver->max_queue_pairs =
          (uint32_t)virtio_mmio_read8(driver->device.base, 0x100U + 8U) |
          ((uint32_t)virtio_mmio_read8(driver->device.base, 0x100U + 9U) << 8);
      if (driver->max_queue_pairs == 0U) driver->multiqueue = 0U;
    }
    /* The RSS parameters, which only exist in the configuration once RSS has
       been negotiated. Read rather than assumed: the table length and the key
       size are ceilings a device sets, and the hash types are a set it may
       support only part of. Asking for a hash type a device does not have is
       a request it is entitled to refuse, and a refusal here costs the whole
       of the steering rather than the one type. */
    if (driver->rss != 0U) {
      driver->rss_max_key_size = (uint32_t)virtio_mmio_read8(
          driver->device.base, 0x100U + VIRTIO_NET_CFG_RSS_MAX_KEY_SIZE);
      driver->rss_max_table_entries =
          (uint32_t)virtio_mmio_read8(
              driver->device.base, 0x100U + VIRTIO_NET_CFG_RSS_MAX_TABLE_LEN) |
          ((uint32_t)virtio_mmio_read8(
               driver->device.base,
               0x100U + VIRTIO_NET_CFG_RSS_MAX_TABLE_LEN + 1U) << 8U);
      driver->rss_supported_hash_types = 0U;
      for (uint32_t i = 0U; i < 4U; ++i) {
        driver->rss_supported_hash_types |=
            (uint32_t)virtio_mmio_read8(
                driver->device.base,
                0x100U + VIRTIO_NET_CFG_SUPPORTED_HASH_TYPES + i) << (8U * i);
      }
      klog("virtio-net: rss offered supported_hash_types=0x%x max_table=%u "
           "max_key=%u\n", driver->rss_supported_hash_types,
           driver->rss_max_table_entries, driver->rss_max_key_size);
      /* A device that offers the feature and then supports no hash type or no
         table has nothing to steer with. Better to know that here than to
         send a configuration it will reject. */
      if ((driver->rss_supported_hash_types &
           VIRTIO_NET_HASH_TYPES_WANTED) == 0U ||
          driver->rss_max_table_entries == 0U ||
          driver->rss_max_key_size == 0U) {
        klog("virtio-net: rss offered but unusable; steering stays off\n");
        driver->rss = 0U;
      }
    }
    if (driver->large_rx != 0U && driver->pairs[0].rx_chained == 0U) {
      klog("virtio-net: guest offload without indirect descriptors; receive "
           "buffers cannot reach %u bytes\n",
           VIRTIO_NET_GSO_RX_BUFFER);
    }
    if (driver->large_rx != 0U) {
      klog("virtio-net: guest offload negotiated; receive buffers hold %u "
           "bytes\n",
           virtio_net_rx_buffer_bytes(driver));
    }
    return XAIOS_OK;
  }
  return XAIOS_ERR_IO;
}

uint64_t virtio_net_dma_address(const void *ptr) {
  uint64_t physical = 0;
  uint32_t flags = 0;
  kassert(vmm_translate((uint64_t)(uintptr_t)ptr, &physical, &flags) == XAIOS_OK);
  kassert((flags & XAIOS_VMM_PRESENT) != 0);
  return physical;
}

/* Tell the device how many pairs are in service.
 *
 * The control queue carries a three-part request: a two-byte header naming
 * the class and command, the payload, and one byte the device writes its
 * acknowledgement into. The first two are device-readable and the third is
 * device-writable, which is why they are separate descriptors rather than one
 * buffer -- a device may not write into a descriptor the driver did not mark
 * writable.
 *
 * Sent only after every pair it names has been brought up. A device told to
 * use four pairs starts delivering on four immediately, so sending this while
 * three of them have no buffers posted would drop the frames that landed
 * there. That ordering is the whole reason the servicing work came first. */
xaios_status_t virtio_net_set_queue_pairs(uint16_t pairs) {
  virtio_net_driver_t *g_net = virtio_net_primary_driver();
  if (g_net->ctrl_ready == 0U) return XAIOS_ERR_UNSUPPORTED;
  uint8_t *request = g_net->ctrl_buffer;
  request[0] = (uint8_t)VIRTIO_NET_CTRL_MQ;
  request[1] = (uint8_t)VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET;
  request[2] = (uint8_t)(pairs & 0xffU);
  request[3] = (uint8_t)(pairs >> 8U);
  request[4] = 0xffU; /* not an acknowledgement the device could have written */

  g_net->ctrl_desc[0].addr = virtio_net_dma_address(request);
  g_net->ctrl_desc[0].len = 2U;
  g_net->ctrl_desc[0].flags = VRING_DESC_F_NEXT;
  g_net->ctrl_desc[0].next = 1U;
  g_net->ctrl_desc[1].addr = virtio_net_dma_address(request + 2U);
  g_net->ctrl_desc[1].len = 2U;
  g_net->ctrl_desc[1].flags = VRING_DESC_F_NEXT;
  g_net->ctrl_desc[1].next = 2U;
  g_net->ctrl_desc[2].addr = virtio_net_dma_address(request + 4U);
  g_net->ctrl_desc[2].len = 1U;
  g_net->ctrl_desc[2].flags = VRING_DESC_F_WRITE;
  g_net->ctrl_desc[2].next = 0U;

  g_net->ctrl_avail->ring[g_net->ctrl_avail_idx % VIRTQ_SIZE] = 0U;
  virtio_mmio_barrier();
  ++g_net->ctrl_avail_idx;
  g_net->ctrl_avail->idx = g_net->ctrl_avail_idx;
  virtio_transport_notify(&g_net->device, g_net->ctrl_queue_index);

  xaios_status_t status = virtio_transport_wait_used(
      (volatile uint16_t *)(void *)&g_net->ctrl_used->idx,
      g_net->ctrl_avail_idx);
  if (status != XAIOS_OK) return status;
  g_net->ctrl_last_used = g_net->ctrl_avail_idx;
  virtio_mmio_barrier();
  if (request[4] != (uint8_t)VIRTIO_NET_CTRL_ACK_OK) {
    klog("virtio-net-persist: the device refused %u queue pairs ack=%u\n",
         (uint32_t)pairs, request[4]);
    return XAIOS_ERR_IO;
  }
  return XAIOS_OK;
}

/* The hash key, and why it is this one rather than something generated.
 *
 * Toeplitz hashing exclusive-ors a sliding window of the key for every set
 * bit of the four-tuple, so which bits of the key move decides which bits of
 * the hash move. The first key here was an arithmetic progression --
 * 0x6d + 0x1f per byte -- which looked non-degenerate and was not: byte 13
 * comes out exactly zero, and byte 13 is the window that the low bits of a
 * source port reach. Sixty-four flows differing only in the low six bits of
 * their source port therefore all produced a hash with the same bit zero,
 * every bucket they reached was even, and the device faithfully steered five
 * hundred frames onto pairs zero and two while pairs one and three stayed
 * empty. The spread looked real enough to pass a gate asking only whether
 * more than one queue was used.
 *
 * This is the key every other RSS implementation uses -- the forty bytes from
 * Microsoft's RSS specification, also carried by Linux and DPDK. It is a
 * constant rather than drawn from the entropy pool on purpose: a random key
 * spreads exactly as well and makes a capture impossible to reproduce, and
 * reproducibility is worth more here than unpredictability, because this
 * steers receive queues inside one machine and does not defend anything. */
static const uint8_t virtio_net_rss_key[VIRTIO_NET_RSS_KEY_BYTES] = {
    0x6d, 0x5a, 0x56, 0xda, 0x25, 0x5b, 0x0e, 0xc2,
    0x41, 0x67, 0x25, 0x3d, 0x43, 0xa3, 0x8f, 0xb0,
    0xd0, 0xca, 0x2b, 0xcb, 0xae, 0x7b, 0x30, 0xb4,
    0x77, 0xcb, 0x2d, 0xa3, 0x80, 0x30, 0xf2, 0x0c,
    0x6a, 0x42, 0xb7, 0x3b, 0xbe, 0xac, 0x01, 0xfa,
};

/* Ask the device to steer by hash instead of by whatever it was doing.
 *
 * Without this, a device with several receive queues is free to put every
 * frame on the first one, and the driver polling four queues round robin
 * cannot tell the difference between fair spreading and an empty ring. RSS
 * is what makes the spread a property of the traffic rather than of the
 * device's mood: the device hashes each packet's four-tuple, masks the hash
 * into an indirection table, and the table names the queue.
 *
 * The table is filled round robin over the pairs actually in service, so the
 * queues that exist all get used and the ones that do not are never named.
 * The key is the constant above, for the reasons given there.
 */
xaios_status_t virtio_net_configure_rss(void) {
  virtio_net_driver_t *g_net = virtio_net_primary_driver();
  if (g_net->ctrl_ready == 0U || g_net->rss == 0U) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  uint8_t *request = g_net->ctrl_buffer;
  uint32_t offset = 0U;
  request[offset++] = (uint8_t)VIRTIO_NET_CTRL_MQ;
  request[offset++] = (uint8_t)VIRTIO_NET_CTRL_MQ_RSS_CONFIG;

  /* What this driver wants, narrowed to what the device says it has. The
     narrowing is the point: a device supporting only some of these would
     refuse the whole command over the ones it lacks, and the driver would
     fall back to no steering at all because it asked for too much. */
  uint32_t hash_types =
      VIRTIO_NET_HASH_TYPES_WANTED & g_net->rss_supported_hash_types;
  g_net->rss_hash_types = hash_types;
  for (uint32_t i = 0U; i < 4U; ++i) {
    request[offset++] = (uint8_t)((hash_types >> (8U * i)) & 0xffU);
  }
  /* The table this driver wants, unless the device caps it lower. Halving
     keeps it a power of two, which the device requires because it indexes
     the table by masking a hash rather than by dividing one. */
  uint32_t table_entries = VIRTIO_NET_RSS_TABLE_ENTRIES;
  while (table_entries > g_net->rss_max_table_entries && table_entries > 1U) {
    table_entries /= 2U;
  }
  /* The mask, not the length: the device adds one. */
  uint16_t table_mask = (uint16_t)(table_entries - 1U);
  request[offset++] = (uint8_t)(table_mask & 0xffU);
  request[offset++] = (uint8_t)(table_mask >> 8U);
  /* Where a packet goes when no hash type matched -- an ARP frame, say.
     Queue zero, because something has to take it and pair zero is the one
     guaranteed to exist. */
  request[offset++] = 0U;
  request[offset++] = 0U;
  uint32_t pairs = g_net->active_pairs == 0U ? 1U : g_net->active_pairs;
  for (uint32_t entry = 0U; entry < table_entries; ++entry) {
    uint16_t queue = (uint16_t)(entry % pairs);
    request[offset++] = (uint8_t)(queue & 0xffU);
    request[offset++] = (uint8_t)(queue >> 8U);
  }
  /* How many pairs the driver will use -- a count, not the highest index.
     The field is named max_tx_vq, which reads like an index and was written
     as one here: `pairs - 1`. A device takes this as the queue-pair count and
     applies it the way VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET would, so four pairs
     were announced and then immediately cut to three -- QEMU disables the
     backend queues above the count and reduces every steering decision modulo
     it, which left pair three set up, polled, and unreachable. */
  uint16_t queue_pairs = (uint16_t)pairs;
  request[offset++] = (uint8_t)(queue_pairs & 0xffU);
  request[offset++] = (uint8_t)(queue_pairs >> 8U);
  uint32_t key_bytes = VIRTIO_NET_RSS_KEY_BYTES;
  if (key_bytes > g_net->rss_max_key_size) {
    key_bytes = g_net->rss_max_key_size;
  }
  request[offset++] = (uint8_t)key_bytes;
  for (uint32_t i = 0U; i < key_bytes; ++i) {
    request[offset++] = virtio_net_rss_key[i];
  }
  uint32_t ack_offset = offset;
  request[ack_offset] = 0xffU; /* not a value the device could have written */

  g_net->ctrl_desc[0].addr = virtio_net_dma_address(request);
  g_net->ctrl_desc[0].len = 2U;
  g_net->ctrl_desc[0].flags = VRING_DESC_F_NEXT;
  g_net->ctrl_desc[0].next = 1U;
  g_net->ctrl_desc[1].addr = virtio_net_dma_address(request + 2U);
  g_net->ctrl_desc[1].len = ack_offset - 2U;
  g_net->ctrl_desc[1].flags = VRING_DESC_F_NEXT;
  g_net->ctrl_desc[1].next = 2U;
  g_net->ctrl_desc[2].addr = virtio_net_dma_address(request + ack_offset);
  g_net->ctrl_desc[2].len = 1U;
  g_net->ctrl_desc[2].flags = VRING_DESC_F_WRITE;
  g_net->ctrl_desc[2].next = 0U;

  g_net->ctrl_avail->ring[g_net->ctrl_avail_idx % VIRTQ_SIZE] = 0U;
  virtio_mmio_barrier();
  ++g_net->ctrl_avail_idx;
  g_net->ctrl_avail->idx = g_net->ctrl_avail_idx;
  virtio_transport_notify(&g_net->device, g_net->ctrl_queue_index);

  xaios_status_t status = virtio_transport_wait_used(
      (volatile uint16_t *)(void *)&g_net->ctrl_used->idx,
      g_net->ctrl_avail_idx);
  if (status != XAIOS_OK) return status;
  g_net->ctrl_last_used = g_net->ctrl_avail_idx;
  virtio_mmio_barrier();
  if (request[ack_offset] != (uint8_t)VIRTIO_NET_CTRL_ACK_OK) {
    klog("virtio-net-persist: the device refused the RSS configuration "
         "ack=%u\n", request[ack_offset]);
    return XAIOS_ERR_IO;
  }
  klog("virtio-net-persist: rss configured hash_types=0x%x supported=0x%x "
       "table=%u pairs=%u key_bytes=%u\n", hash_types,
       g_net->rss_supported_hash_types, table_entries, pairs, key_bytes);
  return XAIOS_OK;
}

/* Bring one pair's queues up and fill its receive ring.
 *
 * virtio-net numbers its queues in pairs: receive is 2i, transmit 2i+1, and
 * the control queue -- when negotiated -- sits after the last pair. Pair zero
 * is done inline in `virtio_net_init_persistent` because it is the path that
 * has always run; this is the same sequence for the pairs after it.
 *
 * Setting a pair up is not the same as the device using it. A device starts
 * with one pair in use whatever it advertises, and only begins delivering on
 * the rest when told to by `VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET`. That ordering
 * is the whole reason this lands first: buffers exist and are serviced before
 * anything asks the device to fill them. */
xaios_status_t virtio_net_bring_up_pair(uint32_t index) {
  virtio_net_driver_t *g_net = virtio_net_primary_driver();
  xaios_status_t status = virtio_net_allocate_pair(index);
  if (status != XAIOS_OK) return status;
  virtio_net_queue_pair_t *pair = &g_net->pairs[index];

  virtio_net_bytes_zero(pair->rx_desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  virtio_net_bytes_zero(pair->rx_avail, sizeof(*pair->rx_avail));
  virtio_net_bytes_zero(pair->rx_used, sizeof(*pair->rx_used));
  virtio_net_bytes_zero(pair->tx_desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  virtio_net_bytes_zero(pair->tx_avail, sizeof(*pair->tx_avail));
  virtio_net_bytes_zero(pair->tx_used, sizeof(*pair->tx_used));
  if (g_net->event_idx != 0U) {
    pair->rx_avail->used_event = 0U;
    pair->tx_avail->used_event = 0U;
  }

  status = virtio_transport_setup_queue_vectored(
      &g_net->device, index * 2U, VIRTQ_SIZE, pair->rx_desc, pair->rx_avail,
      pair->rx_used);
  if (status != XAIOS_OK) {
    klog("virtio-net-persist: RX queue %u setup failed status=%d\n",
         index * 2U, (int)status);
    return status;
  }
  status = virtio_transport_setup_queue_vectored(
      &g_net->device, index * 2U + 1U, VIRTQ_SIZE, pair->tx_desc,
      pair->tx_avail, pair->tx_used);
  if (status != XAIOS_OK) {
    klog("virtio-net-persist: TX queue %u setup failed status=%d\n",
         index * 2U + 1U, (int)status);
    return status;
  }

  for (uint32_t i = 0; i < VIRTIO_NET_PERSISTENT_RX_DESCS; ++i) {
    pair->rx_bufs[i] =
        (uint8_t *)kheap_calloc(virtio_net_rx_buffer_bytes(g_net), VIRTIO_DMA_ALIGNMENT);
    if (pair->rx_bufs[i] == 0) {
      klog("virtio-net-persist: pair %u receive buffer %u unavailable\n",
           index, i);
      return XAIOS_ERR_NO_MEMORY;
    }
    pair->rx_desc[i].addr = virtio_net_dma_address(pair->rx_bufs[i]);
    pair->rx_desc[i].len = virtio_net_rx_buffer_bytes(g_net);
    pair->rx_desc[i].flags = VRING_DESC_F_WRITE;
    pair->rx_avail->ring[i] = (uint16_t)i;
  }
  virtio_mmio_barrier();
  pair->rx_avail->idx = VIRTIO_NET_PERSISTENT_RX_DESCS;
  pair->rx_avail_idx = VIRTIO_NET_PERSISTENT_RX_DESCS;
  pair->rx_last_used = 0;
  virtio_transport_notify(&g_net->device, index * 2U);

  for (uint32_t i = 0; i < VIRTIO_NET_PERSISTENT_TX_DESCS; ++i) {
    pair->tx_bufs[i] = (uint8_t *)kheap_calloc(
        VIRTIO_NET_HDR_SIZE + VIRTIO_NET_MAX_FRAME, VIRTIO_DMA_ALIGNMENT);
    if (pair->tx_bufs[i] == 0) {
      klog("virtio-net-persist: pair %u transmit buffer %u unavailable\n",
           index, i);
      return XAIOS_ERR_NO_MEMORY;
    }
  }
  pair->tx_avail_idx = 0;
  pair->tx_last_used = 0;
  return XAIOS_OK;
}
