#include <xaios/arch_cpu.h>
#include <xaios/smp.h>
#include <xaios/assert.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/ipv4.h>
#include <xaios/ipv6.h>
#include <xaios/spinlock.h>
#include <xaios/timer.h>
#include <xaios/net_device.h>
#include <xaios/virtio_net.h>
#include <xaios/virtio_transport.h>
#include <xaios/vmm.h>

#include "virtio_net_internal.h"

static virtio_net_driver_t *g_net;

/* Read by virtio_net_selftest.c, which reaches the driver through this.
   The pointer's value is copied out; the variable itself stays private. */
virtio_net_driver_t *virtio_net_primary_driver(void) { return g_net; }

static void virtio_net_interrupt(uint32_t intid, void *context) {
  virtio_net_driver_t *driver = (virtio_net_driver_t *)context;
  (void)intid;
  if (driver == 0 || driver != g_net) return;
  ++driver->interrupt_count;
  (void)virtio_net_drain_tx_completions();
  /* Receive is not drained here. Handing a frame to the stack takes a lock
     that a thread on this CPU may already hold, and an interrupt is the one
     context that cannot wait for it. What the interrupt does instead is end
     the sleep of whoever was waiting for the link, and that thread drains
     the ring with the lock takeable. */
  network_device_note_interrupt();
  virtio_transport_ack_interrupts(&driver->device);
}

void virtio_net_bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

xaios_status_t virtio_net_allocate_driver(void) {
  if (g_net != 0) {
    return XAIOS_OK;
  }
  g_net = (virtio_net_driver_t *)kheap_calloc(sizeof(*g_net), 16);
  if (g_net == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }
  g_net->active_pairs = 1U;
  return virtio_net_allocate_pair(0U);
}

xaios_status_t virtio_net_init_persistent(void) {
  xaios_status_t status = virtio_net_allocate_driver();
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
  status = virtio_net_negotiate_features(g_net);
  if (status != XAIOS_OK) {
    klog("virtio-net-persist: feature negotiation failed status=%d\n",
         (int)status);
    return status;
  }

  virtio_net_bytes_zero(g_net->pairs[0].rx_desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  virtio_net_bytes_zero(g_net->pairs[0].rx_avail, sizeof(*g_net->pairs[0].rx_avail));
  virtio_net_bytes_zero(g_net->pairs[0].rx_used, sizeof(*g_net->pairs[0].rx_used));
  virtio_net_bytes_zero(g_net->pairs[0].tx_desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  virtio_net_bytes_zero(g_net->pairs[0].tx_avail, sizeof(*g_net->pairs[0].tx_avail));
  virtio_net_bytes_zero(g_net->pairs[0].tx_used, sizeof(*g_net->pairs[0].tx_used));
  if (g_net->event_idx != 0U) {
    g_net->pairs[0].rx_avail->used_event = 0U;
    g_net->pairs[0].tx_avail->used_event = 0U;
  }

  /* Ask for a vector per queue rather than one for the device. Receive and
     transmit completions are then distinguishable at the interrupt, which is
     what steering needs and what one shared vector cannot give: it says only
     that something happened somewhere. Falls back to the shared vector where
     the transport cannot give per-queue ones -- virtio-MMIO has a single
     interrupt line for the whole device -- so this is an improvement where it
     is available and unchanged where it is not. */
  status = virtio_transport_setup_queue_vectored(&g_net->device, 0, VIRTQ_SIZE,
                                                 g_net->pairs[0].rx_desc,
                                                 g_net->pairs[0].rx_avail,
                                                 g_net->pairs[0].rx_used);
  if (status != XAIOS_OK) {
    klog("virtio-net-persist: RX queue setup failed status=%d\n", (int)status);
    return status;
  }
  status = virtio_transport_setup_queue_vectored(&g_net->device, 1, VIRTQ_SIZE,
                                                 g_net->pairs[0].tx_desc,
                                                 g_net->pairs[0].tx_avail,
                                                 g_net->pairs[0].tx_used);
  if (status != XAIOS_OK) {
    klog("virtio-net-persist: TX queue setup failed status=%d\n", (int)status);
    return status;
  }
  klog("virtio-net-persist: queues rx_vector=%u tx_vector=%u multiqueue=%u "
       "max_queue_pairs=%u\n",
       virtio_transport_queue_has_vector(&g_net->device, 0U),
       virtio_transport_queue_has_vector(&g_net->device, 1U),
       g_net->multiqueue, g_net->max_queue_pairs);
  status = virtio_transport_set_driver_ok_checked(&g_net->device);
  if (status != XAIOS_OK) {
    klog("virtio-net-persist: DRIVER_OK failed status=%d\n", (int)status);
    return status;
  }

  /* Allocate and post RX buffers */
  for (uint32_t i = 0; i < VIRTIO_NET_PERSISTENT_RX_DESCS; ++i) {
    if (g_net->pairs[0].rx_chained != 0U) {
      g_net->pairs[0].rx_indirect[i] = (virtq_desc_t *)kheap_calloc(
          sizeof(virtq_desc_t) * VIRTIO_NET_RX_PAGES, VIRTIO_DMA_ALIGNMENT);
      if (g_net->pairs[0].rx_indirect[i] == 0) {
        klog("virtio-net-persist: receive descriptor table %u unavailable\n", i);
        return XAIOS_ERR_NO_MEMORY;
      }
      for (uint32_t page = 0U; page < VIRTIO_NET_RX_PAGES; ++page) {
        g_net->pairs[0].rx_pages[i][page] = (uint8_t *)kheap_calloc(
            VIRTIO_NET_RX_PAGE_BYTES, VIRTIO_DMA_ALIGNMENT);
        if (g_net->pairs[0].rx_pages[i][page] == 0) {
          klog("virtio-net-persist: receive page %u/%u unavailable\n", i, page);
          return XAIOS_ERR_NO_MEMORY;
        }
        g_net->pairs[0].rx_indirect[i][page].addr =
            virtio_net_dma_address(g_net->pairs[0].rx_pages[i][page]);
        g_net->pairs[0].rx_indirect[i][page].len = VIRTIO_NET_RX_PAGE_BYTES;
        g_net->pairs[0].rx_indirect[i][page].flags =
            page + 1U < VIRTIO_NET_RX_PAGES
                ? (uint16_t)(VRING_DESC_F_WRITE | VRING_DESC_F_NEXT)
                : VRING_DESC_F_WRITE;
        g_net->pairs[0].rx_indirect[i][page].next = (uint16_t)(page + 1U);
      }
      g_net->pairs[0].rx_bufs[i] = g_net->pairs[0].rx_pages[i][0];
      g_net->pairs[0].rx_desc[i].addr = virtio_net_dma_address(g_net->pairs[0].rx_indirect[i]);
      g_net->pairs[0].rx_desc[i].len =
          (uint32_t)(sizeof(virtq_desc_t) * VIRTIO_NET_RX_PAGES);
      g_net->pairs[0].rx_desc[i].flags = VRING_DESC_F_INDIRECT;
    } else {
      g_net->pairs[0].rx_bufs[i] = (uint8_t *)kheap_calloc(virtio_net_rx_buffer_bytes(g_net),
                                                  VIRTIO_DMA_ALIGNMENT);
      if (g_net->pairs[0].rx_bufs[i] == 0) {
        klog("virtio-net-persist: receive buffer %u of %u bytes unavailable\n",
             i, virtio_net_rx_buffer_bytes(g_net));
        return XAIOS_ERR_NO_MEMORY;
      }
      g_net->pairs[0].rx_desc[i].addr = virtio_net_dma_address(g_net->pairs[0].rx_bufs[i]);
      g_net->pairs[0].rx_desc[i].len = virtio_net_rx_buffer_bytes(g_net);
      g_net->pairs[0].rx_desc[i].flags = VRING_DESC_F_WRITE;
    }
    g_net->pairs[0].rx_avail->ring[i] = (uint16_t)i;
  }
  virtio_mmio_barrier();
  g_net->pairs[0].rx_avail->idx = VIRTIO_NET_PERSISTENT_RX_DESCS;
  g_net->pairs[0].rx_avail_idx = VIRTIO_NET_PERSISTENT_RX_DESCS;
  g_net->pairs[0].rx_last_used = 0;
  virtio_transport_notify(&g_net->device, 0);

  /* Allocate TX buffers */
  for (uint32_t i = 0; i < VIRTIO_NET_PERSISTENT_TX_DESCS; ++i) {
    g_net->pairs[0].tx_bufs[i] = (uint8_t *)kheap_calloc(
        VIRTIO_NET_HDR_SIZE + VIRTIO_NET_MAX_FRAME, VIRTIO_DMA_ALIGNMENT);
    if (g_net->pairs[0].tx_bufs[i] == 0) {
      klog("virtio-net-persist: transmit buffer %u unavailable\n", i);
      return XAIOS_ERR_NO_MEMORY;
    }
  }
  g_net->pairs[0].tx_avail_idx = 0;
  g_net->pairs[0].tx_last_used = 0;

  /* The pairs after the first, where the device has them. Setting them up
     does not put them into service: a virtio-net device uses one pair until
     `VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET` says otherwise, so this is the half
     that has to exist before that is ever sent. A pair that will not come up
     is not fatal -- the link is already carrying traffic on pair zero, and
     losing the machine over an optimisation would be a poor trade. */
  uint32_t wanted = g_net->multiqueue != 0U ? g_net->max_queue_pairs : 1U;
  if (wanted > VIRTIO_NET_MAX_QUEUE_PAIRS) wanted = VIRTIO_NET_MAX_QUEUE_PAIRS;
  if (wanted == 0U) wanted = 1U;
  for (uint32_t index = 1U; index < wanted; ++index) {
    xaios_status_t pair_status = virtio_net_bring_up_pair(index);
    if (pair_status != XAIOS_OK) {
      klog("virtio-net-persist: pair %u unavailable status=%d; continuing "
           "with %u\n", index, (int)pair_status, g_net->active_pairs);
      break;
    }
    g_net->active_pairs = index + 1U;
  }
  /* Now that every pair named below has buffers posted and is being polled,
     the device can be told to use them. The control queue sits after the last
     pair the device advertises -- not after the last one in service -- so its
     index comes from max_queue_pairs. */
  if (g_net->active_pairs > 1U && g_net->multiqueue != 0U) {
    g_net->ctrl_queue_index = g_net->max_queue_pairs * 2U;
    g_net->ctrl_desc = (virtq_desc_t *)kheap_calloc(
        sizeof(virtq_desc_t) * VIRTQ_SIZE, VIRTIO_DMA_ALIGNMENT);
    g_net->ctrl_avail = (virtq_avail_t *)kheap_calloc(
        sizeof(virtq_avail_t), VIRTIO_DMA_ALIGNMENT);
    g_net->ctrl_used = (virtq_used_t *)kheap_calloc(
        sizeof(virtq_used_t), VIRTIO_DMA_ALIGNMENT);
    /* 64 bytes was enough while the only control command was a two-byte
       queue-pair count. The RSS configuration carries an indirection table
       and a hash key and needs about ninety; sized to 256 so the next
       command is not another silent overflow. */
    g_net->ctrl_buffer = (uint8_t *)kheap_calloc(256U, VIRTIO_DMA_ALIGNMENT);
    if (g_net->ctrl_desc == 0 || g_net->ctrl_avail == 0 ||
        g_net->ctrl_used == 0 || g_net->ctrl_buffer == 0) {
      klog("virtio-net-persist: no control queue memory; staying at one "
           "pair\n");
    } else if (virtio_transport_setup_queue_vectored(
                   &g_net->device, g_net->ctrl_queue_index, VIRTQ_SIZE,
                   g_net->ctrl_desc, g_net->ctrl_avail,
                   g_net->ctrl_used) != XAIOS_OK) {
      klog("virtio-net-persist: control queue %u setup failed; staying at one "
           "pair\n", g_net->ctrl_queue_index);
    } else {
      g_net->ctrl_ready = 1U;
      xaios_status_t mq_status =
          virtio_net_set_queue_pairs((uint16_t)g_net->active_pairs);
      if (mq_status != XAIOS_OK) {
        /* The pairs stay set up and polled; the device simply keeps
           delivering on one. Nothing is lost by that, so a refusal is not a
           reason to fail the link. */
        klog("virtio-net-persist: VQ_PAIRS_SET failed status=%d; the device "
             "keeps using one pair\n", (int)mq_status);
        g_net->active_pairs = 1U;
      }
    }
  }
  /* Steering is configured after the pair count, not before: the
     indirection table names queues, and naming a queue the device has not
     been told to service is a request it is entitled to refuse. */
  if (g_net->rss != 0U && g_net->active_pairs > 1U) {
    if (virtio_net_configure_rss() != XAIOS_OK) {
      /* Hashing declined. The pairs stay up and are still polled; the device
         decides where frames land by whatever rule it had before. That is a
         weaker arrangement, not a broken one, so it is reported rather than
         treated as a link failure. */
      g_net->rss = 0U;
      g_net->rss_hash_types = 0U;
    }
  }
  klog("virtio-net-persist: queue pairs serviced=%u offered=%u rss=%u\n",
       g_net->active_pairs,
       g_net->multiqueue != 0U ? g_net->max_queue_pairs : 1U, g_net->rss);

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
  /* What the wait loop needs to know: whether anything will tell it a frame
     arrived. Without that it has to keep asking. */
  network_device_set_interrupt_driven(status == XAIOS_OK);

  {
    uint8_t mac[6];
    if (virtio_net_get_mac(mac) == XAIOS_OK) {
      klog("virtio-net: hardware address %x:%x:%x:%x:%x:%x\n", mac[0], mac[1],
           mac[2], mac[3], mac[4], mac[5]);
    }
  }
  klog("virtio-net: persistent mode initialized rx=%u tx=%u event_idx=%u indirect_sg=%u interrupt=%u\n",
       VIRTIO_NET_PERSISTENT_RX_DESCS, VIRTIO_NET_PERSISTENT_TX_DESCS,
       g_net->event_idx, g_net->indirect_desc,
       status == XAIOS_OK ? 1U : 0U);
  return XAIOS_OK;
}

/* Record that a frame arrived on a pair, and say so when the picture has
 * changed enough to be worth a line.
 *
 * A line goes out the moment a pair that had received nothing receives its
 * first frame -- that event is the whole claim RSS makes, and reporting only
 * on a schedule would hide it between two prints. Otherwise the report is due
 * when the total doubles, starting at eight: often enough that a run ends on
 * counts large enough to distinguish a spread from a coincidence, rare enough
 * that a link carrying real traffic does not push everything else off the
 * console.
 *
 * The counts are printed whatever they say. A line that appeared only when
 * the traffic had fanned out would be absent in exactly the case worth
 * knowing about -- everything on one queue -- and absence reads as an absent
 * feature rather than as a measurement. */
static void note_rx_frame(uint32_t index) {
  if (index >= VIRTIO_NET_MAX_QUEUE_PAIRS) return;
  uint64_t before = g_net->rx_frames_by_pair[index];
  ++g_net->rx_frames_by_pair[index];
  ++g_net->rx_frames_total;
  uint32_t pairs_used = 0U;
  for (uint32_t i = 0U; i < VIRTIO_NET_MAX_QUEUE_PAIRS; ++i) {
    if (g_net->rx_frames_by_pair[i] != 0U) pairs_used++;
  }
  uint32_t new_pair = before == 0U ? 1U : 0U;
  if (g_net->rx_report_at == 0U) g_net->rx_report_at = 8U;
  if (new_pair == 0U && g_net->rx_frames_total < g_net->rx_report_at) return;
  if (g_net->rx_frames_total >= g_net->rx_report_at) {
    g_net->rx_report_at *= 2U;
  }
  klog("virtio-net-persist: receive serviced=%u carrying=%u rss=%u "
       "hash_types=0x%x frames=%lu frames_by_pair=%lu,%lu,%lu,%lu\n",
       g_net->active_pairs, pairs_used, g_net->rss, g_net->rss_hash_types,
       g_net->rx_frames_total, g_net->rx_frames_by_pair[0],
       g_net->rx_frames_by_pair[1], g_net->rx_frames_by_pair[2],
       g_net->rx_frames_by_pair[3]);
}

/* One pair's receive ring. Returns the frame length, or zero when that
   pair had nothing -- which is not the same as the device having nothing,
   so the interrupt is acknowledged by the caller once every pair has been
   looked at rather than by whichever one is checked first. */
static uint32_t rx_poll_pair(uint32_t index, uint8_t *buffer,
                             uint64_t buffer_size) {
  virtio_net_queue_pair_t *pair = &g_net->pairs[index];

  /* The device publishes used-ring entries before updating idx. Force a fresh
   * device-owned index load, then order the entry reads after it. */
  virtio_mmio_barrier();
  uint16_t used_idx =
      *(volatile uint16_t *)(void *)&pair->rx_used->idx;
  if (used_idx == pair->rx_last_used) return 0;
  virtio_mmio_barrier();
  /* Counted here, before the frame is examined, because the question this
     answers is which queue the device chose -- not whether the contents
     survived. A frame too large for the caller's buffer is still a frame the
     device steered here, and dropping it from the count would make a
     malformed sender look like an idle queue. */
  note_rx_frame(index);

  virtq_used_elem_t *elem =
      &pair->rx_used->ring[pair->rx_last_used % VIRTQ_SIZE];
  uint16_t desc = (uint16_t)elem->id;
  uint32_t rx_len = elem->len;
  uint32_t frame_len = 0;

  if (rx_len > VIRTIO_NET_HDR_SIZE &&
      rx_len - VIRTIO_NET_HDR_SIZE <= buffer_size) {
    frame_len = rx_len - VIRTIO_NET_HDR_SIZE;
    if (pair->rx_chained == 0U) {
      for (uint32_t i = 0; i < frame_len; ++i) {
        buffer[i] = pair->rx_bufs[desc][VIRTIO_NET_HDR_SIZE + i];
      }
    } else {
      /* The device fills the chain in order, so skip the header wherever it
         happens to end and take the rest page by page. */
      uint32_t skip = VIRTIO_NET_HDR_SIZE;
      uint32_t copied = 0U;
      for (uint32_t page = 0U;
           page < VIRTIO_NET_RX_PAGES && copied < frame_len; ++page) {
        if (skip >= VIRTIO_NET_RX_PAGE_BYTES) {
          skip -= VIRTIO_NET_RX_PAGE_BYTES;
          continue;
        }
        const uint8_t *source = pair->rx_pages[desc][page] + skip;
        uint32_t available = VIRTIO_NET_RX_PAGE_BYTES - skip;
        uint32_t remaining = frame_len - copied;
        uint32_t take = remaining < available ? remaining : available;
        for (uint32_t i = 0U; i < take; ++i) buffer[copied + i] = source[i];
        copied += take;
        skip = 0U;
      }
      frame_len = copied;
    }
  }

  /* Every used entry must be returned, including malformed/oversized input. */
  ++pair->rx_last_used;
  if (g_net->event_idx != 0U) {
    pair->rx_avail->used_event = pair->rx_last_used;
  }
  if (pair->rx_chained != 0U) {
    pair->rx_desc[desc].addr = virtio_net_dma_address(pair->rx_indirect[desc]);
    pair->rx_desc[desc].len =
        (uint32_t)(sizeof(virtq_desc_t) * VIRTIO_NET_RX_PAGES);
    pair->rx_desc[desc].flags = VRING_DESC_F_INDIRECT;
  } else {
    pair->rx_desc[desc].addr = virtio_net_dma_address(pair->rx_bufs[desc]);
    pair->rx_desc[desc].len = virtio_net_rx_buffer_bytes(g_net);
    pair->rx_desc[desc].flags = VRING_DESC_F_WRITE;
  }
  pair->rx_avail->ring[pair->rx_avail_idx % VIRTQ_SIZE] = desc;
  virtio_mmio_barrier();
  ++pair->rx_avail_idx;
  pair->rx_avail->idx = pair->rx_avail_idx;
  virtio_transport_notify(&g_net->device, index * 2U);
  virtio_transport_ack_interrupts(&g_net->device);
  return frame_len;
}

/* Every pair that is in service, starting where the last call left off.
 *
 * Round-robin rather than always from zero: a pair with a steady stream would
 * otherwise be the only one ever read, and frames on the others would sit in
 * their rings until it went quiet. With one pair in service this is the same
 * single ring it has always been. */
uint32_t virtio_net_rx_poll(uint8_t *buffer, uint64_t buffer_size) {
  if (g_net == 0 || g_net->persistent == 0 || buffer == 0 ||
      buffer_size == 0) {
    return 0;
  }
  uint32_t pairs = g_net->active_pairs != 0U ? g_net->active_pairs : 1U;
  for (uint32_t step = 0U; step < pairs; ++step) {
    uint32_t index = (g_net->rx_cursor + step) % pairs;
    uint32_t frame_len = rx_poll_pair(index, buffer, buffer_size);
    if (frame_len != 0U) {
      g_net->rx_cursor = (uint32_t)((index + 1U) % pairs);
      return frame_len;
    }
  }
  virtio_transport_ack_interrupts(&g_net->device);
  return 0;
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
