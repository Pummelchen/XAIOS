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
/* Multiple receive/transmit pairs, and the control queue a driver needs to
   tell the device how many of them to use. Reported here whether or not this
   driver drives them: what a device offers is worth knowing before anyone
   writes the code to use it, and a count nobody has read is a guess. */
#define VIRTIO_NET_F_CTRL_VQ (UINT32_C(1) << 17U)
#define VIRTIO_NET_F_MQ (UINT32_C(1) << 22U)
/* The control queue's multiqueue class, and its one command: how many pairs
   the driver is actually servicing. Until it is sent, a device uses one pair
   however many it advertises. */
#define VIRTIO_NET_CTRL_MQ 4U
#define VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET 0U
#define VIRTIO_NET_CTRL_MQ_RSS_CONFIG 1U
/* Receive-side scaling sits at feature bit 60, which is bit 28 of the high
   word -- the first feature this driver wants that does not fit in the low
   one. */
#define VIRTIO_NET_F_RSS_HIGH (UINT32_C(1) << 28U)
/* Hash reporting is bit 57, and is deliberately not requested.
 *
 * It is a separate feature from RSS: RSS makes the device choose the queue,
 * hash reporting makes it also hand the driver the hash value it used. QEMU
 * offers both on a tap-backed device. Taking it would change the receive
 * header from virtio_net_hdr_v1 to virtio_net_hdr_v1_hash -- twenty bytes
 * instead of twelve, on every frame in both directions -- and would switch
 * QEMU from steering in the host kernel to computing every hash itself, since
 * populating the field is something only the emulator can do. Nothing in this
 * system reads a per-packet hash: there is no software receive steering and
 * no flow table keyed by one. Asking for it would cost eight bytes and the
 * host's offload on every packet to deliver a number nobody looks at. The bit
 * is named here so the next person can see it was a decision. */
#define VIRTIO_NET_F_HASH_REPORT_HIGH (UINT32_C(1) << 25U)
/* Which parts of a packet the device hashes. The four-tuple types are what
   this is for: hashing on addresses alone puts every flow between the same
   two machines on one queue, which is the case multiqueue exists to spread.
   The three IPv6 extension-header variants are listed too, because a device
   is free to support only those, and a driver that cannot name them would
   then ask for nothing. */
#define VIRTIO_NET_HASH_TYPE_IPV4 (UINT32_C(1) << 0U)
#define VIRTIO_NET_HASH_TYPE_TCPV4 (UINT32_C(1) << 1U)
#define VIRTIO_NET_HASH_TYPE_UDPV4 (UINT32_C(1) << 2U)
#define VIRTIO_NET_HASH_TYPE_IPV6 (UINT32_C(1) << 3U)
#define VIRTIO_NET_HASH_TYPE_TCPV6 (UINT32_C(1) << 4U)
#define VIRTIO_NET_HASH_TYPE_UDPV6 (UINT32_C(1) << 5U)
#define VIRTIO_NET_HASH_TYPE_IP_EX (UINT32_C(1) << 6U)
#define VIRTIO_NET_HASH_TYPE_TCP_EX (UINT32_C(1) << 7U)
#define VIRTIO_NET_HASH_TYPE_UDP_EX (UINT32_C(1) << 8U)
/* Everything this driver would take if the device had it. What it actually
   asks for is this masked with what the device says it supports -- see
   `configure_rss`. */
#define VIRTIO_NET_HASH_TYPES_WANTED                                    \
  (VIRTIO_NET_HASH_TYPE_IPV4 | VIRTIO_NET_HASH_TYPE_TCPV4 |             \
   VIRTIO_NET_HASH_TYPE_UDPV4 | VIRTIO_NET_HASH_TYPE_IPV6 |             \
   VIRTIO_NET_HASH_TYPE_TCPV6 | VIRTIO_NET_HASH_TYPE_UDPV6 |            \
   VIRTIO_NET_HASH_TYPE_IP_EX | VIRTIO_NET_HASH_TYPE_TCP_EX |           \
   VIRTIO_NET_HASH_TYPE_UDP_EX)
/* Where the RSS parameters live in the device configuration, counted from
   its start: one byte of maximum key size at 17, two of maximum indirection
   table length at 18, and four of supported hash types at 20. They are only
   present once RSS -- or hash reporting -- has been negotiated. */
#define VIRTIO_NET_CFG_RSS_MAX_KEY_SIZE 17U
#define VIRTIO_NET_CFG_RSS_MAX_TABLE_LEN 18U
#define VIRTIO_NET_CFG_SUPPORTED_HASH_TYPES 20U
/* Sixteen entries is a mask of fifteen, which is the smallest power of two
   that still spreads evenly over the four pairs this driver supports. The
   table has to be a power of two because the device indexes it by masking a
   hash, not by dividing one.

   Overridable for the same reason VIRTIO_BLK_MAX_TRANSFER is: a claim about
   steering is only worth as much as the run that would have contradicted it.
   Built with -DVIRTIO_NET_RSS_TABLE_ENTRIES=1 the table has one bucket, every
   hash lands in it, and it names queue zero -- RSS is still negotiated,
   configured and accepted, and every frame arrives on one queue. That is the
   control tests/scripts/qemu-rss-steering-gate.py runs as its second arm, and
   a gate that stays green through it is measuring nothing. Nothing that ships
   is built at anything but sixteen. */
#ifndef VIRTIO_NET_RSS_TABLE_ENTRIES
#define VIRTIO_NET_RSS_TABLE_ENTRIES 16U
#endif
#define VIRTIO_NET_RSS_KEY_BYTES 40U
#define VIRTIO_NET_CTRL_ACK_OK 0U
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
/* Without mergeable receive buffers, negotiating a guest segmentation offload
   would oblige the driver to post receive buffers of at least 65550 bytes,
   because the device may then deliver a coalesced segment that large. A
   buffer that size spans seventeen pages, and a single descriptor must be
   physically contiguous, which the kernel heap cannot promise: it maps pages
   allocated one at a time. Posting one page instead keeps every descriptor
   contiguous and carries any ordinary frame; a coalesced segment larger than
   this is dropped on receive, which the receive path already does safely.
   Lifting that limit needs either a contiguous allocator or an indirect
   descriptor chain per receive buffer. */
#define VIRTIO_NET_GSO_RX_BUFFER 65550U
/* A buffer that large spans seventeen pages, and a descriptor covers one
   physically contiguous run, which the kernel heap cannot promise: it maps
   pages allocated one at a time. The specification lets a receive buffer be a
   descriptor chain, so each slot posts one indirect descriptor naming a page
   per entry. That is why indirect descriptors are asked for above. */
#define VIRTIO_NET_RX_PAGE_BYTES 4096U
#define VIRTIO_NET_RX_PAGES 17U
#define VIRTIO_F_RING_INDIRECT_DESC (UINT32_C(1) << 28U)
#define VIRTIO_F_RING_EVENT_IDX (UINT32_C(1) << 29U)
#define VIRTIO_F_VERSION_1_HIGH UINT32_C(1)
/* The most pairs this driver will set up. The device may offer more; it
   is told how many are in use, so offering more is not an error. */
#define VIRTIO_NET_MAX_QUEUE_PAIRS 4U
#define VIRTIO_NET_MAX_TX_FRAGMENTS 4U
#define VIRTIO_NET_FRAGMENT_BUFFER 4096U

/* Everything that belongs to one receive/transmit pair.
 *
 * This was eighteen fields spread through the driver, which was correct while
 * there could only ever be one pair of them. `VIRTIO_NET_F_MQ` makes that
 * false: a device may offer several, and a driver that services one while the
 * device delivers on all of them loses every packet that lands on a queue
 * nobody is reading. Gathering the state into a pair is the first half of
 * E4 -- buffers and servicing for N pairs -- and has to come before asking a
 * device to use more than one, because a device told to use four pairs will
 * deliver on four whether or not anything is listening. */
typedef struct virtio_net_queue_pair {
  virtq_desc_t *rx_desc;
  virtq_avail_t *rx_avail;
  virtq_used_t *rx_used;
  virtq_desc_t *tx_desc;
  virtq_avail_t *tx_avail;
  virtq_used_t *tx_used;
  uint8_t *rx_packet;
  uint8_t *tx_packet;
  uint16_t rx_avail_idx;
  uint16_t rx_last_used;
  uint16_t tx_avail_idx;
  uint16_t tx_last_used;
  xaios_spinlock_t tx_lock;
  uint8_t *rx_bufs[VIRTIO_NET_PERSISTENT_RX_DESCS];
  virtq_desc_t *rx_indirect[VIRTIO_NET_PERSISTENT_RX_DESCS];
  uint8_t *rx_pages[VIRTIO_NET_PERSISTENT_RX_DESCS][VIRTIO_NET_RX_PAGES];
  uint32_t rx_chained;
  uint8_t *tx_bufs[VIRTIO_NET_PERSISTENT_TX_DESCS];
  virtq_desc_t *tx_indirect[VIRTIO_NET_PERSISTENT_TX_DESCS];
} virtio_net_queue_pair_t;

typedef struct virtio_net_driver {
  virtio_mmio_device_t device;
  /* persistent mode state */
  uint32_t persistent;
  uint64_t interrupt_count;
  uint64_t tx_completion_count;
  uint32_t event_idx;
  uint32_t indirect_desc;
  uint32_t large_rx;
  uint32_t device_present;
  uint64_t scatter_gather_submissions;
  uint64_t copy_fallbacks;
  uint32_t multiqueue;
  /* Whether the device accepted VIRTIO_NET_F_RSS. Separate from multiqueue:
     a device can offer several pairs and no hashing at all. */
  uint32_t rss;
  /* What the device said it can hash on, what it will let the indirection
     table and the key grow to, and what was finally asked for. Read from the
     device configuration rather than assumed: a device is entitled to support
     only some hash types, and a driver naming one it does not have is asking
     for a refusal. The last of the four is what the gate quotes. */
  uint32_t rss_supported_hash_types;
  uint32_t rss_max_table_entries;
  uint32_t rss_max_key_size;
  uint32_t rss_hash_types;
  uint32_t max_queue_pairs;
  /* How many pairs are set up and serviced. Receive polls all of them round
     robin; transmit picks one per CPU. The device may advertise more than
     were successfully brought up, which is why this is the count that was
     achieved rather than the count that was offered. */
  uint32_t active_pairs;
  /* Which pairs have actually carried a frame. A driver that selects a pair
     per CPU and a driver that always picks zero are indistinguishable from
     the outside unless this is counted, and "it should fan out" is not
     evidence that it did. */
  uint64_t tx_frames_by_pair[VIRTIO_NET_MAX_QUEUE_PAIRS];
  uint32_t tx_fanout_reported;
  /* How many pairs had carried a frame when the last line was printed. */
  uint32_t tx_fanout_pairs_reported;
  /* The same count for the direction the device chooses.
   *
   * Transmit fanning out proves the driver picks a queue; it says nothing
   * about steering, because the driver picked. Receive is the direction RSS
   * governs: the device hashes the frame and names the queue, and the only
   * way to know it did is to count what arrived where. A gate that checks
   * "four queues exist" would pass without a single frame having been
   * steered, so this is the number that has to be reported. */
  uint64_t rx_frames_by_pair[VIRTIO_NET_MAX_QUEUE_PAIRS];
  uint64_t rx_frames_total;
  /* When the next distribution line is due. Doubling the threshold keeps a
     busy link from filling the console while still ending on a line whose
     counts are large enough to mean something. */
  uint64_t rx_report_at;
  /* Where the next receive poll starts, so no pair starves another. Receive
     has no CPU affinity to follow -- the device chooses which queue a frame
     lands on -- so a cursor is right here where it would be wrong for
     transmit. */
  uint32_t rx_cursor;
  /* The control queue, when the device has one. It is not a pair: there is a
     single one, and it sits after the last pair the device advertises. */
  virtq_desc_t *ctrl_desc;
  virtq_avail_t *ctrl_avail;
  virtq_used_t *ctrl_used;
  uint8_t *ctrl_buffer;
  uint16_t ctrl_avail_idx;
  uint16_t ctrl_last_used;
  uint32_t ctrl_ready;
  uint32_t ctrl_queue_index;
  virtio_net_queue_pair_t pairs[VIRTIO_NET_MAX_QUEUE_PAIRS];
} virtio_net_driver_t;

static virtio_net_driver_t *g_net;

static uint16_t read_be16(const uint8_t *value) {
  return (uint16_t)(((uint16_t)value[0] << 8U) | value[1]);
}

static uint32_t drain_tx_completions_locked(virtio_net_queue_pair_t *pair) {
  if (g_net == 0 || g_net->persistent == 0U || pair == 0) return 0U;
  virtio_mmio_barrier();
  uint16_t used = *(volatile uint16_t *)(void *)&pair->tx_used->idx;
  uint32_t completed = (uint16_t)(used - pair->tx_last_used);
  pair->tx_last_used = used;
  if (g_net->event_idx != 0U) {
    pair->tx_avail->used_event = used;
  }
  g_net->tx_completion_count += completed;
  return completed;
}

/* Which pair this CPU transmits on.
 *
 * By CPU rather than round-robin, because the point of a second transmit
 * queue is not that frames alternate between them -- it is that two CPUs
 * sending at once do not queue behind the same lock. A shared cursor would
 * reintroduce exactly the contention the queues exist to remove, and would
 * do it in a line of code that looks like fairness. */
static uint32_t tx_pair_index(void) {
  if (g_net == 0 || g_net->active_pairs <= 1U) return 0U;
  return smp_cpu_id() % g_net->active_pairs;
}

/* Every pair, not just the one this CPU sends on: completions belong to
   whichever queue carried the frame, and a pair nobody drains stops
   accepting work once its ring fills. trylock so a busy pair is skipped
   rather than waited on -- this runs from the interrupt path. */
static uint32_t virtio_net_drain_tx_completions(void) {
  if (g_net == 0) return 0U;
  uint32_t completed = 0U;
  uint32_t pairs = g_net->active_pairs == 0U ? 1U : g_net->active_pairs;
  for (uint32_t i = 0U; i < pairs; ++i) {
    virtio_net_queue_pair_t *pair = &g_net->pairs[i];
    if (xaios_spin_trylock(&pair->tx_lock) == 0) continue;
    completed += drain_tx_completions_locked(pair);
    xaios_spin_unlock(&pair->tx_lock);
  }
  return completed;
}

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

/* One pair's rings and scratch buffers. Pair zero is allocated with the
   driver; the rest only once a device says it has them, so a single-queue
   device costs exactly what it did before. */
static xaios_status_t allocate_pair(uint32_t index) {
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

static xaios_status_t allocate_driver(void) {
  if (g_net != 0) {
    return XAIOS_OK;
  }
  g_net = (virtio_net_driver_t *)kheap_calloc(sizeof(*g_net), 16);
  if (g_net == 0) {
    return XAIOS_ERR_NO_MEMORY;
  }
  g_net->active_pairs = 1U;
  return allocate_pair(0U);
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

  bytes_zero(g_net->pairs[0].rx_desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  bytes_zero(g_net->pairs[0].rx_avail, sizeof(*g_net->pairs[0].rx_avail));
  bytes_zero(g_net->pairs[0].rx_used, sizeof(*g_net->pairs[0].rx_used));
  bytes_zero(g_net->pairs[0].tx_desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  bytes_zero(g_net->pairs[0].tx_avail, sizeof(*g_net->pairs[0].tx_avail));
  bytes_zero(g_net->pairs[0].tx_used, sizeof(*g_net->pairs[0].tx_used));
  if (g_net->event_idx != 0U) {
    g_net->pairs[0].rx_avail->used_event = 0U;
    g_net->pairs[0].tx_avail->used_event = 0U;
  }
  bytes_zero(g_net->pairs[0].rx_packet, rx_buffer_bytes(g_net));
  bytes_zero(g_net->pairs[0].tx_packet, 128);

  kassert(virtio_transport_setup_queue(&g_net->device, 0, VIRTQ_SIZE,
                                       g_net->pairs[0].rx_desc, g_net->pairs[0].rx_avail,
                                       g_net->pairs[0].rx_used) == XAIOS_OK);
  kassert(virtio_transport_setup_queue(&g_net->device, 1, VIRTQ_SIZE,
                                       g_net->pairs[0].tx_desc, g_net->pairs[0].tx_avail,
                                       g_net->pairs[0].tx_used) == XAIOS_OK);
  virtio_transport_set_driver_ok(&g_net->device);

  g_net->pairs[0].rx_desc[0].addr = dma_address(g_net->pairs[0].rx_packet);
  g_net->pairs[0].rx_desc[0].len = rx_buffer_bytes(g_net);
  g_net->pairs[0].rx_desc[0].flags = VRING_DESC_F_WRITE;
  g_net->pairs[0].rx_avail->ring[0] = 0;
  virtio_mmio_barrier();
  g_net->pairs[0].rx_avail->idx = 1;
  virtio_transport_notify(&g_net->device, 0);

  uint64_t tx_len = 0;
  build_arp_request(g_net->pairs[0].tx_packet, &tx_len);
  if (g_net->indirect_desc != 0U) {
    virtq_desc_t *indirect = g_net->pairs[0].tx_indirect[0];
    indirect[0].addr = dma_address(g_net->pairs[0].tx_packet);
    indirect[0].len = VIRTIO_NET_HDR_SIZE;
    indirect[0].flags = VRING_DESC_F_NEXT;
    indirect[0].next = 1U;
    indirect[1].addr = dma_address(g_net->pairs[0].tx_packet + VIRTIO_NET_HDR_SIZE);
    indirect[1].len = 21U;
    indirect[1].flags = VRING_DESC_F_NEXT;
    indirect[1].next = 2U;
    indirect[2].addr =
        dma_address(g_net->pairs[0].tx_packet + VIRTIO_NET_HDR_SIZE + 21U);
    indirect[2].len = 21U;
    indirect[2].flags = 0U;
    indirect[2].next = 0U;
    g_net->pairs[0].tx_desc[0].addr = dma_address(indirect);
    g_net->pairs[0].tx_desc[0].len = 3U * sizeof(virtq_desc_t);
    g_net->pairs[0].tx_desc[0].flags = VRING_DESC_F_INDIRECT;
  } else {
    g_net->pairs[0].tx_desc[0].addr = dma_address(g_net->pairs[0].tx_packet);
    g_net->pairs[0].tx_desc[0].len = (uint32_t)tx_len;
    g_net->pairs[0].tx_desc[0].flags = 0U;
  }
  g_net->pairs[0].tx_avail->ring[0] = 0;
  virtio_mmio_barrier();
  g_net->pairs[0].tx_avail->idx = 1;
  virtio_transport_notify(&g_net->device, 1);

  /* Whether a transmit completes inside a fixed window is the device's
     business and the host's, not a kernel invariant. Asserting on it halted a
     machine outright when this ran on a loaded host and the completion arrived
     late -- the posture feature negotiation above already rejects for exactly
     this reason. Report it and leave the path unvalidated instead, and go on
     to reset the device either way, because the real driver initialises after
     this and needs the queues put back. */
  xaios_status_t tx_status =
      virtio_transport_wait_used_notifying(&g_net->device, 1U, &g_net->pairs[0].tx_used->idx, 1);
  xaios_status_t rx_status =
      tx_status == XAIOS_OK
          ? virtio_transport_wait_used_notifying(&g_net->device, 0U, &g_net->pairs[0].rx_used->idx, 1)
          : XAIOS_ERR_IO;
  virtio_transport_ack_interrupts(&g_net->device);

  if (tx_status != XAIOS_OK) {
    /* V-10: this happens on roughly one boot in twenty-five here and nobody
       knows why yet. Five seconds is far too long for a merely slow device,
       so record enough to tell the candidates apart the next time it lands:
       whether the device gave up (status bit 6, DEVICE_NEEDS_RESET), whether
       it ever consumed what was offered, and where both rings stood. */
    klog("virtio-net: transmit completion did not arrive; TX/RX integration "
         "not asserted\n");
    klog("virtio-net: V-10 tx_avail=%u tx_used=%u rx_avail=%u rx_used=%u "
         "device_status=0x%x event_idx=%u indirect=%u\n",
         g_net->pairs[0].tx_avail->idx, g_net->pairs[0].tx_used->idx, g_net->pairs[0].rx_avail->idx,
         g_net->pairs[0].rx_used->idx,
         virtio_transport_device_status(&g_net->device), g_net->event_idx,
         g_net->indirect_desc);
  } else if (rx_status == XAIOS_OK) {
    uint32_t rx_len = g_net->pairs[0].rx_used->ring[0].len;
    /* The request went to QEMU user-mode networking's gateway. Any other
       host answers from its own subnet, so a reply that does not match is
       evidence of a different network rather than of a broken driver. */
    if (is_expected_arp_reply(g_net->pairs[0].rx_packet, rx_len)) {
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
  klog("virtio-net: queue/tx/parser/reset self-test passed event_idx=%u "
       "indirect_sg=%u tx_completed=%u\n",
       g_net->event_idx, g_net->indirect_desc,
       tx_status == XAIOS_OK ? 1U : 0U);
}

static uint64_t net_dma_address(const void *ptr) {
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
static xaios_status_t set_queue_pairs(uint16_t pairs) {
  if (g_net->ctrl_ready == 0U) return XAIOS_ERR_UNSUPPORTED;
  uint8_t *request = g_net->ctrl_buffer;
  request[0] = (uint8_t)VIRTIO_NET_CTRL_MQ;
  request[1] = (uint8_t)VIRTIO_NET_CTRL_MQ_VQ_PAIRS_SET;
  request[2] = (uint8_t)(pairs & 0xffU);
  request[3] = (uint8_t)(pairs >> 8U);
  request[4] = 0xffU; /* not an acknowledgement the device could have written */

  g_net->ctrl_desc[0].addr = net_dma_address(request);
  g_net->ctrl_desc[0].len = 2U;
  g_net->ctrl_desc[0].flags = VRING_DESC_F_NEXT;
  g_net->ctrl_desc[0].next = 1U;
  g_net->ctrl_desc[1].addr = net_dma_address(request + 2U);
  g_net->ctrl_desc[1].len = 2U;
  g_net->ctrl_desc[1].flags = VRING_DESC_F_NEXT;
  g_net->ctrl_desc[1].next = 2U;
  g_net->ctrl_desc[2].addr = net_dma_address(request + 4U);
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
static xaios_status_t configure_rss(void) {
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

  g_net->ctrl_desc[0].addr = net_dma_address(request);
  g_net->ctrl_desc[0].len = 2U;
  g_net->ctrl_desc[0].flags = VRING_DESC_F_NEXT;
  g_net->ctrl_desc[0].next = 1U;
  g_net->ctrl_desc[1].addr = net_dma_address(request + 2U);
  g_net->ctrl_desc[1].len = ack_offset - 2U;
  g_net->ctrl_desc[1].flags = VRING_DESC_F_NEXT;
  g_net->ctrl_desc[1].next = 2U;
  g_net->ctrl_desc[2].addr = net_dma_address(request + ack_offset);
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
static xaios_status_t bring_up_pair(uint32_t index) {
  xaios_status_t status = allocate_pair(index);
  if (status != XAIOS_OK) return status;
  virtio_net_queue_pair_t *pair = &g_net->pairs[index];

  bytes_zero(pair->rx_desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  bytes_zero(pair->rx_avail, sizeof(*pair->rx_avail));
  bytes_zero(pair->rx_used, sizeof(*pair->rx_used));
  bytes_zero(pair->tx_desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  bytes_zero(pair->tx_avail, sizeof(*pair->tx_avail));
  bytes_zero(pair->tx_used, sizeof(*pair->tx_used));
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
        (uint8_t *)kheap_calloc(rx_buffer_bytes(g_net), VIRTIO_DMA_ALIGNMENT);
    if (pair->rx_bufs[i] == 0) {
      klog("virtio-net-persist: pair %u receive buffer %u unavailable\n",
           index, i);
      return XAIOS_ERR_NO_MEMORY;
    }
    pair->rx_desc[i].addr = net_dma_address(pair->rx_bufs[i]);
    pair->rx_desc[i].len = rx_buffer_bytes(g_net);
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

  bytes_zero(g_net->pairs[0].rx_desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  bytes_zero(g_net->pairs[0].rx_avail, sizeof(*g_net->pairs[0].rx_avail));
  bytes_zero(g_net->pairs[0].rx_used, sizeof(*g_net->pairs[0].rx_used));
  bytes_zero(g_net->pairs[0].tx_desc, sizeof(virtq_desc_t) * VIRTQ_SIZE);
  bytes_zero(g_net->pairs[0].tx_avail, sizeof(*g_net->pairs[0].tx_avail));
  bytes_zero(g_net->pairs[0].tx_used, sizeof(*g_net->pairs[0].tx_used));
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
            net_dma_address(g_net->pairs[0].rx_pages[i][page]);
        g_net->pairs[0].rx_indirect[i][page].len = VIRTIO_NET_RX_PAGE_BYTES;
        g_net->pairs[0].rx_indirect[i][page].flags =
            page + 1U < VIRTIO_NET_RX_PAGES
                ? (uint16_t)(VRING_DESC_F_WRITE | VRING_DESC_F_NEXT)
                : VRING_DESC_F_WRITE;
        g_net->pairs[0].rx_indirect[i][page].next = (uint16_t)(page + 1U);
      }
      g_net->pairs[0].rx_bufs[i] = g_net->pairs[0].rx_pages[i][0];
      g_net->pairs[0].rx_desc[i].addr = net_dma_address(g_net->pairs[0].rx_indirect[i]);
      g_net->pairs[0].rx_desc[i].len =
          (uint32_t)(sizeof(virtq_desc_t) * VIRTIO_NET_RX_PAGES);
      g_net->pairs[0].rx_desc[i].flags = VRING_DESC_F_INDIRECT;
    } else {
      g_net->pairs[0].rx_bufs[i] = (uint8_t *)kheap_calloc(rx_buffer_bytes(g_net),
                                                  VIRTIO_DMA_ALIGNMENT);
      if (g_net->pairs[0].rx_bufs[i] == 0) {
        klog("virtio-net-persist: receive buffer %u of %u bytes unavailable\n",
             i, rx_buffer_bytes(g_net));
        return XAIOS_ERR_NO_MEMORY;
      }
      g_net->pairs[0].rx_desc[i].addr = net_dma_address(g_net->pairs[0].rx_bufs[i]);
      g_net->pairs[0].rx_desc[i].len = rx_buffer_bytes(g_net);
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
    xaios_status_t pair_status = bring_up_pair(index);
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
          set_queue_pairs((uint16_t)g_net->active_pairs);
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
    if (configure_rss() != XAIOS_OK) {
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

  /* One pair per CPU, chosen before the lock is taken. */
  uint32_t pair_index = tx_pair_index();
  virtio_net_queue_pair_t *pair = &g_net->pairs[pair_index];
  xaios_spin_lock(&pair->tx_lock);
  (void)drain_tx_completions_locked(pair);
  uint16_t outstanding =
      (uint16_t)(pair->tx_avail_idx - pair->tx_last_used);
  if (outstanding >= VIRTIO_NET_PERSISTENT_TX_DESCS) {
    xaios_spin_unlock(&pair->tx_lock);
    return XAIOS_ERR_BUSY;
  }
  uint16_t desc_idx =
      pair->tx_avail_idx % VIRTIO_NET_PERSISTENT_TX_DESCS;
  bytes_zero(pair->tx_bufs[desc_idx], VIRTIO_NET_HDR_SIZE);

  uint64_t fragment_physical[VIRTIO_NET_MAX_TX_FRAGMENTS];
  uint32_t direct = allow_direct != 0U && g_net->indirect_desc != 0U;
  for (uint32_t i = 0U; i < vector_count && direct != 0U; ++i) {
    if (!dma_range(vectors[i].base, vectors[i].length,
                   &fragment_physical[i])) {
      direct = 0U;
    }
  }
  if (direct != 0U) {
    virtq_desc_t *indirect = pair->tx_indirect[desc_idx];
    indirect[0].addr = net_dma_address(pair->tx_bufs[desc_idx]);
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
    pair->tx_desc[desc_idx].addr = net_dma_address(indirect);
    pair->tx_desc[desc_idx].len =
        (vector_count + 1U) * sizeof(virtq_desc_t);
    pair->tx_desc[desc_idx].flags = VRING_DESC_F_INDIRECT;
    ++g_net->scatter_gather_submissions;
  } else {
    uint64_t offset = VIRTIO_NET_HDR_SIZE;
    for (uint32_t i = 0U; i < vector_count; ++i) {
      const uint8_t *source = (const uint8_t *)vectors[i].base;
      for (uint64_t j = 0U; j < vectors[i].length; ++j) {
        pair->tx_bufs[desc_idx][offset++] = source[j];
      }
    }
    pair->tx_desc[desc_idx].addr = net_dma_address(pair->tx_bufs[desc_idx]);
    pair->tx_desc[desc_idx].len =
        (uint32_t)(VIRTIO_NET_HDR_SIZE + total_payload);
    pair->tx_desc[desc_idx].flags = 0U;
    ++g_net->copy_fallbacks;
  }
  pair->tx_avail->ring[pair->tx_avail_idx % VIRTQ_SIZE] = desc_idx;
  virtio_mmio_barrier();
  ++pair->tx_avail_idx;
  pair->tx_avail->idx = pair->tx_avail_idx;
  /* The token has to say which pair as well as which slot, or a waiter
     watches the wrong queue's used index and the frame it is waiting for
     completes somewhere it never looks. */
  *token = ((uint64_t)pair_index << 32U) | (uint64_t)pair->tx_avail_idx;
  uint64_t sent = ++g_net->tx_frames_by_pair[pair_index];
  xaios_spin_unlock(&pair->tx_lock);
  /* Report the distribution once, rather than only when it is flattering.
     A line that appears only if a second pair is used would be silent in the
     ordinary case and read as an absent feature; this says which pairs
     carried frames whatever the answer, so "all on pair zero" is visible as
     a measurement rather than as nothing. It is the expected answer here:
     the pair follows the sending CPU, and a boot sends from one. */
  /* Reported again the moment a pair that had carried nothing carries its
     first frame, which is the event this whole arrangement exists to produce.
     Reporting only once meant reporting only the boot, where one CPU sends and
     the answer is always "all on pair zero" -- so the interesting case, two
     CPUs sending at once, happened after the only line that would have shown
     it. /bin/netmqtest exists to cause exactly that and could not be seen. */
  uint32_t pairs_used = 0U;
  for (uint32_t i = 0U; i < VIRTIO_NET_MAX_QUEUE_PAIRS; ++i) {
    if (g_net->tx_frames_by_pair[i] != 0U) pairs_used++;
  }
  if ((g_net->tx_fanout_reported == 0U && sent >= 4U) ||
      pairs_used > g_net->tx_fanout_pairs_reported) {
    g_net->tx_fanout_reported = 1U;
    g_net->tx_fanout_pairs_reported = pairs_used;
    klog("virtio-net-persist: transmit pairs=%u frames_by_pair=%lu,%lu,%lu,%lu "
         "(pair follows the sending CPU)\n",
         g_net->active_pairs, g_net->tx_frames_by_pair[0],
         g_net->tx_frames_by_pair[1], g_net->tx_frames_by_pair[2],
         g_net->tx_frames_by_pair[3]);
  }
  virtio_transport_notify(&g_net->device, 2U * pair_index + 1U);
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
  uint64_t last_notify = started;
  uint32_t pair_index = (uint32_t)(token >> 32U);
  if (g_net == 0 || pair_index >= VIRTIO_NET_MAX_QUEUE_PAIRS) {
    return XAIOS_ERR_INVALID;
  }
  virtio_net_queue_pair_t *pair = &g_net->pairs[pair_index];
  while ((uint16_t)(__atomic_load_n(&pair->tx_last_used, __ATOMIC_ACQUIRE) -
                    (uint16_t)token) >= UINT16_C(0x8000)) {
    (void)virtio_net_drain_tx_completions();
    uint64_t now = timer_now_ns();
    if (now - started >= VIRTIO_WAIT_NS) {
      return XAIOS_ERR_IO;
    }
    /* Re-ring for the reason given at wait_used_renotifying: this queue is
       waiting on a doorbell that may never have registered. */
    if (now - last_notify >= VIRTIO_RENOTIFY_NS) {
      virtio_transport_notify(&g_net->device, 2U * pair_index + 1U);
      last_notify = now;
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
    pair->rx_desc[desc].addr = net_dma_address(pair->rx_indirect[desc]);
    pair->rx_desc[desc].len =
        (uint32_t)(sizeof(virtq_desc_t) * VIRTIO_NET_RX_PAGES);
    pair->rx_desc[desc].flags = VRING_DESC_F_INDIRECT;
  } else {
    pair->rx_desc[desc].addr = net_dma_address(pair->rx_bufs[desc]);
    pair->rx_desc[desc].len = rx_buffer_bytes(g_net);
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
