/* Private interface shared by the four files of the virtio network driver.
 *
 * virtio_net.c keeps the driver state, feature-independent bring-up and the
 * receive path; virtio_net_tx.c holds the transmit path and completion
 * handling; virtio_net_setup.c holds pair/queue bring-up, feature negotiation
 * and RSS; and the power-on self-test -- ARP framing, the malformed-packet
 * parser check and the queue/transmit/reset walk -- lives in
 * virtio_net_selftest.c. All of them need the driver's layout and the
 * driver's interface macros, so both live here. The primary driver pointer
 * `g_net' does not: every file asks for its value through
 * virtio_net_primary_driver() and never names the variable itself.
 *
 * Following virtio_blk_internal.h, the driver layout is shared here while the
 * variable stays private to virtio_net.c, and the helpers that cross a file
 * boundary carry the module prefix.
 */
#ifndef XAIOS_DEV_VIRTIO_VIRTIO_NET_INTERNAL_H
#define XAIOS_DEV_VIRTIO_VIRTIO_NET_INTERNAL_H

#include <xaios/spinlock.h>
#include <xaios/status.h>
#include <xaios/types.h>
#include <xaios/virtio_net.h>
#include <xaios/virtio_transport.h>

#define VRING_DESC_F_WRITE UINT16_C(2)
#define VRING_DESC_F_NEXT UINT16_C(1)
#define VRING_DESC_F_INDIRECT UINT16_C(4)
/* VirtIO 1.0 devices use virtio_net_hdr_v1, including num_buffers, even when
 * mergeable receive buffers are not negotiated. */
#define VIRTIO_NET_HDR_SIZE 12U
#define VIRTIO_NET_PERSISTENT_RX_DESCS 8U
#define VIRTIO_NET_PERSISTENT_TX_DESCS 4U
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
/* The most pairs this driver will set up. The device may offer more; it
   is told how many are in use, so offering more is not an error. */
#define VIRTIO_NET_MAX_QUEUE_PAIRS 4U

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
#define VIRTIO_F_RING_INDIRECT_DESC (UINT32_C(1) << 28U)
#define VIRTIO_F_RING_EVENT_IDX (UINT32_C(1) << 29U)
#define VIRTIO_F_VERSION_1_HIGH UINT32_C(1)
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

/* Defined in virtio_net.c. The pointer's value is copied out; the variable
   `g_net' itself stays private to that file. */
virtio_net_driver_t *virtio_net_primary_driver(void);

/* Defined in virtio_net.c and shared with the self-test, which brings up the
   same rings and buffers the real receive/transmit paths use. */
void virtio_net_bytes_zero(void *buffer, uint64_t size);
xaios_status_t virtio_net_allocate_driver(void);

/* Defined in virtio_net_tx.c. The used rings of every pair, drained both by
   the transmit wait loops and by virtio_net_interrupt() in virtio_net.c, which
   is why it is not static any more. */
uint32_t virtio_net_drain_tx_completions(void);

/* Defined in virtio_net_setup.c and called from virtio_net.c's bring-up: the
   receive-buffer sizing the self-test and the bring-up both ask for, pair
   allocation, one pair's queue setup, the control-queue commands, and the DMA
   translation all three files use for their descriptors. */
uint32_t virtio_net_rx_buffer_bytes(const virtio_net_driver_t *driver);
xaios_status_t virtio_net_negotiate_features(virtio_net_driver_t *driver);
xaios_status_t virtio_net_allocate_pair(uint32_t index);
xaios_status_t virtio_net_bring_up_pair(uint32_t index);
xaios_status_t virtio_net_set_queue_pairs(uint16_t pairs);
xaios_status_t virtio_net_configure_rss(void);
uint64_t virtio_net_dma_address(const void *ptr);

#endif /* XAIOS_DEV_VIRTIO_VIRTIO_NET_INTERNAL_H */
