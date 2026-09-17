/* Private interface shared by the two halves of the virtio network driver.
 *
 * virtio_net.c keeps the driver state, bring-up and the transmit/receive
 * paths; the power-on self-test -- ARP framing, the malformed-packet parser
 * check and the queue/transmit/reset walk -- lives in
 * virtio_net_selftest.c. Both halves need the driver's layout, so the type
 * block lives here. The primary driver pointer `g_net' does not: the test
 * asks for its value through virtio_net_primary_driver() and never names the
 * variable itself.
 *
 * Following virtio_blk_internal.h, the driver layout is shared here while the
 * variable stays private to virtio_net.c, and the helpers the self-test needs
 * carry the module prefix because they now cross a file boundary.
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
uint32_t virtio_net_rx_buffer_bytes(const virtio_net_driver_t *driver);
xaios_status_t virtio_net_allocate_driver(void);
xaios_status_t virtio_net_negotiate_features(virtio_net_driver_t *driver);

#endif /* XAIOS_DEV_VIRTIO_VIRTIO_NET_INTERNAL_H */
