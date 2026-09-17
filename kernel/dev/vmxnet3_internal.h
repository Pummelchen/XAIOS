/* Private declarations shared by the VMXNET3 driver's translation units.
 *
 * The register and descriptor offsets, the driver-shared memory layout and
 * the one driver instance live here because the probe path, the ring and
 * activation path, and the per-frame transmit/receive path are now three
 * files and must agree on every one of those offsets byte for byte. Nothing
 * in this header is part of the driver's public surface: it is included only
 * by kernel/dev/vmxnet3*.c, and the public prototypes stay in
 * <xaios/vmxnet3.h>.
 *
 * The low-level accessors below cross those files, so they are defined once,
 * in vmxnet3.c, and carry the module prefix. The definitions themselves are
 * unchanged; only the names gained the prefix, which is what keeps two
 * generic names like `put32` from colliding with another driver at link time
 * now that they are no longer file-local.
 */
#ifndef XAIOS_KERNEL_DEV_VMXNET3_INTERNAL_H
#define XAIOS_KERNEL_DEV_VMXNET3_INTERNAL_H

#include <xaios/status.h>
#include <xaios/types.h>

#define VMXNET3_VENDOR_VMWARE UINT16_C(0x15ad)
#define VMXNET3_DEVICE_ID UINT16_C(0x07b0)

/* Two windows, mapped where nothing else is. E1000E takes 0x320000000 and
   0x6000 bytes; these sit above it with a gap rather than immediately after,
   so a mistake in either mapping faults instead of landing in the other. */
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
#define VMXNET3_REG_ICR UINT32_C(0x038) /* interrupt cause */
#define VMXNET3_REG_ECR UINT32_C(0x040) /* event cause: what the device objected to */
#define VMXNET3_REG_MACH UINT32_C(0x030)

/* Commands. The device distinguishes those that set something from those that
   ask, by the constant they start from. */
#define VMXNET3_CMD_FIRST_GET UINT32_C(0xf00d0000)
#define VMXNET3_CMD_GET_QUEUE_STATUS (VMXNET3_CMD_FIRST_GET + 0U)
#define VMXNET3_CMD_GET_STATS (VMXNET3_CMD_FIRST_GET + 1U)
#define VMXNET3_CMD_GET_LINK (VMXNET3_CMD_FIRST_GET + 2U)
#define VMXNET3_CMD_GET_PERM_MAC_LO (VMXNET3_CMD_FIRST_GET + 3U)
#define VMXNET3_CMD_GET_PERM_MAC_HI (VMXNET3_CMD_FIRST_GET + 4U)
#define VMXNET3_CMD_GET_DID_LO (VMXNET3_CMD_FIRST_GET + 5U)
#define VMXNET3_CMD_GET_DID_HI (VMXNET3_CMD_FIRST_GET + 6U)
#define VMXNET3_CMD_GET_DEV_EXTRA_INFO (VMXNET3_CMD_FIRST_GET + 7U)
/* What interrupt arrangement the device would like. The low two bits are the
   type it expects -- 0 auto, 1 INTx, 2 MSI, 3 MSI-X -- and bits 8..15 how
   many vectors. Never asked before, and it is the one thing the driver
   configures without ever checking what the device wanted: transmit
   completions are DMA writes and should not depend on interrupts, which is an
   argument rather than a measurement until this is read. */
#define VMXNET3_CMD_GET_CONF_INTR (VMXNET3_CMD_FIRST_GET + 8U)

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
/* The device writes these; the driver only reads them. `stopped` and `error`
   are how a queue says it refused the work rather than merely not finishing
   it, and the counters separate "sent nothing" from "sent and threw away". */
#define VMXNET3_TQD_STATUS_STOPPED 0x050U
#define VMXNET3_TQD_STATUS_ERROR 0x054U
#define VMXNET3_TQD_STAT_UCAST_PKTS 0x068U
#define VMXNET3_TQD_STAT_BCAST_PKTS 0x088U
#define VMXNET3_TQD_STAT_ERROR_PKTS 0x098U
#define VMXNET3_TQD_STAT_DISCARD_PKTS 0x0a0U
/* The same fields in the receive queue, at the same offsets, because the two
   configuration blocks are the same size. Used as a control on the transmit
   reading above: if receive is demonstrably working and its counters are
   zero, the offsets are wrong and the transmit zeros mean nothing. */
#define VMXNET3_RQD_STATUS_STOPPED 0x050U
#define VMXNET3_RQD_STATUS_ERROR 0x054U
#define VMXNET3_RQD_STAT_UCAST_PKTS 0x068U
#define VMXNET3_RQD_STAT_BCAST_PKTS 0x088U
#define VMXNET3_RQD_STAT_OUT_OF_BUF 0x098U
#define VMXNET3_RQD_STAT_ERROR_PKTS 0x0a0U

/* The receive queue configuration, from VMware's published definitions.
 *
 * It has the same shape as the transmit one and the same size, which is not a
 * coincidence to be suspicious of: `Vmxnet3_RxQueueConf` carries an eight-byte
 * `rxDataRingBasePA` where the transmit block carries `reserved`, and both
 * state their ring sizes as 32-bit words. These offsets were once "corrected"
 * to a sixteen-bit pair on a misremembering of the structure, which is worth
 * recording because the correction looked exactly like a finding: it produced
 * a plausible story about the device being told its rings held nothing, and
 * the device is in fact told nothing of the sort. Checked against the header
 * rather than against memory, twice. */
#define VMXNET3_RQD_RX_RING1_PA 0x010U
#define VMXNET3_RQD_RX_RING2_PA 0x018U
#define VMXNET3_RQD_COMP_RING_PA 0x020U
#define VMXNET3_RQD_DRIVER_DATA_PA 0x028U
#define VMXNET3_RQD_DATA_RING_PA 0x030U
#define VMXNET3_RQD_RX_RING1_SIZE 0x038U
#define VMXNET3_RQD_RX_RING2_SIZE 0x03cU
#define VMXNET3_RQD_COMP_RING_SIZE 0x040U
#define VMXNET3_RQD_DRIVER_DATA_LEN 0x044U
#define VMXNET3_RQD_INTR_INDEX 0x048U

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
  /* The body ring's own buffers.
   *
   * VMXNET3 receives into two rings: ring1 carries the head of a packet and
   * ring2 its body. Both were allocated and only ring1 was ever filled, while
   * the doorbell told the device thirty-one body descriptors were ready -- so
   * the device was pointed at thirty-one descriptors of zeroes with the
   * generation bit clear. The host said so, in VMware's own log, once per
   * attempt: "VMXNET3 hosted: Cannot retrieve the buffer descriptors per rx
   * packet." Nothing in the guest could see that; it is the first thing this
   * device has said about itself from the outside. */
  uint8_t *rx_body_buffers[VMXNET3_RING_SIZE];
  uint32_t tx_produce;
  uint32_t tx_gen;
  uint32_t tx_comp_consume;
  uint32_t tx_comp_gen;
  uint32_t timeout_reported;
  uint32_t rx_produce;
  uint32_t rx_gen;
  uint32_t rx_comp_consume;
  uint32_t rx_comp_gen;
  /* How many frames this device has handed over. Kept because "one" is a
     different fault from "none", and the two were indistinguishable. */
  uint32_t rx_frames;
} vmxnet3_driver_t;

/* The single driver instance, defined in vmxnet3.c. */
extern vmxnet3_driver_t *vmxnet3_instance;

/* Shared accessors: BAR windows, the write-then-read command register, and
   the little-endian field codecs the device-shared structures are built
   with. Defined once in vmxnet3.c. */
void vmxnet3_put32(uint8_t *base, uint32_t offset, uint32_t value);
void vmxnet3_put64(uint8_t *base, uint32_t offset, uint64_t value);
void vmxnet3_put16(uint8_t *base, uint32_t offset, uint16_t value);
uint32_t vmxnet3_get32(const uint8_t *base, uint32_t offset);
uint64_t vmxnet3_get64(const uint8_t *base, uint32_t offset);
uint32_t vmxnet3_read_bar0(uint32_t offset);
void vmxnet3_write_bar0(uint32_t offset, uint32_t value);
uint32_t vmxnet3_read_bar1(uint32_t offset);
void vmxnet3_write_bar1(uint32_t offset, uint32_t value);
uint32_t vmxnet3_command_result(uint32_t command);
/* Physical address of a buffer, or zero when it is not one contiguous,
   present, mapped run. */
uint64_t vmxnet3_dma_address(const void *pointer, uint64_t length);

#endif /* XAIOS_KERNEL_DEV_VMXNET3_INTERNAL_H */
