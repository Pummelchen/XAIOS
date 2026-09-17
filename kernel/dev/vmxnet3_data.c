/* VMXNET3 transmit and receive.
 *
 * The per-frame path: one frame out and waited on, one frame in if the device
 * has left one. Split out of vmxnet3.c so the descriptor handover protocol --
 * write the descriptor, set the generation bit last, ring the doorbell -- sits
 * in one file; the bodies are unchanged.
 */
#include <xaios/arch_cpu.h>
#include <xaios/klog.h>
#include <xaios/timer.h>
#include <xaios/vmxnet3.h>

#include "vmxnet3_internal.h"

/* Send one frame and wait for the device to say it took it.
 *
 * The generation bit is what hands a descriptor over: the driver writes the
 * whole descriptor first and sets the generation last, so a device reading
 * concurrently either sees a descriptor it does not own or a complete one,
 * never a half-written one. That ordering is the entire handover protocol,
 * which is why the write of word2 is separated from the rest rather than
 * being one assignment. */
xaios_status_t vmxnet3_tx(const uint8_t *data, uint64_t length) {
  if (vmxnet3_instance == 0 || vmxnet3_instance->active == 0U || data == 0 ||
      length == 0U || length > VMXNET3_FRAME_BYTES) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t slot = vmxnet3_instance->tx_produce;
  uint8_t *buffer = vmxnet3_instance->tx_buffers[slot];
  for (uint64_t i = 0U; i < length; ++i) buffer[i] = data[i];
  uint64_t physical = vmxnet3_dma_address(buffer, VMXNET3_FRAME_BYTES);
  if (physical == 0U) return XAIOS_ERR_IO;

  vmxnet3_tx_desc_t *desc = &vmxnet3_instance->tx_ring[slot];
  desc->address = physical;
  /* End of packet, and ask for a completion so the ring can be reclaimed. */
  desc->word3 = (UINT32_C(1) << VMXNET3_TXD_W3_EOP_SHIFT) |
                (UINT32_C(1) << VMXNET3_TXD_W3_CQ_SHIFT);
  xaios_cpu_io_barrier();
  desc->word2 = ((uint32_t)length & VMXNET3_TXD_W2_LEN_MASK) |
                (vmxnet3_instance->tx_gen << VMXNET3_TXD_W2_GEN_SHIFT);
  xaios_cpu_io_barrier();

  vmxnet3_instance->tx_produce = slot + 1U;
  if (vmxnet3_instance->tx_produce >= VMXNET3_RING_SIZE) {
    vmxnet3_instance->tx_produce = 0U;
    vmxnet3_instance->tx_gen ^= 1U; /* the ring wrapped, so the sense flips */
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
  vmxnet3_put32(vmxnet3_instance->tqd, VMXNET3_TQD_NUM_DEFERRED, 0U);
  xaios_cpu_io_barrier();
  vmxnet3_write_bar0(VMXNET3_REG_TXPROD, vmxnet3_instance->tx_produce);

  /* Wait for the completion carrying the driver's current sense. Bounded,
     because a device that never answers must not take the machine with it. */
  uint64_t started = timer_now_ns();
  for (;;) {
    vmxnet3_tx_comp_desc_t *comp =
        &vmxnet3_instance->tx_comp[vmxnet3_instance->tx_comp_consume];
    uint32_t generation = comp->word3 >> VMXNET3_TXCD_W3_GEN_SHIFT;
    if (generation == vmxnet3_instance->tx_comp_gen) {
      vmxnet3_instance->tx_comp_consume++;
      if (vmxnet3_instance->tx_comp_consume >= VMXNET3_RING_SIZE) {
        vmxnet3_instance->tx_comp_consume = 0U;
        vmxnet3_instance->tx_comp_gen ^= 1U;
      }
      return XAIOS_OK;
    }
    if (started != 0U && timer_now_ns() - started >= UINT64_C(100000000)) {
      /* Ask the device why, once.
         "transmit timed out" repeated 284 times says only that a completion
         never arrived, which was already the symptom. The device keeps the
         answer in registers and in the queue it was given: whether it stopped
         the queue and with what error, what it counted as sent, errored and
         discarded, and what is actually sitting in the completion slot the
         driver is watching. Printed once because a driver that floods the
         console during a failure destroys the log that would explain it. */
      if (vmxnet3_instance->timeout_reported == 0U) {
        vmxnet3_instance->timeout_reported = 1U;
        klog("vmxnet3: transmit timed out; device state follows\n");
        /* Ask before reading.
           The queue's status and statistics are marked in VMware's own
           definitions as "driver read after a GET command": the device does
           not keep them live in guest memory, it writes them when asked. The
           first version of this read them without asking and reported
           `queue_stopped=0 queue_error=0 ucast=0 error=0 discard=0`, which is
           what freshly zeroed memory says whatever the device thinks. Every
           one of those numbers was the calloc, not an answer. */
        (void)vmxnet3_command_result(VMXNET3_CMD_GET_QUEUE_STATUS);
        (void)vmxnet3_command_result(VMXNET3_CMD_GET_STATS);
        uint32_t conf_intr = vmxnet3_command_result(VMXNET3_CMD_GET_CONF_INTR);
        klog("vmxnet3:   device wants intr type=%u vectors=%u raw=0x%x; "
             "driver set num=%u mask_mode=%u ctrl=0x%x did=%x%x\n",
             conf_intr & 0x3U, (conf_intr >> 8U) & 0xffU, conf_intr,
             vmxnet3_instance->shared[VMXNET3_DS_INTR_NUM_INTRS],
             vmxnet3_instance->shared[VMXNET3_DS_INTR_MASK_MODE],
             vmxnet3_get32(vmxnet3_instance->shared, VMXNET3_DS_INTR_CTRL),
             vmxnet3_command_result(VMXNET3_CMD_GET_DID_HI),
             vmxnet3_command_result(VMXNET3_CMD_GET_DID_LO));
        klog("vmxnet3:   ecr=0x%x icr=0x%x queue_stopped=%u queue_error=0x%x\n",
             vmxnet3_read_bar1(VMXNET3_REG_ECR), vmxnet3_read_bar1(VMXNET3_REG_ICR),
             vmxnet3_get32(vmxnet3_instance->tqd, VMXNET3_TQD_STATUS_STOPPED) & 0xffU,
             vmxnet3_get32(vmxnet3_instance->tqd, VMXNET3_TQD_STATUS_ERROR));
        klog("vmxnet3:   device counted ucast=%lu bcast=%lu error=%lu "
             "discard=%lu\n",
             vmxnet3_get64(vmxnet3_instance->tqd, VMXNET3_TQD_STAT_UCAST_PKTS),
             vmxnet3_get64(vmxnet3_instance->tqd, VMXNET3_TQD_STAT_BCAST_PKTS),
             vmxnet3_get64(vmxnet3_instance->tqd, VMXNET3_TQD_STAT_ERROR_PKTS),
             vmxnet3_get64(vmxnet3_instance->tqd, VMXNET3_TQD_STAT_DISCARD_PKTS));
        klog("vmxnet3:   waiting slot=%u want_gen=%u comp=[0x%x 0x%x 0x%x "
             "0x%x] txprod=%u deferred=%u\n",
             vmxnet3_instance->tx_comp_consume, vmxnet3_instance->tx_comp_gen,
             comp->word0, comp->word1, comp->word2, comp->word3,
             vmxnet3_instance->tx_produce,
             vmxnet3_get32(vmxnet3_instance->tqd, VMXNET3_TQD_NUM_DEFERRED));
        klog("vmxnet3:   descriptor sent word2=0x%x word3=0x%x\n",
             vmxnet3_instance->tx_ring[slot].word2, vmxnet3_instance->tx_ring[slot].word3);
        {
          const uint8_t *rqd = vmxnet3_instance->queues + VMXNET3_TQD_BYTES;
          klog("vmxnet3:   control -- receive counted ucast=%lu bcast=%lu "
               "out_of_buf=%lu error=%lu (nonzero here means the transmit "
               "zeros above are real)\n",
               vmxnet3_get64(rqd, VMXNET3_RQD_STAT_UCAST_PKTS),
               vmxnet3_get64(rqd, VMXNET3_RQD_STAT_BCAST_PKTS),
               vmxnet3_get64(rqd, VMXNET3_RQD_STAT_OUT_OF_BUF),
               vmxnet3_get64(rqd, VMXNET3_RQD_STAT_ERROR_PKTS));
          /* Read back the sizes the device was given, from the bytes it
             parses. This is the field that was wrong: written as two
             thirty-two-bit words in the transmit block's positions, the
             device read zero-length receive rings and said so in the host's
             log rather than in the guest's. Printing them here means a
             recurrence names itself. */
          klog("vmxnet3:   receive queue conf rx1=%u rx2=%u comp=%u "
               "intr_idx=%u ddlen=%u stopped=%u error=0x%x\n",
               vmxnet3_get32(rqd, VMXNET3_RQD_RX_RING1_SIZE),
               vmxnet3_get32(rqd, VMXNET3_RQD_RX_RING2_SIZE),
               vmxnet3_get32(rqd, VMXNET3_RQD_COMP_RING_SIZE),
               vmxnet3_get32(rqd, VMXNET3_RQD_INTR_INDEX),
               vmxnet3_get32(rqd, VMXNET3_RQD_DRIVER_DATA_LEN),
               vmxnet3_get32(rqd, VMXNET3_RQD_STATUS_STOPPED) & 0xffU,
               vmxnet3_get32(rqd, VMXNET3_RQD_STATUS_ERROR));
        }
      }
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
  if (vmxnet3_instance == 0 || vmxnet3_instance->active == 0U || buffer == 0 ||
      capacity == 0U) {
    return 0U;
  }
  vmxnet3_rx_comp_desc_t *comp = &vmxnet3_instance->rx_comp[vmxnet3_instance->rx_comp_consume];
  uint32_t generation = comp->word3 >> VMXNET3_RXCD_W3_GEN_SHIFT;
  if (generation != vmxnet3_instance->rx_comp_gen) {
    /* Nothing to take. Two things happen on the way out, both of them about
       a receive path that stops after one frame -- which is where this driver
       stands: transmit works, the first frame arrives, and the second does
       not.
       The doorbell is re-rung occasionally, because a device that refused a
       frame for want of a buffer may not look again until it is told there is
       one, and this is the driver's only chance to say so once the ring is
       full. It does not clear the stall on QEMU's model, which is recorded
       rather than hidden.
       And the ring is described once, so a machine that stops says what it
       stopped holding rather than merely going quiet. */
    static uint32_t idle;
    static uint32_t described;
    if ((idle & 0xfffU) == 0U) {
      vmxnet3_write_bar0(VMXNET3_REG_RXPROD, vmxnet3_instance->rx_produce);
    }
    if (++idle == 20000U && described == 0U) {
      described = 1U;
      klog("vmxnet3: receive idle at comp slot=%u want_gen=%u "
           "words=[0x%x 0x%x 0x%x 0x%x] rxprod=%u rx_gen=%u "
           "ring[0].w2=0x%x ring[1].w2=0x%x frames=%u\n",
           vmxnet3_instance->rx_comp_consume, vmxnet3_instance->rx_comp_gen, comp->word0,
           comp->word1, comp->word2, comp->word3, vmxnet3_instance->rx_produce,
           vmxnet3_instance->rx_gen, vmxnet3_instance->rx_ring[0].word2,
           vmxnet3_instance->rx_ring[1].word2, vmxnet3_instance->rx_frames);
    }
    return 0U;
  }
  ++vmxnet3_instance->rx_frames;
  uint32_t index = comp->word0 & UINT32_C(0xfff);
  uint32_t length = comp->word2 & VMXNET3_RXCD_W2_LEN_MASK;
  uint32_t error = (comp->word2 >> VMXNET3_RXCD_W2_ERR_SHIFT) & 1U;
  uint32_t copied = 0U;
  if (error == 0U && length != 0U && index < VMXNET3_RING_SIZE) {
    uint32_t take = length;
    if ((uint64_t)take > capacity) take = (uint32_t)capacity;
    const uint8_t *source = vmxnet3_instance->rx_buffers[index];
    for (uint32_t i = 0U; i < take; ++i) buffer[i] = source[i];
    copied = take;
  }

  /* Hand a descriptor back whatever happened to the frame: a receive ring
     that keeps a slot after a bad packet shrinks by one every time.
   *
   * Refilled at the ring's own fill position rather than at the slot the
   * completion named, and the fill position is what the doorbell is then
   * told. Those are the same slot in steady state, but they are not the same
   * *number*: the producer index means "the next slot I will fill", and
   * writing the slot just completed rewinds it. After the first frame the
   * device was told the ring was empty again and delivered nothing more --
   * which looked like a receive path that worked once, and cost the DHCP
   * acknowledgement after an offer that had arrived perfectly.
   *
   * The generation flips when the fill position wraps, because a descriptor
   * on the second lap through the ring carries the opposite generation; a
   * ring refilled forever with the first lap's value stops being readable to
   * the device after one lap. */
  uint32_t slot = vmxnet3_instance->rx_produce;
  uint64_t physical =
      vmxnet3_dma_address(vmxnet3_instance->rx_buffers[slot], VMXNET3_FRAME_BYTES);
  if (physical != 0U) {
    vmxnet3_rx_desc_t *desc = &vmxnet3_instance->rx_ring[slot];
    desc->address = physical;
    desc->word3 = 0U;
    xaios_cpu_io_barrier();
    desc->word2 = (VMXNET3_FRAME_BYTES & VMXNET3_RXD_W2_LEN_MASK) |
                  (UINT32_C(0) << VMXNET3_RXD_W2_BTYPE_SHIFT) |
                  (vmxnet3_instance->rx_gen << VMXNET3_RXD_W2_GEN_SHIFT);
  }
  vmxnet3_instance->rx_produce++;
  if (vmxnet3_instance->rx_produce >= VMXNET3_RING_SIZE) {
    vmxnet3_instance->rx_produce = 0U;
    vmxnet3_instance->rx_gen ^= 1U;
  }
  vmxnet3_instance->rx_comp_consume++;
  if (vmxnet3_instance->rx_comp_consume >= VMXNET3_RX_COMP_SIZE) {
    vmxnet3_instance->rx_comp_consume = 0U;
    vmxnet3_instance->rx_comp_gen ^= 1U;
  }
  xaios_cpu_io_barrier();
  vmxnet3_write_bar0(VMXNET3_REG_RXPROD, vmxnet3_instance->rx_produce);
  return copied;
}
