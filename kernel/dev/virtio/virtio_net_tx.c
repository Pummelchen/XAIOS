/* Virtio network driver: transmit path and completion handling.
 *
 * Split out of virtio_net.c. Everything here submits a frame to the device or
 * retires a completed one: descriptor construction (direct or indirect), the
 * copy fallback, the per-CPU pair choice, the token that names both a pair and
 * a ring slot, and the used-ring drain that the interrupt handler in
 * virtio_net.c calls through virtio_net_drain_tx_completions(). The driver
 * pointer is read into a caller-owned local through
 * virtio_net_primary_driver(), as virtio_net_selftest.c already does, so the
 * variable itself stays private to virtio_net.c.
 */
#include <xaios/arch_cpu.h>
#include <xaios/ipv4.h>
#include <xaios/ipv6.h>
#include <xaios/klog.h>
#include <xaios/smp.h>
#include <xaios/timer.h>
#include <xaios/vmm.h>

#include "virtio_net_internal.h"

static uint16_t read_be16(const uint8_t *value) {
  return (uint16_t)(((uint16_t)value[0] << 8U) | value[1]);
}

static uint32_t drain_tx_completions_locked(virtio_net_queue_pair_t *pair) {
  virtio_net_driver_t *g_net = virtio_net_primary_driver();
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
  virtio_net_driver_t *g_net = virtio_net_primary_driver();
  if (g_net == 0 || g_net->active_pairs <= 1U) return 0U;
  return smp_cpu_id() % g_net->active_pairs;
}

/* Every pair, not just the one this CPU sends on: completions belong to
   whichever queue carried the frame, and a pair nobody drains stops
   accepting work once its ring fills. trylock so a busy pair is skipped
   rather than waited on -- this runs from the interrupt path. */
uint32_t virtio_net_drain_tx_completions(void) {
  virtio_net_driver_t *g_net = virtio_net_primary_driver();
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

static xaios_status_t tx_submit_vectors(const xaios_net_iovec_t *vectors,
                                        uint32_t vector_count,
                                        uint32_t allow_direct,
                                        uint64_t *token) {
  virtio_net_driver_t *g_net = virtio_net_primary_driver();
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
  virtio_net_bytes_zero(pair->tx_bufs[desc_idx], VIRTIO_NET_HDR_SIZE);

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
    indirect[0].addr = virtio_net_dma_address(pair->tx_bufs[desc_idx]);
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
    pair->tx_desc[desc_idx].addr = virtio_net_dma_address(indirect);
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
    pair->tx_desc[desc_idx].addr = virtio_net_dma_address(pair->tx_bufs[desc_idx]);
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
  virtio_net_driver_t *g_net = virtio_net_primary_driver();
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
