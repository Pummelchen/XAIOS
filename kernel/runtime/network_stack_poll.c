/*
 * The poll plane of the network stack, moved verbatim out of network_stack.c.
 * See network_stack_poll.h for the interface, what crossed the boundary and
 * why the receive dispatch moved with the loop.
 */

#include "network_stack_poll.h"

#include "network_stack_icmp.h"
#include "network_stack_listener.h"
#include "network_stack_tcp.h"
#include "network_stack_udp.h"
#include "network_stack_udp_rx.h"
#include "network_stack_v6.h"
#include "network_stack_wire.h"

#include <xaios/dns.h>
#include <xaios/icmpv6.h>
#include <xaios/ipv4.h>
#include <xaios/ipv6.h>
#include <xaios/klog.h>
#include <xaios/net_device.h>
#include <xaios/network_stack.h>
#include <xaios/ntp.h>
#include <xaios/operations.h>
#include <xaios/timer.h>

/* Twice the receive ring depth, so one poll can clear a full ring and the
   refills that land while it works. */
#define NETWORK_POLL_RX_BUDGET 16U

static uint64_t g_poll_tick_count;
/* Polls taken by the CPU carrying the network tick, counted apart from the
   ones a syscall makes. See network_tick_poll_count() in the header. */
static uint64_t g_tick_poll_count;
#define NETWORK_POLL_GAP_OUTAGE_NS UINT64_C(1000000000)
#define NETWORK_POLL_GAP_RECORD_LINES 32U

static uint64_t g_poll_last_ns;
static uint64_t g_poll_gap_max_ns;
static uint64_t g_poll_gap_outage_count;
static uint32_t g_poll_gap_record_lines;

void net_poll_reset_gap(void) {
  g_poll_last_ns = 0U;
  g_poll_gap_max_ns = 0U;
  g_poll_gap_outage_count = 0U;
  g_poll_gap_record_lines = 0U;
}

void net_poll_reset_ticks(void) {
  g_poll_tick_count = 0;
  g_tick_poll_count = 0;
}

static int network_reassemble_incoming(uint8_t *frame, uint32_t *frame_len,
                                       uint16_t ethertype) {
  uint64_t completed_len = *frame_len;
  xaios_status_t status;

  if (ethertype == NETWORK_ETHERTYPE_IPV4) {
    if (!ipv4_validate_incoming(frame, completed_len)) {
      return 0;
    }
    if (!ipv4_is_fragment(frame, completed_len)) {
      return 1;
    }
    status = ipv4_reassemble(frame, &completed_len);
  } else if (ethertype == NETWORK_ETHERTYPE_IPV6) {
    if (!ipv6_is_fragment_v6(frame, completed_len)) {
      return 1;
    }
    status = ipv6_reassemble_v6(frame, &completed_len);
  } else {
    return 0;
  }

  if (status != XAIOS_OK || completed_len > NETWORK_BUFFER_SIZE) {
    return 0;
  }
  *frame_len = (uint32_t)completed_len;
  return 1;
}

/* B-44: how long the stack went undriven, and saying so.

   Most of this poll comes from the network syscalls a process makes and from
   wait_events, and on a booted machine the process making those calls is sshd
   -- which the kernel starts as its last act, on the boot CPU, after switching
   preemption and the periodic timer off (kmain.c). One secondary CPU carries a
   network tick (OD-011) whose interrupt wakes it so its idle loop polls this
   stack, and that is what bounds the window a blocking call in that loop
   opens. Before the tick, a pause anywhere in the
   loop was a total network outage: nothing came off the receive ring, no ACK
   left, no retransmit fired, no flow expired.

   Whether the arrangement should change was a design question and is argued
   in wiki/Architecture.md; the timer was chosen and is landed. What was
   indefensible is that it was invisible:
   from inside, a stack that has not run for ten seconds is indistinguishable
   from a quiet network, and from outside it is indistinguishable from the
   machine having gone away. So the gap between consecutive polls is measured
   here, the longest one is kept, and a gap long enough to be an outage says
   so on the console.

   Measured only while a listener is registered. With no listener there is
   nothing the poll is late for, and a machine with no network service would
   otherwise report enormous gaps that mean nothing -- a metric that fires on
   an idle machine is a metric nobody reads. */
static uint32_t listeners_active_unlocked(void) {
  /* The registry counts its own live rows now; this keeps the name the
     poll-gap code below reads. */
  return network_listener_active_count();
}

static void network_note_poll_gap(uint64_t now_ns) {
  uint32_t listeners = listeners_active_unlocked();
  if (listeners == 0U) {
    /* Nothing is waiting on this stack. Forget when it last ran, so the first
       poll after a listener appears is not charged with the idle stretch
       before it. */
    g_poll_last_ns = 0U;
    return;
  }
  uint64_t previous = g_poll_last_ns;
  g_poll_last_ns = now_ns;
  if (previous == 0U || now_ns <= previous) return;
  uint64_t gap_ns = now_ns - previous;
  if (gap_ns >= NETWORK_POLL_GAP_OUTAGE_NS) {
    ++g_poll_gap_outage_count;
    /* Rate-limited for the reason every log on this path is: a machine that
       is stalling repeatedly must not turn its own diagnosis into the next
       stall. First, then every sixty-fourth. */
    if (g_poll_gap_outage_count == 1U ||
        (g_poll_gap_outage_count % 64U) == 0U) {
      klog("network: stack was not polled for ms=%lu outages=%lu listeners=%u "
           "(nothing drives this poll but the processes calling into it)\n",
           gap_ns / UINT64_C(1000000), g_poll_gap_outage_count, listeners);
    }
  }
  if (gap_ns <= g_poll_gap_max_ns) return;
  g_poll_gap_max_ns = gap_ns;
  /* Every new maximum, which is a short and self-limiting sequence: it climbs
     to the cadence of whatever is driving the poll and then stops. Capped all
     the same, so a machine that degrades steadily cannot fill the console. */
  if (g_poll_gap_record_lines >= NETWORK_POLL_GAP_RECORD_LINES) return;
  ++g_poll_gap_record_lines;
  klog("network: longest gap between polls us=%lu polls=%lu tick=%lu "
       "listeners=%u\n",
       g_poll_gap_max_ns / UINT64_C(1000), g_poll_tick_count,
       __atomic_load_n(&g_tick_poll_count, __ATOMIC_RELAXED), listeners);
}

uint64_t network_poll_gap_max_ns(void) { return g_poll_gap_max_ns; }
uint64_t network_poll_gap_outage_count(void) {
  return g_poll_gap_outage_count;
}

/* The network's own work, under the guard. `operations_tick()` is deliberately
   not here: it is the power path, it quiesces storage and it can stop the
   machine, and it belongs to whichever caller is in a position to do that. Both
   public entry points call it first -- `network_poll_tick` for a syscall and
   `network_poll_tick_from_carrier` for the tick CPU's idle loop, both in thread
   context -- so this function stays the network's work and nothing else. */
static void network_poll_tick_locked(void) {
  if (net_stack_persistent_ready() == 0U) {
    return;
  }
  uint8_t local_mac[6];
  net_stack_local_mac(local_mac);
  uint64_t now_ns = timer_now_ns();
  network_note_poll_gap(now_ns);
  ntp_tick(now_ns);
  net_v6_expire_public(now_ns);
  net_ping_expire(now_ns);
  uint8_t rx_buf[NETWORK_BUFFER_SIZE];
  ++g_poll_tick_count;
  /* Take everything the device has queued rather than one frame per call. The
     receive ring holds a handful of buffers, so draining only the head leaves
     a link with steady inbound traffic permanently full: the device then drops
     what arrives, and the guest answers nothing it was not already holding.
     An interrupt hides this by draining promptly; a platform with none, and a
     poll that runs only inside network syscalls, does not. Bounded so a busy
     link cannot hold the poll lock indefinitely. */
  for (uint32_t drained = 0U; drained < NETWORK_POLL_RX_BUDGET; ++drained) {
    uint32_t frame_len = network_device_rx_poll(rx_buf, sizeof(rx_buf));
    if (frame_len == 0) {
      break;
    }
    /* A frame is the only way an external peer makes a socket readable, so
       this is where a waiter is told its answer has expired. Before the
       frame is parsed rather than after: what it turns into -- data, a
       connection, a close -- all change readiness, and none of them are
       worth distinguishing here. */
    network_readiness_note();
  if (frame_len < 14U) {
    return;
  }
  uint16_t ethertype = net_wire_read_u16_be(rx_buf + 12U);
  if (ethertype == 0x0806U) {
    net_arp_handle_frame(rx_buf, frame_len, local_mac);
  } else if (ethertype == NETWORK_ETHERTYPE_IPV4) {
    if (frame_len < 34U ||
        !network_reassemble_incoming(rx_buf, &frame_len, ethertype)) {
      return;
    }
    uint8_t protocol = rx_buf[23U];
    if (protocol == NETWORK_IP_PROTO_UDP &&
        ntp_process_ipv4_frame(rx_buf, frame_len, now_ns) == XAIOS_OK) {
      return;
    }
    if (protocol == NETWORK_IP_PROTO_UDP &&
        dns_process_ipv4_frame(rx_buf, frame_len, now_ns) == XAIOS_OK) {
      dns_tick(now_ns);
      return;
    }
    if (protocol == XAIOS_IPV4_PROTO_ICMP) {
      if (net_icmp_handle_ipv4(rx_buf, frame_len, now_ns, local_mac) != 0) {
        return;
      }
    } else if (protocol == NETWORK_IP_PROTO_UDP) {
      network_stack_process_udp_frame(rx_buf, frame_len);
    } else if (protocol == NETWORK_IP_PROTO_TCP) {
      (void)network_stack_process_tcp_frame(rx_buf, frame_len);
    }
  } else if (ethertype == NETWORK_ETHERTYPE_IPV6) {
    net_stack_note_ipv6_rx();
    if (frame_len < 54U ||
        !network_reassemble_incoming(rx_buf, &frame_len, ethertype)) {
      return;
    }
    uint8_t next_header = rx_buf[20U]; /* byte 6 of IPv6 at offset 14 */
    if (next_header == XAIOS_IPV6_NEXT_ICMPV6) {
      net_icmpv6_handle_frame(rx_buf, frame_len, now_ns, local_mac);
    } else if (next_header == NETWORK_IP_PROTO_UDP) {
      network_stack_process_udp_frame_v6(rx_buf, frame_len);
    } else if (next_header == NETWORK_IP_PROTO_TCP) {
      (void)network_stack_process_tcp_frame_v6(rx_buf, frame_len);
    }
  }
  }
  /* Drain pending TCP transmissions (SYN-ACK, data, ACK, FIN) */
  dns_tick(now_ns);
  network_stack_retransmit_tcp_flows(now_ns);
  network_stack_expire_tcp_flows(now_ns);
  net_stack_tcp_drain_pending();
}

void network_poll_tick(void) {
  network_stack_lock();
  /* The power path runs here and only here, which is where a shutdown is
     asked for from. Called before the network's own work, as it always was. */
  operations_tick();
  network_poll_tick_locked();
  /* The resolver's transport tick belongs inside this guard, not after it. It
     mutates the pending query and drives the TCP flow carrying it, and dns.c's
     own comment says the resolver shares this guard rather than holding one of
     its own precisely because the poll calls back into it. Called after the
     unlock it raced every dns_resolve_address on another CPU -- and once a tick
     can arrive in interrupt context, which is what OD-011 adds, it would
     re-enter a resolver call already in progress on this one. */
  dns_transport_tick(timer_now_ns());
  network_stack_unlock();
}

void network_poll_tick_from_carrier(void) {
  /* Thread context, so this is the whole poll: `operations_tick()` is the
     power path and belongs here and on the syscall path, and nowhere else. */
  network_poll_tick();
  __atomic_add_fetch(&g_tick_poll_count, 1U, __ATOMIC_RELAXED);
}

uint64_t network_tick_poll_count(void) {
  return __atomic_load_n(&g_tick_poll_count, __ATOMIC_RELAXED);
}

uint64_t network_poll_tick_count(void) {
  return g_poll_tick_count;
}
