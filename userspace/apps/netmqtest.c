/* Two CPUs transmitting at once, which is the case multiqueue exists for.
 *
 * E4 built per-queue-pair transmit and chose the pair by `smp_cpu_id() %
 * active_pairs` rather than by a shared cursor, on the reasoning that the
 * point of a second transmit queue is not that frames alternate but that two
 * CPUs sending at the same moment do not queue behind one lock. The driver
 * then reported `transmit pairs=4 frames_by_pair=4,0,0,0` -- every frame on
 * pair zero -- and that was the correct answer, because a boot sends from one
 * CPU and a per-CPU selector has one pair to choose from. The row said so
 * plainly and named what was missing: "What this does not yet show is two CPUs
 * transmitting concurrently ... demonstrating it needs a multi-threaded sender
 * rather than more driver work."
 *
 * This is that sender. It exists to make the distribution non-trivial, so the
 * selector is exercised rather than merely present.
 *
 * The threads are pinned, not merely created. `xaios_thread_create` takes a
 * preferred CPU and the placement code prefers an idle worker, but "prefer" is
 * not "guarantee": B-02 was two user threads landing on the same worker CPU,
 * where the second waits behind the first and the wait is invisible to the
 * caller. A test that let placement choose could produce frames_by_pair with
 * one non-zero entry and no way to tell whether the selector is broken or the
 * threads simply shared a CPU. Naming the CPU removes that ambiguity: if the
 * frames still land on one pair, the selector is wrong.
 *
 * What this cannot show on every machine: SLIRP is single-queue, so a driver
 * servicing four pairs is indistinguishable from one servicing one, and macOS
 * has no tap device. The distribution is only meaningful against
 * `XAIOS_QEMU_X86_TAP` with `XAIOS_QEMU_X86_TAP_QUEUES` above one. On a
 * single-queue link this still runs and still reports, and every frame
 * correctly lands on pair zero -- one pair is all there is. The gate reads the
 * driver's own line rather than this program's opinion, so it can tell those
 * cases apart.
 */
#include <xaios_user.h>

#define SENDER_COUNT 2U
#define FRAMES_PER_SENDER 8U
#define SENDER_STACK_BYTES 16384U

static unsigned char g_stacks[SENDER_COUNT][SENDER_STACK_BYTES]
    __attribute__((aligned(16)));

typedef struct sender_state {
  u64 cpu;
  u64 sent;
  u64 failed;
} sender_state_t;

static sender_state_t g_senders[SENDER_COUNT];

/* Send, and count what happened rather than stopping at the first refusal.
 *
 * A sender that returns on its first error makes the whole test depend on
 * whichever thread was unlucky, and reports a distribution that describes the
 * error rather than the selector. Both figures are reported.
 */
static u64 sender_main(void *argument) {
  sender_state_t *state = (sender_state_t *)argument;
  const char payload[] = "xaios-multiqueue-transmit";

  /* A real datagram to a real address, because the obvious call does not
     transmit.
     
     The first version of this used xaios_net_udp_echo, which reads like a UDP
     send and is not one: network_stack_app_udp_echo builds a frame and hands
     it to network_stack_process_udp_frame, so the packet is processed inside
     the stack and never reaches the device. xaios_net_external_session with
     the UDP protocol calls the same function. Either would have produced a
     test that ran two threads, reported sixteen frames sent, and left
     frames_by_pair untouched -- passing while proving nothing about the thing
     it exists to prove. It did exactly that on a four-queue tap before this
     was noticed.
     
     sendto on a bound socket goes through the stack to network_device_tx,
     which is the path with the per-CPU pair selector in it. The destination
     is the gateway of the emulated network: it does not have to answer, and
     nothing here waits for a reply -- the frame leaving is the whole event. */
  u64 handle = 0U;
  if (xaios_net_bind_udp(24000U + state->cpu, &handle) < 0) {
    state->failed += FRAMES_PER_SENDER;
    return 0U;
  }
  xaios_ip_addr_user_t destination;
  destination.family = 4U;
  for (u32 b = 0U; b < 16U; ++b) destination.addr[b] = 0U;
  /* 10.0.2.2 under SLIRP, and the tap's own address on a tap network: either
     way a host on the guest's link, so the frame is transmitted rather than
     dropped as unroutable. */
  destination.addr[0] = 10U;
  destination.addr[1] = 0U;
  destination.addr[2] = 2U;
  destination.addr[3] = 2U;

  for (u32 i = 0U; i < FRAMES_PER_SENDER; ++i) {
    u64 written = 0U;
    if (xaios_net_sendto(handle, payload, xaios_strlen(payload), &written,
                         &destination) < 0) {
      state->failed++;
    } else {
      state->sent++;
    }
  }
  (void)xaios_net_close(handle);
  return state->sent;
}

int main(void) {
  xaios_log("/bin/netmqtest: two pinned senders transmitting concurrently\n");

  u64 ids[SENDER_COUNT];
  u32 started = 0U;
  for (u32 i = 0U; i < SENDER_COUNT; ++i) {
    g_senders[i].cpu = (u64)(i + 1U);
    g_senders[i].sent = 0U;
    g_senders[i].failed = 0U;
    /* CPU 0 is deliberately not used. The process itself runs there, so a
       thread asked for CPU 0 competes with its own parent and the placement
       is decided by scheduling rather than by the request. */
    if (xaios_thread_create(sender_main, &g_senders[i], g_stacks[i],
                            SENDER_STACK_BYTES, g_senders[i].cpu,
                            &ids[i]) < 0) {
      xaios_log_u64("/bin/netmqtest: thread create failed cpu=",
                    g_senders[i].cpu, "\n");
      continue;
    }
    started++;
  }

  u64 joined = 0U;
  for (u32 i = 0U; i < started; ++i) {
    u64 result = 0U;
    if (xaios_thread_join(ids[i], 30000000000ULL, &result) >= 0) {
      joined++;
    }
  }

  u64 sent = 0U;
  u64 failed = 0U;
  for (u32 i = 0U; i < SENDER_COUNT; ++i) {
    sent += g_senders[i].sent;
    failed += g_senders[i].failed;
  }

  /* Reported whatever it says. A line that appears only when the numbers
     flatter is silent in the ordinary case and reads as an absent feature --
     the same reasoning the driver's own frames_by_pair line was given. */
  xaios_log_u64("/bin/netmqtest: senders=", (u64)started, "");
  xaios_log_u64(" joined=", joined, "");
  xaios_log_u64(" frames_sent=", sent, "");
  xaios_log_u64(" frames_failed=", failed, "\n");

  if (started != SENDER_COUNT || joined != SENDER_COUNT) {
    xaios_log("/bin/netmqtest: FAILED not every sender ran to completion\n");
    return 1;
  }
  if (sent == 0U) {
    xaios_log("/bin/netmqtest: FAILED no frame was transmitted at all\n");
    return 1;
  }
  xaios_log("/bin/netmqtest: concurrent transmit complete\n");
  return 0;
}
