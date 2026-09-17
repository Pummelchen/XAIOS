/* The Advanced Interrupt Architecture: IMSIC for messages, APLIC for wires.
 *
 * Why this file exists at all. Until it did, RISC-V was the only architecture
 * in this tree where every device queue was serviced by polling: NVMe said
 * "no message-signalled interrupts on this machine" and virtio said "MSI-X
 * unavailable", against four MSI-X queues on AArch64 and x86-64. That was
 * recorded as a property of the board, and it was half a property of the
 * board and half a property of this kernel. QEMU's `virt` machine does offer
 * message-signalled interrupts -- `-machine virt,aia=aplic-imsic` publishes
 * an APLIC and an IMSIC at both privilege levels -- but the only interrupt
 * controller this port had a driver for was the PLIC, which carries wires and
 * not messages. Selecting the capable board therefore produced a machine that
 * booted every self-test and reported that external interrupts would not be
 * delivered: correct degradation, and not a usable configuration.
 *
 * What the two controllers are, because the names do not say it.
 *
 * The IMSIC is the message receiver, and it is remarkably plain compared to a
 * GIC ITS. Each hart owns one 4 KiB page of physical address space per
 * privilege level; a device raises an interrupt on that hart by writing a
 * small integer -- the external interrupt identity -- as one 32-bit word to
 * that page. There is no device table, no interrupt translation table, no
 * command queue and no synchronisation command. The address is the hart and
 * the data is the interrupt. Everything the shared MSI-X code needs from an
 * interrupt controller -- "give me an address and a word that will reach this
 * CPU" -- is therefore two lines of arithmetic here, where on AArch64 it is
 * six hundred lines of ITS.
 *
 * The hart's own view of its interrupt file is not memory at all: enabling an
 * identity, setting a threshold and taking the top pending interrupt are done
 * through CSRs (siselect/sireg indirection, and stopei). So the file is
 * written from outside by devices and read from inside by its own hart, and
 * neither side can do the other's job. That is why enabling an identity has
 * to happen on the hart that will receive it, and why this file records a
 * target and lets a hart pick its own up when it comes online rather than
 * pretending one hart can program another's.
 *
 * The APLIC is the wire receiver. Devices that pull a line rather than write
 * a word -- the virtio-mmio transports, the UART, the RTC -- are attached to
 * it. In this configuration it is programmed in MSI delivery mode, which
 * means it does not deliver anything to a hart directly: it forwards each
 * asserted source onward as an MSI to an IMSIC. So it is not an alternative
 * to the IMSIC, it is a translator that puts wired devices onto the same
 * delivery path as PCI ones. The PCI host bridge on this board names the
 * supervisor IMSIC as its `msi-parent` directly and does not involve the
 * APLIC at all.
 *
 * What is discovered and what is refused.
 *
 * A board with AIA publishes two of everything: an IMSIC and an APLIC for
 * machine mode, which belong to firmware, and another pair for supervisor
 * mode, which belong to this kernel. They have identical compatible strings
 * and differ only in what they are wired to, so "the first riscv,imsics node"
 * is a coin toss -- and programming firmware's controller is accepted
 * silently by QEMU and delivers nothing here. The supervisor IMSIC is the one
 * whose `interrupts-extended` names cause 9, the supervisor external
 * interrupt; the machine one names cause 11. The supervisor APLIC is the one
 * whose `msi-parent` is that IMSIC. Both are found by what they are attached
 * to, never by address and never by position.
 *
 * An APLIC with no IMSIC beside it -- `aia=aplic`, where the APLIC delivers
 * directly to harts rather than by message -- is detected and refused rather
 * than half-driven. Direct mode is a third delivery path with its own claim
 * register and its own idle-hart semantics, and nothing in this tree needs it
 * today; saying so is better than a driver that appears to configure it.
 *
 * What is not proven here. The self-test below sends this hart a message
 * through its own interrupt file and requires it to arrive, which proves the
 * receiver, the enable bit, the threshold, the trap path and the dispatch
 * loop. It does not prove that a *device* can reach the file, because the
 * write comes from the CPU rather than over the bus. The claim that a device
 * MSI is delivered is made by the NVMe interrupt self-test, which submits a
 * read with the queue unmasked and requires the completion to arrive without
 * anybody polling for it.
 *
 * The driver is three files now. aia_init.c owns the device-tree discovery
 * above and the register programming that follows it; aia_selftest.c owns the
 * two delivery tests; this file owns the per-identity vector table and the
 * runtime that allocates identities, attaches handlers, routes wired sources
 * and drains the interrupt file from the trap handler. The split is a size
 * split: the register map, the ordering of every write and the text of every
 * diagnostic are unchanged, and the geometry this file needs is asked of
 * aia_init.c through aia_internal.h rather than read from its state.
 */
#include <xaios/riscv64_aia.h>
#include <xaios/status.h>

#include <stdint.h>

#include "aia_internal.h"

typedef struct aia_vector {
  riscv64_aia_handler_t handler;
  void *context;
  /* Which hart's file this identity was enabled on, and the wired source it
     stands for -- zero when it is a message from a device rather than a
     translated wire. A level-triggered wire has to be re-armed at the APLIC
     after its handler runs, and the identity is all the dispatch loop knows
     by then. */
  uint32_t hart;
  uint32_t wired_source;
  uint8_t enabled;
  uint8_t pending_enable;
  /* Whether a message for this identity has ever actually arrived.
   *
   * The distinction this records is the one the whole change turns on:
   * "a handler was registered" is a statement about this kernel, and "an
   * interrupt was delivered" is a statement about the machine. Every driver
   * in this tree can also poll, so a board on which no message ever arrives
   * boots and passes exactly as one where they all do. The first arrival per
   * identity is announced once, which is what makes the difference visible in
   * a log instead of only in a debugger. */
  uint8_t announced;
} aia_vector_t;

/* The runtime half. The controller geometry discovery found lives in
   aia_init.c; what is here is the per-identity table and the counters the
   trap path updates. */
static uint32_t g_next_identity = 1U;
static uint64_t g_delivered;
static uint64_t g_spurious;
static aia_vector_t g_vectors[AIA_MAX_IDENTITIES];

uint64_t riscv64_aia_delivered(void) { return g_delivered; }
uint64_t riscv64_aia_spurious(void) { return g_spurious; }

/* Anything already promised to this hart while it was still asleep. A driver
   that configured a queue before the secondary came online recorded its
   identity here rather than writing another hart's CSRs, which is not
   something one hart can do. The loop lives here because the table it walks
   does, and riscv64_aia_init_hart() calls it from aia_init.c. */
void riscv64_aia_enable_pending_for_hart(uint32_t hart) {
  for (uint32_t identity = 1U; identity < riscv64_aia_identity_count();
       ++identity) {
    aia_vector_t *vector = &g_vectors[identity];
    if (vector->hart != hart) continue;
    if (vector->pending_enable == 0U && vector->enabled == 0U) continue;
    riscv64_aia_imsic_set_enable(identity, 1);
    vector->pending_enable = 0U;
    vector->enabled = 1U;
  }
}

xaios_status_t riscv64_aia_allocate(uint32_t *identifier) {
  if (identifier == 0) return XAIOS_ERR_INVALID;
  if (riscv64_aia_present() == 0) return XAIOS_ERR_UNSUPPORTED;
  /* Handed out once and never reissued. A free-slot search would reissue an
     identity whose owner polls and therefore never registered a handler, and
     two devices sharing one identity deliver each other's interrupts -- the
     same reasoning the GIC's LPI allocator carries, and the same failure. */
  while (g_next_identity < riscv64_aia_identity_count()) {
    uint32_t candidate = g_next_identity++;
    if (g_vectors[candidate].handler == 0 &&
        g_vectors[candidate].enabled == 0U &&
        g_vectors[candidate].pending_enable == 0U) {
      *identifier = candidate;
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NO_MEMORY;
}

xaios_status_t riscv64_aia_register(uint32_t identifier, uint32_t cpu_id,
                                    riscv64_aia_handler_t handler,
                                    void *context) {
  if (riscv64_aia_present() == 0) return XAIOS_ERR_UNSUPPORTED;
  if (identifier == 0U || identifier >= riscv64_aia_identity_count() ||
      handler == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t hart = riscv64_hart_of_cpu(cpu_id);
  if (!riscv64_aia_file_known(hart)) {
    return XAIOS_ERR_INVALID;
  }
  aia_vector_t *vector = &g_vectors[identifier];
  if (vector->handler != 0 && vector->handler != handler) {
    return XAIOS_ERR_BUSY;
  }
  vector->handler = handler;
  vector->context = context;
  vector->hart = hart;
  /* Enabling is a CSR write, and a CSR belongs to the hart executing it. A
     target that is not this hart is recorded and enabled by that hart when it
     brings its own file up, rather than pretended. */
  if (hart == riscv64_hart_of_cpu(smp_cpu_id())) {
    riscv64_aia_imsic_set_enable(identifier, 1);
    vector->enabled = 1U;
    vector->pending_enable = 0U;
  } else {
    vector->pending_enable = 1U;
  }
  return XAIOS_OK;
}

xaios_status_t riscv64_aia_unregister(uint32_t identifier) {
  if (riscv64_aia_present() == 0) return XAIOS_ERR_UNSUPPORTED;
  if (identifier == 0U || identifier >= riscv64_aia_identity_count()) {
    return XAIOS_ERR_INVALID;
  }
  aia_vector_t *vector = &g_vectors[identifier];
  if (vector->enabled != 0U &&
      vector->hart == riscv64_hart_of_cpu(smp_cpu_id())) {
    riscv64_aia_imsic_set_enable(identifier, 0);
    vector->enabled = 0U;
  }
  vector->pending_enable = 0U;
  vector->handler = 0;
  vector->context = 0;
  if (vector->wired_source != 0U) {
    (void)riscv64_aia_disable_wired(vector->wired_source);
    vector->wired_source = 0U;
  }
  return XAIOS_OK;
}

xaios_status_t riscv64_aia_message_target(uint32_t identifier, uint32_t cpu_id,
                                          uint64_t *address, uint32_t *data) {
  if (address == 0 || data == 0) return XAIOS_ERR_INVALID;
  *address = 0U;
  *data = 0U;
  if (riscv64_aia_present() == 0) return XAIOS_ERR_UNSUPPORTED;
  if (identifier == 0U || identifier >= riscv64_aia_identity_count()) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t file = 0U;
  if (!riscv64_aia_file_of_cpu(cpu_id, &file)) return XAIOS_ERR_INVALID;
  /* This is the whole of MSI addressing on this architecture: the page is the
     hart and the word is the interrupt. No translation table, no device id,
     no event id, and nothing to synchronise afterwards. */
  *address = riscv64_aia_message_address(file);
  *data = identifier;
  return XAIOS_OK;
}

xaios_status_t riscv64_aia_route_wired(uint32_t source, uint32_t identifier,
                                       uint32_t cpu_id) {
  if (riscv64_aia_wired_present() == 0) return XAIOS_ERR_UNSUPPORTED;
  if (source == 0U || source > riscv64_aia_aplic_sources() ||
      identifier == 0U || identifier >= riscv64_aia_identity_count()) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t file = 0U;
  if (!riscv64_aia_file_of_cpu(cpu_id, &file)) return XAIOS_ERR_INVALID;
  /* Level-high, because that is what every wired device on this board's tree
     declares (`interrupts = <n 4>`). In message delivery mode a level source
     sends one message when its line rises and is re-armed after the handler
     runs; the dispatch loop below does that re-arming, which is the part a
     driver written against direct delivery does not have to think about. */
  *riscv64_aia_aplic_register(APLIC_SOURCECFG + (source - 1U) * 4U) =
      APLIC_SOURCECFG_LEVEL_HIGH;
  /* target: hart index in the top bits, identity in the low ones. The hart
     index the APLIC uses to compute an IMSIC address is the interrupt file
     index, not the hart id -- the same number the message target above
     uses. */
  *riscv64_aia_aplic_register(APLIC_TARGET + (source - 1U) * 4U) =
      (file << 18U) | (identifier & UINT32_C(0x7ff));
  riscv64_aia_device_barrier();
  uint32_t sourcecfg =
      *riscv64_aia_aplic_register(APLIC_SOURCECFG + (source - 1U) * 4U);
  if (sourcecfg != APLIC_SOURCECFG_LEVEL_HIGH) {
    /* A source the controller refused to configure is one that will never
       fire, and a driver told "registered" would wait for it forever. */
    return XAIOS_ERR_IO;
  }
  g_vectors[identifier].wired_source = source;
  *riscv64_aia_aplic_register(APLIC_SETIENUM) = source;
  riscv64_aia_device_barrier();
  return XAIOS_OK;
}

xaios_status_t riscv64_aia_disable_wired(uint32_t source) {
  if (riscv64_aia_wired_present() == 0) return XAIOS_ERR_UNSUPPORTED;
  if (source == 0U || source > riscv64_aia_aplic_sources()) {
    return XAIOS_ERR_INVALID;
  }
  *riscv64_aia_aplic_register(APLIC_CLRIENUM) = source;
  *riscv64_aia_aplic_register(APLIC_SOURCECFG + (source - 1U) * 4U) =
      APLIC_SOURCECFG_INACTIVE;
  riscv64_aia_device_barrier();
  return XAIOS_OK;
}

uint32_t riscv64_aia_dispatch(void) {
  if (riscv64_aia_present() == 0) return 0U;
  uint32_t handled = 0U;
  /* Bounded, because the loop can re-arm what it just took. A level-triggered
     wire whose device is still asserting is re-sent by the APLIC the moment
     it is re-armed below, so an unbounded drain would never return from the
     trap on a device whose handler did not quieten it. Leaving the rest
     pending and returning costs one more trap and keeps the hart able to do
     anything else at all. */
  while (handled < 64U) {
    uint64_t top = 0U;
    /* Read and claim in one instruction. stopei reports the highest-priority
       pending-and-enabled identity in the top half of the value, and writing
       to it clears that identity's pending bit; a plain read would loop on
       the same interrupt forever. */
    __asm__ volatile("csrrw %0, 0x15c, zero" : "=r"(top) : : "memory");
    if (top == 0U) break;
    uint32_t identity = (uint32_t)(top >> 16U);
    ++handled;
    ++g_delivered;
    if (identity < riscv64_aia_identity_count() &&
        g_vectors[identity].handler != 0) {
      g_vectors[identity].handler(identity, g_vectors[identity].context);
      if (g_vectors[identity].announced == 0U) {
        /* Safe from a trap: klog takes its lock with a try and drops the line
           rather than waiting, so it cannot deadlock against the code this
           interrupted. The same trylock means a line can be dropped under
           contention -- which is true of every line this kernel logs, self-
           test results included -- so the counters below, not this message,
           are the authority on how many arrived. */
        klog("aia: identity=%u first message delivered hart=%u wired_source="
             "%u\n", identity, g_vectors[identity].hart,
             g_vectors[identity].wired_source);
        g_vectors[identity].announced = 1U;
      }
      uint32_t source = g_vectors[identity].wired_source;
      if (source != 0U && riscv64_aia_wired_present() != 0) {
        /* A level-triggered wire re-arms itself only if it is still low when
           this is written; if the device is still asserting, the APLIC sends
           another message straight away, which is what a level interrupt
           means. Without this a wired device fires exactly once per boot --
           and the boot still looks healthy, because everything in this tree
           can also poll. */
        *riscv64_aia_aplic_register(APLIC_SETIPNUM_LE) = source;
      }
    } else {
      /* An identity nobody claimed. Counted rather than ignored: this is what
         a target register programmed for the wrong hart or the wrong identity
         produces, and a silent count of zero is the only way to tell that
         apart from a device that never fired. */
      ++g_spurious;
    }
  }
  return handled;
}
