/* The interrupt-controller interface, backed by whichever controller this
 * board turned out to have.
 *
 * These are named gic_* because the shared kernel calls them that, and that
 * naming is itself worth recording: `gic` is AArch64's controller, and a
 * shared header naming one architecture's hardware is the identity-versus-
 * capability line being crossed inside the very codebase that has a rule
 * against it. Renaming the interface across every caller is a larger change
 * than this port, so the names stay and this comment carries the finding.
 * What the interface actually means is "register, route and dispatch an
 * interrupt", which a PLIC does perfectly well and an APLIC/IMSIC pair does
 * with messages as well as wires.
 *
 * Two backends, chosen at run time from what the device tree published, never
 * at build time. The PLIC is what QEMU's default `virt` board has and what
 * every existing gate on this architecture runs on; the AIA pair is what
 * `virt,aia=aplic-imsic` has. exception_init picks one and this file asks
 * which it picked -- so the same kernel image boots on both, and a board with
 * a PLIC behaves exactly as it did before this file learned about messages.
 *
 * The LPI vocabulary in this interface is GIC vocabulary, and the mapping to
 * RISC-V is close enough to be honest about. A GIC LPI is an interrupt
 * identifier that only exists as a message; an IMSIC external interrupt
 * identity is exactly that and nothing else -- there is no wired form of one.
 * gic_its_configure_msi asks "what address and word will reach this CPU with
 * this identifier", and on this architecture that is a page number and the
 * identifier itself, with no translation table in between. So the three LPI
 * entry points below are implementable here in a way they were not on a PLIC,
 * and they report absence only when the board really has no message path.
 */
#include <xaios/gic.h>
#include <xaios/riscv64_aia.h>
#include <xaios/status.h>

void klog(const char *fmt, ...);
xaios_status_t riscv64_irq_register(uint32_t source,
                                    void (*handler)(uint32_t, void *),
                                    void *context);
void riscv64_plic_enable(uint32_t source, uint32_t priority);
uint32_t smp_cpu_id(void);

static xaios_gic_info_t g_info;

void gic_configure_platform(uint64_t distributor_base,
                            uint64_t redistributor_base,
                            uint64_t redistributor_length) {
  /* The controller's address comes from the device tree in exception.c, which
     runs before this. Firmware describing a GIC would be describing hardware
     this machine does not have, so the values are recorded and not acted
     on. */
  (void)redistributor_base;
  (void)redistributor_length;
  g_info.distributor_base = distributor_base;
}

void gic_init_platform(void) {
  /* exception_init already found the controller, configured it and unmasked
     external interrupts. Doing it again here would be the second half of an
     initialisation split across two files for no reason. */
  /* One hart, and the controller's source count is what a caller asking about
     interrupt lines wants. Left at what the tree implied rather than
     invented. */
  g_info.cpu_count_hint = 1U;
  if (riscv64_aia_present()) {
    /* Worded differently from the PLIC line on purpose. Every RISC-V gate in
       this tree asserts the PLIC sentence, so a board that quietly stopped
       finding its PLIC and fell back to something else would still print the
       PLIC's words if the two shared one message -- which is the failure mode
       a per-controller sentence exists to prevent. */
    klog("irq: riscv64 aia %s serving the interrupt-controller interface\n",
         riscv64_aia_wired_present() ? "aplic+imsic" : "imsic");
    return;
  }
  klog("irq: riscv64 plic serving the interrupt-controller interface\n");
}

void gic_disable_platform(void) {}

void gic_enable_full(void) {
  __asm__ volatile("csrs sstatus, %0" : : "r"(UINT64_C(2)));
}

void gic_disable_full(void) {
  __asm__ volatile("csrc sstatus, %0" : : "r"(UINT64_C(2)));
}

void gic_secondary_init(uint32_t cpu_id) {
  (void)cpu_id;
  /* An IMSIC interrupt file is per hart and is configured through CSRs, so
     the only code that can bring one up is code running on that hart. This is
     that moment: delivery on, threshold zero, and any identity a driver
     promised to this hart while it was still asleep enabled now.
     A PLIC context would need its threshold set here for the same reason,
     which nothing has needed yet -- every interrupt on that board is taken by
     the boot hart. */
  riscv64_aia_init_hart();
}

xaios_status_t gic_register_interrupt(uint32_t intid,
                                      xaios_irq_handler_t handler,
                                      void *context) {
  return riscv64_irq_register(intid, handler, context);
}

xaios_status_t gic_unregister_interrupt(uint32_t intid,
                                        xaios_irq_handler_t handler,
                                        void *context) {
  (void)handler;
  (void)context;
  /* Masked at the controller rather than forgotten in software: a source
     left enabled with no handler is claimed and completed by the dispatch
     loop forever, which is quieter and worse than an unhandled interrupt.
     On the AIA board this reaches the APLIC and the identity's enable bit
     instead, which is the same statement in different registers. */
  if (riscv64_aia_present()) {
    (void)riscv64_aia_unregister(intid);
  }
  riscv64_plic_enable(intid, 0U);
  return XAIOS_OK;
}

xaios_status_t gic_route_interrupt(uint32_t intid, uint32_t cpu_id) {
  (void)intid;
  /* One hart, so every interrupt is already routed to it. Reporting success
     for the only hart and not-found for any other keeps a caller that is
     spreading interrupts across CPUs from believing it succeeded. */
  return cpu_id == 0U ? XAIOS_OK : XAIOS_ERR_NOT_FOUND;
}

int gic_dispatch_interrupt(uint32_t intid) {
  (void)intid;
  /* Dispatch happens in the trap handler, which claims from the controller
     rather than being handed a number. Nothing to do here. */
  return 0;
}

const xaios_gic_info_t *gic_info(void) { return &g_info; }

void gic_self_test(void) {
  if (riscv64_aia_present()) {
    riscv64_aia_self_test();
    return;
  }
  klog("irq: riscv64 plic interface present (no LPI, no message-signalled "
       "translation)\n");
}

/* Message-signalled interrupts, in the vocabulary the shared drivers use.
 *
 * On a PLIC board these still report absence, which every caller already
 * handles by polling -- and that is the configuration all the existing gates
 * run in. On an AIA board they are real: an identity is an IMSIC external
 * interrupt identity, and the "translation" a GIC ITS performs has no
 * equivalent to perform because the message needs none.
 */
xaios_status_t gic_allocate_lpi(uint32_t *intid) {
  if (riscv64_aia_present()) return riscv64_aia_allocate(intid);
  if (intid != 0) *intid = 0U;
  return XAIOS_ERR_UNSUPPORTED;
}

xaios_status_t gic_register_lpi(uint32_t intid, uint32_t cpu_id,
                                xaios_irq_handler_t handler, void *context) {
  if (riscv64_aia_present()) {
    return riscv64_aia_register(intid, cpu_id, handler, context);
  }
  (void)intid;
  (void)cpu_id;
  (void)handler;
  (void)context;
  return XAIOS_ERR_UNSUPPORTED;
}

xaios_status_t gic_its_configure_msi(uint32_t device_id, uint32_t event_id,
                                     uint32_t intid, uint32_t cpu_id,
                                     uint64_t *message_address,
                                     uint32_t *message_data) {
  /* device_id and event_id are what an ITS needs to find a translation table
     entry. An IMSIC has no table: the address names the hart and the data
     names the interrupt, so both are genuinely unused here rather than
     unimplemented. Saying that plainly is better than inventing a use for
     them. */
  (void)device_id;
  (void)event_id;
  if (riscv64_aia_present()) {
    return riscv64_aia_message_target(intid, cpu_id, message_address,
                                      message_data);
  }
  (void)intid;
  (void)cpu_id;
  if (message_address != 0) *message_address = 0U;
  if (message_data != 0) *message_data = 0U;
  return XAIOS_ERR_UNSUPPORTED;
}

int gic_its_available(void) { return riscv64_aia_present(); }

void gic_its_set_base(uint64_t base) { (void)base; }
