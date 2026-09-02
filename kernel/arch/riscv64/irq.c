/* The interrupt-controller interface, backed by the PLIC.
 *
 * These are named gic_* because the shared kernel calls them that, and that
 * naming is itself worth recording: `gic` is AArch64's controller, and a
 * shared header naming one architecture's hardware is the identity-versus-
 * capability line being crossed inside the very codebase that has a rule
 * against it. Renaming the interface across every caller is a larger change
 * than this port, so the names stay and this comment carries the finding.
 * What the interface actually means is "register, route and dispatch an
 * interrupt", which the PLIC does perfectly well.
 *
 * The mapping is not exact and the differences are honest ones. RISC-V has
 * no LPIs and no message-signalled interrupt translation service, so those
 * report absence rather than pretending; the shared callers already handle a
 * platform without them, because three of the four supported environments
 * lack an ITS too.
 */
#include <xaios/gic.h>
#include <xaios/status.h>

void klog(const char *fmt, ...);
xaios_status_t riscv64_irq_register(uint32_t source,
                                    void (*handler)(uint32_t, void *),
                                    void *context);
void riscv64_plic_enable(uint32_t source, uint32_t priority);

static xaios_gic_info_t g_info;

void gic_configure_platform(uint64_t distributor_base,
                            uint64_t redistributor_base,
                            uint64_t redistributor_length) {
  /* The PLIC's address comes from the device tree in exception.c, which runs
     before this. Firmware describing a GIC would be describing hardware this
     machine does not have, so the values are recorded and not acted on. */
  (void)redistributor_base;
  (void)redistributor_length;
  g_info.distributor_base = distributor_base;
}

void gic_init_platform(void) {
  /* exception_init already found the PLIC, set the threshold and unmasked
     external interrupts. Doing it again here would be the second half of an
     initialisation split across two files for no reason. */
  /* One hart, and the PLIC's source count is what a caller asking about
     interrupt lines wants. Left at what the tree implied rather than
     invented. */
  g_info.cpu_count_hint = 1U;
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
  /* Each hart has its own PLIC context and would need its threshold set as
     it comes up. There are no secondary harts yet, and doing nothing is
     correct until there are. */
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
     loop forever, which is quieter and worse than an unhandled interrupt. */
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
  /* Dispatch happens in the trap handler, which claims from the PLIC rather
     than being handed a number. Nothing to do here. */
  return 0;
}

const xaios_gic_info_t *gic_info(void) { return &g_info; }

void gic_self_test(void) {
  klog("irq: riscv64 plic interface present (no LPI, no message-signalled "
       "translation)\n");
}

/* Locality-based interrupts and the translation service that delivers them
   are GIC features with no RISC-V equivalent on this board. Reported absent,
   which every caller already handles. */
xaios_status_t gic_allocate_lpi(uint32_t *intid) {
  if (intid != 0) *intid = 0U;
  return XAIOS_ERR_UNSUPPORTED;
}

xaios_status_t gic_register_lpi(uint32_t intid, uint32_t cpu_id,
                                xaios_irq_handler_t handler, void *context) {
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
  (void)device_id;
  (void)event_id;
  (void)intid;
  (void)cpu_id;
  if (message_address != 0) *message_address = 0U;
  if (message_data != 0) *message_data = 0U;
  return XAIOS_ERR_UNSUPPORTED;
}

int gic_its_available(void) { return 0; }

void gic_its_set_base(uint64_t base) { (void)base; }
