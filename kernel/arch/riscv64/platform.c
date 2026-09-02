/* The devices this board does not have, answered honestly.
 *
 * PCI, an IOMMU and a real-time clock all have shared callers that expect a
 * definition. QEMU's virt board does have a PCIe host bridge, and wiring it up
 * is real work rather than a stub -- but claiming it works when nothing has
 * enumerated it would be worse than saying so. Each of these reports absence
 * in the way its caller already handles, which is the same thing the other
 * architectures do where a capability is missing.
 */
#include <xaios/riscv64_sbi.h>
#include <xaios/topology.h>
#include <xaios/status.h>
#include <xaios/types.h>

void klog(const char *fmt, ...);

/* PCI is no longer stubbed here. The ECAM enumerator that used to live under
   arch/aarch64 is shared code now, and this board's host bridge is described
   in the device tree like everything else, so riscv64 gets the same driver
   the other architectures use rather than an apology. What remains
   unimplemented is message-signalled interrupts, below, which need more than
   a bus. */

/* No IOMMU. RISC-V has one in its specification and this board does not
   present it, so device DMA is unmediated here -- which the SMMU-aware paths
   already handle, since three of the four supported environments have no
   IOMMU either. */
void smmu_init(void) {
  klog("smmu: riscv64 has no IOMMU on this board; DMA is unmediated\n");
}

void smmu_self_test(void) {}

/* The Goldfish RTC on this board is not driven yet. Wall time therefore
   advances from an unknown epoch, which timer.c says plainly rather than
   inventing a date. */
void rtc_init(void) {
  klog("rtc: riscv64 goldfish clock not driven; the epoch is unknown\n");
}

void rtc_self_test(void) {}

/* Message-signalled interrupts, the stream identifier an IOMMU would use to
   tell devices apart, and the rest of the configuration-space work all come
   from the shared enumerator now. What this board still lacks is a way to
   deliver an MSI at all: the PLIC takes wires, not messages, so the
   interrupt-controller side reports no translation service and the shared
   code never reaches the point of programming a vector. */

/* One hart, one node, no heterogeneity to describe. */
void topology_init(void) {
  klog("topology: riscv64 single hart, one node\n");
}

void topology_self_test(void) {}

/* No watchdog on this board. Kicking one that does not exist is harmless;
   claiming to have armed one would not be, because the caller would stop
   worrying about a hang nothing is watching for. */
void watchdog_init(void) {
  klog("watchdog: riscv64 has none on this board; nothing is watching for a "
       "hang\n");
}

void watchdog_kick(void) {}

void watchdog_trigger_reset(void) {}

/* The boot counter lives in persistent storage the other architectures reach
   through firmware variables. Until this port has that, every boot looks like
   the first -- which is the truthful answer, not a useful one. */
void boot_counter_increment(void) {}

uint32_t boot_in_recovery_mode(void) { return 0U; }

/* Runtime exception setup beyond what exception_init already did. The vector
   is armed once and does not change. */
void exception_runtime_init(void) {}

void watchdog_self_test(void) {}

void boot_counter_reset(void) {}

/* Reset through SBI's system-reset extension, which is the only way a
   supervisor-mode kernel can restart the machine. */
void arch_reboot(void) {
  sbi_shutdown();
  for (;;) {
    __asm__ volatile("wfi");
  }
}

/* One hart is one core, one socket, one node, one domain. The shared
   scheduler asks these to decide where to place work; answering with a single
   domain is truthful and makes every placement decision trivially correct. */
static xaios_sched_domain_t g_domain;

uint32_t topology_get_core_domain(uint32_t cpu_id) {
  (void)cpu_id;
  return 0U;
}

uint32_t topology_get_socket_domain(uint32_t cpu_id) {
  (void)cpu_id;
  return 0U;
}

uint32_t topology_get_numa_domain(uint32_t cpu_id) {
  (void)cpu_id;
  return 0U;
}

uint32_t topology_get_numa_node_for_cpu(uint32_t cpu_id) {
  (void)cpu_id;
  return 0U;
}

const xaios_sched_domain_t *topology_get_domain(uint32_t domain_id) {
  if (domain_id != 0U) return 0;
  g_domain.domain_id = 0U;
  g_domain.level = 3U; /* system: there is no finer structure to describe */
  g_domain.parent_domain = UINT32_MAX;
  g_domain.member_count = 1U;
  g_domain.members[0] = 0U;
  return &g_domain;
}

const xaios_cpu_topology_t *topology_get_cpu(uint32_t cpu_id) {
  (void)cpu_id;
  return 0;
}

void arch_power_off(void) {
  sbi_shutdown();
  for (;;) {
    __asm__ volatile("wfi");
  }
}
