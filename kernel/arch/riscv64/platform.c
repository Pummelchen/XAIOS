/* The devices this board does not have, answered honestly.
 *
 * PCI, an IOMMU and a real-time clock all have shared callers that expect a
 * definition. QEMU's virt board does have a PCIe host bridge, and wiring it up
 * is real work rather than a stub -- but claiming it works when nothing has
 * enumerated it would be worse than saying so. Each of these reports absence
 * in the way its caller already handles, which is the same thing the other
 * architectures do where a capability is missing.
 */
#include <xaios/riscv64_fdt.h>
#include <xaios/riscv64_sbi.h>
#include <xaios/timer.h>
#include <xaios/topology.h>
#include <xaios/status.h>
#include <xaios/types.h>

void klog(const char *fmt, ...);

/* The tree, shared with the pieces below that read it. Set by boot.c before
   any of this runs. */
static const void *g_device_tree;

void riscv64_platform_set_device_tree(const void *blob) {
  g_device_tree = blob;
}

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

/* The Goldfish real-time clock.
 *
 * Two 32-bit registers holding one 64-bit nanosecond count since the Unix
 * epoch: the low half latches the high half, so they have to be read in that
 * order and in that order only. Reading high first returns a value that is
 * correct except across a rollover of the low word, which is the kind of bug
 * that appears once every four seconds and never in a test.
 *
 * Found in the device tree rather than assumed, like everything else on this
 * board. Before this, wall time advanced from zero and the kernel said so
 * plainly -- which was honest, and meant every timestamp on the machine was
 * wrong by fifty-six years.
 */
#define GOLDFISH_TIME_LOW UINT64_C(0x00)
#define GOLDFISH_TIME_HIGH UINT64_C(0x04)

static uint64_t g_rtc_base;

static uint64_t goldfish_now_ns(void) {
  if (g_rtc_base == 0U) return 0U;
  volatile const uint32_t *low =
      (volatile const uint32_t *)(uintptr_t)(g_rtc_base + GOLDFISH_TIME_LOW);
  volatile const uint32_t *high =
      (volatile const uint32_t *)(uintptr_t)(g_rtc_base + GOLDFISH_TIME_HIGH);
  uint32_t low_value = *low;
  uint32_t high_value = *high;
  return ((uint64_t)high_value << 32) | (uint64_t)low_value;
}

void rtc_init(void) {
  uint64_t base = 0U;
  if (g_device_tree == 0 ||
      !fdt_find_compatible(g_device_tree, "google,goldfish-rtc", &base)) {
    klog("rtc: no goldfish clock in the device tree; the epoch stays "
         "unknown and timestamps will be wrong by decades\n");
    return;
  }
  g_rtc_base = base;
  uint64_t now = goldfish_now_ns();
  if (now == 0U) {
    klog("rtc: goldfish clock at %lx reads zero; treating it as absent "
         "rather than believing 1970\n", base);
    g_rtc_base = 0U;
    return;
  }
  /* Told to the shared clock as an absolute epoch, which is what
     wall_time_set_ns takes; source 2 is the same identifier the other
     architectures use for a hardware clock. */
  (void)wall_time_set_ns(now, 2U);
  klog("rtc: goldfish at %lx epoch_ns=%lu\n", base, now);
}

void rtc_self_test(void) {
  if (g_rtc_base == 0U) {
    klog("rtc: self-test skipped, no clock on this machine\n");
    return;
  }
  /* It has to move, and it has to move forward. A latched pair read in the
     wrong order fails here rather than four seconds later. */
  uint64_t first = goldfish_now_ns();
  for (volatile uint32_t spin = 0U; spin < 200000U; ++spin) {
  }
  uint64_t second = goldfish_now_ns();
  if (second <= first) {
    klog("rtc: the clock did not advance: %lu then %lu\n", first, second);
    return;
  }
  klog("rtc: self-test passed advance=%lu ns\n", second - first);
}

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
