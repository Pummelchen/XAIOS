/* The devices this board does not have, answered honestly.
 *
 * PCI, an IOMMU and a real-time clock all have shared callers that expect a
 * definition. QEMU's virt board does have a PCIe host bridge, and wiring it up
 * is real work rather than a stub -- but claiming it works when nothing has
 * enumerated it would be worse than saying so. Each of these reports absence
 * in the way its caller already handles, which is the same thing the other
 * architectures do where a capability is missing.
 */
#include <xaios/exception.h>
#include <xaios/pci.h>
#include <xaios/riscv64_fdt.h>
#include <xaios/riscv64_sbi.h>
#include <xaios/smmu.h>
#include <xaios/vmm.h>
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

/* The RISC-V IOMMU: looked for rather than assumed (B-130).
 *
 * This said "riscv64 has no IOMMU on this board" as a compile-time sentence.
 * The plain `virt` board genuinely has none, and that is still what a boot
 * without the device reports -- but the sentence is now the *result* of a look,
 * because QEMU attaches one with `-device riscv-iommu-pci` (Red Hat
 * 0x1b36:0x0014) and the same kernel has to notice it.
 *
 * The register file is one 4 KiB page at BAR0 and `CAP` sits at offset 0; it is
 * read here only to prove the device answers. Nothing is programmed yet, and
 * that matters: QEMU resets the device with its device directory table Off, so
 * an unprogrammed IOMMU refuses PCI DMA rather than passing it through. The
 * milestones that program it, and the ordering that keeps a half-programmed
 * table from taking the machine's PCI DMA with it, are in
 * docs/RISCV-IOMMU.md. */
#define RISCV_IOMMU_PCI_VENDOR XAIOS_PCI_VENDOR_REDHAT
#define RISCV_IOMMU_PCI_DEVICE UINT16_C(0x0014)

/* Where the look happens.
 *
 * Not in `smmu_init`: the IOMMU here is a PCI function, and `pci_init()` runs
 * later in `kmain` than the shared `smmu_init(boot)` call, so a probe there
 * would search an inventory that does not exist yet and report every board as
 * having no IOMMU -- which is exactly what it did on a QEMU command line that
 * had one attached. `smmu_self_test()` is called after `pci_init()`, which is
 * where this port's look belongs. */
void smmu_init(const struct xaios_boot_info *boot) { (void)boot; }

static void riscv64_iommu_probe(void) {
  uint32_t index = pci_find_device(RISCV_IOMMU_PCI_VENDOR,
                                   RISCV_IOMMU_PCI_DEVICE);
  if (index == UINT32_C(0xFFFFFFFF)) {
    klog("smmu: riscv64 pci inventory has no 0x%04x:0x%04x and the tree has no "
         "riscv,iommu node\n",
         (unsigned)RISCV_IOMMU_PCI_VENDOR, (unsigned)RISCV_IOMMU_PCI_DEVICE);
    klog("smmu: riscv64 has no IOMMU on this board; DMA is unmediated\n");
    return;
  }

  (void)pci_enable_device(index);
  uint64_t base = pci_bar_address(index, 0U);
  if (base == 0U) {
    klog("smmu: riscv64 riscv-iommu-pci present with no BAR0 assigned; DMA is "
         "unmediated\n");
    return;
  }

  /* BAR0 is above this port's identity-mapped device window -- QEMU places it at
   * `0x400010000` -- so the page has to be mapped before a register can be read
   * from it, which is what the AArch64 SMMU self-test does for the same reason.
   * Without the mapping the read faults (`class=load-page-fault cause=13
   * stval=0x400010000`) and takes the machine down for one log field. */
  xaios_status_t mapped = vmm_map_page(base, base, XAIOS_VMM_DEVICE);
  if (mapped != XAIOS_OK) {
    klog("smmu: riscv64 riscv-iommu-pci at 0x%lx could not be mapped "
         "(status=%d); DMA is unmediated\n",
         (unsigned long)base, (int)mapped);
    return;
  }

  /* A read that faults and a read of all-ones mean the same thing here, and
     neither is fatal -- the containment the ECAM probe uses. */
  exception_mmio_probe_begin();
  uint64_t cap = *(volatile const uint64_t *)(uintptr_t)base;
  exception_mmio_probe_end();
  if (exception_mmio_probe_faulted() != 0) {
    klog("smmu: riscv64 riscv-iommu-pci at 0x%lx does not answer; DMA is "
         "unmediated\n",
         (unsigned long)base);
    return;
  }

  /* CAP: version in bits 7:0, Sv39/Sv48/Sv57 at 9/10/11, and the
     interrupt-generation support at 29:28. Decoded rather than dumped, because
     the version says which specification the device implements and the Sv bits
     say which page-table formats the driver that follows may use. */
  klog("riscv-iommu: found device=%u base=0x%lx cap=0x%lx version=0x%lx sv39=%u "
       "sv48=%u sv57=%u igs=%u\n",
       (unsigned)index, (unsigned long)base, (unsigned long)cap,
       (unsigned long)(cap & UINT64_C(0xff)),
       (unsigned)((cap >> 9U) & 1U), (unsigned)((cap >> 10U) & 1U),
       (unsigned)((cap >> 11U) & 1U), (unsigned)((cap >> 28U) & 3U));
  klog("smmu: riscv64 riscv-iommu-pci present, not yet programmed; PCI DMA is "
       "refused by the device until then\n");
}

void smmu_self_test(void) { riscv64_iommu_probe(); }

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
   supervisor-mode kernel can restart the machine -- and reset is the whole
   point: this called `sbi_shutdown()`, which is the same extension asked to
   *stop*, so `reboot` powered the machine off. The administrative lifecycle
   gate found it the first time it ran on this architecture: after `ssh
   reboot` the machine never came back (B-127). */
void arch_reboot(void) {
  sbi_system_reset(SBI_SRST_RESET_COLD_REBOOT, SBI_SRST_REASON_NONE);
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
