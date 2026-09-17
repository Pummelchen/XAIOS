/* The platform half of kmain: the boot stages between the first interrupt
 * vectors and the discovery of storage.
 *
 * boot_cpu_memory_bring_up runs where the machine first has vectors, a timer
 * and a stack canary, and leaves it with NUMA, physical and virtual memory and
 * the firmware framebuffer mapped. boot_platform_bring_up then maps the
 * architecture's interrupt and IOMMU windows, configures the GIC and ECAM,
 * brings up the heap, PCI, console, input, SMMU, RTC and watchdog, and runs the
 * runtime self-test battery.
 *
 * These helpers own no state: nothing crosses back into kmain, so no pointer
 * into file-scope state is ever handed out. The two entry points are declared
 * in boot_platform_internal.h.
 */

#include "boot_platform_internal.h"

#include <xaios/arena.h>
#include <xaios/assert.h>
#include <xaios/boot_ui.h>
#include <xaios/child_channel.h>
#include <xaios/core_lease.h>
#include <xaios/exception.h>
#include <xaios/gic.h>
#include <xaios/git_workspace.h>
#include <xaios/input.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/klog_ring.h>
#include <xaios/numa.h>
#include <xaios/pci.h>
#include <xaios/pmm.h>
#include <xaios/ram_residency.h>
#include <xaios/rate_limit.h>
#include <xaios/remote_login.h>
#include <xaios/rtc.h>
#include <xaios/sandbox.h>
#include <xaios/security.h>
#include <xaios/smmu.h>
#include <xaios/smp.h>
#include <xaios/source_index.h>
#include <xaios/spinlock.h>
#include <xaios/stack_canary.h>
#include <xaios/status.h>
#include <xaios/timer.h>
#include <xaios/topology.h>
#include <xaios/virtio_console.h>
#include <xaios/vmm.h>
#include <xaios/watchdog.h>
#if defined(__aarch64__)
#include <xaios/aarch64_acpi.h>
#include <xaios/aarch64_sve.h>
#endif

/* The page granularity helper the platform mappings below use. It is private
   to this module: after the split nothing outside it maps MMIO. */
static void map_mmio_range(uint64_t start, uint64_t size) {
  const uint64_t page_size = 4096;
  uint64_t page = start & ~(page_size - 1U);
  uint64_t end = (start + size + page_size - 1U) & ~(page_size - 1U);
  while (page < end) {
    kassert(vmm_map_page(page, page,
                         XAIOS_VMM_PRESENT | XAIOS_VMM_WRITABLE |
                             XAIOS_VMM_DEVICE) == XAIOS_OK);
    page += page_size;
  }
}

static void early_spinlock_self_test(void) {
  xaios_spinlock_t lock = XAIOS_SPINLOCK_INIT;
  kassert(smp_online_count() <= 1U);
  kassert(xaios_spin_trylock(&lock) == 1);
  kassert(xaios_spin_held(&lock) == 1);
  kassert(xaios_spin_trylock(&lock) == 0);
  xaios_spin_unlock(&lock);
  kassert(xaios_spin_held(&lock) == 0);
  kassert(lock.next_ticket == 0U);
  kassert(lock.serve == 0U);
  kassert(lock.guard == 0U);
  kassert(xaios_spin_trylock(&lock) == 1);
  kassert(xaios_spin_held(&lock) == 1);
  xaios_spin_unlock(&lock);
  klog("spinlock: early single-core try-lock self-test passed\n");
}

void boot_cpu_memory_bring_up(const xaios_boot_info_t *boot) {
  exception_init();
  exception_self_test();
#if defined(__aarch64__)
  aarch64_sve2_self_test();
#endif
  early_spinlock_self_test();
  timer_init();
  timer_self_test();
  stack_canary_init();
  stack_canary_self_test();
  smp_init_platform(boot);
  smp_self_test();
  boot_ui_update(35U, "CPU and interrupts", "memory management", 4U);

  numa_init(boot);
  numa_self_test();

  pmm_init(boot);
  vmm_init(boot);
  klog_counters_ready();
  /* The firmware framebuffer, before anything draws on it again.
   *
   * Until translation was enabled, writing to it worked because firmware's
   * tables covered it. The kernel's own tables identity-map physical memory
   * and the handful of device windows it knows the addresses of; a
   * framebuffer firmware placed outside RAM is neither. On a VMware Fusion
   * guest with four gibibytes it sits at 0xff0000000, well past the end of
   * memory, and the next line boot_ui drew took a translation fault -- while
   * the same guest with one or two gibibytes had the framebuffer low enough
   * to fall inside the identity map and worked. Nothing about the framebuffer
   * changed; only how much RAM was underneath it.
   *
   * Mapped here rather than in boot_ui because boot_ui runs before there are
   * page tables to map anything into, and the very next statement draws. */
  if (boot->framebuffer_base != 0U && boot->framebuffer_size != 0U) {
    map_mmio_range(boot->framebuffer_base, boot->framebuffer_size);
    /* Where it is, and whether that is above the memory the machine has.
       B-12 is entirely about that comparison, and nothing recorded it: a
       Fusion guest at 4 GiB and the same guest at 2 both printed a working
       framebuffer, and only one of them had exercised the mapping this line
       exists for. Reported so a boot log says which case it was rather than
       leaving it to be inferred from the memory size. */
    klog("boot-ui: framebuffer mapped base=0x%lx bytes=0x%lx ram_pages=%lu\n",
         boot->framebuffer_base, boot->framebuffer_size, pmm_total_pages());
  }
  vmm_self_test();
  boot_ui_update(45U, "memory management", "devices and storage", 3U);
}

void boot_platform_bring_up(const xaios_boot_info_t *boot) {
#if defined(__aarch64__)
  map_mmio_range(XAIOS_SMMU_MMIO_BASE, 0x10000);
  map_mmio_range(XAIOS_SMMU_MMIO_PAGE1, 0x10000);
#endif
  smmu_init(boot);

#if defined(__aarch64__)
  map_mmio_range(boot->uart_base, 4096);
  aarch64_acpi_info_t acpi_info;
  uint64_t gic_distributor = UINT64_C(0x08000000);
  uint64_t gic_redistributor = UINT64_C(0x080A0000);
  uint64_t gic_redistributor_bytes = UINT64_C(0x00f60000);
  if (aarch64_acpi_parse(boot->acpi_rsdp, &acpi_info) != 0) {
    uint64_t required_redistributor_bytes =
        (uint64_t)smp_capacity() * UINT64_C(0x20000);
    if (smp_capacity() != 0U &&
        acpi_info.gic_redistributor_length >= required_redistributor_bytes) {
      gic_distributor = acpi_info.gic_distributor_base;
      gic_redistributor = acpi_info.gic_redistributor_base;
      /* Message-signalled interrupts need the translation service, and where
         it sits is a property of the machine rather than of one emulator. */
      if (acpi_info.gic_its_base != 0U) {
        gic_its_set_base(acpi_info.gic_its_base);
        klog("platform: ACPI GIC ITS at 0x%lx\n", acpi_info.gic_its_base);
      } else {
        klog("platform: firmware reports no GIC ITS; PCI interrupts are "
             "polled\n");
      }
      gic_redistributor_bytes = acpi_info.gic_redistributor_length;
      gic_configure_platform(gic_distributor, gic_redistributor,
                             gic_redistributor_bytes);
    } else {
      klog("platform: ACPI GIC redistributor range too small cpus=%u bytes=%lu\n",
           smp_capacity(), acpi_info.gic_redistributor_length);
      gic_distributor = 0U;
      gic_redistributor = 0U;
      gic_redistributor_bytes = 0U;
      gic_disable_platform();
    }
    pci_configure_ecam(acpi_info.pci_ecam_base, acpi_info.pci_start_bus,
                       acpi_info.pci_end_bus);
    klog("platform: ACPI GICv%u CPUs=%u ECAM=0x%lx bus=%u-%u\n",
         acpi_info.gic_version, acpi_info.enabled_cpus,
         acpi_info.pci_ecam_base, acpi_info.pci_start_bus,
         acpi_info.pci_end_bus);
  } else {
    uint32_t low_redistributors =
        smp_capacity() < 123U ? smp_capacity() : 123U;
    gic_redistributor_bytes =
        (uint64_t)low_redistributors * UINT64_C(0x20000);
    if (smp_capacity() > low_redistributors) {
      map_mmio_range(UINT64_C(0x4000000000),
                     (uint64_t)(smp_capacity() - low_redistributors) *
                         UINT64_C(0x20000));
    }
    pci_configure_ecam(boot->pci_ecam_base, boot->pci_ecam_start_bus,
                       boot->pci_ecam_end_bus);
  }
  if (gic_distributor != 0U && gic_redistributor != 0U &&
      gic_redistributor_bytes != 0U) {
    map_mmio_range(gic_distributor, UINT64_C(0x20000));
    map_mmio_range(gic_redistributor, gic_redistributor_bytes);
  }
  map_mmio_range(UINT64_C(0x0a000000), UINT64_C(0x4000));
#else
  /* The x86 UART is port I/O. Keep a software VMM descriptor for capability
   * and translation validation without treating the port as MMIO. */
  map_mmio_range(boot->uart_base, 4096);
#endif

  /* PCI drivers allocate DMA rings, so establish the heap before probing. */
  kheap_self_test();
  /* Before anything becomes resident, so the first reservation is counted. */
  ram_residency_init();

  /* Map ECAM and enumerate PCIe. */
  pci_init();
  pci_self_test();

  /* A platform with no UART has had nothing to say until now. Attach the
     virtio console if one exists, then replay what was logged before it did,
     so the early boot is not lost. Absent on QEMU, which logs to a PL011. */
  if (virtio_console_init() == XAIOS_OK) {
    klog_set_console_sink(virtio_console_write);
    klog_set_console_source(virtio_console_read);
    klog_set_console_poll(virtio_console_pending);
#if defined(__aarch64__)
    char *replay = (char *)kheap_alloc(XAIOS_KLOG_FLUSH_MAX, 16U);
    if (replay != 0) {
      uint64_t replay_start = 0U;
      uint64_t replay_next = 0U;
      uint64_t replay_latest = 0U;
      uint32_t replayed =
          klog_ring_snapshot(replay, XAIOS_KLOG_FLUSH_MAX, 0U, &replay_start,
                             &replay_next, &replay_latest);
      if (replayed != 0U) {
        virtio_console_write(replay, replayed);
      }
      kheap_free(replay);
    }
#endif
    klog("virtio-console: kernel log attached\n");
  }
  input_init();
  input_self_test();
  smmu_self_test();

  /* Initialize the architecture real-time clock. */
#if defined(__aarch64__)
  map_mmio_range(XAIOS_PL031_RTC_BASE, 4096);
#endif
  rtc_init();
  wall_time_calibrate();
  rtc_self_test();

  /* Initialize watchdog timer */
  watchdog_init();
  watchdog_self_test();

  klog("VMM architecture device mappings installed\n");
  exception_runtime_init();
  topology_init();
  topology_self_test();
  arena_manager_init();
  arena_self_test();
  rate_limit_init();
  rate_limit_self_test();
  security_self_test();
  child_channel_init();
  child_channel_self_test();
  remote_login_self_test();
  source_index_runtime_init();
  source_index_self_test();
  git_workspace_runtime_init();
  git_workspace_self_test();
  sandbox_self_test();
  core_lease_self_test();
}
