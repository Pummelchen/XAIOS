/* The runtime half of kmain: from the page-allocator canary to serving SSH.
 *
 * boot_runtime_run runs once, after the fault-test marker has been emitted, and
 * does not return until the machine has settled -- the initial filesystem
 * lookups and the launch of /init and the service manager, the preemptive
 * scheduler with its interrupt canaries, the boot-test application profile,
 * the second boot-summary report, the network-readiness gate that withholds
 * SSH on a machine with no IPv4 network, the wall-clock sync, and the tail.
 *
 * boot_sync_wall_clock was a static helper in kmain.c and stays private here;
 * the NTP deadline it is bounded by moves with it.
 */

#include "boot_apps_internal.h"
#include "boot_runtime_internal.h"

#include <xaios/arch_cpu.h>
#include <xaios/assert.h>
#include <xaios/boot_ui.h>
#include <xaios/gic.h>
#include <xaios/initramfs.h>
#include <xaios/klog.h>
#include <xaios/network_stack.h>
#include <xaios/ntp.h>
#include <xaios/nvme.h>
#include <xaios/operations.h>
#include <xaios/pmm.h>
#include <xaios/scheduler.h>
#include <xaios/smp.h>
#include <xaios/status.h>
#include <xaios/system_slot.h>
#include <xaios/telemetry.h>
#include <xaios/thread.h>
#include <xaios/timer.h>
#include <xaios/virtio_blk.h>
#include <xaios/virtio_gpu.h>
#if defined(__aarch64__)
#include <xaios/aarch64_sve.h>
#endif

/* Two NTP retransmits plus margin, well inside the client's own 10s
   timeout, so a filtered UDP/123 costs a bounded pause and nothing more. */
#define BOOT_NTP_DEADLINE_NS UINT64_C(6000000000)

/* Set the wall clock from NTP before any service starts.

   The clock is otherwise whatever the RTC reports, and QEMU's PL031 commonly
   reports epoch zero, leaving the system in 1970. Anything that checks a
   certificate validity window then sees every certificate as not-yet-valid,
   which is how xapt fails against the updater's publicly issued certificate.

   Bounded and non-fatal. The default server is a bare address, so this needs
   no DNS, but UDP/123 is filtered on some networks and a boot must not stall
   waiting for a reply that will never arrive. */

static void boot_sync_wall_clock(void) {
  if (ntp_sync(0U) != XAIOS_ERR_BUSY) {
    klog("kernel: boot ntp not started state=%u\n",
         (unsigned)ntp_status().state);
    return;
  }
  uint64_t deadline = timer_now_ns() + BOOT_NTP_DEADLINE_NS;
  while (ntp_status().state == XAIOS_NTP_PENDING &&
         timer_now_ns() < deadline) {
    network_poll_tick();
    xaios_cpu_relax();
  }
  klog("kernel: boot ntp state=%u epoch_seconds=%lu source=%u\n",
       (unsigned)ntp_status().state,
       wall_time_now_ns() / UINT64_C(1000000000),
       (unsigned)wall_time_source());
}

void boot_runtime_run(const xaios_boot_info_t *boot,
                      xaios_status_t persistent_status,
                      xaios_status_t nvme_status) {
  uint32_t persistent_network_ready = 0U;
  void *pages[1024];
  for (unsigned i = 0; i < 1024; ++i) {
    pages[i] = pmm_alloc_page();
    kassert(pages[i] != 0);
  }
  for (unsigned i = 0; i < 1024; ++i) {
    pmm_free_page(pages[i]);
  }

  klog("PMM 1024 page allocate/free test passed\n");

  const xaios_initramfs_file_t *init_file = 0;
  const xaios_initramfs_file_t *manager_file = 0;
#if XAIOS_BOOT_TEST_APPS
  const xaios_initramfs_file_t *worker_file = 0;
#endif
  const xaios_initramfs_config_t *init_config = initramfs_config();
  kassert(init_config != 0);
  kassert(initramfs_lookup(init_config->service_path, &init_file) == XAIOS_OK);
  kassert(initramfs_lookup(init_config->service_manager_path, &manager_file) ==
          XAIOS_OK);
#if XAIOS_BOOT_TEST_APPS
  kassert(initramfs_lookup("/bin/xaios-worker", &worker_file) == XAIOS_OK);
#endif
  boot_apps_launch_init(init_file, manager_file, init_config, persistent_status,
                        &persistent_network_ready);

  /* Initialize preemptive scheduler infrastructure */
  scheduler_lock();
#if defined(__x86_64__)
  uint64_t initial_block_interrupts = virtio_block_interrupt_count();
#endif
  gic_enable_full();
  if (nvme_status == XAIOS_OK) {
    /* UNSUPPORTED is the answer from a machine whose interrupt controller has
       no messages to signal with -- the queues are polled and there is
       nothing to canary. Anything else that is not OK means interrupts were
       configured and did not arrive, which is a defect. */
    xaios_status_t nvme_interrupts = nvme_interrupt_self_test();
    kassert(nvme_interrupts == XAIOS_OK ||
            nvme_interrupts == XAIOS_ERR_UNSUPPORTED);
  }
#if defined(__x86_64__)
  /* The canary asks the block device to complete a request and raise an
     interrupt. When the loader supplied the initial filesystem in memory there
     is no device to ask, and every step below fails on that rather than on
     anything being wrong -- which is what happened the first time this kernel
     booted from the unified image, where the initial filesystem rides on the
     boot medium instead of arriving as a separate drive. Report that the test
     did not apply; do not assert that memory can raise interrupts. */
  if (virtio_block_is_memory_backed() != 0U) {
    klog("virtio-blk: x86 completion canary skipped; the block device is "
         "loader memory, which raises no interrupts\n");
  } else {
    uint64_t interrupt_drain_deadline = timer_now_ns() + UINT64_C(100000000);
    while (virtio_block_interrupt_count() == initial_block_interrupts &&
           timer_now_ns() < interrupt_drain_deadline)
      xaios_cpu_relax();
    uint8_t interrupt_sector[512];
    kassert(virtio_block_interrupt_canary_arm(
        0U, interrupt_sector, sizeof(interrupt_sector)) == XAIOS_OK);
    xaios_status_t interrupt_status =
        virtio_block_interrupt_canary_wait(UINT64_C(1000000000));
    if (interrupt_status == XAIOS_OK) {
      klog("virtio-blk: x86 completion canary passed mode=msix count=%lu\n",
           virtio_block_interrupt_count());
    } else {
      kassert(virtio_block_read_sector(0U, interrupt_sector,
                                       sizeof(interrupt_sector)) == XAIOS_OK);
      klog("virtio-blk: x86 completion canary passed mode=bounded-poll "
           "status=%d\n",
           (int)interrupt_status);
    }
  }
#endif
  timer_enable_periodic(XAIOS_SCHEDULER_DEFAULT_TICK_HZ);
  kassert(smp_set_scheduling_enabled(smp_cpu_id(), 1U) == XAIOS_OK);
  uint64_t simd_irq_status = aarch64_simd_irq_self_test();
  klog("scheduler: SIMD/FP interrupt canary status=%lu\n",
       simd_irq_status);
  kassert(simd_irq_status == 1U);
#if defined(__aarch64__)
  if (aarch64_sve_enabled() != 0U) {
    uint64_t sve_irq_status = aarch64_sve_irq_self_test();
    klog("scheduler: SVE interrupt canary status=%lu\n", sve_irq_status);
    kassert(sve_irq_status == 1U);
    klog("scheduler: SVE Z/P/FFR interrupt preservation passed EL0-task-state=1\n");
  }
#endif
  scheduler_unlock();
  klog("scheduler: SIMD/FP interrupt preservation passed\n");
  kassert(smp_release_secondary_schedulers() == XAIOS_OK);
  xaios_thread_self_test();
  /* A CPU that cannot take an interrupt must still answer a TLB shootdown:
     with the scheduler up, one CPU can be made to spin on a guard while
     another shoots down inside it (B-123). */
  smp_shootdown_ack_self_test();
  /* And a wakeup must not be lost between an idle CPU's check and its wait. */
  smp_idle_wakeup_self_test();
  klog("kernel: preemptive scheduler infrastructure enabled\n");
  boot_ui_update(85U, "scheduler", "runtime services", 2U);

  /* A boot slot is healthy once mandatory platform services are live. Optional
   * diagnostic applications exercise the same runtime but must not hold an
   * otherwise bootable system slot in its pending state. */
  if (system_slot_available() != 0U) {
    kassert(system_slot_mark_boot_success(boot) == XAIOS_OK);
  }
  operations_mark_boot_ready();

#if XAIOS_BOOT_TEST_APPS
  boot_apps_run_test_dispatch(worker_file);
#endif

  /* Stop preemption after the concurrent worker gate. Keep interrupt delivery
   * available for bounded userspace idle waits and VirtIO completions. */
  kassert(smp_set_scheduling_enabled(smp_cpu_id(), 0U) == XAIOS_OK);
  timer_disable();
  klog("kernel: preemption disabled; interrupt-backed idle waits retained\n");

  boot_apps_run_profile();

  boot_ui_update(90U, "runtime services", "IPv4 network readiness", 2U);

  telemetry_emit_boot_summary();

  if (persistent_network_ready == 0U) {
    klog("kernel: SSH service withheld; IPv4 network is not ready\n");
    boot_ui_error("network readiness", XAIOS_ERR_IO);
    for (;;) {
      xaios_cpu_wait();
    }
  }

  boot_sync_wall_clock();

  /* Boot drawing is finished here: what follows is a service that runs until
     the machine stops. Report what the display cost while the figure still
     covers a bounded, comparable amount of work. */
  virtio_gpu_report_transfer_cost();

  boot_apps_run_tail();
}
