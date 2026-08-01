#include <xaios/assert.h>
#include <xaios/agent_protocol.h>
#include <xaios/ai_cell.h>
#include <xaios/arena.h>
#include <xaios/arp.h>
#include <xaios/boot_info.h>
#include <xaios/core_lease.h>
#include <xaios/elf_loader.h>
#include <xaios/exception.h>
#include <xaios/gic.h>
#include <xaios/icmp.h>
#include <xaios/icmpv6.h>
#include <xaios/ipv6.h>
#include <xaios/ndp.h>
#include <xaios/routing.h>
#include <xaios/socket_buffer.h>
#include <xaios/initramfs.h>
#include <xaios/cpu_ai_runtime.h>
#include <xaios/ipv4.h>
#include <xaios/kheap.h>
#include <xaios/klog_ring.h>
#include <xaios/git_workspace.h>
#include <xaios/klog.h>
#include <xaios/model_arena.h>
#include <xaios/mutable_fs.h>
#include <xaios/pmm.h>
#include <xaios/persistence.h>
#include <xaios/rate_limit.h>
#include <xaios/remote_login.h>
#include <xaios/rtc.h>
#include <xaios/sandbox.h>
#include <xaios/scheduler.h>
#include <xaios/security.h>
#include <xaios/sha256.h>
#include <xaios/source_index.h>
#include <xaios/service.h>
#include <xaios/smp.h>
#include <xaios/network_stack.h>
#include <xaios/numa.h>
#include <xaios/pci.h>
#include <xaios/smmu.h>
#include <xaios/spinlock.h>
#include <xaios/stack_canary.h>
#include <xaios/syscall.h>
#include <xaios/telemetry.h>
#include <xaios/timer.h>
#include <xaios/topology.h>
#include <xaios/update.h>
#include <xaios/user.h>
#include <xaios/virtio_blk.h>
#include <xaios/virtio_net.h>
#include <xaios/vmm.h>
#include <xaios/watchdog.h>

static const char g_vmm_rodata_probe[] = "vmm-rodata";
static uint64_t g_vmm_data_probe;

static void early_spinlock_self_test(void) {
  xaios_spinlock_t lock = XAIOS_SPINLOCK_INIT;
  kassert(smp_online_count() <= 1U);
  kassert(xaios_spin_trylock(&lock) == 1);
  kassert(xaios_spin_trylock(&lock) == 0);
  xaios_spin_unlock(&lock);
  kassert(lock.next_ticket == 0U);
  kassert(lock.serve == 0U);
  kassert(lock.guard == 0U);
  kassert(xaios_spin_trylock(&lock) == 1);
  xaios_spin_unlock(&lock);
  klog("spinlock: early single-core try-lock self-test passed\n");
}

static void run_user_app(const char *path, uint32_t pid, uint64_t capabilities) {
  const xaios_initramfs_file_t *file = 0;
  xaios_user_process_t process;
  kassert(initramfs_lookup(path, &file) == XAIOS_OK);
  kassert(user_load_process(file, pid, capabilities, &process) == XAIOS_OK);
  int exit_code = user_process_run(&process);
  if (exit_code != 0) {
    klog("kernel: WARNING %s exited with non-zero status=%d\n",
         path, exit_code);
  }
  klog("kernel: %s returned to kernel exit_code=%d\n",
       path, exit_code);
  user_process_reclaim_address_space(&process);
}

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

void kmain(const xaios_boot_info_t *boot) {
  klog_init(boot);
  klog("XAIOS kernel starting\n");
  kassert(boot->magic == XAIOS_BOOT_INFO_MAGIC);
  kassert(boot->version == XAIOS_BOOT_INFO_VERSION);

  klog("boot: memory_map=0x%lx size=%lu desc_size=%lu\n",
       boot->memory_map, boot->memory_map_size, boot->memory_descriptor_size);
  klog("boot: kernel=[0x%lx, 0x%lx)\n",
       boot->kernel_phys_base, boot->kernel_phys_end);

  exception_init();
  exception_self_test();
  early_spinlock_self_test();
  timer_init();
  timer_self_test();
  stack_canary_init();
  stack_canary_self_test();
  smp_init_qemu_virt();
  smp_self_test();

  topology_init();          /* Build CPU hierarchy for hierarchical scheduler */
  topology_self_test();

  numa_init(boot);
  numa_self_test();

  pmm_init(boot);
  vmm_init(boot);
  vmm_self_test();

  /* Map SMMU MMIO and initialize */
  map_mmio_range(XAIOS_SMMU_MMIO_BASE, 0x10000);
  map_mmio_range(XAIOS_SMMU_MMIO_PAGE1, 0x10000);
  smmu_init();
  smmu_self_test();

  map_mmio_range(boot->uart_base, 4096);
  map_mmio_range(UINT64_C(0x08000000), UINT64_C(0x20000));
  map_mmio_range(UINT64_C(0x080A0000),
                 (uint64_t)smp_online_count() * UINT64_C(0x20000));
  map_mmio_range(UINT64_C(0x0a000000), UINT64_C(0x4000));

  /* Map ECAM and enumerate PCIe */
  pci_init();
  pci_self_test();

  /* Map RTC MMIO and initialize real-time clock */
  map_mmio_range(XAIOS_PL031_RTC_BASE, 4096);
  rtc_init();
  wall_time_calibrate();
  rtc_self_test();

  /* Initialize watchdog timer */
  watchdog_init();
  watchdog_self_test();

  klog("VMM MMIO device mappings installed\n");
  kheap_self_test();
  arena_manager_init();
  arena_self_test();
  rate_limit_init();
  rate_limit_self_test();
  security_self_test();
  remote_login_self_test();
  source_index_runtime_init();
  source_index_self_test();
  git_workspace_runtime_init();
  git_workspace_self_test();
  sandbox_self_test();
  core_lease_self_test();
  uint64_t translated = 0;
  uint32_t flags = 0;
  kassert(vmm_translate((uint64_t)(uintptr_t)&kmain, &translated, &flags) == XAIOS_OK);
  kassert(translated == (uint64_t)(uintptr_t)&kmain);
  kassert((flags & XAIOS_VMM_EXECUTABLE) != 0);
  kassert((flags & XAIOS_VMM_DEVICE) == 0);
  kassert(vmm_translate((uint64_t)(uintptr_t)g_vmm_rodata_probe, &translated, &flags) == XAIOS_OK);
  kassert(translated == (uint64_t)(uintptr_t)g_vmm_rodata_probe);
  kassert((flags & XAIOS_VMM_WRITABLE) == 0);
  kassert((flags & XAIOS_VMM_EXECUTABLE) == 0);
  kassert(vmm_translate((uint64_t)(uintptr_t)&g_vmm_data_probe, &translated, &flags) == XAIOS_OK);
  kassert(translated == (uint64_t)(uintptr_t)&g_vmm_data_probe);
  kassert((flags & XAIOS_VMM_WRITABLE) != 0);
  kassert((flags & XAIOS_VMM_EXECUTABLE) == 0);
  kassert(vmm_translate(boot->uart_base, &translated, &flags) == XAIOS_OK);
  kassert(translated == boot->uart_base);
  kassert((flags & XAIOS_VMM_DEVICE) != 0);
  kassert((flags & XAIOS_VMM_EXECUTABLE) == 0);
  klog("VMM translation test passed\n");
  gic_init_qemu_virt();
  gic_self_test();

  virtio_block_self_test();
  persistence_self_test();
  mutable_fs_self_test();
  /* The QEMU runner pins the persistent disk to VirtIO-MMIO slot 1. */
  xaios_status_t persistent_status = mutable_fs_mount_persistent(1);
  if (persistent_status == XAIOS_OK) {
    xaios_mfs_fsck_result_t fsck = mutable_fs_fsck();
    klog("kernel: persistent fsck valid=%u v%u files=%lu dirs=%lu\n",
         fsck.valid, fsck.version, fsck.files, fsck.directories);
    /* Initialize persistent log ring buffer */
    klog_ring_init();
    klog_ring_self_test();
    /* Increment boot counter for recovery detection */
    boot_counter_increment();
    if (boot_in_recovery_mode()) {
      klog("boot: RECOVERY MODE -- attempting update recovery\n");
      update_recover_boot();
      boot_counter_reset();
    }
  } else {
    klog("kernel: persistent mount skipped status=%d\n", (int)persistent_status);
  }
  update_self_test();
  update_delivery_self_test();
  virtio_net_self_test();
  arp_self_test();
  ipv4_self_test();
  icmp_self_test();
  ipv6_self_test();
  icmpv6_self_test();
  ndp_self_test();
  sockbuf_self_test();
  routing_self_test();
  network_stack_self_test();
  initramfs_self_test();
  syscall_self_test();
  user_process_table_init();
  user_process_lifecycle_self_test();
  user_scheduler_self_test();
  scheduler_init();
  scheduler_self_test();
  elf_loader_self_test();
  service_supervisor_init();
  model_arena_self_test();
  cpu_ai_runtime_self_test();
  ai_cell_self_test();
  agent_protocol_self_test();
  telemetry_emit_boot_summary();

  /* Flush logs to persistent storage */
  klog_flush();

  /* Boot completed successfully -- reset boot counter */
  boot_counter_reset();

#if defined(XAIOS_FAULT_TEST_PAGE)
  exception_trigger_page_fault_for_test();
#elif defined(XAIOS_FAULT_TEST_RO)
  klog("exceptions: triggering controlled rodata write fault\n");
  volatile char *ro = (volatile char *)(uintptr_t)g_vmm_rodata_probe;
  *ro = 'X';
#elif defined(XAIOS_FAULT_TEST_NX)
  klog("exceptions: triggering controlled NX execute fault\n");
  void (*bad_exec)(void) = (void (*)(void))(uintptr_t)&g_vmm_data_probe;
  bad_exec();
#endif

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
  const xaios_initramfs_file_t *worker_file = 0;
  xaios_user_process_t init_process;
  xaios_user_process_t manager_process;
  const xaios_initramfs_config_t *init_config = initramfs_config();
  kassert(init_config != 0);
  kassert(initramfs_lookup(init_config->service_path, &init_file) == XAIOS_OK);
  kassert(initramfs_lookup(init_config->service_manager_path, &manager_file) ==
          XAIOS_OK);
  kassert(initramfs_lookup("/bin/xaios-worker", &worker_file) == XAIOS_OK);
  kassert(user_load_init(init_file, &init_process) == XAIOS_OK);
  int init_exit_code = user_process_run(&init_process);
  kassert(init_exit_code == 0);
  klog("kernel: /init returned to kernel exit_code=%u\n",
       (unsigned)init_exit_code);
  user_process_reclaim_address_space(&init_process);

  kassert(user_load_process(manager_file, 2,
                            XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_OSCTL |
                                XAIOS_CAP_FS_READ | XAIOS_CAP_SERVICE_CONTROL |
                                XAIOS_CAP_ADMIN | XAIOS_CAP_FS_WRITE,
                            &manager_process) == XAIOS_OK);
  kassert(service_start(init_config->service_manager_path) == XAIOS_OK);
  int manager_exit_code = user_process_run(&manager_process);
  kassert(manager_exit_code == 0);
  klog("kernel: /bin/service-manager returned to kernel exit_code=%u\n",
       (unsigned)manager_exit_code);
  user_process_reclaim_address_space(&manager_process);

  /* Initialize persistent network for real TX/RX */
  if (virtio_net_init_persistent() == XAIOS_OK) {
    network_init_persistent();
    klog("kernel: persistent network stack enabled\n");
  } else {
    klog("kernel: persistent network init skipped\n");
  }

  /* Initialize preemptive scheduler infrastructure */
  gic_enable_full();
  timer_enable_periodic(XAIOS_SCHEDULER_DEFAULT_TICK_HZ);
  kassert(smp_set_scheduling_enabled(smp_cpu_id(), 1U) == XAIOS_OK);
  smp_release_secondary_schedulers();
  klog("kernel: preemptive scheduler infrastructure enabled\n");

  for (uint32_t pid = 3; pid <= 5; ++pid) {
    xaios_user_process_t worker_process;
    kassert(user_load_process(worker_file, pid, XAIOS_CAP_LOG | XAIOS_CAP_EXIT,
                              &worker_process) == XAIOS_OK);
    kassert(user_process_make_runnable(pid, 2) == XAIOS_OK);
    kassert(user_process_snapshot(pid, &worker_process) == XAIOS_OK);
    kassert(service_start("/bin/xaios-worker") == XAIOS_OK);
    int worker_exit_code = user_process_run(&worker_process);
    kassert(worker_exit_code == 0);
    klog("kernel: /bin/xaios-worker pid=%u returned to kernel exit_code=%u\n",
         pid, (unsigned)worker_exit_code);
    user_process_reclaim_address_space(&worker_process);
  }

  /* Disable preemptive infrastructure after concurrent workers */
  kassert(smp_set_scheduling_enabled(smp_cpu_id(), 0U) == XAIOS_OK);
  timer_disable();
  gic_disable_full();

  /* Per-app least-privilege capability masks */
  const uint64_t shell_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_FS_READ |
      XAIOS_CAP_FS_WRITE | XAIOS_CAP_OSCTL | XAIOS_CAP_TIME |
      XAIOS_CAP_NET | XAIOS_CAP_NET_SOCKET | XAIOS_CAP_REMOTE_LOGIN;
  const uint64_t hello_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT;
  const uint64_t sysinfo_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_TIME;
  const uint64_t systest_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT |
      XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE;
  const uint64_t smptest_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT |
      XAIOS_CAP_OSCTL | XAIOS_CAP_SMP | XAIOS_CAP_THREADS;
  const uint64_t nettest_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT |
      XAIOS_CAP_OSCTL | XAIOS_CAP_NET;
  const uint64_t lstm_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_CPU_AI |
      XAIOS_CAP_ML;
  const uint64_t sshtest_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_NET |
      XAIOS_CAP_NET_SOCKET | XAIOS_CAP_REMOTE_LOGIN;
  const uint64_t mltest_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_CPU_AI |
      XAIOS_CAP_ML;
  const uint64_t posix_shell_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT |
      XAIOS_CAP_REMOTE_LOGIN;
  const uint64_t agenttest_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_AGENT |
      XAIOS_CAP_CPU_AI | XAIOS_CAP_ML;

  run_user_app("/bin/xaios-shell", 6, shell_caps);
  run_user_app("/bin/hello", 7, hello_caps);
  run_user_app("/bin/sysinfo", 8, sysinfo_caps);
  run_user_app("/bin/systest", 9, systest_caps);
  run_user_app("/bin/smptest", 10, smptest_caps);
  run_user_app("/bin/nettest", 11, nettest_caps);
  run_user_app("/bin/lstm-xor", 12, lstm_caps);
  run_user_app("/bin/sshtest", 13, sshtest_caps);
  run_user_app("/bin/mltest", 14, mltest_caps);
  run_user_app("/bin/posix-shell", 15, posix_shell_caps);
  run_user_app("/bin/agenttest", 16, agenttest_caps);

  telemetry_emit_boot_summary();

  for (;;) {
    __asm__ volatile("wfe");
  }
}
