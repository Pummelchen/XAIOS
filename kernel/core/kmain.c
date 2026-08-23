#include <xaios/assert.h>
#include <xaios/admin_control.h>
#include <xaios/agent_protocol.h>
#include <xaios/ahci.h>
#include <xaios/app_store.h>
#include <xaios/ai_cell.h>
#include <xaios/arch_cpu.h>
#include <xaios/ai_kernels.h>
#include <xaios/arena.h>
#include <xaios/arp.h>
#include <xaios/boot_info.h>
#include <xaios/boot_ui.h>
#include <xaios/core_lease.h>
#include <xaios/control_protocol.h>
#include <xaios/child_channel.h>
#include <xaios/dns.h>
#include <xaios/elf_loader.h>
#include <xaios/entropy.h>
#include <xaios/exception.h>
#include <xaios/gic.h>
#include <xaios/icmp.h>
#include <xaios/icmpv6.h>
#include <xaios/input.h>
#include <xaios/ipv6.h>
#include <xaios/ndp.h>
#include <xaios/ntp.h>
#include <xaios/operations.h>
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
#include <xaios/storage_admin.h>
#include <xaios/system_slot.h>
#include <xaios/service.h>
#include <xaios/smp.h>
#include <xaios/network_stack.h>
#include <xaios/net_device.h>
#include <xaios/network_config.h>
#include <xaios/numa.h>
#include <xaios/nvme.h>
#include <xaios/pci.h>
#include <xaios/smmu.h>
#include <xaios/spinlock.h>
#include <xaios/stack_canary.h>
#include <xaios/syscall.h>
#include <xaios/telemetry.h>
#include <xaios/timer.h>
#include <xaios/topology.h>
#include <xaios/thread.h>
#include <xaios/update.h>
#include <xaios/user.h>
#include <xaios/virtio_blk.h>
#include <xaios/virtio_rng.h>
#include <xaios/vfs_mutable.h>
#include <xaios/vfs_model.h>
#include <xaios/vmm.h>
#include <xaios/watchdog.h>
#if defined(__aarch64__)
#include <xaios/aarch64_acpi.h>
#include <xaios/aarch64_sve.h>
#endif

#ifndef XAIOS_BOOT_TEST_APPS
#define XAIOS_BOOT_TEST_APPS 0
#endif

#ifndef XAIOS_LIBC_TEST
#define XAIOS_LIBC_TEST 0
#endif

static const char g_vmm_rodata_probe[] = "vmm-rodata";
static uint64_t g_vmm_data_probe;
static virtio_block_handle_t *g_storage_admin_handle;
static virtio_block_handle_t *g_persistent_handle;

static void provision_read_only_config(const char *path) {
  const xaios_initramfs_file_t *file = 0;
  xaios_mfs_stat_t existing;
  if (mutable_fs_stat(path, &existing) == XAIOS_OK) {
    klog("kernel: preserved persistent config path=%s bytes=%lu\n", path,
         existing.size);
    return;
  }
  xaios_status_t status = initramfs_lookup(path, &file);
  if (status == XAIOS_ERR_NOT_FOUND) return;
  if (status != XAIOS_OK || file == 0 || file->base == 0 || file->size == 0U ||
      file->size > XAIOS_MFS_MAX_FILE_BYTES_V3 ||
      mutable_fs_write(path, file->base, file->size) != XAIOS_OK) {
    klog("kernel: failed to provision config path=%s\n", path);
    return;
  }
  klog("kernel: provisioned config path=%s bytes=%lu\n", path, file->size);
}

static void provision_ephemeral_credential(const char *path) {
  const xaios_initramfs_file_t *file = 0;
  xaios_status_t status = initramfs_lookup(path, &file);
  if (status == XAIOS_ERR_NOT_FOUND) return;
  if (status != XAIOS_OK || file == 0 || file->base == 0 || file->size == 0U ||
      file->size > XAIOS_MFS_MAX_FILE_BYTES_V3 ||
      mutable_fs_write(path, file->base, file->size) != XAIOS_OK) {
    klog("kernel: failed to provision credential path=%s\n", path);
    return;
  }
  klog("kernel: provisioned ephemeral credential path=%s bytes=%lu\n", path,
       file->size);
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

static int run_user_app(const char *path, uint32_t pid, uint64_t capabilities) {
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
  return exit_code;
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
  uint32_t persistent_network_ready = 0U;
  klog_init(boot);
  boot_ui_begin(boot);
  boot_ui_self_test();
  boot_ui_update(25U, "hardware handoff", "CPU and interrupts", 5U);
  klog("XAIOS kernel starting\n");
  kassert(boot->magic == XAIOS_BOOT_INFO_MAGIC);
  kassert(boot->version == XAIOS_BOOT_INFO_VERSION);

  klog("boot: memory_map=0x%lx size=%lu desc_size=%lu\n",
       boot->memory_map, boot->memory_map_size, boot->memory_descriptor_size);
  klog("boot: kernel=[0x%lx, 0x%lx)\n",
       boot->kernel_phys_base, boot->kernel_phys_end);

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
  vmm_self_test();
  boot_ui_update(45U, "memory management", "devices and storage", 3U);

  /* Map architecture interrupt/IOMMU resources and initialize. */
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

  /* Map ECAM and enumerate PCIe. */
  pci_init();
  pci_self_test();
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
  gic_init_platform();
  gic_self_test();
  boot_ui_update(48U, "platform devices", "storage discovery", 3U);

  xaios_nvme_self_test_result_t nvme_result;
  xaios_status_t nvme_status = nvme_self_test(&nvme_result);
  if (nvme_status != XAIOS_OK && nvme_status != XAIOS_ERR_NOT_FOUND) {
    klog("nvme: self-test failed status=%d\n", (int)nvme_status);
  }
  xaios_status_t ahci_status = ahci_init();
  if (ahci_status != XAIOS_OK && ahci_status != XAIOS_ERR_NOT_FOUND) {
    klog("ahci: initialization failed status=%d\n", (int)ahci_status);
  }

  boot_ui_update(49U, "storage discovery", "entropy and boot storage", 3U);
  virtio_rng_self_test();
  entropy_init(boot);
  entropy_self_test();
  if (boot->boot_image_size != 0U) {
    kassert(virtio_block_set_boot_memory(
                (void *)(uintptr_t)boot->boot_image_base,
                boot->boot_image_size) == XAIOS_OK);
  }
  boot_ui_update(50U, "entropy and boot storage", "boot storage validation", 3U);
  virtio_block_self_test();
  boot_ui_update(51U, "boot storage validation", "initial filesystem", 3U);
  initramfs_self_test();
  /* Snapshot state must land on the durable volume, not on vblk0: that device
     carries the initramfs/test image and the QEMU launcher attaches it with
     snapshot=on, so its writes are thrown away when the machine stops. Bind
     the dedicated persistent slot before the self-test runs, and reuse the
     same handle for MutableFS below. */
  if (virtio_block_open_slot(1U, &g_persistent_handle) == XAIOS_OK) {
    persistence_bind_block_device(g_persistent_handle);
  }
  if (virtio_block_is_read_only() != 0U && g_persistent_handle == 0) {
    persistence_runtime_init();
    klog("persistence: writable self-test skipped boot device is read-only\n");
    klog("mutable-fs: writable self-test deferred no persistent block device\n");
  } else {
    persistence_self_test();
    mutable_fs_self_test();
  }
  boot_ui_update(52U, "boot storage", "persistent filesystem", 3U);
  /* Prefer a standards-enumerated NVMe namespace when one has completed its
   * controller canary; QEMU retains its explicit VirtIO compatibility slot. */
  xaios_status_t persistent_status = nvme_status == XAIOS_OK
                                         ? mutable_fs_mount_device("/dev/nvme0n1")
                                         : XAIOS_ERR_NOT_FOUND;
  /* An enumerated NVMe namespace may be a test or model volume rather than
   * MutableFS storage. Preserve its contents and continue probing the
   * explicitly provisioned persistence devices instead of suppressing SSH. */
  if (persistent_status != XAIOS_OK && ahci_status == XAIOS_OK) {
    persistent_status = mutable_fs_mount_device("/dev/ahci0p0");
    if (persistent_status == XAIOS_OK) {
      klog("mutable-fs: using registered AHCI persistent data disk\n");
    }
  }
  if (persistent_status != XAIOS_OK) {
    /* vblk0 remains the immutable initramfs/test image. Open the dedicated
     * second VirtIO block device for durable MutableFS state. */
    xaios_status_t virtio_status =
        g_persistent_handle != 0
            ? XAIOS_OK
            : virtio_block_open_slot(1U, &g_persistent_handle);
    persistent_status = virtio_status == XAIOS_OK
                            ? mutable_fs_mount_device("/dev/vblk1")
                            : virtio_status;
    if (persistent_status == XAIOS_OK) {
      klog("mutable-fs: using registered QEMU persistent data disk\n");
    }
  }
  if (persistent_status == XAIOS_OK) {
    xaios_mfs_fsck_result_t fsck = mutable_fs_fsck();
    klog("kernel: persistent fsck valid=%u v%u files=%lu dirs=%lu\n",
         fsck.valid, fsck.version, fsck.files, fsck.directories);
    provision_read_only_config("/etc/xaios_authorized_keys");
    provision_read_only_config("/etc/xaios_sshd_users");
    provision_read_only_config("/etc/xaios_console_pin");
    provision_read_only_config("/etc/xapt.conf");
    provision_ephemeral_credential("/etc/xaios_ssh_client_identity");
    admin_control_init();
    admin_control_self_test();
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
  operations_init(persistent_status == XAIOS_OK ? 1U : 0U);
  kassert(vfs_mount_mutable_root() == XAIOS_OK);
  klog("vfs: MutableFS mounted at /\n");

  /* The boot loader selected this immutable system slot. Admit and validate
   * its redundant metadata before optional model-volume discovery so recovery
   * remains independent of model fixture work. */
  xaios_status_t system_slot_status = system_slot_init(boot);
  if (system_slot_status != XAIOS_OK) {
    klog("system-slot: unavailable status=%d\n", (int)system_slot_status);
  }
  system_slot_self_test();

#if defined(XAIOS_STORAGE_CRASH_AFTER_SYSTEM_BACKUP) || \
    defined(XAIOS_STORAGE_CRASH_AFTER_SYSTEM_PRIMARY)
  /* The crash gate exercises only redundant system metadata persistence. Do
   * not make that fault injection wait for unrelated model and diagnostic
   * fixture work later in the boot sequence. */
  if (system_slot_available() != 0U) {
    kassert(system_slot_mark_boot_success(boot) == XAIOS_OK);
  }
#endif

  boot_ui_update(55U, "persistent filesystem", "model and system volumes", 2U);
  xaios_status_t model_volume_status = vfs_mount_model_volume(4U);
  if (model_volume_status == XAIOS_OK) {
    vfs_model_self_test();
  } else {
    klog("modelfs: mount skipped status=%d\n", (int)model_volume_status);
  }
  xaios_status_t storage_admin_status =
      virtio_block_open_slot(5U, &g_storage_admin_handle);
  if (storage_admin_status == XAIOS_OK) {
    storage_admin_status = storage_admin_attach(
        virtio_block_device_h(g_storage_admin_handle), 1U);
  }
  if (storage_admin_status == XAIOS_OK) {
    klog("storage-admin: scratch device attached slot=5 mutation=enabled\n");
  } else {
    klog("storage-admin: scratch device unavailable status=%d\n",
         (int)storage_admin_status);
  }
  if (persistent_status == XAIOS_OK) {
    update_self_test();
    update_delivery_self_test();
  } else {
    klog("update: self-tests deferred no writable persistent filesystem\n");
  }
  app_store_init();
  boot_ui_update(60U, "devices and storage", "kernel services", 2U);
  network_config_reset_defaults();
  network_device_self_test();
  arp_self_test();
  ipv4_self_test();
  icmp_self_test();
  ipv6_self_test();
  icmpv6_self_test();
  ndp_self_test();
  sockbuf_self_test();
  routing_self_test();
  dns_self_test();
  ntp_self_test();
  operations_self_test();
  network_stack_self_test();
  syscall_self_test();
  user_process_table_init();
  user_process_lifecycle_self_test();
  user_scheduler_self_test();
  scheduler_init();
  scheduler_self_test();
  xaios_thread_runtime_init();
  elf_loader_self_test();
  service_supervisor_init();
  model_arena_self_test();
  ai_kernel_self_test();
  cpu_ai_runtime_self_test();
  ai_cell_self_test();
  agent_protocol_self_test();
  control_protocol_self_test();
  boot_ui_update(70U, "kernel services", "userspace services", 2U);
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
#if XAIOS_BOOT_TEST_APPS
  const xaios_initramfs_file_t *worker_file = 0;
#endif
  xaios_user_process_t init_process;
  xaios_user_process_t manager_process;
  const xaios_initramfs_config_t *init_config = initramfs_config();
  kassert(init_config != 0);
  kassert(initramfs_lookup(init_config->service_path, &init_file) == XAIOS_OK);
  kassert(initramfs_lookup(init_config->service_manager_path, &manager_file) ==
          XAIOS_OK);
#if XAIOS_BOOT_TEST_APPS
  kassert(initramfs_lookup("/bin/xaios-worker", &worker_file) == XAIOS_OK);
#endif
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
  if (manager_exit_code != 0 && persistent_status != XAIOS_OK) {
    klog("kernel: service-manager deferred exit_code=%u no writable persistent storage status=%d\n",
         (unsigned)manager_exit_code, (int)persistent_status);
  } else {
    kassert(manager_exit_code == 0);
    klog("kernel: /bin/service-manager returned to kernel exit_code=%u\n",
         (unsigned)manager_exit_code);
  }
  user_process_reclaim_address_space(&manager_process);

  /* Initialize persistent network for real TX/RX */
  if (network_device_init_persistent() == XAIOS_OK) {
    if (network_device_kind() == XAIOS_NETWORK_DEVICE_E1000E &&
        network_config_dhcp(UINT64_C(6000000000)) != XAIOS_OK) {
      klog("kernel: DHCP configuration failed for e1000e\n");
      boot_ui_error("network DHCP", XAIOS_ERR_IO);
      goto persistent_network_done;
    }
    network_init_persistent();
    dns_init();
    dns_configure(network_config_dns_server());
    klog("kernel: persistent network stack enabled device=%s\n",
         network_device_name());
    persistent_network_ready = 1U;
    boot_ui_update(80U, "network stack", "scheduler", 2U);
  } else {
    klog("kernel: persistent network init skipped\n");
    boot_ui_error("network-stack", XAIOS_ERR_IO);
  }
persistent_network_done:

  /* Initialize preemptive scheduler infrastructure */
  scheduler_lock();
#if defined(__x86_64__)
  uint64_t initial_block_interrupts = virtio_block_interrupt_count();
#endif
  gic_enable_full();
  if (nvme_status == XAIOS_OK) {
    kassert(nvme_interrupt_self_test() == XAIOS_OK);
  }
#if defined(__x86_64__)
  uint64_t interrupt_drain_deadline =
      timer_now_ns() + UINT64_C(100000000);
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
    klog("virtio-blk: x86 completion canary passed mode=bounded-poll status=%d\n",
         (int)interrupt_status);
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
#endif

  /* Stop preemption after the concurrent worker gate. Keep interrupt delivery
   * available for bounded userspace idle waits and VirtIO completions. */
  kassert(smp_set_scheduling_enabled(smp_cpu_id(), 0U) == XAIOS_OK);
  timer_disable();
  klog("kernel: preemption disabled; interrupt-backed idle waits retained\n");

  const uint64_t sshd_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_FS_READ |
      XAIOS_CAP_FS_WRITE | XAIOS_CAP_NET_SOCKET | XAIOS_CAP_REMOTE_LOGIN |
      XAIOS_CAP_NET | XAIOS_CAP_TIME | XAIOS_CAP_RANDOM |
      XAIOS_CAP_CONSOLE | XAIOS_CAP_CONTROL_QUERY |
      XAIOS_CAP_CONTROL_ADMIN | XAIOS_CAP_STORAGE_READ |
      XAIOS_CAP_STORAGE_MOUNT | XAIOS_CAP_STORAGE_FORMAT |
      XAIOS_CAP_STORAGE_PARTITION | XAIOS_CAP_STORAGE_REPAIR |
      XAIOS_CAP_STORAGE_RESIZE | XAIOS_CAP_STORAGE_TRIM |
      XAIOS_CAP_MODEL_STAGE | XAIOS_CAP_MODEL_ACTIVATE |
      XAIOS_CAP_OSCTL | XAIOS_CAP_SERVICE_CONTROL | XAIOS_CAP_UPDATE |
      XAIOS_CAP_ADMIN;

#if XAIOS_BOOT_TEST_APPS
  /* Deterministic QEMU gate profile: execute diagnostic applications once. */
  const uint64_t shell_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_FS_READ |
      XAIOS_CAP_FS_WRITE | XAIOS_CAP_OSCTL | XAIOS_CAP_TIME |
      XAIOS_CAP_NET | XAIOS_CAP_NET_SOCKET | XAIOS_CAP_REMOTE_LOGIN;
  const uint64_t hello_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT;
  const uint64_t c99_demo_caps = XAIOS_CAP_CONSOLE | XAIOS_CAP_EXIT;
  const uint64_t xaiosctl_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT |
      XAIOS_CAP_TIME | XAIOS_CAP_CONTROL_QUERY | XAIOS_CAP_STORAGE_READ;
  const uint64_t sysinfo_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_TIME;
  const uint64_t systest_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT |
      XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE;
  const uint64_t smptest_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT |
      XAIOS_CAP_OSCTL | XAIOS_CAP_SMP | XAIOS_CAP_THREADS;
  const uint64_t nettest_caps = XAIOS_CAP_LOG | XAIOS_CAP_EXIT |
      XAIOS_CAP_OSCTL | XAIOS_CAP_NET | XAIOS_CAP_TIME;
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
  run_user_app("/bin/xaiosctl", 7, xaiosctl_caps);
  run_user_app("/bin/hello", 8, hello_caps);
  run_user_app("/bin/sysinfo", 9, sysinfo_caps);
  run_user_app("/bin/systest", 10, systest_caps);
  run_user_app("/bin/smptest", 11, smptest_caps);
  run_user_app("/bin/nettest", 12, nettest_caps);
  run_user_app("/bin/lstm-xor", 13, lstm_caps);
  run_user_app("/bin/sshtest", 14, sshtest_caps);
  run_user_app("/bin/mltest", 15, mltest_caps);
  run_user_app("/bin/posix-shell", 16, posix_shell_caps);
  run_user_app("/bin/agenttest", 17, agenttest_caps);
  kassert(run_user_app("/bin/helloworldc99", 23U, c99_demo_caps) == 0);
#else
  klog("kernel: boot diagnostics disabled; utilities are SSH on-demand\n");
#endif

#if XAIOS_LIBC_TEST
  const uint64_t libc_test_caps =
      XAIOS_CAP_EXIT | XAIOS_CAP_CONSOLE | XAIOS_CAP_TIME |
      XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE | XAIOS_CAP_THREADS;
  kassert(run_user_app("/bin/c99-runtime-smoke", 19U, libc_test_caps) == 0);
  kassert(run_user_app("/bin/c99-main-void", 20U, libc_test_caps) == 0);
  kassert(run_user_app("/bin/c99-exit-probe", 21U, libc_test_caps) == 23);
  kassert(run_user_app("/bin/c99-abort-probe", 22U, libc_test_caps) == 134);
  kassert(run_user_app("/bin/c99-thread-context", 24U, libc_test_caps) ==
          0);
  klog("C99-TERMINATION-PROBES-PASS\n");
#endif

  boot_ui_update(90U, "runtime services", "IPv4 network readiness", 2U);

  telemetry_emit_boot_summary();

  if (persistent_network_ready == 0U) {
    klog("kernel: SSH service withheld; IPv4 network is not ready\n");
    boot_ui_error("network readiness", XAIOS_ERR_IO);
    for (;;) {
      xaios_cpu_wait();
    }
  }

  klog("kernel: starting persistent /bin/sshd service\n");
  int sshd_exit =
      run_user_app("/bin/sshd", XAIOS_BOOT_TEST_APPS ? 18U : 3U, sshd_caps);
  boot_ui_error("sshd", sshd_exit);

  for (;;) {
    xaios_cpu_wait();
  }
}
