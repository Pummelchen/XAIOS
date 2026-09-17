#include <xaios/device_window.h>
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
#include <xaios/dhcpv6.h>
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
#include <xaios/gpt.h>
#include <xaios/partition_device.h>
#include <xaios/klog.h>
#include <xaios/version.h>
#include <xaios/virtio_gpu.h>
#include <xaios/model_arena.h>
#include <xaios/xaiboot_fs.h>
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
#include <xaios/fat.h>
#include <xaios/install.h>
#include <xaios/storage_admin.h>
#include <xaios/crash_writer.h>
#include <xaios/ram_residency.h>
#include <xaios/ram_block.h>
#include <xaios/setup_apply.h>
#include <xaios/engine_sha256_dispatch.h>
#include <xaios/storage_bench.h>
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
#include <xaios/virtio_console.h>
#include <xaios/virtio_rng.h>
#include <xaios/vfs_xaiboot.h>
#include <xaios/vfs_xaifs.h>
#include <xaios/vmm.h>
#include <xaios/vmxnet3.h>
#include <xaios/watchdog.h>
#if defined(__aarch64__)
#include <xaios/aarch64_acpi.h>
#include <xaios/aarch64_sve.h>
#endif

#include "boot_apps_internal.h"
#include "boot_storage_internal.h"

/* Two NTP retransmits plus margin, well inside the client's own 10s
   timeout, so a filtered UDP/123 costs a bounded pause and nothing more. */
#define BOOT_NTP_DEADLINE_NS UINT64_C(6000000000)

static const char g_vmm_rodata_probe[] = "vmm-rodata";
static uint64_t g_vmm_data_probe;
static virtio_block_handle_t *g_storage_admin_handle;

static void provision_read_only_config(const char *path) {
  const xaios_initramfs_file_t *file = 0;
  xaios_xbfs_stat_t existing;
  if (xaiboot_fs_stat(path, &existing) == XAIOS_OK) {
    klog("kernel: preserved persistent config path=%s bytes=%lu\n", path,
         existing.size);
    return;
  }
  xaios_status_t status = initramfs_lookup(path, &file);
  if (status == XAIOS_ERR_NOT_FOUND) return;
  if (status != XAIOS_OK || file == 0 || file->base == 0 || file->size == 0U ||
      file->size > XAIOS_XBFS_MAX_FILE_BYTES_V3 ||
      xaiboot_fs_write(path, file->base, file->size) != XAIOS_OK) {
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
      file->size > XAIOS_XBFS_MAX_FILE_BYTES_V3 ||
      xaiboot_fs_write(path, file->base, file->size) != XAIOS_OK) {
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

/* Set the wall clock from NTP before any service starts.

   The clock is otherwise whatever the RTC reports, and QEMU's PL031 commonly
   reports epoch zero, leaving the system in 1970. Anything that checks a
   certificate validity window then sees every certificate as not-yet-valid,
   which is how xapt fails against the updater's publicly issued certificate.

   Bounded and non-fatal. The default server is a bare address, so this needs
   no DNS, but UDP/123 is filtered on some networks and a boot must not stall
   waiting for a reply that will never arrive. */

/* The scratch disk the boot path attaches for storage administration. */
#define XAIOS_INSTALL_TARGET "/dev/vblk5"

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

extern char __kernel_start[];

void kmain(const xaios_boot_info_t *boot) {
  uint32_t persistent_network_ready = 0U;
  klog_init(boot);
  /* Start capturing before any subsystem can fail. A normal boot redraws the
     progress display over the serial console, so a failure explanation is
     cleared from the screen moments before a panic replaces it; the ring is
     what lets the panic screen say why, not just where. */
  klog_ring_init();
  klog_ring_self_test();
  boot_ui_begin(boot);
  boot_ui_self_test();
  boot_ui_update(25U, "hardware handoff", "CPU and interrupts", 5U);
  klog("XAIOS %s kernel starting\n", XAIOS_BUILD_LABEL);
  /* Where this kernel landed, on every boot rather than only in a panic.
     The kernel is position-independent, so a backtrace address means nothing
     without this number, and until now the only thing that printed it was the
     panic screen -- which is to say it was available exactly when the machine
     was already too broken to be sure of anything. B-15 was recorded as
     fifteen addresses with no base for that reason. With it in the ordinary
     console, any console kept from a boot that later dies is enough to read
     its trace, and a panic that fails to print its own header is no longer
     the end of the enquiry.
     It also makes the placement itself observable: this address is the one
     firmware chose, rounded up to the strongest alignment the segments ask
     for, which is what B-19 turned out to be about. */
  klog("kernel: load base %p offset_in_64k %lu\n",
       (void *)(uintptr_t)__kernel_start,
       (unsigned long)((uintptr_t)__kernel_start & 0xFFFFU));
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

#if defined(XAIOS_PANIC_SELFTEST)
  /* A deliberate assertion, so the panic path can be proven on the machine
     where it matters rather than argued about.
     B-15 fired once on VMware Fusion and left fifteen stack addresses and
     nothing else. The panic screen was then taught to print the kernel's
     load base and to replay the end of the log ring, which together turn
     those addresses back into function names and say what the kernel was
     doing. None of that had ever been exercised on Fusion -- only reasoned
     about -- and a diagnostic that has never run is not evidence.
     Placed here on purpose: late enough that the console, the framebuffer
     and the log ring all exist, so the panic goes out over the serial line
     and to the cyan screen exactly as the real one did. Compiled out of
     every build that does not ask for it. */
  kassert(0 == 1);
#endif

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

  /* Storage is discovered and the persistent volume mounted in one stage;
     the mount status and the durability of what was mounted come back for
     the filesystem and lifecycle work that follows. */
  xaios_status_t nvme_status = XAIOS_ERR_NOT_FOUND;
  uint32_t durable_state = 1U;
  xaios_status_t persistent_status =
      boot_storage_bring_up(boot, &nvme_status, &durable_state);

  if (persistent_status == XAIOS_OK) {
    xaios_xbfs_fsck_result_t fsck = xaiboot_fs_fsck();
    klog("kernel: persistent fsck valid=%u v%u files=%lu dirs=%lu\n",
         fsck.valid, fsck.version, fsck.files, fsck.directories);
    provision_read_only_config("/etc/xaios_authorized_keys");
    provision_read_only_config("/etc/xaios_sshd_users");
    provision_read_only_config("/etc/xaios_console_pin");
    provision_read_only_config("/etc/xapt.conf");
    provision_ephemeral_credential("/etc/xaios_ssh_client_identity");
    admin_control_init();
    admin_control_self_test();
    /* Capture already runs; this only adds the persistent flush path. */
    (void)klog_ring_enable_persistence();
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
  operations_init(persistent_status == XAIOS_OK ? 1U : 0U, durable_state);
  kassert(vfs_mount_mutable_root() == XAIOS_OK);
  /* Expose the boot image's /bin read-only, so the userspace ls that ships
     as /bin/ls can list the directory it lives in. */
  kassert(vfs_mount_initramfs("/bin") == XAIOS_OK);
  /* A machine with no durable volume has no /etc at all: xaibootFS mounts but
     backs nothing, so every read under / fails and the credentials
     provision_read_only_config would have copied were never copied. sshd then
     finds no users, locks the local console and refuses to start its network
     server -- a live boot with no way in, which is precisely the boot a USB
     stick performs on a machine that has not been installed yet.

     The credentials exist; they are in the initramfs, which is where the copy
     reads them from. So serve /etc from there when there is nowhere to copy
     them to. Read-only is not a compromise here -- a live boot has nowhere to
     persist a change to them anyway, and saying so is better than appearing
     to accept one. */
  if (persistent_status != XAIOS_OK) {
    xaios_status_t etc_status = vfs_mount_initramfs("/etc");
    klog("vfs: no durable volume; /etc served read-only from initramfs "
         "status=%d\n", (int)etc_status);
  }
  klog("vfs: xaibootFS mounted at /\n");

  /* The boot loader selected this immutable system slot. Admit and validate
   * its redundant metadata before optional xaifs discovery so recovery
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
  /* Before the model volume, because mounting it verifies a signed manifest
     and every read after that hashes what it returns. */
  engine_sha256_dispatch_init();
  xaios_status_t xai_fs_status = vfs_mount_xai_fs(4U);
  if (xai_fs_status == XAIOS_OK) {
#if XAIOS_CRASH_WRITER
    /* Instead of the self-test, not alongside it: the crash gate boots a
       volume whose one staging package is the thing being ingested, and the
       self-test would write its own pattern into that package's first chunk
       and fail the manifest the fixture signed. This call does not return
       until the ingest finishes or the machine dies, which is the point. */
    crash_writer_run();
#else
    vfs_xaifs_self_test();
#endif
  } else {
    klog("xaifs: mount skipped status=%d\n", (int)xai_fs_status);
  }
  /* The configured window, or the only disk nothing else has taken. See the
     function: a fixed position cannot be satisfied by a machine with fewer
     disks than the test bench, which is every machine that is not the bench. */
  xaios_status_t storage_admin_status =
      virtio_block_open_administration_window(5U, BOOT_DISK_SCAN_LIMIT,
                                             &g_storage_admin_handle);
  if (storage_admin_status == XAIOS_OK) {
    storage_admin_status = storage_admin_attach(
        virtio_block_device_h(g_storage_admin_handle), 1U);
  }
  if (storage_admin_status == XAIOS_OK) {
    klog("storage-admin: scratch device attached slot=5 mutation=enabled\n");
    storage_admin_self_test();
#if XAIOS_INSTALL_SELF_TEST
    /* Gate-only. This writes a partition table and a filesystem onto whatever
       is in slot 5 without an operator asking for it, which is the right
       thing for a gate that attaches a scratch disk and exactly the wrong
       thing to compile into an image people boot on their own machines. The
       operator-driven install is the control-protocol path, which requires
       the target's own GUID as confirmation; this one confirms nothing
       because there is nobody to confirm with. */
    boot_storage_install_self_test(XAIOS_INSTALL_TARGET, boot);
#endif
#if XAIOS_STORAGE_BENCH
    storage_bench_run(XAIOS_INSTALL_TARGET);
#endif
  } else {
    klog("storage-admin: scratch device unavailable status=%d\n",
         (int)storage_admin_status);
  }
#if XAIOS_STORAGE_BENCH
  /* Not inside the storage-administration branch above: that branch depends
     on a scratch disk being attached, and whether /models can be measured has
     nothing to do with whether one is. */
  storage_bench_model();
#endif
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
  /* After every driver has asked for its registers, and not before: the
     property is that no two of them were given the same address, and that
     cannot be checked until they have all asked. */
  device_window_self_test();
  arp_self_test();
  ipv4_self_test();
  icmp_self_test();
  ipv6_self_test();
  icmpv6_self_test();
  ndp_self_test();
  dhcpv6_self_test();
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
  /* And through each architecture's own timer path, which is where the
     trap-frame mapping lives (B-129). */
  platform_scheduler_tick_self_test();
  platform_kernel_preemption_self_test();
  xaios_thread_runtime_init();
  elf_loader_self_test();
  service_supervisor_init();
  /* Secondaries become leasable here, before the self-tests that need one.
     A platform that already had them online does nothing. */
  kassert(smp_bring_secondaries_online() == XAIOS_OK);
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

#if defined(XAIOS_FAULT_TEST_PAGE) || defined(XAIOS_FAULT_TEST_RO) || \
    defined(XAIOS_FAULT_TEST_NX)
/* Read out of the finished binary by scripts/build-arch-image.sh and
 * scripts/build-netboot-image.sh, and kept in step with them by
 * tests/repository/check-fault-test-marker.py. Changing the text here without
 * changing it there would leave two scripts looking for a string that no
 * longer exists, which is the quiet half of this failure rather than the loud
 * one. */
#define XAIOS_FAULT_TEST_BUILD_MARKER \
  "fault-test-build: this kernel faults on purpose and must not be shipped"
  /* A kernel built to fault on purpose has to say so in its own bytes.
   *
   * The three branches below are each distinctive once they run, and two of
   * them leave a distinctive string behind; the page-fault one calls a helper
   * that is compiled into every kernel, so it leaves nothing at all. That
   * mattered the day a packaging script picked up build/kernel/kernel.elf
   * while a fault build was in the tree and wrapped it into a netboot binary:
   * the file looked exactly like a release binary, and the only way anyone
   * found out was booting it and watching it halt.
   *
   * This marker is unconditional across all three, so a script that reads the
   * finished artifact can refuse it without booting anything --
   * scripts/build-arch-image.sh and scripts/build-netboot-image.sh both do.
   * It exists only in these builds: a release kernel has no such string,
   * because none of this is compiled into one. */
  klog("%s\n", XAIOS_FAULT_TEST_BUILD_MARKER);
#endif

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
