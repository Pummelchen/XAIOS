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
#include "boot_platform_internal.h"
#include "boot_runtime_internal.h"

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

/* The scratch disk the boot path attaches for storage administration. */
#define XAIOS_INSTALL_TARGET "/dev/vblk5"

extern char __kernel_start[];

void kmain(const xaios_boot_info_t *boot) {
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

  /* Interrupts, timer, canary, SMP, NUMA, physical and virtual memory, and
     the firmware framebuffer mapping; see boot_platform.c. */
  boot_cpu_memory_bring_up(boot);

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
  boot_platform_bring_up(boot);
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

  boot_runtime_run(boot, persistent_status, nvme_status);
}
