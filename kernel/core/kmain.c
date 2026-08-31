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

/* Two NTP retransmits plus margin, well inside the client's own 10s
   timeout, so a filtered UDP/123 costs a bounded pause and nothing more. */
#define BOOT_NTP_DEADLINE_NS UINT64_C(6000000000)

static const char g_vmm_rodata_probe[] = "vmm-rodata";
static uint64_t g_vmm_data_probe;
static virtio_block_handle_t *g_storage_admin_handle;
static virtio_block_handle_t *g_persistent_handle;

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

/* Set the wall clock from NTP before any service starts.

   The clock is otherwise whatever the RTC reports, and QEMU's PL031 commonly
   reports epoch zero, leaving the system in 1970. Anything that checks a
   certificate validity window then sees every certificate as not-yet-valid,
   which is how xapt fails against the updater's publicly issued certificate.

   Bounded and non-fatal. The default server is a bare address, so this needs
   no DNS, but UDP/123 is filtered on some networks and a boot must not stall
   waiting for a reply that will never arrive. */
/* Mount xaibootFS from a partition of a disk the machine already booted from.
 *
 * Until now durable state had to arrive on a separate device: the boot medium
 * carried the kernel and something else carried the writable volume, which is
 * how every hypervisor here is configured and is not how an installed machine
 * works. A disk that has been partitioned holds both, and nothing looked --
 * gpt_read and partition_device_register were both written and neither was
 * ever called on the boot path.
 *
 * Returns XAIOS_OK once a partition typed as xaibootFS storage has been
 * registered and mounted. Anything else leaves the caller to go on probing
 * the separate devices it always did, because a disk without a partition
 * table is the normal case here and not an error.
 */
static xaios_partition_device_t g_boot_partitions[XAIOS_GPT_MAX_PARTITIONS];
static uint8_t g_gpt_scratch[4096] __attribute__((aligned(64)));
static xaios_gpt_table_t g_boot_gpt;
/* The EFI System Partition this machine started from, once one has been
   found. It is the source an install copies from, and there is exactly one. */
static char g_boot_esp[XAIOS_BLOCK_DEVICE_ID_MAX];
/* What the loader handed over. Kept because the install path runs long after
   kmain's argument has gone out of scope, and it needs to know whether this
   machine booted from a self-contained loader. */
static const xaios_boot_info_t *g_boot;

/* Read the boot files out of the EFI System Partition this machine started
   from, and say what is there.

   This is the source half of installing XAIOS onto another disk. The target
   half already works: the system can create a partition of the right type,
   format FAT16 onto it and write files at the paths firmware opens. What it
   could not do was find the bytes to write, because the loader and the kernel
   live on the ESP the machine booted from and nothing had ever opened it.

   Reporting sizes rather than copying anything keeps this a check rather than
   an install: an install needs a target disk and an operator who chose it. */
static void report_boot_esp(const char *identifier) {
  xaios_block_device_t *device = 0;
  if (block_device_open(identifier, &device) != XAIOS_OK || device == 0) {
    klog("boot-esp: %s cannot be opened\n", identifier);
    return;
  }
  xaios_fat_volume_t volume;
  if (fat_mount(device, &volume) != XAIOS_OK) {
    /* An ESP that is not FAT16 is legal -- firmware also accepts FAT32 -- and
       this reader does not handle it. Say so rather than imply the partition
       is broken. */
    klog("boot-esp: %s is not a FAT16 volume this kernel can read\n",
         identifier);
    (void)block_device_close(device);
    return;
  }
  static const char *const k_boot_files[] = {
      "/EFI/BOOT/BOOTAA64.EFI",
      "/EFI/XAIOS/XAIOS.EFI",
      "/EFI/XAIOS/KERNEL.ELF",
      "/EFI/XAIOS/INITFS.IMG",
      "/EFI/XAIOS/ENTROPY.SED",
  };
  uint32_t found = 0U;
  uint64_t total = 0U;
  for (uint64_t index = 0U;
       index < sizeof(k_boot_files) / sizeof(k_boot_files[0]); ++index) {
    uint64_t size = 0U;
    if (fat_stat(&volume, k_boot_files[index], &size, 0) != XAIOS_OK) continue;
    ++found;
    total += size;
    klog("boot-esp: %s size=%lu\n", k_boot_files[index], size);
  }
  klog("boot-esp: readable volume=%s files=%u bytes=%lu clusters=%lu\n",
       identifier, found, total, volume.cluster_count);
  (void)block_device_close(device);
}

static xaios_status_t mount_xaibootfs_from_disk(const char *disk) {
  xaios_block_device_t *device = 0;
  if (block_device_open(disk, &device) != XAIOS_OK || device == 0) {
    return XAIOS_ERR_NOT_FOUND;
  }
  xaios_status_t status =
      gpt_read(device, &g_boot_gpt, g_gpt_scratch, sizeof(g_gpt_scratch));
  if (status != XAIOS_OK ||
      (g_boot_gpt.primary_valid == 0U && g_boot_gpt.backup_valid == 0U)) {
    (void)block_device_close(device);
    return XAIOS_ERR_NOT_FOUND;
  }

  uint32_t mounted = 0U;
  for (uint32_t index = 0U; index < XAIOS_GPT_MAX_PARTITIONS; ++index) {
    const xaios_gpt_partition_t *entry = &g_boot_gpt.partitions[index];
    if (gpt_guid_is_zero(&entry->type_guid)) continue;
    uint32_t is_state =
        gpt_guid_equal(&entry->type_guid, &XAIOS_GPT_TYPE_STATEFS) ? 1U : 0U;
    /* The EFI System Partition is registered too, not only the state
       partition. It holds the loader, the kernel and the initial filesystem
       this machine booted from, which is precisely what installing XAIOS onto
       another disk has to copy. Registering it is what lets the running system
       read its own boot files rather than depending on a host tool to have
       kept a copy. */
    uint32_t is_esp =
        gpt_guid_equal(&entry->type_guid, &XAIOS_GPT_TYPE_ESP) ? 1U : 0U;
    if (is_state == 0U && is_esp == 0U) continue;
    if (is_state != 0U && mounted != 0U) continue;

    char identifier[XAIOS_BLOCK_DEVICE_ID_MAX];
    uint64_t used = 0U;
    for (const char *cursor = disk; *cursor != '\0'; ++cursor) {
      if (used + 4U >= sizeof(identifier)) break;
      identifier[used++] = *cursor;
    }
    identifier[used++] = 'p';
    identifier[used++] = (char)('0' + (char)(index % 10U));
    identifier[used] = '\0';

    if (partition_device_register(&g_boot_partitions[index], device, identifier,
                                  entry, 0U) != XAIOS_OK) {
      continue;
    }
    if (is_esp != 0U) {
      klog("boot-esp: registered %s, the partition this machine booted from\n",
           identifier);
      if (g_boot_esp[0] == '\0') {
        uint64_t copy = 0U;
        while (copy + 1U < sizeof(g_boot_esp) && identifier[copy] != '\0') {
          g_boot_esp[copy] = identifier[copy];
          ++copy;
        }
        g_boot_esp[copy] = '\0';
      }
      report_boot_esp(identifier);
      continue;
    }
    if (xaiboot_fs_mount_device(identifier) == XAIOS_OK) {
      klog("xaibootfs: mounted from %s, a partition of the disk this machine "
           "booted from\n", identifier);
      mounted = 1U;
    }
  }
  return mounted != 0U ? XAIOS_OK : XAIOS_ERR_NOT_FOUND;
}

/* Try every block device the machine has registered, rather than naming one.
 *
 * Which device holds the system depends on how the machine was configured:
 * /dev/vblk0 is the loader's in-memory initial filesystem when there is one
 * and the first physical disk when there is not, so a probe that names it
 * reads a GPT out of an initfs image on exactly the configuration this is for.
 * A partition typed as xaibootFS storage is unambiguous wherever it is found,
 * so look for that instead of guessing where to look. */
/* How far to count disks before concluding there is more than one, and what
   to name the disk of a machine that has exactly one. The slot map in the PCI
   transport runs to 6; naming well above it keeps an installed disk's name
   distinct from an attached volume's. */
#define BOOT_DISK_SCAN_LIMIT 4U
#define BOOT_DISK_SLOT_BASE 16U
/* The scratch disk the boot path attaches for storage administration. */
#define XAIOS_INSTALL_TARGET "/dev/vblk5"

/* Set when the state volume is memory rather than a disk, so the boot path
   and the setup program can tell "nothing has been installed here yet" from
   "this machine is installed". */
static uint32_t g_state_is_ephemeral;
/* Off unless a gate asks for it. See the call site. */
#ifndef XAIOS_INSTALL_SELF_TEST
#define XAIOS_INSTALL_SELF_TEST 0
#endif

static xaios_status_t mount_xaibootfs_from_any_disk(void) {
  xaios_block_device_info_t devices[8];
  uint64_t count = 0U;
  if (block_device_list(devices, 8U, &count) != XAIOS_OK) {
    return XAIOS_ERR_NOT_FOUND;
  }
  for (uint64_t index = 0U; index < count; ++index) {
    if (mount_xaibootfs_from_disk(devices[index].identifier) == XAIOS_OK) {
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NOT_FOUND;
}

/* Install XAIOS onto the scratch disk, when the machine has both an EFI System
   Partition to copy from and a disk to copy onto.

   This is the one operation the whole partition and filesystem effort exists
   for, and the only way to know it works is to do it. It runs when both halves
   are present -- an installed machine has a boot ESP, and the gate attaches a
   spare disk -- and says why it is skipping when they are not, rather than
   passing silently on a machine where it never ran.

   What it does not do is verify by booting the result. That needs firmware and
   a second machine, so the installed-disk gate does it from outside. */
#if XAIOS_INSTALL_SELF_TEST
static void install_self_test(void) {
  /* A machine that arrived over the network has no EFI System Partition to
     copy from, and does not need one: the loader that booted it carries the
     kernel and the initial filesystem inside itself, so writing that one
     binary to a new EFI System Partition is the whole install. This is the
     case network boot exists for -- a blank machine, brought up with no disk,
     putting XAIOS on the disk it has. */
  if (g_boot != 0 && g_boot->payload_loader_base != 0U &&
      g_boot->payload_kernel_base != 0U && g_boot->payload_initfs_base != 0U) {
    char confirmation[XAIOS_STORAGE_GUID_TEXT_MAX];
    xaios_status_t status = install_target_confirmation(
        XAIOS_INSTALL_TARGET, confirmation, sizeof(confirmation));
    if (status != XAIOS_OK) {
      klog("install: cannot determine what to confirm for %s status=%d\n",
           XAIOS_INSTALL_TARGET, (int)status);
      return;
    }
    xaios_install_payload_t payload;
    payload.loader = (const void *)(uintptr_t)g_boot->payload_loader_base;
    payload.loader_bytes = g_boot->payload_loader_size;
    payload.kernel = (const void *)(uintptr_t)g_boot->payload_kernel_base;
    payload.kernel_bytes = g_boot->payload_kernel_size;
    payload.initfs = (const void *)(uintptr_t)g_boot->payload_initfs_base;
    payload.initfs_bytes = g_boot->payload_initfs_size;
    payload.seed = g_boot->entropy_seed_size != 0U ? g_boot->entropy_seed : 0;
    payload.seed_bytes = g_boot->entropy_seed_size;
    xaios_install_report_t netboot_report;
    status = install_to_disk_from_payload(XAIOS_INSTALL_TARGET, &payload,
                                          confirmation, 24U, &netboot_report);
    if (status != XAIOS_OK) {
      klog("install: netboot self-test failed status=%d target=%s\n",
           (int)status, XAIOS_INSTALL_TARGET);
      return;
    }
    klog("install: netboot self-test passed target=%s files=%lu bytes=%lu "
         "esp=%s\n",
         XAIOS_INSTALL_TARGET, netboot_report.file_count,
         netboot_report.bytes_copied, netboot_report.esp_identifier);
    return;
  }
  if (g_boot_esp[0] == '\0') {
    klog("install: self-test skipped, this machine has no EFI System "
         "Partition to copy from and did not arrive over the network\n");
    return;
  }
  char confirmation[XAIOS_STORAGE_GUID_TEXT_MAX];
  xaios_status_t status = install_target_confirmation(
      XAIOS_INSTALL_TARGET, confirmation, sizeof(confirmation));
  if (status != XAIOS_OK) {
    klog("install: cannot determine what to confirm for %s status=%d\n",
         XAIOS_INSTALL_TARGET, (int)status);
    return;
  }
  xaios_install_report_t report;
  status = install_to_disk(XAIOS_INSTALL_TARGET, g_boot_esp, confirmation, 16U,
                           &report);
  if (status != XAIOS_OK) {
    klog("install: self-test failed status=%d target=%s source=%s\n",
         (int)status, XAIOS_INSTALL_TARGET, g_boot_esp);
    return;
  }
  klog("install: self-test passed target=%s files=%lu bytes=%lu esp=%s\n",
       XAIOS_INSTALL_TARGET, report.file_count, report.bytes_copied,
       report.esp_identifier);
}
#endif

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

void kmain(const xaios_boot_info_t *boot) {
  g_boot = boot;
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
  }
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

  xaios_nvme_self_test_result_t nvme_result;
  xaios_status_t nvme_status = nvme_self_test(&nvme_result);
  if (nvme_status != XAIOS_OK && nvme_status != XAIOS_ERR_NOT_FOUND) {
    klog("nvme: self-test failed status=%d\n", (int)nvme_status);
  }
  xaios_status_t ahci_status = ahci_init();
  if (ahci_status != XAIOS_OK && ahci_status != XAIOS_ERR_NOT_FOUND) {
    klog("ahci: initialization failed status=%d\n", (int)ahci_status);
  }

  /* V-06: claim a virtio-GPU if the platform has one. A machine whose firmware
     published a usable framebuffer already has a console and needs nothing
     here; one that did not -- Apple's hypervisor reports PixelBltOnly with a
     zero base -- can still have a display, because the device is on the bus
     even when the protocol to use it died at ExitBootServices. No device, or a
     disabled scanout, leaves the console exactly where it was. */
  if (boot_ui_has_framebuffer() == 0U) {
    xaios_status_t gpu_status = virtio_gpu_init();
    if (gpu_status == XAIOS_OK) {
      uint32_t gpu_width = 0U;
      uint32_t gpu_height = 0U;
      uint32_t *gpu_pixels = virtio_gpu_framebuffer(&gpu_width, &gpu_height);
      if (gpu_pixels != 0) {
        boot_ui_adopt_framebuffer(gpu_pixels, gpu_width, gpu_height,
                                  virtio_gpu_present);
      }
    }
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
     same handle for xaibootFS below. */
  if (virtio_block_open_slot(1U, &g_persistent_handle) == XAIOS_OK) {
    persistence_bind_block_device(g_persistent_handle);
  }
  if (virtio_block_is_read_only() != 0U && g_persistent_handle == 0) {
    persistence_runtime_init();
    klog("persistence: writable self-test skipped boot device is read-only\n");
    klog("xaibootfs: writable self-test deferred no persistent block device\n");
  } else {
    persistence_self_test();
    /* The xaibootFS self-test formats whichever block device is currently
       selected, and until a volume is bound that is the boot device. Under
       QEMU that device is attached with snapshot=on, so formatting it costs
       nothing; on firmware that boots from read-only removable media there is
       no such scratch device, and the durable volume must not be formatted
       merely to exercise the filesystem. Run it only where a throwaway write
       is safe. */
    if (virtio_block_is_read_only() == 0U) {
      xaiboot_fs_self_test();
    } else {
      klog("xaibootfs: self-test skipped no disposable writable device\n");
    }
  }
  boot_ui_update(52U, "boot storage", "persistent filesystem", 3U);
  /* Prefer a standards-enumerated NVMe namespace when one has completed its
   * controller canary; QEMU retains its explicit VirtIO compatibility slot. */
  xaios_status_t persistent_status = nvme_status == XAIOS_OK
                                         ? xaiboot_fs_mount_device("/dev/nvme0n1")
                                         : XAIOS_ERR_NOT_FOUND;
  /* An enumerated NVMe namespace may be a test or xaiFS volume rather than
   * xaibootFS storage. Preserve its contents and continue probing the
   * explicitly provisioned persistence devices instead of suppressing SSH. */
  if (persistent_status != XAIOS_OK && ahci_status == XAIOS_OK) {
    persistent_status = xaiboot_fs_mount_device("/dev/ahci0p0");
    if (persistent_status == XAIOS_OK) {
      klog("xaibootfs: using registered AHCI persistent data disk\n");
    }
  }
  /* A disk the machine booted from may carry its own state in a partition,
     which is what an installed system looks like as opposed to an image with
     volumes attached beside it. Tried before the separate devices below, so a
     machine that has been installed uses its own disk rather than whatever
     else happens to be plugged in. */
  if (persistent_status != XAIOS_OK) {
    /* Enumerate the physical disks first. When the loader supplied the initial
       filesystem in memory, virtio_block_init returns before probing the
       transport at all, so the machine's own disk is not registered and there
       is nothing to search. Enumerating by ordinal rather than by slot is what
       makes this work on an installed machine: the slot map exists to describe
       the test bench, and its first rule is that the firmware's boot disk is
       ordinal zero and belongs to nobody -- which on a machine with one disk
       excludes the only disk there is. Names start above the slot map so that
       a disk found here can never take the name of one attached beside it. */
    /* The first PCI block device, and only that one.

       Firmware boots from a PCI disk, so that is where an installed machine's
       partitions are. Restricting the scan to it replaces an earlier rule --
       "only when the machine has exactly one disk" -- which was wrong twice
       over. It stopped an installed machine recognising its own disk the
       moment a second was attached, which is precisely the install case. And
       counting ordinals across both transports could not address the boot disk
       at all once an MMIO device existed, because every MMIO device is counted
       first; a machine with one of each opened the spare and never saw the disk
       it had booted from.

       On the test bench this opens the firmware's own boot volume, which is
       safe because nothing else does: the PCI slot map reserves ordinal zero
       and hands it to no driver. It carries no XAIOS partition table, so the
       search below simply finds nothing there. */
    virtio_block_handle_t *installed = 0;
    (void)virtio_block_open_pci_ordinal(0U, BOOT_DISK_SLOT_BASE, &installed);
    persistent_status = mount_xaibootfs_from_any_disk();
  }
  if (persistent_status != XAIOS_OK) {
    /* vblk0 remains the immutable initramfs/test image. Open the dedicated
     * second VirtIO block device for durable xaibootFS state. */
    xaios_status_t virtio_status =
        g_persistent_handle != 0
            ? XAIOS_OK
            : virtio_block_open_slot(1U, &g_persistent_handle);
    persistent_status = virtio_status == XAIOS_OK
                            ? xaiboot_fs_mount_device("/dev/vblk1")
                            : virtio_status;
    if (persistent_status == XAIOS_OK) {
      klog("xaibootfs: using registered persistent data disk\n");
    }
  }
  /* No disk to keep state on. Give the machine one made of memory rather than
     letting everything above the block layer fail in its own way: without it
     admin_control_init never runs, sshd rejects its runtime configuration and
     the console locks, and a live boot has no way in at all. What is lost is
     that none of it survives the power going off, which is what a live boot
     means and is now the only thing it means. */
  if (persistent_status != XAIOS_OK) {
    if (ram_block_create("/dev/ram0") == XAIOS_OK) {
      persistent_status = xaiboot_fs_mount_device("/dev/ram0");
      klog("kernel: no durable volume; state kept in memory status=%d\n",
           (int)persistent_status);
      g_state_is_ephemeral = persistent_status == XAIOS_OK ? 1U : 0U;
    }
  }
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
  operations_init(persistent_status == XAIOS_OK ? 1U : 0U);
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
  xaios_status_t storage_admin_status =
      virtio_block_open_slot(5U, &g_storage_admin_handle);
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
    install_self_test();
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
    /* Ask the network for an address before falling back to the compiled-in
       one. That default is QEMU user-mode networking's, and a guest that
       assumes it is simply off-net anywhere else: Virtualization.framework
       hands out a different subnet entirely. QEMU answers DHCP with the same
       address it always did, so nothing changes there. */
    /* Six seconds left room for barely two attempts once retransmission
       backs off, and a server that is slow rather than absent was being
       written off as absent. Fifteen costs nothing when a lease arrives on
       the first try, and is only ever paid in full where there is no DHCP
       server at all. */
    if (network_config_dhcp(UINT64_C(30000000000)) != XAIOS_OK) {
      if (network_device_kind() == XAIOS_NETWORK_DEVICE_E1000E) {
        klog("kernel: DHCP configuration failed for e1000e\n");
        boot_ui_error("network DHCP", XAIOS_ERR_IO);
        goto persistent_network_done;
      }
      klog("kernel: DHCP unanswered; keeping the compiled-in address\n");
    }
    network_init_persistent();
    (void)network_wait_for_ipv6_slaac(UINT64_C(3000000000));
    /* Ask for a lease as well. SLAAC and DHCPv6 answer different questions --
       one derives an address from an announced prefix, the other has a server
       assign and record one -- and a guest does not get to choose which its
       network offers. A network with no DHCPv6 server simply never answers,
       which is why this is not allowed to fail the boot: the budget is short
       and the outcome is logged either way. */
    {
      xaios_dhcpv6_lease_t lease;
      if (dhcpv6_acquire(UINT64_C(4000000000), &lease) == XAIOS_OK &&
          lease.have_address != 0U) {
        (void)network_stack_adopt_dhcpv6(&lease.address,
                                         lease.valid_lifetime_s);
      } else {
        klog("kernel: no DHCPv6 lease; IPv6 stays as router advertisement "
             "configured it\n");
      }
    }
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
#if XAIOS_STRESS_TEST
  run_user_app("/bin/smpstress", 11, smptest_caps | XAIOS_CAP_TIME);
  /* Measurement rather than a check: it reports cost and asserts nothing, so
     it runs where the stress app runs and nowhere else. */
  run_user_app("/bin/perfbench", 11,
               smptest_caps | XAIOS_CAP_TIME | XAIOS_CAP_NET_SOCKET);
#endif
  run_user_app("/bin/nettest", 12, nettest_caps);
  run_user_app("/bin/lstm-xor", 13, lstm_caps);
  run_user_app("/bin/sshtest", 14, sshtest_caps);
  run_user_app("/bin/mltest", 15, mltest_caps);
  run_user_app("/bin/posix-shell", 16, posix_shell_caps);
  run_user_app("/bin/agenttest", 17, agenttest_caps);
#if XAIOS_CLUSTER_TEST
  /* The cluster data plane, which needs a socket rather than a simulated one.
     
     Behind a flag rather than in every boot, because it dials a peer, and a
     machine that is not in a cluster should not open a connection to one on
     every start. It did briefly, and the cost was not the connection: the
     network suite pins exact telemetry counters -- resets, closes, queue
     enqueues -- and an extra dial moved all of them, so a test of the TCP
     state machine failed because something unrelated had used the network.
     make qemu-cluster-gate builds with this set. */
  run_user_app("/bin/clustertest", 18, nettest_caps | XAIOS_CAP_NET_SOCKET);
#endif
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

  boot_sync_wall_clock();

  /* Boot drawing is finished here: what follows is a service that runs until
     the machine stops. Report what the display cost while the figure still
     covers a bounded, comparable amount of work. */
  virtio_gpu_report_transfer_cost();

  /* A machine with no user database has no account, so nobody can log into
     it -- the login prompt would ask for a username that does not exist. Run
     setup first and let the person make one.

     Before sshd, not beside it: the console is a single shared ring and
     whoever reads it takes the keystroke, so two programs on it would race
     for every character. Setup runs to completion and exits.

     An image that packages credentials never gets here, which is every gate
     image and every development build. */
  /* Only when there is no way in at all.

     "No password account" is not the same question. An image that ships
     authorized keys and no password database is a configured machine -- it is
     how a fleet is built, and how the interoperability gates build theirs --
     and running setup on it stops the boot at a prompt nobody is standing in
     front of, so its SSH server never starts and the machine hangs. That is
     what happened to three CI jobs.

     A machine with either credential can be reached by whoever has it, and is
     not this program's business. */
  xaios_xbfs_stat_t credential;
  int has_password_account =
      xaiboot_fs_stat("/etc/xaios_sshd_users", &credential) == XAIOS_OK;
  int has_authorized_keys =
      xaiboot_fs_stat("/etc/xaios_authorized_keys", &credential) == XAIOS_OK;
  if (has_password_account == 0 && has_authorized_keys == 0) {
    /* Setup offers to install, and an install copies from the partition this
       machine booted. Only the kernel knows which that is -- it is found
       while walking the boot disk's partition table -- so record it where
       setup can read it rather than asking a person to work it out from a
       device list. A machine booted from something with no EFI System
       Partition records nothing, and setup then has to ask. */
    if (g_boot_esp[0] != '\0') {
      char line[XAIOS_BLOCK_DEVICE_ID_MAX + 2U];
      uint64_t used = 0U;
      while (g_boot_esp[used] != '\0' && used + 2U < sizeof(line)) {
        line[used] = g_boot_esp[used];
        ++used;
      }
      line[used++] = '\n';
      if (xaiboot_fs_write("/state/boot-esp", line, used) != XAIOS_OK) {
        klog("kernel: could not record the boot ESP for setup\n");
      }
    }
    klog("kernel: no account on this machine; starting /bin/xaios-setup\n");
    const uint64_t setup_caps =
        XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_CONSOLE |
        XAIOS_CAP_FS_READ | XAIOS_CAP_FS_WRITE | XAIOS_CAP_RANDOM |
        XAIOS_CAP_TIME | XAIOS_CAP_NET | XAIOS_CAP_CONTROL_QUERY |
        XAIOS_CAP_CONTROL_ADMIN | XAIOS_CAP_STORAGE_READ |
        XAIOS_CAP_STORAGE_MOUNT | XAIOS_CAP_STORAGE_FORMAT |
        XAIOS_CAP_STORAGE_PARTITION | XAIOS_CAP_ADMIN;
    (void)run_user_app("/bin/xaios-setup", 2U, setup_caps);
    /* Setup cannot write /etc -- no userspace process can -- so it leaves
       what it collected under /state and this installs it. */
    setup_apply_pending();
  }

  klog("kernel: starting persistent /bin/sshd service\n");
  int sshd_exit =
      run_user_app("/bin/sshd", XAIOS_BOOT_TEST_APPS ? 18U : 3U, sshd_caps);
  boot_ui_error("sshd", sshd_exit);

  for (;;) {
    xaios_cpu_wait();
  }
}
