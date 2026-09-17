/* Boot storage: the disk half of the boot path. See boot_storage_internal.h.
 *
 * Everything here ran inline in kmain before it was split out; the move is
 * verbatim and the boot order is unchanged, because kmain still calls the
 * single stage entry point at the same point in the sequence.
 */

#include <xaios/ahci.h>
#include <xaios/assert.h>
#include <xaios/block_device.h>
#include <xaios/boot_ui.h>
#include <xaios/entropy.h>
#include <xaios/fat.h>
#include <xaios/gpt.h>
#include <xaios/initramfs.h>
#include <xaios/install.h>
#include <xaios/klog.h>
#include <xaios/nvme.h>
#include <xaios/partition_device.h>
#include <xaios/persistence.h>
#include <xaios/ram_block.h>
#include <xaios/storage_admin.h>
#include <xaios/virtio_blk.h>
#include <xaios/virtio_gpu.h>
#include <xaios/virtio_rng.h>
#include <xaios/vmxnet3.h>
#include <xaios/xaiboot_fs.h>

#include "boot_storage_internal.h"

/* The dedicated persistent VirtIO slot, opened while storage is discovered and
   reused by every mount attempt below and by the xaibootFS cascade. */
static virtio_block_handle_t *g_persistent_handle;

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
  /* All three removable-media names, because a volume is read the same way
     whichever machine is reading it and a reader that knew only its own would
     report four files on a disk with five. Absence is not an error: a volume
     carries the loader for the machines it is meant to boot. */
  static const char *const k_boot_files[] = {
      "/EFI/BOOT/BOOTAA64.EFI",
      "/EFI/BOOT/BOOTX64.EFI",
      "/EFI/BOOT/BOOTRISCV64.EFI",
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
void boot_storage_install_self_test(const char *target,
                                    const xaios_boot_info_t *boot) {
  /* A machine that arrived over the network has no EFI System Partition to
     copy from, and does not need one: the loader that booted it carries the
     kernel and the initial filesystem inside itself, so writing that one
     binary to a new EFI System Partition is the whole install. This is the
     case network boot exists for -- a blank machine, brought up with no disk,
     putting XAIOS on the disk it has. */
  if (boot != 0 && boot->payload_loader_base != 0U &&
      boot->payload_kernel_base != 0U && boot->payload_initfs_base != 0U) {
    char confirmation[XAIOS_STORAGE_GUID_TEXT_MAX];
    xaios_status_t status = install_target_confirmation(
        target, confirmation, sizeof(confirmation));
    if (status != XAIOS_OK) {
      klog("install: cannot determine what to confirm for %s status=%d\n",
           target, (int)status);
      return;
    }
    xaios_install_payload_t payload;
    payload.loader = (const void *)(uintptr_t)boot->payload_loader_base;
    payload.loader_bytes = boot->payload_loader_size;
    payload.kernel = (const void *)(uintptr_t)boot->payload_kernel_base;
    payload.kernel_bytes = boot->payload_kernel_size;
    payload.initfs = (const void *)(uintptr_t)boot->payload_initfs_base;
    payload.initfs_bytes = boot->payload_initfs_size;
    payload.seed = boot->entropy_seed_size != 0U ? boot->entropy_seed : 0;
    payload.seed_bytes = boot->entropy_seed_size;
    xaios_install_report_t netboot_report;
    status = install_to_disk_from_payload(target, &payload,
                                          confirmation, 24U, &netboot_report);
    if (status != XAIOS_OK) {
      klog("install: netboot self-test failed status=%d target=%s\n",
           (int)status, target);
      return;
    }
    klog("install: netboot self-test passed target=%s files=%lu bytes=%lu "
         "esp=%s\n",
         target, netboot_report.file_count,
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
      target, confirmation, sizeof(confirmation));
  if (status != XAIOS_OK) {
    klog("install: cannot determine what to confirm for %s status=%d\n",
         target, (int)status);
    return;
  }
  xaios_install_report_t report;
  status = install_to_disk(target, g_boot_esp, confirmation, 16U,
                           &report);
  if (status != XAIOS_OK) {
    klog("install: self-test failed status=%d target=%s source=%s\n",
         (int)status, target, g_boot_esp);
    return;
  }
  klog("install: self-test passed target=%s files=%lu bytes=%lu esp=%s\n",
       target, report.file_count, report.bytes_copied,
       report.esp_identifier);
}
#endif

/* Storage discovery and the persistent volume, in the order the machine needs
   it: name the devices, find something that has survived a power cycle on any
   of them, and only then fall back to a volume made of memory. */
xaios_status_t boot_storage_bring_up(const xaios_boot_info_t *boot,
                                     xaios_status_t *nvme_status_out,
                                     uint32_t *durable_state_out) {
  xaios_nvme_self_test_result_t nvme_result;
  xaios_status_t nvme_status = nvme_self_test(&nvme_result);
  if (nvme_status != XAIOS_OK && nvme_status != XAIOS_ERR_NOT_FOUND) {
    klog("nvme: self-test failed status=%d\n", (int)nvme_status);
  }
  /* F-02: say whether this platform has a VMXNET3, and what it reports if so.
     Nothing selects it -- the driver cannot carry a frame yet -- so this is a
     statement about the platform rather than a device coming into service. */
  vmxnet3_self_test();

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
  /* Whether what got mounted above outlives the power going off. Everything
     up to here mounts a disk; the fallback below mounts memory, and the
     operations layer has to say which, because a lifecycle record written to
     memory is not a lifecycle record the next boot can read. */
  uint32_t durable_state = 1U;
  if (persistent_status != XAIOS_OK) {
    if (ram_block_create("/dev/ram0") == XAIOS_OK) {
      persistent_status = xaiboot_fs_mount_device("/dev/ram0");
      durable_state = 0U;
      klog("kernel: no durable volume; state kept in memory status=%d\n",
           (int)persistent_status);
    }
  }
  if (nvme_status_out != 0) *nvme_status_out = nvme_status;
  if (durable_state_out != 0) *durable_state_out = durable_state;
  return persistent_status;
}

/* Reads this file's own ESP name. The caller's buffer is filled and NUL
   terminated; no pointer into the file-scope name escapes. */
uint64_t boot_storage_esp_copy(char *out, uint64_t capacity) {
  if (out == 0 || capacity == 0U) return 0U;
  uint64_t used = 0U;
  while (used + 1U < capacity && g_boot_esp[used] != '\0') {
    out[used] = g_boot_esp[used];
    ++used;
  }
  out[used] = '\0';
  return used;
}
