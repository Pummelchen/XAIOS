#include <xaios/install.h>

#include <xaios/block_device.h>
#include <xaios/fat.h>
#include <xaios/klog.h>
#include <xaios/storage_admin.h>

/* The files firmware and the loader between them need, in the order they are
   copied. BOOTAA64.EFI is what firmware opens from the removable-media path;
   the rest are what the loader then asks for. A source that is missing one is
   not an error here -- an x86_64 volume has BOOTX64.EFI and no BOOTAA64.EFI,
   and an installer that refused to copy what it found would work on one
   architecture only. What is copied is reported, and a caller that cares which
   files arrived can look. */
static const char *const k_boot_files[] = {
    "/EFI/BOOT/BOOTAA64.EFI",
    "/EFI/BOOT/BOOTX64.EFI",
    "/EFI/XAIOS/XAIOS.EFI",
    "/EFI/XAIOS/KERNEL.ELF",
    "/EFI/XAIOS/INITFS.IMG",
    "/EFI/XAIOS/ENTROPY.SED",
};

#define BOOT_FILE_COUNT (sizeof(k_boot_files) / sizeof(k_boot_files[0]))

/* Room beyond the files themselves, for a filesystem's own overhead and for a
   later kernel that is larger than this one. An EFI System Partition that
   cannot hold the next kernel makes updating the machine a reinstall. */
#define ESP_SLACK_BYTES UINT64_C(16777216)
/* FAT16 needs at least 4085 clusters to be FAT16 at all, so a volume below
   this cannot be formatted whatever the files come to. */
#define ESP_MINIMUM_BYTES UINT64_C(33554432)
#define STATE_BYTES UINT64_C(67108864)

/* Where firmware looks on removable media. The architecture in the name is
   the one this kernel was built for, because a loader carrying an AArch64
   kernel is of no use to a machine that would open BOOTX64.EFI. */
#if defined(__aarch64__)
#define XAIOS_INSTALL_REMOVABLE_LOADER "/EFI/BOOT/BOOTAA64.EFI"
#else
#define XAIOS_INSTALL_REMOVABLE_LOADER "/EFI/BOOT/BOOTX64.EFI"
#endif

static void bytes_zero(void *buffer, uint64_t length) {
  uint8_t *out = (uint8_t *)buffer;
  for (uint64_t index = 0U; index < length; ++index) out[index] = 0U;
}

static void string_copy(char *destination, uint64_t capacity,
                        const char *source) {
  uint64_t index = 0U;
  while (index + 1U < capacity && source[index] != '\0') {
    destination[index] = source[index];
    ++index;
  }
  destination[index] = '\0';
}

static int string_equal(const char *left, const char *right) {
  uint64_t index = 0U;
  while (left[index] != '\0' && left[index] == right[index]) ++index;
  return left[index] == right[index];
}

/* The whole-disk name a partition name belongs to: "/dev/vblk16p1" is a
   partition of "/dev/vblk16". Used to refuse installing onto the disk the
   source came from. */
static void whole_disk_of(const char *partition, char *out, uint64_t capacity) {
  uint64_t length = 0U;
  while (partition[length] != '\0' && length + 1U < capacity) ++length;
  uint64_t cut = length;
  /* Trim a trailing "p<digits>", and only that: a name with no such suffix is
     already a whole disk and must come back unchanged. */
  uint64_t digits = 0U;
  while (cut > 0U && partition[cut - 1U] >= '0' && partition[cut - 1U] <= '9') {
    --cut;
    ++digits;
  }
  if (digits == 0U || cut == 0U || partition[cut - 1U] != 'p') cut = length;
  else --cut;
  uint64_t index = 0U;
  while (index < cut && index + 1U < capacity) {
    out[index] = partition[index];
    ++index;
  }
  out[index] = '\0';
}

static xaios_status_t create_partition(const char *target,
                                       const char *confirmation,
                                       const char *name, uint32_t type,
                                       uint64_t bytes, uint64_t operation_id,
                                       xaios_storage_partition_plan_t *result) {
  xaios_storage_partition_request_t request;
  bytes_zero(&request, sizeof(request));
  string_copy(request.target, sizeof(request.target), target);
  string_copy(request.confirmation, sizeof(request.confirmation), confirmation);
  string_copy(request.name, sizeof(request.name), name);
  request.partition_type = type;
  request.size_bytes = bytes;
  request.operation_id = operation_id;
  return storage_admin_partition_create(&request, result);
}

/* The GUID a caller has to confirm before installing onto target.
 *
 * A disk that already has a partition table reports its own. A blank one has
 * none to report -- and a blank disk is the normal state of a disk being
 * installed onto, so this cannot simply fail there. Planning a partition
 * answers the question without writing anything: the plan names the table that
 * would result, and its GUID is what the create then checks against.
 *
 * Doing this here rather than at each call site is deliberate. The self-test
 * previously read an uninitialised report when the verify failed and passed
 * whatever the stack held as the confirmation, which happened to work only
 * because earlier self-tests had left a table behind on the same disk. */
xaios_status_t install_target_confirmation(const char *target, char *out,
                                           uint64_t capacity) {
  if (target == 0 || out == 0 || capacity == 0U) return XAIOS_ERR_INVALID;
  out[0] = '\0';
  xaios_storage_partition_report_t report;
  bytes_zero(&report, sizeof(report));
  if (storage_admin_partition_verify(target, &report) == XAIOS_OK &&
      report.disk_guid[0] != '\0') {
    string_copy(out, capacity, report.disk_guid);
    return XAIOS_OK;
  }

  xaios_storage_partition_request_t request;
  bytes_zero(&request, sizeof(request));
  string_copy(request.target, sizeof(request.target), target);
  string_copy(request.name, sizeof(request.name), "probe");
  request.partition_type = XAIOS_STORAGE_PARTITION_STATE;
  request.size_bytes = UINT64_C(1048576);
  xaios_storage_partition_plan_t plan;
  xaios_status_t status = storage_admin_partition_plan_create(&request, &plan);
  if (status != XAIOS_OK) return status;
  if (plan.report.disk_guid[0] == '\0') return XAIOS_ERR_NOT_FOUND;
  string_copy(out, capacity, plan.report.disk_guid);
  return XAIOS_OK;
}

/* Partition the target and hand back a formatted EFI filesystem on it.
 *
 * Shared by both installs, because what differs between them is only where the
 * bytes come from: a machine with an EFI System Partition copies files off it,
 * and a machine that arrived over the network writes the loader it booted with.
 * Everything before that -- the partition table, the two partitions, the FAT
 * volume and the directories firmware opens -- is the same work. */
static xaios_status_t prepare_target(const char *target,
                                     const char *confirmation,
                                     uint64_t payload, uint64_t operation_id,
                                     xaios_install_report_t *report,
                                     xaios_block_device_t **out_esp,
                                     xaios_fat_volume_t *volume) {
  uint64_t esp_bytes = payload + ESP_SLACK_BYTES;
  if (esp_bytes < ESP_MINIMUM_BYTES) esp_bytes = ESP_MINIMUM_BYTES;

  xaios_storage_partition_plan_t esp;
  xaios_status_t status =
      create_partition(target, confirmation, "XAIOS ESP",
                       XAIOS_STORAGE_PARTITION_ESP, esp_bytes, operation_id,
                       &esp);
  if (status != XAIOS_OK) {
    klog("install: could not create the EFI partition status=%d\n",
         (int)status);
    return status;
  }
  xaios_storage_partition_plan_t state;
  status = create_partition(target, confirmation, "xaibootFS",
                            XAIOS_STORAGE_PARTITION_STATE, STATE_BYTES,
                            operation_id + 1U, &state);
  if (status != XAIOS_OK) {
    klog("install: could not create the state partition status=%d\n",
         (int)status);
    return status;
  }

  xaios_storage_partition_record_t record;
  status = storage_admin_partition_open(esp.partition.identifier,
                                        XAIOS_STORAGE_PARTITION_ESP, 1U,
                                        out_esp, &record);
  if (status != XAIOS_OK) {
    klog("install: could not open %s status=%d\n", esp.partition.identifier,
         (int)status);
    return status;
  }
  status = fat_format(*out_esp, "XAIOS", volume);
  if (status == XAIOS_OK) status = fat_mkdir(volume, "/EFI/BOOT");
  if (status == XAIOS_OK) status = fat_mkdir(volume, "/EFI/XAIOS");
  if (status != XAIOS_OK) {
    klog("install: could not prepare the EFI filesystem status=%d\n",
         (int)status);
    (void)storage_admin_partition_close(*out_esp);
    *out_esp = 0;
    return status;
  }

  string_copy(report->esp_identifier, sizeof(report->esp_identifier),
              esp.partition.identifier);
  string_copy(report->state_identifier, sizeof(report->state_identifier),
              state.partition.identifier);
  report->esp_bytes = esp.partition.size_bytes;
  report->state_bytes = state.partition.size_bytes;
  return XAIOS_OK;
}

xaios_status_t install_to_disk_from_payload(
    const char *target, const xaios_install_payload_t *payload,
    const char *confirmation, uint64_t operation_id,
    xaios_install_report_t *report) {
  if (target == 0 || payload == 0 || confirmation == 0 || report == 0 ||
      operation_id == 0U || payload->loader == 0 ||
      payload->loader_bytes == 0U || payload->kernel == 0 ||
      payload->kernel_bytes == 0U || payload->initfs == 0 ||
      payload->initfs_bytes == 0U) {
    return XAIOS_ERR_INVALID;
  }
  bytes_zero(report, sizeof(report[0]));

  uint64_t total = payload->loader_bytes + payload->kernel_bytes +
                   payload->initfs_bytes;
  xaios_block_device_t *esp_device = 0;
  xaios_fat_volume_t volume;
  xaios_status_t status = prepare_target(target, confirmation, total,
                                         operation_id, report, &esp_device,
                                         &volume);
  if (status != XAIOS_OK) return status;

  /* The same three files an installer from media writes, at the same paths --
     the loader where firmware opens it on removable media, and the kernel and
     initial filesystem where that loader then looks for them. The result is an
     ordinary EFI System Partition, indistinguishable from one written by any
     other route, which is the point: a machine installed over the network is
     not a special kind of machine afterwards. */
  static const char *const k_paths[3] = {
      XAIOS_INSTALL_REMOVABLE_LOADER,
      "/EFI/XAIOS/KERNEL.ELF",
      "/EFI/XAIOS/INITFS.IMG",
  };
  const void *const sources[3] = {payload->loader, payload->kernel,
                                  payload->initfs};
  const uint64_t sizes[3] = {payload->loader_bytes, payload->kernel_bytes,
                             payload->initfs_bytes};
  for (uint64_t index = 0U; index < 3U; ++index) {
    status = fat_write_file(&volume, k_paths[index], sources[index],
                            sizes[index]);
    if (status != XAIOS_OK) {
      klog("install: writing %s failed status=%d\n", k_paths[index],
           (int)status);
      (void)storage_admin_partition_close(esp_device);
      return status;
    }
    report->files[report->file_count].path = k_paths[index];
    report->files[report->file_count].bytes = sizes[index];
    report->files[report->file_count].copied = 1U;
    ++report->file_count;
    report->bytes_copied += sizes[index];
  }
  if (payload->seed != 0 && payload->seed_bytes != 0U) {
    if (fat_write_file(&volume, "/EFI/XAIOS/ENTROPY.SED", payload->seed,
                       payload->seed_bytes) == XAIOS_OK) {
      report->files[report->file_count].path = "/EFI/XAIOS/ENTROPY.SED";
      report->files[report->file_count].bytes = payload->seed_bytes;
      report->files[report->file_count].copied = 1U;
      ++report->file_count;
      report->bytes_copied += payload->seed_bytes;
    }
  }

  (void)storage_admin_partition_close(esp_device);
  klog("install: %s is bootable esp=%s state=%s files=%lu bytes=%lu "
       "source=embedded\n",
       target, report->esp_identifier, report->state_identifier,
       report->file_count, report->bytes_copied);
  return XAIOS_OK;
}

xaios_status_t install_to_disk(const char *target, const char *source_esp,
                               const char *confirmation,
                               uint64_t operation_id,
                               xaios_install_report_t *report) {
  if (target == 0 || source_esp == 0 || confirmation == 0 || report == 0 ||
      operation_id == 0U) {
    return XAIOS_ERR_INVALID;
  }
  bytes_zero(report, sizeof(*report));

  /* Never the disk the source lives on. An installer that can overwrite the
     system running it loses a machine to a typo, and the check costs a string
     compare. */
  char source_disk[XAIOS_BLOCK_DEVICE_ID_MAX];
  whole_disk_of(source_esp, source_disk, sizeof(source_disk));
  if (string_equal(source_disk, target)) {
    klog("install: refusing to install onto %s, which is where %s lives\n",
         target, source_esp);
    return XAIOS_ERR_BUSY;
  }

  xaios_block_device_t *source_device = 0;
  if (block_device_open(source_esp, &source_device) != XAIOS_OK ||
      source_device == 0) {
    return XAIOS_ERR_NOT_FOUND;
  }
  xaios_fat_volume_t source;
  if (fat_mount(source_device, &source) != XAIOS_OK) {
    klog("install: %s is not a FAT volume this kernel can read\n", source_esp);
    (void)block_device_close(source_device);
    return XAIOS_ERR_UNSUPPORTED;
  }

  /* Size the EFI partition from what is actually being copied rather than
     from a constant, so a larger kernel does not silently need a new
     installer. */
  uint64_t payload = 0U;
  uint64_t present = 0U;
  for (uint64_t index = 0U; index < BOOT_FILE_COUNT; ++index) {
    uint64_t size = 0U;
    if (fat_stat(&source, k_boot_files[index], &size, 0) != XAIOS_OK) continue;
    payload += size;
    ++present;
  }
  if (present == 0U) {
    klog("install: %s holds none of the files a machine boots from\n",
         source_esp);
    (void)block_device_close(source_device);
    return XAIOS_ERR_NOT_FOUND;
  }
  uint64_t esp_bytes = payload + ESP_SLACK_BYTES;
  if (esp_bytes < ESP_MINIMUM_BYTES) esp_bytes = ESP_MINIMUM_BYTES;

  xaios_storage_partition_plan_t esp;
  xaios_status_t status =
      create_partition(target, confirmation,
                       "XAIOS ESP", XAIOS_STORAGE_PARTITION_ESP, esp_bytes,
                       operation_id, &esp);
  if (status != XAIOS_OK) {
    klog("install: could not create the EFI partition status=%d\n",
         (int)status);
    (void)block_device_close(source_device);
    return status;
  }

  xaios_storage_partition_plan_t state;
  status = create_partition(target, confirmation,
                            "xaibootFS", XAIOS_STORAGE_PARTITION_STATE,
                            STATE_BYTES, operation_id + 1U, &state);
  if (status != XAIOS_OK) {
    klog("install: could not create the state partition status=%d\n",
         (int)status);
    (void)block_device_close(source_device);
    return status;
  }

  xaios_block_device_t *esp_device = 0;
  xaios_storage_partition_record_t record;
  status = storage_admin_partition_open(esp.partition.identifier,
                                        XAIOS_STORAGE_PARTITION_ESP, 1U,
                                        &esp_device, &record);
  if (status != XAIOS_OK) {
    klog("install: could not open %s status=%d\n", esp.partition.identifier,
         (int)status);
    (void)block_device_close(source_device);
    return status;
  }

  xaios_fat_volume_t destination;
  status = fat_format(esp_device, "XAIOS", &destination);
  if (status == XAIOS_OK) status = fat_mkdir(&destination, "/EFI/BOOT");
  if (status == XAIOS_OK) status = fat_mkdir(&destination, "/EFI/XAIOS");
  if (status != XAIOS_OK) {
    klog("install: could not prepare the EFI filesystem status=%d\n",
         (int)status);
    (void)storage_admin_partition_close(esp_device);
    (void)block_device_close(source_device);
    return status;
  }

  for (uint64_t index = 0U;
       index < BOOT_FILE_COUNT && report->file_count < XAIOS_INSTALL_MAX_FILES;
       ++index) {
    uint64_t size = 0U;
    if (fat_stat(&source, k_boot_files[index], &size, 0) != XAIOS_OK) continue;
    xaios_install_file_t *entry = &report->files[report->file_count++];
    entry->path = k_boot_files[index];
    entry->bytes = size;
    status = fat_copy_file(&destination, k_boot_files[index], &source,
                           k_boot_files[index]);
    if (status != XAIOS_OK) {
      klog("install: copying %s failed status=%d\n", k_boot_files[index],
           (int)status);
      (void)storage_admin_partition_close(esp_device);
      (void)block_device_close(source_device);
      return status;
    }
    entry->copied = 1U;
    report->bytes_copied += size;
  }

  string_copy(report->esp_identifier, sizeof(report->esp_identifier),
              esp.partition.identifier);
  string_copy(report->state_identifier, sizeof(report->state_identifier),
              state.partition.identifier);
  report->esp_bytes = esp.partition.size_bytes;
  report->state_bytes = state.partition.size_bytes;

  (void)storage_admin_partition_close(esp_device);
  (void)block_device_close(source_device);
  klog("install: %s is bootable esp=%s state=%s files=%lu bytes=%lu\n",
       target, report->esp_identifier,
       report->state_identifier, report->file_count, report->bytes_copied);
  return XAIOS_OK;
}
