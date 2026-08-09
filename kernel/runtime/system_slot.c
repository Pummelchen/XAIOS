#include <xaios/arch_cpu.h>
#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/sha256.h>
#include <xaios/system_slot.h>
#include <xaios/virtio_blk.h>

#define SYSTEM_SECTOR_BYTES UINT64_C(512)
#define SYSTEM_METADATA_SECTORS                                      \
  (XAIOS_SYSTEM_METADATA_BYTES / SYSTEM_SECTOR_BYTES)

static virtio_block_handle_t *g_system_handle;
static xaios_system_metadata_t g_metadata;
static uint32_t g_available;
static uint32_t g_staging;
static uint32_t g_staging_slot;
static uint64_t g_staging_written;

#if defined(XAIOS_STORAGE_CRASH_AFTER_SYSTEM_BACKUP) || \
    defined(XAIOS_STORAGE_CRASH_AFTER_SYSTEM_PRIMARY)
static void storage_crash_point(const char *name) {
  klog("storage-crash: reached point=%s\n", name);
  for (;;) xaios_cpu_wait();
}
#endif

static void bytes_zero(void *buffer, uint64_t length) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t index = 0U; index < length; ++index) bytes[index] = 0U;
}

static void bytes_copy(void *destination, const void *source, uint64_t length) {
  uint8_t *out = (uint8_t *)destination;
  const uint8_t *in = (const uint8_t *)source;
  for (uint64_t index = 0U; index < length; ++index) out[index] = in[index];
}

static int bytes_equal(const void *left, const void *right, uint64_t length) {
  const uint8_t *lhs = (const uint8_t *)left;
  const uint8_t *rhs = (const uint8_t *)right;
  uint8_t difference = 0U;
  for (uint64_t index = 0U; index < length; ++index) {
    difference |= lhs[index] ^ rhs[index];
  }
  return difference == 0U;
}

static uint64_t string_length(const char *value) {
  uint64_t length = 0U;
  if (value == 0) return 0U;
  while (length < XAIOS_SYSTEM_SIGNATURE_MAX && value[length] != '\0') {
    ++length;
  }
  return length;
}

static int metadata_valid(const xaios_system_metadata_t *metadata) {
  static const char magic[16] = XAIOS_SYSTEM_MAGIC;
  uint8_t digest[32];
  if (!bytes_equal(metadata->magic, magic, sizeof(magic)) ||
      metadata->version != XAIOS_SYSTEM_VERSION ||
      metadata->header_size != sizeof(*metadata) ||
      metadata->active_slot >= XAIOS_SYSTEM_SLOT_COUNT ||
      (metadata->pending_slot != XAIOS_SYSTEM_SLOT_NONE &&
       metadata->pending_slot >= XAIOS_SYSTEM_SLOT_COUNT) ||
      metadata->pending_attempted > 1U) {
    return 0;
  }
  xaios_sha256(metadata, sizeof(*metadata) - sizeof(metadata->metadata_sha256),
               digest);
  return bytes_equal(digest, metadata->metadata_sha256, sizeof(digest));
}

static xaios_status_t read_extent(uint64_t start_lba, void *buffer,
                                  uint64_t sectors) {
  uint8_t *out = (uint8_t *)buffer;
  for (uint64_t index = 0U; index < sectors; ++index) {
    xaios_status_t status = virtio_block_read_sector_h(
        g_system_handle, start_lba + index,
        out + index * SYSTEM_SECTOR_BYTES, SYSTEM_SECTOR_BYTES);
    if (status != XAIOS_OK) return status;
  }
  return XAIOS_OK;
}

static xaios_status_t write_extent(uint64_t start_lba, const void *buffer,
                                   uint64_t sectors) {
  const uint8_t *input = (const uint8_t *)buffer;
  for (uint64_t index = 0U; index < sectors; ++index) {
    xaios_status_t status = virtio_block_write_sector_h(
        g_system_handle, start_lba + index,
        input + index * SYSTEM_SECTOR_BYTES, SYSTEM_SECTOR_BYTES);
    if (status != XAIOS_OK) return status;
  }
  return XAIOS_OK;
}

static xaios_status_t read_best_metadata(xaios_system_metadata_t *metadata) {
  xaios_system_metadata_t primary;
  xaios_system_metadata_t backup;
  xaios_status_t primary_status = read_extent(
      XAIOS_SYSTEM_METADATA_PRIMARY_LBA, &primary, SYSTEM_METADATA_SECTORS);
  xaios_status_t backup_status = read_extent(
      XAIOS_SYSTEM_METADATA_BACKUP_LBA, &backup, SYSTEM_METADATA_SECTORS);
  int primary_valid = primary_status == XAIOS_OK && metadata_valid(&primary);
  int backup_valid = backup_status == XAIOS_OK && metadata_valid(&backup);
  if (!primary_valid && !backup_valid) return XAIOS_ERR_INVALID;
  if (primary_valid && (!backup_valid || primary.sequence >= backup.sequence)) {
    bytes_copy(metadata, &primary, sizeof(*metadata));
  } else {
    bytes_copy(metadata, &backup, sizeof(*metadata));
  }
  return XAIOS_OK;
}

static xaios_status_t persist_metadata(void) {
  xaios_sha256(&g_metadata,
               sizeof(g_metadata) - sizeof(g_metadata.metadata_sha256),
               g_metadata.metadata_sha256);
  xaios_status_t status = write_extent(XAIOS_SYSTEM_METADATA_BACKUP_LBA,
                                       &g_metadata,
                                       SYSTEM_METADATA_SECTORS);
  if (status != XAIOS_OK) return status;
  status = virtio_block_flush_h(g_system_handle);
  if (status != XAIOS_OK) return status;
#if defined(XAIOS_STORAGE_CRASH_AFTER_SYSTEM_BACKUP)
  storage_crash_point("system-backup-flushed");
#endif
  status = write_extent(XAIOS_SYSTEM_METADATA_PRIMARY_LBA, &g_metadata,
                        SYSTEM_METADATA_SECTORS);
  if (status != XAIOS_OK) return status;
#if defined(XAIOS_STORAGE_CRASH_AFTER_SYSTEM_PRIMARY)
  storage_crash_point("system-primary-written");
#endif
  return virtio_block_flush_h(g_system_handle);
}

xaios_status_t system_slot_init(const xaios_boot_info_t *boot) {
  g_system_handle = 0;
  g_available = 0U;
  g_staging = 0U;
  g_staging_slot = XAIOS_SYSTEM_SLOT_NONE;
  g_staging_written = 0U;
  bytes_zero(&g_metadata, sizeof(g_metadata));
  if (boot == 0 || boot->system_volume_present == 0U ||
      boot->system_slot >= XAIOS_SYSTEM_SLOT_COUNT ||
      boot->system_generation == 0U) {
    return XAIOS_ERR_NOT_FOUND;
  }
  xaios_status_t status = virtio_block_open_slot(6U, &g_system_handle);
  if (status != XAIOS_OK) return status;
  if (virtio_block_capacity_sectors_h(g_system_handle) <
          XAIOS_SYSTEM_VOLUME_SECTORS ||
      read_best_metadata(&g_metadata) != XAIOS_OK ||
      g_metadata.slots[boot->system_slot].valid != 1U ||
      g_metadata.slots[boot->system_slot].generation !=
          boot->system_generation) {
    return XAIOS_ERR_INVALID;
  }
  g_available = 1U;
  klog("system-slot: attached active=%u pending=%u attempted=%u boot=%u generation=%lu sequence=%lu\n",
       g_metadata.active_slot, g_metadata.pending_slot,
       g_metadata.pending_attempted, boot->system_slot,
       boot->system_generation, g_metadata.sequence);
  return XAIOS_OK;
}

xaios_status_t system_slot_begin(uint64_t generation, uint64_t image_size,
                                 const uint8_t hash[32],
                                 const char *signature) {
  uint64_t signature_length = string_length(signature);
  uint64_t highest_generation = g_metadata.slots[0].generation;
  if (g_metadata.slots[1].generation > highest_generation) {
    highest_generation = g_metadata.slots[1].generation;
  }
  if (g_available == 0U || g_staging != 0U || hash == 0 ||
      signature_length == 0U ||
      signature_length >= XAIOS_SYSTEM_SIGNATURE_MAX ||
      generation <= highest_generation || image_size == 0U ||
      image_size > XAIOS_SYSTEM_SLOT_SECTORS * SYSTEM_SECTOR_BYTES) {
    return XAIOS_ERR_INVALID;
  }
  g_staging_slot = g_metadata.active_slot == 0U ? 1U : 0U;
  xaios_system_slot_descriptor_t *slot = &g_metadata.slots[g_staging_slot];
  bytes_zero(slot, sizeof(*slot));
  slot->generation = generation;
  slot->offset_lba = XAIOS_SYSTEM_SLOT0_LBA +
                     g_staging_slot * XAIOS_SYSTEM_SLOT_SECTORS;
  slot->image_size = image_size;
  bytes_copy(slot->sha256, hash, sizeof(slot->sha256));
  bytes_copy(slot->signature, signature, signature_length + 1U);
  g_metadata.pending_slot = XAIOS_SYSTEM_SLOT_NONE;
  g_metadata.pending_attempted = 0U;
  ++g_metadata.sequence;
  if (persist_metadata() != XAIOS_OK) {
    g_staging_slot = XAIOS_SYSTEM_SLOT_NONE;
    return XAIOS_ERR_IO;
  }
  g_staging = 1U;
  g_staging_written = 0U;
  klog("system-slot: staging slot=%u generation=%lu bytes=%lu\n",
       g_staging_slot, generation, image_size);
  return XAIOS_OK;
}

xaios_status_t system_slot_write(uint64_t offset, const void *data,
                                 uint32_t size) {
  if (g_staging == 0U || data == 0 || size == 0U ||
      offset != g_staging_written ||
      offset + size < offset ||
      offset + size > g_metadata.slots[g_staging_slot].image_size) {
    return XAIOS_ERR_INVALID;
  }
  const uint8_t *input = (const uint8_t *)data;
  uint8_t sector[SYSTEM_SECTOR_BYTES];
  uint64_t completed = 0U;
  uint64_t base_lba = g_metadata.slots[g_staging_slot].offset_lba;
  while (completed < size) {
    uint64_t absolute = offset + completed;
    uint64_t sector_index = absolute / SYSTEM_SECTOR_BYTES;
    uint32_t sector_offset = (uint32_t)(absolute % SYSTEM_SECTOR_BYTES);
    uint32_t count = (uint32_t)(SYSTEM_SECTOR_BYTES - sector_offset);
    if (count > size - completed) count = size - (uint32_t)completed;
    if (sector_offset != 0U || count != SYSTEM_SECTOR_BYTES) {
      if (virtio_block_read_sector_h(g_system_handle,
                                     base_lba + sector_index, sector,
                                     sizeof(sector)) != XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
    } else {
      bytes_zero(sector, sizeof(sector));
    }
    bytes_copy(sector + sector_offset, input + completed, count);
    if (virtio_block_write_sector_h(g_system_handle,
                                    base_lba + sector_index, sector,
                                    sizeof(sector)) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
    completed += count;
  }
  g_staging_written += size;
  return XAIOS_OK;
}

xaios_status_t system_slot_finish(void) {
  if (g_staging == 0U ||
      g_staging_written != g_metadata.slots[g_staging_slot].image_size) {
    return XAIOS_ERR_INVALID;
  }
  xaios_sha256_ctx_t hash;
  uint8_t digest[32];
  uint8_t sector[SYSTEM_SECTOR_BYTES];
  uint64_t remaining = g_staging_written;
  uint64_t lba = g_metadata.slots[g_staging_slot].offset_lba;
  xaios_sha256_init(&hash);
  while (remaining > 0U) {
    if (virtio_block_read_sector_h(g_system_handle, lba, sector,
                                   sizeof(sector)) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
    uint64_t count = remaining < sizeof(sector) ? remaining : sizeof(sector);
    xaios_sha256_update(&hash, sector, count);
    remaining -= count;
    ++lba;
  }
  xaios_sha256_final(&hash, digest);
  if (!bytes_equal(digest, g_metadata.slots[g_staging_slot].sha256,
                   sizeof(digest))) {
    return XAIOS_ERR_IO;
  }
  g_metadata.slots[g_staging_slot].valid = 1U;
  ++g_metadata.sequence;
  if (persist_metadata() != XAIOS_OK) return XAIOS_ERR_IO;
  klog("system-slot: verified slot=%u generation=%lu bytes=%lu\n",
       g_staging_slot, g_metadata.slots[g_staging_slot].generation,
       g_staging_written);
  return XAIOS_OK;
}

xaios_status_t system_slot_activate(void) {
  if (g_staging == 0U || g_metadata.slots[g_staging_slot].valid != 1U) {
    return XAIOS_ERR_INVALID;
  }
  g_metadata.pending_slot = g_staging_slot;
  g_metadata.pending_attempted = 0U;
  ++g_metadata.sequence;
  if (persist_metadata() != XAIOS_OK) return XAIOS_ERR_IO;
  klog("system-slot: pending slot=%u generation=%lu\n", g_staging_slot,
       g_metadata.slots[g_staging_slot].generation);
  g_staging = 0U;
  return XAIOS_OK;
}

xaios_status_t system_slot_cancel_pending(void) {
  if (g_available == 0U ||
      (g_metadata.pending_slot == XAIOS_SYSTEM_SLOT_NONE &&
       g_staging == 0U)) {
    return XAIOS_ERR_INVALID;
  }
  g_metadata.pending_slot = XAIOS_SYSTEM_SLOT_NONE;
  g_metadata.pending_attempted = 0U;
  if (g_staging_slot < XAIOS_SYSTEM_SLOT_COUNT) {
    g_metadata.slots[g_staging_slot].valid = 0U;
  }
  ++g_metadata.sequence;
  if (persist_metadata() != XAIOS_OK) return XAIOS_ERR_IO;
  g_staging = 0U;
  g_staging_slot = XAIOS_SYSTEM_SLOT_NONE;
  g_staging_written = 0U;
  return XAIOS_OK;
}

xaios_status_t system_slot_mark_boot_success(const xaios_boot_info_t *boot) {
  if (g_available == 0U || boot == 0 ||
      boot->system_slot >= XAIOS_SYSTEM_SLOT_COUNT ||
      g_metadata.slots[boot->system_slot].generation !=
          boot->system_generation) {
    return XAIOS_ERR_INVALID;
  }
  if (g_metadata.pending_slot == boot->system_slot &&
      g_metadata.pending_attempted != 0U) {
    g_metadata.active_slot = boot->system_slot;
    g_metadata.pending_slot = XAIOS_SYSTEM_SLOT_NONE;
    g_metadata.pending_attempted = 0U;
    ++g_metadata.sequence;
    if (persist_metadata() != XAIOS_OK) return XAIOS_ERR_IO;
    klog("system-slot: boot committed slot=%u generation=%lu sequence=%lu\n",
         boot->system_slot, boot->system_generation, g_metadata.sequence);
  }
  return XAIOS_OK;
}

uint32_t system_slot_available(void) { return g_available; }

void system_slot_self_test(void) {
  if (g_available == 0U) {
    klog("system-slot: self-test skipped volume=unavailable\n");
    return;
  }
  kassert(metadata_valid(&g_metadata));
  kassert(g_metadata.slots[0].offset_lba == XAIOS_SYSTEM_SLOT0_LBA);
  kassert(g_metadata.slots[1].offset_lba ==
          XAIOS_SYSTEM_SLOT0_LBA + XAIOS_SYSTEM_SLOT_SECTORS);
  kassert(g_metadata.slots[g_metadata.active_slot].valid == 1U);
  klog("system-slot: self-test passed redundant_metadata=2 slots=2 active=%u\n",
       g_metadata.active_slot);
}
