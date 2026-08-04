#include "system_volume_loader.h"

#include <xaios/system_slot.h>
#include <xaios/sha256.h>
#include "tweetnacl_subset.h"

#define SYSTEM_BLOCK_SIZE UINT32_C(512)
#define SYSTEM_KERNEL_MAX_BYTES (XAIOS_SYSTEM_SLOT_SECTORS * SYSTEM_BLOCK_SIZE)

static const efi_guid_t k_block_io_guid = {
    0x964e5b21U,
    0x6459U,
    0x11d2U,
    {0x8e, 0x39, 0x00, 0xa0, 0xc9, 0x69, 0x72, 0x3b}};

static const uint8_t k_update_public_key[32] = {
    0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7,
    0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07, 0x3a,
    0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25,
    0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07, 0x51, 0x1a};

static int status_error(efi_status_t status) {
  return (status & (UINT64_C(1) << 63U)) != 0U;
}

static void bytes_copy(void *destination, const void *source, uint64_t size) {
  uint8_t *out = (uint8_t *)destination;
  const uint8_t *in = (const uint8_t *)source;
  for (uint64_t index = 0U; index < size; ++index) out[index] = in[index];
}

static void bytes_zero(void *destination, uint64_t size) {
  uint8_t *out = (uint8_t *)destination;
  for (uint64_t index = 0U; index < size; ++index) out[index] = 0U;
}

static int bytes_equal(const void *left, const void *right, uint64_t size) {
  const uint8_t *lhs = (const uint8_t *)left;
  const uint8_t *rhs = (const uint8_t *)right;
  uint8_t difference = 0U;
  for (uint64_t index = 0U; index < size; ++index) {
    difference |= lhs[index] ^ rhs[index];
  }
  return difference == 0U;
}

static int hex_value(char value) {
  if (value >= '0' && value <= '9') return value - '0';
  if (value >= 'a' && value <= 'f') return value - 'a' + 10;
  if (value >= 'A' && value <= 'F') return value - 'A' + 10;
  return -1;
}

static int parse_hex(const char *text, uint8_t *output, uint32_t bytes) {
  for (uint32_t index = 0U; index < bytes; ++index) {
    int high = hex_value(text[index * 2U]);
    int low = hex_value(text[index * 2U + 1U]);
    if (high < 0 || low < 0) return 0;
    output[index] = (uint8_t)((high << 4U) | low);
  }
  return 1;
}

static int match_literal(const char **cursor, const char *literal) {
  while (*literal != '\0') {
    if (**cursor != *literal) return 0;
    ++*cursor;
    ++literal;
  }
  return 1;
}

static int parse_decimal(const char **cursor, uint64_t *value) {
  uint64_t parsed = 0U;
  uint32_t digits = 0U;
  while (**cursor >= '0' && **cursor <= '9') {
    uint64_t digit = (uint64_t)(**cursor - '0');
    if (parsed > (UINT64_MAX - digit) / 10U) return 0;
    parsed = parsed * 10U + digit;
    ++*cursor;
    ++digits;
  }
  if (digits == 0U) return 0;
  *value = parsed;
  return 1;
}

static int verify_signature(const xaios_system_slot_descriptor_t *slot) {
  const char *cursor = slot->signature;
  const char *start = cursor;
  uint64_t generation = 0U;
  uint8_t digest[32];
  uint8_t signature[64];
  if (!match_literal(&cursor, "xaios-update:v2:gen=") ||
      !parse_decimal(&cursor, &generation) || *cursor++ != ':' ||
      !match_literal(&cursor, "sha256=") ||
      !parse_hex(cursor, digest, sizeof(digest))) {
    return 0;
  }
  cursor += sizeof(digest) * 2U;
  if (*cursor++ != ':' || !match_literal(&cursor, "key=") ||
      !parse_hex(cursor, signature, 32U) ||
      !bytes_equal(signature, k_update_public_key, 32U)) {
    return 0;
  }
  cursor += 64U;
  const char *signed_end = cursor;
  if (*cursor++ != ':' || !match_literal(&cursor, "sig=") ||
      !parse_hex(cursor, signature, sizeof(signature))) {
    return 0;
  }
  cursor += sizeof(signature) * 2U;
  if (*cursor != '\0' || generation != slot->generation ||
      !bytes_equal(digest, slot->sha256, sizeof(digest))) {
    return 0;
  }
  uint64_t signed_length = (uint64_t)(signed_end - start);
  return signed_length <= UINT32_MAX &&
         xaios_ed25519_verify(signature, (const uint8_t *)start,
                              (uint32_t)signed_length,
                              k_update_public_key) == 0;
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

static efi_status_t read_metadata(efi_block_io_protocol_t *block,
                                  xaios_system_metadata_t *metadata) {
  xaios_system_metadata_t primary;
  xaios_system_metadata_t backup;
  efi_status_t primary_status = block->read_blocks(
      block, block->media->media_id, XAIOS_SYSTEM_METADATA_PRIMARY_LBA,
      sizeof(primary), &primary);
  efi_status_t backup_status = block->read_blocks(
      block, block->media->media_id, XAIOS_SYSTEM_METADATA_BACKUP_LBA,
      sizeof(backup), &backup);
  int primary_valid = !status_error(primary_status) && metadata_valid(&primary);
  int backup_valid = !status_error(backup_status) && metadata_valid(&backup);
  if (!primary_valid && !backup_valid) return EFI_NOT_FOUND;
  if (primary_valid && (!backup_valid || primary.sequence >= backup.sequence)) {
    bytes_copy(metadata, &primary, sizeof(*metadata));
  } else {
    bytes_copy(metadata, &backup, sizeof(*metadata));
  }
  return EFI_SUCCESS;
}

static efi_status_t write_metadata(efi_block_io_protocol_t *block,
                                   xaios_system_metadata_t *metadata) {
  if (block->media->read_only != 0U) return EFI_WRITE_PROTECTED;
  xaios_sha256(metadata, sizeof(*metadata) - sizeof(metadata->metadata_sha256),
               metadata->metadata_sha256);
  efi_status_t status = block->write_blocks(
      block, block->media->media_id, XAIOS_SYSTEM_METADATA_BACKUP_LBA,
      sizeof(*metadata), metadata);
  if (status_error(status)) return status;
  status = block->flush_blocks(block);
  if (status_error(status)) return status;
  status = block->write_blocks(
      block, block->media->media_id, XAIOS_SYSTEM_METADATA_PRIMARY_LBA,
      sizeof(*metadata), metadata);
  if (status_error(status)) return status;
  return block->flush_blocks(block);
}

static int descriptor_valid(const xaios_system_slot_descriptor_t *slot,
                            uint32_t slot_index,
                            const efi_block_io_media_t *media) {
  uint64_t expected_lba =
      XAIOS_SYSTEM_SLOT0_LBA + slot_index * XAIOS_SYSTEM_SLOT_SECTORS;
  if (slot->valid != 1U || slot->generation == 0U ||
      slot->offset_lba != expected_lba || slot->image_size == 0U ||
      slot->image_size > SYSTEM_KERNEL_MAX_BYTES ||
      slot->offset_lba > media->last_block ||
      (slot->image_size + SYSTEM_BLOCK_SIZE - 1U) / SYSTEM_BLOCK_SIZE >
          media->last_block - slot->offset_lba + 1U) {
    return 0;
  }
  return verify_signature(slot);
}

static efi_status_t load_slot(efi_system_table_t *system_table,
                              efi_block_io_protocol_t *block,
                              const xaios_system_slot_descriptor_t *slot,
                              void **buffer) {
  uint64_t rounded =
      (slot->image_size + SYSTEM_BLOCK_SIZE - 1U) &
      ~(uint64_t)(SYSTEM_BLOCK_SIZE - 1U);
  efi_physical_address_t address = 0U;
  efi_status_t status = system_table->boot_services->allocate_pages(
      EFI_ALLOCATE_ANY_PAGES, EFI_LOADER_DATA, EFI_SIZE_TO_PAGES(rounded),
      &address);
  if (status_error(status)) return status;
  bytes_zero((void *)(uintptr_t)address, rounded);
  status = block->read_blocks(block, block->media->media_id, slot->offset_lba,
                              rounded, (void *)(uintptr_t)address);
  if (status_error(status)) return status;
  uint8_t digest[32];
  xaios_sha256((void *)(uintptr_t)address, slot->image_size, digest);
  if (!bytes_equal(digest, slot->sha256, sizeof(digest))) {
    return EFI_LOAD_ERROR;
  }
  *buffer = (void *)(uintptr_t)address;
  return EFI_SUCCESS;
}

static efi_status_t try_block_device(
    efi_system_table_t *system_table, efi_block_io_protocol_t *block,
    void **kernel_buffer, uint64_t *kernel_size, uint32_t *selected_slot,
    uint64_t *selected_generation, uint32_t *rollback_performed) {
  if (block == 0 || block->media == 0 || block->media->media_present == 0U ||
      block->media->logical_partition != 0U ||
      block->media->block_size != SYSTEM_BLOCK_SIZE ||
      block->media->last_block + 1U < XAIOS_SYSTEM_VOLUME_SECTORS) {
    return EFI_NOT_FOUND;
  }
  xaios_system_metadata_t metadata;
  efi_status_t status = read_metadata(block, &metadata);
  if (status_error(status)) return status;

  uint32_t selected = metadata.active_slot;
  if (metadata.pending_slot != XAIOS_SYSTEM_SLOT_NONE) {
    if (metadata.pending_attempted != 0U) {
      metadata.pending_slot = XAIOS_SYSTEM_SLOT_NONE;
      metadata.pending_attempted = 0U;
      ++metadata.sequence;
      status = write_metadata(block, &metadata);
      if (status_error(status)) return status;
      *rollback_performed = 1U;
    } else if (descriptor_valid(&metadata.slots[metadata.pending_slot],
                                metadata.pending_slot, block->media)) {
      selected = metadata.pending_slot;
      metadata.pending_attempted = 1U;
      ++metadata.sequence;
      status = write_metadata(block, &metadata);
      if (status_error(status)) return status;
    } else {
      metadata.pending_slot = XAIOS_SYSTEM_SLOT_NONE;
      metadata.pending_attempted = 0U;
      ++metadata.sequence;
      status = write_metadata(block, &metadata);
      if (status_error(status)) return status;
      *rollback_performed = 1U;
    }
  }
  if (!descriptor_valid(&metadata.slots[selected], selected, block->media)) {
    return EFI_LOAD_ERROR;
  }
  status = load_slot(system_table, block, &metadata.slots[selected],
                     kernel_buffer);
  if (status_error(status)) return status;
  *kernel_size = metadata.slots[selected].image_size;
  *selected_slot = selected;
  *selected_generation = metadata.slots[selected].generation;
  return EFI_SUCCESS;
}

efi_status_t system_volume_read_kernel(
    efi_handle_t image_handle, efi_system_table_t *system_table,
    void **kernel_buffer, uint64_t *kernel_size, uint32_t *selected_slot,
    uint64_t *selected_generation, uint32_t *rollback_performed) {
  (void)image_handle;
  if (system_table == 0 || system_table->boot_services == 0 ||
      kernel_buffer == 0 || kernel_size == 0 || selected_slot == 0 ||
      selected_generation == 0 || rollback_performed == 0) {
    return EFI_LOAD_ERROR;
  }
  efi_handle_t *handles = 0;
  uint64_t handle_count = 0U;
  efi_status_t status = system_table->boot_services->locate_handle_buffer(
      EFI_LOCATE_BY_PROTOCOL, (efi_guid_t *)&k_block_io_guid, 0,
      &handle_count, &handles);
  if (status_error(status)) return status;
  for (uint64_t index = 0U; index < handle_count; ++index) {
    efi_block_io_protocol_t *block = 0;
    status = system_table->boot_services->handle_protocol(
        handles[index], (efi_guid_t *)&k_block_io_guid, (void **)&block);
    if (status_error(status)) continue;
    status = try_block_device(system_table, block, kernel_buffer, kernel_size,
                              selected_slot, selected_generation,
                              rollback_performed);
    if (!status_error(status)) {
      (void)system_table->boot_services->free_pool(handles);
      return EFI_SUCCESS;
    }
  }
  (void)system_table->boot_services->free_pool(handles);
  return EFI_NOT_FOUND;
}
