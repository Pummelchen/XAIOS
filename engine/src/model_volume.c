#include <xaios_engine/model_volume.h>

#include <string.h>

#include "sha256.h"

typedef struct volume_candidate {
  uint8_t valid;
  uint8_t volume_uuid[16];
  uint8_t catalog_hash[32];
  uint64_t volume_size;
  uint64_t generation;
  uint64_t catalog_offset;
  uint64_t catalog_length;
  uint64_t catalog_generation;
  uint64_t data_tail;
  uint64_t chunk_size;
  uint64_t package_count;
  uint64_t chunk_count;
  uint64_t package_offset;
  uint64_t chunk_offset;
  uint64_t free_extent_count;
  uint32_t slot;
} volume_candidate_t;

static uint16_t load_le16(const uint8_t *value) {
  return (uint16_t)value[0] | ((uint16_t)value[1] << 8U);
}

static uint32_t load_le32(const uint8_t *value) {
  return (uint32_t)value[0] | ((uint32_t)value[1] << 8U) |
         ((uint32_t)value[2] << 16U) | ((uint32_t)value[3] << 24U);
}

static uint64_t load_le64(const uint8_t *value) {
  uint64_t result = 0U;
  for (uint32_t index = 0U; index < 8U; ++index) {
    result |= (uint64_t)value[index] << (index * 8U);
  }
  return result;
}

static void store_le32(uint8_t output[4], uint32_t value) {
  for (uint32_t index = 0U; index < 4U; ++index) {
    output[index] = (uint8_t)(value >> (index * 8U));
  }
}

static void store_le64(uint8_t output[8], uint64_t value) {
  for (uint32_t index = 0U; index < 8U; ++index) {
    output[index] = (uint8_t)(value >> (index * 8U));
  }
}

static int bytes_zero(const uint8_t *bytes, size_t length) {
  uint8_t combined = 0U;
  for (size_t index = 0U; index < length; ++index) combined |= bytes[index];
  return combined == 0U;
}

static int power_of_two(uint64_t value) {
  return value != 0U && (value & (value - 1U)) == 0U;
}

static xaios_engine_status_t checked_add(uint64_t left, uint64_t right,
                                         uint64_t *result) {
  if (right > UINT64_MAX - left) return XAIOS_ENGINE_ERR_OVERFLOW;
  *result = left + right;
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t checked_multiply(uint64_t left, uint64_t right,
                                              uint64_t *result) {
  if (left != 0U && right > UINT64_MAX / left) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  *result = left * right;
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t range_valid(uint64_t offset, uint64_t length,
                                         uint64_t limit) {
  uint64_t end = 0U;
  if (checked_add(offset, length, &end) != XAIOS_ENGINE_OK || end > limit) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t read_exact(
    const xaios_model_volume_reader_t *reader, uint64_t offset,
    void *destination, size_t length) {
  if (reader == NULL || reader->read_at == NULL || destination == NULL ||
      length == 0U || range_valid(offset, (uint64_t)length, reader->size) !=
                          XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  return reader->read_at(reader->context, offset, destination, length);
}

static void sha256(const void *data, size_t length, uint8_t digest[32]) {
  xaios_engine_sha256_context_t context;
  xaios_engine_sha256_init(&context);
  xaios_engine_sha256_update(&context, data, length);
  xaios_engine_sha256_final(&context, digest);
}

static xaios_engine_status_t hash_reader_range(
    const xaios_model_volume_reader_t *reader, uint64_t offset,
    uint64_t length, void *scratch, size_t scratch_size, uint8_t digest[32]) {
  if (scratch == NULL || scratch_size == 0U ||
      range_valid(offset, length, reader->size) != XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  xaios_engine_sha256_context_t context;
  xaios_engine_sha256_init(&context);
  uint64_t completed = 0U;
  while (completed < length) {
    uint64_t remaining = length - completed;
    size_t count = remaining < (uint64_t)scratch_size
                       ? (size_t)remaining
                       : scratch_size;
    xaios_engine_status_t status =
        read_exact(reader, offset + completed, scratch, count);
    if (status != XAIOS_ENGINE_OK) return status;
    xaios_engine_sha256_update(&context, scratch, count);
    completed += (uint64_t)count;
  }
  xaios_engine_sha256_final(&context, digest);
  return XAIOS_ENGINE_OK;
}

static int valid_chunk_size(uint64_t value) {
  return value >= UINT64_C(2097152) && value <= UINT64_C(16777216) &&
         power_of_two(value);
}

static int valid_target(const char *target) {
  static const char *const targets[] = {
      "portable",          "apple-neon", "apple-accelerate",
      "intel-avx2",        "intel-avx512-vnni", "intel-amx",
  };
  for (size_t index = 0U; index < sizeof(targets) / sizeof(targets[0]);
       ++index) {
    if (strcmp(target, targets[index]) == 0) return 1;
  }
  return 0;
}

static int decode_ascii(const uint8_t source[32], char destination[33]) {
  size_t length = 0U;
  while (length < 32U && source[length] != 0U) {
    if (source[length] < 0x20U || source[length] > 0x7eU) return 0;
    destination[length] = (char)source[length];
    ++length;
  }
  if (length == 0U) return 0;
  for (size_t index = length; index < 32U; ++index) {
    if (source[index] != 0U) return 0;
  }
  destination[length] = '\0';
  return 1;
}

static xaios_engine_status_t decode_catalog_header(
    const xaios_model_volume_reader_t *reader, volume_candidate_t *candidate,
    uint8_t raw[256]) {
  xaios_engine_status_t status = read_exact(
      reader, candidate->catalog_offset, raw,
      (size_t)XAIOS_MODEL_VOLUME_CATALOG_HEADER_SIZE);
  if (status != XAIOS_ENGINE_OK) return status;
  static const uint8_t magic[8] = {'X', 'A', 'I', 'C', 'A', 'T', '1', 0};
  if (memcmp(raw, magic, sizeof(magic)) != 0 || load_le16(raw + 8U) != 1U ||
      load_le16(raw + 10U) != 0U || raw[12] != 1U || raw[13] != 1U ||
      load_le16(raw + 14U) != 0U || load_le64(raw + 16U) != 256U ||
      load_le64(raw + 24U) != candidate->catalog_generation ||
      memcmp(raw + 32U, candidate->volume_uuid, 16U) != 0 ||
      load_le64(raw + 48U) != 384U || load_le64(raw + 64U) != 128U ||
      load_le64(raw + 80U) != 256U ||
      load_le64(raw + 96U) != candidate->catalog_length ||
      load_le64(raw + 104U) != 0U ||
      load_le64(raw + 112U) != candidate->data_tail ||
      load_le64(raw + 128U) != 0U || !bytes_zero(raw + 176U, 80U)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  uint8_t expected[32];
  uint8_t calculated[32];
  memcpy(expected, raw + 144U, sizeof(expected));
  memset(raw + 144U, 0, sizeof(expected));
  sha256(raw, 256U, calculated);
  if (memcmp(expected, calculated, sizeof(expected)) != 0) {
    return XAIOS_ENGINE_ERR_CHECKSUM;
  }
  candidate->package_count = load_le64(raw + 56U);
  candidate->chunk_count = load_le64(raw + 72U);
  candidate->package_offset = load_le64(raw + 80U);
  candidate->chunk_offset = load_le64(raw + 88U);
  candidate->free_extent_count = load_le64(raw + 120U);
  uint64_t package_bytes = 0U;
  uint64_t expected_chunk_offset = 0U;
  uint64_t chunk_bytes = 0U;
  uint64_t expected_length = 0U;
  if (checked_multiply(candidate->package_count, 384U, &package_bytes) !=
          XAIOS_ENGINE_OK ||
      checked_add(256U, package_bytes, &expected_chunk_offset) !=
          XAIOS_ENGINE_OK ||
      checked_multiply(candidate->chunk_count, 128U, &chunk_bytes) !=
          XAIOS_ENGINE_OK ||
      checked_add(expected_chunk_offset, chunk_bytes, &expected_length) !=
          XAIOS_ENGINE_OK ||
      candidate->chunk_offset != expected_chunk_offset ||
      expected_length != candidate->catalog_length) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t read_candidate(
    const xaios_model_volume_reader_t *reader, uint32_t slot, void *scratch,
    size_t scratch_size, volume_candidate_t *candidate) {
  uint8_t *raw = (uint8_t *)scratch;
  if (scratch_size < 4096U) return XAIOS_ENGINE_ERR_INVALID;
  xaios_engine_status_t status =
      read_exact(reader, (uint64_t)slot * 4096U, raw, 4096U);
  if (status != XAIOS_ENGINE_OK) return status;
  static const uint8_t magic[8] = {'X', 'A', 'I', 'O', 'S', 'V', '1', 0};
  uint8_t expected[32];
  uint8_t calculated[32];
  memcpy(expected, raw + 136U, sizeof(expected));
  memset(raw + 136U, 0, sizeof(expected));
  sha256(raw, 4096U, calculated);
  if (memcmp(expected, calculated, sizeof(expected)) != 0) {
    return XAIOS_ENGINE_ERR_CHECKSUM;
  }
  if (memcmp(raw, magic, sizeof(magic)) != 0 || load_le16(raw + 8U) != 1U ||
      load_le16(raw + 10U) != 0U || raw[12] != 1U || raw[13] != 1U ||
      load_le16(raw + 14U) != 0U || load_le64(raw + 16U) != 4096U ||
      load_le64(raw + 24U) != 4096U ||
      !valid_chunk_size(load_le64(raw + 32U)) ||
      load_le64(raw + 40U) > reader->size || load_le64(raw + 48U) == 0U ||
      (load_le64(raw + 56U) & 4095U) != 0U ||
      load_le64(raw + 64U) == 0U || load_le64(raw + 72U) == 0U ||
      load_le64(raw + 80U) < XAIOS_MODEL_VOLUME_DATA_START ||
      load_le64(raw + 80U) > load_le64(raw + 40U) ||
      bytes_zero(raw + 88U, 16U) || !bytes_zero(raw + 168U, 3928U) ||
      range_valid(load_le64(raw + 56U), load_le64(raw + 64U),
                  load_le64(raw + 40U)) != XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  memset(candidate, 0, sizeof(*candidate));
  candidate->slot = slot;
  candidate->volume_size = load_le64(raw + 40U);
  candidate->generation = load_le64(raw + 48U);
  candidate->catalog_offset = load_le64(raw + 56U);
  candidate->catalog_length = load_le64(raw + 64U);
  candidate->catalog_generation = load_le64(raw + 72U);
  candidate->data_tail = load_le64(raw + 80U);
  candidate->chunk_size = load_le64(raw + 32U);
  memcpy(candidate->volume_uuid, raw + 88U, 16U);
  memcpy(candidate->catalog_hash, raw + 104U, 32U);
  status = hash_reader_range(reader, candidate->catalog_offset,
                             candidate->catalog_length, scratch, scratch_size,
                             calculated);
  if (status != XAIOS_ENGINE_OK) return status;
  if (memcmp(calculated, candidate->catalog_hash, 32U) != 0) {
    return XAIOS_ENGINE_ERR_CHECKSUM;
  }
  status = decode_catalog_header(reader, candidate, raw);
  if (status != XAIOS_ENGINE_OK) return status;
  candidate->valid = 1U;
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_model_volume_probe(
    const xaios_model_volume_reader_t *reader, void *scratch,
    size_t scratch_size, xaios_model_volume_probe_t *probe) {
  if (reader == NULL || reader->read_at == NULL || scratch == NULL ||
      scratch_size < 4096U || probe == NULL) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  volume_candidate_t candidates[2];
  memset(candidates, 0, sizeof(candidates));
  xaios_engine_status_t first =
      read_candidate(reader, 0U, scratch, scratch_size, &candidates[0]);
  xaios_engine_status_t second =
      read_candidate(reader, 1U, scratch, scratch_size, &candidates[1]);
  memset(probe, 0, sizeof(*probe));
  probe->first_valid = first == XAIOS_ENGINE_OK ? 1U : 0U;
  probe->second_valid = second == XAIOS_ENGINE_OK ? 1U : 0U;
  if (probe->first_valid == 0U && probe->second_valid == 0U) {
    return first == XAIOS_ENGINE_ERR_CHECKSUM ||
                   second == XAIOS_ENGINE_ERR_CHECKSUM
               ? XAIOS_ENGINE_ERR_CHECKSUM
               : XAIOS_ENGINE_ERR_INVALID;
  }
  volume_candidate_t *selected = probe->first_valid != 0U ? &candidates[0]
                                                           : &candidates[1];
  if (probe->first_valid != 0U && probe->second_valid != 0U) {
    probe->copies_compatible =
        memcmp(candidates[0].volume_uuid, candidates[1].volume_uuid, 16U) ==
                0 &&
        candidates[0].chunk_size == candidates[1].chunk_size;
    if (candidates[1].generation > candidates[0].generation ||
        (candidates[1].generation == candidates[0].generation &&
         candidates[1].slot > candidates[0].slot)) {
      selected = &candidates[1];
    }
  }
  probe->selected_generation = selected->generation;
  probe->selected_volume_size = selected->volume_size;
  probe->selected_superblock = selected->slot;
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_model_volume_open(
    const xaios_model_volume_reader_t *reader,
    xaios_model_volume_verify_signature_fn verify_signature,
    void *verify_context, void *scratch, size_t scratch_size,
    xaios_model_volume_t *volume) {
  if (reader == NULL || reader->read_at == NULL || reader->size < 4096U ||
      scratch == NULL || scratch_size < 4096U || volume == NULL) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  volume_candidate_t candidates[2];
  memset(candidates, 0, sizeof(candidates));
  xaios_engine_status_t first =
      read_candidate(reader, 0U, scratch, scratch_size, &candidates[0]);
  xaios_engine_status_t second =
      read_candidate(reader, 1U, scratch, scratch_size, &candidates[1]);
  if (first != XAIOS_ENGINE_OK && second != XAIOS_ENGINE_OK) {
    return first == XAIOS_ENGINE_ERR_CHECKSUM ||
                   second == XAIOS_ENGINE_ERR_CHECKSUM
               ? XAIOS_ENGINE_ERR_CHECKSUM
               : XAIOS_ENGINE_ERR_INVALID;
  }
  volume_candidate_t *selected = first == XAIOS_ENGINE_OK ? &candidates[0]
                                                           : &candidates[1];
  if (first == XAIOS_ENGINE_OK && second == XAIOS_ENGINE_OK) {
    if (candidates[0].generation == candidates[1].generation &&
        memcmp(candidates[0].catalog_hash, candidates[1].catalog_hash, 32U) !=
            0) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
    if (candidates[1].generation > candidates[0].generation ||
        (candidates[1].generation == candidates[0].generation &&
         candidates[1].slot > candidates[0].slot)) {
      selected = &candidates[1];
    }
  }
  memset(volume, 0, sizeof(*volume));
  volume->reader = *reader;
  volume->verify_signature = verify_signature;
  volume->verify_context = verify_context;
  memcpy(volume->volume_uuid, selected->volume_uuid, 16U);
  memcpy(volume->catalog_hash, selected->catalog_hash, 32U);
  volume->volume_size = selected->volume_size;
  volume->generation = selected->generation;
  volume->catalog_offset = selected->catalog_offset;
  volume->catalog_length = selected->catalog_length;
  volume->catalog_generation = selected->catalog_generation;
  volume->data_tail = selected->data_tail;
  volume->chunk_size = selected->chunk_size;
  volume->package_count = selected->package_count;
  volume->chunk_count = selected->chunk_count;
  volume->package_offset = selected->package_offset;
  volume->chunk_offset = selected->chunk_offset;
  volume->free_extent_count = selected->free_extent_count;
  volume->selected_superblock = selected->slot;
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_model_volume_read_package(
    const xaios_model_volume_t *volume, uint64_t index,
    xaios_model_volume_package_t *package) {
  uint8_t raw[384];
  uint64_t relative = 0U;
  uint64_t base = 0U;
  uint64_t offset = 0U;
  if (volume == NULL || package == NULL || index >= volume->package_count ||
      checked_multiply(index, 384U, &relative) != XAIOS_ENGINE_OK ||
      checked_add(volume->catalog_offset, volume->package_offset, &base) !=
          XAIOS_ENGINE_OK ||
      checked_add(base, relative, &offset) != XAIOS_ENGINE_OK ||
      read_exact(&volume->reader, offset, raw, sizeof(raw)) !=
          XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  memset(package, 0, sizeof(*package));
  package->state = load_le32(raw);
  package->record_id = load_le64(raw + 8U);
  memcpy(package->model_uuid, raw + 16U, 16U);
  memcpy(package->package_id, raw + 32U, 32U);
  memcpy(package->signer_public_key, raw + 64U, 32U);
  memcpy(package->signature, raw + 96U, 64U);
  memcpy(package->source_revision, raw + 160U, 32U);
  package->logical_size = load_le64(raw + 192U);
  package->chunk_size = load_le64(raw + 200U);
  package->chunk_start = load_le64(raw + 208U);
  package->chunk_count = load_le64(raw + 216U);
  uint64_t chunk_end = 0U;
  if ((package->state != XAIOS_MODEL_VOLUME_PACKAGE_STAGING &&
       package->state != XAIOS_MODEL_VOLUME_PACKAGE_ACTIVE &&
       package->state != XAIOS_MODEL_VOLUME_PACKAGE_QUARANTINED) ||
      load_le32(raw + 4U) != 0U || package->record_id == 0U ||
      bytes_zero(package->model_uuid, 16U) ||
      bytes_zero(package->package_id, 32U) ||
      bytes_zero(package->signer_public_key, 32U) ||
      bytes_zero(package->signature, 64U) ||
      bytes_zero(package->source_revision, 32U) ||
      package->logical_size == 0U || package->chunk_size != volume->chunk_size ||
      package->chunk_count == 0U ||
      checked_add(package->chunk_start, package->chunk_count, &chunk_end) !=
          XAIOS_ENGINE_OK ||
      chunk_end > volume->chunk_count ||
      !decode_ascii(raw + 224U, package->architecture_id) ||
      !decode_ascii(raw + 256U, package->target_id) ||
      !valid_target(package->target_id) || !bytes_zero(raw + 288U, 96U)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_model_volume_read_chunk(
    const xaios_model_volume_t *volume, uint64_t index,
    xaios_model_volume_chunk_t *chunk) {
  uint8_t raw[128];
  uint64_t relative = 0U;
  uint64_t base = 0U;
  uint64_t offset = 0U;
  if (volume == NULL || chunk == NULL || index >= volume->chunk_count ||
      checked_multiply(index, 128U, &relative) != XAIOS_ENGINE_OK ||
      checked_add(volume->catalog_offset, volume->chunk_offset, &base) !=
          XAIOS_ENGINE_OK ||
      checked_add(base, relative, &offset) != XAIOS_ENGINE_OK ||
      read_exact(&volume->reader, offset, raw, sizeof(raw)) !=
          XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  memset(chunk, 0, sizeof(*chunk));
  chunk->record_id = load_le64(raw);
  chunk->logical_offset = load_le64(raw + 8U);
  chunk->physical_offset = load_le64(raw + 16U);
  chunk->length = load_le64(raw + 24U);
  chunk->flags = load_le32(raw + 32U);
  memcpy(chunk->checksum, raw + 40U, 32U);
  chunk->extent_length = load_le64(raw + 72U);
  uint64_t physical_end = 0U;
  uint64_t catalog_end = 0U;
  if (load_le32(raw + 36U) != 0U || chunk->length == 0U ||
      (chunk->flags & ~(XAIOS_MODEL_VOLUME_CHUNK_COMPLETE |
                        XAIOS_MODEL_VOLUME_CHUNK_ZERO |
                        XAIOS_MODEL_VOLUME_CHUNK_FREE |
                        XAIOS_MODEL_VOLUME_CHUNK_HASH_PENDING)) != 0U ||
      !bytes_zero(raw + 80U, 48U)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  if ((chunk->flags & XAIOS_MODEL_VOLUME_CHUNK_FREE) != 0U) {
    if (chunk->record_id != 0U || chunk->logical_offset != 0U ||
        chunk->physical_offset < XAIOS_MODEL_VOLUME_DATA_START ||
        (chunk->physical_offset & 4095U) != 0U ||
        (chunk->extent_length & 4095U) != 0U ||
        !bytes_zero(chunk->checksum, 32U) ||
        chunk->extent_length != chunk->length ||
        checked_add(chunk->physical_offset, chunk->extent_length,
                    &physical_end) != XAIOS_ENGINE_OK ||
        physical_end > volume->data_tail) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
  } else if (chunk->record_id == 0U ||
             ((chunk->flags & XAIOS_MODEL_VOLUME_CHUNK_HASH_PENDING) == 0U &&
              bytes_zero(chunk->checksum, 32U)) ||
             ((chunk->flags & XAIOS_MODEL_VOLUME_CHUNK_HASH_PENDING) != 0U &&
              (!bytes_zero(chunk->checksum, 32U) ||
               (chunk->flags & (XAIOS_MODEL_VOLUME_CHUNK_COMPLETE |
                                XAIOS_MODEL_VOLUME_CHUNK_ZERO)) != 0U))) {
    return XAIOS_ENGINE_ERR_INVALID;
  } else if ((chunk->flags & XAIOS_MODEL_VOLUME_CHUNK_ZERO) != 0U) {
    if (chunk->physical_offset != 0U || chunk->extent_length != 0U ||
        (chunk->flags & XAIOS_MODEL_VOLUME_CHUNK_COMPLETE) == 0U) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
  } else if (chunk->physical_offset < XAIOS_MODEL_VOLUME_DATA_START ||
             (chunk->physical_offset & 4095U) != 0U ||
             chunk->extent_length < chunk->length ||
             (chunk->extent_length & 4095U) != 0U ||
             checked_add(chunk->physical_offset, chunk->extent_length,
                         &physical_end) != XAIOS_ENGINE_OK ||
             physical_end > volume->data_tail ||
             checked_add(volume->catalog_offset, volume->catalog_length,
                         &catalog_end) != XAIOS_ENGINE_OK ||
             (chunk->physical_offset < catalog_end &&
              physical_end > volume->catalog_offset)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t verify_chunk_data(
    const xaios_model_volume_t *volume,
    const xaios_model_volume_chunk_t *chunk, void *scratch,
    size_t scratch_size) {
  xaios_engine_sha256_context_t context;
  xaios_engine_sha256_init(&context);
  uint64_t completed = 0U;
  if ((chunk->flags & XAIOS_MODEL_VOLUME_CHUNK_ZERO) != 0U) {
    memset(scratch, 0, scratch_size);
  }
  while (completed < chunk->length) {
    uint64_t remaining = chunk->length - completed;
    size_t count = remaining < (uint64_t)scratch_size
                       ? (size_t)remaining
                       : scratch_size;
    if ((chunk->flags & XAIOS_MODEL_VOLUME_CHUNK_ZERO) == 0U) {
      xaios_engine_status_t status = read_exact(
          &volume->reader, chunk->physical_offset + completed, scratch, count);
      if (status != XAIOS_ENGINE_OK) return status;
    }
    xaios_engine_sha256_update(&context, scratch, count);
    completed += (uint64_t)count;
  }
  uint8_t digest[32];
  xaios_engine_sha256_final(&context, digest);
  return memcmp(digest, chunk->checksum, sizeof(digest)) == 0
             ? XAIOS_ENGINE_OK
             : XAIOS_ENGINE_ERR_CHECKSUM;
}

static xaios_engine_status_t verify_package_identity(
    const xaios_model_volume_t *volume,
    const xaios_model_volume_package_t *package, void *scratch,
    size_t scratch_size, uint64_t *bad_logical_offset, int verify_data) {
  if (volume == NULL || package == NULL || bad_logical_offset == NULL ||
      (verify_data != 0 && (scratch == NULL || scratch_size < 4096U))) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  *bad_logical_offset = UINT64_MAX;
  xaios_engine_sha256_context_t identity;
  xaios_engine_sha256_init(&identity);
  static const uint8_t domain[] = "xaios.model.volume.package.v1\0";
  xaios_engine_sha256_update(&identity, domain, sizeof(domain) - 1U);
  xaios_engine_sha256_update(&identity, package->model_uuid, 16U);
  xaios_engine_sha256_update(&identity, package->source_revision, 32U);
  uint8_t fixed[32];
  memset(fixed, 0, sizeof(fixed));
  memcpy(fixed, package->architecture_id, strlen(package->architecture_id));
  xaios_engine_sha256_update(&identity, fixed, sizeof(fixed));
  memset(fixed, 0, sizeof(fixed));
  memcpy(fixed, package->target_id, strlen(package->target_id));
  xaios_engine_sha256_update(&identity, fixed, sizeof(fixed));
  uint8_t encoded[20];
  store_le64(encoded, package->logical_size);
  store_le64(encoded + 8U, package->chunk_size);
  xaios_engine_sha256_update(&identity, encoded, 16U);
  uint64_t expected_logical = 0U;
  for (uint64_t relative = 0U; relative < package->chunk_count; ++relative) {
    uint64_t index = 0U;
    xaios_model_volume_chunk_t chunk;
    if (checked_add(package->chunk_start, relative, &index) !=
            XAIOS_ENGINE_OK ||
        xaios_model_volume_read_chunk(volume, index, &chunk) !=
            XAIOS_ENGINE_OK ||
        chunk.record_id != package->record_id ||
        (chunk.flags & XAIOS_MODEL_VOLUME_CHUNK_FREE) != 0U ||
        chunk.logical_offset != expected_logical ||
        chunk.length > package->chunk_size ||
        checked_add(expected_logical, chunk.length, &expected_logical) !=
            XAIOS_ENGINE_OK ||
        expected_logical > package->logical_size) {
      *bad_logical_offset = expected_logical;
      return XAIOS_ENGINE_ERR_INVALID;
    }
    store_le64(encoded, chunk.logical_offset);
    store_le64(encoded + 8U, chunk.length);
    store_le32(encoded + 16U,
               (chunk.flags & XAIOS_MODEL_VOLUME_CHUNK_ZERO) != 0U
                   ? XAIOS_MODEL_VOLUME_CHUNK_ZERO
                   : 0U);
    xaios_engine_sha256_update(&identity, encoded, sizeof(encoded));
    xaios_engine_sha256_update(&identity, chunk.checksum, 32U);
    if ((chunk.flags & XAIOS_MODEL_VOLUME_CHUNK_COMPLETE) == 0U &&
        (verify_data != 0 ||
         package->state != XAIOS_MODEL_VOLUME_PACKAGE_STAGING)) {
      *bad_logical_offset = chunk.logical_offset;
      return XAIOS_ENGINE_ERR_INVALID;
    }
    if (verify_data != 0) {
      xaios_engine_status_t status =
          verify_chunk_data(volume, &chunk, scratch, scratch_size);
      if (status != XAIOS_ENGINE_OK) {
        *bad_logical_offset = chunk.logical_offset;
        return status;
      }
    }
  }
  if (expected_logical != package->logical_size) {
    *bad_logical_offset = expected_logical;
    return XAIOS_ENGINE_ERR_INVALID;
  }
  uint8_t package_id[32];
  xaios_engine_sha256_final(&identity, package_id);
  if (memcmp(package_id, package->package_id, sizeof(package_id)) != 0) {
    return XAIOS_ENGINE_ERR_CHECKSUM;
  }
  if (volume->verify_signature == NULL) return XAIOS_ENGINE_ERR_CAPABILITY;
  return volume->verify_signature(volume->verify_context,
                                  package->signer_public_key,
                                  package->signature, package_id);
}

xaios_engine_status_t xaios_model_volume_verify_package(
    const xaios_model_volume_t *volume,
    const xaios_model_volume_package_t *package, void *scratch,
    size_t scratch_size, uint64_t *bad_logical_offset) {
  return verify_package_identity(volume, package, scratch, scratch_size,
                                 bad_logical_offset, 1);
}

xaios_engine_status_t xaios_model_volume_verify_package_manifest(
    const xaios_model_volume_t *volume,
    const xaios_model_volume_package_t *package) {
  uint64_t bad_logical_offset = UINT64_MAX;
  return verify_package_identity(volume, package, NULL, 0U,
                                 &bad_logical_offset, 0);
}

xaios_engine_status_t xaios_model_volume_pread(
    const xaios_model_volume_t *volume,
    const xaios_model_volume_package_t *package, uint64_t offset,
    void *destination, size_t length) {
  if (volume == NULL || package == NULL || destination == NULL || length == 0U ||
      package->state == XAIOS_MODEL_VOLUME_PACKAGE_QUARANTINED ||
      range_valid(offset, (uint64_t)length, package->logical_size) !=
          XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  uint8_t *output = (uint8_t *)destination;
  uint64_t cursor = offset;
  size_t remaining = length;
  for (uint64_t relative = 0U;
       relative < package->chunk_count && remaining != 0U; ++relative) {
    xaios_model_volume_chunk_t chunk;
    uint64_t index = 0U;
    uint64_t chunk_end = 0U;
    if (checked_add(package->chunk_start, relative, &index) !=
            XAIOS_ENGINE_OK ||
        xaios_model_volume_read_chunk(volume, index, &chunk) !=
            XAIOS_ENGINE_OK ||
        checked_add(chunk.logical_offset, chunk.length, &chunk_end) !=
            XAIOS_ENGINE_OK) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
    if (cursor < chunk.logical_offset || cursor >= chunk_end) continue;
    if (chunk.record_id != package->record_id ||
        (chunk.flags & XAIOS_MODEL_VOLUME_CHUNK_COMPLETE) == 0U) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
    uint64_t within = cursor - chunk.logical_offset;
    uint64_t available = chunk.length - within;
    size_t count = available < (uint64_t)remaining ? (size_t)available
                                                   : remaining;
    if ((chunk.flags & XAIOS_MODEL_VOLUME_CHUNK_ZERO) != 0U) {
      memset(output, 0, count);
    } else {
      xaios_engine_status_t status = read_exact(
          &volume->reader, chunk.physical_offset + within, output, count);
      if (status != XAIOS_ENGINE_OK) return status;
    }
    output += count;
    remaining -= count;
    cursor += (uint64_t)count;
  }
  return remaining == 0U ? XAIOS_ENGINE_OK : XAIOS_ENGINE_ERR_INVALID;
}

xaios_engine_status_t xaios_model_volume_verify_range(
    const xaios_model_volume_t *volume,
    const xaios_model_volume_package_t *package, uint64_t offset,
    uint64_t length, void *scratch, size_t scratch_size,
    uint64_t *bad_logical_offset) {
  if (volume == NULL || package == NULL || length == 0U ||
      scratch == NULL || scratch_size < 4096U || bad_logical_offset == NULL ||
      package->state == XAIOS_MODEL_VOLUME_PACKAGE_QUARANTINED ||
      range_valid(offset, length, package->logical_size) !=
          XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  *bad_logical_offset = UINT64_MAX;
  uint64_t requested_end = offset + length;
  for (uint64_t relative = 0U; relative < package->chunk_count; ++relative) {
    uint64_t index = 0U;
    uint64_t chunk_end = 0U;
    xaios_model_volume_chunk_t chunk;
    if (checked_add(package->chunk_start, relative, &index) !=
            XAIOS_ENGINE_OK ||
        xaios_model_volume_read_chunk(volume, index, &chunk) !=
            XAIOS_ENGINE_OK ||
        checked_add(chunk.logical_offset, chunk.length, &chunk_end) !=
            XAIOS_ENGINE_OK ||
        chunk.record_id != package->record_id ||
        (chunk.flags & XAIOS_MODEL_VOLUME_CHUNK_COMPLETE) == 0U ||
        (chunk.flags & XAIOS_MODEL_VOLUME_CHUNK_FREE) != 0U) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
    if (chunk_end <= offset || chunk.logical_offset >= requested_end) continue;
    xaios_engine_status_t status =
        verify_chunk_data(volume, &chunk, scratch, scratch_size);
    if (status != XAIOS_ENGINE_OK) {
      *bad_logical_offset = chunk.logical_offset;
      return status;
    }
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_model_volume_pread_verified(
    const xaios_model_volume_t *volume,
    const xaios_model_volume_package_t *package, uint64_t offset,
    void *destination, size_t length, void *scratch, size_t scratch_size,
    uint64_t *bad_logical_offset) {
  if (destination == NULL) return XAIOS_ENGINE_ERR_INVALID;
  xaios_engine_status_t status = xaios_model_volume_verify_range(
      volume, package, offset, (uint64_t)length, scratch, scratch_size,
      bad_logical_offset);
  return status == XAIOS_ENGINE_OK
             ? xaios_model_volume_pread(volume, package, offset, destination,
                                        length)
             : status;
}
