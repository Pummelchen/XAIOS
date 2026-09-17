#include <xaios_engine/xai_fs.h>

#include <string.h>

#include "sha256.h"
#include "xai_fs_codec.h"

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

/* Two mebibytes to sixty-four, a power of two.
   
   The ceiling used to be sixteen, and it was the thing that made a package
   past about a terabyte start growing its chunk count again -- the catalog is
   rewritten on every commit and is 128 bytes a chunk, so chunk count is what
   decides whether ingesting one is possible at all. Nothing was sized by this
   figure: every path that touches a chunk streams it through a fixed scratch
   buffer, and the read cache allocates per chunk against a budget. So the cap
   was a limit on nothing but itself.
   
   It is still a cap. Bigger chunks cost more on a partial read, which has to
   hash a whole chunk to hand back any of it, so the policy in the writer only
   reaches for the larger sizes when the catalog would otherwise be worse. */
static int valid_chunk_size(uint64_t value) {
  return value >= UINT64_C(2097152) && value <= UINT64_C(67108864) &&
         xai_fs_codec_power_of_two(value);
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
    const xaios_xai_fs_reader_t *reader, volume_candidate_t *candidate,
    uint8_t raw[256]) {
  xaios_engine_status_t status = xai_fs_codec_read_exact(
      reader, candidate->catalog_offset, raw,
      (size_t)XAIOS_XAI_FS_CATALOG_HEADER_SIZE);
  if (status != XAIOS_ENGINE_OK) return status;
  static const uint8_t magic[8] = {'X', 'A', 'I', 'C', 'A', 'T', '1', 0};
  if (memcmp(raw, magic, sizeof(magic)) != 0 || xai_fs_codec_load_le16(raw + 8U) != 1U ||
      xai_fs_codec_load_le16(raw + 10U) != 0U || raw[12] != 1U || raw[13] != 1U ||
      xai_fs_codec_load_le16(raw + 14U) != 0U || xai_fs_codec_load_le64(raw + 16U) != 256U ||
      xai_fs_codec_load_le64(raw + 24U) != candidate->catalog_generation ||
      memcmp(raw + 32U, candidate->volume_uuid, 16U) != 0 ||
      xai_fs_codec_load_le64(raw + 48U) != 384U || xai_fs_codec_load_le64(raw + 64U) != 128U ||
      xai_fs_codec_load_le64(raw + 80U) != 256U ||
      xai_fs_codec_load_le64(raw + 96U) != candidate->catalog_length ||
      xai_fs_codec_load_le64(raw + 104U) != 0U ||
      xai_fs_codec_load_le64(raw + 112U) != candidate->data_tail ||
      xai_fs_codec_load_le64(raw + 128U) != 0U || !xai_fs_codec_bytes_zero(raw + 176U, 80U)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  uint8_t expected[32];
  uint8_t calculated[32];
  memcpy(expected, raw + 144U, sizeof(expected));
  memset(raw + 144U, 0, sizeof(expected));
  xai_fs_codec_sha256(raw, 256U, calculated);
  if (memcmp(expected, calculated, sizeof(expected)) != 0) {
    return XAIOS_ENGINE_ERR_CHECKSUM;
  }
  candidate->package_count = xai_fs_codec_load_le64(raw + 56U);
  candidate->chunk_count = xai_fs_codec_load_le64(raw + 72U);
  candidate->package_offset = xai_fs_codec_load_le64(raw + 80U);
  candidate->chunk_offset = xai_fs_codec_load_le64(raw + 88U);
  candidate->free_extent_count = xai_fs_codec_load_le64(raw + 120U);
  uint64_t package_bytes = 0U;
  uint64_t expected_chunk_offset = 0U;
  uint64_t chunk_bytes = 0U;
  uint64_t expected_length = 0U;
  if (xai_fs_codec_checked_multiply(candidate->package_count, 384U, &package_bytes) !=
          XAIOS_ENGINE_OK ||
      xai_fs_codec_checked_add(256U, package_bytes, &expected_chunk_offset) !=
          XAIOS_ENGINE_OK ||
      xai_fs_codec_checked_multiply(candidate->chunk_count, 128U, &chunk_bytes) !=
          XAIOS_ENGINE_OK ||
      xai_fs_codec_checked_add(expected_chunk_offset, chunk_bytes, &expected_length) !=
          XAIOS_ENGINE_OK ||
      candidate->chunk_offset != expected_chunk_offset ||
      expected_length != candidate->catalog_length) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t read_candidate(
    const xaios_xai_fs_reader_t *reader, uint32_t slot, void *scratch,
    size_t scratch_size, volume_candidate_t *candidate) {
  uint8_t *raw = (uint8_t *)scratch;
  if (scratch_size < 4096U) return XAIOS_ENGINE_ERR_INVALID;
  xaios_engine_status_t status =
      xai_fs_codec_read_exact(reader, (uint64_t)slot * 4096U, raw, 4096U);
  if (status != XAIOS_ENGINE_OK) return status;
  static const uint8_t magic[8] = {'X', 'A', 'I', 'O', 'S', 'V', '1', 0};
  uint8_t expected[32];
  uint8_t calculated[32];
  memcpy(expected, raw + 136U, sizeof(expected));
  memset(raw + 136U, 0, sizeof(expected));
  xai_fs_codec_sha256(raw, 4096U, calculated);
  if (memcmp(expected, calculated, sizeof(expected)) != 0) {
    return XAIOS_ENGINE_ERR_CHECKSUM;
  }
  if (memcmp(raw, magic, sizeof(magic)) != 0 || xai_fs_codec_load_le16(raw + 8U) != 1U ||
      xai_fs_codec_load_le16(raw + 10U) != 0U || raw[12] != 1U || raw[13] != 1U ||
      xai_fs_codec_load_le16(raw + 14U) != 0U || xai_fs_codec_load_le64(raw + 16U) != 4096U ||
      xai_fs_codec_load_le64(raw + 24U) != 4096U ||
      !valid_chunk_size(xai_fs_codec_load_le64(raw + 32U)) ||
      xai_fs_codec_load_le64(raw + 40U) > reader->size || xai_fs_codec_load_le64(raw + 48U) == 0U ||
      (xai_fs_codec_load_le64(raw + 56U) & 4095U) != 0U ||
      xai_fs_codec_load_le64(raw + 64U) == 0U || xai_fs_codec_load_le64(raw + 72U) == 0U ||
      xai_fs_codec_load_le64(raw + 80U) < XAIOS_XAI_FS_DATA_START ||
      xai_fs_codec_load_le64(raw + 80U) > xai_fs_codec_load_le64(raw + 40U) ||
      xai_fs_codec_bytes_zero(raw + 88U, 16U) || !xai_fs_codec_bytes_zero(raw + 168U, 3928U) ||
      xai_fs_codec_range_valid(xai_fs_codec_load_le64(raw + 56U), xai_fs_codec_load_le64(raw + 64U),
                  xai_fs_codec_load_le64(raw + 40U)) != XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  memset(candidate, 0, sizeof(*candidate));
  candidate->slot = slot;
  candidate->volume_size = xai_fs_codec_load_le64(raw + 40U);
  candidate->generation = xai_fs_codec_load_le64(raw + 48U);
  candidate->catalog_offset = xai_fs_codec_load_le64(raw + 56U);
  candidate->catalog_length = xai_fs_codec_load_le64(raw + 64U);
  candidate->catalog_generation = xai_fs_codec_load_le64(raw + 72U);
  candidate->data_tail = xai_fs_codec_load_le64(raw + 80U);
  candidate->chunk_size = xai_fs_codec_load_le64(raw + 32U);
  memcpy(candidate->volume_uuid, raw + 88U, 16U);
  memcpy(candidate->catalog_hash, raw + 104U, 32U);
  status = xai_fs_codec_hash_reader_range(reader, candidate->catalog_offset,
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

xaios_engine_status_t xaios_xai_fs_probe(
    const xaios_xai_fs_reader_t *reader, void *scratch,
    size_t scratch_size, xaios_xai_fs_probe_t *probe) {
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

xaios_engine_status_t xaios_xai_fs_open(
    const xaios_xai_fs_reader_t *reader,
    xaios_xai_fs_verify_signature_fn verify_signature,
    void *verify_context, void *scratch, size_t scratch_size,
    xaios_xai_fs_t *volume) {
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

xaios_engine_status_t xaios_xai_fs_read_package(
    const xaios_xai_fs_t *volume, uint64_t index,
    xaios_xai_fs_package_t *package) {
  uint8_t raw[384];
  uint64_t relative = 0U;
  uint64_t base = 0U;
  uint64_t offset = 0U;
  if (volume == NULL || package == NULL || index >= volume->package_count ||
      xai_fs_codec_checked_multiply(index, 384U, &relative) != XAIOS_ENGINE_OK ||
      xai_fs_codec_checked_add(volume->catalog_offset, volume->package_offset, &base) !=
          XAIOS_ENGINE_OK ||
      xai_fs_codec_checked_add(base, relative, &offset) != XAIOS_ENGINE_OK ||
      xai_fs_codec_read_exact(&volume->reader, offset, raw, sizeof(raw)) !=
          XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  memset(package, 0, sizeof(*package));
  package->state = xai_fs_codec_load_le32(raw);
  package->record_id = xai_fs_codec_load_le64(raw + 8U);
  memcpy(package->model_uuid, raw + 16U, 16U);
  memcpy(package->package_id, raw + 32U, 32U);
  memcpy(package->signer_public_key, raw + 64U, 32U);
  memcpy(package->signature, raw + 96U, 64U);
  memcpy(package->source_revision, raw + 160U, 32U);
  package->logical_size = xai_fs_codec_load_le64(raw + 192U);
  package->chunk_size = xai_fs_codec_load_le64(raw + 200U);
  package->chunk_start = xai_fs_codec_load_le64(raw + 208U);
  package->chunk_count = xai_fs_codec_load_le64(raw + 216U);
  uint64_t chunk_end = 0U;
  if ((package->state != XAIOS_XAI_FS_PACKAGE_STAGING &&
       package->state != XAIOS_XAI_FS_PACKAGE_ACTIVE &&
       package->state != XAIOS_XAI_FS_PACKAGE_QUARANTINED) ||
      xai_fs_codec_load_le32(raw + 4U) != 0U || package->record_id == 0U ||
      xai_fs_codec_bytes_zero(package->model_uuid, 16U) ||
      xai_fs_codec_bytes_zero(package->package_id, 32U) ||
      xai_fs_codec_bytes_zero(package->signer_public_key, 32U) ||
      xai_fs_codec_bytes_zero(package->signature, 64U) ||
      xai_fs_codec_bytes_zero(package->source_revision, 32U) ||
      package->logical_size == 0U || package->chunk_size != volume->chunk_size ||
      package->chunk_count == 0U ||
      xai_fs_codec_checked_add(package->chunk_start, package->chunk_count, &chunk_end) !=
          XAIOS_ENGINE_OK ||
      chunk_end > volume->chunk_count ||
      !decode_ascii(raw + 224U, package->architecture_id) ||
      !decode_ascii(raw + 256U, package->target_id) ||
      !valid_target(package->target_id) || !xai_fs_codec_bytes_zero(raw + 288U, 96U)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_xai_fs_read_chunk(
    const xaios_xai_fs_t *volume, uint64_t index,
    xaios_xai_fs_chunk_t *chunk) {
  uint8_t raw[128];
  uint64_t relative = 0U;
  uint64_t base = 0U;
  uint64_t offset = 0U;
  if (volume == NULL || chunk == NULL || index >= volume->chunk_count ||
      xai_fs_codec_checked_multiply(index, 128U, &relative) != XAIOS_ENGINE_OK ||
      xai_fs_codec_checked_add(volume->catalog_offset, volume->chunk_offset, &base) !=
          XAIOS_ENGINE_OK ||
      xai_fs_codec_checked_add(base, relative, &offset) != XAIOS_ENGINE_OK ||
      xai_fs_codec_read_exact(&volume->reader, offset, raw, sizeof(raw)) !=
          XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  memset(chunk, 0, sizeof(*chunk));
  chunk->record_id = xai_fs_codec_load_le64(raw);
  chunk->logical_offset = xai_fs_codec_load_le64(raw + 8U);
  chunk->physical_offset = xai_fs_codec_load_le64(raw + 16U);
  chunk->length = xai_fs_codec_load_le64(raw + 24U);
  chunk->flags = xai_fs_codec_load_le32(raw + 32U);
  memcpy(chunk->checksum, raw + 40U, 32U);
  chunk->extent_length = xai_fs_codec_load_le64(raw + 72U);
  uint64_t physical_end = 0U;
  uint64_t catalog_end = 0U;
  if (xai_fs_codec_load_le32(raw + 36U) != 0U || chunk->length == 0U ||
      (chunk->flags & ~(XAIOS_XAI_FS_CHUNK_COMPLETE |
                        XAIOS_XAI_FS_CHUNK_ZERO |
                        XAIOS_XAI_FS_CHUNK_FREE |
                        XAIOS_XAI_FS_CHUNK_HASH_PENDING)) != 0U ||
      !xai_fs_codec_bytes_zero(raw + 80U, 48U)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  if ((chunk->flags & XAIOS_XAI_FS_CHUNK_FREE) != 0U) {
    if (chunk->record_id != 0U || chunk->logical_offset != 0U ||
        chunk->physical_offset < XAIOS_XAI_FS_DATA_START ||
        (chunk->physical_offset & 4095U) != 0U ||
        (chunk->extent_length & 4095U) != 0U ||
        !xai_fs_codec_bytes_zero(chunk->checksum, 32U) ||
        chunk->extent_length != chunk->length ||
        xai_fs_codec_checked_add(chunk->physical_offset, chunk->extent_length,
                    &physical_end) != XAIOS_ENGINE_OK ||
        physical_end > volume->data_tail) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
  } else if (chunk->record_id == 0U ||
             ((chunk->flags & XAIOS_XAI_FS_CHUNK_HASH_PENDING) == 0U &&
              xai_fs_codec_bytes_zero(chunk->checksum, 32U)) ||
             ((chunk->flags & XAIOS_XAI_FS_CHUNK_HASH_PENDING) != 0U &&
              (!xai_fs_codec_bytes_zero(chunk->checksum, 32U) ||
               (chunk->flags & (XAIOS_XAI_FS_CHUNK_COMPLETE |
                                XAIOS_XAI_FS_CHUNK_ZERO)) != 0U))) {
    return XAIOS_ENGINE_ERR_INVALID;
  } else if ((chunk->flags & XAIOS_XAI_FS_CHUNK_ZERO) != 0U) {
    if (chunk->physical_offset != 0U || chunk->extent_length != 0U ||
        (chunk->flags & XAIOS_XAI_FS_CHUNK_COMPLETE) == 0U) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
  } else if (chunk->physical_offset < XAIOS_XAI_FS_DATA_START ||
             (chunk->physical_offset & 4095U) != 0U ||
             chunk->extent_length < chunk->length ||
             (chunk->extent_length & 4095U) != 0U ||
             xai_fs_codec_checked_add(chunk->physical_offset, chunk->extent_length,
                         &physical_end) != XAIOS_ENGINE_OK ||
             physical_end > volume->data_tail ||
             xai_fs_codec_checked_add(volume->catalog_offset, volume->catalog_length,
                         &catalog_end) != XAIOS_ENGINE_OK ||
             (chunk->physical_offset < catalog_end &&
              physical_end > volume->catalog_offset)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  return XAIOS_ENGINE_OK;
}
