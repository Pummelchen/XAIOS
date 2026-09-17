/* The xaiFS reader's verify and read path.
 *
 * Split out of `xai_fs.c` unchanged: package verification (both the full,
 * data-checking form and the manifest-only form), the plain read, the
 * range verify and the single-pass verified read. `xai_fs_codec.c` supplies
 * the codec and `xaios_xai_fs_read_chunk` in `xai_fs.c` supplies the chunk
 * records; `<xaios_engine/xai_fs.h>` is unchanged.
 */

#include <xaios_engine/xai_fs.h>

#include <string.h>

#include "sha256.h"
#include "xai_fs_codec.h"

static xaios_engine_status_t verify_chunk_data(
    const xaios_xai_fs_t *volume,
    const xaios_xai_fs_chunk_t *chunk, void *scratch,
    size_t scratch_size) {
  xaios_engine_sha256_context_t context;
  xaios_engine_sha256_init(&context);
  uint64_t completed = 0U;
  if ((chunk->flags & XAIOS_XAI_FS_CHUNK_ZERO) != 0U) {
    memset(scratch, 0, scratch_size);
  }
  while (completed < chunk->length) {
    uint64_t remaining = chunk->length - completed;
    size_t count = remaining < (uint64_t)scratch_size
                       ? (size_t)remaining
                       : scratch_size;
    if ((chunk->flags & XAIOS_XAI_FS_CHUNK_ZERO) == 0U) {
      xaios_engine_status_t status = xai_fs_codec_read_exact(
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
    const xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package, void *scratch,
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
  xai_fs_codec_store_le64(encoded, package->logical_size);
  xai_fs_codec_store_le64(encoded + 8U, package->chunk_size);
  xaios_engine_sha256_update(&identity, encoded, 16U);
  uint64_t expected_logical = 0U;
  for (uint64_t relative = 0U; relative < package->chunk_count; ++relative) {
    uint64_t index = 0U;
    xaios_xai_fs_chunk_t chunk;
    if (xai_fs_codec_checked_add(package->chunk_start, relative, &index) !=
            XAIOS_ENGINE_OK ||
        xaios_xai_fs_read_chunk(volume, index, &chunk) !=
            XAIOS_ENGINE_OK ||
        chunk.record_id != package->record_id ||
        (chunk.flags & XAIOS_XAI_FS_CHUNK_FREE) != 0U ||
        chunk.logical_offset != expected_logical ||
        chunk.length > package->chunk_size ||
        xai_fs_codec_checked_add(expected_logical, chunk.length, &expected_logical) !=
            XAIOS_ENGINE_OK ||
        expected_logical > package->logical_size) {
      *bad_logical_offset = expected_logical;
      return XAIOS_ENGINE_ERR_INVALID;
    }
    xai_fs_codec_store_le64(encoded, chunk.logical_offset);
    xai_fs_codec_store_le64(encoded + 8U, chunk.length);
    xai_fs_codec_store_le32(encoded + 16U,
               (chunk.flags & XAIOS_XAI_FS_CHUNK_ZERO) != 0U
                   ? XAIOS_XAI_FS_CHUNK_ZERO
                   : 0U);
    xaios_engine_sha256_update(&identity, encoded, sizeof(encoded));
    xaios_engine_sha256_update(&identity, chunk.checksum, 32U);
    if ((chunk.flags & XAIOS_XAI_FS_CHUNK_COMPLETE) == 0U &&
        (verify_data != 0 ||
         package->state != XAIOS_XAI_FS_PACKAGE_STAGING)) {
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

xaios_engine_status_t xaios_xai_fs_verify_package(
    const xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package, void *scratch,
    size_t scratch_size, uint64_t *bad_logical_offset) {
  return verify_package_identity(volume, package, scratch, scratch_size,
                                 bad_logical_offset, 1);
}

xaios_engine_status_t xaios_xai_fs_verify_package_manifest(
    const xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package) {
  uint64_t bad_logical_offset = UINT64_MAX;
  return verify_package_identity(volume, package, NULL, 0U,
                                 &bad_logical_offset, 0);
}

xaios_engine_status_t xaios_xai_fs_pread(
    const xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package, uint64_t offset,
    void *destination, size_t length) {
  if (volume == NULL || package == NULL || destination == NULL || length == 0U ||
      package->state == XAIOS_XAI_FS_PACKAGE_QUARANTINED ||
      xai_fs_codec_range_valid(offset, (uint64_t)length, package->logical_size) !=
          XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  uint8_t *output = (uint8_t *)destination;
  uint64_t cursor = offset;
  size_t remaining = length;
  for (uint64_t relative = 0U;
       relative < package->chunk_count && remaining != 0U; ++relative) {
    xaios_xai_fs_chunk_t chunk;
    uint64_t index = 0U;
    uint64_t chunk_end = 0U;
    if (xai_fs_codec_checked_add(package->chunk_start, relative, &index) !=
            XAIOS_ENGINE_OK ||
        xaios_xai_fs_read_chunk(volume, index, &chunk) !=
            XAIOS_ENGINE_OK ||
        xai_fs_codec_checked_add(chunk.logical_offset, chunk.length, &chunk_end) !=
            XAIOS_ENGINE_OK) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
    if (cursor < chunk.logical_offset || cursor >= chunk_end) continue;
    if (chunk.record_id != package->record_id ||
        (chunk.flags & XAIOS_XAI_FS_CHUNK_COMPLETE) == 0U) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
    uint64_t within = cursor - chunk.logical_offset;
    uint64_t available = chunk.length - within;
    size_t count = available < (uint64_t)remaining ? (size_t)available
                                                   : remaining;
    if ((chunk.flags & XAIOS_XAI_FS_CHUNK_ZERO) != 0U) {
      memset(output, 0, count);
    } else {
      xaios_engine_status_t status = xai_fs_codec_read_exact(
          &volume->reader, chunk.physical_offset + within, output, count);
      if (status != XAIOS_ENGINE_OK) return status;
    }
    output += count;
    remaining -= count;
    cursor += (uint64_t)count;
  }
  return remaining == 0U ? XAIOS_ENGINE_OK : XAIOS_ENGINE_ERR_INVALID;
}

xaios_engine_status_t xaios_xai_fs_verify_range(
    const xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package, uint64_t offset,
    uint64_t length, void *scratch, size_t scratch_size,
    uint64_t *bad_logical_offset) {
  if (volume == NULL || package == NULL || length == 0U ||
      scratch == NULL || scratch_size < 4096U || bad_logical_offset == NULL ||
      package->state == XAIOS_XAI_FS_PACKAGE_QUARANTINED ||
      xai_fs_codec_range_valid(offset, length, package->logical_size) !=
          XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  *bad_logical_offset = UINT64_MAX;
  uint64_t requested_end = offset + length;
  for (uint64_t relative = 0U; relative < package->chunk_count; ++relative) {
    uint64_t index = 0U;
    uint64_t chunk_end = 0U;
    xaios_xai_fs_chunk_t chunk;
    if (xai_fs_codec_checked_add(package->chunk_start, relative, &index) !=
            XAIOS_ENGINE_OK ||
        xaios_xai_fs_read_chunk(volume, index, &chunk) !=
            XAIOS_ENGINE_OK ||
        xai_fs_codec_checked_add(chunk.logical_offset, chunk.length, &chunk_end) !=
            XAIOS_ENGINE_OK ||
        chunk.record_id != package->record_id ||
        (chunk.flags & XAIOS_XAI_FS_CHUNK_COMPLETE) == 0U ||
        (chunk.flags & XAIOS_XAI_FS_CHUNK_FREE) != 0U) {
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

/* Read a chunk once, hashing it as it goes, and hand back the part that was
   asked for.
   
   This used to be verify_range followed by pread, which read every byte
   twice: once to compute the digest and again to fill the caller's buffer.
   Reading a 500 GB package that way costs a terabyte of I/O to deliver half
   of one, and on this path there is no reason for it -- the bytes being
   hashed and the bytes being returned are the same bytes.
   
   A request covering a whole chunk reads straight into the caller's buffer
   and hashes it there, so the scratch is not touched at all. A partial
   request still has to read the whole chunk, because the checksum covers the
   whole chunk, but it copies its slice out of what it read rather than going
   back to the volume for it. */
static xaios_engine_status_t pread_verified_chunk(
    const xaios_xai_fs_t *volume, const xaios_xai_fs_chunk_t *chunk,
    uint64_t offset, uint64_t length, uint8_t *destination, void *scratch,
    size_t scratch_size) {
  uint64_t chunk_end = chunk->logical_offset + chunk->length;
  uint64_t wanted_end = offset + length;
  uint64_t slice_start = offset > chunk->logical_offset ? offset
                                                        : chunk->logical_offset;
  uint64_t slice_end = wanted_end < chunk_end ? wanted_end : chunk_end;
  uint8_t *slice = destination + (slice_start - offset);
  int whole = slice_start == chunk->logical_offset && slice_end == chunk_end;

  xaios_engine_sha256_context_t context;
  xaios_engine_sha256_init(&context);
  if ((chunk->flags & XAIOS_XAI_FS_CHUNK_ZERO) != 0U) {
    /* Nothing on the volume to read: the record says the chunk is zero and
       the digest below is what decides whether to believe it. */
    memset(scratch, 0, scratch_size);
    if (slice_end > slice_start) {
      memset(slice, 0, (size_t)(slice_end - slice_start));
    }
    uint64_t completed = 0U;
    while (completed < chunk->length) {
      uint64_t remaining = chunk->length - completed;
      size_t count = remaining < (uint64_t)scratch_size ? (size_t)remaining
                                                        : scratch_size;
      xaios_engine_sha256_update(&context, scratch, count);
      completed += (uint64_t)count;
    }
  } else if (whole) {
    xaios_engine_status_t status = xai_fs_codec_read_exact(
        &volume->reader, chunk->physical_offset, slice, (size_t)chunk->length);
    if (status != XAIOS_ENGINE_OK) return status;
    xaios_engine_sha256_update(&context, slice, (size_t)chunk->length);
  } else {
    uint64_t completed = 0U;
    while (completed < chunk->length) {
      uint64_t remaining = chunk->length - completed;
      size_t count = remaining < (uint64_t)scratch_size ? (size_t)remaining
                                                        : scratch_size;
      xaios_engine_status_t status = xai_fs_codec_read_exact(
          &volume->reader, chunk->physical_offset + completed, scratch, count);
      if (status != XAIOS_ENGINE_OK) return status;
      xaios_engine_sha256_update(&context, scratch, count);
      /* Where this scratch-load sits in the chunk, intersected with what the
         caller asked for. Copying here is what saves the second read. */
      uint64_t load_start = chunk->logical_offset + completed;
      uint64_t load_end = load_start + (uint64_t)count;
      uint64_t copy_start = load_start > slice_start ? load_start : slice_start;
      uint64_t copy_end = load_end < slice_end ? load_end : slice_end;
      if (copy_end > copy_start) {
        memcpy(destination + (copy_start - offset),
               (const uint8_t *)scratch + (copy_start - load_start),
               (size_t)(copy_end - copy_start));
      }
      completed += (uint64_t)count;
    }
  }
  uint8_t digest[32];
  xaios_engine_sha256_final(&context, digest);
  return memcmp(digest, chunk->checksum, sizeof(digest)) == 0
             ? XAIOS_ENGINE_OK
             : XAIOS_ENGINE_ERR_CHECKSUM;
}

xaios_engine_status_t xaios_xai_fs_pread_verified(
    const xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package, uint64_t offset,
    void *destination, size_t length, void *scratch, size_t scratch_size,
    uint64_t *bad_logical_offset) {
  if (volume == NULL || package == NULL || destination == NULL ||
      length == 0U || scratch == NULL || scratch_size < 4096U ||
      bad_logical_offset == NULL ||
      package->state == XAIOS_XAI_FS_PACKAGE_QUARANTINED ||
      xai_fs_codec_range_valid(offset, (uint64_t)length, package->logical_size) !=
          XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  *bad_logical_offset = UINT64_MAX;
  uint64_t requested_end = offset + (uint64_t)length;
  uint64_t delivered = 0U;
  for (uint64_t relative = 0U; relative < package->chunk_count; ++relative) {
    uint64_t index = 0U;
    uint64_t chunk_end = 0U;
    xaios_xai_fs_chunk_t chunk;
    if (xai_fs_codec_checked_add(package->chunk_start, relative, &index) !=
            XAIOS_ENGINE_OK ||
        xaios_xai_fs_read_chunk(volume, index, &chunk) != XAIOS_ENGINE_OK ||
        xai_fs_codec_checked_add(chunk.logical_offset, chunk.length, &chunk_end) !=
            XAIOS_ENGINE_OK ||
        chunk.record_id != package->record_id ||
        (chunk.flags & XAIOS_XAI_FS_CHUNK_COMPLETE) == 0U ||
        (chunk.flags & XAIOS_XAI_FS_CHUNK_FREE) != 0U) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
    if (chunk_end <= offset || chunk.logical_offset >= requested_end) continue;
    xaios_engine_status_t status = pread_verified_chunk(
        volume, &chunk, offset, (uint64_t)length, (uint8_t *)destination,
        scratch, scratch_size);
    if (status != XAIOS_ENGINE_OK) {
      *bad_logical_offset = chunk.logical_offset;
      return status;
    }
    uint64_t slice_start = offset > chunk.logical_offset ? offset
                                                         : chunk.logical_offset;
    uint64_t slice_end = requested_end < chunk_end ? requested_end : chunk_end;
    delivered += slice_end - slice_start;
  }
  /* Every byte asked for came out of a chunk that hashed correctly. A gap in
     the extent map would leave part of the buffer untouched, and returning
     that silently is exactly the kind of quietly-wrong result this path
     exists to prevent. */
  return delivered == (uint64_t)length ? XAIOS_ENGINE_OK
                                       : XAIOS_ENGINE_ERR_INVALID;
}
