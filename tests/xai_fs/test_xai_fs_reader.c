#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <xaios_engine/model_file.h>
#include <xaios_engine/xai_fs.h>

#include "sha256.h"
#include "tweetnacl_subset.h"

#include "test_xai_fs_reader_support.h"

int xaios_random(void *buffer, uint64_t size) {
  (void)buffer;
  (void)size;
  return -1;
}

xaios_engine_status_t xaifs_test_read_at(void *context, uint64_t offset,
                                     void *destination, size_t length) {
  xaifs_test_file_reader_t *reader = (xaifs_test_file_reader_t *)context;
  if (offset > (uint64_t)INT64_MAX ||
      fseeko(reader->file, (off_t)offset, SEEK_SET) != 0 ||
      fread(destination, 1U, length, reader->file) != length) {
    return XAIOS_ENGINE_ERR_IO;
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaifs_test_write_at(void *context, uint64_t offset,
                                      const void *source, size_t length) {
  xaifs_test_file_writer_t *writer = (xaifs_test_file_writer_t *)context;
  if (writer->fail_superblock && offset < 2U * 4096U) {
    return XAIOS_ENGINE_ERR_IO;
  }
  if (offset > (uint64_t)INT64_MAX ||
      fseeko(writer->file, (off_t)offset, SEEK_SET) != 0 ||
      fwrite(source, 1U, length, writer->file) != length) {
    return XAIOS_ENGINE_ERR_IO;
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaifs_test_flush_writer(void *context) {
  xaifs_test_file_writer_t *writer = (xaifs_test_file_writer_t *)context;
  return fflush(writer->file) == 0 && fsync(fileno(writer->file)) == 0
             ? XAIOS_ENGINE_OK
             : XAIOS_ENGINE_ERR_IO;
}

xaios_engine_status_t xaifs_test_verify_signature(
    void *context, const uint8_t public_key[32], const uint8_t signature[64],
    const uint8_t message[32]) {
  (void)context;
  return xaios_ed25519_verify(signature, message, 32U, public_key) == 0
             ? XAIOS_ENGINE_OK
             : XAIOS_ENGINE_ERR_CHECKSUM;
}

typedef struct prefetch_capture {
  uint64_t calls;
  uint64_t bytes;
} prefetch_capture_t;

static xaios_engine_status_t capture_prefetch(void *context,
                                               uint64_t physical_offset,
                                               uint64_t length) {
  prefetch_capture_t *capture = (prefetch_capture_t *)context;
  assert(physical_offset >= XAIOS_XAI_FS_DATA_START);
  assert(length != 0U);
  ++capture->calls;
  capture->bytes += length;
  return XAIOS_ENGINE_OK;
}

int main(int argc, char **argv) {
  assert(argc == 3);
  FILE *file = fopen(argv[1], "r+b");
  assert(file != NULL);
  assert(fseeko(file, 0, SEEK_END) == 0);
  off_t end = ftello(file);
  assert(end > 0);
  xaifs_test_file_reader_t context = {file};
  xaios_xai_fs_reader_t reader = {
      &context,
      xaifs_test_read_at,
      (uint64_t)end,
  };
  static uint8_t scratch[64U * 1024U];
  xaios_xai_fs_t volume;
  assert(xaios_xai_fs_open(&reader, xaifs_test_verify_signature, NULL, scratch,
                                 sizeof(scratch), &volume) ==
         XAIOS_ENGINE_OK);
  assert(volume.package_count == 3U);
  assert(volume.volume_size == UINT64_C(67108864));
  assert(volume.chunk_size == UINT64_C(2097152));

  xaios_xai_fs_package_t package;
  assert(xaios_xai_fs_read_package(&volume, 0U, &package) ==
         XAIOS_ENGINE_OK);
  assert(package.state == XAIOS_XAI_FS_PACKAGE_ACTIVE);
  assert(package.logical_size == UINT64_C(2101248));
  assert(strcmp(package.architecture_id, "c-reader-test") == 0);
  uint64_t bad_offset = 0U;
  assert(xaios_xai_fs_verify_package(&volume, &package, scratch,
                                           sizeof(scratch), &bad_offset) ==
         XAIOS_ENGINE_OK);
  assert(bad_offset == UINT64_MAX);
  assert(xaios_xai_fs_verify_package_manifest(&volume, &package) ==
         XAIOS_ENGINE_OK);

  xaios_xai_fs_package_t sftp_staging;
  assert(xaios_xai_fs_read_package(&volume, 2U, &sftp_staging) ==
         XAIOS_ENGINE_OK);
  assert(sftp_staging.state == XAIOS_XAI_FS_PACKAGE_STAGING);
  assert(sftp_staging.logical_size == UINT64_C(2162688));
  assert(sftp_staging.chunk_count == 2U);
  assert(strcmp(sftp_staging.architecture_id, "sftp-staging-test") == 0);
  assert(xaios_xai_fs_verify_package_manifest(&volume, &sftp_staging) ==
         XAIOS_ENGINE_OK);

  /* Straddling a chunk boundary: the tail of one chunk and the head of the
     next, so neither is read whole and both have to be hashed whole anyway. */
  uint8_t data[8192];
  uint64_t offset = UINT64_C(2093056);
  assert(xaios_xai_fs_pread_verified(
             &volume, &package, offset, data, sizeof(data), scratch,
             sizeof(scratch), &bad_offset) == XAIOS_ENGINE_OK);
  assert(bad_offset == UINT64_MAX);
  for (uint64_t index = 0U; index < sizeof(data); ++index) {
    assert(data[index] == (uint8_t)((offset + index) % 4096U % 251U));
  }

  /* A request covering exactly one whole chunk, which is the case the read
     path optimises: the bytes go straight into the caller's buffer and are
     hashed there, so the scratch is never touched. Poison the scratch first
     so a version that quietly went through it would return the poison. */
  static uint8_t whole_chunk[2U * 1024U * 1024U];
  memset(scratch, 0xa5, sizeof(scratch));
  assert(xaios_xai_fs_pread_verified(
             &volume, &package, 0U, whole_chunk, sizeof(whole_chunk), scratch,
             sizeof(scratch), &bad_offset) == XAIOS_ENGINE_OK);
  assert(bad_offset == UINT64_MAX);
  for (uint64_t index = 0U; index < sizeof(whole_chunk); ++index) {
    assert(whole_chunk[index] == (uint8_t)(index % 4096U % 251U));
  }

  /* A read the extent map cannot satisfy in full must fail rather than hand
     back a buffer that is right in front and untouched behind. */
  assert(xaios_xai_fs_pread_verified(
             &volume, &package, package.logical_size - 8U, data, 4096U,
             scratch, sizeof(scratch), &bad_offset) ==
         XAIOS_ENGINE_ERR_INVALID);

  xaios_model_file_t model;
  assert(xaios_model_file_open(&volume, package.package_id, 0U, &model) ==
         XAIOS_ENGINE_OK);
  uint64_t extent_count = 0U;
  assert(xaios_model_file_extent_map(&model, NULL, 0U, &extent_count) ==
         XAIOS_ENGINE_ERR_CAPABILITY);
  assert(extent_count == 2U);
  xaios_model_file_extent_t extents[2];
  assert(xaios_model_file_extent_map(&model, extents, 2U, &extent_count) ==
         XAIOS_ENGINE_OK);
  assert(extents[0].logical_offset == 0U);
  assert(extents[0].length == UINT64_C(2097152));
  assert(extents[0].zero == 0U);
  assert(extents[1].logical_offset == UINT64_C(2097152));
  assert(extents[1].length == 4096U);

  prefetch_capture_t capture = {0U, 0U};
  assert(xaios_model_file_prefetch(&model, offset, sizeof(data),
                                   capture_prefetch, &capture) ==
         XAIOS_ENGINE_OK);
  assert(capture.calls == 2U);
  assert(capture.bytes == sizeof(data));

  void *arena = NULL;
  assert(posix_memalign(&arena, 4096U, sizeof(data)) == 0);
  assert(xaios_model_file_read_into_arena(
             &model, offset, arena, sizeof(data), 4096U, scratch,
             sizeof(scratch), &bad_offset) == XAIOS_ENGINE_OK);
  assert(memcmp(arena, data, sizeof(data)) == 0);
  assert(xaios_model_file_read_into_arena(
             &model, offset, (uint8_t *)arena + 1U, sizeof(data), 4096U,
             scratch, sizeof(scratch), &bad_offset) ==
         XAIOS_ENGINE_ERR_INVALID);
  assert(model.metrics.read_calls == 1U);
  assert(model.metrics.requested_bytes == sizeof(data));
  assert(model.metrics.delivered_bytes == sizeof(data));
  assert(model.metrics.prefetch_calls == 2U);
  assert(model.metrics.prefetched_bytes == sizeof(data));
  assert(model.metrics.failures == 0U);
  free(arena);
  xaios_model_file_close(&model);
  assert(xaios_model_file_pread(&model, 0U, data, 1U, scratch,
                                sizeof(scratch), &bad_offset) ==
         XAIOS_ENGINE_ERR_INVALID);

  package.signature[0] ^= 1U;
  assert(xaios_xai_fs_verify_package_manifest(&volume, &package) ==
         XAIOS_ENGINE_ERR_CHECKSUM);
  assert(xaios_xai_fs_verify_package(&volume, &package, scratch,
                                           sizeof(scratch), &bad_offset) ==
         XAIOS_ENGINE_ERR_CHECKSUM);
  package.signature[0] ^= 1U;
  xaifs_test_staging_writer(file, &volume, &package, scratch, sizeof(scratch));
  fclose(file);
  xaifs_test_format_writer();
  xaifs_test_replica_repair();
  xaifs_test_sparse_large_model(argv[2]);
  puts("xaifs: format, signed stream, model-file, and >100 GiB sparse tests passed");
  return 0;
}
