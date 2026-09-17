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

void xaifs_test_sparse_large_model(const char *path) {
  FILE *backing = fopen(path, "rb");
  assert(backing != NULL);
  assert(fseeko(backing, 0, SEEK_END) == 0);
  off_t end = ftello(backing);
  assert(end == (off_t)(UINT64_C(128) << 30U));
  xaifs_test_file_reader_t context = {backing};
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
  xaios_xai_fs_package_t package;
  assert(xaios_xai_fs_read_package(&volume, 0U, &package) ==
         XAIOS_ENGINE_OK);
  assert(package.logical_size > (UINT64_C(100) << 30U));

  xaios_model_file_t model;
  assert(xaios_model_file_open(&volume, package.package_id, 0U, &model) ==
         XAIOS_ENGINE_OK);
  void *arena = NULL;
  assert(posix_memalign(&arena, 4096U, 4096U) == 0);
  uint64_t bad_offset = 0U;
  const uint64_t offset = (UINT64_C(100) << 30U) + 4096U;
  assert(xaios_model_file_read_into_arena(
             &model, offset, arena, 4096U, 4096U, scratch, sizeof(scratch),
             &bad_offset) == XAIOS_ENGINE_OK);
  assert(bad_offset == UINT64_MAX);
  for (size_t index = 0U; index < 4096U; ++index) {
    assert(((uint8_t *)arena)[index] == 0U);
  }
  assert(model.metrics.requested_bytes == 4096U);
  assert(model.metrics.delivered_bytes == 4096U);
  free(arena);
  xaios_model_file_close(&model);
  fclose(backing);
}

void xaifs_test_staging_writer(FILE *file, xaios_xai_fs_t *volume,
                                xaios_xai_fs_package_t *active,
                                uint8_t *scratch, size_t scratch_size) {
  xaios_xai_fs_package_t staging;
  assert(xaios_xai_fs_read_package(volume, 1U, &staging) ==
         XAIOS_ENGINE_OK);
  assert(staging.state == XAIOS_XAI_FS_PACKAGE_STAGING);
  assert(staging.logical_size == 4096U);
  assert(xaios_xai_fs_verify_package_manifest(volume, &staging) ==
         XAIOS_ENGINE_OK);
  xaifs_test_file_writer_t file_writer = {file, 0};
  xaios_xai_fs_writer_t writer = {
      &file_writer,
      xaifs_test_write_at,
      xaifs_test_flush_writer,
  };

  uint8_t data[4096];
  for (uint64_t index = 0U; index < sizeof(data); ++index) {
    data[index] = (uint8_t)((index * 7U + 3U) & 0xffU);
  }
  uint64_t original_generation = volume->generation;
  uint64_t completed = UINT64_MAX;
  assert(xaios_xai_fs_pwrite_staging(volume, active, &writer, 0U, data,
                                           sizeof(data)) ==
         XAIOS_ENGINE_ERR_INVALID);
  uint8_t wrong[1024];
  memset(wrong, 0xa5, sizeof(wrong));
  assert(xaios_xai_fs_pwrite_staging(volume, &staging, &writer, 0U,
                                           wrong, sizeof(wrong)) ==
         XAIOS_ENGINE_OK);
  assert(xaios_xai_fs_commit_staging_range(
             volume, &staging, &writer, 0U, sizeof(wrong), scratch,
             scratch_size, &completed) == XAIOS_ENGINE_OK);
  assert(completed == 0U && volume->generation == original_generation);

  assert(xaios_xai_fs_pwrite_staging(volume, &staging, &writer, 0U, data,
                                           sizeof(data)) ==
         XAIOS_ENGINE_OK);
  file_writer.fail_superblock = 1;
  assert(xaios_xai_fs_commit_staging_range(
             volume, &staging, &writer, 0U, sizeof(data), scratch,
             scratch_size, &completed) == XAIOS_ENGINE_ERR_IO);
  assert(volume->generation == original_generation);

  xaios_xai_fs_t recovered;
  xaios_xai_fs_reader_t reader = {
      &(xaifs_test_file_reader_t){file},
      xaifs_test_read_at,
      volume->reader.size,
  };
  assert(xaios_xai_fs_open(&reader, xaifs_test_verify_signature, NULL, scratch,
                                 scratch_size, &recovered) ==
         XAIOS_ENGINE_OK);
  assert(recovered.generation == original_generation);
  xaios_xai_fs_chunk_t recovered_chunk;
  assert(xaios_xai_fs_read_chunk(&recovered, staging.chunk_start,
                                       &recovered_chunk) == XAIOS_ENGINE_OK);
  assert((recovered_chunk.flags & XAIOS_XAI_FS_CHUNK_COMPLETE) == 0U);

  file_writer.fail_superblock = 0;
  assert(xaios_xai_fs_commit_staging_range(
             volume, &staging, &writer, 0U, sizeof(data), scratch,
             scratch_size, &completed) == XAIOS_ENGINE_OK);
  assert(completed == 1U && volume->generation == original_generation + 1U);
  assert(xaios_xai_fs_read_chunk(volume, staging.chunk_start,
                                       &recovered_chunk) == XAIOS_ENGINE_OK);
  assert((recovered_chunk.flags & XAIOS_XAI_FS_CHUNK_COMPLETE) != 0U);
  uint64_t bad_offset = 0U;
  assert(xaios_xai_fs_verify_package(volume, &staging, scratch,
                                           scratch_size, &bad_offset) ==
         XAIOS_ENGINE_OK);
  assert(bad_offset == UINT64_MAX);
  assert(xaios_xai_fs_pwrite_staging(volume, &staging, &writer, 0U, data,
                                           sizeof(data)) ==
         XAIOS_ENGINE_ERR_CAPABILITY);

  uint64_t activation_generation = volume->generation;
  file_writer.fail_superblock = 1;
  assert(xaios_xai_fs_activate_staging(
             volume, &staging, &writer, scratch, scratch_size) ==
         XAIOS_ENGINE_ERR_IO);
  assert(volume->generation == activation_generation);
  assert(xaios_xai_fs_open(&reader, xaifs_test_verify_signature, NULL, scratch,
                                 scratch_size, &recovered) ==
         XAIOS_ENGINE_OK);
  assert(xaios_xai_fs_read_package(&recovered, 1U, &staging) ==
         XAIOS_ENGINE_OK);
  assert(staging.state == XAIOS_XAI_FS_PACKAGE_STAGING);

  file_writer.fail_superblock = 0;
  assert(xaios_xai_fs_activate_staging(
             volume, &staging, &writer, scratch, scratch_size) ==
         XAIOS_ENGINE_OK);
  assert(volume->generation == activation_generation + 1U);
  assert(xaios_xai_fs_read_package(volume, 1U, &staging) ==
         XAIOS_ENGINE_OK);
  assert(staging.state == XAIOS_XAI_FS_PACKAGE_ACTIVE);
  assert(xaios_xai_fs_verify_package(volume, &staging, scratch,
                                           scratch_size, &bad_offset) ==
         XAIOS_ENGINE_OK);
  assert(xaios_xai_fs_activate_staging(
             volume, &staging, &writer, scratch, scratch_size) ==
         XAIOS_ENGINE_ERR_INVALID);
}

void xaifs_test_replica_repair(void) {
  const uint64_t volume_size = UINT64_C(64) << 20U;
  const size_t data_size = (size_t)UINT64_C(3145825);
  static uint8_t scratch[64U * 1024U];
  uint8_t *data = (uint8_t *)malloc(data_size);
  uint8_t *recovered = (uint8_t *)malloc(data_size);
  assert(data != NULL && recovered != NULL);
  for (size_t index = 0U; index < data_size; ++index) {
    data[index] = (uint8_t)((index * 29U + 17U) & 0xffU);
  }

  FILE *source_file = tmpfile();
  FILE *target_file = tmpfile();
  assert(source_file != NULL && target_file != NULL);
  assert(ftruncate(fileno(source_file), (off_t)volume_size) == 0);
  assert(ftruncate(fileno(target_file), (off_t)volume_size) == 0);
  xaifs_test_file_writer_t source_file_writer = {source_file, 0};
  xaifs_test_file_writer_t target_file_writer = {target_file, 0};
  xaios_xai_fs_writer_t source_writer = {
      &source_file_writer, xaifs_test_write_at, xaifs_test_flush_writer};
  xaios_xai_fs_writer_t target_writer = {
      &target_file_writer, xaifs_test_write_at, xaifs_test_flush_writer};
  const uint8_t source_uuid[16] = {
      0x11U, 0x22U, 0x33U, 0x44U, 0x55U, 0x66U, 0x77U, 0x88U,
      0x99U, 0xaaU, 0xbbU, 0xccU, 0xddU, 0xeeU, 0xf0U, 0x01U};
  const uint8_t target_uuid[16] = {
      0x12U, 0x23U, 0x34U, 0x45U, 0x56U, 0x67U, 0x78U, 0x89U,
      0x9aU, 0xabU, 0xbcU, 0xcdU, 0xdeU, 0xefU, 0xf1U, 0x02U};
  assert(xaios_xai_fs_format(&source_writer, volume_size,
                                   UINT64_C(2097152), source_uuid, scratch,
                                   sizeof(scratch)) == XAIOS_ENGINE_OK);
  assert(xaios_xai_fs_format(&target_writer, volume_size,
                                   UINT64_C(2097152), target_uuid, scratch,
                                   sizeof(scratch)) == XAIOS_ENGINE_OK);
  xaifs_test_file_reader_t source_reader_context = {source_file};
  xaifs_test_file_reader_t target_reader_context = {target_file};
  xaios_xai_fs_reader_t source_reader = {
      &source_reader_context, xaifs_test_read_at, volume_size};
  xaios_xai_fs_reader_t target_reader = {
      &target_reader_context, xaifs_test_read_at, volume_size};
  xaios_xai_fs_t source;
  xaios_xai_fs_t target;
  assert(xaios_xai_fs_open(&source_reader, xaifs_test_verify_signature, NULL,
                                 scratch, sizeof(scratch), &source) ==
         XAIOS_ENGINE_OK);
  assert(xaios_xai_fs_open(&target_reader, xaifs_test_verify_signature, NULL,
                                 scratch, sizeof(scratch), &target) ==
         XAIOS_ENGINE_OK);

  xaios_xai_fs_package_t package_template;
  memset(&package_template, 0, sizeof(package_template));
  for (uint32_t index = 0U; index < 16U; ++index) {
    package_template.model_uuid[index] = (uint8_t)(0x41U + index);
  }
  for (uint32_t index = 0U; index < 32U; ++index) {
    package_template.source_revision[index] = (uint8_t)(0x70U + index);
  }
  package_template.logical_size = data_size;
  package_template.chunk_size = source.chunk_size;
  memcpy(package_template.architecture_id, "replica-test", 13U);
  memcpy(package_template.target_id, "portable", 9U);
  xaifs_test_replica_package_identity(&package_template, data, package_template.package_id);
  const uint8_t signing_seed[32] = {
      31U, 30U, 29U, 28U, 27U, 26U, 25U, 24U,
      23U, 22U, 21U, 20U, 19U, 18U, 17U, 16U,
      15U, 14U, 13U, 12U, 11U, 10U, 9U, 8U,
      7U, 6U, 5U, 4U, 3U, 2U, 1U, 0U};
  xaios_ed25519_public_key(package_template.signer_public_key, signing_seed);
  assert(xaios_ed25519_sign(package_template.signature,
                            package_template.package_id, 32U,
                            package_template.signer_public_key,
                            signing_seed) == 0);
  xaios_xai_fs_package_t source_package;
  xaios_xai_fs_package_t target_package;
  xaifs_test_write_active_package(&source, &package_template, data, &source_writer,
                       scratch, sizeof(scratch), &source_package);
  xaifs_test_write_active_package(&target, &package_template, data, &target_writer,
                       scratch, sizeof(scratch), &target_package);

  xaios_xai_fs_chunk_t target_chunk;
  assert(xaios_xai_fs_read_chunk(&target, target_package.chunk_start,
                                       &target_chunk) == XAIOS_ENGINE_OK);
  uint8_t damaged = 0U;
  assert(xaifs_test_write_at(&target_file_writer, target_chunk.physical_offset + 4096U,
                  &damaged, sizeof(damaged)) == XAIOS_ENGINE_OK);
  assert(xaifs_test_flush_writer(&target_file_writer) == XAIOS_ENGINE_OK);
  uint64_t bad_offset = UINT64_MAX;
  assert(xaios_xai_fs_verify_package(&target, &target_package, scratch,
                                           sizeof(scratch), &bad_offset) ==
         XAIOS_ENGINE_ERR_CHECKSUM);
  assert(xaios_xai_fs_quarantine_package(
             &target, &target_package, &target_writer, scratch,
             sizeof(scratch)) == XAIOS_ENGINE_OK);
  assert(xaios_xai_fs_read_package(&target, 0U, &target_package) ==
         XAIOS_ENGINE_OK);
  assert(target_package.state == XAIOS_XAI_FS_PACKAGE_QUARANTINED);

  const uint64_t quarantined_generation = target.generation;
  xaios_xai_fs_package_t mismatch = source_package;
  mismatch.source_revision[0] ^= 0xffU;
  assert(xaios_xai_fs_repair_from_replica(
             &target, &target_package, &source, &mismatch, &target_writer,
             scratch, sizeof(scratch), NULL) == XAIOS_ENGINE_ERR_INVALID);
  assert(target.generation == quarantined_generation);

  xaios_xai_fs_chunk_t source_chunk;
  assert(xaios_xai_fs_read_chunk(&source, source_package.chunk_start,
                                       &source_chunk) == XAIOS_ENGINE_OK);
  uint8_t original = data[8192U];
  uint8_t corrupt = (uint8_t)(original ^ 0xffU);
  assert(xaifs_test_write_at(&source_file_writer, source_chunk.physical_offset + 8192U,
                  &corrupt, sizeof(corrupt)) == XAIOS_ENGINE_OK);
  assert(xaifs_test_flush_writer(&source_file_writer) == XAIOS_ENGINE_OK);
  assert(xaios_xai_fs_repair_from_replica(
             &target, &target_package, &source, &source_package,
             &target_writer, scratch, sizeof(scratch), NULL) ==
         XAIOS_ENGINE_ERR_CHECKSUM);
  assert(target.generation == quarantined_generation);
  assert(xaifs_test_write_at(&source_file_writer, source_chunk.physical_offset + 8192U,
                  &original, sizeof(original)) == XAIOS_ENGINE_OK);
  assert(xaifs_test_flush_writer(&source_file_writer) == XAIOS_ENGINE_OK);

  target_file_writer.fail_superblock = 1;
  assert(xaios_xai_fs_repair_from_replica(
             &target, &target_package, &source, &source_package,
             &target_writer, scratch, sizeof(scratch), NULL) ==
         XAIOS_ENGINE_ERR_IO);
  xaios_xai_fs_t reopened_target;
  assert(xaios_xai_fs_open(&target_reader, xaifs_test_verify_signature, NULL,
                                 scratch, sizeof(scratch), &reopened_target) ==
         XAIOS_ENGINE_OK);
  assert(reopened_target.generation == quarantined_generation);
  assert(xaios_xai_fs_read_package(&reopened_target, 0U,
                                         &target_package) == XAIOS_ENGINE_OK);
  assert(target_package.state == XAIOS_XAI_FS_PACKAGE_QUARANTINED);
  target = reopened_target;
  target_file_writer.fail_superblock = 0;

  uint64_t copied = 0U;
  assert(xaios_xai_fs_repair_from_replica(
             &target, &target_package, &source, &source_package,
             &target_writer, scratch, sizeof(scratch), &copied) ==
         XAIOS_ENGINE_OK);
  assert(copied == data_size);
  assert(xaios_xai_fs_read_package(&target, 0U, &target_package) ==
         XAIOS_ENGINE_OK);
  assert(target_package.state == XAIOS_XAI_FS_PACKAGE_ACTIVE);
  assert(xaios_xai_fs_verify_package(&target, &target_package, scratch,
                                           sizeof(scratch), &bad_offset) ==
         XAIOS_ENGINE_OK);
  assert(xaios_xai_fs_pread(&target, &target_package, 0U, recovered,
                                  data_size) == XAIOS_ENGINE_OK);
  assert(memcmp(data, recovered, data_size) == 0);
  assert(xaios_xai_fs_repair_from_replica(
             &target, &target_package, &source, &source_package,
             &target_writer, scratch, sizeof(scratch), NULL) ==
         XAIOS_ENGINE_ERR_INVALID);

  fclose(source_file);
  fclose(target_file);
  free(recovered);
  free(data);
}
