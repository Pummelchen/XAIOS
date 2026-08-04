#define _POSIX_C_SOURCE 200809L

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <xaios_engine/model_file.h>
#include <xaios_engine/model_volume.h>

#include "sha256.h"
#include "tweetnacl_subset.h"

typedef struct file_reader {
  FILE *file;
} file_reader_t;

int xaios_random(void *buffer, uint64_t size) {
  (void)buffer;
  (void)size;
  return -1;
}

static xaios_engine_status_t read_at(void *context, uint64_t offset,
                                     void *destination, size_t length) {
  file_reader_t *reader = (file_reader_t *)context;
  if (offset > (uint64_t)INT64_MAX ||
      fseeko(reader->file, (off_t)offset, SEEK_SET) != 0 ||
      fread(destination, 1U, length, reader->file) != length) {
    return XAIOS_ENGINE_ERR_IO;
  }
  return XAIOS_ENGINE_OK;
}

typedef struct file_writer {
  FILE *file;
  int fail_superblock;
} file_writer_t;

static xaios_engine_status_t write_at(void *context, uint64_t offset,
                                      const void *source, size_t length) {
  file_writer_t *writer = (file_writer_t *)context;
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

static xaios_engine_status_t flush_writer(void *context) {
  file_writer_t *writer = (file_writer_t *)context;
  return fflush(writer->file) == 0 && fsync(fileno(writer->file)) == 0
             ? XAIOS_ENGINE_OK
             : XAIOS_ENGINE_ERR_IO;
}

static xaios_engine_status_t verify_signature(
    void *context, const uint8_t public_key[32], const uint8_t signature[64],
    const uint8_t message[32]) {
  (void)context;
  return xaios_ed25519_verify(signature, message, 32U, public_key) == 0
             ? XAIOS_ENGINE_OK
             : XAIOS_ENGINE_ERR_CHECKSUM;
}

static void test_store_le32(uint8_t output[4], uint32_t value) {
  for (uint32_t index = 0U; index < 4U; ++index) {
    output[index] = (uint8_t)(value >> (index * 8U));
  }
}

static void test_store_le64(uint8_t output[8], uint64_t value) {
  for (uint32_t index = 0U; index < 8U; ++index) {
    output[index] = (uint8_t)(value >> (index * 8U));
  }
}

static void hash_bytes(const void *data, size_t length, uint8_t digest[32]) {
  xaios_engine_sha256_context_t context;
  xaios_engine_sha256_init(&context);
  xaios_engine_sha256_update(&context, data, length);
  xaios_engine_sha256_final(&context, digest);
}

static void dynamic_package_identity(
    const xaios_model_volume_package_t *package, const uint8_t checksum[32],
    uint8_t identity[32]) {
  xaios_engine_sha256_context_t context;
  xaios_engine_sha256_init(&context);
  static const uint8_t domain[] = "xaios.model.volume.package.v1\0";
  xaios_engine_sha256_update(&context, domain, sizeof(domain) - 1U);
  xaios_engine_sha256_update(&context, package->model_uuid, 16U);
  xaios_engine_sha256_update(&context, package->source_revision, 32U);
  uint8_t fixed[32];
  memset(fixed, 0, sizeof(fixed));
  memcpy(fixed, package->architecture_id, strlen(package->architecture_id));
  xaios_engine_sha256_update(&context, fixed, sizeof(fixed));
  memset(fixed, 0, sizeof(fixed));
  memcpy(fixed, package->target_id, strlen(package->target_id));
  xaios_engine_sha256_update(&context, fixed, sizeof(fixed));
  uint8_t encoded[20];
  test_store_le64(encoded, package->logical_size);
  test_store_le64(encoded + 8U, package->chunk_size);
  xaios_engine_sha256_update(&context, encoded, 16U);
  test_store_le64(encoded, 0U);
  test_store_le64(encoded + 8U, package->logical_size);
  test_store_le32(encoded + 16U, 0U);
  xaios_engine_sha256_update(&context, encoded, sizeof(encoded));
  xaios_engine_sha256_update(&context, checksum, 32U);
  xaios_engine_sha256_final(&context, identity);
}

typedef struct prefetch_capture {
  uint64_t calls;
  uint64_t bytes;
} prefetch_capture_t;

static xaios_engine_status_t capture_prefetch(void *context,
                                               uint64_t physical_offset,
                                               uint64_t length) {
  prefetch_capture_t *capture = (prefetch_capture_t *)context;
  assert(physical_offset >= XAIOS_MODEL_VOLUME_DATA_START);
  assert(length != 0U);
  ++capture->calls;
  capture->bytes += length;
  return XAIOS_ENGINE_OK;
}

static void test_sparse_large_model(const char *path) {
  FILE *backing = fopen(path, "rb");
  assert(backing != NULL);
  assert(fseeko(backing, 0, SEEK_END) == 0);
  off_t end = ftello(backing);
  assert(end == (off_t)(UINT64_C(128) << 30U));
  file_reader_t context = {backing};
  xaios_model_volume_reader_t reader = {
      &context,
      read_at,
      (uint64_t)end,
  };
  static uint8_t scratch[64U * 1024U];
  xaios_model_volume_t volume;
  assert(xaios_model_volume_open(&reader, verify_signature, NULL, scratch,
                                 sizeof(scratch), &volume) ==
         XAIOS_ENGINE_OK);
  xaios_model_volume_package_t package;
  assert(xaios_model_volume_read_package(&volume, 0U, &package) ==
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

static void test_staging_writer(FILE *file, xaios_model_volume_t *volume,
                                xaios_model_volume_package_t *active,
                                uint8_t *scratch, size_t scratch_size) {
  xaios_model_volume_package_t staging;
  assert(xaios_model_volume_read_package(volume, 1U, &staging) ==
         XAIOS_ENGINE_OK);
  assert(staging.state == XAIOS_MODEL_VOLUME_PACKAGE_STAGING);
  assert(staging.logical_size == 4096U);
  assert(xaios_model_volume_verify_package_manifest(volume, &staging) ==
         XAIOS_ENGINE_OK);
  file_writer_t file_writer = {file, 0};
  xaios_model_volume_writer_t writer = {
      &file_writer,
      write_at,
      flush_writer,
  };

  uint8_t data[4096];
  for (uint64_t index = 0U; index < sizeof(data); ++index) {
    data[index] = (uint8_t)((index * 7U + 3U) & 0xffU);
  }
  uint64_t original_generation = volume->generation;
  uint64_t completed = UINT64_MAX;
  assert(xaios_model_volume_pwrite_staging(volume, active, &writer, 0U, data,
                                           sizeof(data)) ==
         XAIOS_ENGINE_ERR_INVALID);
  uint8_t wrong[1024];
  memset(wrong, 0xa5, sizeof(wrong));
  assert(xaios_model_volume_pwrite_staging(volume, &staging, &writer, 0U,
                                           wrong, sizeof(wrong)) ==
         XAIOS_ENGINE_OK);
  assert(xaios_model_volume_commit_staging_range(
             volume, &staging, &writer, 0U, sizeof(wrong), scratch,
             scratch_size, &completed) == XAIOS_ENGINE_OK);
  assert(completed == 0U && volume->generation == original_generation);

  assert(xaios_model_volume_pwrite_staging(volume, &staging, &writer, 0U, data,
                                           sizeof(data)) ==
         XAIOS_ENGINE_OK);
  file_writer.fail_superblock = 1;
  assert(xaios_model_volume_commit_staging_range(
             volume, &staging, &writer, 0U, sizeof(data), scratch,
             scratch_size, &completed) == XAIOS_ENGINE_ERR_IO);
  assert(volume->generation == original_generation);

  xaios_model_volume_t recovered;
  xaios_model_volume_reader_t reader = {
      &(file_reader_t){file},
      read_at,
      volume->reader.size,
  };
  assert(xaios_model_volume_open(&reader, verify_signature, NULL, scratch,
                                 scratch_size, &recovered) ==
         XAIOS_ENGINE_OK);
  assert(recovered.generation == original_generation);
  xaios_model_volume_chunk_t recovered_chunk;
  assert(xaios_model_volume_read_chunk(&recovered, staging.chunk_start,
                                       &recovered_chunk) == XAIOS_ENGINE_OK);
  assert((recovered_chunk.flags & XAIOS_MODEL_VOLUME_CHUNK_COMPLETE) == 0U);

  file_writer.fail_superblock = 0;
  assert(xaios_model_volume_commit_staging_range(
             volume, &staging, &writer, 0U, sizeof(data), scratch,
             scratch_size, &completed) == XAIOS_ENGINE_OK);
  assert(completed == 1U && volume->generation == original_generation + 1U);
  assert(xaios_model_volume_read_chunk(volume, staging.chunk_start,
                                       &recovered_chunk) == XAIOS_ENGINE_OK);
  assert((recovered_chunk.flags & XAIOS_MODEL_VOLUME_CHUNK_COMPLETE) != 0U);
  uint64_t bad_offset = 0U;
  assert(xaios_model_volume_verify_package(volume, &staging, scratch,
                                           scratch_size, &bad_offset) ==
         XAIOS_ENGINE_OK);
  assert(bad_offset == UINT64_MAX);
  assert(xaios_model_volume_pwrite_staging(volume, &staging, &writer, 0U, data,
                                           sizeof(data)) ==
         XAIOS_ENGINE_ERR_CAPABILITY);

  uint64_t activation_generation = volume->generation;
  file_writer.fail_superblock = 1;
  assert(xaios_model_volume_activate_staging(
             volume, &staging, &writer, scratch, scratch_size) ==
         XAIOS_ENGINE_ERR_IO);
  assert(volume->generation == activation_generation);
  assert(xaios_model_volume_open(&reader, verify_signature, NULL, scratch,
                                 scratch_size, &recovered) ==
         XAIOS_ENGINE_OK);
  assert(xaios_model_volume_read_package(&recovered, 1U, &staging) ==
         XAIOS_ENGINE_OK);
  assert(staging.state == XAIOS_MODEL_VOLUME_PACKAGE_STAGING);

  file_writer.fail_superblock = 0;
  assert(xaios_model_volume_activate_staging(
             volume, &staging, &writer, scratch, scratch_size) ==
         XAIOS_ENGINE_OK);
  assert(volume->generation == activation_generation + 1U);
  assert(xaios_model_volume_read_package(volume, 1U, &staging) ==
         XAIOS_ENGINE_OK);
  assert(staging.state == XAIOS_MODEL_VOLUME_PACKAGE_ACTIVE);
  assert(xaios_model_volume_verify_package(volume, &staging, scratch,
                                           scratch_size, &bad_offset) ==
         XAIOS_ENGINE_OK);
  assert(xaios_model_volume_activate_staging(
             volume, &staging, &writer, scratch, scratch_size) ==
         XAIOS_ENGINE_ERR_INVALID);
}

static void test_format_writer(void) {
  const uint64_t volume_size = UINT64_C(64) << 20U;
  const uint8_t volume_uuid[16] = {
      0x10U, 0x21U, 0x32U, 0x43U, 0x54U, 0x65U, 0x76U, 0x87U,
      0x98U, 0xa9U, 0xbaU, 0xcbU, 0xdcU, 0xedU, 0xfeU, 0x0fU};
  FILE *file = tmpfile();
  assert(file != NULL);
  assert(ftruncate(fileno(file), (off_t)volume_size) == 0);
  file_writer_t file_writer = {file, 0};
  xaios_model_volume_writer_t writer = {
      &file_writer,
      write_at,
      flush_writer,
  };
  static uint8_t scratch[64U * 1024U];
  assert(xaios_model_volume_format(&writer, volume_size, UINT64_C(2097152),
                                   volume_uuid, scratch, sizeof(scratch)) ==
         XAIOS_ENGINE_OK);

  file_reader_t file_reader = {file};
  xaios_model_volume_reader_t reader = {
      &file_reader,
      read_at,
      volume_size,
  };
  xaios_model_volume_t volume;
  assert(xaios_model_volume_open(&reader, verify_signature, NULL, scratch,
                                 sizeof(scratch), &volume) ==
         XAIOS_ENGINE_OK);
  assert(volume.volume_size == volume_size);
  assert(volume.generation == 1U);
  assert(volume.catalog_generation == 1U);
  assert(volume.package_count == 0U);
  assert(volume.chunk_count == 0U);
  assert(volume.data_tail == XAIOS_MODEL_VOLUME_DATA_START);
  assert(memcmp(volume.volume_uuid, volume_uuid, sizeof(volume_uuid)) == 0);

  xaios_model_volume_probe_t probe;
  assert(xaios_model_volume_probe(&reader, scratch, sizeof(scratch), &probe) ==
         XAIOS_ENGINE_OK);
  assert(probe.first_valid == 1U && probe.second_valid == 1U);
  assert(probe.copies_compatible == 1U);
  assert(probe.selected_generation == 1U);

  const uint64_t grown_size = UINT64_C(96) << 20U;
  assert(ftruncate(fileno(file), (off_t)grown_size) == 0);
  reader.size = grown_size;
  volume.reader.size = grown_size;
  file_writer.fail_superblock = 1;
  assert(xaios_model_volume_grow(&volume, &writer, grown_size, scratch,
                                 sizeof(scratch)) == XAIOS_ENGINE_ERR_IO);
  assert(volume.volume_size == volume_size && volume.generation == 1U);
  xaios_model_volume_t recovered;
  assert(xaios_model_volume_open(&reader, verify_signature, NULL, scratch,
                                 sizeof(scratch), &recovered) ==
         XAIOS_ENGINE_OK);
  assert(recovered.volume_size == volume_size && recovered.generation == 1U);

  file_writer.fail_superblock = 0;
  assert(xaios_model_volume_grow(&volume, &writer, grown_size, scratch,
                                 sizeof(scratch)) == XAIOS_ENGINE_OK);
  assert(volume.volume_size == grown_size && volume.generation == 2U);
  assert(xaios_model_volume_grow(&volume, &writer, volume_size, scratch,
                                 sizeof(scratch)) ==
         XAIOS_ENGINE_ERR_UNSUPPORTED);
  assert(xaios_model_volume_open(&reader, verify_signature, NULL, scratch,
                                 sizeof(scratch), &recovered) ==
         XAIOS_ENGINE_OK);
  assert(recovered.volume_size == grown_size && recovered.generation == 2U);

  uint8_t damaged[4096];
  memset(damaged, 0xa5, sizeof(damaged));
  assert(write_at(&file_writer, XAIOS_MODEL_VOLUME_SUPERBLOCK_SIZE, damaged,
                  sizeof(damaged)) ==
         XAIOS_ENGINE_OK);
  assert(flush_writer(&file_writer) == XAIOS_ENGINE_OK);
  assert(xaios_model_volume_probe(&reader, scratch, sizeof(scratch), &probe) ==
         XAIOS_ENGINE_OK);
  assert(probe.first_valid == 1U && probe.second_valid == 0U);
  assert(xaios_model_volume_open(&reader, verify_signature, NULL, scratch,
                                 sizeof(scratch), &volume) ==
         XAIOS_ENGINE_OK);
  assert(volume.selected_superblock == 0U && volume.generation == 2U);
  assert(xaios_model_volume_repair_superblock(
             &volume, &writer, scratch, sizeof(scratch)) == XAIOS_ENGINE_OK);
  assert(xaios_model_volume_probe(&reader, scratch, sizeof(scratch), &probe) ==
         XAIOS_ENGINE_OK);
  assert(probe.first_valid == 1U && probe.second_valid == 1U &&
         probe.copies_compatible == 1U && probe.selected_generation == 2U);

  static uint8_t dynamic_data[4096];
  for (uint64_t index = 0U; index < sizeof(dynamic_data); ++index) {
    dynamic_data[index] = (uint8_t)((index * 11U + 5U) & 0xffU);
  }
  uint8_t data_hash[32];
  hash_bytes(dynamic_data, sizeof(dynamic_data), data_hash);
  xaios_model_volume_package_t package_template;
  memset(&package_template, 0, sizeof(package_template));
  for (uint32_t index = 0U; index < 16U; ++index) {
    package_template.model_uuid[index] = (uint8_t)(0x30U + index);
  }
  for (uint32_t index = 0U; index < 32U; ++index) {
    package_template.source_revision[index] = (uint8_t)(0x60U + index);
  }
  package_template.logical_size = sizeof(dynamic_data);
  package_template.chunk_size = volume.chunk_size;
  memcpy(package_template.architecture_id, "dynamic-test", 13U);
  memcpy(package_template.target_id, "portable", 9U);
  dynamic_package_identity(&package_template, data_hash,
                           package_template.package_id);
  const uint8_t signing_seed[32] = {
      1U,  2U,  3U,  4U,  5U,  6U,  7U,  8U,
      9U,  10U, 11U, 12U, 13U, 14U, 15U, 16U,
      17U, 18U, 19U, 20U, 21U, 22U, 23U, 24U,
      25U, 26U, 27U, 28U, 29U, 30U, 31U, 32U};
  xaios_ed25519_public_key(package_template.signer_public_key, signing_seed);
  assert(xaios_ed25519_sign(package_template.signature,
                            package_template.package_id, 32U,
                            package_template.signer_public_key,
                            signing_seed) == 0);
  xaios_model_volume_package_t registered;
  uint64_t pre_registration_generation = volume.generation;
  file_writer.fail_superblock = 1;
  assert(xaios_model_volume_register_staging(
             &volume, &package_template, &writer, scratch, sizeof(scratch),
             &registered) == XAIOS_ENGINE_ERR_IO);
  assert(volume.generation == pre_registration_generation &&
         volume.package_count == 0U);
  xaios_model_volume_t registration_recovered;
  assert(xaios_model_volume_open(&reader, verify_signature, NULL, scratch,
                                 sizeof(scratch), &registration_recovered) ==
         XAIOS_ENGINE_OK);
  assert(registration_recovered.generation == pre_registration_generation &&
         registration_recovered.package_count == 0U);

  file_writer.fail_superblock = 0;
  assert(xaios_model_volume_register_staging(
             &volume, &package_template, &writer, scratch, sizeof(scratch),
             &registered) == XAIOS_ENGINE_OK);
  assert(registered.state == XAIOS_MODEL_VOLUME_PACKAGE_STAGING &&
         registered.chunk_count == 1U && volume.package_count == 1U);
  xaios_model_volume_chunk_t dynamic_chunk;
  assert(xaios_model_volume_read_chunk(&volume, registered.chunk_start,
                                       &dynamic_chunk) == XAIOS_ENGINE_OK);
  assert(dynamic_chunk.flags == XAIOS_MODEL_VOLUME_CHUNK_HASH_PENDING);
  assert(xaios_model_volume_verify_package_manifest(&volume, &registered) ==
         XAIOS_ENGINE_ERR_CHECKSUM);
  uint64_t completed = UINT64_MAX;
  assert(xaios_model_volume_pwrite_staging(
             &volume, &registered, &writer, 0U, dynamic_data, 2048U) ==
         XAIOS_ENGINE_OK);
  assert(xaios_model_volume_commit_staging_range(
             &volume, &registered, &writer, 0U, 2048U, scratch,
             sizeof(scratch), &completed) == XAIOS_ENGINE_OK);
  assert(completed == 0U);
  assert(xaios_model_volume_pwrite_staging(
             &volume, &registered, &writer, 0U, dynamic_data,
             sizeof(dynamic_data)) == XAIOS_ENGINE_OK);
  assert(xaios_model_volume_commit_staging_range(
             &volume, &registered, &writer, 0U, sizeof(dynamic_data), scratch,
             sizeof(scratch), &completed) == XAIOS_ENGINE_OK);
  assert(completed == 1U);
  assert(xaios_model_volume_read_package(&volume, 0U, &registered) ==
         XAIOS_ENGINE_OK);
  assert(xaios_model_volume_read_chunk(&volume, registered.chunk_start,
                                       &dynamic_chunk) == XAIOS_ENGINE_OK);
  assert(dynamic_chunk.flags == XAIOS_MODEL_VOLUME_CHUNK_COMPLETE &&
         memcmp(dynamic_chunk.checksum, data_hash, 32U) == 0);
  uint64_t dynamic_bad_offset = 0U;
  assert(xaios_model_volume_verify_package(
             &volume, &registered, scratch, sizeof(scratch),
             &dynamic_bad_offset) == XAIOS_ENGINE_OK);
  assert(dynamic_bad_offset == UINT64_MAX);
  assert(xaios_model_volume_activate_staging(
             &volume, &registered, &writer, scratch, sizeof(scratch)) ==
         XAIOS_ENGINE_OK);

  xaios_model_volume_package_t cleanup_template = package_template;
  cleanup_template.model_uuid[0] ^= 0x55U;
  cleanup_template.source_revision[0] ^= 0x33U;
  dynamic_package_identity(&cleanup_template, data_hash,
                           cleanup_template.package_id);
  assert(xaios_ed25519_sign(cleanup_template.signature,
                            cleanup_template.package_id, 32U,
                            cleanup_template.signer_public_key,
                            signing_seed) == 0);
  xaios_model_volume_package_t cleanup_package;
  assert(xaios_model_volume_register_staging(
             &volume, &cleanup_template, &writer, scratch, sizeof(scratch),
             &cleanup_package) == XAIOS_ENGINE_OK);
  xaios_model_volume_chunk_t cleanup_chunk;
  assert(xaios_model_volume_read_chunk(&volume, cleanup_package.chunk_start,
                                       &cleanup_chunk) == XAIOS_ENGINE_OK);
  uint64_t reusable_physical = cleanup_chunk.physical_offset;
  uint64_t cleanup_generation = volume.generation;
  uint64_t reclaimed = 0U;
  file_writer.fail_superblock = 1;
  assert(xaios_model_volume_remove_staging(
             &volume, &cleanup_package, &writer, scratch, sizeof(scratch),
             &reclaimed) == XAIOS_ENGINE_ERR_IO);
  assert(volume.generation == cleanup_generation && reclaimed == 0U);
  assert(xaios_model_volume_open(&reader, verify_signature, NULL, scratch,
                                 sizeof(scratch), &registration_recovered) ==
         XAIOS_ENGINE_OK);
  assert(registration_recovered.package_count == 2U);

  file_writer.fail_superblock = 0;
  assert(xaios_model_volume_remove_staging(
             &volume, &cleanup_package, &writer, scratch, sizeof(scratch),
             &reclaimed) == XAIOS_ENGINE_OK);
  assert(reclaimed == 4096U && volume.package_count == 1U &&
         volume.free_extent_count == 1U);

  xaios_model_volume_package_t reuse_template = cleanup_template;
  reuse_template.model_uuid[1] ^= 0x66U;
  reuse_template.source_revision[1] ^= 0x44U;
  dynamic_package_identity(&reuse_template, data_hash,
                           reuse_template.package_id);
  assert(xaios_ed25519_sign(reuse_template.signature,
                            reuse_template.package_id, 32U,
                            reuse_template.signer_public_key,
                            signing_seed) == 0);
  xaios_model_volume_package_t reused_package;
  assert(xaios_model_volume_register_staging(
             &volume, &reuse_template, &writer, scratch, sizeof(scratch),
             &reused_package) == XAIOS_ENGINE_OK);
  xaios_model_volume_chunk_t reused_chunk;
  assert(xaios_model_volume_read_chunk(&volume, reused_package.chunk_start,
                                       &reused_chunk) == XAIOS_ENGINE_OK);
  assert(reused_chunk.physical_offset == reusable_physical &&
         volume.free_extent_count == 0U);

  file_writer.fail_superblock = 1;
  assert(xaios_model_volume_format(&writer, grown_size, UINT64_C(2097152),
                                   volume_uuid, scratch, sizeof(scratch)) ==
         XAIOS_ENGINE_ERR_IO);
  assert(xaios_model_volume_format(&writer, grown_size, UINT64_C(1048576),
                                   volume_uuid, scratch, sizeof(scratch)) ==
         XAIOS_ENGINE_ERR_INVALID);
  fclose(file);
}

int main(int argc, char **argv) {
  assert(argc == 3);
  FILE *file = fopen(argv[1], "r+b");
  assert(file != NULL);
  assert(fseeko(file, 0, SEEK_END) == 0);
  off_t end = ftello(file);
  assert(end > 0);
  file_reader_t context = {file};
  xaios_model_volume_reader_t reader = {
      &context,
      read_at,
      (uint64_t)end,
  };
  static uint8_t scratch[64U * 1024U];
  xaios_model_volume_t volume;
  assert(xaios_model_volume_open(&reader, verify_signature, NULL, scratch,
                                 sizeof(scratch), &volume) ==
         XAIOS_ENGINE_OK);
  assert(volume.package_count == 3U);
  assert(volume.volume_size == UINT64_C(67108864));
  assert(volume.chunk_size == UINT64_C(2097152));

  xaios_model_volume_package_t package;
  assert(xaios_model_volume_read_package(&volume, 0U, &package) ==
         XAIOS_ENGINE_OK);
  assert(package.state == XAIOS_MODEL_VOLUME_PACKAGE_ACTIVE);
  assert(package.logical_size == UINT64_C(2101248));
  assert(strcmp(package.architecture_id, "c-reader-test") == 0);
  uint64_t bad_offset = 0U;
  assert(xaios_model_volume_verify_package(&volume, &package, scratch,
                                           sizeof(scratch), &bad_offset) ==
         XAIOS_ENGINE_OK);
  assert(bad_offset == UINT64_MAX);
  assert(xaios_model_volume_verify_package_manifest(&volume, &package) ==
         XAIOS_ENGINE_OK);

  xaios_model_volume_package_t sftp_staging;
  assert(xaios_model_volume_read_package(&volume, 2U, &sftp_staging) ==
         XAIOS_ENGINE_OK);
  assert(sftp_staging.state == XAIOS_MODEL_VOLUME_PACKAGE_STAGING);
  assert(sftp_staging.logical_size == UINT64_C(2162688));
  assert(sftp_staging.chunk_count == 2U);
  assert(strcmp(sftp_staging.architecture_id, "sftp-staging-test") == 0);
  assert(xaios_model_volume_verify_package_manifest(&volume, &sftp_staging) ==
         XAIOS_ENGINE_OK);

  uint8_t data[8192];
  uint64_t offset = UINT64_C(2093056);
  assert(xaios_model_volume_pread_verified(
             &volume, &package, offset, data, sizeof(data), scratch,
             sizeof(scratch), &bad_offset) == XAIOS_ENGINE_OK);
  assert(bad_offset == UINT64_MAX);
  for (uint64_t index = 0U; index < sizeof(data); ++index) {
    assert(data[index] == (uint8_t)((offset + index) % 4096U % 251U));
  }

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
  assert(xaios_model_volume_verify_package_manifest(&volume, &package) ==
         XAIOS_ENGINE_ERR_CHECKSUM);
  assert(xaios_model_volume_verify_package(&volume, &package, scratch,
                                           sizeof(scratch), &bad_offset) ==
         XAIOS_ENGINE_ERR_CHECKSUM);
  package.signature[0] ^= 1U;
  test_staging_writer(file, &volume, &package, scratch, sizeof(scratch));
  fclose(file);
  test_format_writer();
  test_sparse_large_model(argv[2]);
  puts("model-volume: format, signed stream, model-file, and >100 GiB sparse tests passed");
  return 0;
}
