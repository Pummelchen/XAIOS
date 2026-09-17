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
    const xaios_xai_fs_package_t *package, const uint8_t checksum[32],
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

void xaifs_test_replica_package_identity(
    const xaios_xai_fs_package_t *package, const uint8_t *data,
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
  for (uint64_t offset = 0U; offset < package->logical_size;) {
    uint64_t length = package->logical_size - offset;
    if (length > package->chunk_size) length = package->chunk_size;
    uint8_t checksum[32];
    hash_bytes(data + offset, (size_t)length, checksum);
    test_store_le64(encoded, offset);
    test_store_le64(encoded + 8U, length);
    test_store_le32(encoded + 16U, 0U);
    xaios_engine_sha256_update(&context, encoded, sizeof(encoded));
    xaios_engine_sha256_update(&context, checksum, sizeof(checksum));
    offset += length;
  }
  xaios_engine_sha256_final(&context, identity);
}

void xaifs_test_format_writer(void) {
  const uint64_t volume_size = UINT64_C(64) << 20U;
  const uint8_t volume_uuid[16] = {
      0x10U, 0x21U, 0x32U, 0x43U, 0x54U, 0x65U, 0x76U, 0x87U,
      0x98U, 0xa9U, 0xbaU, 0xcbU, 0xdcU, 0xedU, 0xfeU, 0x0fU};
  FILE *file = tmpfile();
  assert(file != NULL);
  assert(ftruncate(fileno(file), (off_t)volume_size) == 0);
  xaifs_test_file_writer_t file_writer = {file, 0};
  xaios_xai_fs_writer_t writer = {
      &file_writer,
      xaifs_test_write_at,
      xaifs_test_flush_writer,
  };
  static uint8_t scratch[64U * 1024U];
  assert(xaios_xai_fs_format(&writer, volume_size, UINT64_C(2097152),
                                   volume_uuid, scratch, sizeof(scratch)) ==
         XAIOS_ENGINE_OK);

  xaifs_test_file_reader_t file_reader = {file};
  xaios_xai_fs_reader_t reader = {
      &file_reader,
      xaifs_test_read_at,
      volume_size,
  };
  xaios_xai_fs_t volume;
  assert(xaios_xai_fs_open(&reader, xaifs_test_verify_signature, NULL, scratch,
                                 sizeof(scratch), &volume) ==
         XAIOS_ENGINE_OK);
  assert(volume.volume_size == volume_size);
  assert(volume.generation == 1U);
  assert(volume.catalog_generation == 1U);
  assert(volume.package_count == 0U);
  assert(volume.chunk_count == 0U);
  assert(volume.data_tail == XAIOS_XAI_FS_DATA_START);
  assert(memcmp(volume.volume_uuid, volume_uuid, sizeof(volume_uuid)) == 0);

  xaios_xai_fs_probe_t probe;
  assert(xaios_xai_fs_probe(&reader, scratch, sizeof(scratch), &probe) ==
         XAIOS_ENGINE_OK);
  assert(probe.first_valid == 1U && probe.second_valid == 1U);
  assert(probe.copies_compatible == 1U);
  assert(probe.selected_generation == 1U);

  const uint64_t grown_size = UINT64_C(96) << 20U;
  assert(ftruncate(fileno(file), (off_t)grown_size) == 0);
  reader.size = grown_size;
  volume.reader.size = grown_size;
  file_writer.fail_superblock = 1;
  assert(xaios_xai_fs_grow(&volume, &writer, grown_size, scratch,
                                 sizeof(scratch)) == XAIOS_ENGINE_ERR_IO);
  assert(volume.volume_size == volume_size && volume.generation == 1U);
  xaios_xai_fs_t recovered;
  assert(xaios_xai_fs_open(&reader, xaifs_test_verify_signature, NULL, scratch,
                                 sizeof(scratch), &recovered) ==
         XAIOS_ENGINE_OK);
  assert(recovered.volume_size == volume_size && recovered.generation == 1U);

  file_writer.fail_superblock = 0;
  assert(xaios_xai_fs_grow(&volume, &writer, grown_size, scratch,
                                 sizeof(scratch)) == XAIOS_ENGINE_OK);
  assert(volume.volume_size == grown_size && volume.generation == 2U);
  assert(xaios_xai_fs_grow(&volume, &writer, volume_size, scratch,
                                 sizeof(scratch)) ==
         XAIOS_ENGINE_ERR_UNSUPPORTED);
  assert(xaios_xai_fs_open(&reader, xaifs_test_verify_signature, NULL, scratch,
                                 sizeof(scratch), &recovered) ==
         XAIOS_ENGINE_OK);
  assert(recovered.volume_size == grown_size && recovered.generation == 2U);

  uint8_t damaged[4096];
  memset(damaged, 0xa5, sizeof(damaged));
  assert(xaifs_test_write_at(&file_writer, XAIOS_XAI_FS_SUPERBLOCK_SIZE, damaged,
                  sizeof(damaged)) ==
         XAIOS_ENGINE_OK);
  assert(xaifs_test_flush_writer(&file_writer) == XAIOS_ENGINE_OK);
  assert(xaios_xai_fs_probe(&reader, scratch, sizeof(scratch), &probe) ==
         XAIOS_ENGINE_OK);
  assert(probe.first_valid == 1U && probe.second_valid == 0U);
  assert(xaios_xai_fs_open(&reader, xaifs_test_verify_signature, NULL, scratch,
                                 sizeof(scratch), &volume) ==
         XAIOS_ENGINE_OK);
  assert(volume.selected_superblock == 0U && volume.generation == 2U);
  assert(xaios_xai_fs_repair_superblock(
             &volume, &writer, scratch, sizeof(scratch)) == XAIOS_ENGINE_OK);
  assert(xaios_xai_fs_probe(&reader, scratch, sizeof(scratch), &probe) ==
         XAIOS_ENGINE_OK);
  assert(probe.first_valid == 1U && probe.second_valid == 1U &&
         probe.copies_compatible == 1U && probe.selected_generation == 2U);

  static uint8_t dynamic_data[4096];
  for (uint64_t index = 0U; index < sizeof(dynamic_data); ++index) {
    dynamic_data[index] = (uint8_t)((index * 11U + 5U) & 0xffU);
  }
  uint8_t data_hash[32];
  hash_bytes(dynamic_data, sizeof(dynamic_data), data_hash);
  xaios_xai_fs_package_t package_template;
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
  xaios_xai_fs_package_t registered;
  uint64_t pre_registration_generation = volume.generation;
  file_writer.fail_superblock = 1;
  assert(xaios_xai_fs_register_staging(
             &volume, &package_template, &writer, scratch, sizeof(scratch),
             &registered) == XAIOS_ENGINE_ERR_IO);
  assert(volume.generation == pre_registration_generation &&
         volume.package_count == 0U);
  xaios_xai_fs_t registration_recovered;
  assert(xaios_xai_fs_open(&reader, xaifs_test_verify_signature, NULL, scratch,
                                 sizeof(scratch), &registration_recovered) ==
         XAIOS_ENGINE_OK);
  assert(registration_recovered.generation == pre_registration_generation &&
         registration_recovered.package_count == 0U);

  file_writer.fail_superblock = 0;
  assert(xaios_xai_fs_register_staging(
             &volume, &package_template, &writer, scratch, sizeof(scratch),
             &registered) == XAIOS_ENGINE_OK);
  assert(registered.state == XAIOS_XAI_FS_PACKAGE_STAGING &&
         registered.chunk_count == 1U && volume.package_count == 1U);
  xaios_xai_fs_chunk_t dynamic_chunk;
  assert(xaios_xai_fs_read_chunk(&volume, registered.chunk_start,
                                       &dynamic_chunk) == XAIOS_ENGINE_OK);
  assert(dynamic_chunk.flags == XAIOS_XAI_FS_CHUNK_HASH_PENDING);
  assert(xaios_xai_fs_verify_package_manifest(&volume, &registered) ==
         XAIOS_ENGINE_ERR_CHECKSUM);
  uint64_t completed = UINT64_MAX;
  assert(xaios_xai_fs_pwrite_staging(
             &volume, &registered, &writer, 0U, dynamic_data, 2048U) ==
         XAIOS_ENGINE_OK);
  assert(xaios_xai_fs_commit_staging_range(
             &volume, &registered, &writer, 0U, 2048U, scratch,
             sizeof(scratch), &completed) == XAIOS_ENGINE_OK);
  assert(completed == 0U);
  assert(xaios_xai_fs_pwrite_staging(
             &volume, &registered, &writer, 0U, dynamic_data,
             sizeof(dynamic_data)) == XAIOS_ENGINE_OK);
  assert(xaios_xai_fs_commit_staging_range(
             &volume, &registered, &writer, 0U, sizeof(dynamic_data), scratch,
             sizeof(scratch), &completed) == XAIOS_ENGINE_OK);
  assert(completed == 1U);
  assert(xaios_xai_fs_read_package(&volume, 0U, &registered) ==
         XAIOS_ENGINE_OK);
  assert(xaios_xai_fs_read_chunk(&volume, registered.chunk_start,
                                       &dynamic_chunk) == XAIOS_ENGINE_OK);
  assert(dynamic_chunk.flags == XAIOS_XAI_FS_CHUNK_COMPLETE &&
         memcmp(dynamic_chunk.checksum, data_hash, 32U) == 0);
  uint64_t dynamic_bad_offset = 0U;
  assert(xaios_xai_fs_verify_package(
             &volume, &registered, scratch, sizeof(scratch),
             &dynamic_bad_offset) == XAIOS_ENGINE_OK);
  assert(dynamic_bad_offset == UINT64_MAX);
  assert(xaios_xai_fs_activate_staging(
             &volume, &registered, &writer, scratch, sizeof(scratch)) ==
         XAIOS_ENGINE_OK);

  xaios_xai_fs_package_t cleanup_template = package_template;
  cleanup_template.model_uuid[0] ^= 0x55U;
  cleanup_template.source_revision[0] ^= 0x33U;
  dynamic_package_identity(&cleanup_template, data_hash,
                           cleanup_template.package_id);
  assert(xaios_ed25519_sign(cleanup_template.signature,
                            cleanup_template.package_id, 32U,
                            cleanup_template.signer_public_key,
                            signing_seed) == 0);
  xaios_xai_fs_package_t cleanup_package;
  assert(xaios_xai_fs_register_staging(
             &volume, &cleanup_template, &writer, scratch, sizeof(scratch),
             &cleanup_package) == XAIOS_ENGINE_OK);
  xaios_xai_fs_chunk_t cleanup_chunk;
  assert(xaios_xai_fs_read_chunk(&volume, cleanup_package.chunk_start,
                                       &cleanup_chunk) == XAIOS_ENGINE_OK);
  uint64_t reusable_physical = cleanup_chunk.physical_offset;
  uint64_t cleanup_generation = volume.generation;
  uint64_t reclaimed = 0U;
  file_writer.fail_superblock = 1;
  assert(xaios_xai_fs_remove_staging(
             &volume, &cleanup_package, &writer, scratch, sizeof(scratch),
             &reclaimed) == XAIOS_ENGINE_ERR_IO);
  assert(volume.generation == cleanup_generation && reclaimed == 0U);
  assert(xaios_xai_fs_open(&reader, xaifs_test_verify_signature, NULL, scratch,
                                 sizeof(scratch), &registration_recovered) ==
         XAIOS_ENGINE_OK);
  assert(registration_recovered.package_count == 2U);

  file_writer.fail_superblock = 0;
  assert(xaios_xai_fs_remove_staging(
             &volume, &cleanup_package, &writer, scratch, sizeof(scratch),
             &reclaimed) == XAIOS_ENGINE_OK);
  assert(reclaimed == 4096U && volume.package_count == 1U &&
         volume.free_extent_count == 1U);

  xaios_xai_fs_package_t reuse_template = cleanup_template;
  reuse_template.model_uuid[1] ^= 0x66U;
  reuse_template.source_revision[1] ^= 0x44U;
  dynamic_package_identity(&reuse_template, data_hash,
                           reuse_template.package_id);
  assert(xaios_ed25519_sign(reuse_template.signature,
                            reuse_template.package_id, 32U,
                            reuse_template.signer_public_key,
                            signing_seed) == 0);
  xaios_xai_fs_package_t reused_package;
  assert(xaios_xai_fs_register_staging(
             &volume, &reuse_template, &writer, scratch, sizeof(scratch),
             &reused_package) == XAIOS_ENGINE_OK);
  xaios_xai_fs_chunk_t reused_chunk;
  assert(xaios_xai_fs_read_chunk(&volume, reused_package.chunk_start,
                                       &reused_chunk) == XAIOS_ENGINE_OK);
  assert(reused_chunk.physical_offset == reusable_physical &&
         volume.free_extent_count == 0U);

  file_writer.fail_superblock = 1;
  assert(xaios_xai_fs_format(&writer, grown_size, UINT64_C(2097152),
                                   volume_uuid, scratch, sizeof(scratch)) ==
         XAIOS_ENGINE_ERR_IO);
  assert(xaios_xai_fs_format(&writer, grown_size, UINT64_C(1048576),
                                   volume_uuid, scratch, sizeof(scratch)) ==
         XAIOS_ENGINE_ERR_INVALID);
  fclose(file);
}

void xaifs_test_write_active_package(
    xaios_xai_fs_t *volume, const xaios_xai_fs_package_t *template,
    const uint8_t *data, xaios_xai_fs_writer_t *writer,
    uint8_t *scratch, size_t scratch_size,
    xaios_xai_fs_package_t *active) {
  xaios_xai_fs_package_t staging;
  uint64_t completed = 0U;
  assert(xaios_xai_fs_register_staging(volume, template, writer, scratch,
                                             scratch_size, &staging) ==
         XAIOS_ENGINE_OK);
  assert(xaios_xai_fs_pwrite_staging(volume, &staging, writer, 0U, data,
                                           (size_t)staging.logical_size) ==
         XAIOS_ENGINE_OK);
  assert(xaios_xai_fs_commit_staging_range(
             volume, &staging, writer, 0U, staging.logical_size, scratch,
             scratch_size, &completed) == XAIOS_ENGINE_OK);
  assert(completed == staging.chunk_count);
  assert(xaios_xai_fs_activate_staging(volume, &staging, writer, scratch,
                                             scratch_size) == XAIOS_ENGINE_OK);
  assert(xaios_xai_fs_read_package(volume, 0U, active) ==
         XAIOS_ENGINE_OK);
  assert(active->state == XAIOS_XAI_FS_PACKAGE_ACTIVE);
}
