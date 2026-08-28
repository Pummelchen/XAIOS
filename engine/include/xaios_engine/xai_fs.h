#ifndef XAIOS_ENGINE_XAI_FS_H
#define XAIOS_ENGINE_XAI_FS_H

#include <stddef.h>
#include <stdint.h>

#include <xaios_engine/model_v2.h>

#define XAIOS_XAI_FS_MAGIC "XAIOSV1\0"
#define XAIOS_XAI_FS_SUPERBLOCK_SIZE UINT64_C(4096)
#define XAIOS_XAI_FS_CATALOG_HEADER_SIZE UINT64_C(256)
#define XAIOS_XAI_FS_PACKAGE_RECORD_SIZE UINT64_C(384)
#define XAIOS_XAI_FS_CHUNK_RECORD_SIZE UINT64_C(128)
#define XAIOS_XAI_FS_DATA_START UINT64_C(1048576)
#define XAIOS_XAI_FS_PACKAGE_STAGING UINT32_C(1)
#define XAIOS_XAI_FS_PACKAGE_ACTIVE UINT32_C(2)
#define XAIOS_XAI_FS_PACKAGE_QUARANTINED UINT32_C(3)
#define XAIOS_XAI_FS_CHUNK_COMPLETE UINT32_C(1)
#define XAIOS_XAI_FS_CHUNK_ZERO UINT32_C(2)
#define XAIOS_XAI_FS_CHUNK_FREE UINT32_C(4)
#define XAIOS_XAI_FS_CHUNK_HASH_PENDING UINT32_C(8)

typedef xaios_model_v2_reader_t xaios_xai_fs_reader_t;

typedef xaios_engine_status_t (*xaios_xai_fs_verify_signature_fn)(
    void *context, const uint8_t public_key[32], const uint8_t signature[64],
    const uint8_t message[32]);

typedef xaios_engine_status_t (*xaios_xai_fs_write_at_fn)(
    void *context, uint64_t offset, const void *source, size_t length);
typedef xaios_engine_status_t (*xaios_xai_fs_flush_fn)(void *context);

typedef struct xaios_xai_fs_writer {
  void *context;
  xaios_xai_fs_write_at_fn write_at;
  xaios_xai_fs_flush_fn flush;
} xaios_xai_fs_writer_t;

typedef struct xaios_xai_fs {
  xaios_xai_fs_reader_t reader;
  xaios_xai_fs_verify_signature_fn verify_signature;
  void *verify_context;
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
  uint32_t selected_superblock;
} xaios_xai_fs_t;

typedef struct xaios_xai_fs_package {
  uint32_t state;
  uint64_t record_id;
  uint8_t model_uuid[16];
  uint8_t package_id[32];
  uint8_t signer_public_key[32];
  uint8_t signature[64];
  uint8_t source_revision[32];
  uint64_t logical_size;
  uint64_t chunk_size;
  uint64_t chunk_start;
  uint64_t chunk_count;
  char architecture_id[33];
  char target_id[33];
} xaios_xai_fs_package_t;

typedef struct xaios_xai_fs_chunk {
  uint64_t record_id;
  uint64_t logical_offset;
  uint64_t physical_offset;
  uint64_t length;
  uint64_t extent_length;
  uint32_t flags;
  uint8_t checksum[32];
} xaios_xai_fs_chunk_t;

typedef struct xaios_xai_fs_probe {
  uint64_t selected_generation;
  uint64_t selected_volume_size;
  uint32_t first_valid;
  uint32_t second_valid;
  uint32_t copies_compatible;
  uint32_t selected_superblock;
} xaios_xai_fs_probe_t;

xaios_engine_status_t xaios_xai_fs_format(
    const xaios_xai_fs_writer_t *writer, uint64_t volume_size,
    uint64_t chunk_size, const uint8_t volume_uuid[16], void *scratch,
    size_t scratch_size);
xaios_engine_status_t xaios_xai_fs_probe(
    const xaios_xai_fs_reader_t *reader, void *scratch,
    size_t scratch_size, xaios_xai_fs_probe_t *probe);
xaios_engine_status_t xaios_xai_fs_grow(
    xaios_xai_fs_t *volume,
    const xaios_xai_fs_writer_t *writer, uint64_t new_volume_size,
    void *scratch, size_t scratch_size);
xaios_engine_status_t xaios_xai_fs_repair_superblock(
    xaios_xai_fs_t *volume,
    const xaios_xai_fs_writer_t *writer, void *scratch,
    size_t scratch_size);
xaios_engine_status_t xaios_xai_fs_register_staging(
    xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package_template,
    const xaios_xai_fs_writer_t *writer, void *scratch,
    size_t scratch_size, xaios_xai_fs_package_t *registered_package);
xaios_engine_status_t xaios_xai_fs_quarantine_package(
    xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package,
    const xaios_xai_fs_writer_t *writer, void *scratch,
    size_t scratch_size);
xaios_engine_status_t xaios_xai_fs_remove_staging(
    xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package,
    const xaios_xai_fs_writer_t *writer, void *scratch,
    size_t scratch_size, uint64_t *reclaimed_bytes);
xaios_engine_status_t xaios_xai_fs_remove_quarantined(
    xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package,
    const xaios_xai_fs_writer_t *writer, void *scratch,
    size_t scratch_size, uint64_t *reclaimed_bytes);
xaios_engine_status_t xaios_xai_fs_repair_from_replica(
    xaios_xai_fs_t *target,
    const xaios_xai_fs_package_t *target_package,
    const xaios_xai_fs_t *replica,
    const xaios_xai_fs_package_t *replica_package,
    const xaios_xai_fs_writer_t *target_writer, void *scratch,
    size_t scratch_size, uint64_t *copied_bytes);

xaios_engine_status_t xaios_xai_fs_open(
    const xaios_xai_fs_reader_t *reader,
    xaios_xai_fs_verify_signature_fn verify_signature,
    void *verify_context, void *scratch, size_t scratch_size,
    xaios_xai_fs_t *volume);
xaios_engine_status_t xaios_xai_fs_read_package(
    const xaios_xai_fs_t *volume, uint64_t index,
    xaios_xai_fs_package_t *package);
xaios_engine_status_t xaios_xai_fs_read_chunk(
    const xaios_xai_fs_t *volume, uint64_t index,
    xaios_xai_fs_chunk_t *chunk);
xaios_engine_status_t xaios_xai_fs_verify_package(
    const xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package, void *scratch,
    size_t scratch_size, uint64_t *bad_logical_offset);
xaios_engine_status_t xaios_xai_fs_verify_package_manifest(
    const xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package);
xaios_engine_status_t xaios_xai_fs_pread(
    const xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package, uint64_t offset,
    void *destination, size_t length);
xaios_engine_status_t xaios_xai_fs_pread_verified(
    const xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package, uint64_t offset,
    void *destination, size_t length, void *scratch, size_t scratch_size,
    uint64_t *bad_logical_offset);
xaios_engine_status_t xaios_xai_fs_verify_range(
    const xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package, uint64_t offset,
    uint64_t length, void *scratch, size_t scratch_size,
    uint64_t *bad_logical_offset);
xaios_engine_status_t xaios_xai_fs_pwrite_staging(
    const xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package,
    const xaios_xai_fs_writer_t *writer, uint64_t offset,
    const void *source, size_t length);
xaios_engine_status_t xaios_xai_fs_commit_staging_range(
    xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package,
    const xaios_xai_fs_writer_t *writer, uint64_t offset,
    uint64_t length, void *scratch, size_t scratch_size,
    uint64_t *completed_chunks);
xaios_engine_status_t xaios_xai_fs_activate_staging(
    xaios_xai_fs_t *volume,
    const xaios_xai_fs_package_t *package,
    const xaios_xai_fs_writer_t *writer, void *scratch,
    size_t scratch_size);

#endif
