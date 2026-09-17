/* Shared declarations for the split xai_fs reader test. The test is one hosted
   binary built from three translation units: the driver owns the file
   reader/writer primitives, the read-at/verify callbacks and main; the format
   helper owns the format and replica cases with their package-identity
   helpers; the staging helper owns the staging-writer and sparse-model cases.
   Every symbol below is defined exactly once, in the translation unit named
   for it in the .c file, and every translation unit includes this header. */
#ifndef XAIOS_TESTS_XAI_FS_TEST_XAI_FS_READER_SUPPORT_H
#define XAIOS_TESTS_XAI_FS_TEST_XAI_FS_READER_SUPPORT_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include <xaios_engine/xai_fs.h>

typedef struct xaifs_test_file_reader {
  FILE *file;
} xaifs_test_file_reader_t;

typedef struct xaifs_test_file_writer {
  FILE *file;
  int fail_superblock;
} xaifs_test_file_writer_t;

/* Defined in test_xai_fs_reader.c. */
xaios_engine_status_t xaifs_test_read_at(void *context, uint64_t offset,
                                         void *destination, size_t length);
xaios_engine_status_t xaifs_test_write_at(void *context, uint64_t offset,
                                          const void *source, size_t length);
xaios_engine_status_t xaifs_test_flush_writer(void *context);
xaios_engine_status_t xaifs_test_verify_signature(
    void *context, const uint8_t public_key[32], const uint8_t signature[64],
    const uint8_t message[32]);

/* Defined in test_xai_fs_reader_format.c. */
void xaifs_test_format_writer(void);
void xaifs_test_write_active_package(
    xaios_xai_fs_t *volume, const xaios_xai_fs_package_t *template,
    const uint8_t *data, xaios_xai_fs_writer_t *writer, uint8_t *scratch,
    size_t scratch_size, xaios_xai_fs_package_t *active);
void xaifs_test_replica_package_identity(
    const xaios_xai_fs_package_t *package, const uint8_t *data,
    uint8_t identity[32]);

/* Defined in test_xai_fs_reader_staging.c. */
void xaifs_test_staging_writer(FILE *file, xaios_xai_fs_t *volume,
                               xaios_xai_fs_package_t *active,
                               uint8_t *scratch, size_t scratch_size);
void xaifs_test_sparse_large_model(const char *path);
void xaifs_test_replica_repair(void);

#endif /* XAIOS_TESTS_XAI_FS_TEST_XAI_FS_READER_SUPPORT_H */
