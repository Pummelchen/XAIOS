#ifndef XAIOS_ENGINE_XAI_FS_WRITER_INTERNAL_H
#define XAIOS_ENGINE_XAI_FS_WRITER_INTERNAL_H

/* Helpers shared by the xaiFS writer's two translation units.
 *
 * `xai_fs_writer.c` was one file. The little-endian codecs, the checked
 * arithmetic, the record encoders and the chunk-completion check moved to
 * `xai_fs_writer_util.c`, and the writer still calls them, so they are declared
 * here. `<xaios_engine/xai_fs.h>` remains the module's public surface; nothing
 * in this header is for anyone else.
 *
 * `valid_chunk_size` is deliberately not here. It reads
 * `XAI_FS_MIN_CHUNK_SIZE` and `XAI_FS_MAX_CHUNK_SIZE`, and
 * `tests/repository/check-xai-fs-chunk-bounds.py` reads those two `#define`s
 * out of `xai_fs_writer.c`'s own text and compares them with the reader, the
 * host tool and `docs/MODELFS-FORMAT.md`. The bounds stay in the writer, so the
 * function that reads them stays with the bounds rather than a copy of them
 * appearing a second time here.
 */

#include <xaios_engine/xai_fs.h>

#include <stddef.h>
#include <stdint.h>

void store_le16(uint8_t output[2], uint16_t value);
void store_le32(uint8_t output[4], uint32_t value);
void store_le64(uint8_t output[8], uint64_t value);

xaios_engine_status_t checked_add(uint64_t left, uint64_t right,
                                  uint64_t *result);
xaios_engine_status_t checked_multiply(uint64_t left, uint64_t right,
                                       uint64_t *result);
xaios_engine_status_t align_up(uint64_t value, uint64_t alignment,
                               uint64_t *result);

xaios_engine_status_t read_exact(const xaios_xai_fs_t *volume, uint64_t offset,
                                 void *destination, size_t length);
xaios_engine_status_t write_exact(const xaios_xai_fs_writer_t *writer,
                                  uint64_t offset, const void *source,
                                  size_t length);
void sha256(const void *data, size_t length, uint8_t digest[32]);

int ranges_intersect(uint64_t first_offset, uint64_t first_length,
                     uint64_t second_offset, uint64_t second_length);
int valid_uuid(const uint8_t uuid[16]);
int bytes_nonzero(const uint8_t *bytes, size_t length);
int valid_ascii(const char value[33]);
int valid_target(const char *target);

void encode_package_record(const xaios_xai_fs_package_t *package,
                           uint8_t raw[384]);
void encode_chunk_record(const xaios_xai_fs_chunk_t *chunk, uint8_t raw[128]);

xaios_engine_status_t chunk_completion_status(
    const xaios_xai_fs_t *volume, const xaios_xai_fs_package_t *package,
    const xaios_xai_fs_chunk_t *chunk, uint64_t offset, uint64_t length,
    void *scratch, size_t scratch_size, int *should_complete,
    uint8_t learned_checksum[32]);

#endif
