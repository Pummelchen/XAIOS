#ifndef XAIOS_ENGINE_XAI_FS_CODEC_H
#define XAIOS_ENGINE_XAI_FS_CODEC_H

/* The xaiFS reader's byte codec and checked arithmetic.
 *
 * `xai_fs.c` was one file. The little-endian loads and stores, the checked
 * add and multiply, the range check, the bounded read, SHA-256 over a range
 * and the all-zero test moved to `xai_fs_codec.c`; the volume open/probe path
 * that stayed in `xai_fs.c` and the verify/read path now in `xai_fs_read.c`
 * both call them, so they are declared here.
 *
 * The names carry a `xai_fs_codec_` prefix because `xai_fs_writer_util.c`
 * exports `store_le32`, `checked_add`, `read_exact`, `sha256` and friends
 * under their bare names, and the kernel, the userspace library and the
 * hosted tests link both objects. `<xaios_engine/xai_fs.h>` remains the
 * module's public surface; nothing in this header is for anyone else.
 *
 * `valid_chunk_size` deliberately did not move. It reads the two chunk-size
 * bounds whose text `tests/repository/check-xai-fs-chunk-bounds.py` finds in
 * `xai_fs.c`, so the function that reads them stays beside them.
 */

#include <xaios_engine/xai_fs.h>

#include <stddef.h>
#include <stdint.h>

uint16_t xai_fs_codec_load_le16(const uint8_t *value);
uint32_t xai_fs_codec_load_le32(const uint8_t *value);
uint64_t xai_fs_codec_load_le64(const uint8_t *value);
void xai_fs_codec_store_le32(uint8_t output[4], uint32_t value);
void xai_fs_codec_store_le64(uint8_t output[8], uint64_t value);
int xai_fs_codec_bytes_zero(const uint8_t *bytes, size_t length);
int xai_fs_codec_power_of_two(uint64_t value);
xaios_engine_status_t xai_fs_codec_checked_add(uint64_t left, uint64_t right,
                                               uint64_t *result);
xaios_engine_status_t xai_fs_codec_checked_multiply(uint64_t left,
                                                    uint64_t right,
                                                    uint64_t *result);
xaios_engine_status_t xai_fs_codec_range_valid(uint64_t offset,
                                               uint64_t length,
                                               uint64_t limit);
xaios_engine_status_t xai_fs_codec_read_exact(
    const xaios_xai_fs_reader_t *reader, uint64_t offset, void *destination,
    size_t length);
void xai_fs_codec_sha256(const void *data, size_t length, uint8_t digest[32]);
xaios_engine_status_t xai_fs_codec_hash_reader_range(
    const xaios_xai_fs_reader_t *reader, uint64_t offset, uint64_t length,
    void *scratch, size_t scratch_size, uint8_t digest[32]);

#endif
