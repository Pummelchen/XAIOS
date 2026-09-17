#ifndef XAIOS_ENGINE_XAI_FS_WRITER_PARTS_H
#define XAIOS_ENGINE_XAI_FS_WRITER_PARTS_H

/* Declarations shared by the xaiFS writer's catalog, staging and rewrite
 * translation units.
 *
 * `xai_fs_writer.c` was one file. The little-endian codecs, the checked
 * arithmetic and the record encoders went to `xai_fs_writer_util.c`; the
 * staging path (write, register, activate) went to
 * `xai_fs_writer_staging.c`; and the two full-catalog rewrites -- removing a
 * package and committing a dirty range -- went to `xai_fs_writer_rewrite.c`.
 *
 * The catalog and superblock encoders and the two allocation helpers stayed in
 * `xai_fs_writer.c`, which is the only unit that can keep them beside the
 * chunk-size bounds: `tests/repository/check-xai-fs-chunk-bounds.py` reads
 * `XAI_FS_MIN_CHUNK_SIZE` and `XAI_FS_MAX_CHUNK_SIZE` out of that file's own
 * text, and `valid_chunk_size` is their only user. The other units call the
 * encoders, so they are declared here rather than duplicated. Nothing in this
 * header is for anyone outside the writer.
 *
 * `XAI_FS_BLOCK_SIZE` and `XAI_FS_WRITER_SCRATCH_MIN` are needed by all three
 * units, so they live here once instead of in whichever unit happened to keep
 * them. The two chunk-size bounds deliberately do not.
 */

#include <xaios_engine/xai_fs.h>

#include <stddef.h>
#include <stdint.h>

#define XAI_FS_BLOCK_SIZE UINT64_C(4096)
#define XAI_FS_WRITER_SCRATCH_MIN UINT64_C(8192)

void xai_fs_writer_encode_catalog_header(const xaios_xai_fs_t *volume,
                                         uint64_t generation,
                                         uint64_t data_tail,
                                         uint8_t raw[256]);

xaios_engine_status_t xai_fs_writer_data_high_water(
    const xaios_xai_fs_t *volume, uint64_t *high_water);

xaios_engine_status_t xai_fs_writer_choose_catalog_slot(
    const xaios_xai_fs_t *volume, uint64_t data_floor,
    uint64_t catalog_length, uint64_t *catalog_offset, uint64_t *final_tail);

void xai_fs_writer_encode_superblock(const xaios_xai_fs_t *volume,
                                     uint64_t generation,
                                     uint64_t catalog_offset,
                                     uint64_t catalog_generation,
                                     uint64_t data_tail,
                                     const uint8_t catalog_hash[32],
                                     uint8_t raw[4096]);

xaios_engine_status_t xai_fs_writer_remove_package_in_state(
    xaios_xai_fs_t *volume, const xaios_xai_fs_package_t *package,
    const xaios_xai_fs_writer_t *writer, void *scratch,
    size_t scratch_size, uint32_t required_state, uint64_t *reclaimed_bytes);

#endif
