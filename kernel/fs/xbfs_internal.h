/*
 * Shared declarations for xaibootFS's translation units: the path and sector
 * constants, and the small helpers every part of the filesystem uses.
 *
 * Split out of xaiboot_fs.c, which was 3890 lines. These helpers own none of
 * the filesystem's state -- no volume, no metadata buffer, no counters -- so
 * they move without an accessor layer, which the rest of that file will need
 * before it can be cut.
 */

#ifndef XAIOS_KERNEL_FS_XBFS_INTERNAL_H
#define XAIOS_KERNEL_FS_XBFS_INTERNAL_H

#include <xaios/status.h>
#include <xaios/xaiboot_fs.h>

#define XBFS_SECTOR_SIZE UINT64_C(512)
#define XBFS_PATH_MAX 256U
#define XBFS_CHECKSUM_OFFSET UINT64_C(80)
#define FNV1A64_OFFSET UINT64_C(14695981039346656037)
#define FNV1A64_PRIME UINT64_C(1099511628211)

void xbfs_bytes_zero(void *buffer, uint64_t size);
void xbfs_bytes_copy(void *dst, const void *src, uint64_t size);
int xbfs_bytes_eq(const void *a, const void *b, uint64_t size);
uint64_t xbfs_cstr_len(const char *value);
int xbfs_str_eq(const char *a, const char *b);
xaios_status_t xbfs_append_char(char *buffer, uint64_t capacity,
                                 uint64_t *offset, char value);
xaios_status_t xbfs_append_cstr(char *buffer, uint64_t capacity,
                                 uint64_t *offset, const char *value);
xaios_status_t xbfs_append_u32(char *buffer, uint64_t capacity,
                                uint64_t *offset, uint32_t value);
uint64_t xbfs_fnv1a64_extend(uint64_t hash, const void *buffer,
                               uint64_t size);
uint64_t xbfs_fnv1a64(const void *buffer, uint64_t size);
uint64_t xbfs_mfs_checksum(const void *data, uint64_t size);
void xbfs_copy_path(char dst[XBFS_PATH_MAX], const char *src);
const char *xbfs_basename_of(const char *path);
void xbfs_parent_path_of(const char *path, char parent[XBFS_PATH_MAX]);
uint64_t xbfs_blocks_for_size(uint64_t size);
int xbfs_path_is_at_or_below(const char *path, const char *root);
int xbfs_direct_child_of(const char *parent, const char *child,
                           const char **name);

#endif /* XAIOS_KERNEL_FS_XBFS_INTERNAL_H */
