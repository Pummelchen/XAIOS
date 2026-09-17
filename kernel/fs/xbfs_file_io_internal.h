/*
 * Private interface between xaiboot_fs.c and xbfs_file_io.c, the translation
 * unit that owns the byte-level file data path: the data-block to absolute
 * sector mapping, the extent read/write primitives, the whole-file write, the
 * whole-file read, and the extent clone a snapshot takes.
 *
 * Nothing here owns state. The node table, the mount flags, the generation and
 * the metadata stay in xaiboot_fs.c and are reached through the accessors in
 * xbfs_internal.h; the block I/O and the data-region geometry come from
 * xbfs_metadata_internal.h. Every entry point runs with the volume lock held,
 * exactly as the static functions it replaces did, and takes no lock itself.
 * xbfs_find_node hands back a row of the live node table, good only for the
 * duration of the call that asked for it.
 *
 * xbfs_node_count_by_type is the one symbol that travels the other way: it
 * stays in xaiboot_fs.c because it walks the node table there, and crosses so
 * this module's diagnostics can name the population it ran out of.
 */

#ifndef XAIOS_KERNEL_FS_XBFS_FILE_IO_INTERNAL_H
#define XAIOS_KERNEL_FS_XBFS_FILE_IO_INTERNAL_H

#include "xbfs_internal.h"

/* The absolute sector a data block lives at. A pure value: the data region's
   start sector plus the block index, and no pointer. */
uint64_t xbfs_absolute_data_sector(uint64_t block_index);

/* Copy a file's blocks into a freshly allocated set of extents, for a
   snapshot. The destination gets its own extents rather than a share of the
   source's: a snapshot that pointed at the same blocks would change whenever
   the file did. On a block I/O failure the destination's extents are released
   and `*destination_count` is set to zero. */
xaios_status_t xbfs_clone_extents(const xaios_xbfs_extent_t *source,
                                  uint32_t source_count,
                                  xaios_xbfs_extent_t *destination,
                                  uint32_t *destination_count);

/* Read an active file's bytes into a caller-owned buffer and verify its
   recorded content hash. Returns XAIOS_ERR_INVALID when the volume is not
   mounted, the path is invalid, or `buffer`/`out_size` is null;
   XAIOS_ERR_NOT_FOUND when the path is not an active file or `buffer_size`
   cannot hold it; XAIOS_ERR_IO on a block read failure; and XAIOS_ERR_INVALID
   again when the hash does not match. `buffer` and `*out_size` are only
   meaningful on XAIOS_OK. */
xaios_status_t xbfs_read_file(const char *path, void *buffer,
                              uint64_t buffer_size, uint64_t *out_size);

/* Defined in xaiboot_fs.c: how many active nodes record `type`. */
uint64_t xbfs_node_count_by_type(uint32_t type);

#endif /* XAIOS_KERNEL_FS_XBFS_FILE_IO_INTERNAL_H */
