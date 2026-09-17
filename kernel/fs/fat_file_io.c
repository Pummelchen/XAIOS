/*
 * fatFS's file operations: create directory, write a whole file, read one
 * back, stat it, and stream-copy between two mounted volumes. See
 * fat_volume_internal.h.
 */

#include "fat_internal.h"
#include "fat_volume_internal.h"

#include <xaios/klog.h>

xaios_status_t fat_mkdir(xaios_fat_volume_t *volume, const char *path) {
  if (volume == 0 || volume->mounted == 0U || path == 0) {
    return XAIOS_ERR_INVALID;
  }
  /* Each component in turn, so that creating /EFI/BOOT on an empty volume
     creates /EFI as well. An installer should not have to spell out the
     parents of the directory it wants. */
  char partial[XAIOS_FAT_PATH_MAX];
  uint64_t length = 0U;
  uint64_t cursor = 0U;
  while (path[cursor] == '/') ++cursor;
  for (;;) {
    uint64_t start = cursor;
    while (path[cursor] != '\0' && path[cursor] != '/') ++cursor;
    if (cursor == start) break;
    if (length + (cursor - start) + 2U >= sizeof(partial)) {
      return XAIOS_ERR_INVALID;
    }
    if (length != 0U) partial[length++] = '/';
    for (uint64_t index = start; index < cursor; ++index) {
      partial[length++] = path[index];
    }
    partial[length] = '\0';

    directory_cursor_t parent;
    fat_name_t name;
    xaios_status_t status = fat_resolve_parent(volume, partial, &parent, &name);
    if (status != XAIOS_OK) return status;
    directory_entry_t existing;
    status = fat_find_entry(volume, &parent, &name, &existing);
    if (status == XAIOS_OK) {
      /* Already there. A directory is fine and an installer that ran before
         should find it; a file of the same name is not. */
      if ((existing.attributes & FAT_ATTR_DIRECTORY) == 0U) {
        return XAIOS_ERR_INVALID;
      }
    } else {
      uint32_t cluster = 0U;
      status = fat_allocate_cluster(volume, &cluster);
      if (status != XAIOS_OK) return status;
      status = fat_zero_cluster(volume, cluster);
      if (status != XAIOS_OK) return status;
      status = fat_write_named_entry(volume, &parent, &name,
                                 FAT_NO_EXISTING_ENTRY, FAT_ATTR_DIRECTORY,
                                 cluster, 0U);
      if (status != XAIOS_OK) return status;
      /* "." and "..", which some firmware requires to be present and which
         cost two entries. ".." points at the root as cluster zero, which is
         how FAT16 names the root directory from inside a subdirectory. */
      directory_cursor_t self = {0U, cluster};
      uint8_t dot[FAT_NAME_LENGTH];
      for (uint64_t index = 0U; index < FAT_NAME_LENGTH; ++index) {
        dot[index] = ' ';
      }
      dot[0] = (uint8_t)'.';
      status = fat_write_entry(volume, &self, 0U, dot, FAT_ATTR_DIRECTORY, cluster,
                           0U);
      if (status != XAIOS_OK) return status;
      dot[1] = (uint8_t)'.';
      status = fat_write_entry(volume, &self, 1U, dot, FAT_ATTR_DIRECTORY,
                           parent.is_root != 0U ? 0U : parent.first_cluster,
                           0U);
      if (status != XAIOS_OK) return status;
    }
    while (path[cursor] == '/') ++cursor;
    if (path[cursor] == '\0') break;
  }
  (void)block_flush(volume->device);
  return XAIOS_OK;
}

xaios_status_t fat_write_file(xaios_fat_volume_t *volume, const char *path,
                              const void *data, uint64_t length) {
  if (volume == 0 || volume->mounted == 0U || path == 0 ||
      (data == 0 && length != 0U) || length > UINT32_MAX) {
    return XAIOS_ERR_INVALID;
  }
  directory_cursor_t parent;
  fat_name_t name;
  xaios_status_t status = fat_resolve_parent(volume, path, &parent, &name);
  if (status != XAIOS_OK) return status;

  directory_entry_t existing;
  uint64_t existing_index = FAT_NO_EXISTING_ENTRY;
  status = fat_find_entry(volume, &parent, &name, &existing);
  if (status == XAIOS_OK) {
    if ((existing.attributes & FAT_ATTR_DIRECTORY) != 0U) {
      return XAIOS_ERR_INVALID;
    }
    /* Replacing: the old chain goes back to the free list first, so that
       writing the same file twice does not consume the volume twice. */
    if (existing.first_cluster >= 2U) {
      status = fat_free_chain(volume, existing.first_cluster);
      if (status != XAIOS_OK) return status;
    }
    existing_index = existing.index;
  }

  uint32_t first = 0U;
  uint32_t previous = 0U;
  uint64_t written = 0U;
  const uint8_t *bytes = (const uint8_t *)data;
  uint64_t cluster_bytes = volume->sectors_per_cluster * volume->sector_size;
  while (written < length) {
    uint32_t cluster = 0U;
    status = fat_allocate_cluster(volume, &cluster);
    if (status != XAIOS_OK) {
      if (first >= 2U) (void)fat_free_chain(volume, first);
      return status;
    }
    if (first == 0U) {
      first = cluster;
    } else {
      status = fat_entry_set(volume, previous, cluster);
      if (status != XAIOS_OK) {
        (void)fat_free_chain(volume, first);
        return status;
      }
    }
    previous = cluster;
    uint64_t base = fat_cluster_sector(volume, cluster);
    for (uint64_t index = 0U;
         index < volume->sectors_per_cluster && written < length; ++index) {
      uint64_t chunk = length - written;
      if (chunk > volume->sector_size) chunk = volume->sector_size;
      fat_bytes_zero(g_fat_sector, volume->sector_size);
      fat_bytes_copy(g_fat_sector, &bytes[written], chunk);
      status = fat_write_sector(volume, base + index, g_fat_sector);
      if (status != XAIOS_OK) {
        (void)fat_free_chain(volume, first);
        return status;
      }
      written += chunk;
    }
    if (cluster_bytes == 0U) return XAIOS_ERR_INVALID;
  }

  status = fat_write_named_entry(volume, &parent, &name, existing_index, 0U,
                             first, (uint32_t)length);
  if (status != XAIOS_OK) {
    if (first >= 2U) (void)fat_free_chain(volume, first);
    return status;
  }
  (void)block_flush(volume->device);
  return XAIOS_OK;
}

xaios_status_t fat_read_file(xaios_fat_volume_t *volume, const char *path,
                             void *buffer, uint64_t capacity,
                             uint64_t *out_length) {
  if (volume == 0 || volume->mounted == 0U || path == 0 || out_length == 0) {
    return XAIOS_ERR_INVALID;
  }
  directory_cursor_t parent;
  fat_name_t name;
  xaios_status_t status = fat_resolve_parent(volume, path, &parent, &name);
  if (status != XAIOS_OK) return status;
  directory_entry_t entry;
  status = fat_find_entry(volume, &parent, &name, &entry);
  if (status != XAIOS_OK) return status;
  if ((entry.attributes & FAT_ATTR_DIRECTORY) != 0U) {
    return XAIOS_ERR_INVALID;
  }
  *out_length = entry.size;
  /* Report the size even when the buffer is too small, so a caller can ask
     once, size a buffer and ask again. */
  if (entry.size > capacity) return XAIOS_ERR_NO_MEMORY;
  uint8_t *out = (uint8_t *)buffer;
  uint64_t read = 0U;
  uint32_t cluster = entry.first_cluster;
  while (read < entry.size) {
    if (cluster < 2U || (uint64_t)cluster >= volume->cluster_count + 2U) {
      return XAIOS_ERR_INVALID;
    }
    uint64_t base = fat_cluster_sector(volume, cluster);
    for (uint64_t index = 0U;
         index < volume->sectors_per_cluster && read < entry.size; ++index) {
      status = fat_read_sector(volume, base + index, g_fat_sector);
      if (status != XAIOS_OK) return status;
      uint64_t chunk = entry.size - read;
      if (chunk > volume->sector_size) chunk = volume->sector_size;
      fat_bytes_copy(&out[read], g_fat_sector, chunk);
      read += chunk;
    }
    uint32_t next = 0U;
    status = fat_entry_get(volume, cluster, &next);
    if (status != XAIOS_OK) return status;
    cluster = next;
  }
  return XAIOS_OK;
}

xaios_status_t fat_stat(xaios_fat_volume_t *volume, const char *path,
                        uint64_t *out_size, uint32_t *out_is_directory) {
  if (volume == 0 || volume->mounted == 0U || path == 0) {
    return XAIOS_ERR_INVALID;
  }
  directory_cursor_t parent;
  fat_name_t name;
  xaios_status_t status = fat_resolve_parent(volume, path, &parent, &name);
  if (status != XAIOS_OK) return status;
  directory_entry_t entry;
  status = fat_find_entry(volume, &parent, &name, &entry);
  if (status != XAIOS_OK) return status;
  if (out_size != 0) *out_size = entry.size;
  if (out_is_directory != 0) {
    *out_is_directory = (entry.attributes & FAT_ATTR_DIRECTORY) != 0U ? 1U : 0U;
  }
  return XAIOS_OK;
}

/* A second buffer, holding payload while g_fat_sector holds metadata.
 *
 * Every function above borrows g_fat_sector for whatever sector it is currently
 * reading or writing, which is fine while one volume is being touched at a
 * time. A copy is not that: it reads a data sector from the source, and then,
 * before that data has been written anywhere, it reads and writes FAT entries
 * and directory entries on the destination. Each of those lands in g_fat_sector.
 * Sharing one buffer would copy the destination's own metadata into the file
 * instead of the source's contents. */
static uint8_t g_payload[FAT_SECTOR_SIZE];

/*
 * Copy a file from one mounted volume to another, a sector at a time.
 *
 * Whole-file read and write cannot do this: an installer copies a kernel and
 * an initial filesystem, which are megabytes, and a kernel that had to hold
 * one entirely in memory to copy it would need the memory for the largest file
 * it might ever meet. Streaming needs a fixed sector and a cluster chain that
 * grows as it goes.
 *
 * The destination entry is written last, after every byte is on the disk. A
 * directory entry that appears before its contents is a file that reads as
 * whatever the clusters held before, and on a partition firmware is about to
 * boot from, that is worse than no file.
 */
xaios_status_t fat_copy_file(xaios_fat_volume_t *destination,
                             const char *destination_path,
                             xaios_fat_volume_t *source,
                             const char *source_path) {
  if (destination == 0 || destination->mounted == 0U || source == 0 ||
      source->mounted == 0U || destination_path == 0 || source_path == 0) {
    return XAIOS_ERR_INVALID;
  }

  directory_cursor_t source_parent;
  fat_name_t source_name;
  xaios_status_t status =
      fat_resolve_parent(source, source_path, &source_parent, &source_name);
  if (status != XAIOS_OK) return status;
  directory_entry_t source_entry;
  status = fat_find_entry(source, &source_parent, &source_name, &source_entry);
  if (status != XAIOS_OK) return status;
  if ((source_entry.attributes & FAT_ATTR_DIRECTORY) != 0U) {
    return XAIOS_ERR_INVALID;
  }

  directory_cursor_t parent;
  fat_name_t name;
  status = fat_resolve_parent(destination, destination_path, &parent, &name);
  if (status != XAIOS_OK) return status;
  directory_entry_t existing;
  uint64_t existing_index = FAT_NO_EXISTING_ENTRY;
  status = fat_find_entry(destination, &parent, &name, &existing);
  if (status == XAIOS_OK) {
    if ((existing.attributes & FAT_ATTR_DIRECTORY) != 0U) {
      return XAIOS_ERR_INVALID;
    }
    if (existing.first_cluster >= 2U) {
      status = fat_free_chain(destination, existing.first_cluster);
      if (status != XAIOS_OK) return status;
    }
    existing_index = existing.index;
  }

  uint32_t first = 0U;
  uint32_t previous = 0U;
  uint32_t source_cluster = source_entry.first_cluster;
  uint64_t remaining = source_entry.size;
  uint64_t source_offset = 0U;
  while (remaining != 0U) {
    if (source_cluster < 2U ||
        (uint64_t)source_cluster >= source->cluster_count + 2U) {
      if (first >= 2U) (void)fat_free_chain(destination, first);
      return XAIOS_ERR_INVALID;
    }
    uint32_t cluster = 0U;
    status = fat_allocate_cluster(destination, &cluster);
    if (status != XAIOS_OK) {
      if (first >= 2U) (void)fat_free_chain(destination, first);
      return status;
    }
    if (first == 0U) {
      first = cluster;
    } else {
      status = fat_entry_set(destination, previous, cluster);
      if (status != XAIOS_OK) {
        (void)fat_free_chain(destination, first);
        return status;
      }
    }
    previous = cluster;

    uint64_t source_base = fat_cluster_sector(source, source_cluster);
    uint64_t destination_base = fat_cluster_sector(destination, cluster);
    /* The two volumes need not agree on cluster size, so the inner loop is
       bounded by the destination's cluster and by whatever is left of the
       source's -- whichever runs out first decides when to follow a chain. */
    for (uint64_t index = 0U;
         index < destination->sectors_per_cluster && remaining != 0U;
         ++index) {
      uint64_t within = source_offset % source->sectors_per_cluster;
      status = fat_read_sector(source, source_base + within, g_payload);
      if (status != XAIOS_OK) {
        klog("fat: copy read failed sector=%lu cluster=%u offset=%lu "
             "remaining=%lu status=%d\n",
             source_base + within, source_cluster, source_offset, remaining,
             (int)status);
        (void)fat_free_chain(destination, first);
        return status;
      }
      uint64_t chunk = remaining < destination->sector_size
                           ? remaining
                           : destination->sector_size;
      if (chunk < destination->sector_size) {
        /* The tail of the last sector is whatever the source sector held past
           the end of the file. Clear it rather than copy it: the file's size
           says those bytes are not part of it, and writing them out would put
           unrelated contents of another disk onto this one. */
        for (uint64_t index2 = chunk; index2 < destination->sector_size;
             ++index2) {
          g_payload[index2] = 0U;
        }
      }
      status = fat_write_sector(destination, destination_base + index, g_payload);
      if (status != XAIOS_OK) {
        klog("fat: copy write failed sector=%lu cluster=%u of %lu "
             "remaining=%lu status=%d\n",
             destination_base + index, cluster, destination->cluster_count,
             remaining, (int)status);
        (void)fat_free_chain(destination, first);
        return status;
      }
      remaining -= chunk;
      ++source_offset;
      if (source_offset % source->sectors_per_cluster == 0U) {
        uint32_t next = 0U;
        status = fat_entry_get(source, source_cluster, &next);
        if (status != XAIOS_OK) {
          (void)fat_free_chain(destination, first);
          return status;
        }
        source_cluster = next;
        source_base = remaining != 0U && next >= 2U &&
                              (uint64_t)next < source->cluster_count + 2U
                          ? fat_cluster_sector(source, next)
                          : 0U;
      }
    }
  }

  status = fat_write_named_entry(destination, &parent, &name, existing_index, 0U,
                             first, source_entry.size);
  if (status != XAIOS_OK) {
    if (first >= 2U) (void)fat_free_chain(destination, first);
    return status;
  }
  (void)block_flush(destination->device);
  return XAIOS_OK;
}
