/*
 * fatFS's directory traversal and entry placement: the cursor over the
 * root region or a cluster chain, the search for an 8.3 or long name, and
 * the placement of the long-name entries that precede one. See
 * fat_volume_internal.h.
 */

#include "fat_internal.h"
#include "fat_volume_internal.h"

/* The sector holding entry `index` of a directory, and its offset within it.
   Returns XAIOS_ERR_NOT_FOUND once the directory runs out, which for a cluster
   chain means the chain ended -- the caller decides whether to extend it. */
static xaios_status_t directory_entry_sector(const xaios_fat_volume_t *volume,
                                             const directory_cursor_t *cursor,
                                             uint64_t index,
                                             uint64_t *out_sector,
                                             uint64_t *out_offset) {
  uint64_t per_sector = volume->sector_size / FAT_DIR_ENTRY_SIZE;
  *out_offset = (index % per_sector) * FAT_DIR_ENTRY_SIZE;
  if (cursor->is_root != 0U) {
    uint64_t sector_index = index / per_sector;
    if (sector_index >= volume->root_sectors) return XAIOS_ERR_NOT_FOUND;
    *out_sector = volume->root_start_sector + sector_index;
    return XAIOS_OK;
  }
  uint64_t per_cluster = per_sector * volume->sectors_per_cluster;
  uint64_t cluster_index = index / per_cluster;
  uint32_t cluster = cursor->first_cluster;
  for (uint64_t step = 0U; step < cluster_index; ++step) {
    uint32_t next = 0U;
    xaios_status_t status = fat_entry_get(volume, cluster, &next);
    if (status != XAIOS_OK) return status;
    if (next < 2U || (uint64_t)next >= volume->cluster_count + 2U) {
      return XAIOS_ERR_NOT_FOUND;
    }
    cluster = next;
  }
  *out_sector = fat_cluster_sector(volume, cluster) +
                (index % per_cluster) / per_sector;
  return XAIOS_OK;
}

/* Add one cluster to a directory's chain and clear it, so that a directory can
   hold more entries than one cluster's worth. */
static xaios_status_t extend_directory(const xaios_fat_volume_t *volume,
                                       const directory_cursor_t *cursor) {
  if (cursor->is_root != 0U) return XAIOS_ERR_NO_MEMORY;
  uint32_t cluster = cursor->first_cluster;
  for (uint64_t guard = 0U;; ++guard) {
    if (guard > volume->cluster_count) return XAIOS_ERR_INVALID;
    uint32_t next = 0U;
    xaios_status_t status = fat_entry_get(volume, cluster, &next);
    if (status != XAIOS_OK) return status;
    if (next < 2U || (uint64_t)next >= volume->cluster_count + 2U) break;
    cluster = next;
  }
  uint32_t added = 0U;
  xaios_status_t status = fat_allocate_cluster(volume, &added);
  if (status != XAIOS_OK) return status;
  status = fat_zero_cluster(volume, added);
  if (status != XAIOS_OK) return status;
  return fat_entry_set(volume, cluster, added);
}


/* Where in an assembled long name a given entry's characters belong, and how
   to read them out of the entry. The thirteen characters are in three runs
   rather than one, which is an artefact of the entry having been fitted
   around the fields an 8.3 entry already used. */

/* Take one long-name entry's characters into `out` at its ordinal's place.
   Returns zero when the entry holds a character this reader will not
   represent -- anything outside ASCII, which no name here uses and which
   would otherwise be silently mangled into a name that matched nothing. */


/* Find a named entry in a directory, by its 8.3 name or by its long one.
 *
 * Long-name entries used to be skipped, on the reasoning that this writer
 * never created any. That was true and it was not the same as never needing
 * to read one: an EFI System Partition assembled by mtools carries
 * BOOTRISCV64.EFI as a long name over a BOOTRI~1.EFI alias, and a reader that
 * skipped them reported a volume with one fewer file than it has -- and an
 * installer copying from it silently left the machine's own boot path off the
 * disk it wrote. Assembled here and matched case-insensitively, which is how
 * FAT names compare. */
xaios_status_t fat_find_entry(const xaios_fat_volume_t *volume,
                                 const directory_cursor_t *cursor,
                                 const fat_name_t *name,
                                 directory_entry_t *entry) {
  char assembled[XAIOS_FAT_PATH_MAX + 1U];
  uint32_t assembled_length = 0U;
  uint32_t assembled_valid = 0U;
  uint8_t assembled_checksum = 0U;
  for (uint64_t index = 0U;; ++index) {
    uint64_t sector = 0U;
    uint64_t offset = 0U;
    xaios_status_t status =
        directory_entry_sector(volume, cursor, index, &sector, &offset);
    if (status != XAIOS_OK) return XAIOS_ERR_NOT_FOUND;
    status = fat_read_sector(volume, sector, g_fat_sector);
    if (status != XAIOS_OK) return status;
    const uint8_t *raw = &g_fat_sector[offset];
    if (raw[0] == 0x00U) return XAIOS_ERR_NOT_FOUND;
    if (raw[0] == 0xE5U) {
      assembled_valid = 0U;
      continue;
    }
    if ((raw[11] & FAT_ATTR_LONG_NAME) == FAT_ATTR_LONG_NAME) {
      if ((raw[0] & FAT_LFN_LAST) != 0U) {
        assembled_length = 0U;
        assembled_valid = 1U;
        assembled_checksum = raw[13];
        for (uint32_t i = 0U; i < sizeof(assembled); ++i) assembled[i] = '\0';
      }
      if (assembled_valid != 0U && raw[13] == assembled_checksum) {
        if (fat_lfn_gather(raw, assembled, XAIOS_FAT_PATH_MAX,
                       &assembled_length) == 0U) {
          assembled_valid = 0U;
        }
      } else {
        assembled_valid = 0U;
      }
      continue;
    }
    if ((raw[11] & FAT_ATTR_VOLUME_ID) != 0U) {
      assembled_valid = 0U;
      continue;
    }
    uint32_t matched =
        fat_bytes_equal(raw, name->short_name, FAT_NAME_LENGTH) != 0 ? 1U : 0U;
    if (matched == 0U && assembled_valid != 0U && assembled_length != 0U &&
        fat_lfn_checksum(raw) == assembled_checksum) {
      matched = fat_names_equal_fold(assembled, assembled_length, name->text,
                                 name->text_length);
    }
    assembled_valid = 0U;
    if (matched == 0U) continue;
    fat_decode_entry(raw, entry);
    entry->index = index;
    entry->sector = sector;
    entry->offset = offset;
    return XAIOS_OK;
  }
}

/* The same search, by 8.3 name alone. Used when checking whether a generated
   alias is already taken, where the long name is exactly what must not be
   consulted. */
static xaios_status_t find_short_entry(const xaios_fat_volume_t *volume,
                                       const directory_cursor_t *cursor,
                                       const uint8_t name[FAT_NAME_LENGTH]) {
  for (uint64_t index = 0U;; ++index) {
    uint64_t sector = 0U;
    uint64_t offset = 0U;
    xaios_status_t status =
        directory_entry_sector(volume, cursor, index, &sector, &offset);
    if (status != XAIOS_OK) return XAIOS_ERR_NOT_FOUND;
    status = fat_read_sector(volume, sector, g_fat_sector);
    if (status != XAIOS_OK) return status;
    const uint8_t *raw = &g_fat_sector[offset];
    if (raw[0] == 0x00U) return XAIOS_ERR_NOT_FOUND;
    if (raw[0] == 0xE5U) continue;
    if ((raw[11] & FAT_ATTR_LONG_NAME) == FAT_ATTR_LONG_NAME) continue;
    if (fat_bytes_equal(raw, name, FAT_NAME_LENGTH) != 0) return XAIOS_OK;
  }
}

/* The first run of `count` consecutive slots that have never been used or have
   been deleted, extending the directory as needed.
 *
 * A run rather than a slot, because a name that does not fit 8.3 occupies
 * several: one entry per thirteen characters, and then the 8.3 entry they
 * belong to, all adjacent and in that order. A writer that placed them
 * anywhere else would produce a directory every reader mis-parses. */
static xaios_status_t find_free_run(const xaios_fat_volume_t *volume,
                                    const directory_cursor_t *cursor,
                                    uint32_t count, uint64_t *out_index) {
  uint64_t run_start = 0U;
  uint32_t run = 0U;
  for (uint64_t index = 0U;; ++index) {
    uint64_t sector = 0U;
    uint64_t offset = 0U;
    xaios_status_t status =
        directory_entry_sector(volume, cursor, index, &sector, &offset);
    if (status == XAIOS_ERR_NOT_FOUND) {
      status = extend_directory(volume, cursor);
      if (status != XAIOS_OK) return status;
      status = directory_entry_sector(volume, cursor, index, &sector, &offset);
    }
    if (status != XAIOS_OK) return status;
    status = fat_read_sector(volume, sector, g_fat_sector);
    if (status != XAIOS_OK) return status;
    if (g_fat_sector[offset] == 0x00U || g_fat_sector[offset] == 0xE5U) {
      if (run == 0U) run_start = index;
      ++run;
      if (run >= count) {
        *out_index = run_start;
        return XAIOS_OK;
      }
    } else {
      run = 0U;
    }
  }
}

xaios_status_t fat_write_entry(const xaios_fat_volume_t *volume,
                                  const directory_cursor_t *cursor,
                                  uint64_t index,
                                  const uint8_t name[FAT_NAME_LENGTH],
                                  uint8_t attributes, uint32_t first_cluster,
                                  uint32_t size) {
  uint64_t sector = 0U;
  uint64_t offset = 0U;
  xaios_status_t status =
      directory_entry_sector(volume, cursor, index, &sector, &offset);
  if (status != XAIOS_OK) return status;
  status = fat_read_sector(volume, sector, g_fat_sector);
  if (status != XAIOS_OK) return status;
  uint8_t *raw = &g_fat_sector[offset];
  fat_bytes_zero(raw, FAT_DIR_ENTRY_SIZE);
  fat_bytes_copy(raw, name, FAT_NAME_LENGTH);
  raw[11] = attributes;
  /* A constant date of 1980-01-01, the epoch of the format, rather than zero.
     XAIOS has no wall clock while installing onto a bare machine, and a
     plausible-looking wrong date would be worse than an obviously fixed one --
     but zero is not a legal FAT date at all: the month and day fields are
     one-based, so a zero encodes the zeroth day of the zeroth month, which
     readers render as garbage. Firmware ignores these fields either way. */
  fat_put16(&raw[14], 0U);
  fat_put16(&raw[16], FAT_EPOCH_DATE);
  fat_put16(&raw[18], FAT_EPOCH_DATE);
  fat_put16(&raw[22], 0U);
  fat_put16(&raw[24], FAT_EPOCH_DATE);
  fat_put16(&raw[26], (uint16_t)first_cluster);
  fat_put32(&raw[28], size);
  return fat_write_sector(volume, sector, g_fat_sector);
}

/* Fill in both forms of a component's name, and say whether the long one is
   needed. A name that fits 8.3 needs no long-name entries at all, which is
   every name this writer had ever been asked for until BOOTRISCV64.EFI. */
static xaios_status_t encode_component(const char *component, uint64_t length,
                                       fat_name_t *out) {
  if (length == 0U || length > XAIOS_FAT_PATH_MAX) return XAIOS_ERR_INVALID;
  for (uint64_t index = 0U; index < length; ++index) {
    char value = component[index];
    if (value == '/' || value == '\\' || (uint8_t)value < 0x20U ||
        (uint8_t)value > 0x7EU) {
      return XAIOS_ERR_INVALID;
    }
    out->text[index] = value;
  }
  out->text[length] = '\0';
  out->text_length = (uint32_t)length;
  if (fat_encode_name(component, length, out->short_name) == XAIOS_OK) {
    out->needs_long = 0U;
    return XAIOS_OK;
  }
  out->needs_long = 1U;
  fat_short_alias(component, length, 1U, out->short_name);
  return XAIOS_OK;
}

static uint32_t long_entry_count(const fat_name_t *name) {
  if (name->needs_long == 0U) return 0U;
  return (name->text_length + FAT_LFN_CHARS - 1U) / FAT_LFN_CHARS;
}

/* Choose an alias no other entry in this directory already has. Nine is
   plenty for a boot partition and keeps the alias inside 8.3 without a second
   digit; a directory holding nine files whose names collide in their first
   six characters is not a case an installer meets. */
static xaios_status_t unique_alias(const xaios_fat_volume_t *volume,
                                   const directory_cursor_t *cursor,
                                   fat_name_t *name) {
  for (uint32_t ordinal = 1U; ordinal <= 9U; ++ordinal) {
    fat_short_alias(name->text, name->text_length, ordinal, name->short_name);
    if (find_short_entry(volume, cursor, name->short_name) ==
        XAIOS_ERR_NOT_FOUND) {
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NO_MEMORY;
}

/* Write the long-name entries that precede an 8.3 entry.
 *
 * They go on disk in reverse: the entry holding the last characters comes
 * first and carries the end marker, and the one holding the first characters
 * sits immediately before the 8.3 entry. Every reader depends on that order,
 * and on the checksum tying them to the alias that follows. */
static xaios_status_t write_long_name(const xaios_fat_volume_t *volume,
                                      const directory_cursor_t *cursor,
                                      uint64_t first_index,
                                      const fat_name_t *name) {
  uint32_t entries = long_entry_count(name);
  if (entries == 0U) return XAIOS_OK;
  if (entries > FAT_LFN_MAX_ENTRIES) return XAIOS_ERR_INVALID;
  uint8_t checksum = fat_lfn_checksum(name->short_name);
  for (uint32_t slot = 0U; slot < entries; ++slot) {
    uint32_t ordinal = entries - slot;
    uint64_t sector = 0U;
    uint64_t offset = 0U;
    xaios_status_t status = directory_entry_sector(
        volume, cursor, first_index + slot, &sector, &offset);
    if (status != XAIOS_OK) return status;
    status = fat_read_sector(volume, sector, g_fat_sector);
    if (status != XAIOS_OK) return status;
    uint8_t *raw = &g_fat_sector[offset];
    fat_bytes_zero(raw, FAT_DIR_ENTRY_SIZE);
    raw[0] = (uint8_t)(ordinal | (slot == 0U ? FAT_LFN_LAST : 0U));
    raw[11] = FAT_ATTR_LONG_NAME;
    raw[12] = 0U;
    raw[13] = checksum;
    fat_put16(&raw[26], 0U);
    uint32_t base = (ordinal - 1U) * FAT_LFN_CHARS;
    for (uint32_t index = 0U; index < FAT_LFN_CHARS; ++index) {
      uint32_t position = base + index;
      uint16_t value;
      if (position < name->text_length) {
        value = (uint16_t)(uint8_t)name->text[position];
      } else if (position == name->text_length) {
        value = 0x0000U; /* the terminator */
      } else {
        value = 0xFFFFU; /* unused, and 0xFFFF rather than zero by the spec */
      }
      fat_put16(&raw[fat_k_lfn_offsets[index]], value);
    }
    status = fat_write_sector(volume, sector, g_fat_sector);
    if (status != XAIOS_OK) return status;
  }
  return XAIOS_OK;
}


/* Place a named entry: its long-name entries where it needs them, then the
   8.3 entry they belong to.
 *
 * `existing_index` is where the entry already is when a file is being
 * replaced. Replacing rewrites only the 8.3 entry, because the name has not
 * changed: any long-name entries in front of it still spell it and still
 * checksum to the same alias. Allocating a fresh run instead would leave the
 * old entry in place under the same name, and a directory with two of those
 * is one where the reader finds the stale one -- which is what forty
 * rewrites of the same file produced while this was getting written. */
xaios_status_t fat_write_named_entry(const xaios_fat_volume_t *volume,
                                        const directory_cursor_t *cursor,
                                        fat_name_t *name,
                                        uint64_t existing_index,
                                        uint8_t attributes,
                                        uint32_t first_cluster, uint32_t size) {
  if (existing_index != FAT_NO_EXISTING_ENTRY) {
    return fat_write_entry(volume, cursor, existing_index, name->short_name,
                       attributes, first_cluster, size);
  }
  uint32_t entries = long_entry_count(name);
  if (entries != 0U) {
    xaios_status_t status = unique_alias(volume, cursor, name);
    if (status != XAIOS_OK) return status;
  }
  uint64_t slot = 0U;
  xaios_status_t status = find_free_run(volume, cursor, entries + 1U, &slot);
  if (status != XAIOS_OK) return status;
  status = write_long_name(volume, cursor, slot, name);
  if (status != XAIOS_OK) return status;
  return fat_write_entry(volume, cursor, slot + entries, name->short_name,
                     attributes, first_cluster, size);
}

/* Walk a path to the directory containing its last component, which is
   returned separately. The root is the starting point and '/' the separator,
   even though FAT itself uses '\\' -- the rest of XAIOS uses '/', and the
   conversion belongs here rather than in every caller. */
xaios_status_t fat_resolve_parent(const xaios_fat_volume_t *volume,
                                     const char *path,
                                     directory_cursor_t *parent,
                                     fat_name_t *final_name) {
  if (path == 0 || path[0] == '\0') return XAIOS_ERR_INVALID;
  parent->is_root = 1U;
  parent->first_cluster = 0U;
  uint64_t index = 0U;
  while (path[index] == '/') ++index;
  if (path[index] == '\0') return XAIOS_ERR_INVALID;
  for (;;) {
    uint64_t start = index;
    while (path[index] != '\0' && path[index] != '/') {
      if (index - start >= XAIOS_FAT_PATH_MAX) return XAIOS_ERR_INVALID;
      ++index;
    }
    uint64_t length = index - start;
    fat_name_t name;
    xaios_status_t status = encode_component(&path[start], length, &name);
    if (status != XAIOS_OK) return status;
    uint64_t next = index;
    while (path[next] == '/') ++next;
    if (path[next] == '\0') {
      *final_name = name;
      return XAIOS_OK;
    }
    directory_entry_t entry;
    status = fat_find_entry(volume, parent, &name, &entry);
    if (status != XAIOS_OK) return status;
    if ((entry.attributes & FAT_ATTR_DIRECTORY) == 0U) {
      return XAIOS_ERR_INVALID;
    }
    parent->is_root = 0U;
    parent->first_cluster = entry.first_cluster;
    index = next;
  }
}
