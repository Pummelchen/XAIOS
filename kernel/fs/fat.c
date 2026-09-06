#include <xaios/fat.h>

#include <xaios/klog.h>

/* On-disk layout constants. All FAT structures are little-endian regardless of
   the machine, so every field goes through the put/get helpers below rather
   than being written as a struct. */
#define FAT_SECTOR_SIZE UINT64_C(512)
#define FAT_DIR_ENTRY_SIZE UINT64_C(32)
#define FAT_ROOT_ENTRIES UINT64_C(512)
#define FAT_RESERVED_SECTORS UINT64_C(1)
#define FAT_COPIES UINT64_C(2)
#define FAT_EOC UINT32_C(0xFFFF)
#define FAT_FREE UINT32_C(0)
/* FAT16 is defined by cluster count, not by anything in the boot sector: a
   volume with fewer than 4085 clusters is FAT12 and firmware will read it as
   FAT12 no matter what the file system type string says. Staying inside these
   bounds is what makes the volume actually be the thing it claims. */
#define FAT_MIN_CLUSTERS UINT64_C(4085)
#define FAT_MAX_CLUSTERS UINT64_C(65524)
/* What the format aims for when it can. Not a limit of the format -- a limit
   on how much work writing a file costs, since every cluster is an allocation
   and three FAT sector operations. */
#define FAT_PREFERRED_MAX_CLUSTERS UINT64_C(8192)

#define FAT_ATTR_READ_ONLY UINT8_C(0x01)
#define FAT_ATTR_VOLUME_ID UINT8_C(0x08)
#define FAT_ATTR_DIRECTORY UINT8_C(0x10)
#define FAT_ATTR_LONG_NAME UINT8_C(0x0F)

#define FAT_NAME_LENGTH 11U
/* 1980-01-01. Year is counted from 1980 in bits 15..9, month one-based in bits
   8..5, day one-based in bits 4..0. */
#define FAT_EPOCH_DATE UINT16_C(0x0021)

static void bytes_zero(void *buffer, uint64_t length) {
  uint8_t *out = (uint8_t *)buffer;
  for (uint64_t index = 0U; index < length; ++index) out[index] = 0U;
}

static void bytes_copy(void *destination, const void *source,
                       uint64_t length) {
  uint8_t *out = (uint8_t *)destination;
  const uint8_t *in = (const uint8_t *)source;
  for (uint64_t index = 0U; index < length; ++index) out[index] = in[index];
}

static int bytes_equal(const void *left, const void *right, uint64_t length) {
  const uint8_t *a = (const uint8_t *)left;
  const uint8_t *b = (const uint8_t *)right;
  for (uint64_t index = 0U; index < length; ++index) {
    if (a[index] != b[index]) return 0;
  }
  return 1;
}

static void put16(uint8_t *out, uint16_t value) {
  out[0] = (uint8_t)(value & 0xFFU);
  out[1] = (uint8_t)((value >> 8) & 0xFFU);
}

static void put32(uint8_t *out, uint32_t value) {
  out[0] = (uint8_t)(value & 0xFFU);
  out[1] = (uint8_t)((value >> 8) & 0xFFU);
  out[2] = (uint8_t)((value >> 16) & 0xFFU);
  out[3] = (uint8_t)((value >> 24) & 0xFFU);
}

static uint16_t get16(const uint8_t *in) {
  return (uint16_t)((uint16_t)in[0] | ((uint16_t)in[1] << 8));
}

static uint32_t get32(const uint8_t *in) {
  return (uint32_t)in[0] | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16) |
         ((uint32_t)in[3] << 24);
}

static char upper(char value) {
  return (value >= 'a' && value <= 'z') ? (char)(value - 'a' + 'A') : value;
}

/* One sector of scratch, used for every read-modify-write below. A single
   buffer means this is not reentrant, which is correct for an installer: two
   things writing one FAT volume at once is a corrupt volume, and serialising
   here is cheaper than discovering that later. */
static uint8_t g_sector[FAT_SECTOR_SIZE];

static xaios_status_t read_sector(const xaios_fat_volume_t *volume,
                                  uint64_t sector, void *buffer) {
  if (sector >= volume->total_sectors) return XAIOS_ERR_INVALID;
  return block_read(volume->device, sector * volume->sector_size, buffer,
                    volume->sector_size);
}

static xaios_status_t write_sector(const xaios_fat_volume_t *volume,
                                   uint64_t sector, const void *buffer) {
  if (sector >= volume->total_sectors) return XAIOS_ERR_INVALID;
  return block_write(volume->device, sector * volume->sector_size, buffer,
                     volume->sector_size);
}

/*
 * Convert one path component to the 11-byte on-disk name: eight of base, three
 * of extension, space padded, upper case. A component that does not fit is
 * refused rather than truncated -- two files whose names differ only past the
 * eighth character would silently become one.
 */
/* A path component, in both the forms a directory can hold it.
 *
 * 8.3 was enough until RISC-V. UEFI's removable-media path is named for the
 * machine -- \EFI\BOOT\BOOTAA64.EFI, \EFI\BOOT\BOOTX64.EFI, and
 * \EFI\BOOT\BOOTRISCV64.EFI -- and the third does not fit: eleven
 * characters of base where 8.3 allows eight. So a machine of this
 * architecture could format an EFI System Partition perfectly and had no way
 * to put on it the one file its own firmware opens. It installed a disk that
 * booted only because the copy this repository builds with mtools had a long
 * name on it, and the installer's own copy silently had four files where it
 * should have had five.
 *
 * `text` is the name as asked for, `short_name` the 8.3 entry that always
 * exists -- either the name itself, or a generated alias like BOOTRI~1 -- and
 * `needs_long` says whether long-name entries have to accompany it. */
typedef struct fat_name {
  uint8_t short_name[FAT_NAME_LENGTH];
  char text[XAIOS_FAT_PATH_MAX + 1U];
  uint32_t text_length;
  uint32_t needs_long;
} fat_name_t;

/* Thirteen UTF-16 characters per long-name entry, which is what fixes how
   many entries a name of a given length costs. */
#define FAT_LFN_CHARS 13U
#define FAT_LFN_LAST UINT8_C(0x40)
#define FAT_LFN_MAX_ENTRIES 20U

static xaios_status_t encode_name(const char *component, uint64_t length,
                                  uint8_t out[FAT_NAME_LENGTH]) {
  if (length == 0U) return XAIOS_ERR_INVALID;
  for (uint64_t index = 0U; index < FAT_NAME_LENGTH; ++index) out[index] = ' ';
  uint64_t dot = length;
  for (uint64_t index = 0U; index < length; ++index) {
    if (component[index] == '.') {
      /* The last dot separates the extension; an earlier one is not a legal
         8.3 name at all. "." and ".." are handled by the caller. */
      if (dot != length) return XAIOS_ERR_INVALID;
      dot = index;
    }
  }
  uint64_t base_length = dot;
  uint64_t extension_length = dot == length ? 0U : length - dot - 1U;
  if (base_length == 0U || base_length > 8U || extension_length > 3U) {
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t index = 0U; index < base_length; ++index) {
    char value = upper(component[index]);
    if (value == '/' || value == '\\' || (uint8_t)value < 0x20U) {
      return XAIOS_ERR_INVALID;
    }
    out[index] = (uint8_t)value;
  }
  for (uint64_t index = 0U; index < extension_length; ++index) {
    out[8U + index] = (uint8_t)upper(component[dot + 1U + index]);
  }
  return XAIOS_OK;
}

/* The checksum a long-name entry carries, computed over the 8.3 alias it
   belongs to. It is what ties the two together: a reader that finds long-name
   entries whose checksum does not match the following 8.3 entry must ignore
   them, because they are the remains of a file some other writer deleted. */
static uint8_t lfn_checksum(const uint8_t name[FAT_NAME_LENGTH]) {
  uint8_t sum = 0U;
  for (uint32_t index = 0U; index < FAT_NAME_LENGTH; ++index) {
    sum = (uint8_t)(((sum & 1U) != 0U ? 0x80U : 0U) + (sum >> 1) + name[index]);
  }
  return sum;
}

/* Is this character one an 8.3 name may hold? Anything else is dropped from a
   generated alias rather than encoded, which is what every other writer does
   and what keeps the alias a legal short name. */
static uint32_t short_name_character(char value) {
  if (value >= 'A' && value <= 'Z') return 1U;
  if (value >= '0' && value <= '9') return 1U;
  return value == '_' || value == '-' || value == '$' || value == '~';
}

/* Build the 8.3 alias for a name that does not fit: up to six legal
   characters of the base, then "~N", then up to three of the extension.
   BOOTRISCV64.EFI becomes BOOTRI~1.EFI, which is what mtools writes for it
   and therefore what a volume built by this repository already carries. */
static void short_alias(const char *component, uint64_t length,
                        uint32_t ordinal, uint8_t out[FAT_NAME_LENGTH]) {
  for (uint32_t index = 0U; index < FAT_NAME_LENGTH; ++index) out[index] = ' ';
  uint64_t dot = length;
  for (uint64_t index = 0U; index < length; ++index) {
    if (component[index] == '.') dot = index;
  }
  uint32_t used = 0U;
  for (uint64_t index = 0U; index < dot && used < 6U; ++index) {
    char value = upper(component[index]);
    if (short_name_character(value) == 0U) continue;
    out[used++] = (uint8_t)value;
  }
  out[used++] = (uint8_t)'~';
  out[used++] = (uint8_t)('0' + (char)(ordinal % 10U));
  uint32_t extension = 0U;
  for (uint64_t index = dot + 1U; index < length && extension < 3U; ++index) {
    char value = upper(component[index]);
    if (short_name_character(value) == 0U) continue;
    out[8U + extension] = (uint8_t)value;
    ++extension;
  }
}

/* Where a cluster's first sector is. Cluster numbering starts at 2: entries 0
   and 1 of the FAT hold the media descriptor and end-of-chain marker, and have
   never addressed data. */
static uint64_t cluster_sector(const xaios_fat_volume_t *volume,
                               uint32_t cluster) {
  return volume->data_start_sector +
         ((uint64_t)cluster - 2U) * volume->sectors_per_cluster;
}

static xaios_status_t fat_entry_get(const xaios_fat_volume_t *volume,
                                    uint32_t cluster, uint32_t *out_value) {
  if (cluster < 2U || (uint64_t)cluster >= volume->cluster_count + 2U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t offset = (uint64_t)cluster * 2U;
  uint64_t sector = volume->reserved_sectors + offset / volume->sector_size;
  xaios_status_t status = read_sector(volume, sector, g_sector);
  if (status != XAIOS_OK) return status;
  *out_value = get16(&g_sector[offset % volume->sector_size]);
  return XAIOS_OK;
}

/* Written to every copy of the FAT. A volume whose copies disagree is one that
   some implementations will read one way and others another, which is exactly
   the failure that is impossible to diagnose from a machine that will not
   boot. */
static xaios_status_t fat_entry_set(const xaios_fat_volume_t *volume,
                                    uint32_t cluster, uint32_t value) {
  if (cluster < 2U || (uint64_t)cluster >= volume->cluster_count + 2U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t offset = (uint64_t)cluster * 2U;
  for (uint64_t copy = 0U; copy < volume->fat_count; ++copy) {
    uint64_t sector = volume->reserved_sectors +
                      copy * volume->sectors_per_fat +
                      offset / volume->sector_size;
    xaios_status_t status = read_sector(volume, sector, g_sector);
    if (status != XAIOS_OK) return status;
    put16(&g_sector[offset % volume->sector_size], (uint16_t)value);
    status = write_sector(volume, sector, g_sector);
    if (status != XAIOS_OK) return status;
  }
  return XAIOS_OK;
}

/* Where the last allocation stopped. Resuming from there rather than from the
   start is the difference between a copy that finishes and one that does not:
   allocating n clusters by scanning from the beginning each time reads the FAT
   O(n^2) times, and copying a 10 MB initial filesystem onto a 32 MB volume
   needs about twenty thousand clusters. Measured as a machine that printed its
   last line and then sat there until the gate's timeout killed it -- no panic,
   no progress, nothing to see.

   Only a hint. It is never trusted: the scan below wraps and re-checks, so a
   stale value costs one wasted pass and never returns a cluster that is in
   use. */
static uint32_t g_next_free_hint = 2U;

static xaios_status_t allocate_cluster(const xaios_fat_volume_t *volume,
                                       uint32_t *out_cluster) {
  uint64_t limit = volume->cluster_count + 2U;
  uint64_t hint = g_next_free_hint;
  if (hint < 2U || hint >= limit) hint = 2U;
  uint64_t entries_per_sector = volume->sector_size / 2U;
  /* From the hint to the end, then from the start back to the hint. Two passes
     cover every cluster exactly once, and the second only runs on a volume
     that is nearly full. */
  for (uint32_t pass = 0U; pass < 2U; ++pass) {
    uint64_t cluster = pass == 0U ? hint : 2U;
    uint64_t end = pass == 0U ? limit : hint;
    while (cluster < end) {
      uint64_t sector =
          volume->reserved_sectors + (cluster * 2U) / volume->sector_size;
      xaios_status_t status = read_sector(volume, sector, g_sector);
      if (status != XAIOS_OK) return status;
      uint64_t within = ((cluster * 2U) % volume->sector_size) / 2U;
      for (; within < entries_per_sector && cluster < end;
           ++within, ++cluster) {
        if (get16(&g_sector[within * 2U]) != FAT_FREE) continue;
        status = fat_entry_set(volume, (uint32_t)cluster, FAT_EOC);
        if (status != XAIOS_OK) return status;
        g_next_free_hint = (uint32_t)(cluster + 1U);
        *out_cluster = (uint32_t)cluster;
        return XAIOS_OK;
      }
    }
  }
  return XAIOS_ERR_NO_MEMORY;
}

static xaios_status_t zero_cluster(const xaios_fat_volume_t *volume,
                                   uint32_t cluster) {
  bytes_zero(g_sector, volume->sector_size);
  uint64_t first = cluster_sector(volume, cluster);
  for (uint64_t index = 0U; index < volume->sectors_per_cluster; ++index) {
    xaios_status_t status = write_sector(volume, first + index, g_sector);
    if (status != XAIOS_OK) return status;
  }
  return XAIOS_OK;
}

/* Release a chain. Used when replacing a file: the old contents go back to the
   free list before the new ones are written, so rewriting a file repeatedly
   does not consume the volume. */
static xaios_status_t free_chain(const xaios_fat_volume_t *volume,
                                 uint32_t first) {
  uint32_t cluster = first;
  uint64_t guard = 0U;
  while (cluster >= 2U && (uint64_t)cluster < volume->cluster_count + 2U) {
    if (guard++ > volume->cluster_count) return XAIOS_ERR_INVALID;
    uint32_t next = 0U;
    xaios_status_t status = fat_entry_get(volume, cluster, &next);
    if (status != XAIOS_OK) return status;
    status = fat_entry_set(volume, cluster, FAT_FREE);
    if (status != XAIOS_OK) return status;
    cluster = next;
  }
  return XAIOS_OK;
}

/*
 * A directory is either the fixed-size root region or a cluster chain. The two
 * are addressed differently on disk and identically everywhere else, so this
 * pair of accessors is what keeps the rest of the file from caring.
 */
typedef struct directory_cursor {
  uint32_t is_root;
  uint32_t first_cluster;
} directory_cursor_t;

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
  *out_sector = cluster_sector(volume, cluster) +
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
  xaios_status_t status = allocate_cluster(volume, &added);
  if (status != XAIOS_OK) return status;
  status = zero_cluster(volume, added);
  if (status != XAIOS_OK) return status;
  return fat_entry_set(volume, cluster, added);
}

typedef struct directory_entry {
  uint8_t name[FAT_NAME_LENGTH];
  uint8_t attributes;
  uint32_t first_cluster;
  uint32_t size;
  uint64_t index;
  uint64_t sector;
  uint64_t offset;
} directory_entry_t;

static void decode_entry(const uint8_t *raw, directory_entry_t *entry) {
  bytes_copy(entry->name, raw, FAT_NAME_LENGTH);
  entry->attributes = raw[11];
  entry->first_cluster = get16(&raw[26]);
  entry->size = get32(&raw[28]);
}

/* Where in an assembled long name a given entry's characters belong, and how
   to read them out of the entry. The thirteen characters are in three runs
   rather than one, which is an artefact of the entry having been fitted
   around the fields an 8.3 entry already used. */
static const uint8_t k_lfn_offsets[FAT_LFN_CHARS] = {
    1U, 3U, 5U, 7U, 9U, 14U, 16U, 18U, 20U, 22U, 24U, 28U, 30U};

/* Take one long-name entry's characters into `out` at its ordinal's place.
   Returns zero when the entry holds a character this reader will not
   represent -- anything outside ASCII, which no name here uses and which
   would otherwise be silently mangled into a name that matched nothing. */
static uint32_t lfn_gather(const uint8_t *raw, char *out, uint32_t capacity,
                           uint32_t *out_length) {
  uint32_t ordinal = raw[0] & 0x3FU;
  if (ordinal == 0U || ordinal > FAT_LFN_MAX_ENTRIES) return 0U;
  uint32_t base = (ordinal - 1U) * FAT_LFN_CHARS;
  for (uint32_t index = 0U; index < FAT_LFN_CHARS; ++index) {
    uint16_t value = get16(&raw[k_lfn_offsets[index]]);
    if (value == 0x0000U || value == 0xFFFFU) continue;
    if (value > 0x7FU) return 0U;
    uint32_t position = base + index;
    if (position >= capacity) return 0U;
    out[position] = (char)value;
    if (position + 1U > *out_length) *out_length = position + 1U;
  }
  return 1U;
}

static uint32_t names_equal_fold(const char *a, uint32_t a_length,
                                 const char *b, uint32_t b_length) {
  if (a_length != b_length) return 0U;
  for (uint32_t index = 0U; index < a_length; ++index) {
    if (upper(a[index]) != upper(b[index])) return 0U;
  }
  return 1U;
}

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
static xaios_status_t find_entry(const xaios_fat_volume_t *volume,
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
    status = read_sector(volume, sector, g_sector);
    if (status != XAIOS_OK) return status;
    const uint8_t *raw = &g_sector[offset];
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
        if (lfn_gather(raw, assembled, XAIOS_FAT_PATH_MAX,
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
        bytes_equal(raw, name->short_name, FAT_NAME_LENGTH) != 0 ? 1U : 0U;
    if (matched == 0U && assembled_valid != 0U && assembled_length != 0U &&
        lfn_checksum(raw) == assembled_checksum) {
      matched = names_equal_fold(assembled, assembled_length, name->text,
                                 name->text_length);
    }
    assembled_valid = 0U;
    if (matched == 0U) continue;
    decode_entry(raw, entry);
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
    status = read_sector(volume, sector, g_sector);
    if (status != XAIOS_OK) return status;
    const uint8_t *raw = &g_sector[offset];
    if (raw[0] == 0x00U) return XAIOS_ERR_NOT_FOUND;
    if (raw[0] == 0xE5U) continue;
    if ((raw[11] & FAT_ATTR_LONG_NAME) == FAT_ATTR_LONG_NAME) continue;
    if (bytes_equal(raw, name, FAT_NAME_LENGTH) != 0) return XAIOS_OK;
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
    status = read_sector(volume, sector, g_sector);
    if (status != XAIOS_OK) return status;
    if (g_sector[offset] == 0x00U || g_sector[offset] == 0xE5U) {
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

static xaios_status_t write_entry(const xaios_fat_volume_t *volume,
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
  status = read_sector(volume, sector, g_sector);
  if (status != XAIOS_OK) return status;
  uint8_t *raw = &g_sector[offset];
  bytes_zero(raw, FAT_DIR_ENTRY_SIZE);
  bytes_copy(raw, name, FAT_NAME_LENGTH);
  raw[11] = attributes;
  /* A constant date of 1980-01-01, the epoch of the format, rather than zero.
     XAIOS has no wall clock while installing onto a bare machine, and a
     plausible-looking wrong date would be worse than an obviously fixed one --
     but zero is not a legal FAT date at all: the month and day fields are
     one-based, so a zero encodes the zeroth day of the zeroth month, which
     readers render as garbage. Firmware ignores these fields either way. */
  put16(&raw[14], 0U);
  put16(&raw[16], FAT_EPOCH_DATE);
  put16(&raw[18], FAT_EPOCH_DATE);
  put16(&raw[22], 0U);
  put16(&raw[24], FAT_EPOCH_DATE);
  put16(&raw[26], (uint16_t)first_cluster);
  put32(&raw[28], size);
  return write_sector(volume, sector, g_sector);
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
  if (encode_name(component, length, out->short_name) == XAIOS_OK) {
    out->needs_long = 0U;
    return XAIOS_OK;
  }
  out->needs_long = 1U;
  short_alias(component, length, 1U, out->short_name);
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
    short_alias(name->text, name->text_length, ordinal, name->short_name);
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
  uint8_t checksum = lfn_checksum(name->short_name);
  for (uint32_t slot = 0U; slot < entries; ++slot) {
    uint32_t ordinal = entries - slot;
    uint64_t sector = 0U;
    uint64_t offset = 0U;
    xaios_status_t status = directory_entry_sector(
        volume, cursor, first_index + slot, &sector, &offset);
    if (status != XAIOS_OK) return status;
    status = read_sector(volume, sector, g_sector);
    if (status != XAIOS_OK) return status;
    uint8_t *raw = &g_sector[offset];
    bytes_zero(raw, FAT_DIR_ENTRY_SIZE);
    raw[0] = (uint8_t)(ordinal | (slot == 0U ? FAT_LFN_LAST : 0U));
    raw[11] = FAT_ATTR_LONG_NAME;
    raw[12] = 0U;
    raw[13] = checksum;
    put16(&raw[26], 0U);
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
      put16(&raw[k_lfn_offsets[index]], value);
    }
    status = write_sector(volume, sector, g_sector);
    if (status != XAIOS_OK) return status;
  }
  return XAIOS_OK;
}

#define FAT_NO_EXISTING_ENTRY UINT64_MAX

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
static xaios_status_t write_named_entry(const xaios_fat_volume_t *volume,
                                        const directory_cursor_t *cursor,
                                        fat_name_t *name,
                                        uint64_t existing_index,
                                        uint8_t attributes,
                                        uint32_t first_cluster, uint32_t size) {
  if (existing_index != FAT_NO_EXISTING_ENTRY) {
    return write_entry(volume, cursor, existing_index, name->short_name,
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
  return write_entry(volume, cursor, slot + entries, name->short_name,
                     attributes, first_cluster, size);
}

/* Walk a path to the directory containing its last component, which is
   returned separately. The root is the starting point and '/' the separator,
   even though FAT itself uses '\\' -- the rest of XAIOS uses '/', and the
   conversion belongs here rather than in every caller. */
static xaios_status_t resolve_parent(const xaios_fat_volume_t *volume,
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
    status = find_entry(volume, parent, &name, &entry);
    if (status != XAIOS_OK) return status;
    if ((entry.attributes & FAT_ATTR_DIRECTORY) == 0U) {
      return XAIOS_ERR_INVALID;
    }
    parent->is_root = 0U;
    parent->first_cluster = entry.first_cluster;
    index = next;
  }
}

xaios_status_t fat_mount(xaios_block_device_t *device,
                         xaios_fat_volume_t *volume) {
  if (device == 0 || volume == 0) return XAIOS_ERR_INVALID;
  xaios_block_device_info_t info;
  if (block_device_info(device, &info) != XAIOS_OK) return XAIOS_ERR_INVALID;
  if (info.logical_sector_size != FAT_SECTOR_SIZE) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  bytes_zero(volume, sizeof(*volume));
  volume->device = device;
  volume->sector_size = info.logical_sector_size;
  volume->total_sectors = info.capacity_bytes / info.logical_sector_size;
  if (read_sector(volume, 0U, g_sector) != XAIOS_OK) return XAIOS_ERR_IO;
  if (g_sector[510] != 0x55U || g_sector[511] != 0xAAU) {
    return XAIOS_ERR_INVALID;
  }
  if (get16(&g_sector[11]) != FAT_SECTOR_SIZE) return XAIOS_ERR_UNSUPPORTED;
  volume->sectors_per_cluster = g_sector[13];
  volume->reserved_sectors = get16(&g_sector[14]);
  volume->fat_count = g_sector[16];
  volume->root_entry_count = get16(&g_sector[17]);
  volume->sectors_per_fat = get16(&g_sector[22]);
  uint64_t declared = get16(&g_sector[19]);
  if (declared == 0U) declared = get32(&g_sector[32]);
  if (volume->sectors_per_cluster == 0U || volume->fat_count == 0U ||
      volume->sectors_per_fat == 0U || volume->reserved_sectors == 0U ||
      declared == 0U || declared > volume->total_sectors) {
    return XAIOS_ERR_INVALID;
  }
  volume->total_sectors = declared;
  volume->root_start_sector =
      volume->reserved_sectors + volume->fat_count * volume->sectors_per_fat;
  volume->root_sectors =
      (volume->root_entry_count * FAT_DIR_ENTRY_SIZE + volume->sector_size -
       1U) /
      volume->sector_size;
  volume->data_start_sector = volume->root_start_sector + volume->root_sectors;
  if (volume->data_start_sector >= volume->total_sectors) {
    return XAIOS_ERR_INVALID;
  }
  volume->cluster_count = (volume->total_sectors - volume->data_start_sector) /
                          volume->sectors_per_cluster;
  if (volume->cluster_count < FAT_MIN_CLUSTERS ||
      volume->cluster_count > FAT_MAX_CLUSTERS) {
    /* Outside these bounds the volume is FAT12 or FAT32 whatever its boot
       sector says, and this code would read it wrong. */
    return XAIOS_ERR_UNSUPPORTED;
  }
  volume->mounted = 1U;
  g_next_free_hint = 2U;
  return XAIOS_OK;
}

xaios_status_t fat_format(xaios_block_device_t *device, const char *label,
                          xaios_fat_volume_t *volume) {
  if (device == 0 || volume == 0) return XAIOS_ERR_INVALID;
  xaios_block_device_info_t info;
  if (block_device_info(device, &info) != XAIOS_OK) return XAIOS_ERR_INVALID;
  if (info.read_only != 0U) return XAIOS_ERR_UNSUPPORTED;
  if (info.logical_sector_size != FAT_SECTOR_SIZE) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  bytes_zero(volume, sizeof(*volume));
  volume->device = device;
  volume->sector_size = info.logical_sector_size;
  volume->total_sectors = info.capacity_bytes / info.logical_sector_size;
  volume->reserved_sectors = FAT_RESERVED_SECTORS;
  volume->fat_count = FAT_COPIES;
  volume->root_entry_count = FAT_ROOT_ENTRIES;
  volume->root_sectors =
      (volume->root_entry_count * FAT_DIR_ENTRY_SIZE + volume->sector_size -
       1U) /
      volume->sector_size;

  /* Choose a cluster size that keeps the cluster count moderate, not the
     smallest one that is merely legal.

     The smallest legal choice wastes the least space, which is why it was the
     original rule, and it is the wrong trade for this volume. Cluster count is
     what the work of writing a file is measured in: every cluster costs an
     allocation, a FAT read and a write to each copy of the FAT, and the block
     driver moves one sector per request. A 32 MiB EFI partition formatted with
     512-byte clusters has 65,000 of them, and copying a 10 MiB initial
     filesystem onto it came to roughly eighty-five thousand synchronous
     requests -- enough that one of them passed the driver's five-second
     deadline and the queue was reset out from under the copy. The install
     failed with an I/O error that was really a throughput problem.

     Targeting a bounded cluster count instead is what every real formatter
     does, and it cuts the metadata work on that volume eightfold. The floor of
     4085 still binds: below it the volume is FAT12 whatever the boot sector
     says. */
  uint64_t chosen = 0U;
  for (uint32_t pass = 0U; pass < 2U && chosen == 0U; ++pass) {
    /* First pass insists on a moderate cluster count; the second accepts any
       legal one, for a volume too large for the first to satisfy. */
    uint64_t ceiling = pass == 0U ? FAT_PREFERRED_MAX_CLUSTERS
                                  : FAT_MAX_CLUSTERS;
    for (uint64_t sectors_per_cluster = 1U; sectors_per_cluster <= 64U;
         sectors_per_cluster *= 2U) {
      /* The FAT has to hold two bytes per cluster plus the two reserved
         entries, and it comes out of the same space the clusters do, so this
         converges rather than solving in one step. */
      uint64_t fat_sectors = 1U;
      for (uint64_t attempt = 0U; attempt < 8U; ++attempt) {
        uint64_t data_start = volume->reserved_sectors +
                              volume->fat_count * fat_sectors +
                              volume->root_sectors;
        if (data_start >= volume->total_sectors) {
          fat_sectors = 0U;
          break;
        }
        uint64_t clusters =
            (volume->total_sectors - data_start) / sectors_per_cluster;
        uint64_t needed = ((clusters + 2U) * 2U + volume->sector_size - 1U) /
                          volume->sector_size;
        if (needed <= fat_sectors) break;
        fat_sectors = needed;
      }
      if (fat_sectors == 0U) continue;
      uint64_t data_start = volume->reserved_sectors +
                            volume->fat_count * fat_sectors +
                            volume->root_sectors;
      if (data_start >= volume->total_sectors) continue;
      uint64_t clusters =
          (volume->total_sectors - data_start) / sectors_per_cluster;
      if (clusters < FAT_MIN_CLUSTERS || clusters > ceiling) continue;
      volume->sectors_per_cluster = sectors_per_cluster;
      volume->sectors_per_fat = fat_sectors;
      volume->data_start_sector = data_start;
      volume->cluster_count = clusters;
      chosen = 1U;
      break;
    }
  }
  if (chosen == 0U) {
    /* No cluster size produces a legal FAT16 volume here. Refuse rather than
       write FAT12 or FAT32 under a FAT16 label: firmware would read the
       result as what it really is, or not at all, and say nothing either
       way. */
    return XAIOS_ERR_UNSUPPORTED;
  }
  volume->root_start_sector =
      volume->reserved_sectors + volume->fat_count * volume->sectors_per_fat;

  /* Boot sector. The jump instruction and OEM name are what a firmware
     implementation looks at first to decide this is a FAT volume at all. */
  bytes_zero(g_sector, volume->sector_size);
  g_sector[0] = 0xEBU;
  g_sector[1] = 0x3CU;
  g_sector[2] = 0x90U;
  static const char oem[] = "XAIOS1.0";
  bytes_copy(&g_sector[3], oem, 8U);
  put16(&g_sector[11], (uint16_t)volume->sector_size);
  g_sector[13] = (uint8_t)volume->sectors_per_cluster;
  put16(&g_sector[14], (uint16_t)volume->reserved_sectors);
  g_sector[16] = (uint8_t)volume->fat_count;
  put16(&g_sector[17], (uint16_t)volume->root_entry_count);
  if (volume->total_sectors < UINT64_C(0x10000)) {
    put16(&g_sector[19], (uint16_t)volume->total_sectors);
  } else {
    put16(&g_sector[19], 0U);
    put32(&g_sector[32], (uint32_t)volume->total_sectors);
  }
  g_sector[21] = 0xF8U; /* fixed disk */
  put16(&g_sector[22], (uint16_t)volume->sectors_per_fat);
  put16(&g_sector[24], 63U);  /* sectors per track, unused but conventional */
  put16(&g_sector[26], 255U); /* heads, likewise */
  g_sector[38] = 0x29U;       /* extended boot signature: label and id follow */
  put32(&g_sector[39], UINT32_C(0x58414F53));
  for (uint64_t index = 0U; index < 11U; ++index) {
    g_sector[43U + index] = ' ';
  }
  if (label != 0) {
    for (uint64_t index = 0U; index < 11U && label[index] != '\0'; ++index) {
      g_sector[43U + index] = (uint8_t)upper(label[index]);
    }
  }
  static const char type[] = "FAT16   ";
  bytes_copy(&g_sector[54], type, 8U);
  g_sector[510] = 0x55U;
  g_sector[511] = 0xAAU;
  xaios_status_t status = write_sector(volume, 0U, g_sector);
  if (status != XAIOS_OK) return status;

  /* Clear both FATs and the root directory. Everything past that is data and
     is unreachable until a FAT entry points at it, so leaving it as it was
     costs nothing and writing it would cost the whole volume's worth of I/O
     on every install. */
  bytes_zero(g_sector, volume->sector_size);
  for (uint64_t sector = volume->reserved_sectors;
       sector < volume->data_start_sector; ++sector) {
    status = write_sector(volume, sector, g_sector);
    if (status != XAIOS_OK) return status;
  }
  /* Entries 0 and 1: the media descriptor, and the end-of-chain marker. */
  status = read_sector(volume, volume->reserved_sectors, g_sector);
  if (status != XAIOS_OK) return status;
  put16(&g_sector[0], 0xFFF8U);
  put16(&g_sector[2], 0xFFFFU);
  for (uint64_t copy = 0U; copy < volume->fat_count; ++copy) {
    status = write_sector(
        volume, volume->reserved_sectors + copy * volume->sectors_per_fat,
        g_sector);
    if (status != XAIOS_OK) return status;
  }
  volume->mounted = 1U;
  /* A new volume is empty, so the hint from whatever was allocated last on
     some other volume is meaningless here. */
  g_next_free_hint = 2U;

  /* The label, again, as a directory entry in the root. The boot sector field
     written above is where firmware looks; this is where every tool that
     reports a volume name looks, and a volume that has one in the boot sector
     and not here reads back as unlabelled. Both, or the two disagree. */
  if (label != 0 && label[0] != '\0') {
    uint8_t name[FAT_NAME_LENGTH];
    for (uint64_t index = 0U; index < FAT_NAME_LENGTH; ++index) {
      name[index] = ' ';
    }
    for (uint64_t index = 0U;
         index < FAT_NAME_LENGTH && label[index] != '\0'; ++index) {
      name[index] = (uint8_t)upper(label[index]);
    }
    directory_cursor_t root = {1U, 0U};
    status = write_entry(volume, &root, 0U, name, FAT_ATTR_VOLUME_ID, 0U, 0U);
    if (status != XAIOS_OK) return status;
  }

  (void)block_flush(device);
  return XAIOS_OK;
}

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
    xaios_status_t status = resolve_parent(volume, partial, &parent, &name);
    if (status != XAIOS_OK) return status;
    directory_entry_t existing;
    status = find_entry(volume, &parent, &name, &existing);
    if (status == XAIOS_OK) {
      /* Already there. A directory is fine and an installer that ran before
         should find it; a file of the same name is not. */
      if ((existing.attributes & FAT_ATTR_DIRECTORY) == 0U) {
        return XAIOS_ERR_INVALID;
      }
    } else {
      uint32_t cluster = 0U;
      status = allocate_cluster(volume, &cluster);
      if (status != XAIOS_OK) return status;
      status = zero_cluster(volume, cluster);
      if (status != XAIOS_OK) return status;
      status = write_named_entry(volume, &parent, &name,
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
      status = write_entry(volume, &self, 0U, dot, FAT_ATTR_DIRECTORY, cluster,
                           0U);
      if (status != XAIOS_OK) return status;
      dot[1] = (uint8_t)'.';
      status = write_entry(volume, &self, 1U, dot, FAT_ATTR_DIRECTORY,
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
  xaios_status_t status = resolve_parent(volume, path, &parent, &name);
  if (status != XAIOS_OK) return status;

  directory_entry_t existing;
  uint64_t existing_index = FAT_NO_EXISTING_ENTRY;
  status = find_entry(volume, &parent, &name, &existing);
  if (status == XAIOS_OK) {
    if ((existing.attributes & FAT_ATTR_DIRECTORY) != 0U) {
      return XAIOS_ERR_INVALID;
    }
    /* Replacing: the old chain goes back to the free list first, so that
       writing the same file twice does not consume the volume twice. */
    if (existing.first_cluster >= 2U) {
      status = free_chain(volume, existing.first_cluster);
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
    status = allocate_cluster(volume, &cluster);
    if (status != XAIOS_OK) {
      if (first >= 2U) (void)free_chain(volume, first);
      return status;
    }
    if (first == 0U) {
      first = cluster;
    } else {
      status = fat_entry_set(volume, previous, cluster);
      if (status != XAIOS_OK) {
        (void)free_chain(volume, first);
        return status;
      }
    }
    previous = cluster;
    uint64_t base = cluster_sector(volume, cluster);
    for (uint64_t index = 0U;
         index < volume->sectors_per_cluster && written < length; ++index) {
      uint64_t chunk = length - written;
      if (chunk > volume->sector_size) chunk = volume->sector_size;
      bytes_zero(g_sector, volume->sector_size);
      bytes_copy(g_sector, &bytes[written], chunk);
      status = write_sector(volume, base + index, g_sector);
      if (status != XAIOS_OK) {
        (void)free_chain(volume, first);
        return status;
      }
      written += chunk;
    }
    if (cluster_bytes == 0U) return XAIOS_ERR_INVALID;
  }

  status = write_named_entry(volume, &parent, &name, existing_index, 0U,
                             first, (uint32_t)length);
  if (status != XAIOS_OK) {
    if (first >= 2U) (void)free_chain(volume, first);
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
  xaios_status_t status = resolve_parent(volume, path, &parent, &name);
  if (status != XAIOS_OK) return status;
  directory_entry_t entry;
  status = find_entry(volume, &parent, &name, &entry);
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
    uint64_t base = cluster_sector(volume, cluster);
    for (uint64_t index = 0U;
         index < volume->sectors_per_cluster && read < entry.size; ++index) {
      status = read_sector(volume, base + index, g_sector);
      if (status != XAIOS_OK) return status;
      uint64_t chunk = entry.size - read;
      if (chunk > volume->sector_size) chunk = volume->sector_size;
      bytes_copy(&out[read], g_sector, chunk);
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
  xaios_status_t status = resolve_parent(volume, path, &parent, &name);
  if (status != XAIOS_OK) return status;
  directory_entry_t entry;
  status = find_entry(volume, &parent, &name, &entry);
  if (status != XAIOS_OK) return status;
  if (out_size != 0) *out_size = entry.size;
  if (out_is_directory != 0) {
    *out_is_directory = (entry.attributes & FAT_ATTR_DIRECTORY) != 0U ? 1U : 0U;
  }
  return XAIOS_OK;
}

/* A second buffer, holding payload while g_sector holds metadata.
 *
 * Every function above borrows g_sector for whatever sector it is currently
 * reading or writing, which is fine while one volume is being touched at a
 * time. A copy is not that: it reads a data sector from the source, and then,
 * before that data has been written anywhere, it reads and writes FAT entries
 * and directory entries on the destination. Each of those lands in g_sector.
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
      resolve_parent(source, source_path, &source_parent, &source_name);
  if (status != XAIOS_OK) return status;
  directory_entry_t source_entry;
  status = find_entry(source, &source_parent, &source_name, &source_entry);
  if (status != XAIOS_OK) return status;
  if ((source_entry.attributes & FAT_ATTR_DIRECTORY) != 0U) {
    return XAIOS_ERR_INVALID;
  }

  directory_cursor_t parent;
  fat_name_t name;
  status = resolve_parent(destination, destination_path, &parent, &name);
  if (status != XAIOS_OK) return status;
  directory_entry_t existing;
  uint64_t existing_index = FAT_NO_EXISTING_ENTRY;
  status = find_entry(destination, &parent, &name, &existing);
  if (status == XAIOS_OK) {
    if ((existing.attributes & FAT_ATTR_DIRECTORY) != 0U) {
      return XAIOS_ERR_INVALID;
    }
    if (existing.first_cluster >= 2U) {
      status = free_chain(destination, existing.first_cluster);
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
      if (first >= 2U) (void)free_chain(destination, first);
      return XAIOS_ERR_INVALID;
    }
    uint32_t cluster = 0U;
    status = allocate_cluster(destination, &cluster);
    if (status != XAIOS_OK) {
      if (first >= 2U) (void)free_chain(destination, first);
      return status;
    }
    if (first == 0U) {
      first = cluster;
    } else {
      status = fat_entry_set(destination, previous, cluster);
      if (status != XAIOS_OK) {
        (void)free_chain(destination, first);
        return status;
      }
    }
    previous = cluster;

    uint64_t source_base = cluster_sector(source, source_cluster);
    uint64_t destination_base = cluster_sector(destination, cluster);
    /* The two volumes need not agree on cluster size, so the inner loop is
       bounded by the destination's cluster and by whatever is left of the
       source's -- whichever runs out first decides when to follow a chain. */
    for (uint64_t index = 0U;
         index < destination->sectors_per_cluster && remaining != 0U;
         ++index) {
      uint64_t within = source_offset % source->sectors_per_cluster;
      status = read_sector(source, source_base + within, g_payload);
      if (status != XAIOS_OK) {
        klog("fat: copy read failed sector=%lu cluster=%u offset=%lu "
             "remaining=%lu status=%d\n",
             source_base + within, source_cluster, source_offset, remaining,
             (int)status);
        (void)free_chain(destination, first);
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
      status = write_sector(destination, destination_base + index, g_payload);
      if (status != XAIOS_OK) {
        klog("fat: copy write failed sector=%lu cluster=%u of %lu "
             "remaining=%lu status=%d\n",
             destination_base + index, cluster, destination->cluster_count,
             remaining, (int)status);
        (void)free_chain(destination, first);
        return status;
      }
      remaining -= chunk;
      ++source_offset;
      if (source_offset % source->sectors_per_cluster == 0U) {
        uint32_t next = 0U;
        status = fat_entry_get(source, source_cluster, &next);
        if (status != XAIOS_OK) {
          (void)free_chain(destination, first);
          return status;
        }
        source_cluster = next;
        source_base = remaining != 0U && next >= 2U &&
                              (uint64_t)next < source->cluster_count + 2U
                          ? cluster_sector(source, next)
                          : 0U;
      }
    }
  }

  status = write_named_entry(destination, &parent, &name, existing_index, 0U,
                             first, source_entry.size);
  if (status != XAIOS_OK) {
    if (first >= 2U) (void)free_chain(destination, first);
    return status;
  }
  (void)block_flush(destination->device);
  return XAIOS_OK;
}
