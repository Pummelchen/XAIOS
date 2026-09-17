#include <xaios/fat.h>

#include "fat_internal.h"
#include "fat_volume_internal.h"

#include <xaios/klog.h>

/* One sector of scratch, used for every read-modify-write below. A single
   buffer means this is not reentrant, which is correct for an installer: two
   things writing one FAT volume at once is a corrupt volume, and serialising
   here is cheaper than discovering that later. */
uint8_t g_fat_sector[FAT_SECTOR_SIZE];

xaios_status_t fat_read_sector(const xaios_fat_volume_t *volume,
                                  uint64_t sector, void *buffer) {
  if (sector >= volume->total_sectors) return XAIOS_ERR_INVALID;
  return block_read(volume->device, sector * volume->sector_size, buffer,
                    volume->sector_size);
}

xaios_status_t fat_write_sector(const xaios_fat_volume_t *volume,
                                   uint64_t sector, const void *buffer) {
  if (sector >= volume->total_sectors) return XAIOS_ERR_INVALID;
  return block_write(volume->device, sector * volume->sector_size, buffer,
                     volume->sector_size);
}

/*
 * Convert one path component to the 11-byte on-disk name: eight of base, three
 * of extension, space padded, fat_upper case. A component that does not fit is
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

/* Thirteen UTF-16 characters per long-name entry, which is what fixes how
   many entries a name of a given length costs. */
#define FAT_LFN_CHARS 13U
#define FAT_LFN_MAX_ENTRIES 20U


/* The checksum a long-name entry carries, computed over the 8.3 alias it
   belongs to. It is what ties the two together: a reader that finds long-name
   entries whose checksum does not match the following 8.3 entry must ignore
   them, because they are the remains of a file some other writer deleted. */

/* Is this character one an 8.3 name may hold? Anything else is dropped from a
   generated alias rather than encoded, which is what every other writer does
   and what keeps the alias a legal short name. */

/* Build the 8.3 alias for a name that does not fit: up to six legal
   characters of the base, then "~N", then up to three of the extension.
   BOOTRISCV64.EFI becomes BOOTRI~1.EFI, which is what mtools writes for it
   and therefore what a volume built by this repository already carries. */

/* Where a cluster's first sector is. Cluster numbering starts at 2: entries 0
   and 1 of the FAT hold the media descriptor and end-of-chain marker, and have
   never addressed data. */
uint64_t fat_cluster_sector(const xaios_fat_volume_t *volume,
                               uint32_t cluster) {
  return volume->data_start_sector +
         ((uint64_t)cluster - 2U) * volume->sectors_per_cluster;
}

xaios_status_t fat_entry_get(const xaios_fat_volume_t *volume,
                                    uint32_t cluster, uint32_t *out_value) {
  if (cluster < 2U || (uint64_t)cluster >= volume->cluster_count + 2U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t offset = (uint64_t)cluster * 2U;
  uint64_t sector = volume->reserved_sectors + offset / volume->sector_size;
  xaios_status_t status = fat_read_sector(volume, sector, g_fat_sector);
  if (status != XAIOS_OK) return status;
  *out_value = fat_get16(&g_fat_sector[offset % volume->sector_size]);
  return XAIOS_OK;
}

/* Written to every copy of the FAT. A volume whose copies disagree is one that
   some implementations will read one way and others another, which is exactly
   the failure that is impossible to diagnose from a machine that will not
   boot. */
xaios_status_t fat_entry_set(const xaios_fat_volume_t *volume,
                                    uint32_t cluster, uint32_t value) {
  if (cluster < 2U || (uint64_t)cluster >= volume->cluster_count + 2U) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t offset = (uint64_t)cluster * 2U;
  for (uint64_t copy = 0U; copy < volume->fat_count; ++copy) {
    uint64_t sector = volume->reserved_sectors +
                      copy * volume->sectors_per_fat +
                      offset / volume->sector_size;
    xaios_status_t status = fat_read_sector(volume, sector, g_fat_sector);
    if (status != XAIOS_OK) return status;
    fat_put16(&g_fat_sector[offset % volume->sector_size], (uint16_t)value);
    status = fat_write_sector(volume, sector, g_fat_sector);
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

xaios_status_t fat_allocate_cluster(const xaios_fat_volume_t *volume,
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
      xaios_status_t status = fat_read_sector(volume, sector, g_fat_sector);
      if (status != XAIOS_OK) return status;
      uint64_t within = ((cluster * 2U) % volume->sector_size) / 2U;
      for (; within < entries_per_sector && cluster < end;
           ++within, ++cluster) {
        if (fat_get16(&g_fat_sector[within * 2U]) != FAT_FREE) continue;
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

xaios_status_t fat_zero_cluster(const xaios_fat_volume_t *volume,
                                   uint32_t cluster) {
  fat_bytes_zero(g_fat_sector, volume->sector_size);
  uint64_t first = fat_cluster_sector(volume, cluster);
  for (uint64_t index = 0U; index < volume->sectors_per_cluster; ++index) {
    xaios_status_t status = fat_write_sector(volume, first + index, g_fat_sector);
    if (status != XAIOS_OK) return status;
  }
  return XAIOS_OK;
}

/* Release a chain. Used when replacing a file: the old contents go back to the
   free list before the new ones are written, so rewriting a file repeatedly
   does not consume the volume. */
xaios_status_t fat_free_chain(const xaios_fat_volume_t *volume,
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


xaios_status_t fat_mount(xaios_block_device_t *device,
                         xaios_fat_volume_t *volume) {
  if (device == 0 || volume == 0) return XAIOS_ERR_INVALID;
  xaios_block_device_info_t info;
  if (block_device_info(device, &info) != XAIOS_OK) return XAIOS_ERR_INVALID;
  if (info.logical_sector_size != FAT_SECTOR_SIZE) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  fat_bytes_zero(volume, sizeof(*volume));
  volume->device = device;
  volume->sector_size = info.logical_sector_size;
  volume->total_sectors = info.capacity_bytes / info.logical_sector_size;
  if (fat_read_sector(volume, 0U, g_fat_sector) != XAIOS_OK) return XAIOS_ERR_IO;
  if (g_fat_sector[510] != 0x55U || g_fat_sector[511] != 0xAAU) {
    return XAIOS_ERR_INVALID;
  }
  if (fat_get16(&g_fat_sector[11]) != FAT_SECTOR_SIZE) return XAIOS_ERR_UNSUPPORTED;
  volume->sectors_per_cluster = g_fat_sector[13];
  volume->reserved_sectors = fat_get16(&g_fat_sector[14]);
  volume->fat_count = g_fat_sector[16];
  volume->root_entry_count = fat_get16(&g_fat_sector[17]);
  volume->sectors_per_fat = fat_get16(&g_fat_sector[22]);
  uint64_t declared = fat_get16(&g_fat_sector[19]);
  if (declared == 0U) declared = fat_get32(&g_fat_sector[32]);
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
  fat_bytes_zero(volume, sizeof(*volume));
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
  fat_bytes_zero(g_fat_sector, volume->sector_size);
  g_fat_sector[0] = 0xEBU;
  g_fat_sector[1] = 0x3CU;
  g_fat_sector[2] = 0x90U;
  static const char oem[] = "XAIOS1.0";
  fat_bytes_copy(&g_fat_sector[3], oem, 8U);
  fat_put16(&g_fat_sector[11], (uint16_t)volume->sector_size);
  g_fat_sector[13] = (uint8_t)volume->sectors_per_cluster;
  fat_put16(&g_fat_sector[14], (uint16_t)volume->reserved_sectors);
  g_fat_sector[16] = (uint8_t)volume->fat_count;
  fat_put16(&g_fat_sector[17], (uint16_t)volume->root_entry_count);
  if (volume->total_sectors < UINT64_C(0x10000)) {
    fat_put16(&g_fat_sector[19], (uint16_t)volume->total_sectors);
  } else {
    fat_put16(&g_fat_sector[19], 0U);
    fat_put32(&g_fat_sector[32], (uint32_t)volume->total_sectors);
  }
  g_fat_sector[21] = 0xF8U; /* fixed disk */
  fat_put16(&g_fat_sector[22], (uint16_t)volume->sectors_per_fat);
  fat_put16(&g_fat_sector[24], 63U);  /* sectors per track, unused but conventional */
  fat_put16(&g_fat_sector[26], 255U); /* heads, likewise */
  g_fat_sector[38] = 0x29U;       /* extended boot signature: label and id follow */
  fat_put32(&g_fat_sector[39], UINT32_C(0x58414F53));
  for (uint64_t index = 0U; index < 11U; ++index) {
    g_fat_sector[43U + index] = ' ';
  }
  if (label != 0) {
    for (uint64_t index = 0U; index < 11U && label[index] != '\0'; ++index) {
      g_fat_sector[43U + index] = (uint8_t)fat_upper(label[index]);
    }
  }
  static const char type[] = "FAT16   ";
  fat_bytes_copy(&g_fat_sector[54], type, 8U);
  g_fat_sector[510] = 0x55U;
  g_fat_sector[511] = 0xAAU;
  xaios_status_t status = fat_write_sector(volume, 0U, g_fat_sector);
  if (status != XAIOS_OK) return status;

  /* Clear both FATs and the root directory. Everything past that is data and
     is unreachable until a FAT entry points at it, so leaving it as it was
     costs nothing and writing it would cost the whole volume's worth of I/O
     on every install. */
  fat_bytes_zero(g_fat_sector, volume->sector_size);
  for (uint64_t sector = volume->reserved_sectors;
       sector < volume->data_start_sector; ++sector) {
    status = fat_write_sector(volume, sector, g_fat_sector);
    if (status != XAIOS_OK) return status;
  }
  /* Entries 0 and 1: the media descriptor, and the end-of-chain marker. */
  status = fat_read_sector(volume, volume->reserved_sectors, g_fat_sector);
  if (status != XAIOS_OK) return status;
  fat_put16(&g_fat_sector[0], 0xFFF8U);
  fat_put16(&g_fat_sector[2], 0xFFFFU);
  for (uint64_t copy = 0U; copy < volume->fat_count; ++copy) {
    status = fat_write_sector(
        volume, volume->reserved_sectors + copy * volume->sectors_per_fat,
        g_fat_sector);
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
      name[index] = (uint8_t)fat_upper(label[index]);
    }
    directory_cursor_t root = {1U, 0U};
    status = fat_write_entry(volume, &root, 0U, name, FAT_ATTR_VOLUME_ID, 0U, 0U);
    if (status != XAIOS_OK) return status;
  }

  (void)block_flush(device);
  return XAIOS_OK;
}
