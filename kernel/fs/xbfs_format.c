/*
 * The on-disk format of xaibootFS: the metadata codec (read one of the two
 * A/B slots and choose the newer intact one, and write the region back),
 * structural validation, formatting, and the v2..v4 to v5 migration.
 *
 * Split out of xaiboot_fs.c. The volume state g_xbfs stays there and is
 * reached through the scalar header accessors below and the existing
 * call-scoped bitmap/node accessors in xbfs_internal.h. read_metadata_slot
 * and metadata_slot_probe stay static here. Every entry point runs with the
 * volume lock held, exactly as the static functions it replaces did.
 *
 * extents_from_blocks and extents_to_blocks deliberately stay in
 * xaiboot_fs.c: the repository's code-scanning contract reads that file as
 * text for the narrowing guard inside extents_to_blocks. The
 * XBFS_*_METADATA_SECTORS defines stay there for a second gate that reads
 * them the same way.
 */

#include <xaios/klog.h>

#include "xbfs_format_internal.h"
#include "xbfs_internal.h"
#include "xbfs_metadata_internal.h"
#include "xbfs_volume_internal.h"

static xaios_status_t read_metadata_slot(uint32_t slot) {
  uint8_t first_sector[XBFS_SECTOR_SIZE];
  uint64_t start = xbfs_metadata_slot_start_sector(slot);
  if (xbfs_blk_read(start, first_sector, sizeof(first_sector)) != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  uint32_t version = 0;
  xbfs_bytes_copy(&version, first_sector + XBFS_MAGIC_LEN, sizeof(version));
  if (version == XBFS_V6_VERSION) {
    xbfs_geometry_select(XBFS_V6_VERSION);
  } else if (version == XBFS_V5_VERSION) {
    xbfs_geometry_select(XBFS_V5_VERSION);
  } else if (version == XBFS_V4_VERSION) {
    xbfs_geometry_select(XBFS_V4_VERSION);
  } else if (version == XBFS_V3_VERSION) {
    xbfs_geometry_select(XBFS_V3_VERSION);
  } else {
    xbfs_geometry_select(XBFS_VERSION);
  }
  xbfs_geometry_t geometry;
  xbfs_geometry_get(&geometry);

  uint32_t sectors = geometry.metadata_sectors;
  uint8_t *metadata = xbfs_metadata_buffer();
  xbfs_bytes_zero(metadata, xbfs_metadata_buffer_bytes());
  xbfs_bytes_copy(metadata, first_sector, XBFS_SECTOR_SIZE);
  for (uint32_t i = 1; i < sectors; ++i) {
    if (xbfs_blk_read(start + i,
                 metadata + i * XBFS_SECTOR_SIZE,
                 XBFS_SECTOR_SIZE) != XAIOS_OK) {
      return XAIOS_ERR_IO;
    }
  }
  uint64_t sequence = 0U;
  xbfs_bytes_copy(&sequence,
             metadata + xbfs_metadata_sequence_offset(), 8);
  xbfs_metadata_set_sequence(sequence);
  uint64_t total_bytes = (uint64_t)sectors * XBFS_SECTOR_SIZE;
  xbfs_metadata_set_verified_checksum(
      xbfs_mfs_checksum(metadata, total_bytes));
  xbfs_volume_state_reset();
  xbfs_volume_header_t header;
  uint64_t p = 0;
  xbfs_bytes_copy(header.magic, metadata + p, XBFS_MAGIC_LEN); p += XBFS_MAGIC_LEN;
  xbfs_bytes_copy(&header.version, metadata + p, 4); p += 4;
  xbfs_bytes_copy(&header.sector_size, metadata + p, 4); p += 4;
  xbfs_bytes_copy(&header.metadata_sectors, metadata + p, 4); p += 4;
  xbfs_bytes_copy(&header.max_nodes, metadata + p, 4); p += 4;
  xbfs_bytes_copy(&header.start_sector, metadata + p, 8); p += 8;
  xbfs_bytes_copy(&header.journal_header_sector, metadata + p, 8); p += 8;
  xbfs_bytes_copy(&header.journal_data_sector, metadata + p, 8); p += 8;
  xbfs_bytes_copy(&header.data_start_sector, metadata + p, 8); p += 8;
  xbfs_bytes_copy(&header.data_sectors, metadata + p, 8); p += 8;
  xbfs_bytes_copy(&header.generation, metadata + p, 8); p += 8;
  xbfs_bytes_copy(&header.committed_generation, metadata + p, 8); p += 8;
  xbfs_bytes_copy(&header.checksum, metadata + p, 8); p += 8;
  xbfs_volume_header_set(&header);
  if (version == XBFS_V6_VERSION) {
    xbfs_bytes_copy(xbfs_block_bitmap(), metadata + p,
               (geometry.data_sectors + 7U) / 8U);
    p += (geometry.data_sectors + 7U) / 8U;
  } else {
    xbfs_bitmap_from_bytes(metadata + p, geometry.data_sectors);
    p += geometry.data_sectors;
  }
  if (version == XBFS_V6_VERSION) {
    for (uint32_t i = 0; i < geometry.max_nodes; ++i) {
      xbfs_bytes_copy(xbfs_node_row(i), metadata + p,
                 sizeof(xaios_xbfs_node_t));
      p += sizeof(xaios_xbfs_node_t);
    }
  } else if (version == XBFS_V5_VERSION) {
    for (uint32_t i = 0; i < geometry.max_nodes; ++i) {
      xaios_xbfs_node_v5_t legacy;
      xbfs_bytes_copy(&legacy, metadata + p, sizeof(legacy));
      p += sizeof(legacy);
      import_v5_node(xbfs_node_row(i), &legacy);
    }
  } else if (version == XBFS_V4_VERSION) {
    for (uint32_t i = 0; i < geometry.max_nodes; ++i) {
      xaios_xbfs_node_v4_t legacy;
      xbfs_bytes_copy(&legacy, metadata + p, sizeof(legacy));
      p += sizeof(legacy);
      import_v4_node(xbfs_node_row(i), &legacy);
    }
  } else {
    for (uint32_t i = 0; i < geometry.max_nodes; ++i) {
      xaios_xbfs_node_v3_t legacy;
      xbfs_bytes_copy(&legacy, metadata + p, sizeof(legacy));
      p += sizeof(legacy);
      import_legacy_node(xbfs_node_row(i), &legacy);
    }
  }
  if (p > total_bytes) {
    return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
}

/* A slot is usable when it parses and its stored checksum matches what its
   own bytes hash to. Structural validation stays with the caller, which
   applies it to whichever slot wins. */
static int metadata_slot_probe(uint32_t slot, uint64_t *out_sequence) {
  if (read_metadata_slot(slot) != XAIOS_OK) return 0;
  xbfs_volume_header_t header;
  xbfs_volume_header_get(&header);
  if (header.checksum != xbfs_metadata_verified_checksum()) return 0;
  if (!xbfs_bytes_eq(header.magic, XBFS_MAGIC, XBFS_MAGIC_LEN)) return 0;
  *out_sequence = xbfs_metadata_sequence();
  return 1;
}

/* Load the newer of the two copies that is intact. */
xaios_status_t xbfs_volume_read_metadata(void) {
  uint64_t sequence[XBFS_METADATA_SLOTS] = {0U, 0U};
  int usable[XBFS_METADATA_SLOTS] = {0, 0};
  uint32_t chosen;
  usable[0] = metadata_slot_probe(0U, &sequence[0]);
  if (xbfs_metadata_mirror_enabled() != 0U) {
    if (usable[0] != 0) {
      /* The primary read, so the geometry it declares is the volume's, and
         the mirror is where that geometry says. v5 and v6 both keep one, and
         both must be probed: checking only for v5 meant a v6 volume never
         looked at its second copy, and since writes alternate slots the
         reader took the older one every time -- one file short after a
         remount, with fsck reporting no errors, because nothing was wrong
         with what it read. It was simply the wrong copy. */
      if (xbfs_geometry_version() == XBFS_V5_VERSION ||
          xbfs_geometry_version() == XBFS_V6_VERSION) {
        usable[1] = metadata_slot_probe(1U, &sequence[1]);
      }
    } else {
      /* A torn primary is the case the mirror exists for, and it is exactly
         the case where the volume cannot say what shape it is: the version
         lives in the copy that is unreadable. The mirror sits immediately
         after the data region, so its sector follows from the format --
         sector 12546 on v5, 2102786 on v6 -- and guessing wrong reads an
         ordinary data block and concludes the volume has no second copy.

         This used to assume v5, which was true when v5 was the only format
         with a mirror and silently wrong afterwards: a v6 volume with a torn
         primary was refused while intact, about half the time a power cut
         landed on the wrong slot, because writes alternate.

         So each layout the device is large enough to hold is tried, largest
         first. Trying rather than deducing is deliberate -- a probe verifies
         a checksum over the region it read, so a layout that is not there
         fails to probe rather than being mistaken for one that is. */
      static const uint32_t k_mirror_layouts[] = {XBFS_V6_VERSION,
                                                  XBFS_V5_VERSION};
      uint64_t capacity = xbfs_blk_capacity();
      for (uint32_t i = 0U;
           i < sizeof(k_mirror_layouts) / sizeof(k_mirror_layouts[0]); ++i) {
        if (k_mirror_layouts[i] == XBFS_V6_VERSION) {
          xbfs_geometry_select(XBFS_V6_VERSION);
        } else {
          xbfs_geometry_select(XBFS_V5_VERSION);
        }
        if (capacity <
            xbfs_metadata_mirror_start_sector() + xbfs_geometry_metadata_sectors()) {
          continue; /* the device is too small to hold this layout's mirror */
        }
        usable[1] = metadata_slot_probe(1U, &sequence[1]);
        if (usable[1] != 0) break;
      }
    }
  }
  if (usable[0] == 0 && usable[1] == 0) {
    /* Neither copy is intact. Reload the primary so the caller sees the
       original bytes and can apply its own blank-versus-damaged judgement. */
    xbfs_metadata_shadow_set_valid(0U, 0U);
    xbfs_metadata_shadow_set_valid(1U, 0U);
    xbfs_metadata_set_slot(0U);
    return read_metadata_slot(0U);
  }
  if (usable[0] != 0 && usable[1] != 0) {
    chosen = sequence[1] > sequence[0] ? 1U : 0U;
  } else {
    chosen = usable[0] != 0 ? 0U : 1U;
  }
  if (usable[chosen ^ 1U] == 0) {
    xbfs_metadata_note_mirror_recovery();
    klog("xaibootfs: metadata slot %u unusable; continuing from slot %u seq=%lu\n",
         (unsigned)(chosen ^ 1U), (unsigned)chosen, sequence[chosen]);
  }
  xbfs_metadata_shadow_set_valid(0U, 0U);
  xbfs_metadata_shadow_set_valid(1U, 0U);
  xbfs_metadata_set_slot(chosen);
  return read_metadata_slot(chosen);
}

xaios_status_t xbfs_write_metadata(void) {
  xbfs_volume_header_t header;
  xbfs_volume_header_get(&header);
  uint8_t *metadata = xbfs_metadata_buffer();
  xbfs_bytes_zero(metadata, xbfs_metadata_buffer_bytes());
  uint64_t p = 0;
  xbfs_bytes_copy(metadata + p, header.magic, XBFS_MAGIC_LEN); p += XBFS_MAGIC_LEN;
  xbfs_bytes_copy(metadata + p, &header.version, 4); p += 4;
  xbfs_bytes_copy(metadata + p, &header.sector_size, 4); p += 4;
  xbfs_bytes_copy(metadata + p, &header.metadata_sectors, 4); p += 4;
  xbfs_bytes_copy(metadata + p, &header.max_nodes, 4); p += 4;
  xbfs_bytes_copy(metadata + p, &header.start_sector, 8); p += 8;
  xbfs_bytes_copy(metadata + p, &header.journal_header_sector, 8); p += 8;
  xbfs_bytes_copy(metadata + p, &header.journal_data_sector, 8); p += 8;
  xbfs_bytes_copy(metadata + p, &header.data_start_sector, 8); p += 8;
  xbfs_bytes_copy(metadata + p, &header.data_sectors, 8); p += 8;
  xbfs_bytes_copy(metadata + p, &header.generation, 8); p += 8;
  xbfs_bytes_copy(metadata + p, &header.committed_generation, 8); p += 8;
  uint64_t checksum_offset = p;
  uint64_t zero_cksum = 0;
  xbfs_bytes_copy(metadata + p, &zero_cksum, 8); p += 8;
  if (xbfs_geometry_version() == XBFS_V6_VERSION) {
    xbfs_bytes_copy(metadata + p, xbfs_block_bitmap(),
               (xbfs_geometry_data_sectors() + 7U) / 8U);
    p += (xbfs_geometry_data_sectors() + 7U) / 8U;
  } else {
    xbfs_bitmap_to_bytes(metadata + p, xbfs_geometry_data_sectors());
    p += xbfs_geometry_data_sectors();
  }
  if (xbfs_geometry_version() == XBFS_V6_VERSION) {
    for (uint32_t i = 0; i < xbfs_geometry_max_nodes(); ++i) {
      xbfs_bytes_copy(metadata + p, xbfs_node_row(i),
                 sizeof(xaios_xbfs_node_t));
      p += sizeof(xaios_xbfs_node_t);
    }
  } else if (xbfs_geometry_version() == XBFS_V5_VERSION) {
    for (uint32_t i = 0; i < xbfs_geometry_max_nodes(); ++i) {
      xaios_xbfs_node_v5_t legacy;
      export_v5_node(&legacy, xbfs_node_row(i));
      xbfs_bytes_copy(metadata + p, &legacy, sizeof(legacy));
      p += sizeof(legacy);
    }
  } else if (xbfs_geometry_version() == XBFS_V4_VERSION) {
    for (uint32_t i = 0; i < xbfs_geometry_max_nodes(); ++i) {
      xaios_xbfs_node_v4_t legacy;
      export_v4_node(&legacy, xbfs_node_row(i));
      xbfs_bytes_copy(metadata + p, &legacy, sizeof(legacy));
      p += sizeof(legacy);
    }
  } else {
    for (uint32_t i = 0; i < xbfs_geometry_max_nodes(); ++i) {
      xaios_xbfs_node_v3_t legacy;
      export_legacy_node(&legacy, xbfs_node_row(i));
      xbfs_bytes_copy(metadata + p, &legacy, sizeof(legacy));
      p += sizeof(legacy);
    }
  }
  uint64_t total_bytes = (uint64_t)xbfs_geometry_metadata_sectors() * XBFS_SECTOR_SIZE;
  if (p > total_bytes) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_NO_MEMORY;
  }
  /* Stamp the write sequence before hashing so the checksum covers it; a
     tear that damages the sequence therefore invalidates the copy too. */
  uint64_t next_sequence = xbfs_metadata_sequence() + 1U;
  xbfs_bytes_copy(metadata + xbfs_metadata_sequence_offset(), &next_sequence, 8);
  header.checksum = xbfs_mfs_checksum(metadata, total_bytes);
  xbfs_volume_header_set(&header);
  xbfs_bytes_copy(metadata + checksum_offset, &header.checksum, 8);
  /* Alternate slots so the copy being overwritten is never the one mount
     would currently choose. Without a mirror this degrades to the previous
     in-place behaviour. */
  uint32_t target = xbfs_metadata_mirror_enabled() != 0U ? (xbfs_metadata_slot() ^ 1U)
                                                    : xbfs_metadata_slot();
  uint64_t start = xbfs_metadata_slot_start_sector(target);
  uint8_t sector[XBFS_SECTOR_SIZE];
  /* Only the sectors that differ from what this slot already holds. When the
     shadow is not trusted -- first commit to the slot since mount, or anything
     that failed part-way through -- every sector is written, which is what the
     code always did. */
  uint32_t known = xbfs_metadata_shadow_valid(target);
  uint64_t moved = 0U;
  for (uint32_t i = 0; i < xbfs_geometry_metadata_sectors(); ++i) {
    const uint8_t *source = metadata + (uint64_t)i * XBFS_SECTOR_SIZE;
    if (known != 0U &&
        xbfs_bytes_eq(source, xbfs_metadata_shadow(target) +
                             (uint64_t)i * XBFS_SECTOR_SIZE,
                 XBFS_SECTOR_SIZE) != 0) {
      continue;
    }
    xbfs_bytes_copy(sector, source, XBFS_SECTOR_SIZE);
    if (xbfs_blk_write(start + i, sector, sizeof(sector)) != XAIOS_OK) {
      klog("xaibootfs: metadata write failed sector=%lu capacity=%lu\n",
           start + i, xbfs_blk_capacity());
      xbfs_stat_bump(XBFS_STAT_REJECT);
      /* Part of the slot is new and part is old, and which is which is no
         longer known. Say so, so the next commit writes it whole. */
      xbfs_metadata_shadow_set_valid(target, 0U);
      return XAIOS_ERR_IO;
    }
    ++moved;
  }
  xaios_status_t flushed = xbfs_blk_flush();
  if (flushed != XAIOS_OK) {
    xbfs_metadata_shadow_set_valid(target, 0U);
    return flushed;
  }
  /* Durable now, so the shadow can be believed. */
  xbfs_bytes_copy(xbfs_metadata_shadow(target), metadata,
             (uint64_t)xbfs_geometry_metadata_sectors() * XBFS_SECTOR_SIZE);
  xbfs_metadata_shadow_set_valid(target, 1U);
  (void)moved;
  /* Only once the new copy is durable does it become the one to read, and
     the other becomes the next target. */
  xbfs_metadata_set_slot(target);
  xbfs_metadata_set_sequence(next_sequence);
  return XAIOS_OK;
}




xaios_status_t xbfs_volume_validate(uint64_t expected_checksum) {
  xbfs_geometry_t geometry;
  xbfs_geometry_get(&geometry);
  xbfs_volume_header_t header;
  xbfs_volume_header_get(&header);
  if (!xbfs_bytes_eq(header.magic, XBFS_MAGIC, XBFS_MAGIC_LEN) ||
      header.version != geometry.version ||
      header.sector_size != XBFS_SECTOR_SIZE ||
      header.metadata_sectors != geometry.metadata_sectors ||
      header.max_nodes != geometry.max_nodes ||
      header.start_sector != XBFS_START_SECTOR ||
      header.journal_header_sector != xbfs_journal_header_sector() ||
      header.journal_data_sector != xbfs_journal_data_sector() ||
      header.data_start_sector != xbfs_data_start_sector() ||
      header.data_sectors != geometry.data_sectors) {
    return XAIOS_ERR_INVALID;
  }
  if (header.checksum != expected_checksum) {
    xbfs_stat_bump(XBFS_STAT_CHECKSUM_ERROR);
    return XAIOS_ERR_INVALID;
  }
  for (uint32_t i = 0; i < geometry.max_nodes; ++i) {
    xaios_xbfs_node_t *node = xbfs_node_row(i);
    if ((node->active != 0 || node->snapshot_active != 0) &&
        xbfs_validate_path(node->path) != XAIOS_OK) {
      return XAIOS_ERR_INVALID;
    }
    if (node->active != 0 &&
        node->type != XBFS_NODE_DIR && node->type != XBFS_NODE_FILE) {
      return XAIOS_ERR_INVALID;
    }
    if (node->snapshot_active != 0 &&
        node->snapshot_type != XBFS_NODE_DIR &&
        node->snapshot_type != XBFS_NODE_FILE) {
      return XAIOS_ERR_INVALID;
    }
    if (xbfs_extent_blocks(node->extents, node->extent_count) >
            geometry.file_max_blocks ||
        xbfs_extent_blocks(node->snapshot_extents, node->snapshot_extent_count) >
            geometry.file_max_blocks ||
        node->extent_count > XBFS_V6_MAX_EXTENTS ||
        node->snapshot_extent_count > XBFS_V6_MAX_EXTENTS ||
        node->size > geometry.max_file_bytes ||
        node->snapshot_size > geometry.max_file_bytes) {
      return XAIOS_ERR_INVALID;
    }
  }
  return XAIOS_OK;
}

xaios_status_t xbfs_volume_format(void) {
  xbfs_geometry_t geometry;
  xbfs_geometry_get(&geometry);
  xbfs_volume_state_reset();
  xbfs_volume_header_t header;
  xbfs_bytes_zero(&header, sizeof(header));
  xbfs_bytes_copy(header.magic, XBFS_MAGIC, XBFS_MAGIC_LEN);
  header.version = geometry.version;
  header.sector_size = (uint32_t)XBFS_SECTOR_SIZE;
  header.metadata_sectors = geometry.metadata_sectors;
  header.max_nodes = geometry.max_nodes;
  header.start_sector = XBFS_START_SECTOR;
  header.journal_header_sector = xbfs_journal_header_sector();
  header.journal_data_sector = xbfs_journal_data_sector();
  header.data_start_sector = xbfs_data_start_sector();
  header.data_sectors = geometry.data_sectors;
  header.generation = 1;
  header.committed_generation = 0;
  xbfs_volume_header_set(&header);
  xbfs_stat_bump(XBFS_STAT_FORMAT);
  xbfs_metadata_set_sequence(0U);
  xbfs_metadata_shadow_set_valid(0U, 0U);
  xbfs_metadata_shadow_set_valid(1U, 0U);
  xbfs_metadata_set_slot(0U);
  if (xbfs_clear_journal() != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  /* Fill both copies at format time. Writing only one would leave a fresh
     volume with a single valid copy until its second metadata write, which
     is exactly the window this is meant to remove. The two writes alternate
     slots, so both end up holding a complete, self-consistent image. */
  if (xbfs_write_metadata() != XAIOS_OK) return XAIOS_ERR_IO;
  if (xbfs_metadata_mirror_enabled() == 0U) return XAIOS_OK;
  return xbfs_write_metadata();
}

xaios_status_t xbfs_volume_migrate_to_v5(void) {
  if (xbfs_geometry_version() == XBFS_V5_VERSION) {
    return XAIOS_OK;
  }
  /* v6 is newer, not older. This exists to bring a v2, v3 or v4 volume
     forward, and running it on a v6 volume rewrites its superblock as v5 and
     loses everything past v5's limits -- which is what it did, silently,
     until the version was checked here rather than only against v5. */
  if (xbfs_geometry_version() == XBFS_V6_VERSION) {
    return XAIOS_OK;
  }
  uint32_t old_version = xbfs_geometry_version();
  xbfs_volume_header_t header;
  xbfs_volume_header_get(&header);
  uint64_t old_data_start = header.data_start_sector;
  uint64_t new_data_start = XBFS_START_SECTOR + XBFS_V5_METADATA_SECTORS +
                            XBFS_JOURNAL_SECTORS;
  uint8_t sector[XBFS_SECTOR_SIZE];
  for (uint32_t remaining = xbfs_geometry_data_sectors(); remaining != 0U;
       --remaining) {
    uint32_t i = remaining - 1U;
    if (xbfs_block_used(i) == 0U) {
      continue;
    }
    if (xbfs_blk_read(old_data_start + i, sector, sizeof(sector)) != XAIOS_OK ||
        xbfs_blk_write(new_data_start + i, sector, sizeof(sector)) != XAIOS_OK) {
      xbfs_stat_bump(XBFS_STAT_REJECT);
      return XAIOS_ERR_IO;
    }
  }
  if (xbfs_blk_flush() != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  xbfs_geometry_select(XBFS_V5_VERSION);
  header.version = XBFS_V5_VERSION;
  header.metadata_sectors = XBFS_V5_METADATA_SECTORS;
  header.max_nodes = XBFS_V5_MAX_NODES;
  header.journal_header_sector = xbfs_journal_header_sector();
  header.journal_data_sector = xbfs_journal_data_sector();
  header.data_start_sector = xbfs_data_start_sector();
  header.data_sectors = XBFS_V5_DATA_SECTORS;
  ++header.generation;
  xbfs_volume_header_set(&header);
  if (xbfs_clear_journal() != XAIOS_OK || xbfs_write_metadata() != XAIOS_OK) {
    return XAIOS_ERR_IO;
  }
  klog("xaibootfs: migrated v%u to v5 nodes=%u sectors=%u\n", old_version,
       xbfs_geometry_max_nodes(), xbfs_geometry_data_sectors());
  return XAIOS_OK;
}
