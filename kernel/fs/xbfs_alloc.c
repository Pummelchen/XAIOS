/*
 * Block and extent allocation for xaibootFS.
 *
 * Split out of xaiboot_fs.c. The block bitmap lives in the volume state there,
 * so this file reaches it through xbfs_block_bitmap(), a pointer good for the
 * duration of the call that asked for it; see xbfs_internal.h. Every function
 * here was static and gains the xbfs_ prefix, and the bodies are unchanged.
 * Nothing here takes the volume lock -- each caller already holds it, exactly
 * as its static predecessor's caller did.
 *
 * extents_from_blocks and extents_to_blocks deliberately stayed in
 * xaiboot_fs.c: the repository's code-scanning contract reads that file as
 * text for the narrowing guard inside extents_to_blocks.
 */

#include "xbfs_internal.h"

/* Whether a block is spoken for, and claiming or releasing one.
   
   Three small functions rather than shifts written out at each use: a bitmap
   indexed wrongly hands out a block that is already in use, and one place to
   be wrong is better than every caller. */
uint32_t xbfs_block_used(uint64_t block) {
  if (block >= xbfs_geometry_data_sectors()) return 1U;
  const uint8_t *bitmap = xbfs_block_bitmap();
  return (bitmap[block >> 3U] &
          (uint8_t)(1U << (block & 7U))) != 0U ? 1U : 0U;
}

static void xbfs_block_claim(uint64_t block) {
  if (block >= xbfs_geometry_data_sectors()) return;
  uint8_t *bitmap = xbfs_block_bitmap();
  bitmap[block >> 3U] |= (uint8_t)(1U << (block & 7U));
}

void xbfs_block_release(uint64_t block) {
  if (block >= xbfs_geometry_data_sectors()) return;
  uint8_t *bitmap = xbfs_block_bitmap();
  bitmap[block >> 3U] &= (uint8_t)~(1U << (block & 7U));
}

/* The bitmap as older versions record it: one byte per block.
   
   In memory it is a bit per block, because a byte would cost two megabytes on
   a v6 volume. On disk that packing is v6's; a v5 volume keeps the encoding it
   was written with, so a machine that mounts one still writes something a v5
   kernel could read. Converting on the way in and out is the price of not
   rewriting other people's disks. */
void xbfs_bitmap_from_bytes(const uint8_t *source, uint64_t blocks) {
  uint8_t *bitmap = xbfs_block_bitmap();
  xbfs_bytes_zero(bitmap, xbfs_block_bitmap_bytes());
  for (uint64_t i = 0U; i < blocks; ++i) {
    if (source[i] != 0U) {
      bitmap[i >> 3U] |= (uint8_t)(1U << (i & 7U));
    }
  }
}

void xbfs_bitmap_to_bytes(uint8_t *destination, uint64_t blocks) {
  const uint8_t *bitmap = xbfs_block_bitmap();
  for (uint64_t i = 0U; i < blocks; ++i) {
    destination[i] = (uint8_t)((bitmap[i >> 3U] &
                                (uint8_t)(1U << (i & 7U))) != 0U ? 1U : 0U);
  }
}

uint64_t xbfs_block_count_used(void) {
  uint64_t count = 0;
  for (uint64_t i = 0; i < xbfs_geometry_data_sectors(); ++i) {
    if (xbfs_block_used(i) != 0U) {
      ++count;
    }
  }
  return count;
}

/* How many blocks a set of extents covers. The size field says how many bytes
   the file holds; this says how much space it occupies, and the two agreeing
   is one of the things fsck checks. */
uint64_t xbfs_extent_blocks(const xaios_xbfs_extent_t *extents,
                              uint32_t count) {
  uint64_t total = 0U;
  for (uint32_t index = 0U; index < count && index < XBFS_V6_MAX_EXTENTS;
       ++index) {
    total += extents[index].length;
  }
  return total;
}

/* The nth block of a file, walking its extents. */
uint64_t xbfs_extent_block_at(const xaios_xbfs_extent_t *extents,
                                uint32_t count, uint64_t index) {
  uint64_t seen = 0U;
  for (uint32_t e = 0U; e < count && e < XBFS_V6_MAX_EXTENTS; ++e) {
    if (index < seen + extents[e].length) {
      return extents[e].start + (index - seen);
    }
    seen += extents[e].length;
  }
  return UINT64_MAX;
}

/* Claim enough blocks for a file, as few runs as possible.
 *
 * Walks the volume taking the first run long enough for what is left. A file
 * that fits in one run costs one extent; a fragmented volume costs several,
 * which is the case extents exist for. Running out of extents before running
 * out of space is a real failure and is reported as one -- a file recorded
 * with only part of its blocks would read as truncated later, which is worse
 * than not being written. */
/* Place a file in at most XBFS_V6_MAX_EXTENTS runs of free blocks.
 *
 * This took the first free runs it found, in address order, and gave up once
 * it had XBFS_V6_MAX_EXTENTS of them. On a fresh volume that is the same as any
 * policy and cheaper than most. On a volume that has been written and
 * rewritten for a while it is the worst available: the low blocks are the most
 * broken up, so first-fit collects that many short runs out of the rubble at the
 * bottom and never reaches the long runs above them. The volume then reports
 * plenty of free space and refuses the write, and because the same path is
 * what snapshots a file, `commit_snapshot` fails on a filesystem `fsck` calls
 * sound -- which halts the machine on its next boot, because the update
 * self-test stages a snapshot and asserts that it worked. See B-52.
 *
 * One scan, which stops early in the case that has always worked and must not
 * get slower: the first run long enough to hold the whole file ends it. That
 * is one extent, it cannot be improved on, and on a mostly empty volume it is
 * the run at block zero -- the same handful of iterations the old code took.
 *
 * The scan also keeps the XBFS_V6_MAX_EXTENTS longest runs as it goes, and
 * those are used only when it reaches the end without finding one that fits,
 * which on a healthy volume does not happen. Filling from the longest first is
 * not merely better than address order, it is the best any policy can do
 * against this constraint: the question is whether some XBFS_V6_MAX_EXTENTS
 * runs can cover the file, and if the longest that many cannot, no such set
 * can. The number was sixteen when this was written and is sixty-four since
 * B-55; the array below is sized by the macro, so it was the prose that went
 * stale and not the code.
 */
xaios_status_t xbfs_allocate_extents(uint64_t blocks_needed,
                                       xaios_xbfs_extent_t *extents,
                                       uint32_t *out_count) {
  *out_count = 0U;
  if (blocks_needed == 0U) return XAIOS_OK;
  if (blocks_needed > xbfs_geometry_data_sectors()) return XAIOS_ERR_INVALID;

  struct free_run {
    uint64_t start;
    uint64_t length;
  };
  struct free_run longest[XBFS_V6_MAX_EXTENTS];
  uint32_t longest_count = 0U;
  uint32_t used = 0U;
  uint64_t remaining = blocks_needed;

  uint64_t block = 0U;
  while (block < xbfs_geometry_data_sectors()) {
    if (xbfs_block_used(block) != 0U) {
      ++block;
      continue;
    }
    uint64_t start = block;
    uint64_t run = 0U;
    while (start + run < xbfs_geometry_data_sectors() &&
           xbfs_block_used(start + run) == 0U) {
      ++run;
      /* Stop measuring once it is long enough. The exact length past that
         point is not used, and on a mostly empty volume the first run is the
         whole volume. */
      if (run >= blocks_needed) break;
    }
    block = start + run;

    if (run >= blocks_needed) {
      extents[0].start = (uint32_t)start;
      extents[0].length = (uint32_t)blocks_needed;
      used = 1U;
      remaining = 0U;
      break;
    }

    /* Keep the XBFS_V6_MAX_EXTENTS longest, longest first. Insertion rather than a sort:
       the array is XBFS_V6_MAX_EXTENTS entries and the scan is the expensive half. */
    uint32_t at = longest_count;
    while (at > 0U && longest[at - 1U].length < run) {
      if (at < XBFS_V6_MAX_EXTENTS) longest[at] = longest[at - 1U];
      --at;
    }
    if (at < XBFS_V6_MAX_EXTENTS) {
      longest[at].start = start;
      longest[at].length = run;
      if (longest_count < XBFS_V6_MAX_EXTENTS) ++longest_count;
    }
  }

  if (remaining != 0U) {
    for (uint32_t i = 0U; i < longest_count && remaining != 0U; ++i) {
      uint64_t take = longest[i].length;
      if (take > remaining) take = remaining;
      extents[used].start = (uint32_t)longest[i].start;
      extents[used].length = (uint32_t)take;
      ++used;
      remaining -= take;
    }
  }

  if (remaining != 0U) {
    *out_count = 0U;
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_NO_MEMORY;
  }

  /* Claimed only once the whole placement is known. The old code claimed as it
     went and released again on failure, so a refused allocation still moved
     both the allocation and the free counter -- the two telemetry numbers a
     reader would use to ask whether this was happening at all. */
  for (uint32_t e = 0U; e < used; ++e) {
    for (uint32_t offset = 0U; offset < extents[e].length; ++offset) {
      xbfs_block_claim((uint64_t)extents[e].start + offset);
      xbfs_stat_bump(XBFS_STAT_ALLOCATION);
    }
  }
  *out_count = used;
  return XAIOS_OK;
}

void xbfs_free_extents(const xaios_xbfs_extent_t *extents, uint32_t count) {
  for (uint32_t e = 0U; e < count && e < XBFS_V6_MAX_EXTENTS; ++e) {
    for (uint32_t offset = 0U; offset < extents[e].length; ++offset) {
      uint64_t block = (uint64_t)extents[e].start + offset;
      if (block < xbfs_geometry_data_sectors() && xbfs_block_used(block) != 0U) {
        xbfs_block_release(block);
        xbfs_stat_bump(XBFS_STAT_FREE);
      }
    }
  }
}

/* Claim more blocks onto the end of a file's list, leaving the ones it already
   has exactly where they are.

   `xbfs_allocate_extents` builds a list from nothing. This adds to a live one, and
   the difference that matters is the first thing it tries: the block
   immediately after the file's current last block. A log grows one block at a
   time, and taking the next block whenever it is free keeps the whole file in
   a single run, so the extent count does not move however long the file gets.
   Only when that block is already taken does this spend an extent, and when
   the format has no extents left it fails rather than truncating the run --
   the caller then writes the file the old way, which is slower and correct.

   Failure restores the list byte for byte and releases every block this call
   claimed, including the ones that merely lengthened the existing tail extent.
   A file left holding blocks that a failed append allocated would leak them;
   one left with a longer tail than its size accounts for would read as
   containing bytes nobody wrote. */
#if XBFS_APPEND_IN_PLACE
xaios_status_t xbfs_extend_extents(xaios_xbfs_extent_t *extents,
                                     uint32_t *extent_count,
                                     uint64_t blocks_needed) {
  if (blocks_needed == 0U) return XAIOS_OK;
  uint32_t original_count = *extent_count;
  uint32_t original_tail_length =
      original_count != 0U ? extents[original_count - 1U].length : 0U;
  uint64_t remaining = blocks_needed;

  while (remaining != 0U) {
    if (*extent_count != 0U) {
      xaios_xbfs_extent_t *tail = &extents[*extent_count - 1U];
      uint64_t next = (uint64_t)tail->start + (uint64_t)tail->length;
      if (next < xbfs_geometry_data_sectors() && xbfs_block_used(next) == 0U) {
        xbfs_block_claim(next);
        xbfs_stat_bump(XBFS_STAT_ALLOCATION);
        tail->length += 1U;
        --remaining;
        continue;
      }
    }
    if (*extent_count >= XBFS_V6_MAX_EXTENTS) break;
    uint64_t block = 0U;
    uint64_t run = 0U;
    while (block < xbfs_geometry_data_sectors() && run == 0U) {
      if (xbfs_block_used(block) != 0U) {
        ++block;
        continue;
      }
      while (block + run < xbfs_geometry_data_sectors() && run < remaining &&
             xbfs_block_used(block + run) == 0U) {
        ++run;
      }
    }
    if (run == 0U) break;
    extents[*extent_count].start = (uint32_t)block;
    extents[*extent_count].length = (uint32_t)run;
    ++(*extent_count);
    for (uint64_t offset = 0U; offset < run; ++offset) {
      xbfs_block_claim(block + offset);
      xbfs_stat_bump(XBFS_STAT_ALLOCATION);
    }
    remaining -= run;
  }

  if (remaining != 0U) {
    for (uint32_t e = original_count; e < *extent_count; ++e) {
      for (uint32_t offset = 0U; offset < extents[e].length; ++offset) {
        xbfs_block_release((uint64_t)extents[e].start + offset);
        xbfs_stat_bump(XBFS_STAT_FREE);
      }
      extents[e].start = 0U;
      extents[e].length = 0U;
    }
    if (original_count != 0U) {
      xaios_xbfs_extent_t *tail = &extents[original_count - 1U];
      for (uint32_t offset = original_tail_length; offset < tail->length;
           ++offset) {
        xbfs_block_release((uint64_t)tail->start + offset);
        xbfs_stat_bump(XBFS_STAT_FREE);
      }
      tail->length = original_tail_length;
    }
    *extent_count = original_count;
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_NO_MEMORY;
  }
  return XAIOS_OK;
}
#endif /* XBFS_APPEND_IN_PLACE */
