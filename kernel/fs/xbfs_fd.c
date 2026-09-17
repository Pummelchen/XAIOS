/*
 * xaibootFS's open-file-descriptor layer, split out of xaiboot_fs.c.
 *
 * The open-file table, the 256 KiB whole-file staging buffer and everything
 * that indexes them live here: the handle lookup, open/read/write/seek/close,
 * and the append-in-place fast path (B-45) that a write goes through when the
 * cursor is at the end of the file.
 *
 * The bodies are unchanged from xaiboot_fs.c. Only the names that cross a
 * translation unit gained an xbfs_ prefix, and the one direct read of the
 * volume's generation became the accessor call declared in xbfs_internal.h.
 * The handle table and the staging buffer are not handed out: the self-test
 * reads a cursor through xbfs_fd_cursor, which returns a value.
 *
 * The append switch's preprocessor guards around the fast path are preserved
 * exactly, so a build that turns the switch off compiles the code it did
 * before.
 */

#include <xaios/klog.h>
#include <xaios/xaiboot_fs.h>

#include "xbfs_internal.h"
#include "xbfs_metadata_internal.h"
#include "xbfs_file_io_internal.h"
#include "xbfs_fd_internal.h"

typedef struct xaios_xbfs_file_handle {
  uint32_t in_use;
  uint32_t flags;
  uint64_t cursor;
  char path[XBFS_PATH_MAX];
} xaios_xbfs_file_handle_t;

static xaios_xbfs_file_handle_t g_open_files[XBFS_MAX_OPEN_FILES];
/* One v5 file's worth, which is the size this path has always staged. The two
   factors are the shared macros; the parent's XBFS_V5_MAX_FILE_BYTES names the
   same expression. */
static uint8_t g_file_buffer[XBFS_V5_FILE_MAX_BLOCKS * XBFS_SECTOR_SIZE];

void xbfs_open_files_forget_tree(const char *root) {
  for (uint32_t i = 0; i < XBFS_MAX_OPEN_FILES; ++i) {
    if (g_open_files[i].in_use != 0 &&
        xbfs_path_is_at_or_below(g_open_files[i].path, root)) {
      g_open_files[i].in_use = 0;
      g_open_files[i].path[0] = '\0';
    }
  }
}

void xbfs_open_files_rebase(const char *old_path, const char *new_path) {
  uint64_t old_len = xbfs_cstr_len(old_path);
  uint64_t new_len = xbfs_cstr_len(new_path);
  for (uint32_t i = 0; i < XBFS_MAX_OPEN_FILES; ++i) {
    if (g_open_files[i].in_use == 0 ||
        !xbfs_path_is_at_or_below(g_open_files[i].path, old_path)) {
      continue;
    }
    char suffix[XBFS_PATH_MAX];
    xbfs_copy_path(suffix, g_open_files[i].path + old_len);
    xbfs_copy_path(g_open_files[i].path, new_path);
    xbfs_bytes_copy(g_open_files[i].path + new_len, suffix,
               xbfs_cstr_len(suffix) + 1U);
  }
}

void xbfs_reset_open_files(void) {
  for (uint32_t i = 0; i < XBFS_MAX_OPEN_FILES; ++i) {
    g_open_files[i].in_use = 0;
    g_open_files[i].flags = 0;
    g_open_files[i].cursor = 0;
    g_open_files[i].path[0] = '\0';
  }
}

static xaios_xbfs_file_handle_t *handle_for_fd(uint32_t fd) {
  if (fd == 0 || fd > XBFS_MAX_OPEN_FILES) {
    return 0;
  }
  xaios_xbfs_file_handle_t *handle = &g_open_files[fd - 1U];
  return handle->in_use != 0 ? handle : 0;
}

int64_t xbfs_fd_open_locked(const char *path, uint32_t flags) {
  char normalized[XBFS_PATH_MAX];
  if (xbfs_normalize_path(path, normalized) != XAIOS_OK ||
      (flags & (XAIOS_XBFS_OPEN_READ | XAIOS_XBFS_OPEN_WRITE)) == 0 ||
      (flags & ~(XAIOS_XBFS_OPEN_READ | XAIOS_XBFS_OPEN_WRITE |
                 XAIOS_XBFS_OPEN_CREATE | XAIOS_XBFS_OPEN_TRUNCATE)) != 0) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return (int64_t)XAIOS_ERR_INVALID;
  }

  xaios_xbfs_node_t *node = xbfs_find_node(normalized, 0);
  if (node == 0 || node->active == 0) {
    if ((flags & XAIOS_XBFS_OPEN_CREATE) == 0) {
      xbfs_stat_bump(XBFS_STAT_REJECT);
      return (int64_t)XAIOS_ERR_NOT_FOUND;
    }
    if ((flags & XAIOS_XBFS_OPEN_WRITE) == 0 || !xbfs_parent_exists_for(normalized)) {
      xbfs_stat_bump(XBFS_STAT_REJECT);
      return (int64_t)XAIOS_ERR_INVALID;
    }
  } else if (node->type != XBFS_NODE_FILE) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return (int64_t)XAIOS_ERR_INVALID;
  }

  if ((flags & XAIOS_XBFS_OPEN_CREATE) != 0 && node == 0) {
    if (xbfs_write_file_locked(normalized, 0, 0) != XAIOS_OK) {
      return (int64_t)XAIOS_ERR_IO;
    }
    node = xbfs_find_node(normalized, 0);
  }
  if ((flags & XAIOS_XBFS_OPEN_TRUNCATE) != 0 && node != 0 &&
      node->active != 0) {
    if (xbfs_write_file_locked(normalized, 0, 0) != XAIOS_OK) {
      return (int64_t)XAIOS_ERR_IO;
    }
  }

  for (uint32_t i = 0; i < XBFS_MAX_OPEN_FILES; ++i) {
    if (g_open_files[i].in_use == 0) {
      g_open_files[i].in_use = 1;
      g_open_files[i].flags = flags;
      g_open_files[i].cursor = 0;
      xbfs_copy_path(g_open_files[i].path, normalized);
      xbfs_stat_bump(XBFS_STAT_OPEN);
      klog("xaibootfs: open fd=%u path=%s flags=0x%x\n", i + 1U,
           normalized, flags);
      return (int64_t)(i + 1U);
    }
  }

  xbfs_stat_bump(XBFS_STAT_REJECT);
  return (int64_t)XAIOS_ERR_NO_MEMORY;
}

int64_t xbfs_fd_read_locked(uint32_t fd, void *buffer, uint64_t size) {
  xaios_xbfs_file_handle_t *handle = handle_for_fd(fd);
  if (handle == 0 || buffer == 0 || size == 0 ||
      (handle->flags & XAIOS_XBFS_OPEN_READ) == 0) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return (int64_t)XAIOS_ERR_INVALID;
  }
  uint64_t file_size = 0;
  xaios_status_t read_status =
      xbfs_read_file(handle->path, g_file_buffer, sizeof(g_file_buffer), &file_size);
  if (read_status != XAIOS_OK) {
    klog("xaibootfs: read-fd failed fd=%u path=%s status=%d\n", fd,
         handle->path, (int)read_status);
    return (int64_t)XAIOS_ERR_IO;
  }
  if (handle->cursor >= file_size) {
    return 0;
  }
  uint64_t available = file_size - handle->cursor;
  uint64_t copy = available < size ? available : size;
  xbfs_bytes_copy(buffer, g_file_buffer + handle->cursor, copy);
  handle->cursor += copy;
  klog("xaibootfs: read-fd fd=%u bytes=%lu cursor=%lu\n", fd, copy,
       handle->cursor);
  return (int64_t)copy;
}

/* Add to the end of a file without rewriting the rest of it. This is B-45.
 *
 * The whole-file path below stages the file in `g_file_buffer`: every append,
 * however small, read the file back, copied it, and wrote all of it out again.
 * `ssh_log` appends about thirty bytes per audit record and sshd emits several
 * per connection, so one SSH connection cost seven whole-file read-modify-
 * writes of the audit log -- and by B-44 sshd's loop is the machine's network
 * thread, so that time is time the guest has no networking at all.
 *
 * What the format allows, and it allows exactly this:
 *
 *   * a node's blocks are a list, not a packing. The blocks a file already has
 *     keep their contents and their positions; making a file longer is adding
 *     to the end of that list, not rebuilding it.
 *   * `content_hash` is FNV-1a, which carries no length and has no
 *     finalisation, so the recorded hash of the first `size` bytes is exactly
 *     the state the byte at `size` folds into. The new hash costs one
 *     multiplication per *appended* byte and none per byte of the file.
 *   * everything written lives at or past the old `size`. Nothing at or past
 *     the old `size` is covered by the old hash, and no reader can reach it.
 *
 * That last point is what makes writing in place here as crash-safe as the
 * copy-on-write path it replaces, and it is worth spelling out because
 * "writes in place" usually means the opposite. Exactly one block is touched
 * that already holds committed bytes -- the partly filled tail block -- and
 * only the bytes in it above `size` are changed. The durability model this
 * filesystem is built for, and the one `qemu-power-loss-gate` actually
 * enforces by replaying a real write journal, is that a write either happened
 * or it did not. Both versions of that tail sector are byte-for-byte identical
 * below `size`, so whichever of them survives a power cut, every byte the
 * committed metadata describes is still there and still hashes to the
 * committed `content_hash`. A crash before the metadata commit loses the
 * record being appended and nothing else -- which is precisely what a crash
 * before the whole-file path's metadata commit loses.
 *
 * The write ordering is the same as well: content out first, then
 * `xbfs_write_metadata`, which carries the only flush. Nothing is published until
 * the metadata naming the new size is durable.
 *
 * It refuses rather than half-working. A cursor that is not at the end, a file
 * that would need more extents than the format has, a volume with no free
 * block: each returns 0 with the node and the bitmap exactly as they were, and
 * the caller writes the file the old way. So the set of writes that succeed is
 * unchanged; only their cost is different.
 *
 * What this gives up, stated rather than buried: the whole-file path re-read
 * the file on every append and so re-verified its content hash on every
 * append. This does not read the file, so a file whose bytes have gone bad is
 * now found at the next read instead of at the next append. Reading a file in
 * order to add to it is the cost this exists to remove, and the check itself
 * is not lost -- `xbfs_read_file` still makes it.
 *
 * Returns 1 when the append was made, 0 when it was not applicable and the
 * caller should fall back, and -1 when the volume failed under it. */
#if XBFS_APPEND_IN_PLACE
static int append_fd_in_place(xaios_xbfs_file_handle_t *handle,
                              const void *buffer, uint64_t size) {
  xaios_xbfs_node_t *node = xbfs_find_node(handle->path, 0);
  if (node == 0 || node->active == 0 || node->type != XBFS_NODE_FILE ||
      size == 0U || handle->cursor != node->size) {
    return 0;
  }

  uint64_t old_size = node->size;
  uint64_t new_size = old_size + size;
  uint64_t old_blocks = xbfs_blocks_for_size(old_size);
  uint64_t new_blocks = xbfs_blocks_for_size(new_size);
  if (new_size > xbfs_geometry_max_file_bytes() ||
      new_blocks > (uint64_t)xbfs_geometry_file_max_blocks()) {
    return 0;
  }
  /* Only a node whose block list matches its size can be reasoned about this
     way. Nothing produces any other shape today; a version that did would take
     the whole-file path rather than have this guess. */
  if (xbfs_extent_blocks(node->extents, node->extent_count) != old_blocks) {
    return 0;
  }

  xaios_xbfs_extent_t extents[XBFS_V6_MAX_EXTENTS];
  uint32_t extent_count = node->extent_count;
  xbfs_bytes_zero(extents, sizeof(extents));
  xbfs_bytes_copy(extents, node->extents, sizeof(extents));
  if (xbfs_extend_extents(extents, &extent_count, new_blocks - old_blocks) !=
      XAIOS_OK) {
    return 0;
  }

  const uint8_t *bytes = (const uint8_t *)buffer;
  uint8_t sector[XBFS_SECTOR_SIZE];
  uint64_t written = 0U;
  uint64_t blocks_touched = 0U;
  int failed = 0;
  while (written < size && failed == 0) {
    uint64_t offset = old_size + written;
    uint64_t index = offset / XBFS_SECTOR_SIZE;
    uint64_t within = offset % XBFS_SECTOR_SIZE;
    uint64_t chunk = XBFS_SECTOR_SIZE - within;
    if (chunk > size - written) chunk = size - written;
    uint64_t block = xbfs_extent_block_at(extents, extent_count, index);
    if (block == UINT64_MAX) {
      failed = 1;
      break;
    }
    /* `within` can only be non-zero on the very first pass, because every
       chunk after the first starts on a block boundary. So this reads at most
       one sector, and only ever the partly filled tail block -- the one whose
       bytes below `within` are committed and have to be written back
       unchanged. A freshly claimed block is written whole, from zero. */
    if (within != 0U) {
      if (xbfs_blk_read(xbfs_absolute_data_sector(block), sector, XBFS_SECTOR_SIZE) !=
          XAIOS_OK) {
        failed = 1;
        break;
      }
    } else {
      xbfs_bytes_zero(sector, sizeof(sector));
    }
    xbfs_bytes_copy(sector + within, bytes + written, chunk);
    if (xbfs_blk_write(xbfs_absolute_data_sector(block), sector, XBFS_SECTOR_SIZE) !=
        XAIOS_OK) {
      failed = 1;
      break;
    }
    written += chunk;
    ++blocks_touched;
  }

  if (failed != 0) {
    /* Nothing is published, so give back only what this call claimed. The
       blocks the file already had are untouched and so is the node. */
    for (uint64_t i = old_blocks; i < new_blocks; ++i) {
      uint64_t block = xbfs_extent_block_at(extents, extent_count, i);
      if (block != UINT64_MAX && xbfs_block_used(block) != 0U) {
        xbfs_block_release(block);
        xbfs_stat_bump(XBFS_STAT_FREE);
      }
    }
    klog("xaibootfs: append block IO failed path=%s added=%lu size=%lu\n",
         handle->path, size, new_size);
    return -1;
  }

  node->size = new_size;
  node->content_hash = xbfs_fnv1a64_extend(node->content_hash, buffer, size);
  node->generation = xbfs_generation_take();
  node->extent_count = extent_count;
  xbfs_bytes_zero(node->extents, sizeof(node->extents));
  xbfs_bytes_copy(node->extents, extents, sizeof(extents));
  /* Counted the way the whole-file path counts it -- once per write of a
     file that spans more than one sector, not once per file that grows into
     one. The telemetry that reads this was written against that meaning. */
  if (new_blocks > 1U) {
    xbfs_stat_bump(XBFS_STAT_MULTI_SECTOR_FILE);
  }
  xbfs_stat_bump(XBFS_STAT_WRITE);
  xbfs_stat_bump(XBFS_STAT_APPEND);
  klog("xaibootfs: append path=%s added=%lu size=%lu touched=%lu blocks=%lu generation=%lu\n",
       node->path, size, node->size, blocks_touched,
       (unsigned long)xbfs_extent_blocks(node->extents, node->extent_count),
       node->generation);
  if (xbfs_write_metadata() != XAIOS_OK) {
    return -1;
  }
  return 1;
}
#endif /* XBFS_APPEND_IN_PLACE */

/* How large a file this path can actually write. Two limits, and the smaller
   one binds.

   xbfs_geometry_max_file_bytes() is what the mounted volume format allows: a
   gibibyte on v6. sizeof(g_file_buffer) is what this path can stage, and it
   is still the v5 figure of 256 KiB. Checking only the first was a kernel
   .bss overflow reachable from userspace -- write past 256 KiB to any file on
   a v6 mutable root and the staging copy ran off the end of a static array
   into whatever the linker had placed after it. v6 raised the format's limit
   without raising the buffer's, and nothing here noticed.

   Refusing is the honest answer until this path streams instead of staging
   whole files. A caller gets XAIOS_ERR_INVALID at 256 KiB, which is where it
   got one before v6 and what the documentation has always said. */
uint64_t xbfs_write_limit(void) {
  uint64_t staging = (uint64_t)sizeof(g_file_buffer);
  return xbfs_geometry_max_file_bytes() < staging ? xbfs_geometry_max_file_bytes() : staging;
}

int64_t xbfs_fd_write_locked(uint32_t fd, const void *buffer, uint64_t size) {
  xaios_xbfs_file_handle_t *handle = handle_for_fd(fd);
  uint64_t limit = xbfs_write_limit();
  if (handle == 0 || buffer == 0 || size == 0 ||
      (handle->flags & XAIOS_XBFS_OPEN_WRITE) == 0 ||
      handle->cursor > limit || size > limit - handle->cursor) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return (int64_t)XAIOS_ERR_INVALID;
  }

#if XBFS_APPEND_IN_PLACE
  /* The common case, and the only one that was expensive: the cursor is at the
     end of the file and the write only makes it longer. Everything else falls
     through to the whole-file path below, unchanged. */
  int appended = append_fd_in_place(handle, buffer, size);
  if (appended < 0) {
    return (int64_t)XAIOS_ERR_IO;
  }
  if (appended > 0) {
    handle->cursor += size;
    klog("xaibootfs: write-fd fd=%u bytes=%lu cursor=%lu\n", fd, size,
         handle->cursor);
    return (int64_t)size;
  }
  xbfs_stat_bump(XBFS_STAT_APPEND_FALLBACK);
#endif

  uint64_t file_size = 0;
  if (xbfs_find_node(handle->path, 0) != 0) {
    if (xbfs_read_file(handle->path, g_file_buffer, sizeof(g_file_buffer), &file_size) !=
        XAIOS_OK) {
      return (int64_t)XAIOS_ERR_IO;
    }
  }
  uint64_t new_size = handle->cursor + size;
  if (new_size < file_size) {
    new_size = file_size;
  }
  /* Only a cursor seeked past the end leaves a hole, and only that hole has to
     read back as zeros. Everything below file_size was just read back, and
     everything from the cursor on is about to be overwritten, so clearing the
     whole buffer meant a 256 KiB memset for every append -- the audit log paid
     roughly 21 MiB of it to write 3 KiB of lines. Nothing above new_size is
     written out, so stale bytes there cannot reach the volume. */
  if (handle->cursor > file_size) {
    xbfs_bytes_zero(g_file_buffer + file_size, handle->cursor - file_size);
  }
  xbfs_bytes_copy(g_file_buffer + handle->cursor, buffer, size);
  if (xbfs_write_file_locked(handle->path, g_file_buffer, new_size) != XAIOS_OK) {
    return (int64_t)XAIOS_ERR_IO;
  }
  handle->cursor += size;
  klog("xaibootfs: write-fd fd=%u bytes=%lu cursor=%lu\n", fd, size,
       handle->cursor);
  return (int64_t)size;
}

xaios_status_t xbfs_fd_seek_locked(uint32_t fd, uint64_t offset) {
  xaios_xbfs_file_handle_t *handle = handle_for_fd(fd);
  if (handle == 0 || offset > xbfs_geometry_max_file_bytes()) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }
  handle->cursor = offset;
  return XAIOS_OK;
}

xaios_status_t xbfs_fd_close_locked(uint32_t fd) {
  xaios_xbfs_file_handle_t *handle = handle_for_fd(fd);
  if (handle == 0) {
    xbfs_stat_bump(XBFS_STAT_REJECT);
    return XAIOS_ERR_INVALID;
  }
  klog("xaibootfs: close fd=%u path=%s\n", fd, handle->path);
  handle->in_use = 0;
  handle->flags = 0;
  handle->cursor = 0;
  handle->path[0] = '\0';
  xbfs_stat_bump(XBFS_STAT_CLOSE);
  return XAIOS_OK;
}

/* sizeof the staging buffer, as a value rather than a pointer to it. */
uint64_t xbfs_file_staging_bytes(void) {
  return (uint64_t)sizeof(g_file_buffer);
}

/* The cursor of an open descriptor, or 0 when `fd` is not open. A value: the
   handle table stays private to this translation unit, so a caller that only
   needs to observe the cursor does not get to hold a pointer into it. */
uint64_t xbfs_fd_cursor(uint32_t fd) {
  const xaios_xbfs_file_handle_t *handle = handle_for_fd(fd);
  return handle != 0 ? handle->cursor : 0U;
}
