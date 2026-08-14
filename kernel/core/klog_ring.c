#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/klog_ring.h>
#include <xaios/mutable_fs.h>
#include <xaios/spinlock.h>
#include <xaios/timer.h>

#define KLOG_PATH "/var/log/kern.log"
#define KLOG_ROTATED_PATH "/var/log/kern.log.1"

typedef struct xaios_klog_ring {
  char buffer[XAIOS_KLOG_RING_SIZE];
  uint32_t write_pos;
  uint32_t read_pos;
  uint32_t count;
  uint32_t overflow;
  uint64_t total_written;
  xaios_spinlock_t lock;
} xaios_klog_ring_t;

static xaios_klog_ring_t g_ring;
static uint32_t g_ring_initialized;
static uint64_t g_persist_count;
static uint64_t g_rotate_count;

void klog_ring_init(void) {
  xaios_spin_init(&g_ring.lock);
  for (uint32_t i = 0; i < XAIOS_KLOG_RING_SIZE; ++i) {
    g_ring.buffer[i] = 0;
  }
  g_ring.write_pos = 0;
  g_ring.read_pos = 0;
  g_ring.count = 0;
  g_ring.overflow = 0;
  g_ring.total_written = 0;
  g_persist_count = 0;
  g_rotate_count = 0;

  /* Ensure the persistent log path exists before enabling the ring. */
  if (mutable_fs_mkdir("/var") != XAIOS_OK ||
      mutable_fs_mkdir("/var/log") != XAIOS_OK) {
    g_ring_initialized = 0;
    klog("klog_ring: initialization failed; persistent path unavailable\n");
    return;
  }

  g_ring_initialized = 1;
  klog("klog_ring: initialized size=%u\n", XAIOS_KLOG_RING_SIZE);
}

void klog_ring_write(const char *data, uint32_t length) {
  if (g_ring_initialized == 0 || data == 0 || length == 0) {
    return;
  }

  xaios_spin_lock(&g_ring.lock);
  for (uint32_t i = 0; i < length; ++i) {
    if (g_ring.count >= XAIOS_KLOG_RING_SIZE) {
      /* Buffer full: drop oldest byte */
      g_ring.read_pos = (g_ring.read_pos + 1U) % XAIOS_KLOG_RING_SIZE;
      --g_ring.count;
      ++g_ring.overflow;
    }
    g_ring.buffer[g_ring.write_pos] = data[i];
    g_ring.write_pos = (g_ring.write_pos + 1U) % XAIOS_KLOG_RING_SIZE;
    ++g_ring.count;
    ++g_ring.total_written;
  }
  xaios_spin_unlock(&g_ring.lock);
}

uint32_t klog_ring_read(char *out, uint32_t max_len) {
  if (g_ring_initialized == 0 || out == 0 || max_len == 0) {
    return 0;
  }

  xaios_spin_lock(&g_ring.lock);
  uint32_t to_read = g_ring.count < max_len ? g_ring.count : max_len;
  for (uint32_t i = 0; i < to_read; ++i) {
    out[i] = g_ring.buffer[g_ring.read_pos];
    g_ring.read_pos = (g_ring.read_pos + 1U) % XAIOS_KLOG_RING_SIZE;
  }
  g_ring.count -= to_read;
  xaios_spin_unlock(&g_ring.lock);
  return to_read;
}

uint32_t klog_ring_snapshot(char *out, uint32_t max_len,
                            uint64_t since_cursor, uint64_t *start_cursor,
                            uint64_t *next_cursor, uint64_t *latest_cursor) {
  if (g_ring_initialized == 0 || out == 0 || max_len == 0 ||
      start_cursor == 0 || next_cursor == 0 || latest_cursor == 0) {
    return 0;
  }

  xaios_spin_lock(&g_ring.lock);
  uint64_t oldest = g_ring.total_written - g_ring.count;
  uint64_t start = since_cursor < oldest ? oldest : since_cursor;
  if (start > g_ring.total_written) {
    start = g_ring.total_written;
  }
  uint64_t available = g_ring.total_written - start;
  uint32_t copied = available < max_len ? (uint32_t)available : max_len;
  uint32_t offset = (uint32_t)(start - oldest);
  uint32_t position = (g_ring.read_pos + offset) % XAIOS_KLOG_RING_SIZE;
  for (uint32_t i = 0; i < copied; ++i) {
    out[i] = g_ring.buffer[position];
    position = (position + 1U) % XAIOS_KLOG_RING_SIZE;
  }
  *start_cursor = start;
  *next_cursor = start + copied;
  *latest_cursor = g_ring.total_written;
  xaios_spin_unlock(&g_ring.lock);
  return copied;
}

void klog_ring_clear(void) {
  if (g_ring_initialized == 0) {
    return;
  }
  xaios_spin_lock(&g_ring.lock);
  g_ring.write_pos = 0;
  g_ring.read_pos = 0;
  g_ring.count = 0;
  xaios_spin_unlock(&g_ring.lock);
}

uint32_t klog_ring_count(void) {
  if (g_ring_initialized == 0) {
    return 0;
  }
  xaios_spin_lock(&g_ring.lock);
  uint32_t count = g_ring.count;
  xaios_spin_unlock(&g_ring.lock);
  return count;
}

uint32_t klog_ring_overflow_count(void) {
  if (g_ring_initialized == 0) {
    return 0;
  }
  xaios_spin_lock(&g_ring.lock);
  uint32_t overflow = g_ring.overflow;
  xaios_spin_unlock(&g_ring.lock);
  return overflow;
}

uint64_t klog_ring_total_written(void) {
  if (g_ring_initialized == 0) {
    return 0;
  }
  xaios_spin_lock(&g_ring.lock);
  uint64_t total = g_ring.total_written;
  xaios_spin_unlock(&g_ring.lock);
  return total;
}

xaios_status_t klog_rotate(void) {
  if (g_ring_initialized == 0) {
    return XAIOS_ERR_INVALID;
  }

  /* Delete old rotated log (ignore error) */
  mutable_fs_delete(KLOG_ROTATED_PATH);

  /* Rename current log to .1 */
  xaios_status_t status = mutable_fs_rename(KLOG_PATH, KLOG_ROTATED_PATH);
  if (status != XAIOS_OK) {
    return status;
  }

  ++g_rotate_count;
  klog("klog_ring: rotated log rotates=%lu\n", g_rotate_count);
  return XAIOS_OK;
}

xaios_status_t klog_flush(void) {
  uint64_t append_offset = 0;
  if (g_ring_initialized == 0 || g_ring.count == 0) {
    return XAIOS_OK;
  }

  /* Check if rotation is needed */
  xaios_mfs_stat_t stat;
  if (mutable_fs_stat(KLOG_PATH, &stat) == XAIOS_OK) {
    if (stat.size > XAIOS_MFS_MAX_FILE_BYTES_V5 - XAIOS_KLOG_FLUSH_MAX) {
      if (klog_rotate() != XAIOS_OK) {
        return XAIOS_ERR_IO;
      }
    } else {
      append_offset = stat.size;
    }
  }

  /* Read a chunk from the ring buffer */
  char flush_buf[XAIOS_KLOG_FLUSH_MAX];
  uint32_t bytes = klog_ring_read(flush_buf, XAIOS_KLOG_FLUSH_MAX);
  if (bytes == 0) {
    return XAIOS_OK;
  }

  /* Open or create the log file */
  int64_t fd = mutable_fs_open(KLOG_PATH,
                                XAIOS_MFS_OPEN_WRITE | XAIOS_MFS_OPEN_CREATE);
  if (fd < 0) {
    return XAIOS_ERR_IO;
  }
  if (append_offset != 0U &&
      mutable_fs_seek((uint32_t)fd, append_offset) != XAIOS_OK) {
    mutable_fs_close((uint32_t)fd);
    return XAIOS_ERR_IO;
  }

  int64_t written = mutable_fs_write_fd((uint32_t)fd, flush_buf, bytes);
  mutable_fs_close((uint32_t)fd);

  if (written < 0 || (uint32_t)written != bytes) {
    return XAIOS_ERR_IO;
  }

  ++g_persist_count;
  return XAIOS_OK;
}

uint64_t klog_persist_count(void) {
  return g_persist_count;
}

uint64_t klog_rotate_count(void) {
  return g_rotate_count;
}

void klog_ring_self_test(void) {
  kassert(g_ring_initialized != 0);

  /* Test ring buffer write/read */
  klog_ring_clear();
  const char test_msg[] = "self-test-ring-buffer\n";
  uint32_t test_len = 0;
  for (uint32_t i = 0; test_msg[i] != '\0'; ++i) {
    ++test_len;
  }
  klog_ring_write(test_msg, test_len);
  kassert(klog_ring_count() == test_len);

  char snapshot_buf[64];
  uint64_t snapshot_start = 0;
  uint64_t snapshot_next = 0;
  uint64_t snapshot_latest = 0;
  uint32_t snapshot_bytes =
      klog_ring_snapshot(snapshot_buf, sizeof(snapshot_buf), 0,
                         &snapshot_start, &snapshot_next, &snapshot_latest);
  kassert(snapshot_bytes == test_len);
  kassert(snapshot_start + snapshot_bytes == snapshot_next);
  kassert(snapshot_next == snapshot_latest);
  kassert(klog_ring_count() == test_len);

  char read_buf[64];
  uint32_t read_bytes = klog_ring_read(read_buf, sizeof(read_buf));
  kassert(read_bytes == test_len);
  for (uint32_t i = 0; i < test_len; ++i) {
    kassert(read_buf[i] == test_msg[i]);
  }
  kassert(klog_ring_count() == 0);

  /* Test overflow */
  klog_ring_clear();
  char fill_buf[128];
  for (uint32_t i = 0; i < sizeof(fill_buf); ++i) {
    fill_buf[i] = 'A';
  }
  /* Fill the entire ring buffer + some extra */
  uint32_t total_fill = XAIOS_KLOG_RING_SIZE + 64U;
  uint32_t remaining = total_fill;
  while (remaining > 0) {
    uint32_t chunk = remaining < (uint32_t)sizeof(fill_buf)
                         ? remaining
                         : (uint32_t)sizeof(fill_buf);
    klog_ring_write(fill_buf, chunk);
    remaining -= chunk;
  }
  kassert(klog_ring_count() == XAIOS_KLOG_RING_SIZE);
  kassert(klog_ring_overflow_count() == 64U);

  /* Test flush (should succeed even if MFS not fully ready) */
  klog_ring_clear();
  klog_ring_write("flush-test\n", 11);
  kassert(klog_flush() == XAIOS_OK);

  klog("klog_ring: self-test passed overflow=%u persists=%lu rotates=%lu\n",
       g_ring.overflow, g_persist_count, g_rotate_count);
}
