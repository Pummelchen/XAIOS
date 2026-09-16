/* The audit log and the instrument that says what it costs.
 *
 * Split whole out of sshd.c: the state below is reached from one place in the
 * server -- the close path in the service loop -- and by ssh_log, which the
 * rest of the server calls as a black box. The measurement stays with the code
 * it measures, so the two paths that touch the durable volume during an
 * ordinary connection can be read in one file. */

#include "sshd_audit.h"

#include "sshd.h"
#include "ssh_utils.h"

#include <stdarg.h>

static int g_log_fd = -1;
static uint32_t g_log_bytes = 0;

/* What the durable volume costs this process, counted rather than assumed.
 *
 * B-45 is an arithmetic claim about work done inside this loop, and by B-44
 * this loop is the machine's networking: while sshd is inside a write to the
 * volume, nothing is taken off the receive ring, no ACK leaves the guest and
 * no retransmit happens. A claim like that is worth exactly as much as the
 * instrument behind it, so the two paths that touch the volume during an
 * ordinary connection -- the audit append and the authorized-key load -- keep
 * running totals of how often they ran, how many bytes they moved, and how
 * long they held the loop.
 *
 * Cumulative rather than per-connection. A console is a lossy transport and a
 * soak scrolls; a running total means the last line that survives is still the
 * whole answer, and per-connection is a division the reader can do. The line
 * is emitted at each close, which is where a reader is already looking.
 *
 * These stay after the fix, and that is the point of them. A measurement taken
 * once, quoted and then deleted cannot notice the day the number goes back
 * up. */
static uint32_t g_audit_write_calls;
static uint64_t g_audit_write_bytes;
static uint64_t g_audit_write_ns;
/* B-63: the total was all this kept, and a mean cannot answer the question the
   total raises. sshd's loop is the only thing that polls the network (B-44), so
   the number that matters is not what durable writes cost on average but what
   the worst single one costs -- 1020 writes averaging 34 ms are unremarkable
   and one write of nine seconds is a dropped connection. Averages hide exactly
   the tail this is about. */
static uint64_t g_audit_write_max_ns;
/* Durable nanoseconds inside the pass currently running, reset at the top of
   each one. B-63: a stall says which phase it was in and not what the phase
   was doing, and the run-long total cannot answer that -- 1020 writes at 34 ms
   and one nine-second pass are the same number until they are separated. If a
   stalled pass reports durable time close to its own length, the audit write is
   the cause; if it reports nearly none, the time is going somewhere else in
   that phase and this rules out the obvious suspect in one reproduction rather
   than several. */
static uint64_t g_pass_durable_ns;

/* Audit records held in memory until there is a reason to pay for them.
 *
 * B-63: every ssh_log() call was one append to the durable volume, and an
 * append carries blk_flush() -- a virtio flush, which is a host fsync. sshd's
 * service loop is the only thing that polls the network (B-44), so each of
 * those fsyncs is a window in which the machine has no networking, and on a
 * host whose disk stalls the window is seconds. A connection takes about five
 * log lines, so it was paying five of them.
 *
 * The records themselves are worth keeping; the per-line fsync is not. The
 * console is where a connection's story is told -- log_connection_close and
 * the refusal lines below write there, and the comment on them says plainly
 * that the audit file is read by no soak and no gate. So lines accumulate here
 * and go out in one write when the buffer fills or a connection ends: one
 * fsync per connection rather than five, with the same bytes in the same order
 * in the same file.
 *
 * What this gives up, stated rather than buried: a crash loses the records
 * still in the buffer. The whole-file path already loses the record being
 * appended, so the guarantee was never "every line survives any crash" -- it
 * was one line's worth of exposure and is now a connection's worth. */
static char g_audit_buffer[SSHD_AUDIT_BUFFER_BYTES];
static uint32_t g_audit_buffered;

/* One durable-write sample: the running total and the worst seen. */
static void record_durable_ns(uint64_t started) {
  uint64_t elapsed = xaios_clock_nanos() - started;
  g_audit_write_ns += elapsed;
  g_pass_durable_ns += elapsed;
  if (elapsed > g_audit_write_max_ns) g_audit_write_max_ns = elapsed;
}

void log_durable_cost(uint32_t connections, uint32_t key_load_calls,
                      uint32_t key_file_reads, uint64_t key_load_ns) {
  /* Widened with audit_worst_us: the appends are bounds-checked so the old
     256 would have truncated rather than overflowed, but a line that silently
     loses key_us at the end is a worse outcome than a slightly larger frame. */
  char line[320];
  u64 offset = 0;
  xaios_memzero(line, sizeof(line));
  xaios_append_cstr(line, sizeof(line), &offset, "sshd: durable cost conns=");
  xaios_append_u64(line, sizeof(line), &offset, connections);
  xaios_append_cstr(line, sizeof(line), &offset, " audit_writes=");
  xaios_append_u64(line, sizeof(line), &offset, g_audit_write_calls);
  xaios_append_cstr(line, sizeof(line), &offset, " audit_bytes=");
  xaios_append_u64(line, sizeof(line), &offset, g_audit_write_bytes);
  xaios_append_cstr(line, sizeof(line), &offset, " audit_worst_us=");
  xaios_append_u64(line, sizeof(line), &offset,
                   g_audit_write_max_ns / UINT64_C(1000));
  xaios_append_cstr(line, sizeof(line), &offset, " audit_us=");
  xaios_append_u64(line, sizeof(line), &offset,
                   g_audit_write_ns / UINT64_C(1000));
  xaios_append_cstr(line, sizeof(line), &offset, " key_loads=");
  xaios_append_u64(line, sizeof(line), &offset, key_load_calls);
  xaios_append_cstr(line, sizeof(line), &offset, " key_file_reads=");
  xaios_append_u64(line, sizeof(line), &offset, key_file_reads);
  xaios_append_cstr(line, sizeof(line), &offset, " key_us=");
  xaios_append_u64(line, sizeof(line), &offset,
                   key_load_ns / UINT64_C(1000));
  xaios_append_cstr(line, sizeof(line), &offset, "\n");
  xaios_log(line);
}

static int ssh_log_reopen(void) {
  if (g_log_fd >= 0) {
    xaios_fs_close(g_log_fd);
    g_log_fd = -1;
  }
  g_log_fd = xaios_fs_open(
      "/state/sshd.log", XAIOS_XBFS_OPEN_WRITE | XAIOS_XBFS_OPEN_CREATE |
                             XAIOS_XBFS_OPEN_TRUNCATE);
  g_log_bytes = 0;
  return g_log_fd < 0 ? -1 : 0;
}

static void int_to_str(uint64_t val, char *buf, uint32_t buf_size) {
  if (buf_size == 0) return;
  char temp[32];
  uint32_t pos = 0;
  if (val == 0) { temp[pos++] = '0'; }
  else {
    while (val > 0 && pos < 31) {
      temp[pos++] = '0' + (val % 10);
      val /= 10;
    }
  }
  uint32_t len = 0;
  for (int32_t i = (int32_t)(pos - 1); i >= 0 && len < buf_size - 1; i--) {
    buf[len++] = temp[i];
  }
  buf[len] = '\0';
}

static void hex_to_str(uint64_t val, char *buf, uint32_t buf_size) {
  if (buf_size < 3) return;
  const char *hex_chars = "0123456789abcdef";
  uint32_t len = 0;
  for (int i = 60; i >= 0 && len < buf_size - 2; i -= 4) {
    uint8_t digit = (uint8_t)((val >> i) & 0xF);
    if (digit != 0 || len > 0) {
      buf[len++] = hex_chars[digit];
    }
  }
  if (len == 0) buf[len++] = '0';
  buf[len] = '\0';
}

/* Put bytes on the durable volume now. The only place that pays for a flush,
   and the only place that counts one. */
static void ssh_audit_write_through(const char *bytes, uint32_t length) {
  if (length == 0U) return;
  uint64_t durable_started = xaios_clock_nanos();
  if (g_log_fd < 0 && ssh_log_reopen() != 0) {
    record_durable_ns(durable_started);
    return;
  }
  if (g_log_bytes + length > SSHD_LOG_ROTATE_BYTES) {
    if (ssh_log_reopen() != 0) {
      record_durable_ns(durable_started);
      return;
    }
    xaios_log("sshd: audit log rotated\n");
  }
  ++g_audit_write_calls;
  g_audit_write_bytes += length;
  int written = xaios_fs_write(g_log_fd, bytes, length);
  if (written != (int)length) {
    if (ssh_log_reopen() != 0) {
      record_durable_ns(durable_started);
      return;
    }
    ++g_audit_write_calls;
    g_audit_write_bytes += length;
    written = xaios_fs_write(g_log_fd, bytes, length);
    if (written != (int)length) {
      record_durable_ns(durable_started);
      return;
    }
  }
  g_log_bytes += length;
  record_durable_ns(durable_started);
}

/* Everything held, in one write. Safe to call with nothing buffered. */
void ssh_audit_flush(void) {
  if (g_audit_buffered == 0U) return;
  uint32_t length = g_audit_buffered;
  /* Cleared first: a write that fails must not leave the same bytes queued to
     be attempted again on every later call. */
  g_audit_buffered = 0U;
  ssh_audit_write_through(g_audit_buffer, length);
}

uint32_t ssh_audit_buffered(void) { return g_audit_buffered; }

uint64_t ssh_audit_write_ns(void) { return g_audit_write_ns; }

uint64_t ssh_audit_pass_durable_ns(void) { return g_pass_durable_ns; }

void ssh_audit_pass_reset(void) { g_pass_durable_ns = 0U; }

void ssh_log(int level, const char *fmt, ...) {
  const char *prefix;
  switch (level) {
    case SSH_LOG_INFO:  prefix = "[INFO]";  break;
    case SSH_LOG_WARN:  prefix = "[WARN]";  break;
    case SSH_LOG_ERROR: prefix = "[ERROR]"; break;
    default: prefix = "[UNKNOWN]"; break;
  }
  va_list args;
  va_start(args, fmt);
  char buffer[512];
  uint32_t buf_pos = 0;
  for (const char *p = fmt; *p && buf_pos < 511; p++) {
    if (*p == '%' && *(p+1)) {
      p++;
      if (*p == 's') {
        const char *str = va_arg(args, const char*);
        if (str) {
          uint32_t len = ssh_str_len(str);
          if (buf_pos + len < 511) {
            for (uint32_t i = 0; i < len; i++) buffer[buf_pos++] = str[i];
          }
        }
      } else if (*p == 'u' || *p == 'd') {
        uint64_t val = va_arg(args, uint64_t);
        char num_buf[32];
        int_to_str(val, num_buf, 32);
        uint32_t len = ssh_str_len(num_buf);
        if (buf_pos + len < 511) {
          for (uint32_t i = 0; i < len; i++) buffer[buf_pos++] = num_buf[i];
        }
      } else if (*p == 'x' || *p == 'X') {
        uint64_t val = va_arg(args, uint64_t);
        char num_buf[32];
        hex_to_str(val, num_buf, 32);
        uint32_t len = ssh_str_len(num_buf);
        if (buf_pos + len < 511) {
          for (uint32_t i = 0; i < len; i++) buffer[buf_pos++] = num_buf[i];
        }
      } else if (*p == 'p') {
        uint64_t val = (uint64_t)va_arg(args, void*);
        char num_buf[32];
        hex_to_str(val, num_buf, 32);
        uint32_t len = ssh_str_len(num_buf);
        if (buf_pos + len + 2 < 511) {
          buffer[buf_pos++] = '0';
          buffer[buf_pos++] = 'x';
          for (uint32_t i = 0; i < len; i++) buffer[buf_pos++] = num_buf[i];
        }
      } else if (*p == '%') {
        if (buf_pos < 511) buffer[buf_pos++] = '%';
      }
    } else {
      buffer[buf_pos++] = *p;
    }
  }
  buffer[buf_pos] = '\0';
  va_end(args);

  while (buf_pos != 0U && buffer[buf_pos - 1U] == '\n') --buf_pos;
  char line[544];
  uint32_t line_pos = 0;
  uint32_t prefix_len = ssh_str_len(prefix);
  for (uint32_t i = 0; i < prefix_len; ++i) line[line_pos++] = prefix[i];
  line[line_pos++] = ' ';
  for (uint32_t i = 0; i < buf_pos; ++i) line[line_pos++] = buffer[i];
  line[line_pos++] = '\n';

  /* From here to the end of this function is time spent on the durable
     volume, and by B-44 that is time the guest has no networking. Timed as a
     block rather than per call so a rotation -- which closes, creates and
     truncates -- is counted where it is actually paid. */
  /* A line too long for the buffer would never fit and must not be dropped
     silently, so the buffer is drained and the line written on its own. */
  if (line_pos > SSHD_AUDIT_BUFFER_BYTES) {
    ssh_audit_flush();
    ssh_audit_write_through(line, line_pos);
    return;
  }
  if (g_audit_buffered + line_pos > SSHD_AUDIT_BUFFER_BYTES) {
    ssh_audit_flush();
  }
  for (uint32_t i = 0; i < line_pos; ++i) {
    g_audit_buffer[g_audit_buffered + i] = line[i];
  }
  g_audit_buffered += line_pos;
}
