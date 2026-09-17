#include <xaios_user.h>

u64 xaios_syscall3(u64 number, u64 arg0, u64 arg1, u64 arg2) {
#if defined(__aarch64__)
  register u64 x0 __asm__("x0") = arg0;
  register u64 x1 __asm__("x1") = arg1;
  register u64 x2 __asm__("x2") = arg2;
  register u64 x8 __asm__("x8") = number;
  __asm__ volatile("svc #0"
                   : "+r"(x0)
                   : "r"(x1), "r"(x2), "r"(x8)
                   : "memory");
  return x0;
#elif defined(__x86_64__)
  register u64 rax __asm__("rax") = number;
  register u64 rdi __asm__("rdi") = arg0;
  register u64 rsi __asm__("rsi") = arg1;
  register u64 rdx __asm__("rdx") = arg2;
  __asm__ volatile("int $0x80"
                   : "+a"(rax)
                   : "D"(rdi), "S"(rsi), "d"(rdx)
                   : "rcx", "r11", "memory");
  return rax;
#elif defined(__riscv)
  /* Number in a7, arguments from a0, result back in a0 -- the same shape as
     an SBI call one privilege level up, and what the kernel's ecall handler
     reads. */
  register u64 a0 __asm__("a0") = arg0;
  register u64 a1 __asm__("a1") = arg1;
  register u64 a2 __asm__("a2") = arg2;
  register u64 a7 __asm__("a7") = number;
  __asm__ volatile("ecall"
                   : "+r"(a0)
                   : "r"(a1), "r"(a2), "r"(a7)
                   : "memory");
  return a0;
#else
#error "Unsupported XAIOS userspace architecture"
#endif
}

u64 xaios_strlen(const char *text) {
  u64 len = 0;
  if (text == 0) {
    return 0;
  }
  while (text[len] != '\0') {
    ++len;
  }
  return len;
}

void xaios_memzero(void *buffer, u64 size) {
  char *bytes = (char *)buffer;
  for (u64 i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

void *memset(void *buffer, int value, u64 size) {
  unsigned char *bytes = (unsigned char *)buffer;
  for (u64 i = 0; i < size; ++i) {
    bytes[i] = (unsigned char)value;
  }
  return buffer;
}

void *memcpy(void *dst, const void *src, u64 size) {
  unsigned char *out = (unsigned char *)dst;
  const unsigned char *in = (const unsigned char *)src;
  for (u64 i = 0; i < size; ++i) {
    out[i] = in[i];
  }
  return dst;
}

void *memmove(void *dst, const void *src, u64 size) {
  unsigned char *out = (unsigned char *)dst;
  const unsigned char *in = (const unsigned char *)src;
  if (out < in) {
    for (u64 i = 0U; i < size; ++i) out[i] = in[i];
  } else if (out > in) {
    for (u64 i = size; i != 0U; --i) out[i - 1U] = in[i - 1U];
  }
  return dst;
}

int memcmp(const void *left, const void *right, u64 size) {
  const unsigned char *a = (const unsigned char *)left;
  const unsigned char *b = (const unsigned char *)right;
  for (u64 i = 0U; i < size; ++i) {
    if (a[i] != b[i]) return (int)a[i] - (int)b[i];
  }
  return 0;
}

u64 strlen(const char *text) { return xaios_strlen(text); }

void *xaios_memcpy(void *dst, const void *src, u64 size) {
  return memcpy(dst, src, size);
}

void xaios_log(const char *text) {
  (void)xaios_syscall3(XAIOS_SYSCALL_LOG, (u64)text, xaios_strlen(text), 0);
}

int xaios_console_read(char *value) {
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_CONSOLE_READ, (u64)value, 1U, 0U);
  return rc == ~0ULL ? -1 : (int)(s64)rc;
}

/* Write a buffer of any length, in pieces the kernel will take.
 *
 * The kernel copies a console write onto its own stack, so it refuses one
 * larger than four kilobytes -- refuses, not truncates: nothing of it is
 * written. An application that composes a screen and writes it in one call
 * therefore worked while its screens were small and produced nothing at all
 * once they were not. The process monitor's frame at eighty columns is three
 * and a half kilobytes; at the hundred and forty a framebuffer console offers
 * it is nine, and every byte of it was dropped. Splitting here means every
 * program gets the whole of what it wrote, whatever its size. */
int xaios_console_write(const char *buffer, u64 size) {
  u64 written = 0U;
  while (written < size) {
    u64 chunk = size - written;
    if (chunk > XAIOS_CONSOLE_WRITE_MAX) chunk = XAIOS_CONSOLE_WRITE_MAX;
    u64 rc = xaios_syscall3(XAIOS_SYSCALL_CONSOLE_WRITE,
                            (u64)(buffer + written), chunk, 0U);
    if (rc == ~0ULL) return written == 0U ? -1 : (int)(s64)written;
    written += rc;
    if (rc != chunk) break;
  }
  return (int)(s64)written;
}

int xaios_console_size(u32 *columns, u32 *rows) {
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_CONSOLE_SIZE, 0U, 0U, 0U);
  if (rc == 0U || rc == ~0ULL) return -1;
  if (columns != 0) *columns = (u32)(rc >> 32);
  if (rows != 0) *rows = (u32)(rc & 0xffffffffULL);
  return 0;
}

int xaios_sleep_ns(u64 nanoseconds) {
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_SLEEP_NANOS, nanoseconds, 0U, 0U);
  return rc == ~0ULL ? -1 : 0;
}

int xaios_wait_events(u64 timeout_ns) {
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_WAIT_EVENTS, timeout_ns, 0U, 0U);
  return rc == ~0ULL ? -1 : (int)rc;
}

void xaios_exit(int code) {
  (void)xaios_syscall3(XAIOS_SYSCALL_EXIT, (u64)(u32)code, 0, 0);
  for (;;) {
#if defined(__aarch64__)
    __asm__ volatile("wfe");
#elif defined(__x86_64__)
    __asm__ volatile("pause");
#elif defined(__riscv)
    /* Not wfi: that is privileged and would trap out of the process that
       executed it. A program that has already asked to exit and been given
       nothing back has nothing better to do than spin. */
    __asm__ volatile("" ::: "memory");
#else
#error "Unsupported XAIOS userspace architecture"
#endif
  }
}

u64 xaios_clock_nanos(void) {
  return xaios_clock_nanos_kind(XAIOS_CLOCK_MONOTONIC);
}

u64 xaios_clock_nanos_kind(u64 kind) {
  return xaios_syscall3(XAIOS_SYSCALL_CLOCK_NANOS, kind, 0, 0);
}

int xaios_random(void *buffer, u64 size) {
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_RANDOM, (u64)buffer, size, 0);
  return rc == size ? 0 : -1;
}

int xaios_osctl(const char *command) {
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_OSCTL, (u64)command,
                         xaios_strlen(command), 0);
  return rc == ~0ULL ? -1 : 0;
}

int xaios_fs_mkdir(const char *path) {
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_FS_MKDIR, (u64)path, xaios_strlen(path), 0);
  return rc == ~0ULL ? -1 : 0;
}

int xaios_fs_delete(const char *path) {
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_FS_DELETE, (u64)path, xaios_strlen(path), 0);
  return rc == ~0ULL ? -1 : 0;
}

int xaios_fs_rename(const char *old_path, const char *new_path) {
  xaios_rename_request_t request;
  request.old_path = (u64)old_path;
  request.old_path_len = xaios_strlen(old_path);
  request.new_path = (u64)new_path;
  request.new_path_len = xaios_strlen(new_path);
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_FS_RENAME, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : 0;
}

int xaios_fs_list(const char *path, char *buffer, u64 buffer_size,
                 u64 *out_size) {
  xaios_list_request_t request;
  request.buffer = (u64)buffer;
  request.buffer_size = buffer_size;
  request.out_size = (u64)out_size;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_FS_LIST, (u64)path, xaios_strlen(path),
                         (u64)&request);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_fs_open(const char *path, u32 flags) {
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_FS_OPEN, (u64)path, xaios_strlen(path),
                         (u64)flags);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_fs_read(int fd, void *buffer, u64 size) {
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_FS_READ, (u64)(u32)fd, (u64)buffer, size);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_fs_write(int fd, const void *buffer, u64 size) {
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_FS_WRITE, (u64)(u32)fd, (u64)buffer, size);
  return rc == ~0ULL ? -1 : (int)rc;
}

s64 xaios_fs_pread(int fd, void *buffer, u64 size, u64 offset) {
  xaios_positional_io_request_t request;
  request.fd = (u64)(u32)fd;
  request.buffer = (u64)buffer;
  request.size = size;
  request.offset = offset;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_FS_PREAD, (u64)&request,
                          sizeof(request), 0);
  return rc == ~0ULL ? -1 : (s64)rc;
}

s64 xaios_fs_pwrite(int fd, const void *buffer, u64 size, u64 offset) {
  xaios_positional_io_request_t request;
  request.fd = (u64)(u32)fd;
  request.buffer = (u64)buffer;
  request.size = size;
  request.offset = offset;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_FS_PWRITE, (u64)&request,
                          sizeof(request), 0);
  return rc == ~0ULL ? -1 : (s64)rc;
}

int xaios_fs_fsync(int fd) {
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_FS_FSYNC, (u64)(u32)fd, 0, 0);
  return rc == ~0ULL ? -1 : 0;
}

int xaios_fs_seek(int fd, u64 offset) {
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_FS_SEEK, (u64)(u32)fd, offset, 0);
  return rc == ~0ULL ? -1 : 0;
}

int xaios_fs_close(int fd) {
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_FS_CLOSE, (u64)(u32)fd, 0, 0);
  return rc == ~0ULL ? -1 : 0;
}

int xaios_fs_stat(const char *path, xaios_xbfs_stat_user_t *stat) {
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_FS_STAT, (u64)path, xaios_strlen(path),
                         (u64)stat);
  return rc == ~0ULL ? -1 : 0;
}

int xaios_smp_run(u64 worker_count, u64 iterations, u64 *ran_workers,
                 u64 *checksum) {
  xaios_smp_request_t request;
  request.worker_count = worker_count;
  request.iterations = iterations;
  request.out_workers = (u64)ran_workers;
  request.out_checksum = (u64)checksum;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_SMP_RUN, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_write_file(const char *path, const char *content) {
  int fd = xaios_fs_open(path, XAIOS_XBFS_OPEN_WRITE | XAIOS_XBFS_OPEN_CREATE |
                                  XAIOS_XBFS_OPEN_TRUNCATE);
  if (fd < 0) {
    return -1;
  }
  u64 content_len = xaios_strlen(content);
  u64 total_written = 0;
  while (total_written < content_len) {
    int n = xaios_fs_write(fd, content + total_written, content_len - total_written);
    if (n <= 0) {
      xaios_fs_close(fd);
      return -1;
    }
    total_written += (u64)n;
  }
  if (xaios_fs_close(fd) != 0) {
    return -1;
  }
  return (int)total_written;
}

int xaios_read_file(const char *path, char *buffer, u64 buffer_size) {
  int fd = xaios_fs_open(path, XAIOS_XBFS_OPEN_READ);
  if (fd < 0) {
    return -1;
  }
  /* Leave room for null terminator */
  u64 read_size = (buffer_size > 0) ? buffer_size - 1 : 0;
  int bytes = xaios_fs_read(fd, buffer, read_size);
  if (xaios_fs_close(fd) != 0 || bytes < 0) {
    return -1;
  }
  buffer[bytes] = '\0';
  return bytes;
}

void xaios_append_cstr(char *buffer, u64 capacity, u64 *offset,
                      const char *text) {
  if (buffer == 0 || offset == 0 || text == 0 || capacity == 0) {
    return;
  }
  for (u64 i = 0; text[i] != '\0' && *offset + 1 < capacity; ++i) {
    buffer[*offset] = text[i];
    ++(*offset);
  }
  buffer[*offset] = '\0';
}

void xaios_append_u64(char *buffer, u64 capacity, u64 *offset, u64 value) {
  char digits[20];
  u64 count = 0;
  if (value == 0) {
    xaios_append_cstr(buffer, capacity, offset, "0");
    return;
  }
  while (value != 0 && count < sizeof(digits)) {
    digits[count++] = (char)('0' + (value % 10ULL));
    value /= 10ULL;
  }
  while (count > 0) {
    char one[2];
    --count;
    one[0] = digits[count];
    one[1] = '\0';
    xaios_append_cstr(buffer, capacity, offset, one);
  }
}

void xaios_log_u64(const char *prefix, u64 value, const char *suffix) {
  char line[160];
  u64 offset = 0;
  xaios_memzero(line, sizeof(line));
  xaios_append_cstr(line, sizeof(line), &offset, prefix);
  xaios_append_u64(line, sizeof(line), &offset, value);
  xaios_append_cstr(line, sizeof(line), &offset, suffix);
  xaios_log(line);
}
