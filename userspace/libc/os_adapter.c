#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/times.h>
#include <time.h>
#include <unistd.h>

typedef uint64_t xaios_u64;

#define XAIOS_SYSCALL_FS_OPEN 11ULL
#define XAIOS_SYSCALL_FS_READ 12ULL
#define XAIOS_SYSCALL_FS_WRITE 13ULL
#define XAIOS_SYSCALL_FS_CLOSE 14ULL
#define XAIOS_SYSCALL_FS_STAT 15ULL
#define XAIOS_SYSCALL_FS_DELETE 17ULL
#define XAIOS_SYSCALL_FS_RENAME 18ULL
#define XAIOS_SYSCALL_CLOCK_NANOS 20ULL
#define XAIOS_SYSCALL_FS_SEEK 36ULL
#define XAIOS_SYSCALL_FS_FSYNC 41ULL

#define XAIOS_CLOCK_REALTIME 1ULL
#define XAIOS_CLOCK_PROCESS_CPU 2ULL
#define XAIOS_XBFS_OPEN_READ 1U
#define XAIOS_XBFS_OPEN_WRITE 2U
#define XAIOS_XBFS_OPEN_CREATE 4U
#define XAIOS_XBFS_OPEN_TRUNCATE 8U
#define XAIOS_FS_TYPE_DIRECTORY 1U
#define XAIOS_LIBC_FD_COUNT 32
#define XAIOS_LIBC_PATH_MAX 256U

typedef struct xaios_xbfs_stat_user {
  uint32_t type;
  uint32_t block_count;
  uint64_t size;
  uint64_t generation;
  uint64_t content_hash;
} xaios_xbfs_stat_user_t;

typedef struct xaios_rename_request {
  uint64_t old_path;
  uint64_t old_path_len;
  uint64_t new_path;
  uint64_t new_path_len;
} xaios_rename_request_t;

typedef struct xaios_libc_fd {
  int kernel_fd;
  int flags;
  int delete_on_close;
  off_t offset;
  char path[XAIOS_LIBC_PATH_MAX];
} xaios_libc_fd_t;

extern xaios_u64 __xaios_libc_syscall3(xaios_u64 number, xaios_u64 arg0,
                                       xaios_u64 arg1, xaios_u64 arg2);

static xaios_libc_fd_t descriptors[XAIOS_LIBC_FD_COUNT];

static size_t path_length(const char *path) {
  return path == NULL ? 0U : strlen(path);
}

static int syscall_failed(xaios_u64 result) {
  return result == UINT64_MAX;
}

static xaios_libc_fd_t *descriptor_for(int fd) {
  if (fd < 3 || fd >= XAIOS_LIBC_FD_COUNT ||
      descriptors[fd].kernel_fd < 0) {
    errno = EBADF;
    return NULL;
  }
  return &descriptors[fd];
}

static int stat_path(const char *path, xaios_xbfs_stat_user_t *value) {
  xaios_u64 result;
  size_t length = path_length(path);
  if (length == 0U || length >= XAIOS_LIBC_PATH_MAX) {
    errno = ENAMETOOLONG;
    return -1;
  }
  result = __xaios_libc_syscall3(XAIOS_SYSCALL_FS_STAT,
                                 (xaios_u64)(uintptr_t)path, length,
                                 (xaios_u64)(uintptr_t)value);
  if (syscall_failed(result)) {
    errno = ENOENT;
    return -1;
  }
  return 0;
}

__attribute__((constructor)) static void initialize_descriptors(void) {
  for (int fd = 0; fd < XAIOS_LIBC_FD_COUNT; ++fd) {
    descriptors[fd].kernel_fd = -1;
  }
}

int open(const char *path, int flags, ...) {
  uint32_t xaios_flags = 0U;
  xaios_xbfs_stat_user_t existing;
  int slot;
  xaios_u64 result;
  size_t length = path_length(path);
  (void)sizeof(va_list);

  if (length == 0U || length >= XAIOS_LIBC_PATH_MAX) {
    errno = length == 0U ? ENOENT : ENAMETOOLONG;
    return -1;
  }
  if ((flags & O_EXCL) != 0 && (flags & O_CREAT) != 0 &&
      stat_path(path, &existing) == 0) {
    errno = EEXIST;
    return -1;
  }
  if ((flags & O_ACCMODE) == O_RDONLY || (flags & O_ACCMODE) == O_RDWR) {
    xaios_flags |= XAIOS_XBFS_OPEN_READ;
  }
  if ((flags & O_ACCMODE) == O_WRONLY || (flags & O_ACCMODE) == O_RDWR) {
    xaios_flags |= XAIOS_XBFS_OPEN_WRITE;
  }
  if ((flags & O_CREAT) != 0) xaios_flags |= XAIOS_XBFS_OPEN_CREATE;
  if ((flags & O_TRUNC) != 0) xaios_flags |= XAIOS_XBFS_OPEN_TRUNCATE;

  for (slot = 3; slot < XAIOS_LIBC_FD_COUNT; ++slot) {
    if (descriptors[slot].kernel_fd < 0) break;
  }
  if (slot == XAIOS_LIBC_FD_COUNT) {
    errno = EMFILE;
    return -1;
  }
  result = __xaios_libc_syscall3(XAIOS_SYSCALL_FS_OPEN,
                                 (xaios_u64)(uintptr_t)path, length,
                                 xaios_flags);
  if (syscall_failed(result)) {
    errno = (flags & O_CREAT) == 0 ? ENOENT : EIO;
    return -1;
  }
  descriptors[slot].kernel_fd = (int)result;
  descriptors[slot].flags = flags;
  descriptors[slot].delete_on_close = 0;
  descriptors[slot].offset = 0;
  memcpy(descriptors[slot].path, path, length + 1U);
  if ((flags & O_APPEND) != 0) {
    xaios_xbfs_stat_user_t value;
    if (stat_path(path, &value) == 0 && value.size <= (uint64_t)INT64_MAX) {
      descriptors[slot].offset = (off_t)value.size;
      (void)__xaios_libc_syscall3(XAIOS_SYSCALL_FS_SEEK, result, value.size,
                                  0U);
    }
  }
  return slot;
}

int close(int fd) {
  xaios_libc_fd_t *descriptor = descriptor_for(fd);
  int delete_on_close;
  char path[XAIOS_LIBC_PATH_MAX];
  if (descriptor == NULL) return -1;
  delete_on_close = descriptor->delete_on_close;
  memcpy(path, descriptor->path, sizeof(path));
  xaios_u64 result = __xaios_libc_syscall3(
      XAIOS_SYSCALL_FS_CLOSE, (xaios_u64)(unsigned)descriptor->kernel_fd, 0U,
      0U);
  if (syscall_failed(result)) {
    errno = EIO;
    return -1;
  }
  descriptor->kernel_fd = -1;
  descriptor->delete_on_close = 0;
  if (delete_on_close != 0) {
    for (int open_fd = 3; open_fd < XAIOS_LIBC_FD_COUNT; ++open_fd) {
      if (descriptors[open_fd].kernel_fd >= 0 &&
          strcmp(descriptors[open_fd].path, path) == 0) {
        return 0;
      }
    }
    if (syscall_failed(__xaios_libc_syscall3(
            XAIOS_SYSCALL_FS_DELETE, (xaios_u64)(uintptr_t)path,
            path_length(path), 0U))) {
      errno = EIO;
      return -1;
    }
  }
  return 0;
}

ssize_t read(int fd, void *buffer, size_t count) {
  xaios_libc_fd_t *descriptor = descriptor_for(fd);
  xaios_u64 result;
  if (descriptor == NULL) return -1;
  result = __xaios_libc_syscall3(
      XAIOS_SYSCALL_FS_READ, (xaios_u64)(unsigned)descriptor->kernel_fd,
      (xaios_u64)(uintptr_t)buffer, count);
  if (syscall_failed(result)) {
    errno = EIO;
    return -1;
  }
  descriptor->offset += (off_t)result;
  return (ssize_t)result;
}

ssize_t write(int fd, const void *buffer, size_t count) {
  xaios_libc_fd_t *descriptor = descriptor_for(fd);
  xaios_u64 result;
  if (descriptor == NULL) return -1;
  if ((descriptor->flags & O_APPEND) != 0 &&
      lseek(fd, 0, SEEK_END) == (off_t)-1) {
    return -1;
  }
  result = __xaios_libc_syscall3(
      XAIOS_SYSCALL_FS_WRITE, (xaios_u64)(unsigned)descriptor->kernel_fd,
      (xaios_u64)(uintptr_t)buffer, count);
  if (syscall_failed(result)) {
    errno = EIO;
    return -1;
  }
  descriptor->offset += (off_t)result;
  return (ssize_t)result;
}

off_t lseek(int fd, off_t offset, int whence) {
  xaios_libc_fd_t *descriptor = descriptor_for(fd);
  xaios_xbfs_stat_user_t value;
  off_t absolute;
  if (descriptor == NULL) return (off_t)-1;
  if (whence == SEEK_SET) {
    absolute = offset;
  } else if (whence == SEEK_CUR) {
    if (__builtin_add_overflow(descriptor->offset, offset, &absolute)) {
      errno = EOVERFLOW;
      return (off_t)-1;
    }
  } else if (whence == SEEK_END) {
    if (stat_path(descriptor->path, &value) != 0 ||
        value.size > (uint64_t)INT64_MAX ||
        __builtin_add_overflow((off_t)value.size, offset, &absolute)) {
      if (errno == 0) errno = EOVERFLOW;
      return (off_t)-1;
    }
  } else {
    errno = EINVAL;
    return (off_t)-1;
  }
  if (absolute < 0) {
    errno = EINVAL;
    return (off_t)-1;
  }
  if (syscall_failed(__xaios_libc_syscall3(
          XAIOS_SYSCALL_FS_SEEK,
          (xaios_u64)(unsigned)descriptor->kernel_fd, (xaios_u64)absolute,
          0U))) {
    errno = EIO;
    return (off_t)-1;
  }
  descriptor->offset = absolute;
  return absolute;
}

int fsync(int fd) {
  xaios_libc_fd_t *descriptor = descriptor_for(fd);
  if (descriptor == NULL) return -1;
  if (syscall_failed(__xaios_libc_syscall3(
          XAIOS_SYSCALL_FS_FSYNC,
          (xaios_u64)(unsigned)descriptor->kernel_fd, 0U, 0U))) {
    errno = EIO;
    return -1;
  }
  return 0;
}

int unlink(const char *path) {
  int deferred = 0;
  size_t length = path_length(path);
  if (length == 0U || length >= XAIOS_LIBC_PATH_MAX) {
    errno = ENOENT;
    return -1;
  }
  for (int fd = 3; fd < XAIOS_LIBC_FD_COUNT; ++fd) {
    if (descriptors[fd].kernel_fd >= 0 &&
        strcmp(descriptors[fd].path, path) == 0) {
      descriptors[fd].delete_on_close = 1;
      deferred = 1;
    }
  }
  if (deferred != 0) return 0;
  if (syscall_failed(__xaios_libc_syscall3(
          XAIOS_SYSCALL_FS_DELETE, (xaios_u64)(uintptr_t)path, length, 0U))) {
    errno = ENOENT;
    return -1;
  }
  return 0;
}

int rename(const char *old_path, const char *new_path) {
  xaios_rename_request_t request;
  request.old_path = (uint64_t)(uintptr_t)old_path;
  request.old_path_len = path_length(old_path);
  request.new_path = (uint64_t)(uintptr_t)new_path;
  request.new_path_len = path_length(new_path);
  if (request.old_path_len == 0U || request.new_path_len == 0U ||
      request.old_path_len >= XAIOS_LIBC_PATH_MAX ||
      request.new_path_len >= XAIOS_LIBC_PATH_MAX) {
    errno = EINVAL;
    return -1;
  }
  if (syscall_failed(__xaios_libc_syscall3(
          XAIOS_SYSCALL_FS_RENAME, (xaios_u64)(uintptr_t)&request,
          sizeof(request), 0U))) {
    errno = EIO;
    return -1;
  }
  return 0;
}

int remove(const char *path) {
  return unlink(path);
}

int system(const char *command) {
  if (command == NULL) return 0;
  errno = ENOSYS;
  return -1;
}

int stat(const char *path, struct stat *value) {
  xaios_xbfs_stat_user_t source;
  if (value == NULL) {
    errno = EINVAL;
    return -1;
  }
  if (stat_path(path, &source) != 0) return -1;
  memset(value, 0, sizeof(*value));
  value->st_mode = source.type == XAIOS_FS_TYPE_DIRECTORY
                       ? (mode_t)(S_IFDIR | 0777)
                       : (mode_t)(S_IFREG | 0666);
  value->st_nlink = 1;
  value->st_size = (off_t)source.size;
  value->st_blksize = 4096;
  value->st_blocks = (blkcnt_t)source.block_count;
  return 0;
}

int fstat(int fd, struct stat *value) {
  xaios_libc_fd_t *descriptor = descriptor_for(fd);
  return descriptor == NULL ? -1 : stat(descriptor->path, value);
}

int gettimeofday(struct timeval *value, void *timezone) {
  xaios_u64 nanos;
  (void)timezone;
  if (value == NULL) {
    errno = EINVAL;
    return -1;
  }
  nanos = __xaios_libc_syscall3(XAIOS_SYSCALL_CLOCK_NANOS,
                                XAIOS_CLOCK_REALTIME, 0U, 0U);
  if (syscall_failed(nanos)) return -1;
  value->tv_sec = (time_t)(nanos / UINT64_C(1000000000));
  value->tv_usec = (suseconds_t)((nanos % UINT64_C(1000000000)) / 1000U);
  return 0;
}

clock_t times(struct tms *value) {
  xaios_u64 nanos = __xaios_libc_syscall3(
      XAIOS_SYSCALL_CLOCK_NANOS, XAIOS_CLOCK_PROCESS_CPU, 0U, 0U);
  clock_t ticks;
  if (syscall_failed(nanos)) return (clock_t)-1;
  ticks = (clock_t)(nanos / (UINT64_C(1000000000) / CLOCKS_PER_SEC));
  if (value != NULL) {
    memset(value, 0, sizeof(*value));
    value->tms_utime = ticks;
  }
  return ticks;
}
