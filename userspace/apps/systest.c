#include <xaios_user.h>

static int expect_ok(int value, const char *message) {
  if (value < 0) {
    xaios_log(message);
    return -1;
  }
  return 0;
}

int main(void) {
  char read_buffer[96];
  char list_buffer[256];
  u64 list_size = 0;
  xaios_mfs_stat_user_t stat;
  xaios_memzero(read_buffer, sizeof(read_buffer));
  xaios_memzero(list_buffer, sizeof(list_buffer));
  xaios_memzero(&stat, sizeof(stat));

  xaios_log("/bin/systest: starting syscall and filesystem suite\n");
  if (xaios_syscall3(XAIOS_SYSCALL_FS_READ, 1ULL << 32U,
                     (u64)read_buffer, 1U) != ~0ULL ||
      xaios_syscall3(XAIOS_SYSCALL_FS_CLOSE, 1ULL << 32U, 0U, 0U) != ~0ULL) {
    xaios_log("/bin/systest: high-bit fd rejection failed\n");
    return 1;
  }
  if (expect_ok(xaios_fs_mkdir("/tmp"), "/bin/systest: mkdir /tmp failed\n") != 0) {
    return 1;
  }
  if (expect_ok(xaios_fs_mkdir("/tmp/systest"), "/bin/systest: mkdir suite failed\n") != 0) {
    return 1;
  }
  if (expect_ok(xaios_write_file("/tmp/systest/input.txt", "xaios-systest\n"),
                "/bin/systest: write failed\n") != 0) {
    return 1;
  }
  if (expect_ok(xaios_read_file("/tmp/systest/input.txt", read_buffer,
                               sizeof(read_buffer) - 1U),
                "/bin/systest: read failed\n") != 0) {
    return 1;
  }
  if (expect_ok(xaios_fs_stat("/tmp/systest/input.txt", &stat),
                "/bin/systest: stat failed\n") != 0) {
    return 1;
  }
  if (expect_ok(xaios_fs_list("/tmp/systest", list_buffer, sizeof(list_buffer),
                             &list_size),
                "/bin/systest: list failed\n") != 0) {
    return 1;
  }
  if (expect_ok(xaios_fs_rename("/tmp/systest/input.txt",
                               "/tmp/systest/renamed.txt"),
                "/bin/systest: rename failed\n") != 0) {
    return 1;
  }
  if (expect_ok(xaios_fs_delete("/tmp/systest/renamed.txt"),
                "/bin/systest: delete file failed\n") != 0) {
    return 1;
  }
  if (expect_ok(xaios_fs_delete("/tmp/systest"),
                "/bin/systest: delete dir failed\n") != 0) {
    return 1;
  }

  xaios_log_u64("/bin/systest: stat_size=", stat.size, "\n");
  xaios_log_u64("/bin/systest: list_bytes=", list_size, "\n");
  xaios_log("/bin/systest: syscall and filesystem suite passed\n");
  return 0;
}
