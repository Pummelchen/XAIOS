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

int xaios_console_write(const char *buffer, u64 size) {
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_CONSOLE_WRITE, (u64)buffer, size, 0U);
  return rc == ~0ULL ? -1 : (int)(s64)rc;
}

u32 xaios_net_local_ipv4(void) {
  return (u32)xaios_syscall3(XAIOS_SYSCALL_NET_LOCAL_IPV4, 0U, 0U, 0U);
}

int xaios_net_local_ipv6(u8 address[16]) {
  return (int)(s64)xaios_syscall3(XAIOS_SYSCALL_NET_LOCAL_IPV6,
                                  (u64)(void *)address, 16U, 0U);
}

void xaios_exit(int code) {
  (void)xaios_syscall3(XAIOS_SYSCALL_EXIT, (u64)(u32)code, 0, 0);
  for (;;) {
#if defined(__aarch64__)
    __asm__ volatile("wfe");
#elif defined(__x86_64__)
    __asm__ volatile("pause");
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

int xaios_net_udp_echo(const void *payload, u64 payload_size,
                      u64 *echoed_bytes) {
  xaios_net_request_t request;
  request.payload = (u64)payload;
  request.payload_size = payload_size;
  request.out_value = (u64)echoed_bytes;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_UDP_ECHO, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_tcp_connect(u64 *round_trips) {
  xaios_net_request_t request;
  request.payload = 0;
  request.payload_size = 0;
  request.out_value = (u64)round_trips;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_TCP_CONNECT, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
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

int xaios_cpu_ai_decode(const void *input, u64 input_size, char *output,
                       u64 output_size, u64 *out_size) {
  xaios_cpu_ai_decode_request_t request;
  request.input = (u64)input;
  request.input_size = input_size;
  request.output = (u64)output;
  request.output_size = output_size;
  request.out_size = (u64)out_size;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_CPU_AI_DECODE, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_remote_login(const char *user, const char *command, char *output,
                      u64 output_size, u64 *out_size) {
  xaios_remote_login_request_t request;
  request.user = (u64)user;
  request.user_size = xaios_strlen(user);
  request.command = (u64)command;
  request.command_size = xaios_strlen(command);
  request.output = (u64)output;
  request.output_size = output_size;
  request.out_size = (u64)out_size;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_REMOTE_LOGIN, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_remote_login_session(u64 session_id, const char *user,
                               const char *command, char *output,
                               u64 output_size, u64 *out_size) {
  xaios_remote_login_session_request_t request;
  request.session_id = session_id;
  request.action = XAIOS_REMOTE_LOGIN_SESSION_EXECUTE;
  request.user = (u64)user;
  request.user_size = xaios_strlen(user);
  request.command = (u64)command;
  request.command_size = xaios_strlen(command);
  request.output = (u64)output;
  request.output_size = output_size;
  request.out_size = (u64)out_size;
  request.metadata = 0ULL;
  request.metadata_size = 0ULL;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_REMOTE_LOGIN_SESSION, (u64)&request,
                          sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_remote_login_session_close(u64 session_id) {
  xaios_remote_login_session_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.session_id = session_id;
  request.action = XAIOS_REMOTE_LOGIN_SESSION_CLOSE;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_REMOTE_LOGIN_SESSION, (u64)&request,
                          sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_remote_login_child_open(u64 session_id, const char *command,
                                  const char *cwd, u64 *child_channel_id) {
  if (command == 0 || cwd == 0 || child_channel_id == 0) return -1;
  xaios_remote_login_session_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.session_id = session_id;
  request.action = XAIOS_REMOTE_LOGIN_SESSION_CHILD_OPEN;
  request.command = (u64)command;
  request.command_size = xaios_strlen(command);
  request.metadata = (u64)cwd;
  request.metadata_size = xaios_strlen(cwd);
  request.out_size = (u64)child_channel_id;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_REMOTE_LOGIN_SESSION, (u64)&request,
                          sizeof(request), 0);
  return (signed long long)rc < 0 ? (int)(signed long long)rc : 0;
}

int xaios_remote_login_child_write(u64 child_channel_id, const void *data,
                                   u64 data_size) {
  if (child_channel_id == 0ULL || data == 0 || data_size == 0ULL) return -1;
  xaios_remote_login_session_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.session_id = child_channel_id;
  request.action = XAIOS_REMOTE_LOGIN_SESSION_CHILD_WRITE;
  request.command = (u64)data;
  request.command_size = data_size;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_REMOTE_LOGIN_SESSION, (u64)&request,
                          sizeof(request), 0);
  return (signed long long)rc < 0 ? (int)(signed long long)rc : 0;
}

int xaios_remote_login_child_read(u64 child_channel_id, void *data,
                                  u64 data_size, u64 *out_size) {
  if (child_channel_id == 0ULL || data == 0 || data_size == 0ULL ||
      out_size == 0) return -1;
  xaios_remote_login_session_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.session_id = child_channel_id;
  request.action = XAIOS_REMOTE_LOGIN_SESSION_CHILD_READ;
  request.output = (u64)data;
  request.output_size = data_size;
  request.out_size = (u64)out_size;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_REMOTE_LOGIN_SESSION, (u64)&request,
                          sizeof(request), 0);
  return (signed long long)rc < 0 ? (int)(signed long long)rc : 0;
}

int xaios_remote_login_child_status(u64 child_channel_id, u64 *out_status) {
  if (child_channel_id == 0ULL || out_status == 0) return -1;
  xaios_remote_login_session_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.session_id = child_channel_id;
  request.action = XAIOS_REMOTE_LOGIN_SESSION_CHILD_STATUS;
  request.out_size = (u64)out_status;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_REMOTE_LOGIN_SESSION, (u64)&request,
                          sizeof(request), 0);
  return (signed long long)rc < 0 ? (int)(signed long long)rc : 0;
}

int xaios_remote_login_child_cancel(u64 child_channel_id) {
  if (child_channel_id == 0ULL) return -1;
  xaios_remote_login_session_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.session_id = child_channel_id;
  request.action = XAIOS_REMOTE_LOGIN_SESSION_CHILD_CANCEL;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_REMOTE_LOGIN_SESSION, (u64)&request,
                          sizeof(request), 0);
  return (signed long long)rc < 0 ? (int)(signed long long)rc : 0;
}

int xaios_remote_login_child_release(u64 child_channel_id) {
  if (child_channel_id == 0ULL) return -1;
  xaios_remote_login_session_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.session_id = child_channel_id;
  request.action = XAIOS_REMOTE_LOGIN_SESSION_CHILD_RELEASE;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_REMOTE_LOGIN_SESSION, (u64)&request,
                          sizeof(request), 0);
  return (signed long long)rc < 0 ? (int)(signed long long)rc : 0;
}

int xaios_net_external_session(u64 protocol, u64 port, const void *payload,
                              u64 payload_size, char *output,
                              u64 output_size, u64 *out_size) {
  xaios_net_external_session_request_t request;
  request.protocol = protocol;
  request.port = port;
  request.payload = (u64)payload;
  request.payload_size = payload_size;
  request.output = (u64)output;
  request.output_size = output_size;
  request.out_size = (u64)out_size;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_EXTERNAL_SESSION, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_thread_group_run(u64 thread_count, u64 iterations, u64 *ran_threads,
                          u64 *checksum) {
  xaios_thread_group_request_t request;
  request.thread_count = thread_count;
  request.iterations = iterations;
  request.out_threads = (u64)ran_threads;
  request.out_checksum = (u64)checksum;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_THREAD_GROUP_RUN, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

extern void xaios_thread_return_trampoline(void);

int xaios_thread_create(xaios_thread_entry_t entry, void *argument,
                        void *stack, u64 stack_size, u64 preferred_cpu,
                        u64 *thread_id) {
  xaios_thread_create_request_t request;
  request.entry = (u64)entry;
  request.argument = (u64)argument;
  request.stack = (u64)stack;
  request.stack_size = stack_size;
  request.return_address = (u64)xaios_thread_return_trampoline;
  request.preferred_cpu = preferred_cpu;
  request.out_thread_id = (u64)thread_id;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_THREAD_CREATE, (u64)&request,
                          sizeof(request), 0);
  return rc == ~0ULL ? -1 : 0;
}

int xaios_thread_join(u64 thread_id, u64 timeout_ns, u64 *result) {
  xaios_thread_join_request_t request;
  request.thread_id = thread_id;
  request.timeout_ns = timeout_ns;
  request.out_result = (u64)result;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_THREAD_JOIN, (u64)&request,
                          sizeof(request), 0);
  return rc == ~0ULL ? -1 : 0;
}

int xaios_thread_cancel(u64 thread_id) {
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_THREAD_CANCEL, thread_id, 0, 0);
  return rc == ~0ULL ? -1 : 0;
}

int xaios_ml_run(u64 model_kind, const void *input, u64 input_size,
                char *output, u64 output_size, u64 *out_size) {
  xaios_ml_run_request_t request;
  request.model_kind = model_kind;
  request.input = (u64)input;
  request.input_size = input_size;
  request.output = (u64)output;
  request.output_size = output_size;
  request.out_size = (u64)out_size;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_ML_RUN, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_listen(u64 port, u64 *out_sockfd) {
  xaios_socket_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.port = port;
  request.out_sockfd = (u64)out_sockfd;
  request.protocol = XAIOS_NET_PROTOCOL_TCP;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_LISTEN, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_connect(const xaios_ip_addr_user_t *remote_addr, u64 port,
                      u64 *out_sockfd) {
  xaios_socket_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.port = port;
  request.out_sockfd = (u64)out_sockfd;
  request.addr_ptr = (u64)remote_addr;
  request.protocol = XAIOS_NET_PROTOCOL_TCP;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_CONNECT, (u64)&request,
                          sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_listen_addr(u64 port, const xaios_ip_addr_user_t *bind_addr,
                          u64 *out_sockfd) {
  xaios_socket_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.port = port;
  request.out_sockfd = (u64)out_sockfd;
  request.addr_ptr = (u64)bind_addr;
  request.protocol = XAIOS_NET_PROTOCOL_TCP;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_LISTEN, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_bind_udp(u64 port, u64 *out_sockfd) {
  xaios_socket_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.port = port;
  request.out_sockfd = (u64)out_sockfd;
  request.protocol = XAIOS_NET_PROTOCOL_UDP;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_LISTEN, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_accept(u64 sockfd, u64 *out_sockfd) {
  xaios_socket_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.sockfd = sockfd;
  request.out_sockfd = (u64)out_sockfd;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_ACCEPT, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_accept_addr(u64 sockfd, u64 *out_sockfd,
                          xaios_ip_addr_user_t *peer_addr, u64 *peer_port) {
  xaios_socket_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.sockfd = sockfd;
  request.out_sockfd = (u64)out_sockfd;
  request.addr_out_ptr = (u64)peer_addr;
  /* peer_port is written to request.port by kernel if provided */
  request.port = (u64)peer_port;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_ACCEPT, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_recv(u64 sockfd, void *buffer, u64 buffer_size, u64 *out_bytes) {
  xaios_socket_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.sockfd = sockfd;
  request.buffer = (u64)buffer;
  request.buffer_size = buffer_size;
  request.out_bytes = (u64)out_bytes;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_RECV, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_recvfrom(u64 sockfd, void *buffer, u64 buffer_size,
                       u64 *out_bytes, xaios_ip_addr_user_t *src_addr) {
  xaios_socket_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.sockfd = sockfd;
  request.buffer = (u64)buffer;
  request.buffer_size = buffer_size;
  request.out_bytes = (u64)out_bytes;
  request.addr_out_ptr = (u64)src_addr;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_RECV, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_send(u64 sockfd, const void *buffer, u64 buffer_size,
                  u64 *out_bytes) {
  xaios_socket_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.sockfd = sockfd;
  request.buffer = (u64)buffer;
  request.buffer_size = buffer_size;
  request.out_bytes = (u64)out_bytes;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_SEND, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_sendto(u64 sockfd, const void *buffer, u64 buffer_size,
                     u64 *out_bytes, const xaios_ip_addr_user_t *dst_addr) {
  xaios_socket_request_t request;
  xaios_memzero(&request, sizeof(request));
  request.sockfd = sockfd;
  request.buffer = (u64)buffer;
  request.buffer_size = buffer_size;
  request.out_bytes = (u64)out_bytes;
  request.addr_ptr = (u64)dst_addr;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_SEND, (u64)&request,
                         sizeof(request), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_net_close(u64 sockfd) {
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_CLOSE, sockfd, 0, 0);
  return rc == ~0ULL ? -1 : 0;
}

int xaios_net_resolve_address(const char *hostname, u32 family,
                              xaios_ip_addr_user_t *out_address) {
  if (hostname == 0 || out_address == 0 || (family != 4U && family != 6U))
    return -1;
  xaios_net_resolve_request_t request;
  request.hostname = (u64)hostname;
  request.hostname_size = xaios_strlen(hostname);
  request.out_address = (u64)out_address;
  request.family = family;
  /* DNS resolution advances through the kernel packet poller. Keep the
   * userspace ABI synchronous by driving pending work to completion rather
   * than exposing a one-shot XAIOS_ERR_BUSY result to every caller. */
  u64 deadline = xaios_clock_nanos() + 16000000000ULL;
  for (;;) {
    u64 rc = xaios_syscall3(XAIOS_SYSCALL_NET_RESOLVE, (u64)&request,
                            sizeof(request), 0);
    s64 status = (s64)rc;
    if (status != -5) return (int)status;
    if (xaios_clock_nanos() >= deadline) return -5;
  }
}

int xaios_net_resolve(const char *hostname, u32 *out_ipv4) {
  if (out_ipv4 == 0) return -1;
  xaios_ip_addr_user_t address;
  int status = xaios_net_resolve_address(hostname, 4U, &address);
  if (status == 0) {
    *out_ipv4 = ((u32)address.addr[0] << 24U) |
                ((u32)address.addr[1] << 16U) |
                ((u32)address.addr[2] << 8U) | address.addr[3];
  }
  return status;
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

int xaios_agent_dispatch(const xaios_agent_request_t *request,
                        xaios_agent_response_t *response,
                        const void *payload, u64 payload_size,
                        char *output, u64 output_size, u64 *out_size) {
  xaios_agent_dispatch_request_t req;
  req.request = (u64)request;
  req.request_size = sizeof(xaios_agent_request_t);
  req.response = (u64)response;
  req.response_size = sizeof(xaios_agent_response_t);
  req.payload = (u64)payload;
  req.payload_size = payload_size;
  req.output = (u64)output;
  req.output_size = output_size;
  req.out_size = (u64)out_size;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_AGENT_DISPATCH, (u64)&req,
                         sizeof(req), 0);
  return rc == ~0ULL ? -1 : (int)rc;
}

int xaios_control_query(const void *request, u64 request_size, void *response,
                        u64 response_size, u64 *out_size) {
  xaios_control_query_request_t query;
  query.request = (u64)request;
  query.request_size = request_size;
  query.response = (u64)response;
  query.response_size = response_size;
  query.out_size = (u64)out_size;
  u64 rc = xaios_syscall3(XAIOS_SYSCALL_CONTROL_QUERY, (u64)&query,
                         sizeof(query), 0);
  return rc == ~0ULL ? -1 : 0;
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
