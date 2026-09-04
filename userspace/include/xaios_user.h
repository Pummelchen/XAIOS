#ifndef XAIOS_USERSPACE_XAIOS_USER_H
#define XAIOS_USERSPACE_XAIOS_USER_H

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;
typedef int s32;
typedef long long s64;

#define XAIOS_BOOT_UI_CONTROL_MAGIC 0x58425549U
#define XAIOS_BOOT_UI_CONTROL_VERSION 3U
#define XAIOS_BOOT_UI_STAGE_SSH_LOADING 1U
#define XAIOS_BOOT_UI_STAGE_SSH_READY 2U
#define XAIOS_BOOT_UI_STAGE_SSH_FAILED 3U
#define XAIOS_BOOT_UI_CONSOLE_LOCKED 0U
#define XAIOS_BOOT_UI_CONSOLE_LOGIN 1U
#define XAIOS_BOOT_UI_CONSOLE_PASSWORD 2U
#define XAIOS_BOOT_UI_CONSOLE_SHELL 3U

typedef struct xaios_boot_ui_control {
  u32 magic;
  u32 version;
  u32 stage;
  s32 status;
  u32 ipv4;
  u32 console_state;
  u32 cursor_visible;
} xaios_boot_ui_control_t;

void *xaios_memcpy(void *dst, const void *src, u64 size);

#include <xaios_control.h>

#define XAIOS_ERR_UNSUPPORTED (-6)
#define XAIOS_ERR_BUSY (-5)

#define XAIOS_SYSCALL_LOG 1ULL
#define XAIOS_SYSCALL_EXIT 2ULL
#define XAIOS_SYSCALL_OSCTL 3ULL
#define XAIOS_SYSCALL_FS_OPEN 11ULL
#define XAIOS_SYSCALL_FS_READ 12ULL
#define XAIOS_SYSCALL_FS_WRITE 13ULL
#define XAIOS_SYSCALL_FS_CLOSE 14ULL
#define XAIOS_SYSCALL_FS_STAT 15ULL
#define XAIOS_SYSCALL_FS_MKDIR 16ULL
#define XAIOS_SYSCALL_FS_DELETE 17ULL
#define XAIOS_SYSCALL_FS_RENAME 18ULL
#define XAIOS_SYSCALL_FS_LIST 19ULL
#define XAIOS_SYSCALL_CLOCK_NANOS 20ULL
#define XAIOS_SYSCALL_NET_UDP_ECHO 21ULL
#define XAIOS_SYSCALL_NET_TCP_CONNECT 22ULL
#define XAIOS_SYSCALL_SMP_RUN 23ULL
#define XAIOS_SYSCALL_CPU_AI_DECODE 24ULL
#define XAIOS_SYSCALL_REMOTE_LOGIN 25ULL
#define XAIOS_SYSCALL_NET_EXTERNAL_SESSION 26ULL
#define XAIOS_SYSCALL_THREAD_GROUP_RUN 27ULL
#define XAIOS_SYSCALL_ML_RUN 28ULL
#define XAIOS_SYSCALL_NET_LISTEN 29ULL
#define XAIOS_SYSCALL_NET_ACCEPT 30ULL
#define XAIOS_SYSCALL_NET_RECV 31ULL
#define XAIOS_SYSCALL_NET_SEND 32ULL
#define XAIOS_SYSCALL_NET_CLOSE 33ULL
#define XAIOS_SYSCALL_AGENT_DISPATCH 34ULL
#define XAIOS_SYSCALL_RANDOM 35ULL
#define XAIOS_SYSCALL_FS_SEEK 36ULL
#define XAIOS_SYSCALL_CONTROL_QUERY 37ULL
#define XAIOS_SYSCALL_REMOTE_LOGIN_SESSION 38ULL
#define XAIOS_SYSCALL_FS_PREAD 39ULL
#define XAIOS_SYSCALL_FS_PWRITE 40ULL
#define XAIOS_SYSCALL_FS_FSYNC 41ULL
#define XAIOS_SYSCALL_THREAD_CREATE 42ULL
#define XAIOS_SYSCALL_THREAD_JOIN 43ULL
#define XAIOS_SYSCALL_THREAD_CANCEL 44ULL
#define XAIOS_SYSCALL_THREAD_EXIT 45ULL
#define XAIOS_SYSCALL_NET_RESOLVE 46ULL
#define XAIOS_SYSCALL_CONSOLE_READ 47ULL
#define XAIOS_SYSCALL_CONSOLE_WRITE 48ULL
#define XAIOS_SYSCALL_NET_LOCAL_IPV4 49ULL
#define XAIOS_SYSCALL_NET_CONNECT 50ULL
#define XAIOS_SYSCALL_NET_LOCAL_IPV6 51ULL
#define XAIOS_SYSCALL_CONSOLE_SIZE 52ULL
#define XAIOS_SYSCALL_SLEEP_NANOS 53ULL
#define XAIOS_SYSCALL_WAIT_EVENTS 54ULL
#define XAIOS_WAIT_EVENT_CONSOLE 1ULL
#define XAIOS_WAIT_EVENT_SOCKET 2ULL
#define XAIOS_WAIT_EVENT_CHILD 4ULL
#define XAIOS_THREAD_CPU_ANY (~0ULL)

#define XAIOS_CLOCK_MONOTONIC 0ULL
#define XAIOS_CLOCK_REALTIME 1ULL
#define XAIOS_CLOCK_PROCESS_CPU 2ULL

#define XAIOS_REMOTE_LOGIN_SESSION_EXECUTE 1ULL
#define XAIOS_REMOTE_LOGIN_SESSION_CLOSE 2ULL
#define XAIOS_REMOTE_LOGIN_SESSION_CHILD_OPEN 3ULL
#define XAIOS_REMOTE_LOGIN_SESSION_CHILD_WRITE 4ULL
#define XAIOS_REMOTE_LOGIN_SESSION_CHILD_READ 5ULL
#define XAIOS_REMOTE_LOGIN_SESSION_CHILD_STATUS 6ULL
#define XAIOS_REMOTE_LOGIN_SESSION_CHILD_CANCEL 7ULL
#define XAIOS_REMOTE_LOGIN_SESSION_CHILD_RELEASE 8ULL

#define XAIOS_CAP_STORAGE_READ 2097152ULL
#define XAIOS_CAP_STORAGE_MOUNT 4194304ULL
#define XAIOS_CAP_STORAGE_FORMAT 8388608ULL
#define XAIOS_CAP_STORAGE_PARTITION 16777216ULL
#define XAIOS_CAP_STORAGE_REPAIR 33554432ULL
#define XAIOS_CAP_STORAGE_RESIZE 67108864ULL
#define XAIOS_CAP_STORAGE_TRIM 134217728ULL
#define XAIOS_CAP_MODEL_STAGE 268435456ULL
#define XAIOS_CAP_MODEL_ACTIVATE 536870912ULL
#define XAIOS_CAP_CONSOLE 1073741824ULL
#define XAIOS_CAP_CREDENTIAL_READ 2147483648ULL

#define XAIOS_NET_PROTOCOL_UDP 17ULL
#define XAIOS_NET_PROTOCOL_TCP 6ULL
#define XAIOS_ML_MODEL_FIXTURE_DECODE 1ULL
#define XAIOS_ML_MODEL_XOR 2ULL
#define XAIOS_ML_MODEL_SUM 3ULL
#define XAIOS_ML_MODEL_PARITY 4ULL
#define XAIOS_ML_MODEL_MATMUL 5ULL
#define XAIOS_ML_MODEL_FORWARD 6ULL

#define XAIOS_AGENT_CMD_INFERENCE 1U
#define XAIOS_AGENT_CMD_INDEX_QUERY 2U
#define XAIOS_AGENT_CMD_GIT_STATUS 3U
#define XAIOS_AGENT_CMD_GIT_DIFF 4U
#define XAIOS_AGENT_CMD_BUILD 5U
#define XAIOS_AGENT_CMD_PING 6U

#define XAIOS_AGENT_STATUS_OK 0U
#define XAIOS_AGENT_STATUS_INVALID 1U
#define XAIOS_AGENT_STATUS_DENIED 2U
#define XAIOS_AGENT_STATUS_NOT_FOUND 3U
#define XAIOS_AGENT_STATUS_INTERNAL_ERROR 4U

#define XAIOS_XBFS_OPEN_READ 1U
#define XAIOS_XBFS_OPEN_WRITE 2U
#define XAIOS_XBFS_OPEN_CREATE 4U
#define XAIOS_XBFS_OPEN_TRUNCATE 8U
#define XAIOS_FS_TYPE_DIRECTORY 1U
#define XAIOS_FS_TYPE_FILE 2U

typedef struct xaios_xbfs_stat_user {
  u32 type;
  u32 block_count;
  u64 size;
  u64 generation;
  u64 content_hash;
} xaios_xbfs_stat_user_t;

typedef struct xaios_rename_request {
  u64 old_path;
  u64 old_path_len;
  u64 new_path;
  u64 new_path_len;
} xaios_rename_request_t;

typedef struct xaios_list_request {
  u64 buffer;
  u64 buffer_size;
  u64 out_size;
} xaios_list_request_t;

typedef struct xaios_positional_io_request {
  u64 fd;
  u64 buffer;
  u64 size;
  u64 offset;
} xaios_positional_io_request_t;

typedef struct xaios_net_request {
  u64 payload;
  u64 payload_size;
  u64 out_value;
} xaios_net_request_t;

typedef struct xaios_smp_request {
  u64 worker_count;
  u64 iterations;
  u64 out_workers;
  u64 out_checksum;
} xaios_smp_request_t;

typedef struct xaios_cpu_ai_decode_request {
  u64 input;
  u64 input_size;
  u64 output;
  u64 output_size;
  u64 out_size;
} xaios_cpu_ai_decode_request_t;

typedef struct xaios_remote_login_request {
  u64 user;
  u64 user_size;
  u64 command;
  u64 command_size;
  u64 output;
  u64 output_size;
  u64 out_size;
} xaios_remote_login_request_t;

typedef struct xaios_remote_login_session_request {
  u64 session_id;
  u64 action;
  u64 user;
  u64 user_size;
  u64 command;
  u64 command_size;
  u64 output;
  u64 output_size;
  u64 out_size;
  u64 metadata;
  u64 metadata_size;
} xaios_remote_login_session_request_t;

typedef struct xaios_net_external_session_request {
  u64 protocol;
  u64 port;
  u64 payload;
  u64 payload_size;
  u64 output;
  u64 output_size;
  u64 out_size;
} xaios_net_external_session_request_t;

typedef struct xaios_thread_group_request {
  u64 thread_count;
  u64 iterations;
  u64 out_threads;
  u64 out_checksum;
} xaios_thread_group_request_t;

typedef u64 (*xaios_thread_entry_t)(void *argument);

typedef struct xaios_thread_create_request {
  u64 entry;
  u64 argument;
  u64 stack;
  u64 stack_size;
  u64 return_address;
  u64 preferred_cpu;
  u64 out_thread_id;
} xaios_thread_create_request_t;

typedef struct xaios_thread_join_request {
  u64 thread_id;
  u64 timeout_ns;
  u64 out_result;
} xaios_thread_join_request_t;

typedef struct xaios_ml_run_request {
  u64 model_kind;
  u64 input;
  u64 input_size;
  u64 output;
  u64 output_size;
  u64 out_size;
} xaios_ml_run_request_t;

/* Userspace mirror of kernel xaios_ip_addr_t for dual-stack IPv4/IPv6 */
typedef struct xaios_ip_addr_user {
  unsigned char family;    /* 4 = IPv4, 6 = IPv6 */
  unsigned char addr[16];  /* IPv4 in bytes 0-3, IPv6 full 16 bytes */
} xaios_ip_addr_user_t;

typedef struct xaios_socket_request {
  u64 sockfd;
  u64 port;
  u64 buffer;
  u64 buffer_size;
  u64 out_bytes;
  u64 out_sockfd;
  /* IPv6 dual-stack: pointer to xaios_ip_addr_user_t for bind/peer address */
  u64 addr_ptr;
  u64 addr_out_ptr;
  u64 protocol;
} xaios_socket_request_t;

typedef struct xaios_net_resolve_request {
  u64 hostname;
  u64 hostname_size;
  u64 out_address;
  u64 family;
} xaios_net_resolve_request_t;

typedef struct xaios_agent_request {
  u32 magic;
  u32 version;
  u32 command;
  u32 cell_id;
  u64 payload_size;
  unsigned char reserved[104];
} xaios_agent_request_t;

typedef struct xaios_agent_response {
  u32 magic;
  u32 version;
  u32 status;
  u32 command;
  u64 payload_size;
  unsigned char reserved[104];
} xaios_agent_response_t;

typedef struct xaios_agent_dispatch_request {
  u64 request;
  u64 request_size;
  u64 response;
  u64 response_size;
  u64 payload;
  u64 payload_size;
  u64 output;
  u64 output_size;
  u64 out_size;
} xaios_agent_dispatch_request_t;

typedef struct xaios_control_query_request {
  u64 request;
  u64 request_size;
  u64 response;
  u64 response_size;
  u64 out_size;
} xaios_control_query_request_t;

u64 xaios_syscall3(u64 number, u64 arg0, u64 arg1, u64 arg2);
u64 xaios_strlen(const char *text);
void xaios_log(const char *text);
void xaios_log_u64(const char *prefix, u64 value, const char *suffix);
void xaios_exit(int code);
u64 xaios_clock_nanos(void);
u64 xaios_clock_nanos_kind(u64 kind);
int xaios_random(void *buffer, u64 size);
int xaios_osctl(const char *command);
int xaios_fs_mkdir(const char *path);
int xaios_fs_delete(const char *path);
int xaios_fs_rename(const char *old_path, const char *new_path);
int xaios_fs_list(const char *path, char *buffer, u64 buffer_size, u64 *out_size);
int xaios_fs_open(const char *path, u32 flags);
int xaios_fs_read(int fd, void *buffer, u64 size);
int xaios_fs_write(int fd, const void *buffer, u64 size);
s64 xaios_fs_pread(int fd, void *buffer, u64 size, u64 offset);
s64 xaios_fs_pwrite(int fd, const void *buffer, u64 size, u64 offset);
int xaios_fs_fsync(int fd);
int xaios_fs_seek(int fd, u64 offset);
int xaios_fs_close(int fd);
int xaios_fs_stat(const char *path, xaios_xbfs_stat_user_t *stat);
int xaios_net_udp_echo(const void *payload, u64 payload_size, u64 *echoed_bytes);
int xaios_net_tcp_connect(u64 *round_trips);
int xaios_smp_run(u64 worker_count, u64 iterations, u64 *ran_workers,
                 u64 *checksum);
int xaios_cpu_ai_decode(const void *input, u64 input_size, char *output,
                       u64 output_size, u64 *out_size);
int xaios_remote_login(const char *user, const char *command, char *output,
                      u64 output_size, u64 *out_size);
int xaios_remote_login_session(u64 session_id, const char *user,
                               const char *command, char *output,
                               u64 output_size, u64 *out_size);
int xaios_remote_login_session_close(u64 session_id);
int xaios_remote_login_child_open(u64 session_id, const char *command,
                                  const char *cwd, u64 *child_channel_id);
int xaios_remote_login_child_write(u64 child_channel_id, const void *data,
                                   u64 data_size);
int xaios_remote_login_child_read(u64 child_channel_id, void *data,
                                  u64 data_size, u64 *out_size);
int xaios_remote_login_child_status(u64 child_channel_id, u64 *out_status);
int xaios_remote_login_child_cancel(u64 child_channel_id);
int xaios_remote_login_child_release(u64 child_channel_id);
int xaios_console_read(char *value);
/* The kernel accepts at most this many bytes in one console write; the
   wrapper below splits a longer buffer into calls of this size. */
#define XAIOS_CONSOLE_WRITE_MAX 4096ULL
int xaios_console_write(const char *buffer, u64 size);
/* The console's size in character cells, or zero when the console cannot say
   -- a serial line has no size to report and the caller keeps its own
   default. A framebuffer console does know, and a program that asks renders
   to the whole screen instead of to a guessed eighty columns in the corner
   of it. */
int xaios_console_size(u32 *columns, u32 *rows);
/* Give the CPU up for at least this long (at most one second per call).
   The one sleep a user process has: everything that waited by polling a
   clock, or by asking for a runtime snapshot with a wait in it, burned a
   core to do nothing. Requires XAIOS_CAP_TIME. */
int xaios_sleep_ns(u64 nanoseconds);
/* Block until there is console input, a packet or connection on a socket
   this process owns, or output or an exit from a child it started -- or
   until the timeout (at most one second) passes. Returns the
   XAIOS_WAIT_EVENT_* bits that ended the wait, zero for the timeout, -1
   when refused. A server that polls non-blocking calls in a loop spins a
   core; one that waits here is idle between events. */
int xaios_wait_events(u64 timeout_ns);
u32 xaios_net_local_ipv4(void);
/* Copies the public IPv6 address out and returns 1, or returns 0 when the
   guest has no public IPv6 address configured. */
int xaios_net_local_ipv6(u8 address[16]);
int xaios_net_external_session(u64 protocol, u64 port, const void *payload,
                              u64 payload_size, char *output,
                              u64 output_size, u64 *out_size);
int xaios_thread_group_run(u64 thread_count, u64 iterations, u64 *ran_threads,
                          u64 *checksum);
int xaios_thread_create(xaios_thread_entry_t entry, void *argument,
                        void *stack, u64 stack_size, u64 preferred_cpu,
                        u64 *thread_id);
int xaios_thread_join(u64 thread_id, u64 timeout_ns, u64 *result);
int xaios_thread_cancel(u64 thread_id);
int xaios_ml_run(u64 model_kind, const void *input, u64 input_size,
                char *output, u64 output_size, u64 *out_size);
int xaios_net_listen(u64 port, u64 *out_sockfd);
int xaios_net_connect(const xaios_ip_addr_user_t *remote_addr, u64 port,
                      u64 *out_sockfd);
int xaios_net_listen_addr(u64 port, const xaios_ip_addr_user_t *bind_addr,
                          u64 *out_sockfd);
int xaios_net_bind_udp(u64 port, u64 *out_sockfd);
int xaios_net_accept(u64 sockfd, u64 *out_sockfd);
int xaios_net_accept_addr(u64 sockfd, u64 *out_sockfd,
                          xaios_ip_addr_user_t *peer_addr, u64 *peer_port);
int xaios_net_recv(u64 sockfd, void *buffer, u64 buffer_size, u64 *out_bytes);
int xaios_net_recvfrom(u64 sockfd, void *buffer, u64 buffer_size,
                       u64 *out_bytes, xaios_ip_addr_user_t *src_addr);
int xaios_net_send(u64 sockfd, const void *buffer, u64 buffer_size,
                  u64 *out_bytes);
int xaios_net_sendto(u64 sockfd, const void *buffer, u64 buffer_size,
                     u64 *out_bytes, const xaios_ip_addr_user_t *dst_addr);
int xaios_net_close(u64 sockfd);
int xaios_net_resolve(const char *hostname, u32 *out_ipv4);
int xaios_net_resolve_address(const char *hostname, u32 family,
                              xaios_ip_addr_user_t *out_address);
int xaios_write_file(const char *path, const char *content);
int xaios_read_file(const char *path, char *buffer, u64 buffer_size);
void xaios_memzero(void *buffer, u64 size);
void xaios_append_u64(char *buffer, u64 capacity, u64 *offset, u64 value);
void xaios_append_cstr(char *buffer, u64 capacity, u64 *offset, const char *text);
int xaios_agent_dispatch(const xaios_agent_request_t *request,
                        xaios_agent_response_t *response,
                        const void *payload, u64 payload_size,
                        char *output, u64 output_size, u64 *out_size);
int xaios_control_query(const void *request, u64 request_size, void *response,
                        u64 response_size, u64 *out_size);

#endif
