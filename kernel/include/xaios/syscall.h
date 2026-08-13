#ifndef XAIOS_SYSCALL_H
#define XAIOS_SYSCALL_H

#include <xaios/status.h>
#include <xaios/types.h>

#define XAIOS_SYSCALL_LOG UINT64_C(1)
#define XAIOS_SYSCALL_EXIT UINT64_C(2)
#define XAIOS_SYSCALL_OSCTL UINT64_C(3)
#define XAIOS_SYSCALL_READ_SERVICE_DESCRIPTOR UINT64_C(4)
#define XAIOS_SYSCALL_SERVICE_STATUS UINT64_C(5)
#define XAIOS_SYSCALL_SERVICE_START UINT64_C(6)
#define XAIOS_SYSCALL_SERVICE_STOP UINT64_C(7)
#define XAIOS_SYSCALL_SERVICE_RESTART UINT64_C(8)
#define XAIOS_SYSCALL_SERVICE_ROLLBACK UINT64_C(9)
#define XAIOS_SYSCALL_SERVICE_UPDATE UINT64_C(10)
#define XAIOS_SYSCALL_FS_OPEN UINT64_C(11)
#define XAIOS_SYSCALL_FS_READ UINT64_C(12)
#define XAIOS_SYSCALL_FS_WRITE UINT64_C(13)
#define XAIOS_SYSCALL_FS_CLOSE UINT64_C(14)
#define XAIOS_SYSCALL_FS_STAT UINT64_C(15)
#define XAIOS_SYSCALL_FS_MKDIR UINT64_C(16)
#define XAIOS_SYSCALL_FS_DELETE UINT64_C(17)
#define XAIOS_SYSCALL_FS_RENAME UINT64_C(18)
#define XAIOS_SYSCALL_FS_LIST UINT64_C(19)
#define XAIOS_SYSCALL_CLOCK_NANOS UINT64_C(20)
#define XAIOS_SYSCALL_NET_UDP_ECHO UINT64_C(21)
#define XAIOS_SYSCALL_NET_TCP_CONNECT UINT64_C(22)
#define XAIOS_SYSCALL_SMP_RUN UINT64_C(23)
#define XAIOS_SYSCALL_CPU_AI_DECODE UINT64_C(24)
#define XAIOS_SYSCALL_REMOTE_LOGIN UINT64_C(25)
#define XAIOS_SYSCALL_NET_EXTERNAL_SESSION UINT64_C(26)
#define XAIOS_SYSCALL_THREAD_GROUP_RUN UINT64_C(27)
#define XAIOS_SYSCALL_ML_RUN UINT64_C(28)
#define XAIOS_SYSCALL_NET_LISTEN UINT64_C(29)
#define XAIOS_SYSCALL_NET_ACCEPT UINT64_C(30)
#define XAIOS_SYSCALL_NET_RECV UINT64_C(31)
#define XAIOS_SYSCALL_NET_SEND UINT64_C(32)
#define XAIOS_SYSCALL_NET_CLOSE UINT64_C(33)
#define XAIOS_SYSCALL_AGENT_DISPATCH UINT64_C(34)
#define XAIOS_SYSCALL_RANDOM UINT64_C(35)
#define XAIOS_SYSCALL_FS_SEEK UINT64_C(36)
#define XAIOS_SYSCALL_CONTROL_QUERY UINT64_C(37)
#define XAIOS_SYSCALL_REMOTE_LOGIN_SESSION UINT64_C(38)
#define XAIOS_SYSCALL_FS_PREAD UINT64_C(39)
#define XAIOS_SYSCALL_FS_PWRITE UINT64_C(40)
#define XAIOS_SYSCALL_FS_FSYNC UINT64_C(41)
#define XAIOS_SYSCALL_THREAD_CREATE UINT64_C(42)
#define XAIOS_SYSCALL_THREAD_JOIN UINT64_C(43)
#define XAIOS_SYSCALL_THREAD_CANCEL UINT64_C(44)
#define XAIOS_SYSCALL_THREAD_EXIT UINT64_C(45)
#define XAIOS_SYSCALL_NET_RESOLVE UINT64_C(46)
#define XAIOS_SYSCALL_CONSOLE_READ UINT64_C(47)
#define XAIOS_SYSCALL_CONSOLE_WRITE UINT64_C(48)
#define XAIOS_SYSCALL_NET_LOCAL_IPV4 UINT64_C(49)
#define XAIOS_SYSCALL_NET_CONNECT UINT64_C(50)

#define XAIOS_CLOCK_MONOTONIC UINT64_C(0)
#define XAIOS_CLOCK_REALTIME UINT64_C(1)
#define XAIOS_CLOCK_PROCESS_CPU UINT64_C(2)

#define XAIOS_CAP_LOG UINT64_C(1)
#define XAIOS_CAP_EXIT UINT64_C(2)
#define XAIOS_CAP_OSCTL UINT64_C(4)
#define XAIOS_CAP_SERVICE_ROLLBACK UINT64_C(8)
#define XAIOS_CAP_UPDATE UINT64_C(16)
#define XAIOS_CAP_FS_READ UINT64_C(32)
#define XAIOS_CAP_SERVICE_CONTROL UINT64_C(64)
#define XAIOS_CAP_ADMIN UINT64_C(128)
#define XAIOS_CAP_FS_WRITE UINT64_C(256)
#define XAIOS_CAP_TIME UINT64_C(512)
#define XAIOS_CAP_NET UINT64_C(1024)
#define XAIOS_CAP_SMP UINT64_C(2048)
#define XAIOS_CAP_CPU_AI UINT64_C(4096)
#define XAIOS_CAP_REMOTE_LOGIN UINT64_C(8192)
#define XAIOS_CAP_THREADS UINT64_C(16384)
#define XAIOS_CAP_ML UINT64_C(32768)
#define XAIOS_CAP_NET_SOCKET UINT64_C(65536)
#define XAIOS_CAP_AGENT UINT64_C(131072)
#define XAIOS_CAP_RANDOM UINT64_C(262144)
#define XAIOS_CAP_CONTROL_QUERY UINT64_C(524288)
#define XAIOS_CAP_CONTROL_ADMIN UINT64_C(1048576)
#define XAIOS_CAP_STORAGE_READ UINT64_C(2097152)
#define XAIOS_CAP_STORAGE_MOUNT UINT64_C(4194304)
#define XAIOS_CAP_STORAGE_FORMAT UINT64_C(8388608)
#define XAIOS_CAP_STORAGE_PARTITION UINT64_C(16777216)
#define XAIOS_CAP_STORAGE_REPAIR UINT64_C(33554432)
#define XAIOS_CAP_STORAGE_RESIZE UINT64_C(67108864)
#define XAIOS_CAP_STORAGE_TRIM UINT64_C(134217728)
#define XAIOS_CAP_MODEL_STAGE UINT64_C(268435456)
#define XAIOS_CAP_MODEL_ACTIVATE UINT64_C(536870912)
#define XAIOS_CAP_CONSOLE UINT64_C(1073741824)
#define XAIOS_CAP_CREDENTIAL_READ UINT64_C(2147483648)

#define XAIOS_REMOTE_LOGIN_SESSION_EXECUTE UINT64_C(1)
#define XAIOS_REMOTE_LOGIN_SESSION_CLOSE UINT64_C(2)
#define XAIOS_REMOTE_LOGIN_SESSION_CHILD_OPEN UINT64_C(3)
#define XAIOS_REMOTE_LOGIN_SESSION_CHILD_WRITE UINT64_C(4)
#define XAIOS_REMOTE_LOGIN_SESSION_CHILD_READ UINT64_C(5)
#define XAIOS_REMOTE_LOGIN_SESSION_CHILD_STATUS UINT64_C(6)
#define XAIOS_REMOTE_LOGIN_SESSION_CHILD_CANCEL UINT64_C(7)
#define XAIOS_REMOTE_LOGIN_SESSION_CHILD_RELEASE UINT64_C(8)

typedef struct xaios_syscall_rename_request {
  uint64_t old_path;
  uint64_t old_path_len;
  uint64_t new_path;
  uint64_t new_path_len;
} xaios_syscall_rename_request_t;

typedef struct xaios_syscall_list_request {
  uint64_t buffer;
  uint64_t buffer_size;
  uint64_t out_size;
} xaios_syscall_list_request_t;

typedef struct xaios_syscall_positional_io_request {
  uint64_t fd;
  uint64_t buffer;
  uint64_t size;
  uint64_t offset;
} xaios_syscall_positional_io_request_t;

typedef struct xaios_syscall_net_request {
  uint64_t payload;
  uint64_t payload_size;
  uint64_t out_value;
} xaios_syscall_net_request_t;

typedef struct xaios_syscall_smp_request {
  uint64_t worker_count;
  uint64_t iterations;
  uint64_t out_workers;
  uint64_t out_checksum;
} xaios_syscall_smp_request_t;

typedef struct xaios_syscall_cpu_ai_decode_request {
  uint64_t input;
  uint64_t input_size;
  uint64_t output;
  uint64_t output_size;
  uint64_t out_size;
} xaios_syscall_cpu_ai_decode_request_t;

typedef struct xaios_syscall_remote_login_request {
  uint64_t user;
  uint64_t user_size;
  uint64_t command;
  uint64_t command_size;
  uint64_t output;
  uint64_t output_size;
  uint64_t out_size;
} xaios_syscall_remote_login_request_t;

typedef struct xaios_syscall_remote_login_session_request {
  uint64_t session_id;
  uint64_t action;
  uint64_t user;
  uint64_t user_size;
  uint64_t command;
  uint64_t command_size;
  uint64_t output;
  uint64_t output_size;
  uint64_t out_size;
  uint64_t metadata;
  uint64_t metadata_size;
} xaios_syscall_remote_login_session_request_t;

typedef struct xaios_syscall_net_external_session_request {
  uint64_t protocol;
  uint64_t port;
  uint64_t payload;
  uint64_t payload_size;
  uint64_t output;
  uint64_t output_size;
  uint64_t out_size;
} xaios_syscall_net_external_session_request_t;

typedef struct xaios_syscall_thread_group_request {
  uint64_t thread_count;
  uint64_t iterations;
  uint64_t out_threads;
  uint64_t out_checksum;
} xaios_syscall_thread_group_request_t;

typedef struct xaios_syscall_thread_create_request {
  uint64_t entry;
  uint64_t argument;
  uint64_t stack;
  uint64_t stack_size;
  uint64_t return_address;
  uint64_t preferred_cpu;
  uint64_t out_thread_id;
} xaios_syscall_thread_create_request_t;

typedef struct xaios_syscall_thread_join_request {
  uint64_t thread_id;
  uint64_t timeout_ns;
  uint64_t out_result;
} xaios_syscall_thread_join_request_t;

typedef struct xaios_syscall_ml_run_request {
  uint64_t model_kind;
  uint64_t input;
  uint64_t input_size;
  uint64_t output;
  uint64_t output_size;
  uint64_t out_size;
} xaios_syscall_ml_run_request_t;

typedef struct xaios_syscall_socket_request {
  uint64_t sockfd;
  uint64_t port;
  uint64_t buffer;
  uint64_t buffer_size;
  uint64_t out_bytes;
  uint64_t out_sockfd;
  /* IPv6 dual-stack: pointer to xaios_ip_addr_t for bind/peer address */
  uint64_t addr_ptr;
  uint64_t addr_out_ptr;
  uint64_t protocol;
} xaios_syscall_socket_request_t;

typedef struct xaios_syscall_net_resolve_request {
  uint64_t hostname;
  uint64_t hostname_size;
  uint64_t out_address;
  uint64_t family;
} xaios_syscall_net_resolve_request_t;

typedef struct xaios_syscall_agent_dispatch_request {
  uint64_t request;
  uint64_t request_size;
  uint64_t response;
  uint64_t response_size;
  uint64_t payload;
  uint64_t payload_size;
  uint64_t output;
  uint64_t output_size;
  uint64_t out_size;
} xaios_syscall_agent_dispatch_request_t;

typedef struct xaios_syscall_control_query_request {
  uint64_t request;
  uint64_t request_size;
  uint64_t response;
  uint64_t response_size;
  uint64_t out_size;
} xaios_syscall_control_query_request_t;

uint64_t syscall_dispatch(uint64_t syscall, uint64_t arg0, uint64_t arg1,
                          uint64_t arg2);
void syscall_self_test(void);
void syscall_release_process_resources(uint32_t owner_pid);
uint64_t syscall_control_plane_count(void);
uint64_t syscall_control_plane_denial_count(void);
uint64_t syscall_service_descriptor_read_count(void);

#endif
