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

uint64_t syscall_dispatch(uint64_t syscall, uint64_t arg0, uint64_t arg1,
                          uint64_t arg2);
void syscall_self_test(void);
uint64_t syscall_control_plane_count(void);
uint64_t syscall_control_plane_denial_count(void);
uint64_t syscall_service_descriptor_read_count(void);

#endif
