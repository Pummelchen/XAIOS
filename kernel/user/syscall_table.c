/*
 * The syscall table. See syscall_table.h.
 */

#include "syscall_table.h"

#include <xaios/control_protocol.h>
#include <xaios/vmm.h>

static const xaios_syscall_entry_t g_syscall_table[] = {
    {XAIOS_SYSCALL_LOG, "log", XAIOS_CAP_LOG},
    {XAIOS_SYSCALL_EXIT, "exit", XAIOS_CAP_EXIT},
    {XAIOS_SYSCALL_OSCTL, "osctl", XAIOS_CAP_OSCTL},
    {XAIOS_SYSCALL_READ_SERVICE_DESCRIPTOR, "read_service_descriptor",
     XAIOS_CAP_FS_READ},
    {XAIOS_SYSCALL_SERVICE_STATUS, "service_status",
     XAIOS_CAP_SERVICE_CONTROL},
    {XAIOS_SYSCALL_SERVICE_START, "service_start", XAIOS_CAP_SERVICE_CONTROL},
    {XAIOS_SYSCALL_SERVICE_STOP, "service_stop", XAIOS_CAP_SERVICE_CONTROL},
    {XAIOS_SYSCALL_SERVICE_RESTART, "service_restart",
     XAIOS_CAP_SERVICE_CONTROL},
    {XAIOS_SYSCALL_SERVICE_ROLLBACK, "service_rollback",
     XAIOS_CAP_SERVICE_ROLLBACK},
    {XAIOS_SYSCALL_SERVICE_UPDATE, "service_update", XAIOS_CAP_UPDATE},
    {XAIOS_SYSCALL_FS_OPEN, "fs_open", XAIOS_CAP_FS_READ},
    {XAIOS_SYSCALL_FS_READ, "fs_read", XAIOS_CAP_FS_READ},
    {XAIOS_SYSCALL_FS_WRITE, "fs_write", XAIOS_CAP_FS_WRITE},
    {XAIOS_SYSCALL_FS_CLOSE, "fs_close", XAIOS_CAP_FS_READ},
    {XAIOS_SYSCALL_FS_STAT, "fs_stat", XAIOS_CAP_FS_READ},
    {XAIOS_SYSCALL_FS_MKDIR, "fs_mkdir", XAIOS_CAP_FS_WRITE},
    {XAIOS_SYSCALL_FS_DELETE, "fs_delete", XAIOS_CAP_FS_WRITE},
    {XAIOS_SYSCALL_FS_RENAME, "fs_rename", XAIOS_CAP_FS_WRITE},
    {XAIOS_SYSCALL_FS_LIST, "fs_list", XAIOS_CAP_FS_READ},
    {XAIOS_SYSCALL_CLOCK_NANOS, "clock_nanos", XAIOS_CAP_TIME},
    {XAIOS_SYSCALL_NET_UDP_ECHO, "net_udp_echo", XAIOS_CAP_NET},
    {XAIOS_SYSCALL_NET_TCP_CONNECT, "net_tcp_connect", XAIOS_CAP_NET},
    {XAIOS_SYSCALL_SMP_RUN, "smp_run", XAIOS_CAP_SMP},
    {XAIOS_SYSCALL_CPU_AI_DECODE, "cpu_ai_decode", XAIOS_CAP_CPU_AI},
    {XAIOS_SYSCALL_REMOTE_LOGIN, "remote_login", XAIOS_CAP_REMOTE_LOGIN},
    {XAIOS_SYSCALL_NET_EXTERNAL_SESSION, "net_external_session", XAIOS_CAP_NET},
    {XAIOS_SYSCALL_THREAD_GROUP_RUN, "thread_group_run", XAIOS_CAP_THREADS},
    {XAIOS_SYSCALL_ML_RUN, "ml_run", XAIOS_CAP_ML},
    {XAIOS_SYSCALL_NET_LISTEN, "net_listen", XAIOS_CAP_NET_SOCKET},
    {XAIOS_SYSCALL_NET_ACCEPT, "net_accept", XAIOS_CAP_NET_SOCKET},
    {XAIOS_SYSCALL_NET_RECV, "net_recv", XAIOS_CAP_NET_SOCKET},
    {XAIOS_SYSCALL_NET_SEND, "net_send", XAIOS_CAP_NET_SOCKET},
    {XAIOS_SYSCALL_NET_CLOSE, "net_close", XAIOS_CAP_NET_SOCKET},
    {XAIOS_SYSCALL_AGENT_DISPATCH, "agent_dispatch", XAIOS_CAP_AGENT},
    {XAIOS_SYSCALL_RANDOM, "random", XAIOS_CAP_RANDOM},
    {XAIOS_SYSCALL_FS_SEEK, "fs_seek", XAIOS_CAP_FS_READ},
    {XAIOS_SYSCALL_CONTROL_QUERY, "control_query", XAIOS_CAP_CONTROL_QUERY},
    {XAIOS_SYSCALL_REMOTE_LOGIN_SESSION, "remote_login_session",
     XAIOS_CAP_REMOTE_LOGIN},
    {XAIOS_SYSCALL_FS_PREAD, "fs_pread", XAIOS_CAP_FS_READ},
    {XAIOS_SYSCALL_FS_PWRITE, "fs_pwrite", XAIOS_CAP_FS_WRITE},
    {XAIOS_SYSCALL_FS_FSYNC, "fs_fsync", XAIOS_CAP_FS_WRITE},
    {XAIOS_SYSCALL_THREAD_CREATE, "thread_create", XAIOS_CAP_THREADS},
    {XAIOS_SYSCALL_THREAD_JOIN, "thread_join", XAIOS_CAP_THREADS},
    {XAIOS_SYSCALL_THREAD_CANCEL, "thread_cancel", XAIOS_CAP_THREADS},
    {XAIOS_SYSCALL_THREAD_EXIT, "thread_exit", XAIOS_CAP_THREADS},
    {XAIOS_SYSCALL_NET_RESOLVE, "net_resolve", XAIOS_CAP_NET},
    {XAIOS_SYSCALL_CONSOLE_READ, "console_read", XAIOS_CAP_CONSOLE},
    {XAIOS_SYSCALL_CONSOLE_WRITE, "console_write", XAIOS_CAP_CONSOLE},
    {XAIOS_SYSCALL_CONSOLE_SIZE, "console_size", XAIOS_CAP_CONSOLE},
    {XAIOS_SYSCALL_SLEEP_NANOS, "sleep_nanos", XAIOS_CAP_TIME},
    {XAIOS_SYSCALL_WAIT_EVENTS, "wait_events", XAIOS_CAP_TIME},
    {XAIOS_SYSCALL_NET_LOCAL_IPV4, "net_local_ipv4", XAIOS_CAP_NET},
    {XAIOS_SYSCALL_NET_CONNECT, "net_connect", XAIOS_CAP_NET_SOCKET},
    {XAIOS_SYSCALL_NET_OPEN_UDP, "net_open_udp", XAIOS_CAP_NET_SOCKET},
    {XAIOS_SYSCALL_NET_LOCAL_IPV6, "net_local_ipv6", XAIOS_CAP_NET},
};

uint64_t syscall_table_control_operation_capability(uint16_t operation) {
  if (operation >= XAIOS_CONTROL_OP_APP_ACTIVATE &&
      operation <= XAIOS_CONTROL_OP_SYSTEM_UPDATE_ABORT) {
    return XAIOS_CAP_UPDATE | XAIOS_CAP_ADMIN;
  }
  if (operation == XAIOS_CONTROL_OP_MODEL_VERIFY ||
      operation == XAIOS_CONTROL_OP_MODEL_REGISTER ||
      operation == XAIOS_CONTROL_OP_MODEL_CLEANUP) {
    return XAIOS_CAP_MODEL_STAGE;
  }
  if (operation == XAIOS_CONTROL_OP_MODEL_ACTIVATE) {
    return XAIOS_CAP_MODEL_ACTIVATE;
  }
  if ((operation >= XAIOS_CONTROL_OP_STORAGE_DEVICE_LIST &&
       operation <= XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_CREATE) ||
      operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_DELETE ||
      operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_PLAN_RESIZE) {
    return XAIOS_CAP_STORAGE_READ;
  }
  if (operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_CREATE ||
      operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_DELETE) {
    return XAIOS_CAP_STORAGE_PARTITION;
  }
  if (operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_RESIZE) {
    return XAIOS_CAP_STORAGE_PARTITION | XAIOS_CAP_STORAGE_RESIZE;
  }
  if (operation == XAIOS_CONTROL_OP_STORAGE_PARTITION_REPAIR) {
    return XAIOS_CAP_STORAGE_PARTITION | XAIOS_CAP_STORAGE_REPAIR;
  }
  if (operation == XAIOS_CONTROL_OP_STORAGE_FORMAT_PLAN ||
      operation == XAIOS_CONTROL_OP_STORAGE_FSCK ||
      operation == XAIOS_CONTROL_OP_STORAGE_FS_RESIZE_PLAN) {
    return XAIOS_CAP_STORAGE_READ;
  }
  if (operation == XAIOS_CONTROL_OP_STORAGE_FORMAT) {
    return XAIOS_CAP_STORAGE_FORMAT;
  }
  if (operation == XAIOS_CONTROL_OP_STORAGE_MOUNT ||
      operation == XAIOS_CONTROL_OP_STORAGE_UNMOUNT) {
    return XAIOS_CAP_STORAGE_MOUNT;
  }
  if (operation == XAIOS_CONTROL_OP_STORAGE_FS_REPAIR) {
    return XAIOS_CAP_STORAGE_REPAIR;
  }
  if (operation == XAIOS_CONTROL_OP_STORAGE_FS_RESIZE) {
    return XAIOS_CAP_STORAGE_RESIZE;
  }
  if (operation == XAIOS_CONTROL_OP_STORAGE_SCRUB_STATUS) {
    return XAIOS_CAP_STORAGE_READ;
  }
  if (operation >= XAIOS_CONTROL_OP_STORAGE_SCRUB_START &&
      operation <= XAIOS_CONTROL_OP_STORAGE_SCRUB_CANCEL) {
    return XAIOS_CAP_STORAGE_REPAIR;
  }
  if (operation == XAIOS_CONTROL_OP_STORAGE_TRIM_STATUS) {
    return XAIOS_CAP_STORAGE_READ;
  }
  if (operation == XAIOS_CONTROL_OP_STORAGE_TRIM_START ||
      operation == XAIOS_CONTROL_OP_STORAGE_TRIM_CANCEL) {
    return XAIOS_CAP_STORAGE_TRIM;
  }
  return 0U;
}

const xaios_syscall_entry_t *syscall_table_lookup(uint64_t number) {
  for (uint32_t i = 0; i < sizeof(g_syscall_table) / sizeof(g_syscall_table[0]);
       ++i) {
    if (g_syscall_table[i].number == number) {
      return &g_syscall_table[i];
    }
  }
  return 0;
}

uint64_t syscall_table_entry_count(void) {
  return (uint64_t)(sizeof(g_syscall_table) / sizeof(g_syscall_table[0]));
}

xaios_status_t syscall_table_copy_user_string(uint64_t user_ptr, uint64_t length,
                                              char *buffer,
                                              uint64_t buffer_size) {
  if (length == 0 || length >= buffer_size ||
      vmm_validate_user_buffer(user_ptr, length, 0) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  const char *src = (const char *)(uintptr_t)user_ptr;
  for (uint64_t i = 0; i < length; ++i) {
    buffer[i] = src[i];
  }
  buffer[length] = '\0';
  return XAIOS_OK;
}

void syscall_table_format_u64_decimal(uint64_t value, char output[21]) {
  char reverse[20];
  uint32_t count = 0U;
  do {
    reverse[count++] = (char)('0' + (value % 10U));
    value /= 10U;
  } while (value != 0U);
  for (uint32_t i = 0U; i < count; ++i) output[i] = reverse[count - i - 1U];
  output[count] = '\0';
}

int syscall_table_command_starts_with(const char *command, const char *name) {
  uint32_t offset = 0U;
  uint32_t index = 0U;
  while (command[offset] == ' ' || command[offset] == '\t') ++offset;
  while (name[index] != '\0') {
    if (command[offset + index] != name[index]) return 0;
    ++index;
  }
  return command[offset + index] == '\0' || command[offset + index] == ' ' ||
         command[offset + index] == '\t';
}

int syscall_table_path_equal(const char *left, const char *right) {
  uint32_t index = 0U;
  while (left[index] != '\0' && right[index] != '\0') {
    if (left[index] != right[index]) return 0;
    ++index;
  }
  return left[index] == right[index];
}
