#include <xaios/agent_protocol.h>
#include <xaios/arena.h>
#include <xaios/assert.h>
#include <xaios/cpu_ai_runtime.h>
#include <xaios/control_protocol.h>
#include <xaios/dns.h>
#include <xaios/initramfs.h>
#include <xaios/ipv4.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/mutable_fs.h>
#include <xaios/network_stack.h>
#include <xaios/remote_login.h>
#include <xaios/security.h>
#include <xaios/service.h>
#include <xaios/smp.h>
#include <xaios/socket_buffer.h>
#include <xaios/spinlock.h>
#include <xaios/syscall.h>
#include <xaios/timer.h>
#include <xaios/thread.h>
#include <xaios/user.h>
#include <xaios/vfs.h>
#include <xaios/vmm.h>
#include <xaios/virtio_rng.h>

typedef struct xaios_syscall_entry {
  uint64_t number;
  const char *name;
  uint64_t required_capability;
} xaios_syscall_entry_t;

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
    {XAIOS_SYSCALL_NET_LOCAL_IPV4, "net_local_ipv4", XAIOS_CAP_NET},
    {XAIOS_SYSCALL_NET_CONNECT, "net_connect", XAIOS_CAP_NET_SOCKET},
};

static uint64_t control_operation_capability(uint16_t operation) {
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

static uint64_t g_control_plane_syscall_count;
static uint64_t g_control_plane_denial_count;
static uint64_t g_service_descriptor_read_count;
static uint32_t g_cpu_ai_app_bound;

#define XAIOS_SYSCALL_LOG_MAX_BYTES UINT64_C(4096)
#define XAIOS_SYSCALL_IO_MAX_BYTES UINT64_C(65536)
#define XAIOS_SYSCALL_NETWORK_IO_MAX_BYTES ((uint64_t)SOCKET_BUFFER_SIZE)

/* ---- Kernel socket table (for sshd) ---- */
#define KERNEL_SOCK_LISTEN UINT32_C(1)
#define KERNEL_SOCK_CONNECTED UINT32_C(2)
#define KERNEL_SOCK_DATAGRAM UINT32_C(3)
#define KERNEL_SOCK_MIN_CAPACITY UINT32_C(64)
#define KERNEL_SOCKETS_PER_CPU UINT32_C(8)
#define KERNEL_SOCK_MIN_PER_PORT UINT32_C(32)

typedef struct kernel_socket {
  uint32_t state;   /* 0=free, KERNEL_SOCK_LISTEN, KERNEL_SOCK_CONNECTED */
  uint16_t port;
  uint8_t  family;          /* 0=any, 4=IPv4, 6=IPv6 */
  uint8_t  protocol;        /* 6=TCP, 17=UDP */
  uint8_t  bind_addr[16];   /* bind address (16 bytes for IPv6) */
  uint8_t  peer_addr[16];   /* peer address (connected sockets) */
  uint16_t peer_port;
  uint32_t owner_pid;
  uint64_t id;              /* unique socket ID from alloc */
} kernel_socket_t;

static kernel_socket_t *g_kernel_sockets;
static uint32_t g_kernel_socket_capacity;
static uint32_t g_kernel_socket_per_port_limit;
static uint64_t g_socket_next_id = 1;
static uint16_t g_next_ephemeral_port = UINT16_C(49152);
static uint32_t g_total_connections = 0;
static xaios_spinlock_t g_kernel_socket_lock = XAIOS_SPINLOCK_INIT;

static void kernel_socket_table_init(void) {
  uint64_t capacity = (uint64_t)smp_online_count() * KERNEL_SOCKETS_PER_CPU;
  if (capacity < KERNEL_SOCK_MIN_CAPACITY) capacity = KERNEL_SOCK_MIN_CAPACITY;
  if (capacity > UINT32_MAX) capacity = UINT32_MAX;
  g_kernel_sockets = (kernel_socket_t *)kheap_calloc(
      capacity * sizeof(*g_kernel_sockets), 64U);
  kassert(g_kernel_sockets != 0);
  g_kernel_socket_capacity = (uint32_t)capacity;
  uint64_t per_port = (uint64_t)smp_online_count() * 2U;
  if (per_port < KERNEL_SOCK_MIN_PER_PORT) {
    per_port = KERNEL_SOCK_MIN_PER_PORT;
  }
  if (per_port > capacity) per_port = capacity;
  g_kernel_socket_per_port_limit = (uint32_t)per_port;
  xaios_spin_init(&g_kernel_socket_lock);
}

static uint64_t kernel_socket_alloc(uint32_t type, uint16_t port,
                                    uint32_t owner_pid) {
  if (g_kernel_sockets == 0 || owner_pid == 0U) return 0U;
  xaios_spin_lock(&g_kernel_socket_lock);
  if (g_total_connections >= g_kernel_socket_capacity) {
    xaios_spin_unlock(&g_kernel_socket_lock);
    klog("syscall: socket allocation denied (capacity reached: %u)\n",
         g_total_connections);
    return 0;
  }

  /* Enforce the per-port limit for connected sockets. */
  if (type == KERNEL_SOCK_CONNECTED) {
    uint32_t port_count = 0;
    for (uint32_t i = 0; i < g_kernel_socket_capacity; ++i) {
      if (g_kernel_sockets[i].state == KERNEL_SOCK_CONNECTED &&
          g_kernel_sockets[i].port == port) {
        port_count++;
      }
    }
    if (port_count >= g_kernel_socket_per_port_limit) {
      xaios_spin_unlock(&g_kernel_socket_lock);
      klog("syscall: socket allocation denied (max per-port: %u for port %u)\n",
           port_count, port);
      return 0;
    }
  }

  for (uint32_t i = 0; i < g_kernel_socket_capacity; ++i) {
    if (g_kernel_sockets[i].state == 0) {
      g_kernel_sockets[i].state = type;
      g_kernel_sockets[i].port = port;
      g_kernel_sockets[i].owner_pid = owner_pid;
      g_kernel_sockets[i].id = g_socket_next_id;
      g_total_connections++;
      uint64_t id = g_socket_next_id++;
      if (g_socket_next_id == 0U) g_socket_next_id = 1U;
      xaios_spin_unlock(&g_kernel_socket_lock);
      return id;
    }
  }
  xaios_spin_unlock(&g_kernel_socket_lock);
  return 0; /* no free slots */
}

static kernel_socket_t *kernel_socket_find_owned_locked(uint64_t sockfd,
                                                        uint32_t owner_pid) {
  for (uint32_t i = 0; i < g_kernel_socket_capacity; ++i) {
    if (g_kernel_sockets[i].state != 0 && g_kernel_sockets[i].id == sockfd &&
        g_kernel_sockets[i].owner_pid == owner_pid) {
      return &g_kernel_sockets[i];
    }
  }
  return 0;
}

static xaios_status_t kernel_socket_snapshot_owned(uint64_t sockfd,
                                                   uint32_t owner_pid,
                                                   kernel_socket_t *snapshot) {
  if (snapshot == 0) return XAIOS_ERR_INVALID;
  xaios_spin_lock(&g_kernel_socket_lock);
  kernel_socket_t *socket = kernel_socket_find_owned_locked(sockfd, owner_pid);
  if (socket == 0) {
    xaios_spin_unlock(&g_kernel_socket_lock);
    return XAIOS_ERR_INVALID;
  }
  *snapshot = *socket;
  xaios_spin_unlock(&g_kernel_socket_lock);
  return XAIOS_OK;
}

static xaios_status_t kernel_socket_free(uint64_t sockfd, uint32_t owner_pid) {
  xaios_spin_lock(&g_kernel_socket_lock);
  kernel_socket_t *socket = kernel_socket_find_owned_locked(sockfd, owner_pid);
  if (socket != 0) {
    socket->state = 0;
    socket->port = 0;
    socket->family = 0;
    socket->protocol = 0;
    socket->peer_port = 0;
    socket->owner_pid = 0;
    socket->id = 0;
    for (uint32_t j = 0; j < 16; ++j) {
      socket->bind_addr[j] = 0;
      socket->peer_addr[j] = 0;
    }
    if (g_total_connections > 0) g_total_connections--;
    xaios_spin_unlock(&g_kernel_socket_lock);
    return XAIOS_OK;
  }
  xaios_spin_unlock(&g_kernel_socket_lock);
  return XAIOS_ERR_INVALID;
}

void syscall_release_process_resources(uint32_t owner_pid) {
  if (owner_pid == 0U) return;
  (void)vfs_release_owner(owner_pid);
  if (g_kernel_sockets == 0) return;
  for (;;) {
    kernel_socket_t snapshot;
    uint32_t found = 0U;
    xaios_spin_lock(&g_kernel_socket_lock);
    for (uint32_t i = 0; i < g_kernel_socket_capacity; ++i) {
      if (g_kernel_sockets[i].state != 0U &&
          g_kernel_sockets[i].owner_pid == owner_pid) {
        snapshot = g_kernel_sockets[i];
        found = 1U;
        break;
      }
    }
    xaios_spin_unlock(&g_kernel_socket_lock);
    if (found == 0U) return;

    socket_flow_mapping_t *mapping =
        network_stack_get_socket_mapping(snapshot.id);
    if (mapping != 0) {
      if (mapping->protocol == XAIOS_NETWORK_PROTOCOL_TCP) {
        (void)network_stack_tcp_close_flow(mapping->flow_id);
      }
      network_stack_unmap_socket(snapshot.id);
    }
    if (snapshot.state == KERNEL_SOCK_LISTEN) {
      network_stack_unregister_listener(snapshot.port);
    } else if (snapshot.state == KERNEL_SOCK_DATAGRAM) {
      network_stack_unregister_udp_listener(snapshot.port);
    }
    (void)kernel_socket_free(snapshot.id, owner_pid);
  }
}

static const xaios_syscall_entry_t *lookup_syscall(uint64_t number) {
  for (uint32_t i = 0; i < sizeof(g_syscall_table) / sizeof(g_syscall_table[0]);
       ++i) {
    if (g_syscall_table[i].number == number) {
      return &g_syscall_table[i];
    }
  }
  return 0;
}

static xaios_status_t copy_user_string(uint64_t user_ptr, uint64_t length,
                                      char *buffer, uint64_t buffer_size) {
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

static void bytes_copy(void *dst, const void *src, uint64_t size) {
  uint8_t *out = (uint8_t *)dst;
  const uint8_t *in = (const uint8_t *)src;
  for (uint64_t i = 0; i < size; ++i) {
    out[i] = in[i];
  }
}

static int is_control_plane_syscall(uint64_t syscall) {
  return syscall == XAIOS_SYSCALL_OSCTL ||
         (syscall >= XAIOS_SYSCALL_READ_SERVICE_DESCRIPTOR &&
          syscall <= XAIOS_SYSCALL_FS_FSYNC);
}

static uint64_t reject_syscall(uint64_t syscall, uint64_t arg0, uint64_t arg1,
                               const char *reason) {
  user_process_note_syscall(1);
  if (is_control_plane_syscall(syscall)) {
    ++g_control_plane_denial_count;
  }
  klog("user: rejected syscall=%lu arg0=0x%lx arg1=0x%lx reason=%s\n",
       syscall, arg0, arg1, reason);
  return UINT64_C(-1);
}

static uint64_t complete_control_syscall(uint64_t value) {
  ++g_control_plane_syscall_count;
  user_process_note_syscall(0);
  return value;
}

static xaios_status_t ensure_app_cpu_ai_binding(void) {
  if (g_cpu_ai_app_bound != 0) {
    return XAIOS_OK;
  }

  const xaios_arena_t *kv = 0;
  xaios_status_t status =
      arena_create(30, XAIOS_ARENA_KV_CACHE, 3, "cpu-ai-user-kv", 4096, 0,
                   &kv);
  if (status != XAIOS_OK || kv == 0) {
    return status;
  }
  status = cpu_ai_runtime_bind_model_with_kv(3, 2, kv->base, kv->size);
  if (status != XAIOS_OK) {
    (void)arena_destroy(30);
    return status;
  }
  g_cpu_ai_app_bound = 1;
  return XAIOS_OK;
}

uint64_t syscall_dispatch(uint64_t syscall, uint64_t arg0, uint64_t arg1,
                          uint64_t arg2) {
  (void)arg2;

  const xaios_syscall_entry_t *entry = lookup_syscall(syscall);
  if (entry == 0) {
    return reject_syscall(syscall, arg0, arg1, "unknown");
  }
  if (user_process_has_capability(entry->required_capability) != XAIOS_OK) {
    const xaios_user_process_t *process = user_current_process();
    uint64_t granted = process != 0 ? process->capability_mask : 0;
    (void)security_authorize_capability(entry->name, granted,
                                        entry->required_capability);
    return reject_syscall(syscall, arg0, arg1, "missing-capability");
  }

  if (syscall == XAIOS_SYSCALL_LOG) {
    char log_snapshot[XAIOS_SYSCALL_LOG_MAX_BYTES];
    if (arg1 == 0U || arg1 > sizeof(log_snapshot) ||
        vmm_validate_user_buffer(arg0, arg1, 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-user-buffer");
    }
    bytes_copy(log_snapshot, (const void *)(uintptr_t)arg0, arg1);
    if (security_reject_credential_material_buffer(log_snapshot, arg1) !=
        XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "log-secret-denied");
    }
    user_process_note_syscall(0);
    klog_write_atomic(log_snapshot, arg1);
    return 0;
  }

  if (syscall == XAIOS_SYSCALL_CONSOLE_READ) {
    uint8_t value = 0U;
    if (arg1 != 1U ||
        vmm_validate_user_buffer(arg0, 1U, XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-console-read-buffer");
    }
    if (!klog_console_read_char(&value)) {
      user_process_note_syscall(0);
      return 0U;
    }
    bytes_copy((void *)(uintptr_t)arg0, &value, 1U);
    user_process_note_syscall(0);
    return 1U;
  }

  if (syscall == XAIOS_SYSCALL_CONSOLE_WRITE) {
    char output[XAIOS_SYSCALL_LOG_MAX_BYTES];
    if (arg1 == 0U || arg1 > sizeof(output) ||
        vmm_validate_user_buffer(arg0, arg1, 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-console-write-buffer");
    }
    bytes_copy(output, (const void *)(uintptr_t)arg0, arg1);
    klog_console_write(output, arg1);
    user_process_note_syscall(0);
    return arg1;
  }

  if (syscall == XAIOS_SYSCALL_NET_LOCAL_IPV4) {
    user_process_note_syscall(0);
    return XAIOS_IPV4_GUEST_IP;
  }

  if (syscall == XAIOS_SYSCALL_EXIT) {
    const xaios_user_process_t *process = user_current_process();
    const char *name = process != 0 && process->name != 0 ? process->name : "";
    if (service_exit(name, (int)arg0) != XAIOS_OK) {
      klog("user: %s exit without service record status=%u\n",
           name, (unsigned)arg0);
    }
    user_process_note_syscall(0);
    klog("user: %s exited status=%u syscalls=%lu rejected=%lu\n",
         name, (unsigned)arg0, process != 0 ? process->syscall_count : 0,
         process != 0 ? process->rejected_syscall_count : 0);
    return user_process_note_exit((int)arg0);
  }

  if (syscall == XAIOS_SYSCALL_CLOCK_NANOS) {
    if (arg0 == XAIOS_CLOCK_MONOTONIC) {
      return complete_control_syscall(timer_now_ns());
    }
    if (arg0 == XAIOS_CLOCK_REALTIME) {
      return complete_control_syscall(wall_time_now_ns());
    }
    if (arg0 == XAIOS_CLOCK_PROCESS_CPU) {
      const xaios_user_process_t *current = user_current_process();
      xaios_user_process_t snapshot;
      if (current == 0 ||
          user_process_snapshot_at(current->pid, timer_now_ns(), &snapshot) !=
              XAIOS_OK) {
        return reject_syscall(syscall, arg0, arg1, "clock-process-unavailable");
      }
      return complete_control_syscall(snapshot.runtime_ns);
    }
    return reject_syscall(syscall, arg0, arg1, "clock-selector-invalid");
  }

  if (syscall == XAIOS_SYSCALL_RANDOM) {
    if (arg1 == 0U || arg1 > 4096U ||
        vmm_validate_user_buffer(arg0, arg1, XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-random-buffer");
    }
    if (virtio_rng_read((void *)(uintptr_t)arg0, arg1) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "entropy-unavailable");
    }
    user_process_note_syscall(0);
    return arg1;
  }

  if (syscall == XAIOS_SYSCALL_READ_SERVICE_DESCRIPTOR) {
    const xaios_initramfs_config_t *config = initramfs_config();
    const xaios_initramfs_file_t *file = 0;
    if (config == 0 ||
        security_authorize_fs_read(config->service_descriptor_path) !=
            XAIOS_OK ||
        initramfs_lookup(config->service_descriptor_path, &file) != XAIOS_OK ||
        file == 0 || file->base == 0 || file->size == 0 ||
        arg1 < file->size ||
        vmm_validate_user_buffer(arg0, file->size, XAIOS_VMM_WRITABLE) !=
            XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "descriptor-read-denied");
    }
    bytes_copy((void *)(uintptr_t)arg0, file->base, file->size);
    ++g_service_descriptor_read_count;
    klog("user: service descriptor read path=%s bytes=%lu\n",
         config->service_descriptor_path, file->size);
    return complete_control_syscall(file->size);
  }

  if (syscall == XAIOS_SYSCALL_OSCTL) {
    char command[128];
    if (copy_user_string(arg0, arg1, command, sizeof(command)) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-user-string");
    }
    if (security_reject_credential_material(command) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "osctl-secret-denied");
    }
    klog("user: osctl command='%s'\n", command);
    if (osctl_execute(command) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "osctl-denied");
    }
    return complete_control_syscall(0);
  }

  if (syscall == XAIOS_SYSCALL_CONTROL_QUERY) {
    xaios_syscall_control_query_request_t query;
    uint8_t request[XAIOS_CONTROL_MAX_REQUEST_BYTES];
    uint8_t *response = 0;
    uint64_t response_bytes = 0U;
    if (arg1 != sizeof(query) ||
        vmm_validate_user_buffer(arg0, sizeof(query), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1,
                            "bad-control-query-request");
    }
    bytes_copy(&query, (const void *)(uintptr_t)arg0, sizeof(query));
    if (query.request_size < sizeof(xaios_control_request_header_t) ||
        query.request_size > sizeof(request) ||
        query.response_size < sizeof(xaios_control_response_header_t) ||
        query.response_size > XAIOS_CONTROL_MAX_RESPONSE_BYTES ||
        vmm_validate_user_buffer(query.request, query.request_size, 0) !=
            XAIOS_OK ||
        vmm_validate_user_buffer(query.response, query.response_size,
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(query.out_size, sizeof(response_bytes),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "control-query-denied");
    }
    bytes_copy(request, (const void *)(uintptr_t)query.request,
               query.request_size);
    const xaios_control_request_header_t *control_request =
        (const xaios_control_request_header_t *)(const void *)request;
    uint64_t operation_capability =
        control_operation_capability(control_request->operation);
    if (operation_capability != 0U &&
        user_process_has_capability(operation_capability) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1,
                            "control-operation-capability-denied");
    }
    response = (uint8_t *)kheap_calloc(query.response_size, 16U);
    if (response == 0) {
      return reject_syscall(syscall, arg0, arg1,
                            "control-query-no-memory");
    }
    xaios_control_role_t role =
        user_process_has_capability(XAIOS_CAP_CONTROL_ADMIN) == XAIOS_OK
            ? XAIOS_CONTROL_ROLE_ADMIN
            : XAIOS_CONTROL_ROLE_OBSERVER;
    xaios_status_t status = control_protocol_dispatch(
        request, query.request_size, response, query.response_size,
        &response_bytes, role);
    if (status != XAIOS_OK || response_bytes > query.response_size) {
      kheap_free(response);
      return reject_syscall(syscall, arg0, arg1,
                            "control-query-dispatch-failed");
    }
    bytes_copy((void *)(uintptr_t)query.response, response, response_bytes);
    bytes_copy((void *)(uintptr_t)query.out_size, &response_bytes,
               sizeof(response_bytes));
    kheap_free(response);
    return complete_control_syscall(response_bytes);
  }

  if (syscall >= XAIOS_SYSCALL_SERVICE_STATUS &&
      syscall <= XAIOS_SYSCALL_SERVICE_ROLLBACK) {
    char service_name[64];
    if (copy_user_string(arg0, arg1, service_name, sizeof(service_name)) !=
        XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-service-name");
    }

    xaios_status_t status = XAIOS_ERR_INVALID;
    if (syscall == XAIOS_SYSCALL_SERVICE_STATUS) {
      status = service_status(service_name);
    } else if (syscall == XAIOS_SYSCALL_SERVICE_START) {
      status = service_start(service_name);
    } else if (syscall == XAIOS_SYSCALL_SERVICE_STOP) {
      status = service_stop(service_name);
    } else if (syscall == XAIOS_SYSCALL_SERVICE_RESTART) {
      status = service_restart(service_name);
    } else if (syscall == XAIOS_SYSCALL_SERVICE_ROLLBACK) {
      status = service_rollback(service_name);
    }

    if (status != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "service-control-denied");
    }
    return complete_control_syscall(0);
  }

  if (syscall == XAIOS_SYSCALL_SERVICE_UPDATE) {
    char signature[128];
    if (copy_user_string(arg0, arg1, signature, sizeof(signature)) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-update-signature");
    }
    if (service_update(signature) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "update-denied");
    }
    return complete_control_syscall(0);
  }

  if (syscall == XAIOS_SYSCALL_FS_OPEN) {
    char path[XAIOS_MFS_PATH_MAX];
    if (copy_user_string(arg0, arg1, path, sizeof(path)) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-fs-path");
    }
    if ((arg2 & XAIOS_MFS_OPEN_WRITE) != 0 &&
        user_process_has_capability(XAIOS_CAP_FS_WRITE) != XAIOS_OK) {
      const xaios_user_process_t *process = user_current_process();
      uint64_t granted = process != 0 ? process->capability_mask : 0;
      (void)security_authorize_capability("fs.open.write", granted,
                                          XAIOS_CAP_FS_WRITE);
      return reject_syscall(syscall, arg0, arg1, "missing-fs-write");
    }
    if ((arg2 & XAIOS_MFS_OPEN_WRITE) != 0 &&
        security_authorize_fs_write(path) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "fs-open-write-denied");
    }
    if ((arg2 & XAIOS_MFS_OPEN_WRITE) == 0 &&
        security_authorize_fs_read(path) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "fs-open-read-denied");
    }
    const xaios_user_process_t *current = user_current_process();
    uint32_t owner_id = current != 0 ? current->pid : 0U;
    int64_t fd = vfs_open(path, (uint32_t)arg2, owner_id);
    if (fd < 0) {
      return reject_syscall(syscall, arg0, arg1, "fs-open-denied");
    }
    return complete_control_syscall((uint64_t)fd);
  }

  if (syscall == XAIOS_SYSCALL_FS_READ) {
    if (arg0 > UINT32_MAX || arg2 == 0U ||
        arg2 > XAIOS_SYSCALL_IO_MAX_BYTES ||
        vmm_validate_user_buffer(arg1, arg2, XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-fs-read-buffer");
    }
    const xaios_user_process_t *current = user_current_process();
    uint32_t owner_id = current != 0 ? current->pid : 0U;
    int64_t bytes = vfs_read((uint32_t)arg0, owner_id,
                             (void *)(uintptr_t)arg1, arg2);
    if (bytes < 0) {
      return reject_syscall(syscall, arg0, arg1, "fs-read-denied");
    }
    return complete_control_syscall((uint64_t)bytes);
  }

  if (syscall == XAIOS_SYSCALL_FS_WRITE) {
    if (arg0 > UINT32_MAX || arg2 == 0U ||
        arg2 > XAIOS_SYSCALL_IO_MAX_BYTES ||
        vmm_validate_user_buffer(arg1, arg2, 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-fs-write-buffer");
    }
    uint8_t *write_snapshot = (uint8_t *)kheap_alloc(arg2, 16U);
    if (write_snapshot == 0) {
      return reject_syscall(syscall, arg0, arg1, "fs-write-no-memory");
    }
    bytes_copy(write_snapshot, (const void *)(uintptr_t)arg1, arg2);
    if (security_reject_credential_material_buffer(
            (const char *)write_snapshot, arg2) != XAIOS_OK) {
      kheap_free(write_snapshot);
      return reject_syscall(syscall, arg0, arg1, "fs-write-secret-denied");
    }
    const xaios_user_process_t *current = user_current_process();
    uint32_t owner_id = current != 0 ? current->pid : 0U;
    int64_t bytes =
        vfs_write((uint32_t)arg0, owner_id, write_snapshot, arg2);
    kheap_free(write_snapshot);
    if (bytes < 0) {
      return reject_syscall(syscall, arg0, arg1, "fs-write-denied");
    }
    return complete_control_syscall((uint64_t)bytes);
  }

  if (syscall == XAIOS_SYSCALL_FS_PREAD ||
      syscall == XAIOS_SYSCALL_FS_PWRITE) {
    xaios_syscall_positional_io_request_t request;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-fs-positional-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.fd > UINT32_MAX || request.size == 0U ||
        request.size > XAIOS_SYSCALL_IO_MAX_BYTES ||
        vmm_validate_user_buffer(
            request.buffer, request.size,
            syscall == XAIOS_SYSCALL_FS_PREAD ? XAIOS_VMM_WRITABLE : 0U) !=
            XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-fs-positional-buffer");
    }
    const xaios_user_process_t *current = user_current_process();
    uint32_t owner_id = current != 0 ? current->pid : 0U;
    int64_t bytes;
    if (syscall == XAIOS_SYSCALL_FS_PREAD) {
      bytes = vfs_pread((uint32_t)request.fd, owner_id,
                        (void *)(uintptr_t)request.buffer, request.size,
                        request.offset);
    } else {
      uint8_t *write_snapshot =
          (uint8_t *)kheap_alloc(request.size, 16U);
      if (write_snapshot == 0) {
        return reject_syscall(syscall, arg0, arg1,
                              "fs-positional-write-no-memory");
      }
      bytes_copy(write_snapshot, (const void *)(uintptr_t)request.buffer,
                 request.size);
      if (security_reject_credential_material_buffer(
              (const char *)write_snapshot, request.size) != XAIOS_OK) {
        kheap_free(write_snapshot);
        return reject_syscall(syscall, arg0, arg1,
                              "fs-positional-write-secret-denied");
      }
      bytes = vfs_pwrite((uint32_t)request.fd, owner_id, write_snapshot,
                         request.size, request.offset);
      kheap_free(write_snapshot);
    }
    if (bytes < 0) {
      return reject_syscall(syscall, arg0, arg1,
                            syscall == XAIOS_SYSCALL_FS_PREAD
                                ? "fs-pread-denied"
                                : "fs-pwrite-denied");
    }
    return complete_control_syscall((uint64_t)bytes);
  }

  if (syscall == XAIOS_SYSCALL_FS_FSYNC) {
    const xaios_user_process_t *current = user_current_process();
    uint32_t owner_id = current != 0 ? current->pid : 0U;
    if (arg0 > UINT32_MAX ||
        vfs_fsync((uint32_t)arg0, owner_id) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "fs-fsync-denied");
    }
    return complete_control_syscall(0U);
  }

  if (syscall == XAIOS_SYSCALL_FS_SEEK) {
    const xaios_user_process_t *current = user_current_process();
    uint32_t owner_id = current != 0 ? current->pid : 0U;
    if (arg0 > UINT32_MAX ||
        vfs_seek((uint32_t)arg0, owner_id, arg1) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "fs-seek-denied");
    }
    return complete_control_syscall(arg1);
  }

  if (syscall == XAIOS_SYSCALL_FS_CLOSE) {
    const xaios_user_process_t *current = user_current_process();
    uint32_t owner_id = current != 0 ? current->pid : 0U;
    if (arg0 > UINT32_MAX ||
        vfs_close((uint32_t)arg0, owner_id) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "fs-close-denied");
    }
    return complete_control_syscall(0);
  }

  if (syscall == XAIOS_SYSCALL_FS_STAT) {
    char path[XAIOS_MFS_PATH_MAX];
    if (copy_user_string(arg0, arg1, path, sizeof(path)) != XAIOS_OK ||
        vmm_validate_user_buffer(arg2, sizeof(xaios_mfs_stat_t),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-fs-stat");
    }
    xaios_vfs_stat_t vfs_value;
    if (vfs_stat(path, &vfs_value) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "fs-stat-denied");
    }
    xaios_mfs_stat_t *value = (xaios_mfs_stat_t *)(uintptr_t)arg2;
    value->type = vfs_value.type;
    value->block_count = vfs_value.block_count;
    value->size = vfs_value.size;
    value->generation = vfs_value.generation;
    value->content_hash = vfs_value.content_hash;
    return complete_control_syscall(sizeof(xaios_mfs_stat_t));
  }

  if (syscall == XAIOS_SYSCALL_FS_MKDIR) {
    char path[XAIOS_MFS_PATH_MAX];
    if (copy_user_string(arg0, arg1, path, sizeof(path)) != XAIOS_OK ||
        security_authorize_fs_write(path) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "fs-mkdir-denied");
    }
    if (vfs_mkdir(path) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "fs-mkdir-failed");
    }
    return complete_control_syscall(0);
  }

  if (syscall == XAIOS_SYSCALL_FS_DELETE) {
    char path[XAIOS_MFS_PATH_MAX];
    if (copy_user_string(arg0, arg1, path, sizeof(path)) != XAIOS_OK ||
        security_authorize_fs_write(path) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "fs-delete-denied");
    }
    if (vfs_delete(path) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "fs-delete-failed");
    }
    return complete_control_syscall(0);
  }

  if (syscall == XAIOS_SYSCALL_FS_RENAME) {
    xaios_syscall_rename_request_t request;
    char old_path[XAIOS_MFS_PATH_MAX];
    char new_path[XAIOS_MFS_PATH_MAX];
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-fs-rename-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (copy_user_string(request.old_path, request.old_path_len, old_path,
                         sizeof(old_path)) != XAIOS_OK ||
        copy_user_string(request.new_path, request.new_path_len, new_path,
                         sizeof(new_path)) != XAIOS_OK ||
        security_authorize_fs_write(old_path) != XAIOS_OK ||
        security_authorize_fs_write(new_path) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "fs-rename-denied");
    }
    if (vfs_rename(old_path, new_path) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "fs-rename-failed");
    }
    return complete_control_syscall(0);
  }

  if (syscall == XAIOS_SYSCALL_FS_LIST) {
    xaios_syscall_list_request_t request;
    char path[XAIOS_MFS_PATH_MAX];
    uint64_t out_size = 0;
    if (copy_user_string(arg0, arg1, path, sizeof(path)) != XAIOS_OK ||
        vmm_validate_user_buffer(arg2, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-fs-list-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg2, sizeof(request));
    if (request.buffer_size == 0 ||
        request.buffer_size > XAIOS_SYSCALL_NETWORK_IO_MAX_BYTES ||
        vmm_validate_user_buffer(request.buffer, request.buffer_size,
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_size, sizeof(out_size),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        security_authorize_fs_read(path) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "fs-list-denied");
    }
    if (vfs_list(path, (char *)(uintptr_t)request.buffer,
                 request.buffer_size, &out_size) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "fs-list-failed");
    }
    bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
               sizeof(out_size));
    return complete_control_syscall(out_size);
  }

  if (syscall == XAIOS_SYSCALL_NET_UDP_ECHO) {
    xaios_syscall_net_request_t request;
    uint8_t payload[64];
    uint64_t echoed = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-net-udp-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.payload_size == 0 || request.payload_size > sizeof(payload) ||
        vmm_validate_user_buffer(request.payload, request.payload_size, 0) !=
            XAIOS_OK ||
        vmm_validate_user_buffer(request.out_value, sizeof(echoed),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "net-udp-denied");
    }
    bytes_copy(payload, (const void *)(uintptr_t)request.payload,
               request.payload_size);
    if (network_stack_app_udp_echo(payload, request.payload_size, &echoed) !=
        XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "net-udp-failed");
    }
    bytes_copy((void *)(uintptr_t)request.out_value, &echoed, sizeof(echoed));
    return complete_control_syscall(echoed);
  }

  if (syscall == XAIOS_SYSCALL_NET_TCP_CONNECT) {
    xaios_syscall_net_request_t request;
    uint64_t round_trips = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-net-tcp-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (vmm_validate_user_buffer(request.out_value, sizeof(round_trips),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "net-tcp-denied");
    }
    if (network_stack_app_tcp_connect(&round_trips) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "net-tcp-failed");
    }
    bytes_copy((void *)(uintptr_t)request.out_value, &round_trips,
               sizeof(round_trips));
    return complete_control_syscall(round_trips);
  }

  if (syscall == XAIOS_SYSCALL_SMP_RUN) {
    xaios_syscall_smp_request_t request;
    uint64_t ran_workers = 0;
    uint64_t checksum = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-smp-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (vmm_validate_user_buffer(request.out_workers, sizeof(ran_workers),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_checksum, sizeof(checksum),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "smp-run-denied");
    }
    if (smp_run_user_task_set(request.worker_count, request.iterations,
                              &ran_workers, &checksum) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "smp-run-failed");
    }
    bytes_copy((void *)(uintptr_t)request.out_workers, &ran_workers,
               sizeof(ran_workers));
    bytes_copy((void *)(uintptr_t)request.out_checksum, &checksum,
               sizeof(checksum));
    return complete_control_syscall(ran_workers);
  }

  if (syscall == XAIOS_SYSCALL_CPU_AI_DECODE) {
    xaios_syscall_cpu_ai_decode_request_t request;
    uint8_t input[32];
    uint64_t out_size = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-cpu-ai-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.input_size == 0 || request.input_size > sizeof(input) ||
        request.output_size == 0 ||
        vmm_validate_user_buffer(request.input, request.input_size, 0) !=
            XAIOS_OK ||
        vmm_validate_user_buffer(request.output, request.output_size,
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_size, sizeof(out_size),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "cpu-ai-denied");
    }
    bytes_copy(input, (const void *)(uintptr_t)request.input,
               request.input_size);
    xaios_status_t decode_status = cpu_ai_runtime_decode_piece(
        3, input, request.input_size, (char *)(uintptr_t)request.output,
        request.output_size, &out_size);
    if (decode_status == XAIOS_ERR_UNSUPPORTED) {
      klog("syscall: production CPU-AI decode is not implemented; QEMU fixture decode is available only through explicit ML fixture mode\n");
      bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
                 sizeof(out_size));
      (void)reject_syscall(syscall, arg0, arg1,
                           "cpu-ai-production-unsupported");
      return (uint64_t)(int64_t)XAIOS_ERR_UNSUPPORTED;
    }
    if (decode_status != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "cpu-ai-failed");
    }
    bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
               sizeof(out_size));
    return complete_control_syscall(out_size);
  }

  if (syscall == XAIOS_SYSCALL_REMOTE_LOGIN) {
    xaios_syscall_remote_login_request_t request;
    char user[32];
    char command[256];
    uint64_t out_size = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-remote-login-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (copy_user_string(request.user, request.user_size, user,
                         sizeof(user)) != XAIOS_OK ||
        copy_user_string(request.command, request.command_size, command,
                         sizeof(command)) != XAIOS_OK ||
        request.output_size == 0 ||
        vmm_validate_user_buffer(request.output, request.output_size,
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_size, sizeof(out_size),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "remote-login-denied");
    }
    if (remote_login_execute(user, command, (char *)(uintptr_t)request.output,
                             request.output_size, &out_size) != XAIOS_OK) {
      bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
                 sizeof(out_size));
      return reject_syscall(syscall, arg0, arg1, "remote-login-failed");
    }
    bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
               sizeof(out_size));
    return complete_control_syscall(out_size);
  }

  if (syscall == XAIOS_SYSCALL_REMOTE_LOGIN_SESSION) {
    xaios_syscall_remote_login_session_request_t request;
    char user[32];
    char command[256];
    uint64_t out_size = 0U;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1,
                            "bad-remote-login-session-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.session_id == 0U) {
      return reject_syscall(syscall, arg0, arg1,
                            "remote-login-session-id-invalid");
    }
    if (request.action == XAIOS_REMOTE_LOGIN_SESSION_CLOSE) {
      if (request.user != 0U || request.user_size != 0U ||
          request.command != 0U || request.command_size != 0U ||
          request.output != 0U || request.output_size != 0U ||
          request.out_size != 0U ||
          remote_login_close_session(request.session_id) != XAIOS_OK) {
        return reject_syscall(syscall, arg0, arg1,
                              "remote-login-session-close-failed");
      }
      return complete_control_syscall(0U);
    }
    if (request.action != XAIOS_REMOTE_LOGIN_SESSION_EXECUTE ||
        copy_user_string(request.user, request.user_size, user,
                         sizeof(user)) != XAIOS_OK ||
        copy_user_string(request.command, request.command_size, command,
                         sizeof(command)) != XAIOS_OK ||
        request.output_size == 0U ||
        vmm_validate_user_buffer(request.output, request.output_size,
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_size, sizeof(out_size),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1,
                            "remote-login-session-denied");
    }
    if (remote_login_execute_session(
            request.session_id, user, command,
            (char *)(uintptr_t)request.output, request.output_size,
            &out_size) != XAIOS_OK) {
      bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
                 sizeof(out_size));
      return reject_syscall(syscall, arg0, arg1,
                            "remote-login-session-failed");
    }
    bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
               sizeof(out_size));
    return complete_control_syscall(out_size);
  }

  if (syscall == XAIOS_SYSCALL_NET_EXTERNAL_SESSION) {
    xaios_syscall_net_external_session_request_t request;
    uint8_t payload[64];
    uint64_t out_size = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-net-external-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.payload_size == 0 || request.payload_size > sizeof(payload) ||
        request.output_size == 0 ||
        vmm_validate_user_buffer(request.payload, request.payload_size, 0) !=
            XAIOS_OK ||
        vmm_validate_user_buffer(request.output, request.output_size,
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_size, sizeof(out_size),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "net-external-denied");
    }
    bytes_copy(payload, (const void *)(uintptr_t)request.payload,
               request.payload_size);
    if (network_stack_external_session(
            request.protocol, request.port, payload, request.payload_size,
            (char *)(uintptr_t)request.output, request.output_size,
            &out_size) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "net-external-failed");
    }
    bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
               sizeof(out_size));
    return complete_control_syscall(out_size);
  }

  if (syscall == XAIOS_SYSCALL_THREAD_GROUP_RUN) {
    xaios_syscall_thread_group_request_t request;
    uint64_t ran_threads = 0;
    uint64_t checksum = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-thread-group-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (vmm_validate_user_buffer(request.out_threads, sizeof(ran_threads),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_checksum, sizeof(checksum),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "thread-group-denied");
    }
    if (smp_run_user_thread_group(request.thread_count, request.iterations,
                                  &ran_threads, &checksum) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "thread-group-failed");
    }
    bytes_copy((void *)(uintptr_t)request.out_threads, &ran_threads,
               sizeof(ran_threads));
    bytes_copy((void *)(uintptr_t)request.out_checksum, &checksum,
               sizeof(checksum));
    return complete_control_syscall(ran_threads);
  }

  if (syscall == XAIOS_SYSCALL_THREAD_CREATE) {
    xaios_syscall_thread_create_request_t request;
    uint64_t thread_id = 0U;
    const xaios_user_process_t *process = user_current_process();
    if (arg1 != sizeof(request) || process == 0 ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-thread-create-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    xaios_status_t entry_status =
        vmm_validate_user_buffer(request.entry, 4U, XAIOS_VMM_EXECUTABLE);
    xaios_status_t return_status = vmm_validate_user_buffer(
        request.return_address, 4U, XAIOS_VMM_EXECUTABLE);
    xaios_status_t stack_status = vmm_validate_user_buffer(
        request.stack, request.stack_size, XAIOS_VMM_WRITABLE);
    xaios_status_t output_status = vmm_validate_user_buffer(
        request.out_thread_id, sizeof(thread_id), XAIOS_VMM_WRITABLE);
    if (request.stack_size < 4096U || request.stack_size > 1048576U ||
        request.stack + request.stack_size < request.stack ||
        request.out_thread_id == 0U ||
        entry_status != XAIOS_OK || return_status != XAIOS_OK ||
        stack_status != XAIOS_OK || output_status != XAIOS_OK ||
        (request.preferred_cpu != UINT64_MAX &&
         request.preferred_cpu > UINT32_MAX)) {
      return reject_syscall(syscall, arg0, arg1, "thread-create-denied");
    }
    uint64_t stack_top =
        (request.stack + request.stack_size) & ~UINT64_C(15);
    uint32_t preferred = request.preferred_cpu == UINT64_MAX
                             ? XAIOS_THREAD_CPU_ANY
                             : (uint32_t)request.preferred_cpu;
    if (stack_top <= request.stack ||
        xaios_user_thread_create(request.entry, request.argument, stack_top,
                                 request.return_address, preferred,
                                 process->pid, &thread_id) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "thread-create-failed");
    }
    bytes_copy((void *)(uintptr_t)request.out_thread_id, &thread_id,
               sizeof(thread_id));
    user_process_note_syscall(0);
    return thread_id;
  }

  if (syscall == XAIOS_SYSCALL_THREAD_JOIN) {
    xaios_syscall_thread_join_request_t request;
    uint64_t result = 0U;
    const xaios_user_process_t *process = user_current_process();
    if (arg1 != sizeof(request) || process == 0 ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-thread-join-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.timeout_ns > UINT64_C(60000000000) ||
        vmm_validate_user_buffer(request.out_result, sizeof(result),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        xaios_user_thread_join(request.thread_id, process->pid,
                               request.timeout_ns, &result) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "thread-join-failed");
    }
    bytes_copy((void *)(uintptr_t)request.out_result, &result, sizeof(result));
    user_process_note_syscall(0);
    return 0U;
  }

  if (syscall == XAIOS_SYSCALL_THREAD_CANCEL) {
    const xaios_user_process_t *process = user_current_process();
    if (process == 0 ||
        xaios_user_thread_cancel(arg0, process->pid) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "thread-cancel-failed");
    }
    user_process_note_syscall(0);
    return 0U;
  }

  if (syscall == XAIOS_SYSCALL_THREAD_EXIT) {
    user_process_note_syscall(0);
    uint64_t encoded = xaios_user_thread_exit(arg0);
    if (encoded == UINT64_MAX) {
      return reject_syscall(syscall, arg0, arg1, "thread-exit-outside-thread");
    }
    return encoded;
  }

  if (syscall == XAIOS_SYSCALL_ML_RUN) {
    xaios_syscall_ml_run_request_t request;
    uint8_t input[64];
    uint64_t out_size = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-ml-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.input_size == 0 || request.input_size > sizeof(input) ||
        request.output_size == 0 ||
        vmm_validate_user_buffer(request.input, request.input_size, 0) !=
            XAIOS_OK ||
        vmm_validate_user_buffer(request.output, request.output_size,
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_size, sizeof(out_size),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "ml-run-denied");
    }
    bytes_copy(input, (const void *)(uintptr_t)request.input,
               request.input_size);
    if (ensure_app_cpu_ai_binding() != XAIOS_OK ||
        cpu_ai_runtime_run_model(3, request.model_kind, input,
                                 request.input_size,
                                 (char *)(uintptr_t)request.output,
                                 request.output_size, &out_size) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "ml-run-failed");
    }
    bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
               sizeof(out_size));
    return complete_control_syscall(out_size);
  }

  if (syscall == XAIOS_SYSCALL_NET_CONNECT) {
    xaios_syscall_socket_request_t request;
    xaios_ip_addr_t remote_addr;
    uint64_t out_sockfd = 0U;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1,
                            "bad-net-connect-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.protocol != XAIOS_NETWORK_PROTOCOL_TCP || request.port == 0U ||
        request.port > UINT16_MAX || request.addr_ptr == 0U ||
        vmm_validate_user_buffer(request.addr_ptr, sizeof(remote_addr), 0) !=
            XAIOS_OK ||
        vmm_validate_user_buffer(request.out_sockfd, sizeof(out_sockfd),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "net-connect-denied");
    }
    bytes_copy(&remote_addr, (const void *)(uintptr_t)request.addr_ptr,
               sizeof(remote_addr));
    if (remote_addr.family != XAIOS_IP_FAMILY_V4) {
      return reject_syscall(syscall, arg0, arg1,
                            "net-connect-family-unsupported");
    }
    uint32_t flow_id = 0U;
    xaios_status_t open_status = XAIOS_ERR_BUSY;
    for (uint32_t attempt = 0U; attempt < 16U; ++attempt) {
      uint16_t local_port = g_next_ephemeral_port++;
      if (g_next_ephemeral_port < 49152U) g_next_ephemeral_port = 49152U;
      open_status = network_stack_tcp_open(
          &remote_addr, (uint16_t)request.port, local_port, &flow_id);
      if (open_status == XAIOS_OK) break;
      if (open_status != XAIOS_ERR_BUSY) break;
    }
    if (open_status != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "net-connect-open-failed");
    }
    uint64_t start = timer_now_ns();
    uint64_t deadline = start + UINT64_C(10000000000);
    do {
      network_poll_tick();
      open_status = network_stack_tcp_open_status(flow_id);
      if (open_status != XAIOS_ERR_BUSY) break;
    } while (timer_now_ns() < deadline);
    if (open_status != XAIOS_OK) {
      (void)network_stack_tcp_abort_flow(flow_id);
      return reject_syscall(syscall, arg0, arg1,
                            "net-connect-handshake-failed");
    }
    const xaios_user_process_t *process = user_current_process();
    uint32_t owner_pid = process != 0 ? process->pid : 0U;
    uint64_t sockfd = kernel_socket_alloc(KERNEL_SOCK_CONNECTED,
                                          (uint16_t)request.port, owner_pid);
    if (sockfd == 0U) {
      (void)network_stack_tcp_abort_flow(flow_id);
      return reject_syscall(syscall, arg0, arg1,
                            "net-connect-socket-failed");
    }
    xaios_spin_lock(&g_kernel_socket_lock);
    kernel_socket_t *socket =
        kernel_socket_find_owned_locked(sockfd, owner_pid);
    kassert(socket != 0);
    socket->protocol = XAIOS_NETWORK_PROTOCOL_TCP;
    socket->family = remote_addr.family;
    socket->peer_port = (uint16_t)request.port;
    for (uint32_t i = 0U; i < 16U; ++i)
      socket->peer_addr[i] = remote_addr.addr[i];
    xaios_spin_unlock(&g_kernel_socket_lock);
    network_stack_map_socket(sockfd, flow_id, XAIOS_NETWORK_PROTOCOL_TCP);
    bytes_copy((void *)(uintptr_t)request.out_sockfd, &sockfd, sizeof(sockfd));
    klog("syscall: net_connect port=%lu sockfd=%lu flow=%u\n", request.port,
         sockfd, flow_id);
    user_process_note_syscall(0);
    return 0U;
  }

  if (syscall == XAIOS_SYSCALL_NET_LISTEN) {
    xaios_syscall_socket_request_t request;
    uint64_t out_sockfd = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-net-listen-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (vmm_validate_user_buffer(request.out_sockfd, sizeof(out_sockfd),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        request.port == 0 || request.port > 65535U) {
      return reject_syscall(syscall, arg0, arg1, "net-listen-denied");
    }
    uint64_t protocol = request.protocol == 0 ? XAIOS_NETWORK_PROTOCOL_TCP
                                              : request.protocol;
    if (protocol != XAIOS_NETWORK_PROTOCOL_TCP &&
        protocol != XAIOS_NETWORK_PROTOCOL_UDP) {
      return reject_syscall(syscall, arg0, arg1, "net-listen-protocol");
    }
    uint8_t addr_buf[17];
    if (request.addr_ptr != 0U) {
      if (vmm_validate_user_buffer(request.addr_ptr, sizeof(addr_buf), 0) !=
          XAIOS_OK) {
        return reject_syscall(syscall, arg0, arg1, "net-listen-address");
      }
      bytes_copy(addr_buf, (const void *)(uintptr_t)request.addr_ptr,
                 sizeof(addr_buf));
      if (addr_buf[0] != 0U && addr_buf[0] != 4U && addr_buf[0] != 6U) {
        return reject_syscall(syscall, arg0, arg1, "net-listen-family");
      }
    }
    const xaios_user_process_t *process = user_current_process();
    uint32_t owner_pid = process != 0 ? process->pid : 0U;
    uint32_t socket_type = protocol == XAIOS_NETWORK_PROTOCOL_UDP
                               ? KERNEL_SOCK_DATAGRAM
                               : KERNEL_SOCK_LISTEN;
    uint64_t sockfd = kernel_socket_alloc(socket_type, (uint16_t)request.port,
                                          owner_pid);
    if (sockfd == 0) {
      return reject_syscall(syscall, arg0, arg1, "net-listen-no-memory");
    }
    xaios_spin_lock(&g_kernel_socket_lock);
    kernel_socket_t *socket =
        kernel_socket_find_owned_locked(sockfd, owner_pid);
    kassert(socket != 0);
    socket->protocol = (uint8_t)protocol;
    if (request.addr_ptr != 0U) {
      socket->family = addr_buf[0];
      for (uint32_t j = 0; j < 16; ++j) {
        socket->bind_addr[j] = addr_buf[1U + j];
      }
    }
    xaios_spin_unlock(&g_kernel_socket_lock);
    *(uint64_t *)(uintptr_t)request.out_sockfd = sockfd;
    if (protocol == XAIOS_NETWORK_PROTOCOL_UDP) {
      network_stack_register_udp_listener((uint16_t)request.port, sockfd);
    } else {
      network_stack_register_listener((uint16_t)request.port, sockfd);
    }
    klog("syscall: net_listen protocol=%lu port=%lu sockfd=%lu\n", protocol,
         request.port, sockfd);
    return XAIOS_OK;
  }

  if (syscall == XAIOS_SYSCALL_NET_ACCEPT) {
    xaios_syscall_socket_request_t request;
    uint64_t out_sockfd = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-net-accept-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (vmm_validate_user_buffer(request.out_sockfd, sizeof(out_sockfd),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        (request.addr_out_ptr != 0U &&
         vmm_validate_user_buffer(request.addr_out_ptr, 17U,
                                  XAIOS_VMM_WRITABLE) != XAIOS_OK) ||
        (request.port != 0U &&
         vmm_validate_user_buffer(request.port, sizeof(uint64_t),
                                  XAIOS_VMM_WRITABLE) != XAIOS_OK)) {
      return reject_syscall(syscall, arg0, arg1, "net-accept-denied");
    }
    const xaios_user_process_t *process = user_current_process();
    uint32_t owner_pid = process != 0 ? process->pid : 0U;
    kernel_socket_t listener;
    if (kernel_socket_snapshot_owned(request.sockfd, owner_pid, &listener) !=
            XAIOS_OK ||
        listener.state != KERNEL_SOCK_LISTEN ||
        listener.protocol != XAIOS_NETWORK_PROTOCOL_TCP) {
      return reject_syscall(syscall, arg0, arg1, "net-accept-bad-listen");
    }
    uint16_t listen_port = listener.port;
    /* Dequeue from accept queue */
    uint32_t flow_id = 0;
    uint32_t peer_ip = 0;
    uint16_t peer_port = 0;
    xaios_ip_addr_t peer_addr;
    xaios_ip_addr_zero(&peer_addr);
    network_poll_tick();
    if (network_stack_accept_connection(listen_port, &flow_id, &peer_ip,
                                          &peer_port, &peer_addr) != XAIOS_OK) {
      return UINT64_MAX;
    }
    /* Allocate connected socket */
    uint64_t connfd =
        kernel_socket_alloc(KERNEL_SOCK_CONNECTED, listen_port, owner_pid);
    if (connfd == 0) {
      network_stack_tcp_close_flow(flow_id);
      return reject_syscall(syscall, arg0, arg1, "net-accept-no-memory");
    }
    /* Store peer info on the socket */
    xaios_spin_lock(&g_kernel_socket_lock);
    kernel_socket_t *socket =
        kernel_socket_find_owned_locked(connfd, owner_pid);
    kassert(socket != 0);
    socket->peer_port = peer_port;
    socket->family = peer_addr.family;
    for (uint32_t j = 0; j < 16; ++j) {
      socket->peer_addr[j] = peer_addr.addr[j];
    }
    xaios_spin_unlock(&g_kernel_socket_lock);
    /* Map socket to flow */
    network_stack_map_socket(connfd, flow_id, 6); /* TCP */
    /* Write peer address to addr_out_ptr if requested */
    if (request.addr_out_ptr != 0) {
      uint8_t addr_buf[17];
      for (uint32_t j = 0; j < 17; ++j) addr_buf[j] = 0;
      addr_buf[0] = peer_addr.family;
      for (uint32_t j = 0; j < 16; ++j) {
        addr_buf[1U + j] = peer_addr.addr[j];
      }
      bytes_copy((void *)(uintptr_t)request.addr_out_ptr, addr_buf, 17);
    }
    if (request.port != 0) {
      *(uint64_t *)(uintptr_t)request.port = peer_port;
    }
    *(uint64_t *)(uintptr_t)request.out_sockfd = connfd;
    klog("syscall: net_accept listenfd=%lu connfd=%lu flow=%u\n",
         request.sockfd, connfd, flow_id);
    return XAIOS_OK;
  }

  if (syscall == XAIOS_SYSCALL_NET_RECV) {
    xaios_syscall_socket_request_t request;
    uint64_t out_bytes = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-net-recv-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.buffer_size == 0 ||
        request.buffer_size > XAIOS_SYSCALL_NETWORK_IO_MAX_BYTES ||
        vmm_validate_user_buffer(request.buffer, request.buffer_size,
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_bytes, sizeof(out_bytes),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        (request.addr_out_ptr != 0U &&
         vmm_validate_user_buffer(request.addr_out_ptr,
                                  sizeof(xaios_ip_addr_t),
                                  XAIOS_VMM_WRITABLE) != XAIOS_OK)) {
      return reject_syscall(syscall, arg0, arg1, "net-recv-denied");
    }
    network_poll_tick();
    const xaios_user_process_t *process = user_current_process();
    uint32_t owner_pid = process != 0 ? process->pid : 0U;
    kernel_socket_t socket_snapshot;
    if (kernel_socket_snapshot_owned(request.sockfd, owner_pid,
                                     &socket_snapshot) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "net-recv-no-socket");
    }
    if (socket_snapshot.state == KERNEL_SOCK_DATAGRAM) {
      xaios_ip_addr_t source_addr;
      uint16_t source_port = 0;
      uint32_t flow_id = 0;
      xaios_ip_addr_zero(&source_addr);
      uint32_t bytes_read = network_stack_udp_recv(
          request.sockfd, (uint8_t *)(uintptr_t)request.buffer,
          (uint32_t)request.buffer_size, &source_addr, &source_port, &flow_id);
      if (request.addr_out_ptr != 0) {
        bytes_copy((void *)(uintptr_t)request.addr_out_ptr, &source_addr,
                   sizeof(source_addr));
      }
      *(uint64_t *)(uintptr_t)request.out_bytes = bytes_read;
      (void)source_port;
      (void)flow_id;
      return XAIOS_OK;
    }
    if (socket_snapshot.state != KERNEL_SOCK_CONNECTED) {
      return reject_syscall(syscall, arg0, arg1, "net-recv-not-connected");
    }
    /* Look up a connected TCP socket. */
    socket_flow_mapping_t *mapping = network_stack_get_socket_mapping(request.sockfd);
    if (mapping == 0) {
      *(uint64_t *)(uintptr_t)request.out_bytes = 0;
      return XAIOS_OK;
    }
    /* Find the flow and read from its rx_buf */
    uint32_t bytes_read = 0;
    if (mapping->protocol == XAIOS_NETWORK_PROTOCOL_TCP) {
      bytes_read = network_stack_tcp_recv(mapping->flow_id,
          (uint8_t *)(uintptr_t)request.buffer,
          (uint32_t)request.buffer_size);
      if (bytes_read == 0 &&
          network_stack_tcp_peer_closed(mapping->flow_id) != 0) {
        *(uint64_t *)(uintptr_t)request.out_bytes = 0;
        return UINT64_MAX;
      }
    }
    *(uint64_t *)(uintptr_t)request.out_bytes = bytes_read;
    return XAIOS_OK;
  }

  if (syscall == XAIOS_SYSCALL_NET_SEND) {
    xaios_syscall_socket_request_t request;
    uint64_t out_bytes = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-net-send-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.buffer_size == 0 ||
        request.buffer_size > XAIOS_SYSCALL_NETWORK_IO_MAX_BYTES ||
        vmm_validate_user_buffer(request.buffer, request.buffer_size, 0) !=
            XAIOS_OK ||
        vmm_validate_user_buffer(request.out_bytes, sizeof(out_bytes),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "net-send-denied");
    }
    network_poll_tick();
    const xaios_user_process_t *process = user_current_process();
    uint32_t owner_pid = process != 0 ? process->pid : 0U;
    kernel_socket_t socket_snapshot;
    if (kernel_socket_snapshot_owned(request.sockfd, owner_pid,
                                     &socket_snapshot) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "net-send-no-socket");
    }
    socket_flow_mapping_t *snd_mapping =
        network_stack_get_socket_mapping(request.sockfd);
    if (snd_mapping == 0 ||
        !((socket_snapshot.state == KERNEL_SOCK_CONNECTED &&
           snd_mapping->protocol == XAIOS_NETWORK_PROTOCOL_TCP) ||
          (socket_snapshot.state == KERNEL_SOCK_DATAGRAM &&
           snd_mapping->protocol == XAIOS_NETWORK_PROTOCOL_UDP))) {
      return reject_syscall(syscall, arg0, arg1, "net-send-bad-state");
    }
    uint8_t *send_snapshot =
        (uint8_t *)kheap_alloc(request.buffer_size, 16U);
    if (send_snapshot == 0) {
      return reject_syscall(syscall, arg0, arg1, "net-send-no-memory");
    }
    bytes_copy(send_snapshot, (const void *)(uintptr_t)request.buffer,
               request.buffer_size);
    uint32_t bytes_written = 0;
    xaios_status_t snd_st = XAIOS_ERR_INVALID;
    if (snd_mapping->protocol == 6) {
      snd_st = network_stack_tcp_send(snd_mapping->flow_id,
          send_snapshot, (uint32_t)request.buffer_size, &bytes_written);
    } else if (snd_mapping->protocol == 17) {
      snd_st = network_stack_udp_send(snd_mapping->flow_id,
          send_snapshot, (uint32_t)request.buffer_size, &bytes_written);
    }
    kheap_free(send_snapshot);
    if (snd_st != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "net-send-failed");
    }
    *(uint64_t *)(uintptr_t)request.out_bytes = bytes_written;
    return XAIOS_OK;
  }

  if (syscall == XAIOS_SYSCALL_NET_CLOSE) {
    const xaios_user_process_t *process = user_current_process();
    uint32_t owner_pid = process != 0 ? process->pid : 0U;
    kernel_socket_t socket_snapshot;
    if (kernel_socket_snapshot_owned(arg0, owner_pid, &socket_snapshot) !=
        XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "net-close-no-socket");
    }
    /* Clean up flow mapping if this is a connected socket */
    socket_flow_mapping_t *close_mapping =
        network_stack_get_socket_mapping(arg0);
    if (close_mapping != 0) {
      if (close_mapping->protocol == 6) {
        network_stack_tcp_close_flow(close_mapping->flow_id);
      }
      network_stack_unmap_socket(arg0);
    }
    if (socket_snapshot.state == KERNEL_SOCK_LISTEN) {
      network_stack_unregister_listener(socket_snapshot.port);
    } else if (socket_snapshot.state == KERNEL_SOCK_DATAGRAM) {
      network_stack_unregister_udp_listener(socket_snapshot.port);
    }
    kassert(kernel_socket_free(arg0, owner_pid) == XAIOS_OK);
    klog("syscall: net_close sockfd=%lu\n", arg0);
    return XAIOS_OK;
  }

  if (syscall == XAIOS_SYSCALL_NET_RESOLVE) {
    xaios_syscall_net_resolve_request_t request;
    char hostname[64];
    uint32_t address = 0U;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-net-resolve-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (copy_user_string(request.hostname, request.hostname_size, hostname,
                         sizeof(hostname)) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_ipv4, sizeof(address),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "net-resolve-denied");
    }
    for (uint64_t i = 0U; i < request.hostname_size; ++i) {
      if (hostname[i] == '\0') {
        return reject_syscall(syscall, arg0, arg1,
                              "net-resolve-embedded-nul");
      }
    }
    network_poll_tick();
    xaios_status_t status = dns_resolve(hostname, &address);
    if (status == XAIOS_OK) {
      bytes_copy((void *)(uintptr_t)request.out_ipv4, &address,
                 sizeof(address));
    }
    user_process_note_syscall(0);
    return (uint64_t)(int64_t)status;
  }

  if (syscall == XAIOS_SYSCALL_AGENT_DISPATCH) {
    xaios_syscall_agent_dispatch_request_t request;
    xaios_agent_request_t agent_req;
    xaios_agent_response_t agent_resp;
    uint8_t agent_payload[4096];
    uint64_t out_size = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-agent-request");
    }
    bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.request_size != sizeof(agent_req) ||
        vmm_validate_user_buffer(request.request, sizeof(agent_req), 0) !=
            XAIOS_OK ||
        request.response_size != sizeof(agent_resp) ||
        vmm_validate_user_buffer(request.response, sizeof(agent_resp),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        request.output_size == 0 ||
        vmm_validate_user_buffer(request.output, request.output_size,
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_size, sizeof(out_size),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "agent-dispatch-denied");
    }
    bytes_copy(&agent_req, (const void *)(uintptr_t)request.request,
               sizeof(agent_req));
    if (request.payload_size > 0) {
      if (request.payload_size > sizeof(agent_payload) ||
          vmm_validate_user_buffer(request.payload, request.payload_size, 0) !=
              XAIOS_OK) {
        return reject_syscall(syscall, arg0, arg1, "agent-payload-denied");
      }
      bytes_copy(agent_payload, (const void *)(uintptr_t)request.payload,
                 request.payload_size);
    }
    if (agent_protocol_dispatch(&agent_req, &agent_resp,
                                request.payload_size > 0 ? agent_payload : 0,
                                request.payload_size,
                                (char *)(uintptr_t)request.output,
                                request.output_size, &out_size) != XAIOS_OK) {
      bytes_copy((void *)(uintptr_t)request.response, &agent_resp,
                 sizeof(agent_resp));
      return reject_syscall(syscall, arg0, arg1, "agent-dispatch-failed");
    }
    bytes_copy((void *)(uintptr_t)request.response, &agent_resp,
               sizeof(agent_resp));
    bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
               sizeof(out_size));
    klog("syscall: agent_dispatch cmd=%u cell=%u out=%lu\n",
         agent_req.command, agent_req.cell_id, out_size);
    return complete_control_syscall(out_size);
  }

  return reject_syscall(syscall, arg0, arg1, "unreachable");
}

void syscall_self_test(void) {
  kernel_socket_table_init();
  uint64_t owned_socket =
      kernel_socket_alloc(KERNEL_SOCK_LISTEN, 2222U, 1001U);
  kernel_socket_t socket_snapshot;
  kassert(owned_socket != 0U);
  kassert(kernel_socket_snapshot_owned(owned_socket, 1001U,
                                       &socket_snapshot) == XAIOS_OK);
  kassert(kernel_socket_snapshot_owned(owned_socket, 1002U,
                                       &socket_snapshot) ==
          XAIOS_ERR_INVALID);
  kassert(kernel_socket_free(owned_socket, 1002U) == XAIOS_ERR_INVALID);
  kassert(kernel_socket_free(owned_socket, 1001U) == XAIOS_OK);
  uint64_t owner_one_a =
      kernel_socket_alloc(KERNEL_SOCK_CONNECTED, 2222U, 1001U);
  uint64_t owner_one_b =
      kernel_socket_alloc(KERNEL_SOCK_CONNECTED, 2222U, 1001U);
  uint64_t owner_two =
      kernel_socket_alloc(KERNEL_SOCK_CONNECTED, 2222U, 1002U);
  kassert(owner_one_a != 0U && owner_one_b != 0U && owner_two != 0U);
  syscall_release_process_resources(1001U);
  kassert(kernel_socket_snapshot_owned(owner_one_a, 1001U,
                                       &socket_snapshot) ==
          XAIOS_ERR_INVALID);
  kassert(kernel_socket_snapshot_owned(owner_one_b, 1001U,
                                       &socket_snapshot) ==
          XAIOS_ERR_INVALID);
  kassert(kernel_socket_snapshot_owned(owner_two, 1002U, &socket_snapshot) ==
          XAIOS_OK);
  kassert(kernel_socket_free(owner_two, 1002U) == XAIOS_OK);
  kassert(g_total_connections == 0U);
  kassert(lookup_syscall(XAIOS_SYSCALL_LOG) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_EXIT) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_OSCTL) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_READ_SERVICE_DESCRIPTOR) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_SERVICE_STATUS) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_SERVICE_START) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_SERVICE_STOP) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_SERVICE_RESTART) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_SERVICE_ROLLBACK) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_SERVICE_UPDATE) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_FS_OPEN) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_FS_READ) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_FS_WRITE) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_FS_CLOSE) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_FS_STAT) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_FS_MKDIR) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_FS_DELETE) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_FS_RENAME) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_FS_LIST) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_CLOCK_NANOS) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_NET_UDP_ECHO) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_NET_TCP_CONNECT) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_SMP_RUN) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_CPU_AI_DECODE) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_REMOTE_LOGIN) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_NET_EXTERNAL_SESSION) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_THREAD_GROUP_RUN) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_ML_RUN) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_NET_LISTEN) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_NET_ACCEPT) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_NET_RECV) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_NET_SEND) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_NET_CLOSE) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_NET_CONNECT) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_AGENT_DISPATCH) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_RANDOM) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_FS_SEEK) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_CONTROL_QUERY) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_REMOTE_LOGIN_SESSION) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_FS_PREAD) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_FS_PWRITE) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_FS_FSYNC) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_THREAD_CREATE) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_THREAD_JOIN) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_THREAD_CANCEL) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_THREAD_EXIT) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_NET_RESOLVE) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_CONSOLE_READ) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_CONSOLE_WRITE) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_NET_LOCAL_IPV4) != 0);
  kassert(lookup_syscall(99) == 0);
  klog("syscall: socket ownership self-test passed capacity=%u per_port=%u\n",
       g_kernel_socket_capacity, g_kernel_socket_per_port_limit);
  klog("syscall: table self-test passed entries=%lu\n",
       (uint64_t)(sizeof(g_syscall_table) / sizeof(g_syscall_table[0])));
}

uint64_t syscall_control_plane_count(void) {
  return g_control_plane_syscall_count;
}

uint64_t syscall_control_plane_denial_count(void) {
  return g_control_plane_denial_count;
}

uint64_t syscall_service_descriptor_read_count(void) {
  return g_service_descriptor_read_count;
}
