#include <xaios/agent_protocol.h>
#include <xaios/arena.h>
#include <xaios/assert.h>
#include <xaios/cpu_ai_runtime.h>
#include <xaios/initramfs.h>
#include <xaios/klog.h>
#include <xaios/mutable_fs.h>
#include <xaios/network_stack.h>
#include <xaios/remote_login.h>
#include <xaios/security.h>
#include <xaios/service.h>
#include <xaios/smp.h>
#include <xaios/socket_buffer.h>
#include <xaios/syscall.h>
#include <xaios/timer.h>
#include <xaios/user.h>
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
};

static uint64_t g_control_plane_syscall_count;
static uint64_t g_control_plane_denial_count;
static uint64_t g_service_descriptor_read_count;
static uint32_t g_cpu_ai_app_bound;

/* ---- Kernel socket table (for sshd) ---- */
#define KERNEL_SOCK_LISTEN UINT32_C(1)
#define KERNEL_SOCK_CONNECTED UINT32_C(2)
#define KERNEL_SOCK_DATAGRAM UINT32_C(3)
#define KERNEL_SOCK_MAX UINT32_C(16)

/* Socket connection accounting bounds kernel flow resources. */
#define KERNEL_SOCK_MAX_PER_PORT UINT32_C(8)
#define KERNEL_SOCK_MAX_TOTAL UINT32_C(64)

typedef struct kernel_socket {
  uint32_t state;   /* 0=free, KERNEL_SOCK_LISTEN, KERNEL_SOCK_CONNECTED */
  uint16_t port;
  uint8_t  family;          /* 0=any, 4=IPv4, 6=IPv6 */
  uint8_t  protocol;        /* 6=TCP, 17=UDP */
  uint8_t  bind_addr[16];   /* bind address (16 bytes for IPv6) */
  uint8_t  peer_addr[16];   /* peer address (connected sockets) */
  uint16_t peer_port;
  uint64_t id;              /* unique socket ID from alloc */
} kernel_socket_t;

static kernel_socket_t g_kernel_sockets[KERNEL_SOCK_MAX];
static uint64_t g_socket_next_id = 1;
static uint32_t g_total_connections = 0;

static uint64_t kernel_socket_alloc(uint32_t type, uint16_t port) {
  /* Enforce the global connection limit. */
  if (g_total_connections >= KERNEL_SOCK_MAX_TOTAL) {
    klog("syscall: socket allocation denied (max connections reached: %u)\n", g_total_connections);
    return 0;
  }

  /* Enforce the per-port limit for connected sockets. */
  if (type == KERNEL_SOCK_CONNECTED) {
    uint32_t port_count = 0;
    for (uint32_t i = 0; i < KERNEL_SOCK_MAX; ++i) {
      if (g_kernel_sockets[i].state == KERNEL_SOCK_CONNECTED &&
          g_kernel_sockets[i].port == port) {
        port_count++;
      }
    }
    if (port_count >= KERNEL_SOCK_MAX_PER_PORT) {
      klog("syscall: socket allocation denied (max per-port: %u for port %u)\n",
           port_count, port);
      return 0;
    }
  }

  for (uint32_t i = 0; i < KERNEL_SOCK_MAX; ++i) {
    if (g_kernel_sockets[i].state == 0) {
      g_kernel_sockets[i].state = type;
      g_kernel_sockets[i].port = port;
      g_kernel_sockets[i].id = g_socket_next_id;
      g_total_connections++;
      return g_socket_next_id++;
    }
  }
  return 0; /* no free slots */
}

static void kernel_socket_free(uint64_t sockfd) {
  for (uint32_t i = 0; i < KERNEL_SOCK_MAX; ++i) {
    if (g_kernel_sockets[i].state != 0 && g_kernel_sockets[i].id == sockfd) {
      g_kernel_sockets[i].state = 0;
      g_kernel_sockets[i].port = 0;
      g_kernel_sockets[i].family = 0;
      g_kernel_sockets[i].protocol = 0;
      g_kernel_sockets[i].peer_port = 0;
      g_kernel_sockets[i].id = 0;
      for (uint32_t j = 0; j < 16; ++j) {
        g_kernel_sockets[i].bind_addr[j] = 0;
        g_kernel_sockets[i].peer_addr[j] = 0;
      }
      /* Release the global connection slot. */
      if (g_total_connections > 0) {
        g_total_connections--;
      }
      return;
    }
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
          syscall <= XAIOS_SYSCALL_FS_SEEK);
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
    if (vmm_validate_user_buffer(arg0, arg1, 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-user-buffer");
    }
    const char *log_src = (const char *)(uintptr_t)arg0;
    if (security_reject_credential_material_buffer(log_src, arg1) !=
        XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "log-secret-denied");
    }
    user_process_note_syscall(0);
    klog_write((const char *)(uintptr_t)arg0, arg1);
    return 0;
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
    return complete_control_syscall(timer_now_ns());
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
    int64_t fd = mutable_fs_open(path, (uint32_t)arg2);
    if (fd < 0) {
      return reject_syscall(syscall, arg0, arg1, "fs-open-denied");
    }
    return complete_control_syscall((uint64_t)fd);
  }

  if (syscall == XAIOS_SYSCALL_FS_READ) {
    if (vmm_validate_user_buffer(arg1, arg2, XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-fs-read-buffer");
    }
    int64_t bytes = mutable_fs_read_fd((uint32_t)arg0,
                                       (void *)(uintptr_t)arg1, arg2);
    if (bytes < 0) {
      return reject_syscall(syscall, arg0, arg1, "fs-read-denied");
    }
    return complete_control_syscall((uint64_t)bytes);
  }

  if (syscall == XAIOS_SYSCALL_FS_WRITE) {
    if (vmm_validate_user_buffer(arg1, arg2, 0) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "bad-fs-write-buffer");
    }
    if (security_reject_credential_material_buffer((const char *)(uintptr_t)arg1,
                                                   arg2) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "fs-write-secret-denied");
    }
    int64_t bytes = mutable_fs_write_fd((uint32_t)arg0,
                                        (const void *)(uintptr_t)arg1, arg2);
    if (bytes < 0) {
      return reject_syscall(syscall, arg0, arg1, "fs-write-denied");
    }
    return complete_control_syscall((uint64_t)bytes);
  }

  if (syscall == XAIOS_SYSCALL_FS_SEEK) {
    if (mutable_fs_seek((uint32_t)arg0, arg1) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "fs-seek-denied");
    }
    return complete_control_syscall(arg1);
  }

  if (syscall == XAIOS_SYSCALL_FS_CLOSE) {
    if (mutable_fs_close((uint32_t)arg0) != XAIOS_OK) {
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
    if (mutable_fs_stat(path, (xaios_mfs_stat_t *)(uintptr_t)arg2) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "fs-stat-denied");
    }
    return complete_control_syscall(sizeof(xaios_mfs_stat_t));
  }

  if (syscall == XAIOS_SYSCALL_FS_MKDIR) {
    char path[XAIOS_MFS_PATH_MAX];
    if (copy_user_string(arg0, arg1, path, sizeof(path)) != XAIOS_OK ||
        security_authorize_fs_write(path) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "fs-mkdir-denied");
    }
    if (mutable_fs_mkdir(path) != XAIOS_OK) {
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
    if (mutable_fs_delete(path) != XAIOS_OK) {
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
    if (mutable_fs_rename(old_path, new_path) != XAIOS_OK) {
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
    if (request.buffer_size == 0 || request.buffer_size > UINT32_MAX ||
        vmm_validate_user_buffer(request.buffer, request.buffer_size,
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_size, sizeof(out_size),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        security_authorize_fs_read(path) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "fs-list-denied");
    }
    if (mutable_fs_list(path, (char *)(uintptr_t)request.buffer,
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
    char command[96];
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
      return reject_syscall(syscall, arg0, arg1, "remote-login-failed");
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
    uint32_t socket_type = protocol == XAIOS_NETWORK_PROTOCOL_UDP
                               ? KERNEL_SOCK_DATAGRAM
                               : KERNEL_SOCK_LISTEN;
    uint64_t sockfd =
        kernel_socket_alloc(socket_type, (uint16_t)request.port);
    if (sockfd == 0) {
      return reject_syscall(syscall, arg0, arg1, "net-listen-no-memory");
    }
    /* Store bind address if provided */
    if (request.addr_ptr != 0) {
      /* addr_ptr points to xaios_ip_addr_t (17 bytes: 1 family + 16 addr) */
      uint8_t addr_buf[17];
      if (vmm_validate_user_buffer(request.addr_ptr, 17, 0) == XAIOS_OK) {
        bytes_copy(addr_buf, (const void *)(uintptr_t)request.addr_ptr, 17);
        /* Find the socket and store the bind address */
        for (uint32_t i = 0; i < KERNEL_SOCK_MAX; ++i) {
          if (g_kernel_sockets[i].state == socket_type &&
              g_kernel_sockets[i].id == sockfd) {
            g_kernel_sockets[i].family = addr_buf[0];
            for (uint32_t j = 0; j < 16; ++j) {
              g_kernel_sockets[i].bind_addr[j] = addr_buf[1 + j];
            }
            break;
          }
        }
      }
    }
    for (uint32_t i = 0; i < KERNEL_SOCK_MAX; ++i) {
      if (g_kernel_sockets[i].state == socket_type &&
          g_kernel_sockets[i].id == sockfd) {
        g_kernel_sockets[i].protocol = (uint8_t)protocol;
        break;
      }
    }
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
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "net-accept-denied");
    }
    /* Find the listen port from the listen sockfd */
    uint16_t listen_port = 0;
    for (uint32_t i = 0; i < KERNEL_SOCK_MAX; ++i) {
      if (g_kernel_sockets[i].state == KERNEL_SOCK_LISTEN &&
          g_kernel_sockets[i].protocol == XAIOS_NETWORK_PROTOCOL_TCP &&
          g_kernel_sockets[i].id == request.sockfd) {
        listen_port = g_kernel_sockets[i].port;
        break;
      }
    }
    if (listen_port == 0) {
      return reject_syscall(syscall, arg0, arg1, "net-accept-bad-listen");
    }
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
    uint64_t connfd = kernel_socket_alloc(KERNEL_SOCK_CONNECTED, listen_port);
    if (connfd == 0) {
      return reject_syscall(syscall, arg0, arg1, "net-accept-no-memory");
    }
    /* Store peer info on the socket */
    for (uint32_t i = 0; i < KERNEL_SOCK_MAX; ++i) {
      if (g_kernel_sockets[i].state == KERNEL_SOCK_CONNECTED &&
          g_kernel_sockets[i].id == connfd) {
        g_kernel_sockets[i].peer_port = peer_port;
        g_kernel_sockets[i].family = peer_addr.family;
        for (uint32_t j = 0; j < 16; ++j) {
          g_kernel_sockets[i].peer_addr[j] = peer_addr.addr[j];
        }
        break;
      }
    }
    /* Map socket to flow */
    network_stack_map_socket(connfd, flow_id, 6); /* TCP */
    /* Write peer address to addr_out_ptr if requested */
    if (request.addr_out_ptr != 0) {
      if (vmm_validate_user_buffer(request.addr_out_ptr, 17,
                                   XAIOS_VMM_WRITABLE) == XAIOS_OK) {
        uint8_t addr_buf[17];
        for (uint32_t j = 0; j < 17; ++j) { addr_buf[j] = 0; }
        addr_buf[0] = peer_addr.family;
        for (uint32_t j = 0; j < 16; ++j) {
          addr_buf[1U + j] = peer_addr.addr[j];
        }
        bytes_copy((void *)(uintptr_t)request.addr_out_ptr, addr_buf, 17);
      }
    }
    if (request.port != 0 &&
        vmm_validate_user_buffer(request.port, sizeof(uint64_t),
                                 XAIOS_VMM_WRITABLE) == XAIOS_OK) {
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
        vmm_validate_user_buffer(request.buffer, request.buffer_size,
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_bytes, sizeof(out_bytes),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "net-recv-denied");
    }
    network_poll_tick();
    for (uint32_t i = 0; i < KERNEL_SOCK_MAX; ++i) {
      if (g_kernel_sockets[i].state == KERNEL_SOCK_DATAGRAM &&
          g_kernel_sockets[i].id == request.sockfd) {
        xaios_ip_addr_t source_addr;
        uint16_t source_port = 0;
        uint32_t flow_id = 0;
        xaios_ip_addr_zero(&source_addr);
        uint32_t bytes_read = network_stack_udp_recv(
            request.sockfd, (uint8_t *)(uintptr_t)request.buffer,
            (uint32_t)request.buffer_size, &source_addr, &source_port,
            &flow_id);
        if (request.addr_out_ptr != 0 &&
            vmm_validate_user_buffer(request.addr_out_ptr, sizeof(source_addr),
                                     XAIOS_VMM_WRITABLE) == XAIOS_OK) {
          bytes_copy((void *)(uintptr_t)request.addr_out_ptr, &source_addr,
                     sizeof(source_addr));
        }
        *(uint64_t *)(uintptr_t)request.out_bytes = bytes_read;
        (void)source_port;
        (void)flow_id;
        return XAIOS_OK;
      }
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
    if (request.buffer_size == 0 || request.buffer_size > UINT32_MAX ||
        vmm_validate_user_buffer(request.buffer, request.buffer_size, 0) !=
            XAIOS_OK ||
        vmm_validate_user_buffer(request.out_bytes, sizeof(out_bytes),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "net-send-denied");
    }
    network_poll_tick();
    /* Wire to real TCP send via network stack */
    socket_flow_mapping_t *snd_mapping =
        network_stack_get_socket_mapping(request.sockfd);
    if (snd_mapping == 0) {
      return reject_syscall(syscall, arg0, arg1, "net-send-no-socket");
    }
    uint32_t bytes_written = 0;
    xaios_status_t snd_st = XAIOS_ERR_INVALID;
    if (snd_mapping->protocol == 6) {
      snd_st = network_stack_tcp_send(snd_mapping->flow_id,
          (const uint8_t *)(uintptr_t)request.buffer,
          (uint32_t)request.buffer_size, &bytes_written);
    } else if (snd_mapping->protocol == 17) {
      snd_st = network_stack_udp_send(snd_mapping->flow_id,
          (const uint8_t *)(uintptr_t)request.buffer,
          (uint32_t)request.buffer_size, &bytes_written);
    }
    if (snd_st != XAIOS_OK) {
      return reject_syscall(syscall, arg0, arg1, "net-send-failed");
    }
    *(uint64_t *)(uintptr_t)request.out_bytes = bytes_written;
    klog("syscall: net_send sockfd=%lu len=%lu written=%u\n",
         request.sockfd, request.buffer_size, bytes_written);
    return XAIOS_OK;
  }

  if (syscall == XAIOS_SYSCALL_NET_CLOSE) {
    /* Clean up flow mapping if this is a connected socket */
    socket_flow_mapping_t *close_mapping =
        network_stack_get_socket_mapping(arg0);
    if (close_mapping != 0) {
      if (close_mapping->protocol == 6) {
        network_stack_tcp_close_flow(close_mapping->flow_id);
      }
      network_stack_unmap_socket(arg0);
    }
    /* Unregister listener if this was a listen socket */
    for (uint32_t i = 0; i < KERNEL_SOCK_MAX; ++i) {
      if (g_kernel_sockets[i].id == arg0) {
        if (g_kernel_sockets[i].state == KERNEL_SOCK_LISTEN) {
          network_stack_unregister_listener(g_kernel_sockets[i].port);
        } else if (g_kernel_sockets[i].state == KERNEL_SOCK_DATAGRAM) {
          network_stack_unregister_udp_listener(g_kernel_sockets[i].port);
        }
        break;
      }
    }
    kernel_socket_free(arg0);
    klog("syscall: net_close sockfd=%lu\n", arg0);
    return XAIOS_OK;
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
  kassert(lookup_syscall(XAIOS_SYSCALL_AGENT_DISPATCH) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_RANDOM) != 0);
  kassert(lookup_syscall(XAIOS_SYSCALL_FS_SEEK) != 0);
  kassert(lookup_syscall(99) == 0);
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
