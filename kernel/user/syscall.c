#include <xaios/agent_protocol.h>
#include <xaios/arena.h>
#include <xaios/assert.h>
#include <xaios/boot_ui.h>
#include <xaios/child_channel.h>
#include <xaios/cpu_ai_runtime.h>
#include <xaios/control_protocol.h>
#include <xaios/dns.h>
#include <xaios/entropy.h>
#include <xaios/initramfs.h>
#include <xaios/ipv4.h>
#include <xaios/network_config.h>
#include <xaios/kheap.h>
#include <xaios/klog.h>
#include <xaios/local_ports.h>
#include <xaios/xaiboot_fs.h>
#include <xaios/net_device.h>
#include <xaios/network_stack.h>
#include <xaios/remote_login.h>
#include <xaios/security.h>
#include <xaios/service.h>
#include <xaios/smp.h>
#include <xaios/socket_buffer.h>
#include <xaios/spinlock.h>
#include <xaios/syscall.h>

#include "syscall_internal.h"
#include "syscall_table.h"
#include <xaios/timer.h>
#include <xaios/thread.h>
#include <xaios/user.h>
#include <xaios/vfs.h>
#include <xaios/vmm.h>
#include "syscall_family.h"

static uint64_t g_control_plane_syscall_count;
static uint64_t g_control_plane_denial_count;
static uint64_t g_service_descriptor_read_count;

/* The allocation body, with `g_kernel_socket_lock` already held.
 *
 * Split from the wrapper below so that choosing an ephemeral port and taking
 * the descriptor for it can happen inside one critical section. Doing them in
 * two -- which is what the first version did -- leaves a window in which
 * another CPU selects the same port, and the "is it in use" test it ran before
 * releasing the lock cannot see an allocation that has not happened yet. */

/* The range the kernel draws ports from when the caller does not name one.
 *
 * 49152 is where RFC 6335 puts the dynamic range, and it is the same start the
 * DNS resolver uses for the same reason. Returning 0 means the range is
 * exhausted, which is a refusal and not a wrap: a caller told port 0 would
 * believe it had been given one. */
/* The floor of the dynamic range, and the allocator's alone: the kernel's own
   protocols source from the block below it rather than from inside it. The
   partition is stated in `local_ports.h` so the three claimants cannot drift
   into one another again (B-77). */

/* Draw the next ephemeral port, advancing the shared counter atomically.
 *
 * A plain load, increment and store is a lost-update race: two CPUs both load
 * P, both store P+1, and both keep P. For the datagram path that would mean two
 * descriptors on one port, and the reply lookup stops at the first match, so
 * the second socket would be silent forever.
 *
 * The counter is advanced with a compare-and-swap rather than a fetch-and-add
 * so that the value written back is the wrapped one: the add would leave 0,
 * 1, ... in the counter for a moment, and a draw reading it in that window
 * would be handed a port outside the dynamic range. Nothing else writes the
 * counter, so the loop converges on the first attempt in the ordinary case. */

/* Select an ephemeral port and allocate the datagram descriptor for it, or
 * return 0 with `*out_port` untouched.
 *
 * Both halves happen under `g_kernel_socket_lock`, and that is the point of
 * the function rather than an accident of it. The first version drew a port,
 * tested whether any descriptor held it, released the lock, and then allocated
 * -- and every step of that is a separate window. Two CPUs could draw the same
 * value, because the counter was a plain read-modify-write with nothing
 * serialising it; and even with distinct values, a scan for "is it in use"
 * cannot see an allocation that has not happened yet, so two CPUs could each
 * find the same port free. Either way two live descriptors end up holding one
 * port, and because a reply is looked up by port and the lookup stops at the
 * first match, the second socket is unreachable with nothing said.
 *
 * `netmqtest` exists to run two syscall-issuing threads on two CPUs at once,
 * so this is the shape the machine is already exercised in -- it was simply
 * never a case anyone had asked a port-selection question in.
 *
 * The caller must have released every other lock: this takes the socket lock
 * and, on failure, logs while holding it. */

/* Whether any socket this owner holds has something a non-blocking call
   would return. The owner's sockets are copied out under the table lock
   first: the network stack has a lock of its own, and the two are never
   held together. */

/* A word that may alias anything: these helpers fill structs that are
   then read through their own types, and a plain uint64_t store could
   be reordered past those reads under strict aliasing. */
typedef uint64_t __attribute__((may_alias)) xaios_copy_word_t;

void syscall_dispatch_bytes_copy(void *dst, const void *src, uint64_t size) {
  uint8_t *out = (uint8_t *)dst;
  const uint8_t *in = (const uint8_t *)src;
  uint64_t i = 0;
  /* A word at a time where both sides allow it: the control plane moves
     several kilobytes per query, and under emulation a byte loop over them
     was a measurable part of every query. */
  if ((((uintptr_t)out | (uintptr_t)in) & 7U) == 0U) {
    for (; i + 8U <= size; i += 8U) {
      *(xaios_copy_word_t *)(void *)(out + i) =
          *(const xaios_copy_word_t *)(const void *)(in + i);
    }
  }
  for (; i < size; ++i) {
    out[i] = in[i];
  }
}

static int is_control_plane_syscall(uint64_t syscall) {
  return syscall == XAIOS_SYSCALL_OSCTL ||
         (syscall >= XAIOS_SYSCALL_READ_SERVICE_DESCRIPTOR &&
          syscall <= XAIOS_SYSCALL_FS_FSYNC);
}

uint64_t syscall_dispatch_reject(uint64_t syscall, uint64_t arg0, uint64_t arg1,
                               const char *reason) {
  user_process_note_syscall(1);
  if (is_control_plane_syscall(syscall)) {
    ++g_control_plane_denial_count;
  }
  klog("user: rejected syscall=%lu arg0=0x%lx arg1=0x%lx reason=%s\n",
       syscall, arg0, arg1, reason);
  return UINT64_C(-1);
}

uint64_t syscall_dispatch_complete(uint64_t value) {
  ++g_control_plane_syscall_count;
  user_process_note_syscall(0);
  return value;
}

uint64_t syscall_dispatch(uint64_t syscall, uint64_t arg0, uint64_t arg1,
                          uint64_t arg2) {
  (void)arg2;

  const xaios_syscall_entry_t *entry = syscall_table_lookup(syscall);
  if (entry == 0) {
    return syscall_dispatch_reject(syscall, arg0, arg1, "unknown");
  }
  if (user_process_has_capability(entry->required_capability) != XAIOS_OK) {
    const xaios_user_process_t *process = user_current_process();
    uint64_t granted = process != 0 ? process->capability_mask : 0;
    (void)security_authorize_capability(entry->name, granted,
                                        entry->required_capability);
    /* Who was refused, and what they were holding.
       "missing-capability" alone cannot tell a program that was never given
       a capability from one whose current-process binding has been lost --
       and the second is a kernel fault wearing the first's words. The pid is
       what separates them: a program that has been printing happily and is
       suddenly refused `console_write` with pid=0 was not denied anything,
       it was unbound. */
    klog("user: %s refused for cpu=%u pid=%u name=%s granted=0x%lx "
         "needed=0x%lx\n", entry->name, smp_cpu_id(),
         process != 0 ? process->pid : 0U,
         process != 0 ? process->name : "(none)", granted,
         entry->required_capability);
    if (process == 0) {
      static uint32_t reported;
      if (reported < 2U) {
        ++reported;
        user_current_process_debug();
      }
    }
    return syscall_dispatch_reject(syscall, arg0, arg1, "missing-capability");
  }

  if (syscall == XAIOS_SYSCALL_LOG) return syscall_time(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_CONSOLE_READ) return syscall_time(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_WAIT_EVENTS) return syscall_time(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_SLEEP_NANOS) return syscall_time(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_CONSOLE_SIZE) return syscall_time(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_CONSOLE_WRITE) return syscall_time(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_NET_LOCAL_IPV6) return syscall_netio(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_NET_LOCAL_IPV4) return syscall_netio(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_EXIT) return syscall_process(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_CLOCK_NANOS) return syscall_time(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_RANDOM) {
    if (arg1 == 0U || arg1 > 4096U ||
        vmm_validate_user_buffer(arg0, arg1, XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-random-buffer");
    }
    if (entropy_read((void *)(uintptr_t)arg0, arg1) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "entropy-unavailable");
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
      return syscall_dispatch_reject(syscall, arg0, arg1, "descriptor-read-denied");
    }
    syscall_dispatch_bytes_copy((void *)(uintptr_t)arg0, file->base, file->size);
    ++g_service_descriptor_read_count;
    klog("user: service descriptor read path=%s bytes=%lu\n",
         config->service_descriptor_path, file->size);
    return syscall_dispatch_complete(file->size);
  }

  if (syscall == XAIOS_SYSCALL_OSCTL) return syscall_control(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_CONTROL_QUERY) return syscall_control(syscall, arg0, arg1, arg2);

  if (syscall >= XAIOS_SYSCALL_SERVICE_STATUS &&
      syscall <= XAIOS_SYSCALL_SERVICE_ROLLBACK) {
    return syscall_control(syscall, arg0, arg1, arg2);
  }

  if (syscall == XAIOS_SYSCALL_SERVICE_UPDATE) return syscall_control(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_FS_OPEN) return syscall_file(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_FS_READ) return syscall_file(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_FS_WRITE) return syscall_file(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_FS_PREAD ||
      syscall == XAIOS_SYSCALL_FS_PWRITE) {
    return syscall_file(syscall, arg0, arg1, arg2);
  }

  if (syscall == XAIOS_SYSCALL_FS_FSYNC) return syscall_file(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_FS_SEEK) return syscall_file(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_FS_CLOSE) return syscall_file(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_FS_STAT) return syscall_file(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_FS_MKDIR) return syscall_file(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_FS_DELETE) return syscall_file(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_FS_RENAME) return syscall_file(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_FS_LIST) return syscall_file(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_NET_UDP_ECHO) return syscall_netio(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_NET_TCP_CONNECT) return syscall_netio(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_SMP_RUN) return syscall_process(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_CPU_AI_DECODE) return syscall_compute(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_REMOTE_LOGIN) return syscall_control(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_REMOTE_LOGIN_SESSION) return syscall_control(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_NET_EXTERNAL_SESSION) return syscall_netio(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_THREAD_GROUP_RUN) return syscall_process(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_THREAD_CREATE) return syscall_process(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_THREAD_JOIN) return syscall_process(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_THREAD_CANCEL) return syscall_process(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_THREAD_EXIT) return syscall_process(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_ML_RUN) return syscall_compute(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_NET_CONNECT) return syscall_net(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_NET_LISTEN) return syscall_net(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_NET_OPEN_UDP) return syscall_net(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_NET_ACCEPT) return syscall_net(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_NET_RECV) return syscall_netio(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_NET_SEND) return syscall_netio(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_NET_CLOSE) return syscall_net(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_NET_RESOLVE) return syscall_netio(syscall, arg0, arg1, arg2);

  if (syscall == XAIOS_SYSCALL_AGENT_DISPATCH) return syscall_control(syscall, arg0, arg1, arg2);

  return syscall_dispatch_reject(syscall, arg0, arg1, "unreachable");
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
  kassert(syscall_socket_total_connections() == 0U);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_LOG) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_EXIT) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_OSCTL) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_READ_SERVICE_DESCRIPTOR) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_SERVICE_STATUS) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_SERVICE_START) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_SERVICE_STOP) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_SERVICE_RESTART) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_SERVICE_ROLLBACK) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_SERVICE_UPDATE) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_FS_OPEN) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_FS_READ) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_FS_WRITE) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_FS_CLOSE) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_FS_STAT) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_FS_MKDIR) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_FS_DELETE) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_FS_RENAME) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_FS_LIST) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_CLOCK_NANOS) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_NET_UDP_ECHO) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_NET_TCP_CONNECT) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_SMP_RUN) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_CPU_AI_DECODE) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_REMOTE_LOGIN) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_NET_EXTERNAL_SESSION) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_THREAD_GROUP_RUN) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_ML_RUN) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_NET_LISTEN) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_NET_ACCEPT) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_NET_RECV) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_NET_SEND) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_NET_CLOSE) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_NET_CONNECT) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_WAIT_EVENTS) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_AGENT_DISPATCH) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_RANDOM) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_FS_SEEK) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_CONTROL_QUERY) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_REMOTE_LOGIN_SESSION) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_FS_PREAD) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_FS_PWRITE) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_FS_FSYNC) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_THREAD_CREATE) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_THREAD_JOIN) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_THREAD_CANCEL) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_THREAD_EXIT) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_NET_RESOLVE) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_CONSOLE_READ) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_CONSOLE_WRITE) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_CONSOLE_SIZE) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_SLEEP_NANOS) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_NET_LOCAL_IPV4) != 0);
  kassert(syscall_table_lookup(XAIOS_SYSCALL_NET_OPEN_UDP) != 0);
  kassert(syscall_table_lookup(99) == 0);
  klog("syscall: socket ownership self-test passed capacity=%u per_port=%u\n",
       syscall_socket_capacity(), syscall_socket_per_port_limit());
  klog("syscall: table self-test passed entries=%lu\n",
       syscall_table_entry_count());
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
