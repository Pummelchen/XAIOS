/*
 * The time syscall family. See syscall_family.h.
 *
 * Lifted out of syscall_dispatch in syscall.c, whose blocks for these
 * numbers are reproduced here verbatim: same guards, same order, same
 * error reasons.
 */

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

uint64_t syscall_time(uint64_t syscall, uint64_t arg0,
                                                      uint64_t arg1, uint64_t arg2) {
  (void)arg2;

  if (syscall == XAIOS_SYSCALL_LOG) {
    char log_snapshot[XAIOS_SYSCALL_LOG_MAX_BYTES];
    if (arg1 == 0U || arg1 > sizeof(log_snapshot) ||
        vmm_validate_user_buffer(arg0, arg1, 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-user-buffer");
    }
    syscall_dispatch_bytes_copy(log_snapshot, (const void *)(uintptr_t)arg0, arg1);
    if (security_reject_credential_material_buffer(log_snapshot, arg1) !=
        XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "log-secret-denied");
    }
    user_process_note_syscall(0);
    klog_write_atomic(log_snapshot, arg1);
    return 0;
  }

  if (syscall == XAIOS_SYSCALL_CONSOLE_READ) {
    uint8_t value = 0U;
    /* The console's owner polls this constantly; it is where a present the
       terminal deferred gets made. */
    boot_ui_present_pending();
    if (arg1 != 1U ||
        vmm_validate_user_buffer(arg0, 1U, XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-console-read-buffer");
    }
    if (!klog_console_read_char(&value)) {
      user_process_note_syscall(0);
      return 0U;
    }
    syscall_dispatch_bytes_copy((void *)(uintptr_t)arg0, &value, 1U);
    user_process_note_syscall(0);
    return 1U;
  }

  if (syscall == XAIOS_SYSCALL_WAIT_EVENTS) {
    /* Block until there is something the caller could act on -- console
       input, a packet or connection on a socket it owns, output or an exit
       from a child it started -- or the timeout, bounded to a second. Each
       kind is checked only for a process that could read it, or the wait
       would return at once for ever. The network stack is driven from here
       while the caller sleeps, as it is from the calls the caller is not
       making; a sleep slice bounds how long anything that raises no
       interrupt waits to be noticed. */
    uint64_t timeout_ns = arg0 > UINT64_C(1000000000) ? UINT64_C(1000000000)
                                                      : arg0;
    const xaios_user_process_t *process = user_current_process();
    uint32_t owner_token = process != 0 ? process->owner_token : 0U;
    uint32_t pid = process != 0 ? process->pid : 0U;
    uint64_t mask = process != 0 ? process->capability_mask : 0U;
    int watch_console = (mask & XAIOS_CAP_CONSOLE) != 0U;
    int watch_sockets = (mask & XAIOS_CAP_NET_SOCKET) != 0U;
    int watch_children = (mask & XAIOS_CAP_REMOTE_LOGIN) != 0U;
    uint64_t deadline_ns = timer_now_ns() + timeout_ns;
    uint64_t events = 0U;
    uint64_t slice_ns = XAIOS_WAIT_SLICE_NS;
    /* Driving the stack is most of what a look costs under emulation, and
       for a link that raises interrupts almost every look found nothing:
       the tick now runs when a frame actually arrived, and otherwise on a
       slow cadence that keeps the timers behind it moving. A link with no
       interrupt is still polled every slice, because nothing else empties
       its ring. */
    int poll_every_slice =
        watch_sockets != 0 && network_device_interrupt_driven() == 0;
    uint64_t seen_activity = network_device_activity();
    /* Whether asking "is any socket ready" could give a different answer than
       last time. Deriving it walks the socket table under its lock and then,
       per socket this caller owns, the flow table under the network lock --
       thousands of iterations to say "no" while nothing is arriving. The
       stack bumps a generation where a socket can become ready; until it
       moves, the previous answer stands. UINT64_MAX so the first look always
       derives one. */
    uint64_t seen_readiness = UINT64_MAX;
    int sockets_ready = 0;
    uint64_t next_housekeeping_ns = 0U;
    for (;;) {
      if (watch_console) boot_ui_present_pending();
      /* Only a process that could receive drives the network stack: for
         the others the tick is a cost with nothing to show for it. */
      if (watch_sockets) {
        uint64_t activity = network_device_activity();
        uint64_t look_ns = timer_now_ns();
        if (poll_every_slice != 0 || activity != seen_activity ||
            look_ns >= next_housekeeping_ns) {
          seen_activity = activity;
          next_housekeeping_ns = look_ns + XAIOS_WAIT_HOUSEKEEPING_NS;
          network_poll_tick();
        }
      }
      if (watch_console && klog_console_input_pending()) {
        events |= XAIOS_WAIT_EVENT_CONSOLE;
      }
      if (watch_sockets) {
        uint64_t readiness = network_readiness_generation();
        if (readiness != seen_readiness) {
          seen_readiness = readiness;
          sockets_ready = kernel_sockets_ready_for(owner_token);
        }
        if (sockets_ready != 0) events |= XAIOS_WAIT_EVENT_SOCKET;
      }
      if (watch_children && child_channel_pending_for(pid)) {
        events |= XAIOS_WAIT_EVENT_CHILD;
      }
      uint64_t now_ns = timer_now_ns();
      if (events != 0U || now_ns >= deadline_ns) break;
      uint64_t slice_end_ns = now_ns + slice_ns;
      /* The one caller that wants an early return: everything it is waiting
         for arrives as an interrupt, and a sleep that ran to its deadline
         would hold the answer for the rest of the slice. A plain sleep must
         not do this -- a program that asked for a second and got a packet
         has not slept for a second. */
      user_process_idle_until_event(slice_end_ns < deadline_ns ? slice_end_ns
                                                               : deadline_ns);
      if (slice_ns < XAIOS_WAIT_SLICE_MAX_NS) slice_ns *= 2U;
    }
    user_process_note_syscall(0);
    return events;
  }

  if (syscall == XAIOS_SYSCALL_SLEEP_NANOS) {
    /* Bounded to a second so a caller cannot park itself for ever by
       mistake; the idle wait gives the CPU up, which is the whole point. */
    uint64_t nanoseconds = arg0 > UINT64_C(1000000000) ? UINT64_C(1000000000)
                                                       : arg0;
    uint64_t now_ns = timer_now_ns();
    user_process_idle_until(now_ns + nanoseconds);
    user_process_note_syscall(0);
    return 0U;
  }

  if (syscall == XAIOS_SYSCALL_CONSOLE_SIZE) {
    /* Columns in the high half, rows in the low half; zero when the console
       has no size to report, which is what a serial line answers. */
    uint32_t columns = 0U;
    uint32_t rows = 0U;
    boot_ui_terminal_size(&columns, &rows);
    user_process_note_syscall(0);
    return ((uint64_t)columns << 32) | (uint64_t)rows;
  }

  if (syscall == XAIOS_SYSCALL_CONSOLE_WRITE) {
    char output[XAIOS_SYSCALL_LOG_MAX_BYTES];
    if (arg1 == 0U || arg1 > sizeof(output) ||
        vmm_validate_user_buffer(arg0, arg1, 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-console-write-buffer");
    }
    syscall_dispatch_bytes_copy(output, (const void *)(uintptr_t)arg0, arg1);
    if (arg1 == sizeof(xaios_boot_ui_control_t)) {
      xaios_boot_ui_control_t control;
      syscall_dispatch_bytes_copy(&control, output, sizeof(control));
      if (boot_ui_handle_control(&control) != 0U) {
        user_process_note_syscall(0);
        return arg1;
      }
    }
    klog_console_write(output, arg1);
    user_process_note_syscall(0);
    return arg1;
  }

  if (syscall == XAIOS_SYSCALL_CLOCK_NANOS) {
    if (arg0 == XAIOS_CLOCK_MONOTONIC) {
      return syscall_dispatch_complete(timer_now_ns());
    }
    if (arg0 == XAIOS_CLOCK_REALTIME) {
      return syscall_dispatch_complete(wall_time_now_ns());
    }
    if (arg0 == XAIOS_CLOCK_PROCESS_CPU) {
      const xaios_user_process_t *current = user_current_process();
      xaios_user_process_t snapshot;
      if (current == 0 ||
          user_process_snapshot_at(current->pid, timer_now_ns(), &snapshot) !=
              XAIOS_OK) {
        return syscall_dispatch_reject(syscall, arg0, arg1, "clock-process-unavailable");
      }
      return syscall_dispatch_complete(snapshot.runtime_ns);
    }
    return syscall_dispatch_reject(syscall, arg0, arg1, "clock-selector-invalid");
  }

  return syscall_dispatch_reject(syscall, arg0, arg1, "unreachable");
}
