/*
 * The control syscall family. See syscall_family.h.
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

static xaios_status_t child_process_ready(uint32_t pid, void *opaque) {
  return child_channel_bind_child((uint64_t)(uintptr_t)opaque, pid);
}

static void child_process_complete(uint32_t pid, int exit_code, void *opaque) {
  (void)child_channel_finish((uint64_t)(uintptr_t)opaque, pid, exit_code);
}

uint64_t syscall_control(uint64_t syscall, uint64_t arg0,
                                                         uint64_t arg1, uint64_t arg2) {
  (void)arg2;

  if (syscall == XAIOS_SYSCALL_OSCTL) {
    char command[128];
    if (syscall_table_copy_user_string(arg0, arg1, command, sizeof(command)) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-user-string");
    }
    if (security_reject_credential_material(command) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "osctl-secret-denied");
    }
    klog("user: osctl command='%s'\n", command);
    if (osctl_execute(command) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "osctl-denied");
    }
    return syscall_dispatch_complete(0);
  }

  if (syscall == XAIOS_SYSCALL_CONTROL_QUERY) {
    xaios_syscall_control_query_request_t query;
    uint8_t request[XAIOS_CONTROL_MAX_REQUEST_BYTES];
    uint8_t *response = 0;
    uint64_t response_bytes = 0U;
    if (arg1 != sizeof(query) ||
        vmm_validate_user_buffer(arg0, sizeof(query), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1,
                            "bad-control-query-request");
    }
    syscall_dispatch_bytes_copy(&query, (const void *)(uintptr_t)arg0, sizeof(query));
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
      return syscall_dispatch_reject(syscall, arg0, arg1, "control-query-denied");
    }
    syscall_dispatch_bytes_copy(request, (const void *)(uintptr_t)query.request,
               query.request_size);
    const xaios_control_request_header_t *control_request =
        (const xaios_control_request_header_t *)(const void *)request;
    uint64_t operation_capability =
        syscall_table_control_operation_capability(control_request->operation);
    if (operation_capability != 0U &&
        user_process_has_capability(operation_capability) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1,
                            "control-operation-capability-denied");
    }
    response = (uint8_t *)kheap_calloc(query.response_size, 16U);
    if (response == 0) {
      return syscall_dispatch_reject(syscall, arg0, arg1,
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
      return syscall_dispatch_reject(syscall, arg0, arg1,
                            "control-query-dispatch-failed");
    }
    syscall_dispatch_bytes_copy((void *)(uintptr_t)query.response, response, response_bytes);
    syscall_dispatch_bytes_copy((void *)(uintptr_t)query.out_size, &response_bytes,
               sizeof(response_bytes));
    kheap_free(response);
    return syscall_dispatch_complete(response_bytes);
  }

  if (syscall >= XAIOS_SYSCALL_SERVICE_STATUS &&
      syscall <= XAIOS_SYSCALL_SERVICE_ROLLBACK) {
    char service_name[64];
    if (syscall_table_copy_user_string(arg0, arg1, service_name, sizeof(service_name)) !=
        XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-service-name");
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
      return syscall_dispatch_reject(syscall, arg0, arg1, "service-control-denied");
    }
    return syscall_dispatch_complete(0);
  }

  if (syscall == XAIOS_SYSCALL_SERVICE_UPDATE) {
    char signature[128];
    if (syscall_table_copy_user_string(arg0, arg1, signature, sizeof(signature)) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-update-signature");
    }
    if (service_update(signature) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "update-denied");
    }
    return syscall_dispatch_complete(0);
  }

  if (syscall == XAIOS_SYSCALL_REMOTE_LOGIN) {
    xaios_syscall_remote_login_request_t request;
    char user[32];
    char command[256];
    uint64_t out_size = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-remote-login-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (syscall_table_copy_user_string(request.user, request.user_size, user,
                         sizeof(user)) != XAIOS_OK ||
        syscall_table_copy_user_string(request.command, request.command_size, command,
                         sizeof(command)) != XAIOS_OK ||
        request.output_size == 0 ||
        vmm_validate_user_buffer(request.output, request.output_size,
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_size, sizeof(out_size),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "remote-login-denied");
    }
    if (remote_login_execute(user, command, (char *)(uintptr_t)request.output,
                             request.output_size, &out_size) != XAIOS_OK) {
      syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
                 sizeof(out_size));
      return syscall_dispatch_reject(syscall, arg0, arg1, "remote-login-failed");
    }
    syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
               sizeof(out_size));
    return syscall_dispatch_complete(out_size);
  }

  if (syscall == XAIOS_SYSCALL_REMOTE_LOGIN_SESSION) {
    xaios_syscall_remote_login_session_request_t request;
    char user[32];
    char command[256];
    char cwd[256];
    uint64_t out_size = 0U;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1,
                            "bad-remote-login-session-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
    if (request.session_id == 0U) {
      return syscall_dispatch_reject(syscall, arg0, arg1,
                            "remote-login-session-id-invalid");
    }
    if (request.action == XAIOS_REMOTE_LOGIN_SESSION_CLOSE) {
      if (request.user != 0U || request.user_size != 0U ||
          request.command != 0U || request.command_size != 0U ||
          request.output != 0U || request.output_size != 0U ||
          request.out_size != 0U || request.metadata != 0U ||
          request.metadata_size != 0U) {
        return syscall_dispatch_reject(syscall, arg0, arg1,
                              "remote-login-session-close-malformed");
      }
      /* Closing a session that was never opened is not a denial.
         sshd closes the session of every connection it tears down, because
         it cannot know whether the kernel allocated a context for it -- that
         is the B-25 fix, and the alternative was the flag that got it wrong.
         Counting each of those as a rejected syscall would put a line in the
         log and a denial in the control-plane count for every connection
         that never ran a command, which is most of them. A malformed request
         is still refused above; this is the ordinary case. */
      (void)remote_login_close_session(request.session_id);
      return syscall_dispatch_complete(0U);
    }
    const xaios_user_process_t *caller = user_current_process();
    uint32_t caller_pid = caller == 0 ? 0U : caller->pid;
    if (request.action == XAIOS_REMOTE_LOGIN_SESSION_CHILD_OPEN) {
      const xaios_initramfs_file_t *file = 0;
      uint64_t channel_id = 0U;
      uint32_t child_pid = 0U;
      uint64_t child_thread = 0U;
      char channel_text[21];
      const char *argv[4];
      const char *child_path = 0;
      if (caller_pid == 0U ||
          syscall_table_copy_user_string(request.command, request.command_size, command,
                           sizeof(command)) != XAIOS_OK ||
          syscall_table_copy_user_string(request.metadata, request.metadata_size, cwd,
                           sizeof(cwd)) != XAIOS_OK ||
          request.output != 0U || request.output_size != 0U ||
          request.out_size == 0U ||
          vmm_validate_user_buffer(request.out_size, sizeof(channel_id),
                                   XAIOS_VMM_WRITABLE) != XAIOS_OK) {
        return syscall_dispatch_reject(syscall, arg0, arg1, "child-channel-open-denied");
      }
      /* Which program the session wants as a child. The process monitor is
         a child too now: one process that streams frames for as long as the
         session lasts, rather than a launch per frame -- which is what
         makes sixty frames a second a matter of writing them. */
      int child_is_xtop = syscall_table_command_starts_with(command, "xtop");
      child_path = child_is_xtop ? "/bin/xtop"
                   : syscall_table_command_starts_with(command, "scp") ? "/bin/scp"
                                                          : "/bin/ssh";
      xaios_status_t child_status = initramfs_lookup(child_path, &file);
      if (child_status != XAIOS_OK || file == 0 || file->executable == 0U) {
        return child_status == XAIOS_OK ? XAIOS_ERR_NOT_FOUND : child_status;
      }
      child_status = child_channel_open(caller_pid, request.session_id,
                                        &channel_id);
      if (child_status != XAIOS_OK) return child_status;
      syscall_table_format_u64_decimal(channel_id, channel_text);
      argv[0] = child_path;
      argv[1] = channel_text;
      argv[2] = cwd;
      argv[3] = command;
      uint64_t child_caps =
          child_is_xtop
              ? (XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_TIME |
                 XAIOS_CAP_REMOTE_LOGIN | XAIOS_CAP_CONTROL_QUERY)
              : (XAIOS_CAP_LOG | XAIOS_CAP_EXIT | XAIOS_CAP_NET |
                 XAIOS_CAP_NET_SOCKET | XAIOS_CAP_FS_READ |
                 XAIOS_CAP_FS_WRITE | XAIOS_CAP_TIME |
                 XAIOS_CAP_REMOTE_LOGIN | XAIOS_CAP_RANDOM |
                 XAIOS_CAP_CREDENTIAL_READ);
      child_status = user_process_start_async(
              file, child_caps,
              4U, argv, caller_pid, child_process_ready,
              child_process_complete, (void *)(uintptr_t)channel_id,
              &child_pid, &child_thread);
      if (child_status != XAIOS_OK) {
        (void)child_channel_cancel(channel_id, caller_pid);
        (void)child_channel_release(channel_id, caller_pid);
        return child_status;
      }
      syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_size, &channel_id,
                 sizeof(channel_id));
      klog("child-channel: opened id=%lu parent=%u child=%u detached=%u\n",
           channel_id, caller_pid, child_pid, child_thread == 0U ? 1U : 0U);
      return syscall_dispatch_complete(channel_id);
    }
    if (request.action == XAIOS_REMOTE_LOGIN_SESSION_CHILD_WRITE) {
      if (caller_pid == 0U || request.command_size == 0U ||
          request.command_size > XAIOS_CHILD_CHANNEL_BUFFER_BYTES ||
          request.user != 0U || request.user_size != 0U ||
          request.output != 0U || request.output_size != 0U ||
          request.out_size != 0U || request.metadata != 0U ||
          request.metadata_size != 0U ||
          vmm_validate_user_buffer(request.command, request.command_size, 0U) !=
              XAIOS_OK) {
        return syscall_dispatch_reject(syscall, arg0, arg1, "child-channel-write-failed");
      }
      {
        xaios_status_t write_status = child_channel_write(
            request.session_id, caller_pid,
            (const void *)(uintptr_t)request.command, request.command_size);
        /* A full ring is flow control, not a violation: the writer is told
           to wait and nothing is logged. A process monitor writing frames
           faster than a slow link drained them logged a rejection every
           millisecond, thousands of lines for a channel doing its job. */
        if (write_status == XAIOS_ERR_BUSY) {
          user_process_note_syscall(0);
          return (uint64_t)(int64_t)XAIOS_ERR_BUSY;
        }
        if (write_status != XAIOS_OK) {
          return syscall_dispatch_reject(syscall, arg0, arg1, "child-channel-write-failed");
        }
      }
      return syscall_dispatch_complete(request.command_size);
    }
    if (request.action == XAIOS_REMOTE_LOGIN_SESSION_CHILD_READ) {
      if (caller_pid == 0U || request.user != 0U || request.user_size != 0U ||
          request.command != 0U || request.command_size != 0U ||
          request.metadata != 0U || request.metadata_size != 0U ||
          request.output_size == 0U ||
          request.output_size > XAIOS_CHILD_CHANNEL_BUFFER_BYTES ||
          request.out_size == 0U ||
          vmm_validate_user_buffer(request.output, request.output_size,
                                   XAIOS_VMM_WRITABLE) != XAIOS_OK ||
          vmm_validate_user_buffer(request.out_size, sizeof(out_size),
                                   XAIOS_VMM_WRITABLE) != XAIOS_OK ||
          child_channel_read(request.session_id, caller_pid,
                             (void *)(uintptr_t)request.output,
                             request.output_size, &out_size) != XAIOS_OK) {
        return syscall_dispatch_reject(syscall, arg0, arg1, "child-channel-read-failed");
      }
      syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
                 sizeof(out_size));
      return syscall_dispatch_complete(out_size);
    }
    if (request.action == XAIOS_REMOTE_LOGIN_SESSION_CHILD_STATUS) {
      uint64_t status = 0U;
      if (caller_pid == 0U || request.user != 0U || request.user_size != 0U ||
          request.command != 0U || request.command_size != 0U ||
          request.output != 0U || request.output_size != 0U ||
          request.metadata != 0U || request.metadata_size != 0U ||
          request.out_size == 0U ||
          vmm_validate_user_buffer(request.out_size, sizeof(status),
                                   XAIOS_VMM_WRITABLE) != XAIOS_OK ||
          child_channel_status(request.session_id, caller_pid, &status) !=
              XAIOS_OK) {
        return syscall_dispatch_reject(syscall, arg0, arg1, "child-channel-status-failed");
      }
      syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_size, &status, sizeof(status));
      return syscall_dispatch_complete(status);
    }
    if (request.action == XAIOS_REMOTE_LOGIN_SESSION_CHILD_CANCEL) {
      if (caller_pid == 0U || request.user != 0U || request.user_size != 0U ||
          request.command != 0U || request.command_size != 0U ||
          request.output != 0U || request.output_size != 0U ||
          request.out_size != 0U || request.metadata != 0U ||
          request.metadata_size != 0U ||
          child_channel_cancel(request.session_id, caller_pid) != XAIOS_OK) {
        return syscall_dispatch_reject(syscall, arg0, arg1, "child-channel-cancel-failed");
      }
      return syscall_dispatch_complete(0U);
    }
    if (request.action == XAIOS_REMOTE_LOGIN_SESSION_CHILD_RELEASE) {
      if (caller_pid == 0U || request.user != 0U || request.user_size != 0U ||
          request.command != 0U || request.command_size != 0U ||
          request.output != 0U || request.output_size != 0U ||
          request.out_size != 0U || request.metadata != 0U ||
          request.metadata_size != 0U ||
          child_channel_release(request.session_id, caller_pid) != XAIOS_OK) {
        return syscall_dispatch_reject(syscall, arg0, arg1, "child-channel-release-failed");
      }
      return syscall_dispatch_complete(0U);
    }
    if (request.action != XAIOS_REMOTE_LOGIN_SESSION_EXECUTE ||
        syscall_table_copy_user_string(request.user, request.user_size, user,
                         sizeof(user)) != XAIOS_OK ||
        syscall_table_copy_user_string(request.command, request.command_size, command,
                         sizeof(command)) != XAIOS_OK ||
        request.output_size == 0U ||
        request.metadata != 0U || request.metadata_size != 0U ||
        vmm_validate_user_buffer(request.output, request.output_size,
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK ||
        vmm_validate_user_buffer(request.out_size, sizeof(out_size),
                                 XAIOS_VMM_WRITABLE) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1,
                            "remote-login-session-denied");
    }
    if (remote_login_execute_session(
            request.session_id, user, command,
            (char *)(uintptr_t)request.output, request.output_size,
            &out_size) != XAIOS_OK) {
      syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
                 sizeof(out_size));
      return syscall_dispatch_reject(syscall, arg0, arg1,
                            "remote-login-session-failed");
    }
    syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
               sizeof(out_size));
    return syscall_dispatch_complete(out_size);
  }

  if (syscall == XAIOS_SYSCALL_AGENT_DISPATCH) {
    xaios_syscall_agent_dispatch_request_t request;
    xaios_agent_request_t agent_req;
    xaios_agent_response_t agent_resp;
    uint8_t agent_payload[4096];
    uint64_t out_size = 0;
    if (arg1 != sizeof(request) ||
        vmm_validate_user_buffer(arg0, sizeof(request), 0) != XAIOS_OK) {
      return syscall_dispatch_reject(syscall, arg0, arg1, "bad-agent-request");
    }
    syscall_dispatch_bytes_copy(&request, (const void *)(uintptr_t)arg0, sizeof(request));
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
      return syscall_dispatch_reject(syscall, arg0, arg1, "agent-dispatch-denied");
    }
    syscall_dispatch_bytes_copy(&agent_req, (const void *)(uintptr_t)request.request,
               sizeof(agent_req));
    if (request.payload_size > 0) {
      if (request.payload_size > sizeof(agent_payload) ||
          vmm_validate_user_buffer(request.payload, request.payload_size, 0) !=
              XAIOS_OK) {
        return syscall_dispatch_reject(syscall, arg0, arg1, "agent-payload-denied");
      }
      syscall_dispatch_bytes_copy(agent_payload, (const void *)(uintptr_t)request.payload,
                 request.payload_size);
    }
    if (agent_protocol_dispatch(&agent_req, &agent_resp,
                                request.payload_size > 0 ? agent_payload : 0,
                                request.payload_size,
                                (char *)(uintptr_t)request.output,
                                request.output_size, &out_size) != XAIOS_OK) {
      syscall_dispatch_bytes_copy((void *)(uintptr_t)request.response, &agent_resp,
                 sizeof(agent_resp));
      return syscall_dispatch_reject(syscall, arg0, arg1, "agent-dispatch-failed");
    }
    syscall_dispatch_bytes_copy((void *)(uintptr_t)request.response, &agent_resp,
               sizeof(agent_resp));
    syscall_dispatch_bytes_copy((void *)(uintptr_t)request.out_size, &out_size,
               sizeof(out_size));
    klog("syscall: agent_dispatch cmd=%u cell=%u out=%lu\n",
         agent_req.command, agent_req.cell_id, out_size);
    return syscall_dispatch_complete(out_size);
  }

  return syscall_dispatch_reject(syscall, arg0, arg1, "unreachable");
}
