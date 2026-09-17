#include <xaios_user.h>

/* The session-shaped syscall wrappers: remote-login sessions and their child
 * channels, thread groups and the per-thread lifecycle, the ML and CPU-AI
 * decodes, the agent dispatch and the control query. These were the
 * request-marshalling half of xaios_user.c; they moved here unchanged so no
 * source file passes the repository's 500-line limit. Every symbol is
 * declared in <xaios_user.h> and still has the same name and signature. */

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
