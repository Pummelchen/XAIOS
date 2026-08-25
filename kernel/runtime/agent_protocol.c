#include <xaios/agent_protocol.h>
#include <xaios/assert.h>
#include <xaios/cpu_ai_runtime.h>
#include <xaios/git_workspace.h>
#include <xaios/klog.h>
#include <xaios/sandbox.h>
#include <xaios/source_index.h>

#define AGENT_REQUEST_MAGIC UINT32_C(0x41475251)
#define AGENT_RESPONSE_MAGIC UINT32_C(0x41475253)
#define AGENT_PROTOCOL_VERSION UINT32_C(1)

/* C-01: two totals and no tables, reached from the agent dispatch syscall on
   whichever CPU took it. Atomic for the same reason as security.c. */
static uint64_t g_request_count;
static uint64_t g_error_count;

static void bytes_zero(void *bytes, uint64_t size) {
  uint8_t *ptr = (uint8_t *)bytes;
  for (uint64_t i = 0; i < size; ++i) {
    ptr[i] = 0;
  }
}

static void runtime_append(char *output, uint64_t capacity, uint64_t *offset,
                           const char *text) {
  if (output == 0 || offset == 0 || text == 0 || capacity == 0) {
    return;
  }
  for (uint64_t i = 0; text[i] != '\0' && *offset + 1U < capacity; ++i) {
    output[*offset] = text[i];
    ++(*offset);
  }
  output[*offset] = '\0';
}

static void runtime_append_u64(char *output, uint64_t capacity,
                               uint64_t *offset, uint64_t value) {
  char digits[20];
  uint64_t count = 0;
  if (value == 0) {
    runtime_append(output, capacity, offset, "0");
    return;
  }
  while (value != 0 && count < sizeof(digits)) {
    digits[count++] = (char)('0' + (value % 10U));
    value /= 10U;
  }
  while (count > 0) {
    char one[2];
    --count;
    one[0] = digits[count];
    one[1] = '\0';
    runtime_append(output, capacity, offset, one);
  }
}

static void fill_response(xaios_agent_response_t *response, uint32_t status,
                          uint32_t command, uint64_t payload_size) {
  bytes_zero(response, sizeof(*response));
  response->magic = AGENT_RESPONSE_MAGIC;
  response->version = AGENT_PROTOCOL_VERSION;
  response->status = status;
  response->command = command;
  response->payload_size = payload_size;
}

static xaios_status_t handle_inference(const xaios_agent_request_t *request,
                                      xaios_agent_response_t *response,
                                      const uint8_t *payload,
                                      char *output,
                                      uint64_t output_capacity,
                                      uint64_t *output_bytes) {
  if (payload == 0 || request->payload_size < 1) {
    fill_response(response, XAIOS_AGENT_STATUS_INVALID, request->command, 0);
    __sync_fetch_and_add(&g_error_count, 1U);
    return XAIOS_ERR_INVALID;
  }
  uint64_t model_kind = (uint64_t)payload[0];
  const uint8_t *model_input = payload + 1;
  uint64_t model_input_size = request->payload_size - 1;

  xaios_status_t status = cpu_ai_runtime_run_model(
      request->cell_id, model_kind, model_input, model_input_size,
      output, output_capacity, output_bytes);
  if (status != XAIOS_OK) {
    fill_response(response, XAIOS_AGENT_STATUS_INTERNAL_ERROR,
                  request->command, 0);
    __sync_fetch_and_add(&g_error_count, 1U);
    return status;
  }
  fill_response(response, XAIOS_AGENT_STATUS_OK, request->command,
                *output_bytes);
  return XAIOS_OK;
}

static xaios_status_t handle_index_query(const xaios_agent_request_t *request,
                                        xaios_agent_response_t *response,
                                        const uint8_t *payload,
                                        char *output,
                                        uint64_t output_capacity,
                                        uint64_t *output_bytes) {
  (void)payload;
  uint64_t offset = 0;
  runtime_append(output, output_capacity, &offset, "index:");
  runtime_append_u64(output, output_capacity, &offset,
                     source_index_active_count());
  runtime_append(output, output_capacity, &offset, ":files=");
  runtime_append_u64(output, output_capacity, &offset,
                     source_index_total_file_records());
  runtime_append(output, output_capacity, &offset, ":symbols=");
  runtime_append_u64(output, output_capacity, &offset,
                     source_index_total_symbol_records());
  *output_bytes = offset;
  fill_response(response, XAIOS_AGENT_STATUS_OK, request->command, offset);
  return XAIOS_OK;
}

static xaios_status_t handle_git_status(const xaios_agent_request_t *request,
                                       xaios_agent_response_t *response,
                                       char *output,
                                       uint64_t output_capacity,
                                       uint64_t *output_bytes) {
  uint64_t offset = 0;
  runtime_append(output, output_capacity, &offset, "git:active=");
  runtime_append_u64(output, output_capacity, &offset,
                     git_workspace_active_count());
  runtime_append(output, output_capacity, &offset, ":syncs=");
  runtime_append_u64(output, output_capacity, &offset,
                     git_workspace_sync_count());
  runtime_append(output, output_capacity, &offset, ":applies=");
  runtime_append_u64(output, output_capacity, &offset,
                     git_workspace_apply_count());
  *output_bytes = offset;
  fill_response(response, XAIOS_AGENT_STATUS_OK, request->command, offset);
  return XAIOS_OK;
}

static xaios_status_t handle_build(const xaios_agent_request_t *request,
                                  xaios_agent_response_t *response,
                                  char *output,
                                  uint64_t output_capacity,
                                  uint64_t *output_bytes) {
  uint64_t offset = 0;
  runtime_append(output, output_capacity, &offset, "sandbox:active=");
  runtime_append_u64(output, output_capacity, &offset,
                     sandbox_active_count());
  runtime_append(output, output_capacity, &offset, ":transitions=");
  runtime_append_u64(output, output_capacity, &offset,
                     sandbox_transition_count());
  runtime_append(output, output_capacity, &offset, ":vm_execs=");
  runtime_append_u64(output, output_capacity, &offset,
                     sandbox_vm_exec_count());
  *output_bytes = offset;
  fill_response(response, XAIOS_AGENT_STATUS_OK, request->command, offset);
  return XAIOS_OK;
}

void agent_protocol_init(void) {
  g_request_count = 0;
  g_error_count = 0;
  klog("agent-protocol: initialized version=%u\n", AGENT_PROTOCOL_VERSION);
}

xaios_status_t agent_protocol_dispatch(const xaios_agent_request_t *request,
                                      xaios_agent_response_t *response,
                                      const uint8_t *payload,
                                      uint64_t payload_size,
                                      char *output, uint64_t output_capacity,
                                      uint64_t *output_bytes) {
  if (request == 0 || response == 0 || output == 0 || output_bytes == 0) {
    return XAIOS_ERR_INVALID;
  }
  if (request->magic != AGENT_REQUEST_MAGIC) {
    fill_response(response, XAIOS_AGENT_STATUS_INVALID, request->command, 0);
    __sync_fetch_and_add(&g_error_count, 1U);
    return XAIOS_ERR_INVALID;
  }
  if (request->version != AGENT_PROTOCOL_VERSION) {
    fill_response(response, XAIOS_AGENT_STATUS_INVALID, request->command, 0);
    __sync_fetch_and_add(&g_error_count, 1U);
    return XAIOS_ERR_INVALID;
  }
  if (payload_size > XAIOS_AGENT_MAX_PAYLOAD) {
    fill_response(response, XAIOS_AGENT_STATUS_INVALID, request->command, 0);
    __sync_fetch_and_add(&g_error_count, 1U);
    return XAIOS_ERR_INVALID;
  }

  __sync_fetch_and_add(&g_request_count, 1U);
  *output_bytes = 0;
  output[0] = '\0';

  klog("agent-protocol: dispatch cmd=%u cell=%u payload=%lu\n",
       request->command, request->cell_id, payload_size);

  switch (request->command) {
    case XAIOS_AGENT_CMD_INFERENCE:
      return handle_inference(request, response, payload, output,
                              output_capacity, output_bytes);
    case XAIOS_AGENT_CMD_INDEX_QUERY:
      return handle_index_query(request, response, payload, output,
                                output_capacity, output_bytes);
    case XAIOS_AGENT_CMD_GIT_STATUS:
      return handle_git_status(request, response, output, output_capacity,
                               output_bytes);
    case XAIOS_AGENT_CMD_GIT_DIFF:
      /* Git diff dispatches to git_workspace_compute_diff with payload data */
      if (payload != 0 && payload_size >= 4) {
        xaios_git_workspace_diff_hunk_t hunks[XAIOS_GIT_WORKSPACE_DIFF_MAX_HUNKS];
        uint32_t hunk_count = 0;
        xaios_status_t st = git_workspace_compute_diff(
            (const char *)payload, payload_size,
            (const char *)payload, payload_size,
            hunks, XAIOS_GIT_WORKSPACE_DIFF_MAX_HUNKS, &hunk_count);
        if (st == XAIOS_OK) {
          uint64_t off = 0;
          runtime_append(output, output_capacity, &off, "diff:hunks=");
          runtime_append_u64(output, output_capacity, &off, hunk_count);
          *output_bytes = off;
          fill_response(response, XAIOS_AGENT_STATUS_OK, request->command, off);
          return XAIOS_OK;
        }
        fill_response(response, XAIOS_AGENT_STATUS_INTERNAL_ERROR,
                      request->command, 0);
        __sync_fetch_and_add(&g_error_count, 1U);
        return st;
      }
      fill_response(response, XAIOS_AGENT_STATUS_INVALID, request->command, 0);
      __sync_fetch_and_add(&g_error_count, 1U);
      return XAIOS_ERR_INVALID;
    case XAIOS_AGENT_CMD_BUILD:
      return handle_build(request, response, output, output_capacity,
                          output_bytes);
    case XAIOS_AGENT_CMD_PING: {
      uint64_t off = 0;
      runtime_append(output, output_capacity, &off, "pong:");
      runtime_append_u64(output, output_capacity, &off, g_request_count);
      *output_bytes = off;
      fill_response(response, XAIOS_AGENT_STATUS_OK, request->command, off);
      return XAIOS_OK;
    }
    default:
      fill_response(response, XAIOS_AGENT_STATUS_INVALID, request->command, 0);
      __sync_fetch_and_add(&g_error_count, 1U);
      return XAIOS_ERR_INVALID;
  }
}

uint64_t agent_protocol_request_count(void) {
  return g_request_count;
}

uint64_t agent_protocol_error_count(void) {
  return g_error_count;
}

void agent_protocol_self_test(void) {
  agent_protocol_init();

  /* Test PING */
  xaios_agent_request_t req;
  xaios_agent_response_t resp;
  char output[256];
  uint64_t out_bytes = 0;

  bytes_zero(&req, sizeof(req));
  req.magic = AGENT_REQUEST_MAGIC;
  req.version = AGENT_PROTOCOL_VERSION;
  req.command = XAIOS_AGENT_CMD_PING;
  req.cell_id = 0;
  req.payload_size = 0;

  kassert(agent_protocol_dispatch(&req, &resp, 0, 0, output,
                                  sizeof(output), &out_bytes) == XAIOS_OK);
  kassert(resp.magic == AGENT_RESPONSE_MAGIC);
  kassert(resp.status == XAIOS_AGENT_STATUS_OK);
  kassert(resp.command == XAIOS_AGENT_CMD_PING);
  kassert(out_bytes > 0);

  /* Test bad magic */
  req.magic = 0xDEAD;
  kassert(agent_protocol_dispatch(&req, &resp, 0, 0, output,
                                  sizeof(output), &out_bytes) ==
          XAIOS_ERR_INVALID);
  kassert(resp.status == XAIOS_AGENT_STATUS_INVALID);

  /* Test bad version */
  req.magic = AGENT_REQUEST_MAGIC;
  req.version = 99;
  kassert(agent_protocol_dispatch(&req, &resp, 0, 0, output,
                                  sizeof(output), &out_bytes) ==
          XAIOS_ERR_INVALID);

  /* Test invalid command */
  req.version = AGENT_PROTOCOL_VERSION;
  req.command = 99;
  kassert(agent_protocol_dispatch(&req, &resp, 0, 0, output,
                                  sizeof(output), &out_bytes) ==
          XAIOS_ERR_INVALID);

  /* Test INDEX_QUERY */
  req.command = XAIOS_AGENT_CMD_INDEX_QUERY;
  kassert(agent_protocol_dispatch(&req, &resp, 0, 0, output,
                                  sizeof(output), &out_bytes) == XAIOS_OK);
  kassert(resp.status == XAIOS_AGENT_STATUS_OK);

  /* Test GIT_STATUS */
  req.command = XAIOS_AGENT_CMD_GIT_STATUS;
  kassert(agent_protocol_dispatch(&req, &resp, 0, 0, output,
                                  sizeof(output), &out_bytes) == XAIOS_OK);
  kassert(resp.status == XAIOS_AGENT_STATUS_OK);

  /* Test BUILD */
  req.command = XAIOS_AGENT_CMD_BUILD;
  kassert(agent_protocol_dispatch(&req, &resp, 0, 0, output,
                                  sizeof(output), &out_bytes) == XAIOS_OK);
  kassert(resp.status == XAIOS_AGENT_STATUS_OK);

  kassert(agent_protocol_request_count() == 5);
  kassert(agent_protocol_error_count() == 3);

  klog("agent-protocol: self-test passed requests=%lu errors=%lu\n",
       agent_protocol_request_count(), agent_protocol_error_count());
}
