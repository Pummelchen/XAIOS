#include <xaios_user.h>

#include "ssh_channel.h"
#include "ssh_client.h"
#include "ssh_child_ipc.h"
#include "ssh_crypto.h"
#include "ssh_utils.h"

static u64 g_child_channel_id;
static uint8_t g_ipc_write[SSH_CHILD_IPC_HEADER_SIZE + SSH_CHILD_IPC_PAYLOAD_MAX];
static uint8_t g_ipc_read[SSH_CHILD_IPC_HEADER_SIZE + SSH_CHILD_IPC_PAYLOAD_MAX];
static uint32_t g_ipc_read_used;

static int parse_u64(const char *text, u64 *value) {
  u64 parsed = 0U;
  if (text == 0 || value == 0 || text[0] == '\0') return -1;
  for (u64 i = 0U; text[i] != '\0'; ++i) {
    if (text[i] < '0' || text[i] > '9' ||
        parsed > (~0ULL - (u64)(text[i] - '0')) / 10U) {
      return -1;
    }
    parsed = parsed * 10U + (u64)(text[i] - '0');
  }
  if (parsed == 0U) return -1;
  *value = parsed;
  return 0;
}

static int ipc_write(uint32_t type, const uint8_t *data, uint32_t length) {
  if ((data == 0 && length != 0U) || length > SSH_CHILD_IPC_PAYLOAD_MAX)
    return -1;
  ssh_child_ipc_header(g_ipc_write, type, length);
  if (length != 0U)
    ssh_mem_copy(g_ipc_write + SSH_CHILD_IPC_HEADER_SIZE, data, length);
  return xaios_remote_login_child_write(
      g_child_channel_id, g_ipc_write, SSH_CHILD_IPC_HEADER_SIZE + length);
}

static int ipc_receive(void) {
  if (g_ipc_read_used == sizeof(g_ipc_read)) return -1;
  u64 size = 0U;
  if (xaios_remote_login_child_read(
          g_child_channel_id, g_ipc_read + g_ipc_read_used,
          sizeof(g_ipc_read) - g_ipc_read_used, &size) != 0 ||
      size > sizeof(g_ipc_read) - g_ipc_read_used) {
    return -1;
  }
  g_ipc_read_used += (uint32_t)size;
  return 0;
}

static int ipc_next(uint32_t *type, uint8_t *output, uint32_t capacity,
                    uint32_t *length) {
  if (g_ipc_read_used < SSH_CHILD_IPC_HEADER_SIZE) return 1;
  if (ssh_child_ipc_read_u32(g_ipc_read) != SSH_CHILD_IPC_MAGIC) return -1;
  uint32_t payload_length = ssh_child_ipc_read_u32(g_ipc_read + 8U);
  if (payload_length > SSH_CHILD_IPC_PAYLOAD_MAX ||
      payload_length > capacity) return -1;
  uint32_t frame_length = SSH_CHILD_IPC_HEADER_SIZE + payload_length;
  if (g_ipc_read_used < frame_length) return 1;
  *type = ssh_child_ipc_read_u32(g_ipc_read + 4U);
  *length = payload_length;
  if (payload_length != 0U)
    ssh_mem_copy(output, g_ipc_read + SSH_CHILD_IPC_HEADER_SIZE,
                 payload_length);
  uint32_t remaining = g_ipc_read_used - frame_length;
  for (uint32_t i = 0U; i < remaining; ++i)
    g_ipc_read[i] = g_ipc_read[frame_length + i];
  g_ipc_read_used = remaining;
  return 0;
}

int ssh_channel_send_data(int sockfd, uint32_t remote_id,
                          const uint8_t *data, uint32_t length) {
  (void)sockfd;
  (void)remote_id;
  uint32_t offset = 0U;
  while (offset < length) {
    uint32_t chunk = length - offset;
    if (chunk > SSH_CHILD_IPC_PAYLOAD_MAX) chunk = SSH_CHILD_IPC_PAYLOAD_MAX;
    if (ipc_write(SSH_CHILD_IPC_OUTPUT, data + offset, chunk) != 0) return -1;
    offset += chunk;
  }
  return 0;
}

int ssh_client_app_agent_exchange(const uint8_t *request,
                                  uint32_t request_length, uint8_t *response,
                                  uint32_t response_capacity,
                                  uint32_t *response_length,
                                  uint64_t deadline) {
  uint32_t used = 0U;
  if (request == 0 || request_length == 0U || response == 0 ||
      response_length == 0 ||
      ipc_write(SSH_CHILD_IPC_AGENT_REQUEST, request, request_length) != 0)
    return -1;
  for (;;) {
    uint8_t payload[SSH_CHILD_IPC_PAYLOAD_MAX];
    uint32_t type = 0U;
    uint32_t length = 0U;
    int next = ipc_next(&type, payload, sizeof(payload), &length);
    if (next < 0) return -1;
    if (next > 0) {
      if (xaios_clock_nanos() >= deadline || ipc_receive() != 0) return -1;
      continue;
    }
    if (type != SSH_CHILD_IPC_AGENT_RESPONSE) continue;
    if (length > response_capacity - used) return -1;
    ssh_mem_copy(response + used, payload, length);
    used += length;
    if (used >= 4U) {
      uint32_t message_length = ssh_child_ipc_read_u32(response);
      if (message_length == 0U || message_length > response_capacity - 4U)
        return -1;
      if (used == message_length + 4U) {
        *response_length = used;
        return 0;
      }
      if (used > message_length + 4U) return -1;
    }
  }
}

int main(int argc, char **argv) {
  if (argc != 4 || argv == 0) return 2;
  u64 channel_id = 0U;
  if (parse_u64(argv[1], &channel_id) != 0 || argv[2][0] != '/' ||
      argv[3][0] == '\0') {
    return 2;
  }
  g_child_channel_id = channel_id;

  ssh_channel_t channel;
  ssh_mem_zero(&channel, sizeof(channel));
  channel.active = 1U;
  channel.owner_sockfd = channel_id;
  channel.terminal_columns = 120U;
  channel.terminal_rows = 40U;
  ssh_client_app_set_cwd(argv[2]);
  if (crypto_random_init() != 0) return 2;
  if (ssh_client_prepare(&channel, argv[3]) <= 0) return 2;

  for (;;) {
    u64 status = 0U;
    if (xaios_remote_login_child_status(channel_id, &status) != 0 ||
        (u32)status != 1U) {
      ssh_client_close(&channel);
      return (u32)status == 3U ? 0 : 1;
    }
    uint8_t input[SSH_CHILD_IPC_PAYLOAD_MAX];
    if (ipc_receive() != 0) {
      ssh_client_close(&channel);
      return 1;
    }
    for (;;) {
      uint32_t type = 0U;
      uint32_t input_size = 0U;
      int next = ipc_next(&type, input, sizeof(input), &input_size);
      if (next > 0) break;
      if (next < 0 || type != SSH_CHILD_IPC_INPUT) {
        ssh_client_close(&channel);
        return 1;
      }
      int result = ssh_client_is_prompting(&channel)
                       ? ssh_client_password_input(&channel, input,
                                                   input_size)
                       : ssh_client_forward_input(&channel, input,
                                                  input_size);
      if (result < 0) {
        ssh_client_close(&channel);
        return 1;
      }
    }
    if (ssh_client_is_active(&channel)) {
      if (ssh_client_tick(&channel, xaios_clock_nanos()) < 0) {
        ssh_client_close(&channel);
        return 1;
      }
    } else if (!ssh_client_is_prompting(&channel)) {
      return 0;
    }
  }
}
