#include <xaios_user.h>

#include "ssh_channel.h"
#include "ssh_client.h"
#include "ssh_crypto.h"
#include "ssh_utils.h"

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

int ssh_channel_send_data(int sockfd, uint32_t remote_id,
                          const uint8_t *data, uint32_t length) {
  (void)remote_id;
  return xaios_remote_login_child_write((u64)(uint32_t)sockfd, data, length);
}

int main(int argc, char **argv) {
  if (argc != 4 || argv == 0) return 2;
  u64 channel_id = 0U;
  if (parse_u64(argv[1], &channel_id) != 0 || argv[2][0] != '/' ||
      argv[3][0] == '\0') {
    return 2;
  }

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
    uint8_t input[512];
    u64 input_size = 0U;
    if (xaios_remote_login_child_read(channel_id, input, sizeof(input),
                                      &input_size) != 0) {
      ssh_client_close(&channel);
      return 1;
    }
    if (input_size != 0U) {
      int result = ssh_client_is_prompting(&channel)
                       ? ssh_client_password_input(&channel, input,
                                                   (uint32_t)input_size)
                       : ssh_client_forward_input(&channel, input,
                                                  (uint32_t)input_size);
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
