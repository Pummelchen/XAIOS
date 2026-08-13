#include "ssh_client.h"

#include "ssh_channel.h"
#include "ssh_utils.h"
#include <xaios_user.h>

typedef struct ssh_client_proxy {
  uint32_t active;
  u64 child_channel_id;
} ssh_client_proxy_t;

static ssh_client_proxy_t g_proxies[SSH_CHANNEL_MAX];

static uint32_t append_u32(char *output, uint32_t capacity, uint32_t value) {
  char digits[10];
  uint32_t count = 0U;
  do {
    digits[count++] = (char)('0' + value % 10U);
    value /= 10U;
  } while (value != 0U);
  if (count + 1U > capacity) return 0U;
  for (uint32_t i = 0U; i < count; ++i) output[i] = digits[count - i - 1U];
  output[count] = '\0';
  return count;
}

static ssh_client_proxy_t *proxy_for(const ssh_channel_t *channel) {
  if (channel == 0 || channel->ssh_client_slot == 0U ||
      channel->ssh_client_slot > SSH_CHANNEL_MAX) {
    return 0;
  }
  ssh_client_proxy_t *proxy = &g_proxies[channel->ssh_client_slot - 1U];
  return proxy->active != 0U ? proxy : 0;
}

static int command_is_outbound(const char *command) {
  uint32_t offset = 0U;
  while (command[offset] == ' ' || command[offset] == '\t') ++offset;
  const char *name = command + offset;
  uint32_t length = 0U;
  while (name[length] != '\0' && name[length] != ' ' && name[length] != '\t') {
    ++length;
  }
  return (length == 3U && name[0] == 's' && name[1] == 's' && name[2] == 'h') ||
         (length == 3U && name[0] == 's' && name[1] == 'c' && name[2] == 'p');
}

static void proxy_release(ssh_channel_t *channel, int cancel) {
  ssh_client_proxy_t *proxy = proxy_for(channel);
  if (proxy == 0) return;
  if (cancel != 0) {
    (void)xaios_remote_login_child_cancel(proxy->child_channel_id);
  }
  (void)xaios_remote_login_child_release(proxy->child_channel_id);
  xaios_memzero(proxy, sizeof(*proxy));
  channel->ssh_client_slot = 0U;
}

int ssh_client_prepare(struct ssh_channel *channel, const char *command) {
  if (channel == 0 || command == 0 || !command_is_outbound(command)) return 0;
  if (proxy_for(channel) != 0) return -1;
  ssh_client_proxy_t *proxy = 0;
  uint32_t index = 0U;
  for (; index < SSH_CHANNEL_MAX; ++index) {
    if (g_proxies[index].active == 0U) {
      proxy = &g_proxies[index];
      break;
    }
  }
  if (proxy == 0) {
    static const char busy[] = "ssh: outbound client capacity reached\r\n";
    (void)ssh_channel_send_data((int)channel->owner_sockfd, channel->remote_id,
                                (const uint8_t *)busy, sizeof(busy) - 1U);
    return -1;
  }

  char cwd[256];
  u64 cwd_size = 0U;
  if (xaios_remote_login_session(channel->owner_sockfd, "admin", "pwd", cwd,
                                 sizeof(cwd), &cwd_size) != 0 ||
      cwd_size == 0U || cwd_size >= sizeof(cwd)) {
    cwd[0] = '/';
    cwd[1] = '\0';
    cwd_size = 1U;
  }
  while (cwd_size != 0U &&
         (cwd[cwd_size - 1U] == '\n' || cwd[cwd_size - 1U] == '\r')) {
    cwd[--cwd_size] = '\0';
  }
  int launch_status = xaios_remote_login_child_open(
      channel->owner_sockfd, command, cwd, &proxy->child_channel_id);
  if (cwd_size == 0U || launch_status != 0) {
    const char *failed = "ssh: outbound child launch failed\r\n";
    if (launch_status == -1) failed = "ssh: outbound child launch failed: invalid request\r\n";
    if (launch_status == -2) failed = "ssh: outbound child launch failed: no memory\r\n";
    if (launch_status == -3) failed = "ssh: outbound child launch failed: client app missing\r\n";
    if (launch_status == -4) failed = "ssh: outbound child launch failed: I/O error\r\n";
    if (launch_status == -5) failed = "ssh: outbound child launch failed: busy\r\n";
    if (launch_status == -6) failed = "ssh: outbound child launch failed: no worker CPU\r\n";
    (void)ssh_channel_send_data((int)channel->owner_sockfd, channel->remote_id,
                                (const uint8_t *)failed, xaios_strlen(failed));
    xaios_memzero(proxy, sizeof(*proxy));
    return -1;
  }
  proxy->active = 1U;
  channel->ssh_client_slot = index + 1U;
  return 1;
}

int ssh_client_password_input(struct ssh_channel *channel,
                              const uint8_t *data, uint32_t length) {
  return ssh_client_forward_input(channel, data, length);
}

int ssh_client_forward_input(struct ssh_channel *channel,
                             const uint8_t *data, uint32_t length) {
  ssh_client_proxy_t *proxy = proxy_for(channel);
  if (proxy == 0 || data == 0 || length == 0U ||
      xaios_remote_login_child_write(proxy->child_channel_id, data, length) != 0) {
    return -1;
  }
  return 0;
}

int ssh_client_tick(struct ssh_channel *channel, uint64_t now_ns) {
  (void)now_ns;
  ssh_client_proxy_t *proxy = proxy_for(channel);
  if (proxy == 0) return 0;
  for (uint32_t iteration = 0U; iteration < 8U; ++iteration) {
    uint8_t output[4096];
    u64 output_size = 0U;
    if (xaios_remote_login_child_read(proxy->child_channel_id, output,
                                      sizeof(output), &output_size) != 0) {
      proxy_release(channel, 1);
      return -1;
    }
    if (output_size == 0U) break;
    if (ssh_channel_send_data((int)channel->owner_sockfd, channel->remote_id,
                              output, (uint32_t)output_size) != 0) {
      proxy_release(channel, 1);
      return -1;
    }
  }
  u64 status = 0U;
  if (xaios_remote_login_child_status(proxy->child_channel_id, &status) != 0) {
    proxy_release(channel, 1);
    return -1;
  }
  if ((u32)status == 1U) return 0;
  if ((u32)status == 4U) {
    char message[48] = "ssh: outbound client failed (exit ";
    uint32_t used = 34U;
    used += append_u32(message + used, sizeof(message) - used,
                       (u32)(status >> 32U));
    if (used + 3U < sizeof(message)) {
      message[used++] = ')';
      message[used++] = '\r';
      message[used++] = '\n';
      message[used] = '\0';
      (void)ssh_channel_send_data((int)channel->owner_sockfd,
                                  channel->remote_id,
                                  (const uint8_t *)message, used);
    }
  }
  proxy_release(channel, 0);
  return 1;
}

void ssh_client_close(struct ssh_channel *channel) {
  proxy_release(channel, 1);
}

int ssh_client_is_prompting(const struct ssh_channel *channel) {
  (void)channel;
  return 0;
}

int ssh_client_is_active(const struct ssh_channel *channel) {
  return proxy_for(channel) != 0;
}
