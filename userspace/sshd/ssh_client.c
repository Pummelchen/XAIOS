#include "ssh_client.h"

#include "ssh_client_scp.h"
#include "ssh_client_internal.h"
#include "ssh_client_shared.h"
#include "ssh_sftp.h"

#include "ssh_channel.h"
#include "ssh_connection.h"
#include "ssh_crypto.h"
#include "ssh_identity.h"
#include "ssh_known_hosts.h"
#include "ssh_mlkem.h"
#include "ssh_protocol.h"
#include "ssh_utils.h"
#include "tweetnacl_subset.h"
#include <xaios_user.h>

#if defined(XAIOS_SSH_CLIENT_APP)
#define SSH_CLIENT_CONTEXTS 1U
#else
#define SSH_CLIENT_CONTEXTS SSH_MAX_CLIENT_CONNECTIONS
#endif

static ssh_client_context_t g_clients[SSH_CLIENT_CONTEXTS];

#if defined(XAIOS_SSH_CLIENT_APP)
static char g_client_app_cwd[SSH_CLIENT_PATH_MAX];

void ssh_client_app_set_cwd(const char *cwd) {
  if (cwd == 0) {
    g_client_app_cwd[0] = '\0';
    return;
  }
  (void)sshclient_string_copy(g_client_app_cwd, sizeof(g_client_app_cwd), cwd);
}
#endif

int sshclient_bytes_equal(const uint8_t *a, const uint8_t *b,
                          uint32_t length) {
  uint8_t difference = 0U;
  for (uint32_t i = 0U; i < length; ++i) difference |= a[i] ^ b[i];
  return difference == 0U;
}

uint32_t sshclient_string_copy(char *output, uint32_t capacity,
                               const char *input) {
  uint32_t length = 0U;
  if (capacity == 0U) return 0U;
  while (input[length] != '\0' && length + 1U < capacity) {
    output[length] = input[length];
    ++length;
  }
  output[length] = '\0';
  return length;
}

int sshclient_output_text(const ssh_client_context_t *client, const char *text) {
  return ssh_channel_send_data((int)client->outer_sockfd,
                               client->outer_remote_id,
                               (const uint8_t *)text, ssh_str_len(text));
}

static ssh_client_context_t *client_for_channel(const ssh_channel_t *channel) {
  if (channel == 0 || channel->ssh_client_slot == 0U ||
      channel->ssh_client_slot > SSH_CLIENT_CONTEXTS) {
    return 0;
  }
  ssh_client_context_t *client =
      &g_clients[channel->ssh_client_slot - 1U];
  return client->active != 0U ? client : 0;
}

ssh_client_context_t *sshclient_client_allocate(ssh_channel_t *channel) {
  for (uint32_t i = 0U; i < SSH_CLIENT_CONTEXTS; ++i) {
    if (g_clients[i].active != 0U) continue;
    ssh_mem_zero(&g_clients[i], sizeof(g_clients[i]));
    g_clients[i].active = 1U;
    g_clients[i].outer_sockfd = channel->owner_sockfd;
    g_clients[i].outer_remote_id = channel->remote_id;
    g_clients[i].port = 22U;
    channel->ssh_client_slot = i + 1U;
    return &g_clients[i];
  }
  return 0;
}

void sshclient_client_release(ssh_channel_t *channel,
                              ssh_client_context_t *client) {
  if (client == 0) return;
  if (client->sockfd != 0U && client->sockfd != SSH_CLIENT_RELAY_SOCKET)
    (void)xaios_net_close(client->sockfd);
  if (client->transport != 0) ssh_conn_free(client->transport);
  if (client->proxy_transport != 0) {
    if (client->proxy_transport->crypto.enabled != 0) {
      uint8_t close[5] = {SSH_MSG_CHANNEL_CLOSE, 0U, 0U, 0U, 0U};
      ssh_write_u32_be(close + 1U, client->proxy_remote_channel);
      (void)ssh_packet_write_encrypted((int)client->proxy_sockfd, close,
                                       sizeof(close));
    }
    ssh_conn_free(client->proxy_transport);
  }
  if (client->proxy_sockfd != 0U) (void)xaios_net_close(client->proxy_sockfd);
  ssh_mem_zero(client->password, sizeof(client->password));
  ssh_mem_zero(client, sizeof(*client));
  if (channel != 0) channel->ssh_client_slot = 0U;
}

/* One attempt with the credential the client now holds: the handshake, the
   sentence when it fails, the next credential when a jump host asks for one,
   and the transfer when the command was scp.
   1 -- the session is live, or the transfer is finished;
   0 -- a further credential is outstanding and its prompt has gone out;
  -1 -- the attempt failed and the client has been released.
   `echo_newline` is for the prompt path only: it closes the line the typed
   password was hidden on. Nothing was typed when no prompt was shown. */
int sshclient_client_proceed(ssh_client_context_t *client, ssh_channel_t *channel,
                             int echo_newline) {
  for (;;) {
    int handshake = sshclient_handshake(client, channel);
    int echo_failed = echo_newline != 0 && sshclient_output_text(client, "\r\n") != 0;
    echo_newline = 0;
    if (echo_failed || handshake < 0) {
      if (handshake < 0) {
        xaios_log("ssh-client: handshake failed\n");
      }
      const char *message = "ssh: connection or authentication failed\r\n";
      if (handshake == -10 || handshake == -26)
        message = "ssh: connection failed\r\n";
      if (handshake == -11) message = "ssh: client memory unavailable\r\n";
      if (handshake == -12 || handshake == -13 || handshake == -14 ||
          handshake == -15 || handshake == -16) {
        message = "ssh: protocol version exchange failed\r\n";
      }
      if (handshake == -17 || handshake == -18 || handshake == -19 ||
          handshake == -20 || handshake == -21 || handshake == -22) {
        message = "ssh: key exchange failed\r\n";
      }
      if (handshake == -17) message = "ssh: key exchange initialization failed\r\n";
      if (handshake == -18) message = "ssh: server key exchange proposal invalid\r\n";
      if (handshake == -19) message = "ssh: key generation failed\r\n";
      if (handshake == -20) message = "ssh: key exchange request failed\r\n";
      if (handshake == -21) message = "ssh: key exchange reply invalid\r\n";
      if (handshake == -22) message = "ssh: new-keys exchange failed\r\n";
      if (handshake == -23) message = "ssh: authentication failed\r\n";
      if (handshake == -24) message = "ssh: session open failed\r\n";
      if (handshake == -25) message = "ssh: host key verification failed\r\n";
      if (handshake == -27) message = "ssh: identity file or passphrase invalid\r\n";
      if (handshake == -28) message = "ssh: public-key authentication failed\r\n";
      (void)sshclient_output_text(client, message);
      sshclient_client_release(channel, client);
      return -1;
    }
    if (handshake != 1) break;
    int credential = sshclient_request_credential(client, channel);
    if (credential < 0) {
      sshclient_client_release(channel, client);
      return -1;
    }
    if (credential > 0) return 0;
  }
  if (client->mode == SSH_CLIENT_MODE_SCP_UPLOAD ||
      client->mode == SSH_CLIENT_MODE_SCP_DOWNLOAD) {
    int transfer = sshclient_scp_transfer(client);
    const char *status = "scp: transfer failed\r\n";
    if (transfer == 0) status = "scp: transfer complete\r\n";
    else if (transfer == -11) status = "scp: SFTP request send failed\r\n";
    else if (transfer == -12) status = "scp: invalid SFTP version reply\r\n";
    else if (transfer == -41) status = "scp: SFTP reply timeout\r\n";
    else if (transfer == -42) status = "scp: remote SFTP service closed\r\n";
    else if (transfer == -43) status = "scp: remote SFTP service error\r\n";
    else if (transfer == -21) status = "scp: local source not found\r\n";
    else if (transfer == -22) status = "scp: local source open failed\r\n";
    else if (transfer == -23) status = "scp: remote destination open failed\r\n";
    else if (transfer == -24) status = "scp: local source read failed\r\n";
    else if (transfer == -25) status = "scp: remote write failed\r\n";
    else if (transfer == -26) status = "scp: remote rejected write\r\n";
    else if (transfer == -27) status = "scp: local close failed\r\n";
    else if (transfer == -28) status = "scp: remote close failed\r\n";
    else if (transfer == -29) status = "scp: directory requires -r or unsupported file type\r\n";
    else if (transfer == -30) status = "scp: cannot create destination directory\r\n";
    else if (transfer == -31) status = "scp: directory path or listing exceeds XAIOS limits\r\n";
    else if (transfer == -32) status = "scp: cannot create local destination\r\n";
    else if (transfer == -33) status = "scp: cannot inspect remote source\r\n";
    (void)sshclient_output_text(client, status);
    sshclient_client_release(channel, client);
    return transfer == 0 ? 1 : -1;
  }
  return 1;
}

int sshclient_resolve_local_path(const ssh_channel_t *channel, const char *input,
                                 char *output, uint32_t capacity) {
  uint32_t length = ssh_str_len(input);
  if (length == 0U || length + 1U > capacity) return -1;
  if (input[0] == '/') {
    ssh_mem_copy(output, input, length + 1U);
    while (length > 1U && output[length - 1U] == '/') output[--length] = '\0';
    return 0;
  }
  char cwd[SSH_CLIENT_PATH_MAX];
#if defined(XAIOS_SSH_CLIENT_APP)
  (void)channel;
  uint32_t cwd_length = sshclient_string_copy(cwd, sizeof(cwd), g_client_app_cwd);
  if (cwd_length == 0U) return -1;
#else
  u64 cwd_length = 0U;
  if (xaios_remote_login_session(channel->owner_sockfd, "admin", "pwd", cwd,
                                 sizeof(cwd), &cwd_length) < 0 ||
      cwd_length == 0U || cwd_length >= sizeof(cwd)) return -1;
#endif
  while (cwd_length != 0U &&
         (cwd[cwd_length - 1U] == '\n' || cwd[cwd_length - 1U] == '\r'))
    --cwd_length;
  uint32_t separator = cwd_length == 1U && cwd[0] == '/' ? 0U : 1U;
  if (cwd_length + separator + length + 1U > capacity) return -1;
  ssh_mem_copy(output, cwd, cwd_length);
  uint32_t used = (uint32_t)cwd_length;
  if (separator != 0U) output[used++] = '/';
  ssh_mem_copy(output + used, input, length + 1U);
  used += length;
  while (used > 1U && output[used - 1U] == '/') output[--used] = '\0';
  return 0;
}

int ssh_client_password_input(struct ssh_channel *channel,
                              const uint8_t *data, uint32_t length) {
  ssh_client_context_t *client = client_for_channel(channel);
  if (client == 0 || client->prompting == 0U) return -1;
  /* Somebody is there: the idle clock starts again from this keystroke. */
  client->prompt_deadline = xaios_clock_nanos() + SSH_CLIENT_PROMPT_IDLE_NS;
  for (uint32_t i = 0U; i < length; ++i) {
    uint8_t value = data[i];
    if (value == 3U) {
      (void)sshclient_output_text(client, "^C\r\n");
      sshclient_client_release(channel, client);
      return 1;
    }
    if (value == 8U || value == 127U) {
      if (client->password_length != 0U)
        client->password[--client->password_length] = '\0';
      continue;
    }
    if (value != '\r' && value != '\n') {
      if (value >= 32U && value <= 126U &&
          client->password_length < SSH_CLIENT_PASSWORD_MAX) {
        client->password[client->password_length++] = (char)value;
        client->password[client->password_length] = '\0';
      }
      continue;
    }
    client->prompting = 0U;
    return sshclient_client_proceed(client, channel, 1) == 0 ? 0 : 1;
  }
  return 0;
}

int send_channel_data(ssh_client_context_t *client,
                             const uint8_t *data, uint32_t length) {
  uint32_t offset = 0U;
  while (offset < length) {
    if (client->remote_window == 0U) {
      uint64_t deadline = xaios_clock_nanos() + SSH_CLIENT_TIMEOUT_NS;
      for (;;) {
        ssh_packet_t *packet = &client->packet_workspace;
        if (wait_encrypted_packet(client, packet, deadline) != 0 ||
            packet->len == 0U) return -1;
        if (packet->data[0] == SSH_MSG_CHANNEL_WINDOW_ADJUST &&
            packet->len >= 9U) {
          uint32_t added = ssh_read_u32_be(packet->data + 5U);
          if (UINT32_MAX - client->remote_window < added) return -1;
          client->remote_window += added;
          break;
        }
        if (packet->data[0] == SSH_MSG_CHANNEL_CLOSE ||
            packet->data[0] == SSH_MSG_DISCONNECT) return -1;
      }
    }
    uint32_t chunk = length - offset;
    if (chunk > client->remote_window) chunk = client->remote_window;
    if (chunk > client->remote_max_packet) chunk = client->remote_max_packet;
    if (chunk > SSH_WIRE_MAX_CHUNK) chunk = SSH_WIRE_MAX_CHUNK;
    uint8_t *packet = client->packet_workspace.data;
    packet[0] = SSH_MSG_CHANNEL_DATA;
    ssh_write_u32_be(packet + 1U, client->remote_channel);
    ssh_write_u32_be(packet + 5U, chunk);
    ssh_mem_copy(packet + 9U, data + offset, chunk);
    if (ssh_packet_write_encrypted((int)client->sockfd, packet, chunk + 9U) != 0)
      return -1;
    client->remote_window -= chunk;
    offset += chunk;
  }
  return 0;
}

int ssh_client_forward_input(struct ssh_channel *channel,
                             const uint8_t *data, uint32_t length) {
  ssh_client_context_t *client = client_for_channel(channel);
  if (client == 0 || client->connected == 0U ||
      client->mode != SSH_CLIENT_MODE_SHELL) return -1;
  return send_channel_data(client, data, length);
}

static int client_send_close(ssh_client_context_t *client) {
  if (client->close_sent != 0U) return 0;
  uint8_t packet[5];
  packet[0] = SSH_MSG_CHANNEL_CLOSE;
  ssh_write_u32_be(packet + 1U, client->remote_channel);
  if (ssh_packet_write_encrypted((int)client->sockfd, packet,
                                 sizeof(packet)) != 0) return -1;
  client->close_sent = 1U;
  return 0;
}

int ssh_client_tick(struct ssh_channel *channel, uint64_t now_ns) {
  ssh_client_context_t *client = client_for_channel(channel);
  if (client == 0) return 0;
  if (client->prompting != 0U) {
    /* B-37's backstop. A prompt this client cannot know is unanswerable --
       it is never told whether the session has a terminal -- stops being a
       wait once nothing has been typed at it for long enough, and becomes a
       failure the caller can see and act on. */
    if (now_ns < client->prompt_deadline) return 0;
    (void)sshclient_output_text(
        client,
        "\r\nssh: nothing answered the prompt; no terminal? "
        "use -o BatchMode=yes\r\n");
    sshclient_client_release(channel, client);
    return -1;
  }
  if (client->connected == 0U) return 0;
  for (uint32_t iteration = 0U; iteration < 8U; ++iteration) {
    ssh_packet_t *packet = &client->packet_workspace;
    int result = ssh_packet_read_encrypted((int)client->sockfd, packet);
    if (result > 0) return 0;
    if (result < 0 || packet->len == 0U) {
      (void)sshclient_output_text(client, "\r\nssh: connection closed with protocol error\r\n");
      sshclient_client_release(channel, client);
      return 1;
    }
    uint8_t type = packet->data[0];
    if ((type == SSH_MSG_CHANNEL_DATA ||
         type == SSH_MSG_CHANNEL_EXTENDED_DATA) && packet->len >= 9U) {
      uint32_t string_offset = type == SSH_MSG_CHANNEL_DATA ? 5U : 9U;
      if (type == SSH_MSG_CHANNEL_EXTENDED_DATA && packet->len < 13U)
        return -1;
      uint32_t length = ssh_read_u32_be(packet->data + string_offset);
      string_offset += 4U;
      if (length > packet->len - string_offset) return -1;
      if (ssh_channel_send_data((int)client->outer_sockfd,
                                client->outer_remote_id,
                                packet->data + string_offset, length) != 0)
        return -1;
      if (length > client->receive_window) return -1;
      client->receive_window -= length;
      if (client->receive_window <= SSH_CLIENT_WINDOW / 2U) {
        uint32_t added = SSH_CLIENT_WINDOW - client->receive_window;
        uint8_t adjust[9];
        adjust[0] = SSH_MSG_CHANNEL_WINDOW_ADJUST;
        ssh_write_u32_be(adjust + 1U, client->remote_channel);
        ssh_write_u32_be(adjust + 5U, added);
        if (ssh_packet_write_encrypted((int)client->sockfd, adjust,
                                       sizeof(adjust)) != 0) return -1;
        client->receive_window += added;
      }
    } else if (type == SSH_MSG_CHANNEL_WINDOW_ADJUST && packet->len >= 9U) {
      uint32_t added = ssh_read_u32_be(packet->data + 5U);
      if (UINT32_MAX - client->remote_window < added) return -1;
      client->remote_window += added;
    } else if (type == SSH_MSG_CHANNEL_REQUEST && packet->len >= 9U) {
      uint32_t name_length = ssh_read_u32_be(packet->data + 5U);
      if (name_length == 11U && packet->len >= 25U &&
          sshclient_bytes_equal(packet->data + 9U, (const uint8_t *)"exit-status", 11U)) {
        client->exit_status = ssh_read_u32_be(packet->data + 21U);
      }
    } else if (type == SSH_MSG_CHANNEL_EOF) {
      (void)client_send_close(client);
    } else if (type == SSH_MSG_CHANNEL_CLOSE || type == SSH_MSG_DISCONNECT) {
      (void)client_send_close(client);
      if (client->mode == SSH_CLIENT_MODE_SHELL)
        (void)sshclient_output_text(client, "\r\nConnection closed.\r\n");
      else if (client->exit_status != 0U)
        (void)sshclient_output_text(client, "ssh: remote command failed\r\n");
      sshclient_client_release(channel, client);
      return 1;
    } else if (type == SSH_MSG_GLOBAL_REQUEST && packet->len >= 6U) {
      uint32_t name_length = ssh_read_u32_be(packet->data + 1U);
      if (name_length <= packet->len - 6U && packet->data[5U + name_length] != 0U) {
        uint8_t failure = SSH_MSG_REQUEST_FAILURE;
        if (ssh_packet_write_encrypted((int)client->sockfd, &failure, 1U) != 0)
          return -1;
      }
    }
  }
  return 0;
}

void ssh_client_close(struct ssh_channel *channel) {
  ssh_client_context_t *client = client_for_channel(channel);
  if (client == 0) return;
  if (client->connected != 0U) (void)client_send_close(client);
  sshclient_client_release(channel, client);
}

int ssh_client_is_prompting(const struct ssh_channel *channel) {
  ssh_client_context_t *client = client_for_channel(channel);
  return client != 0 && client->prompting != 0U;
}

int ssh_client_is_active(const struct ssh_channel *channel) {
  ssh_client_context_t *client = client_for_channel(channel);
  /* A client waiting for an answer is active too, so that it is ticked and
     the prompt's idle clock is read. Without this the only caller ticks
     nothing until a connection exists, and the wait would be unbounded
     again. */
  return client != 0 && (client->connected != 0U || client->prompting != 0U);
}
