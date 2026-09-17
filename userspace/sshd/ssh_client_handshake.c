/* The SSH client's channel setup and handshake orchestration, split out of
 * `ssh_client.c`: the channel-reply wait, the session channel open, the
 * direct-tcpip proxy channel and its stream callbacks, and `client_handshake`,
 * now `sshclient_handshake`. One `XAIOS_SSH_CLIENT_APP` region moved with the
 * handshake and keeps its exact meaning: the app build authenticates with a
 * forwarded agent, every other build refuses with the same -28 it returned
 * before.
 */

#include "ssh_client_internal.h"

#include "ssh_client_scp.h"

#include "ssh_channel.h"
#include "ssh_identity.h"
#include "ssh_mlkem.h"
#include "tweetnacl_subset.h"

static int wait_channel_reply(ssh_client_context_t *client, uint8_t expected,
                              uint64_t deadline, ssh_packet_t *out_packet) {
  for (;;) {
    if (wait_encrypted_packet(client, out_packet, deadline) != 0) return -1;
    if (out_packet->len != 0U && out_packet->data[0] == expected) return 0;
    if (out_packet->len >= 9U &&
        out_packet->data[0] == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
      uint32_t added = ssh_read_u32_be(out_packet->data + 5U);
      if (UINT32_MAX - client->remote_window < added) return -1;
      client->remote_window += added;
      continue;
    }
    if (out_packet->len != 0U &&
        (out_packet->data[0] == SSH_MSG_CHANNEL_FAILURE ||
         out_packet->data[0] == SSH_MSG_CHANNEL_OPEN_FAILURE ||
         out_packet->data[0] == SSH_MSG_DISCONNECT)) return -1;
  }
}

static int open_session_channel(ssh_client_context_t *client,
                                const ssh_channel_t *outer,
                                uint64_t deadline) {
  uint8_t packet[512];
  uint32_t position = 0U;
  packet[position++] = SSH_MSG_CHANNEL_OPEN;
  position = append_string(packet, position, sizeof(packet),
                           (const uint8_t *)"session", 7U);
  if (position == UINT32_MAX || position + 12U > sizeof(packet)) return -1;
  ssh_write_u32_be(packet + position, client->local_channel);
  position += 4U;
  ssh_write_u32_be(packet + position, SSH_CLIENT_WINDOW);
  position += 4U;
  ssh_write_u32_be(packet + position, SSH_CLIENT_PACKET);
  position += 4U;
  if (ssh_packet_write_encrypted((int)client->sockfd, packet, position) != 0)
    return -1;
  ssh_packet_t *response = &client->packet_workspace;
  if (wait_channel_reply(client, SSH_MSG_CHANNEL_OPEN_CONFIRM, deadline,
                         response) != 0 || response->len < 17U ||
      ssh_read_u32_be(response->data + 1U) != client->local_channel) return -1;
  client->remote_channel = ssh_read_u32_be(response->data + 5U);
  client->remote_window = ssh_read_u32_be(response->data + 9U);
  client->remote_max_packet = ssh_read_u32_be(response->data + 13U);
  client->receive_window = SSH_CLIENT_WINDOW;
  if (client->remote_max_packet == 0U) return -1;

  if (client->mode == SSH_CLIENT_MODE_SHELL) {
    position = 0U;
    packet[position++] = SSH_MSG_CHANNEL_REQUEST;
    ssh_write_u32_be(packet + position, client->remote_channel);
    position += 4U;
    position = append_string(packet, position, sizeof(packet),
                             (const uint8_t *)"pty-req", 7U);
    packet[position++] = 1U;
    position = append_string(packet, position, sizeof(packet),
                             (const uint8_t *)"xterm-256color", 14U);
    ssh_write_u32_be(packet + position, outer->terminal_columns);
    position += 4U;
    ssh_write_u32_be(packet + position, outer->terminal_rows);
    position += 4U;
    ssh_write_u32_be(packet + position, 0U);
    position += 4U;
    ssh_write_u32_be(packet + position, 0U);
    position += 4U;
    position = append_string(packet, position, sizeof(packet), 0, 0U);
    if (position == UINT32_MAX ||
        ssh_packet_write_encrypted((int)client->sockfd, packet, position) != 0 ||
        wait_channel_reply(client, SSH_MSG_CHANNEL_SUCCESS, deadline,
                           response) != 0) return -1;
  }

  position = 0U;
  packet[position++] = SSH_MSG_CHANNEL_REQUEST;
  ssh_write_u32_be(packet + position, client->remote_channel);
  position += 4U;
  const char *request = client->mode == SSH_CLIENT_MODE_SHELL
                            ? "shell"
                            : (client->mode == SSH_CLIENT_MODE_EXEC
                                   ? "exec"
                                   : "subsystem");
  position = append_string(packet, position, sizeof(packet),
                           (const uint8_t *)request, ssh_str_len(request));
  packet[position++] = 1U;
  if (client->mode == SSH_CLIENT_MODE_EXEC) {
    position = append_string(packet, position, sizeof(packet),
                             (const uint8_t *)client->command,
                             ssh_str_len(client->command));
  }
  if (client->mode == SSH_CLIENT_MODE_SCP_UPLOAD ||
      client->mode == SSH_CLIENT_MODE_SCP_DOWNLOAD) {
    position = append_string(packet, position, sizeof(packet),
                             (const uint8_t *)"sftp", 4U);
  }
  if (position == UINT32_MAX ||
      ssh_packet_write_encrypted((int)client->sockfd, packet, position) != 0 ||
      wait_channel_reply(client, SSH_MSG_CHANNEL_SUCCESS, deadline,
                         response) != 0) return -1;
  return 0;
}

static int proxy_send_window_adjust(ssh_client_context_t *client,
                                    uint32_t added) {
  uint8_t packet[9];
  packet[0] = SSH_MSG_CHANNEL_WINDOW_ADJUST;
  ssh_write_u32_be(packet + 1U, client->proxy_remote_channel);
  ssh_write_u32_be(packet + 5U, added);
  return ssh_packet_write_encrypted((int)client->proxy_sockfd, packet,
                                    sizeof(packet));
}

static int proxy_process_packet(ssh_client_context_t *client,
                                const ssh_packet_t *packet) {
  if (packet->len == 0U) return -1;
  uint8_t type = packet->data[0];
  if (type == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
    if (packet->len != 9U ||
        ssh_read_u32_be(packet->data + 1U) != client->proxy_local_channel)
      return -1;
    uint32_t added = ssh_read_u32_be(packet->data + 5U);
    if (UINT32_MAX - client->proxy_remote_window < added) return -1;
    client->proxy_remote_window += added;
    return 0;
  }
  if (type == SSH_MSG_CHANNEL_DATA) {
    if (packet->len < 9U ||
        ssh_read_u32_be(packet->data + 1U) != client->proxy_local_channel)
      return -1;
    uint32_t length = ssh_read_u32_be(packet->data + 5U);
    if (length > packet->len - 9U ||
        length > sizeof(client->proxy_rx) - client->proxy_rx_used ||
        length > client->proxy_receive_window) return -1;
    ssh_mem_copy(client->proxy_rx + client->proxy_rx_used, packet->data + 9U,
                 length);
    client->proxy_rx_used += length;
    client->proxy_receive_window -= length;
    if (client->proxy_receive_window <= SSH_CLIENT_WINDOW / 2U) {
      uint32_t added = SSH_CLIENT_WINDOW - client->proxy_receive_window;
      if (proxy_send_window_adjust(client, added) != 0) return -1;
      client->proxy_receive_window += added;
    }
    return 0;
  }
  if (type == SSH_MSG_CHANNEL_EOF || type == SSH_MSG_CHANNEL_CLOSE ||
      type == SSH_MSG_DISCONNECT) {
    return -1;
  }
  if (type == SSH_MSG_GLOBAL_REQUEST && packet->len >= 6U) {
    uint32_t name_length = ssh_read_u32_be(packet->data + 1U);
    if (name_length > packet->len - 6U) return -1;
    if (packet->data[5U + name_length] != 0U) {
      uint8_t failure = SSH_MSG_REQUEST_FAILURE;
      return ssh_packet_write_encrypted((int)client->proxy_sockfd, &failure,
                                        1U);
    }
  }
  return 0;
}

static int proxy_pump(ssh_client_context_t *client, uint64_t deadline) {
  if (client == 0 || client->proxy_transport == 0) return -1;
  int result = sshclient_wait_encrypted_packet_fd((int)client->proxy_sockfd,
                                        &client->proxy_packet_workspace,
                                        deadline);
  if (result != 0) return result;
  return proxy_process_packet(client, &client->proxy_packet_workspace);
}

static int proxy_stream_send(void *context, const uint8_t *data,
                             u64 length, u64 *sent) {
  ssh_client_context_t *client = (ssh_client_context_t *)context;
  if (client == 0 || data == 0 || sent == 0 || client->proxy_established == 0U ||
      client->proxy_transport == 0) return -1;
  *sent = 0U;
  uint64_t deadline = xaios_clock_nanos() + SSH_CLIENT_TIMEOUT_NS;
  while (client->proxy_remote_window == 0U) {
    if (proxy_pump(client, deadline) != 0) return -1;
  }
  uint32_t chunk = length > UINT32_MAX ? UINT32_MAX : (uint32_t)length;
  if (chunk > client->proxy_remote_window) chunk = client->proxy_remote_window;
  if (chunk > client->proxy_remote_max_packet) chunk = client->proxy_remote_max_packet;
  if (chunk > SSH_WIRE_MAX_CHUNK) chunk = SSH_WIRE_MAX_CHUNK;
  if (chunk == 0U) return -1;
  /* The target handshake retains frame_workspace as its server KEXINIT. */
  uint8_t *packet = client->proxy_packet_workspace.data;
  packet[0] = SSH_MSG_CHANNEL_DATA;
  ssh_write_u32_be(packet + 1U, client->proxy_remote_channel);
  ssh_write_u32_be(packet + 5U, chunk);
  ssh_mem_copy(packet + 9U, data, chunk);
  if (ssh_packet_write_encrypted((int)client->proxy_sockfd, packet,
                                 chunk + 9U) != 0) return -1;
  client->proxy_remote_window -= chunk;
  *sent = chunk;
  return 0;
}

static int proxy_stream_recv(void *context, uint8_t *data,
                             u64 length, u64 *received) {
  ssh_client_context_t *client = (ssh_client_context_t *)context;
  if (client == 0 || data == 0 || received == 0 ||
      client->proxy_established == 0U || client->proxy_transport == 0) return -1;
  *received = 0U;
  for (uint32_t attempts = 0U; attempts < 16U; ++attempts) {
    if (client->proxy_rx_used != 0U) {
      uint32_t count = length < client->proxy_rx_used ? (uint32_t)length
                                                       : client->proxy_rx_used;
      ssh_mem_copy(data, client->proxy_rx, count);
      uint32_t remaining = client->proxy_rx_used - count;
      for (uint32_t i = 0U; i < remaining; ++i)
        client->proxy_rx[i] = client->proxy_rx[count + i];
      client->proxy_rx_used = remaining;
      *received = count;
      return 0;
    }
    int result = proxy_pump(client, xaios_clock_nanos() + SSH_CLIENT_TIMEOUT_NS);
    if (result > 0) return 0;
    if (result < 0) return -1;
  }
  return 0;
}

static int open_proxy_channel(ssh_client_context_t *client, uint64_t deadline) {
  uint8_t packet[512];
  uint32_t position = 0U;
  packet[position++] = SSH_MSG_CHANNEL_OPEN;
  position = append_string(packet, position, sizeof(packet),
                           (const uint8_t *)"direct-tcpip", 12U);
  if (position == UINT32_MAX || position + 12U > sizeof(packet)) return -1;
  client->local_channel = 1U;
  ssh_write_u32_be(packet + position, client->local_channel);
  position += 4U;
  ssh_write_u32_be(packet + position, SSH_CLIENT_WINDOW);
  position += 4U;
  ssh_write_u32_be(packet + position, SSH_CLIENT_PACKET);
  position += 4U;
  position = append_string(packet, position, sizeof(packet),
                           (const uint8_t *)client->target_host,
                           ssh_str_len(client->target_host));
  if (position == UINT32_MAX || position + 4U > sizeof(packet)) return -1;
  ssh_write_u32_be(packet + position, client->target_port);
  position += 4U;
  position = append_string(packet, position, sizeof(packet),
                           (const uint8_t *)"127.0.0.1", 9U);
  if (position == UINT32_MAX || position + 4U > sizeof(packet)) return -1;
  ssh_write_u32_be(packet + position, 0U);
  position += 4U;
  if (ssh_packet_write_encrypted((int)client->sockfd, packet, position) != 0)
    return -1;
  for (;;) {
    ssh_packet_t *response = &client->packet_workspace;
    if (wait_encrypted_packet(client, response, deadline) != 0 ||
        response->len == 0U) return -1;
    if (response->data[0] == SSH_MSG_CHANNEL_OPEN_FAILURE ||
        response->data[0] == SSH_MSG_DISCONNECT) return -1;
    if (response->data[0] != SSH_MSG_CHANNEL_OPEN_CONFIRM) continue;
    if (response->len != 17U ||
        ssh_read_u32_be(response->data + 1U) != client->local_channel)
      return -1;
    client->remote_channel = ssh_read_u32_be(response->data + 5U);
    client->remote_window = ssh_read_u32_be(response->data + 9U);
    client->remote_max_packet = ssh_read_u32_be(response->data + 13U);
    client->receive_window = SSH_CLIENT_WINDOW;
    return client->remote_max_packet == 0U ? -1 : 0;
  }
}

static void promote_proxy_transport(ssh_client_context_t *client) {
  client->proxy_sockfd = client->sockfd;
  client->proxy_transport = client->transport;
  client->proxy_local_channel = client->local_channel;
  client->proxy_remote_channel = client->remote_channel;
  client->proxy_remote_window = client->remote_window;
  client->proxy_remote_max_packet = client->remote_max_packet;
  client->proxy_receive_window = client->receive_window;
  client->sockfd = 0U;
  client->transport = 0;
  client->local_channel = 0U;
  client->remote_channel = 0U;
  client->remote_window = 0U;
  client->remote_max_packet = 0U;
  client->receive_window = 0U;
  sshclient_string_copy(client->host, sizeof(client->host), client->target_host);
  sshclient_string_copy(client->user, sizeof(client->user), client->target_user);
  client->port = client->target_port;
  client->use_identity = client->target_use_identity;
  client->use_agent = 0U;
  client->proxy_established = 1U;
  ssh_mem_zero(client->password, sizeof(client->password));
  client->password_length = 0U;
}

int sshclient_handshake(ssh_client_context_t *client,
                            const ssh_channel_t *outer) {
  uint64_t deadline = xaios_clock_nanos() + SSH_CLIENT_TIMEOUT_NS;
  client->transport = ssh_conn_client_alloc();
  if (client->transport == 0) return -11;
  if (client->proxy_established != 0U) {
    client->sockfd = SSH_CLIENT_RELAY_SOCKET;
    client->transport->sockfd = client->sockfd;
    client->transport->send_fn = proxy_stream_send;
    client->transport->recv_fn = proxy_stream_recv;
    client->transport->io_context = client;
  } else {
    xaios_ip_addr_user_t address;
    if (sshclient_resolve_host(client->host, &address, deadline) != 0) return -10;
    if (xaios_net_connect(&address, client->port, &client->sockfd) != 0)
      return -26;
    client->transport->sockfd = client->sockfd;
  }

  static const uint8_t client_version[] = "SSH-2.0-XAIOS_Client_1.0";
  static const uint8_t client_version_line[] = "SSH-2.0-XAIOS_Client_1.0\r\n";
  u64 sent = 0U;
  if (ssh_conn_send(client->transport, client_version_line,
                    sizeof(client_version_line) - 1U, &sent) != 0 ||
      sent != sizeof(client_version_line) - 1U) return -12;
  uint8_t server_version[256];
  uint32_t server_version_length = 0U;
  for (;;) {
    u64 received = 0U;
    if (ssh_conn_recv(client->transport, server_version + server_version_length,
                      1U, &received) != 0) return -13;
    if (received == 0U) {
      if (xaios_clock_nanos() >= deadline) return -14;
      continue;
    }
    if (server_version[server_version_length++] == '\n') break;
    if (server_version_length == sizeof(server_version)) return -15;
  }
  while (server_version_length != 0U &&
         (server_version[server_version_length - 1U] == '\r' ||
          server_version[server_version_length - 1U] == '\n')) {
    --server_version_length;
  }
  if (server_version_length < 8U ||
      !sshclient_bytes_equal(server_version, (const uint8_t *)"SSH-2.0-", 8U)) return -16;

  uint8_t client_kex[512];
  uint32_t client_kex_length = 0U;
  if (sshclient_build_kexinit(client_kex, sizeof(client_kex), &client_kex_length) != 0 ||
      ssh_packet_write((int)client->sockfd, client_kex, client_kex_length) != 0)
    return -17;
  ssh_packet_t *packet = &client->packet_workspace;
  uint32_t hybrid = 0U;
  if (sshclient_wait_plain_packet(client, packet, deadline) != 0 ||
      sshclient_validate_server_kexinit(packet, &hybrid) != 0) return -18;
  uint32_t server_kex_length = packet->len;
  if (server_kex_length > sizeof(client->frame_workspace)) return -18;
  ssh_mem_copy(client->frame_workspace, packet->data, server_kex_length);
  client->transport->kex_hybrid = hybrid;

  uint8_t client_private[32];
  uint8_t client_public[SSH_MLKEM768_PUBLIC_KEY_SIZE + 32U];
  uint8_t mlkem_secret_key[SSH_MLKEM768_SECRET_KEY_SIZE];
  uint32_t client_public_length = 32U;
  if (crypto_random_bytes(client_private, sizeof(client_private)) != 0 ||
      xaios_x25519_base(client_public + (hybrid != 0U
                                            ? SSH_MLKEM768_PUBLIC_KEY_SIZE
                                            : 0U),
                        client_private) != 0) return -19;
  if (hybrid != 0U) {
    if (ssh_mlkem768_keypair(client_public, mlkem_secret_key) != 0) return -19;
    client_public_length = sizeof(client_public);
  }
  uint8_t init[SSH_MLKEM768_PUBLIC_KEY_SIZE + 32U + 5U];
  init[0] = SSH_MSG_KEXDH_INIT;
  ssh_write_u32_be(init + 1U, client_public_length);
  ssh_mem_copy(init + 5U, client_public, client_public_length);
  if (ssh_packet_write((int)client->sockfd, init,
                       client_public_length + 5U) != 0) return -20;
  if (sshclient_wait_plain_packet(client, packet, deadline) != 0) return -21;
  int kex_reply = sshclient_parse_kex_reply(client, packet, client_version,
                                  sizeof(client_version) - 1U, server_version,
                                  server_version_length, client_kex,
                                  client_kex_length, client->frame_workspace,
                                  server_kex_length, client_private,
                                  client_public, client_public_length,
                                  hybrid != 0U ? mlkem_secret_key : 0);
  if (kex_reply == -2) return -25;
  if (kex_reply != 0) return -21;
  ssh_mem_zero(client_private, sizeof(client_private));
  ssh_mem_zero(mlkem_secret_key, sizeof(mlkem_secret_key));
  if (sshclient_wait_plain_packet(client, packet, deadline) != 0 ||
      packet->len != 1U || packet->data[0] != SSH_MSG_NEWKEYS) return -22;
  uint8_t client_newkeys = SSH_MSG_NEWKEYS;
  if (ssh_packet_write((int)client->sockfd, &client_newkeys, 1U) != 0 ||
      sshclient_derive_crypto(client->transport) != 0) return -23;
  if (client->use_agent != 0U) {
#if defined(XAIOS_SSH_CLIENT_APP)
    if (sshclient_authenticate_agent(client, deadline) != 0) return -28;
#else
    return -28;
#endif
  } else if (client->use_identity != 0U) {
    ssh_identity_t identity;
    if (ssh_identity_load(client->identity_path, client->password, &identity) !=
        0) {
      ssh_mem_zero(&identity, sizeof(identity));
      return -27;
    }
    if (sshclient_authenticate_public_key(client, deadline, &identity) != 0) {
      ssh_mem_zero(&identity, sizeof(identity));
      return -28;
    }
    ssh_mem_zero(&identity, sizeof(identity));
    ssh_mem_zero(client->password, sizeof(client->password));
    client->password_length = 0U;
  } else if (sshclient_authenticate_password(client, deadline) != 0) {
    return -23;
  }
  if (client->proxy_enabled != 0U && client->proxy_established == 0U) {
    if (open_proxy_channel(client, deadline) != 0) return -24;
    promote_proxy_transport(client);
    return 1;
  }
  if (open_session_channel(client, outer, deadline) != 0) return -24;
  client->connected = 1U;
  return 0;
}
