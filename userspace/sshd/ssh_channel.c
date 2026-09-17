#include "ssh_channel.h"
#include "ssh_channel_internal.h"
#include "ssh_alt_screen.h"
#include "ssh_channel_shell.h"
#include "ssh_channel_stream.h"
#include "ssh_connection.h"
#include "ssh_protocol.h"
#include "ssh_utils.h"
#include "sftp_server.h"
#include "ssh_client.h"
#include "nano_editor.h"
#include "pong_game.h"
#include "sshd.h"
#include <xaios_control_client.h>
#include <xaios_user.h>
#include <xaios_screen.h>

#define SFTP_REQUEST_READ 5U
#define SFTP_REQUEST_WRITE 6U

enum {
  SSH_XTOP_SORT_CPU = 0U,
  SSH_XTOP_SORT_MEMORY,
  SSH_XTOP_SORT_TIME,
  SSH_XTOP_SORT_PID,
  SSH_XTOP_SORT_STATE,
  SSH_XTOP_SORT_SYSCALLS,
  SSH_XTOP_SORT_COMMAND,
  SSH_XTOP_SORT_PARENT
};

int nano_command_argument(const char *command, char *argument,
                                 uint32_t capacity) {
  uint32_t i = 0U;
  uint32_t used = 0U;
  while (command[i] == ' ' || command[i] == '\t') ++i;
  while (command[i] != '\0' && command[i] != ' ' && command[i] != '\t') ++i;
  while (command[i] == ' ' || command[i] == '\t') ++i;
  if (command[i] == '\0' || command[i] == '-') return -1;
  while (command[i] != '\0' && command[i] != ' ' && command[i] != '\t' &&
         command[i] != '\r' && command[i] != '\n') {
    if (used + 1U >= capacity) return -1;
    argument[used++] = command[i++];
  }
  while (command[i] == ' ' || command[i] == '\t' || command[i] == '\r' ||
         command[i] == '\n') ++i;
  if (command[i] != '\0') return -1;
  argument[used] = '\0';
  return 0;
}

int ssh_channel_packet_string_equal(const uint8_t *value, uint32_t value_len,
                                    const char *expected) {
  uint32_t expected_len = ssh_str_len(expected);
  if (value_len != expected_len) return 0;
  for (uint32_t i = 0; i < value_len; ++i) {
    if (value[i] != (uint8_t)expected[i]) return 0;
  }
  return 1;
}

int ssh_channel_packet_has_zero(const uint8_t *value, uint32_t value_len) {
  for (uint32_t i = 0; i < value_len; ++i) {
    if (value[i] == 0U) return 1;
  }
  return 0;
}

static int parse_forward_ipv4(const char *text,
                              xaios_ip_addr_user_t *address) {
  uint32_t part = 0U, value = 0U, digits = 0U;
  xaios_memzero(address, sizeof(*address));
  for (uint32_t i = 0U;; ++i) {
    char character = text[i];
    if (character >= '0' && character <= '9') {
      value = value * 10U + (uint32_t)(character - '0');
      if (value > 255U || ++digits > 3U) return -1;
    } else if (character == '.' || character == '\0') {
      if (digits == 0U || part >= 4U) return -1;
      address->addr[part++] = (uint8_t)value;
      value = 0U;
      digits = 0U;
      if (character == '\0') break;
    } else {
      return -1;
    }
  }
  if (part != 4U) return -1;
  address->family = 4U;
  return 0;
}

static int connect_forward_target(const uint8_t *host, uint32_t host_length,
                                  uint32_t port, u64 *socket) {
  char name[128];
  xaios_ip_addr_user_t address;
  if (host_length == 0U || host_length >= sizeof(name) || port == 0U ||
      port > 65535U || ssh_channel_packet_has_zero(host, host_length)) return -1;
  ssh_mem_copy(name, host, host_length);
  name[host_length] = '\0';
  if (parse_forward_ipv4(name, &address) != 0) {
    int status = xaios_net_resolve_address(name, 4U, &address);
    if (status != 0) status = xaios_net_resolve_address(name, 6U, &address);
    if (status != 0) return -1;
  }
  return xaios_net_connect(&address, port, socket);
}

int pong_command_exact(const char *command) {
  uint32_t index = 0U;
  static const char name[] = "pong";
  while (command[index] == ' ' || command[index] == '\t' ||
         command[index] == '\r' || command[index] == '\n') ++index;
  for (uint32_t i = 0U; i < sizeof(name) - 1U; ++i)
    if (command[index++] != name[i]) return 0;
  while (command[index] == ' ' || command[index] == '\t' ||
         command[index] == '\r' || command[index] == '\n') ++index;
  return command[index] == '\0';
}

int ssh_channel_handle_packet(int sockfd, const ssh_packet_t *pkt) {
  if (pkt->len == 0) return -1;
  uint8_t msg_type = pkt->data[0];

  if (msg_type == SSH_MSG_CHANNEL_OPEN_CONFIRM) {
    if (pkt->len < 17U) return -1;
    uint32_t local_id = ssh_read_u32_be(pkt->data + 1U);
    ssh_channel_t *agent = ssh_channel_find_local(sockfd, local_id);
    if (agent == 0 || agent->is_agent == 0U ||
        agent->agent_open_pending == 0U) return -1;
    agent->remote_id = ssh_read_u32_be(pkt->data + 5U);
    agent->remote_window = ssh_read_u32_be(pkt->data + 9U);
    agent->remote_max_packet = ssh_read_u32_be(pkt->data + 13U);
    if (agent->remote_max_packet == 0U) return -1;
    agent->agent_open_pending = 0U;
    ssh_channel_t *session = ssh_channel_find_local(
        sockfd, agent->agent_session_local_id);
    if (session == 0) return -1;
    session->agent_open_pending = 0U;
    return ssh_client_agent_ready(session);
  }

  if (msg_type == SSH_MSG_CHANNEL_OPEN_FAILURE) {
    if (pkt->len < 9U) return -1;
    ssh_channel_t *agent = ssh_channel_find_local(
        sockfd, ssh_read_u32_be(pkt->data + 1U));
    if (agent == 0 || agent->is_agent == 0U) return 0;
    ssh_channel_t *session = ssh_channel_find_local(
        sockfd, agent->agent_session_local_id);
    if (session != 0) {
      session->agent_forwarding = 0U;
      session->agent_open_pending = 0U;
    }
    ssh_mem_zero(agent, sizeof(*agent));
    return 0;
  }

  if (msg_type == SSH_MSG_CHANNEL_OPEN) {
    if (pkt->len < 17) return -1;
    uint32_t type_len = ssh_read_string_len(pkt->data + 1);
    if (type_len > pkt->len - 17U) return -1;
    uint32_t off = 5U + type_len;
    if (off + 12U > pkt->len) return -1;
    uint32_t remote_id = ssh_read_u32_be(pkt->data + off);
    uint32_t is_session =
        ssh_channel_packet_string_equal(pkt->data + 5U, type_len, "session");
    uint32_t is_forward =
        ssh_channel_packet_string_equal(pkt->data + 5U, type_len, "direct-tcpip");
    if (is_session == 0U && is_forward == 0U) {
      uint8_t failure[17];
      failure[0] = SSH_MSG_CHANNEL_OPEN_FAILURE;
      ssh_write_u32_be(failure + 1U, remote_id);
      ssh_write_u32_be(failure + 5U, 1U);
      ssh_write_u32_be(failure + 9U, 0U);
      ssh_write_u32_be(failure + 13U, 0U);
      return ssh_packet_write_encrypted(sockfd, failure, sizeof(failure));
    }
    ssh_channel_t *ch = ssh_channel_alloc(sockfd);
    if (!ch) {
      uint8_t failure[17];
      failure[0] = SSH_MSG_CHANNEL_OPEN_FAILURE;
      ssh_write_u32_be(failure + 1U, remote_id);
      ssh_write_u32_be(failure + 5U, 4U);
      ssh_write_u32_be(failure + 9U, 0U);
      ssh_write_u32_be(failure + 13U, 0U);
      return ssh_packet_write_encrypted(sockfd, failure, sizeof(failure));
    }
    ch->remote_id = remote_id;
    ch->window_size = SSH_CHANNEL_INITIAL_WINDOW;
    ch->remote_window = ssh_read_u32_be(pkt->data + off + 4U);
    ch->remote_max_packet = ssh_read_u32_be(pkt->data + off + 8U);
    if (ch->remote_max_packet == 0U) {
      ch->active = 0U;
      return -1;
    }
    if (is_forward != 0U) {
      ssh_connection_t *connection = ssh_conn_find((u64)(uint32_t)sockfd);
      uint32_t cursor = off + 12U;
      if (connection == 0 ||
          connection->principal_role != XAIOS_CONTROL_ROLE_ADMIN ||
          pkt->len - cursor < 4U) {
        ch->active = 0U;
        return -1;
      }
      uint32_t host_length = ssh_read_u32_be(pkt->data + cursor);
      cursor += 4U;
      if (host_length > pkt->len - cursor ||
          pkt->len - cursor - host_length < 8U) {
        ch->active = 0U;
        return -1;
      }
      const uint8_t *host = pkt->data + cursor;
      cursor += host_length;
      uint32_t port = ssh_read_u32_be(pkt->data + cursor);
      cursor += 4U;
      uint32_t origin_length = ssh_read_u32_be(pkt->data + cursor);
      cursor += 4U;
      if (origin_length > pkt->len - cursor ||
          pkt->len - cursor - origin_length != 4U ||
          ssh_channel_packet_has_zero(pkt->data + cursor, origin_length) ||
          connect_forward_target(host, host_length, port,
                                 &ch->forward_fd) != 0) {
        uint8_t failure[17];
        failure[0] = SSH_MSG_CHANNEL_OPEN_FAILURE;
        ssh_write_u32_be(failure + 1U, remote_id);
        ssh_write_u32_be(failure + 5U, 2U);
        ssh_write_u32_be(failure + 9U, 0U);
        ssh_write_u32_be(failure + 13U, 0U);
        ssh_stream_screen_release(ch);
        ssh_mem_zero(ch, sizeof(*ch));
        return ssh_packet_write_encrypted(sockfd, failure, sizeof(failure));
      }
      ch->is_forward = 1U;
    }
    /* Send CHANNEL_OPEN_CONFIRMATION */
    uint8_t reply[32];
    reply[0] = SSH_MSG_CHANNEL_OPEN_CONFIRM;
    ssh_write_u32_be(reply + 1, ch->remote_id);
    ssh_write_u32_be(reply + 5, ch->local_id);
    ssh_write_u32_be(reply + 9, SSH_CHANNEL_INITIAL_WINDOW);
    ssh_write_u32_be(reply + 13, SSH_CHANNEL_MAX_PACKET);
    return ssh_packet_write_encrypted(sockfd, reply, 17);
  }

  if (msg_type == SSH_MSG_CHANNEL_DATA) {
    if (pkt->len < 9) return -1;
    uint32_t local_id = ssh_read_u32_be(pkt->data + 1);
    uint32_t data_len = ssh_read_string_len(pkt->data + 5);
    if (data_len > pkt->len - 9U || data_len == 0) return -1;

    /* Find channel for window management */
    ssh_channel_t *ch = ssh_channel_find_local(sockfd, local_id);
    if (!ch) return -1;
    if (data_len > ch->window_size || data_len > SSH_CHANNEL_MAX_PACKET) {
      return -1;
    }
    ch->window_size -= data_len;
    if (ch->window_size <= SSH_CHANNEL_INITIAL_WINDOW / 2U) {
      uint32_t added = SSH_CHANNEL_INITIAL_WINDOW - ch->window_size;
      if (ssh_stream_send_window_adjust(sockfd, ch->remote_id, added) != 0) return -1;
      ch->window_size += added;
    }

    if (ch->is_forward != 0U) {
      uint32_t offset = 0U;
      while (offset < data_len) {
        u64 sent = 0U;
        if (xaios_net_send(ch->forward_fd, pkt->data + 9U + offset,
                           data_len - offset, &sent) != 0 || sent == 0U ||
            sent > data_len - offset) return -1;
        offset += (uint32_t)sent;
      }
      return 0;
    }

    if (ch->is_agent != 0U) {
      ssh_channel_t *session = ssh_channel_find_local(
          sockfd, ch->agent_session_local_id);
      if (session == 0 ||
          ssh_client_agent_response(session, pkt->data + 9U, data_len) != 0)
        return -1;
      return 0;
    }

    if (ch->is_sftp != 0U) {
      if (data_len > SSH_CHANNEL_SFTP_BUFFER_SIZE - ch->sftp_rx_used) {
        xaios_log("sshd: SFTP channel receive buffer exceeded\n");
        return -1;
      }
      ssh_mem_copy(ch->sftp_rx + ch->sftp_rx_used, pkt->data + 9, data_len);
      ch->sftp_rx_used += data_len;

      while (ch->sftp_rx_used >= 4U) {
        uint32_t sftp_len = ssh_read_u32_be(ch->sftp_rx);
        if (sftp_len == 0U ||
            sftp_len > SSH_CHANNEL_SFTP_REQUEST_MAX - 4U) {
          xaios_log("sshd: rejected invalid SFTP packet length\n");
          return -1;
        }
        if (ch->sftp_rx_used < sftp_len + 4U) break;
        if (sftp_handle_message(sockfd, ch->remote_id,
                                ch->sftp_rx + 4U, sftp_len) != 0) {
          xaios_log("sshd: SFTP request handler failed\n");
          return -1;
        }
        uint32_t consumed = sftp_len + 4U;
        uint32_t remaining = ch->sftp_rx_used - consumed;
        for (uint32_t i = 0; i < remaining; ++i) {
          ch->sftp_rx[i] = ch->sftp_rx[consumed + i];
        }
        ch->sftp_rx_used = remaining;
      }
      return 0;
    }

    if (ch->nano.active != 0U) {
      return nano_handle_input(ch, pkt->data + 9U, data_len);
    }

    if (ch->less.active != 0U) {
      return less_handle_input(ch, pkt->data + 9U, data_len);
    }

    if (ch->pong.active != 0U) {
      return pong_handle_input(ch, pkt->data + 9U, data_len);
    }

    if (ssh_client_is_prompting(ch)) {
      int result = ssh_client_password_input(ch, pkt->data + 9U, data_len);
      return result > 0 ? shell_send_prompt(ch) : result;
    }

    if (ssh_client_is_active(ch)) {
      return ssh_client_forward_input(ch, pkt->data + 9U, data_len);
    }

    if (ch->shell_active != 0U) {
      return ssh_shell_handle_input(ch, pkt->data + 9U, data_len);
    }

    /* Execute command via remote_login */
    char command[4096];
    if (data_len >= sizeof(command) ||
        ssh_channel_packet_has_zero(pkt->data + 9U, data_len)) return -1;
    ssh_mem_copy(command, pkt->data + 9, data_len);
    command[data_len] = '\0';
    if (ssh_shell_prepare_command(ch, command, sizeof(command)) != 0) return -1;

    char output[8192];
    u64 out_size = 0;
    int result = ssh_shell_execute_admin(sockfd, command, output, sizeof(output),
                                        &out_size);

    if (result < 0 && out_size == 0U) {
      const char *error_msg = "Command execution failed\n";
      uint32_t error_len = ssh_str_len(error_msg);
      return ssh_channel_send_data(sockfd, ch->remote_id,
                                   (const uint8_t *)error_msg, error_len);
    }

    uint32_t output_len = (uint32_t)out_size;
    if (output_len == 0) {
      output_len = 1;
      output[0] = '\n';
      output[1] = '\0';
    }

    return ssh_channel_send_data(sockfd, ch->remote_id,
                                 (const uint8_t *)output, output_len);
  }

  if (msg_type == SSH_MSG_CHANNEL_REQUEST) {
    return ssh_channel_handle_request(sockfd, pkt);
  }

  if (msg_type == SSH_MSG_CHANNEL_EOF) {
    if (pkt->len < 5U) return -1;
    ssh_channel_t *ch = ssh_channel_find_local(
        sockfd, ssh_read_u32_be(pkt->data + 1U));
    if (ch == 0 || ch->close_sent != 0U) return 0;
    if (ch->is_forward != 0U) {
      if (ch->forward_fd != 0U) (void)xaios_net_close(ch->forward_fd);
      ch->forward_fd = 0U;
      ch->exit_status = 0U;
      ch->close_after_flush = 1U;
      return flush_channel(ch);
    }
    if (ch->is_sftp != 0U) {
      ch->exit_status = 0U;
      ch->close_after_flush = 1U;
      return flush_channel(ch);
    }
    if (ch->nano.active != 0U) return nano_finish(ch, 0U);
    if (ch->less.active != 0U) return less_finish(ch, 0U);
    if (ch->pong.active != 0U) return pong_finish(ch, 0U);
    if (ssh_client_is_prompting(ch) || ssh_client_is_active(ch)) return 0;
    if (ch->shell_active != 0U) {
      (void)xaios_remote_login_session_close(ch->owner_sockfd);
      ch->shell_active = 0U;
      ch->exit_status = 0U;
      ch->close_after_flush = 1U;
      return flush_channel(ch);
    }
    return 0;
  }

  if (msg_type == SSH_MSG_CHANNEL_CLOSE) {
    if (pkt->len >= 5) {
      uint32_t local_id = ssh_read_u32_be(pkt->data + 1);
      ssh_channel_t *ch = ssh_channel_find_local(sockfd, local_id);
      if (ch) {
        if (ch->forward_fd != 0U) (void)xaios_net_close(ch->forward_fd);
        sftp_close_channel(sockfd, ch->remote_id);
        ssh_client_close(ch);
        if (ch->is_agent != 0U) {
          ssh_channel_t *session = ssh_channel_find_local(
              sockfd, ch->agent_session_local_id);
          if (session != 0) {
            session->agent_forwarding = 0U;
            session->agent_open_pending = 0U;
          }
        } else {
          ssh_channel_t *agent = ssh_channel_find_agent(ch);
          if (agent != 0) {
            if (agent->close_sent == 0U && agent->remote_max_packet != 0U) {
              uint8_t close_agent[5];
              close_agent[0] = SSH_MSG_CHANNEL_CLOSE;
              ssh_write_u32_be(close_agent + 1U, agent->remote_id);
              (void)ssh_packet_write_encrypted(sockfd, close_agent,
                                               sizeof(close_agent));
            }
            ssh_mem_zero(agent, sizeof(*agent));
          }
        }
        if (ch->close_sent == 0U) {
          uint8_t close_msg[5];
          close_msg[0] = SSH_MSG_CHANNEL_CLOSE;
          ssh_write_u32_be(close_msg + 1, ch->remote_id);
          if (ssh_packet_write_encrypted(sockfd, close_msg,
                                         sizeof(close_msg)) != 0) return -1;
        }
        ssh_stream_screen_release(ch);
        ssh_mem_zero(ch, sizeof(*ch));
      }
    }
    return 0;
  }

  if (msg_type == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
    if (pkt->len >= 9) {
      uint32_t local_id = ssh_read_u32_be(pkt->data + 1);
      uint32_t bytes_to_add = ssh_read_u32_be(pkt->data + 5);
      ssh_channel_t *ch = ssh_channel_find_local(sockfd, local_id);
      if (ch) {
        if (UINT32_MAX - ch->remote_window < bytes_to_add) return -1;
        ch->remote_window += bytes_to_add;
        return flush_channel(ch);
      }
    }
    return 0;
  }

  if (msg_type == SSH_MSG_CHANNEL_SUCCESS || msg_type == SSH_MSG_CHANNEL_FAILURE) {
    /* Responses to our requests — accept and ignore */
    return 0;
  }

  return 0; /* ignore unknown channel messages */
}
