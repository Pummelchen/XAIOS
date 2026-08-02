#include "ssh_channel.h"
#include "ssh_protocol.h"
#include "ssh_utils.h"
#include "sftp_server.h"
#include <xaios_user.h>

static ssh_channel_t g_channels[SSH_CHANNEL_MAX];
static uint32_t g_next_local_id = 1;

void ssh_channel_init(void) {
  for (uint32_t i = 0; i < SSH_CHANNEL_MAX; ++i) {
    g_channels[i].active = 0;
    g_channels[i].local_id = 0;
    g_channels[i].remote_id = 0;
    g_channels[i].window_size = 0;
    g_channels[i].remote_window = 0;
    g_channels[i].bytes_consumed = 0;
    g_channels[i].is_sftp = 0;
    g_channels[i].sftp_rx_used = 0;
  }
  g_next_local_id = 1;
}

static ssh_channel_t *alloc_channel(void) {
  for (uint32_t i = 0; i < SSH_CHANNEL_MAX; ++i) {
    if (!g_channels[i].active) {
      g_channels[i].active = 1;
      g_channels[i].local_id = g_next_local_id++;
      g_channels[i].bytes_consumed = 0;
      g_channels[i].is_sftp = 0;
      g_channels[i].sftp_rx_used = 0;
      return &g_channels[i];
    }
  }
  return (ssh_channel_t *)0;
}

static ssh_channel_t *find_channel_by_remote(uint32_t remote_id) {
  for (uint32_t i = 0; i < SSH_CHANNEL_MAX; ++i) {
    if (g_channels[i].active && g_channels[i].remote_id == remote_id) {
      return &g_channels[i];
    }
  }
  return (ssh_channel_t *)0;
}

static ssh_channel_t *find_channel_by_local(uint32_t local_id) {
  for (uint32_t i = 0; i < SSH_CHANNEL_MAX; ++i) {
    if (g_channels[i].active && g_channels[i].local_id == local_id) {
      return &g_channels[i];
    }
  }
  return (ssh_channel_t *)0;
}

/* Send window adjust: type 93, recipient_channel, bytes_to_add */
static void send_window_adjust(int sockfd, uint32_t remote_id, uint32_t bytes) {
  uint8_t adjust[9];
  adjust[0] = SSH_MSG_CHANNEL_WINDOW_ADJUST;
  ssh_write_u32_be(adjust + 1, remote_id);
  ssh_write_u32_be(adjust + 5, bytes);
  ssh_packet_write_encrypted(sockfd, adjust, 9);
}

/* Send channel success/failure */
static void send_channel_reply(int sockfd, uint32_t remote_id, int success) {
  uint8_t reply[5];
  reply[0] = success ? SSH_MSG_CHANNEL_SUCCESS : SSH_MSG_CHANNEL_FAILURE;
  ssh_write_u32_be(reply + 1, remote_id);
  ssh_packet_write_encrypted(sockfd, reply, 5);
}

/* Send CHANNEL_DATA with output */
static int send_channel_data(int sockfd, uint32_t remote_id,
                              const uint8_t *data, uint32_t len) {
  uint8_t reply[SSH_MAX_PACKET_SIZE];
  if (9 + len > SSH_MAX_PACKET_SIZE) return -1;
  ssh_channel_t *ch = find_channel_by_remote(remote_id);
  if (ch) {
    if (len > ch->remote_window) {
      len = ch->remote_window;
    }
    ch->remote_window -= len;
  }
  if (len == 0) return 0;
  reply[0] = SSH_MSG_CHANNEL_DATA;
  ssh_write_u32_be(reply + 1, remote_id);
  ssh_write_u32_be(reply + 5, len);
  ssh_mem_copy(reply + 9, data, len);
  return ssh_packet_write_encrypted(sockfd, reply, 9 + len);
}

/* Send CHANNEL_EOF */
static void send_channel_eof(int sockfd, uint32_t remote_id) {
  uint8_t eof_msg[5];
  eof_msg[0] = SSH_MSG_CHANNEL_EOF;
  ssh_write_u32_be(eof_msg + 1, remote_id);
  ssh_packet_write_encrypted(sockfd, eof_msg, 5);
}

static void send_channel_exit_status(int sockfd, uint32_t remote_id,
                                     uint32_t status) {
  uint8_t message[25];
  static const char request[] = "exit-status";
  message[0] = SSH_MSG_CHANNEL_REQUEST;
  ssh_write_u32_be(message + 1U, remote_id);
  ssh_write_u32_be(message + 5U, sizeof(request) - 1U);
  ssh_mem_copy(message + 9U, request, sizeof(request) - 1U);
  message[20] = 0;
  ssh_write_u32_be(message + 21U, status);
  ssh_packet_write_encrypted(sockfd, message, sizeof(message));
}

/* ---- Handle CHANNEL_REQUEST (type 98) ---- */
static int handle_channel_request(int sockfd, const ssh_packet_t *pkt) {
  if (pkt->len < 10) return -1;

  /* Parse: uint32 recipient_channel, string request_type, bool want_reply */
  uint32_t local_id = ssh_read_u32_be(pkt->data + 1);
  ssh_channel_t *ch = find_channel_by_local(local_id);
  if (!ch) return -1;

  uint32_t type_len = ssh_read_string_len(pkt->data + 5);
  if (5 + 4 + type_len + 1 > pkt->len) return -1;

  char request_type[64];
  uint32_t copy_len = type_len < 63 ? type_len : 63;
  ssh_mem_copy(request_type, pkt->data + 9, copy_len);
  request_type[copy_len] = '\0';

  uint32_t type_end = 9 + type_len;
  uint8_t want_reply = (type_end < pkt->len) ? pkt->data[type_end] : 0;

  uint32_t data_start = type_end + 1;

  if (ssh_str_eq(request_type, "pty-req")) {
    /* Parse: string term, uint32 width, uint32 height, uint32 pixwidth, uint32 pixheight, string modes */
    /* Accept and ignore — reply success */
    if (want_reply) {
      send_channel_reply(sockfd, ch->remote_id, 1);
    }
    return 0;
  }

  if (ssh_str_eq(request_type, "env")) {
    /* Accept and ignore */
    if (want_reply) {
      send_channel_reply(sockfd, ch->remote_id, 1);
    }
    return 0;
  }

  if (ssh_str_eq(request_type, "shell")) {
    if (want_reply) {
      send_channel_reply(sockfd, ch->remote_id, 1);
    }
    return 0;
  }

  if (ssh_str_eq(request_type, "exec")) {
    /* Parse command string */
    if (data_start + 4 > pkt->len) {
      if (want_reply) send_channel_reply(sockfd, ch->remote_id, 0);
      return -1;
    }
    uint32_t cmd_len = ssh_read_string_len(pkt->data + data_start);
    if (data_start + 4 + cmd_len > pkt->len) {
      if (want_reply) send_channel_reply(sockfd, ch->remote_id, 0);
      return -1;
    }
    char command[4096];
    uint32_t clamped = cmd_len < 4095 ? cmd_len : 4095;
    ssh_mem_copy(command, pkt->data + data_start + 4, clamped);
    command[clamped] = '\0';

    if (want_reply) {
      send_channel_reply(sockfd, ch->remote_id, 1);
    }

    /* Execute command */
    char output[8192];
    u64 out_size = 0;
    int result = xaios_remote_login("admin", command, output, sizeof(output), &out_size);

    if (result < 0) {
      const char *err = "Command execution failed\n";
      send_channel_data(sockfd, ch->remote_id, (const uint8_t *)err, ssh_str_len(err));
    } else {
      uint32_t olen = (uint32_t)out_size;
      if (olen == 0) { olen = 1; output[0] = '\n'; }
      if (olen > 0) {
        send_channel_data(sockfd, ch->remote_id, (const uint8_t *)output, olen);
      }
    }

    send_channel_exit_status(sockfd, ch->remote_id, result < 0 ? 1U : 0U);
    send_channel_eof(sockfd, ch->remote_id);

    /* Send CHANNEL_CLOSE */
    uint8_t close_msg[5];
    close_msg[0] = SSH_MSG_CHANNEL_CLOSE;
    ssh_write_u32_be(close_msg + 1, ch->remote_id);
    ssh_packet_write_encrypted(sockfd, close_msg, 5);
    ch->active = 0;
    return 0;
  }

  if (ssh_str_eq(request_type, "subsystem")) {
    /* Parse subsystem name */
    if (data_start + 4 > pkt->len) {
      if (want_reply) send_channel_reply(sockfd, ch->remote_id, 0);
      return -1;
    }
    uint32_t name_len = ssh_read_string_len(pkt->data + data_start);
    if (data_start + 4 + name_len > pkt->len) {
      if (want_reply) send_channel_reply(sockfd, ch->remote_id, 0);
      return -1;
    }
    char subsystem[64];
    uint32_t slen = name_len < 63 ? name_len : 63;
    ssh_mem_copy(subsystem, pkt->data + data_start + 4, slen);
    subsystem[slen] = '\0';

    if (ssh_str_eq(subsystem, "sftp")) {
      if (want_reply) {
        send_channel_reply(sockfd, ch->remote_id, 1);
      }
      ch->is_sftp = 1;
      ch->sftp_rx_used = 0;
      return 0;
    }

    /* Unknown subsystem */
    if (want_reply) {
      send_channel_reply(sockfd, ch->remote_id, 0);
    }
    return 0;
  }

  /* Unknown request type */
  if (want_reply) {
    send_channel_reply(sockfd, ch->remote_id, 0);
  }
  return 0;
}

int ssh_channel_handle_packet(int sockfd, const ssh_packet_t *pkt) {
  if (pkt->len == 0) return -1;
  uint8_t msg_type = pkt->data[0];

  if (msg_type == SSH_MSG_CHANNEL_OPEN) {
    if (pkt->len < 17) return -1;
    uint32_t type_len = ssh_read_string_len(pkt->data + 1);
    if (type_len > pkt->len - 17U) return -1;
    uint32_t off = 5U + type_len;
    if (off + 12U > pkt->len) return -1;
    ssh_channel_t *ch = alloc_channel();
    if (!ch) return -1;
    ch->remote_id = ssh_read_u32_be(pkt->data + off);
    ch->window_size = ssh_read_u32_be(pkt->data + off + 4);
    ch->remote_window = 65536;
    ch->bytes_consumed = 0;
    /* Send CHANNEL_OPEN_CONFIRMATION */
    uint8_t reply[32];
    reply[0] = SSH_MSG_CHANNEL_OPEN_CONFIRM;
    ssh_write_u32_be(reply + 1, ch->remote_id);
    ssh_write_u32_be(reply + 5, ch->local_id);
    ssh_write_u32_be(reply + 9, 65536); /* initial window */
    ssh_write_u32_be(reply + 13, 32768); /* max packet */
    return ssh_packet_write_encrypted(sockfd, reply, 17);
  }

  if (msg_type == SSH_MSG_CHANNEL_DATA) {
    if (pkt->len < 9) return -1;
    uint32_t local_id = ssh_read_u32_be(pkt->data + 1);
    uint32_t data_len = ssh_read_string_len(pkt->data + 5);
    if (9 + data_len > pkt->len || data_len == 0) return -1;

    /* Find channel for window management */
    ssh_channel_t *ch = find_channel_by_local(local_id);
    if (!ch) return -1;
    if (ch) {
      ch->bytes_consumed += data_len;
      /* Replenish window when more than 32KB consumed */
      if (ch->bytes_consumed >= 32768) {
        send_window_adjust(sockfd, ch->remote_id, 65536);
        ch->window_size += 65536;
        ch->bytes_consumed = 0;
      }
    }

    if (ch->is_sftp != 0U) {
      if (data_len > SSH_CHANNEL_SFTP_BUFFER_SIZE - ch->sftp_rx_used) {
        return -1;
      }
      ssh_mem_copy(ch->sftp_rx + ch->sftp_rx_used, pkt->data + 9, data_len);
      ch->sftp_rx_used += data_len;

      while (ch->sftp_rx_used >= 4U) {
        uint32_t sftp_len = ssh_read_u32_be(ch->sftp_rx);
        if (sftp_len == 0U || sftp_len > SSH_CHANNEL_SFTP_BUFFER_SIZE - 4U) {
          return -1;
        }
        if (ch->sftp_rx_used < sftp_len + 4U) break;
        if (sftp_handle_message(sockfd, ch->remote_id,
                                ch->sftp_rx + 4U, sftp_len) != 0) {
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

    /* Execute command via remote_login */
    char command[4096];
    if (data_len >= 4096) data_len = 4095;
    ssh_mem_copy(command, pkt->data + 9, data_len);
    command[data_len] = '\0';

    char output[8192];
    u64 out_size = 0;
    int result = xaios_remote_login("admin", command, output, sizeof(output), &out_size);

    if (result < 0) {
      const char *error_msg = "Command execution failed\n";
      uint32_t error_len = ssh_str_len(error_msg);
      uint8_t reply[SSH_MAX_PACKET_SIZE];
      reply[0] = SSH_MSG_CHANNEL_DATA;
      ssh_write_u32_be(reply + 1, ch ? ch->remote_id : local_id);
      ssh_write_u32_be(reply + 5, error_len);
      ssh_mem_copy(reply + 9, error_msg, error_len);
      return ssh_packet_write_encrypted(sockfd, reply, 9 + error_len);
    }

    uint32_t output_len = (uint32_t)out_size;
    if (output_len == 0) {
      output_len = 1;
      output[0] = '\n';
      output[1] = '\0';
    }

    uint8_t reply[SSH_MAX_PACKET_SIZE];
    reply[0] = SSH_MSG_CHANNEL_DATA;
    ssh_write_u32_be(reply + 1, ch ? ch->remote_id : local_id);
    ssh_write_u32_be(reply + 5, output_len);
    ssh_mem_copy(reply + 9, output, output_len);

    return ssh_packet_write_encrypted(sockfd, reply, 9 + output_len);
  }

  if (msg_type == SSH_MSG_CHANNEL_REQUEST) {
    return handle_channel_request(sockfd, pkt);
  }

  if (msg_type == SSH_MSG_CHANNEL_EOF || msg_type == SSH_MSG_CHANNEL_CLOSE) {
    if (pkt->len >= 5) {
      uint32_t local_id = ssh_read_u32_be(pkt->data + 1);
      ssh_channel_t *ch = find_channel_by_local(local_id);
      if (ch) {
        uint8_t close_msg[5];
        close_msg[0] = SSH_MSG_CHANNEL_CLOSE;
        ssh_write_u32_be(close_msg + 1, ch->remote_id);
        ssh_packet_write_encrypted(sockfd, close_msg, 5);
        ch->active = 0;
      }
    }
    return 0;
  }

  if (msg_type == SSH_MSG_CHANNEL_WINDOW_ADJUST) {
    if (pkt->len >= 9) {
      uint32_t local_id = ssh_read_u32_be(pkt->data + 1);
      uint32_t bytes_to_add = ssh_read_u32_be(pkt->data + 5);
      ssh_channel_t *ch = find_channel_by_local(local_id);
      if (ch) {
        ch->remote_window += bytes_to_add;
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
