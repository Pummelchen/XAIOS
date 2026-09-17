/* The SSH client's SFTP client, split out of `ssh_client.c`.
 *
 * The eleven `sftp_*` functions are unchanged, and all of them are
 * unconditional: every `#if defined(XAIOS_SSH_CLIENT_APP)` region in
 * `ssh_client.c` sits above this block. `read_u64_be` came along because
 * `sftp_parse_attributes` is its only caller. `write_u64_be` stayed, because
 * the scp half uses it.
 */

#include "ssh_sftp.h"

#include "ssh_protocol.h"
#include "ssh_utils.h"
#include <xaios_user.h>

static uint64_t read_u64_be(const uint8_t *buffer) {
  return ((uint64_t)ssh_read_u32_be(buffer) << 32U) |
         ssh_read_u32_be(buffer + 4U);
}

int sftp_send_message(ssh_client_context_t *client,
                             const uint8_t *payload, uint32_t payload_length) {
  if (payload_length > SSH_CLIENT_SFTP_BUFFER - 4U) return -1;
  uint8_t *framed = client->frame_workspace;
  ssh_write_u32_be(framed, payload_length);
  ssh_mem_copy(framed + 4U, payload, payload_length);
  return send_channel_data(client, framed, payload_length + 4U);
}

int sftp_receive_message(ssh_client_context_t *client, uint8_t *output,
                                uint32_t capacity, uint32_t *out_length,
                                uint64_t deadline) {
  for (;;) {
    if (client->sftp_used >= 4U) {
      uint32_t length = ssh_read_u32_be(client->sftp_buffer);
      if (length == 0U || length > SSH_CLIENT_SFTP_BUFFER - 4U ||
          length > capacity) return -1;
      if (client->sftp_used >= length + 4U) {
        ssh_mem_copy(output, client->sftp_buffer + 4U, length);
        uint32_t remaining = client->sftp_used - length - 4U;
        for (uint32_t i = 0U; i < remaining; ++i)
          client->sftp_buffer[i] = client->sftp_buffer[length + 4U + i];
        client->sftp_used = remaining;
        *out_length = length;
        return 0;
      }
    }
    ssh_packet_t *packet = &client->packet_workspace;
    if (wait_encrypted_packet(client, packet, deadline) != 0 ||
        packet->len == 0U) return -41;
    if (packet->data[0] == SSH_MSG_CHANNEL_WINDOW_ADJUST && packet->len >= 9U) {
      uint32_t added = ssh_read_u32_be(packet->data + 5U);
      if (UINT32_MAX - client->remote_window < added) return -1;
      client->remote_window += added;
      continue;
    }
    if (packet->data[0] == SSH_MSG_CHANNEL_DATA && packet->len >= 9U) {
      if (ssh_read_u32_be(packet->data + 1U) != client->local_channel)
        return -1;
      uint32_t length = ssh_read_u32_be(packet->data + 5U);
      if (length > packet->len - 9U ||
          length > SSH_CLIENT_SFTP_BUFFER - client->sftp_used) return -1;
      ssh_mem_copy(client->sftp_buffer + client->sftp_used,
                   packet->data + 9U, length);
      client->sftp_used += length;
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
      continue;
    }
    if (packet->data[0] == SSH_MSG_CHANNEL_CLOSE ||
        packet->data[0] == SSH_MSG_DISCONNECT) return -42;
    if (packet->data[0] == SSH_MSG_CHANNEL_EXTENDED_DATA) return -43;
  }
}

int sftp_expect_status(const uint8_t *message, uint32_t length,
                              uint32_t request_id, uint32_t expected_code) {
  return length >= 9U && message[0] == 101U &&
         ssh_read_u32_be(message + 1U) == request_id &&
         ssh_read_u32_be(message + 5U) == expected_code ? 0 : -1;
}

int sftp_open_remote(ssh_client_context_t *client, const char *path,
                            uint32_t flags, uint8_t *handle,
                            uint32_t *handle_length, uint64_t deadline) {
  uint8_t request[512];
  uint32_t position = 0U;
  uint32_t request_id = ++client->sftp_request_id;
  request[position++] = 3U;
  ssh_write_u32_be(request + position, request_id);
  position += 4U;
  position = append_string(request, position, sizeof(request),
                           (const uint8_t *)path, ssh_str_len(path));
  if (position == UINT32_MAX || position + 8U > sizeof(request)) return -1;
  ssh_write_u32_be(request + position, flags);
  position += 4U;
  ssh_write_u32_be(request + position, 0U);
  position += 4U;
  if (sftp_send_message(client, request, position) != 0) return -1;
  uint32_t response_length = 0U;
  if (sftp_receive_message(client, request, sizeof(request), &response_length,
                           deadline) != 0 || response_length < 9U ||
      request[0] != 102U || ssh_read_u32_be(request + 1U) != request_id) {
    return -1;
  }
  uint32_t length = ssh_read_u32_be(request + 5U);
  if (length == 0U || length > 64U || length > response_length - 9U)
    return -1;
  ssh_mem_copy(handle, request + 9U, length);
  *handle_length = length;
  return 0;
}

int sftp_close_remote(ssh_client_context_t *client,
                             const uint8_t *handle, uint32_t handle_length,
                             uint64_t deadline) {
  uint8_t request[128];
  uint32_t request_id = ++client->sftp_request_id;
  request[0] = 4U;
  ssh_write_u32_be(request + 1U, request_id);
  uint32_t position = append_string(request, 5U, sizeof(request), handle,
                                    handle_length);
  if (position == UINT32_MAX || sftp_send_message(client, request, position) != 0)
    return -1;
  uint32_t response_length = 0U;
  if (sftp_receive_message(client, request, sizeof(request), &response_length,
                           deadline) != 0) return -1;
  return sftp_expect_status(request, response_length, request_id, 0U);
}

int sftp_initialize(ssh_client_context_t *client, uint64_t deadline) {
  /* OpenSSH advertises a sizeable extension list in its VERSION reply. */
  uint8_t message[2048];
  message[0] = 1U;
  ssh_write_u32_be(message + 1U, 3U);
  if (sftp_send_message(client, message, 5U) != 0) return -11;
  uint32_t length = 0U;
  int receive = sftp_receive_message(client, message, sizeof(message), &length,
                                     deadline);
  if (receive != 0) return receive;
  if (length < 5U || message[0] != 2U ||
      ssh_read_u32_be(message + 1U) < 3U) return -12;
  return 0;
}

int sftp_parse_attributes(const uint8_t *message, uint32_t length,
                                 uint32_t *position,
                                 sftp_file_info_t *info) {
  if (*position > length || length - *position < 4U) return -1;
  uint32_t flags = ssh_read_u32_be(message + *position);
  *position += 4U;
  info->type = XAIOS_FS_TYPE_FILE;
  info->size = 0U;
  if ((flags & 1U) != 0U) {
    if (length - *position < 8U) return -1;
    info->size = read_u64_be(message + *position);
    *position += 8U;
  }
  if ((flags & 2U) != 0U) {
    if (length - *position < 8U) return -1;
    *position += 8U;
  }
  if ((flags & 4U) != 0U) {
    if (length - *position < 4U) return -1;
    uint32_t permissions = ssh_read_u32_be(message + *position);
    *position += 4U;
    uint32_t file_type = permissions & UINT32_C(0170000);
    if (file_type == UINT32_C(0040000)) info->type = XAIOS_FS_TYPE_DIRECTORY;
    else if (file_type != 0U && file_type != UINT32_C(0100000)) return -2;
  }
  if ((flags & 8U) != 0U) {
    if (length - *position < 8U) return -1;
    *position += 8U;
  }
  if ((flags & UINT32_C(0x80000000)) != 0U) {
    if (length - *position < 4U) return -1;
    uint32_t count = ssh_read_u32_be(message + *position);
    *position += 4U;
    for (uint32_t i = 0U; i < count; ++i) {
      for (uint32_t field = 0U; field < 2U; ++field) {
        if (length - *position < 4U) return -1;
        uint32_t field_length = ssh_read_u32_be(message + *position);
        *position += 4U;
        if (field_length > length - *position) return -1;
        *position += field_length;
      }
    }
  }
  return 0;
}

int sftp_stat_remote(ssh_client_context_t *client, const char *path,
                            sftp_file_info_t *info) {
  uint8_t message[512];
  uint32_t request_id = ++client->sftp_request_id;
  message[0] = 7U;
  ssh_write_u32_be(message + 1U, request_id);
  uint32_t length = append_string(message, 5U, sizeof(message),
                                  (const uint8_t *)path, ssh_str_len(path));
  if (length == UINT32_MAX || sftp_send_message(client, message, length) != 0)
    return -1;
  if (sftp_receive_message(client, message, sizeof(message), &length,
                           client_deadline()) != 0 || length < 5U ||
      ssh_read_u32_be(message + 1U) != request_id) return -1;
  if (message[0] == 101U) return 1;
  if (message[0] != 105U) return -1;
  uint32_t position = 5U;
  return sftp_parse_attributes(message, length, &position, info);
}

int sftp_make_directory(ssh_client_context_t *client,
                               const char *path) {
  uint8_t message[512];
  uint32_t request_id = ++client->sftp_request_id;
  message[0] = 14U;
  ssh_write_u32_be(message + 1U, request_id);
  uint32_t position = append_string(message, 5U, sizeof(message),
                                    (const uint8_t *)path, ssh_str_len(path));
  if (position == UINT32_MAX || sizeof(message) - position < 8U) return -1;
  ssh_write_u32_be(message + position, 4U);
  ssh_write_u32_be(message + position + 4U, UINT32_C(0040755));
  position += 8U;
  if (sftp_send_message(client, message, position) != 0) return -1;
  uint32_t length = 0U;
  if (sftp_receive_message(client, message, sizeof(message), &length,
                           client_deadline()) != 0 || length < 9U ||
      message[0] != 101U || ssh_read_u32_be(message + 1U) != request_id)
    return -1;
  if (ssh_read_u32_be(message + 5U) == 0U) return 0;
  sftp_file_info_t info;
  return sftp_stat_remote(client, path, &info) == 0 &&
                 info.type == XAIOS_FS_TYPE_DIRECTORY
             ? 0
             : -1;
}

int sftp_open_directory(ssh_client_context_t *client, const char *path,
                               uint8_t *handle, uint32_t *handle_length) {
  uint8_t message[512];
  uint32_t request_id = ++client->sftp_request_id;
  message[0] = 11U;
  ssh_write_u32_be(message + 1U, request_id);
  uint32_t length = append_string(message, 5U, sizeof(message),
                                  (const uint8_t *)path, ssh_str_len(path));
  if (length == UINT32_MAX || sftp_send_message(client, message, length) != 0)
    return -1;
  if (sftp_receive_message(client, message, sizeof(message), &length,
                           client_deadline()) != 0 || length < 9U ||
      message[0] != 102U || ssh_read_u32_be(message + 1U) != request_id)
    return -1;
  uint32_t value_length = ssh_read_u32_be(message + 5U);
  if (value_length == 0U || value_length > 64U || value_length > length - 9U)
    return -1;
  ssh_mem_copy(handle, message + 9U, value_length);
  *handle_length = value_length;
  return 0;
}

int sftp_read_directory(ssh_client_context_t *client,
                               const uint8_t *handle, uint32_t handle_length,
                               uint8_t *message, uint32_t capacity,
                               uint32_t *length) {
  uint32_t request_id = ++client->sftp_request_id;
  message[0] = 12U;
  ssh_write_u32_be(message + 1U, request_id);
  uint32_t request_length = append_string(message, 5U, capacity, handle,
                                          handle_length);
  if (request_length == UINT32_MAX ||
      sftp_send_message(client, message, request_length) != 0) return -1;
  if (sftp_receive_message(client, message, capacity, length,
                           client_deadline()) != 0 || *length < 5U ||
      ssh_read_u32_be(message + 1U) != request_id) return -1;
  if (message[0] == 101U) {
    return *length >= 9U && ssh_read_u32_be(message + 5U) == 1U ? 1 : -1;
  }
  return message[0] == 104U && *length >= 9U ? 0 : -1;
}
