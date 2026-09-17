#include "ssh_protocol.h"
#include "ssh_channel.h"
#include "ssh_utils.h"
#include "sftp_server.h"
#include <xaios_user.h>
#include "sftp_server_internal.h"

/* Global State */
static sftp_file_handle_t g_sftp_handles[SFTP_MAX_HANDLES];
static uint32_t g_next_handle_id = 1;
static uint32_t g_response_channel_id;
static uint8_t g_sftp_wire_buf[SSH_MAX_PACKET_SIZE];

int sftp_send_packet(int sockfd, const uint8_t *payload,
                            uint32_t payload_len) {
  if (payload == 0 || payload_len > sizeof(g_sftp_wire_buf) - 4U) {
    return -1;
  }
  uint32_t channel_data_len = payload_len + 4U;
  ssh_write_u32_be(g_sftp_wire_buf, payload_len);
  ssh_mem_copy(g_sftp_wire_buf + 4U, payload, payload_len);
  return ssh_channel_send_data(sockfd, g_response_channel_id,
                               g_sftp_wire_buf, channel_data_len);
}

/* Validate path - prevent directory traversal */
int sftp_validate_path(const char *path) {
  static const char control_prefix[] = "/state/control";
  static const char host_key[] = "/state/xaios_host_key";
  static const char password_users[] = "/etc/xaios_sshd_users";
  static const char authorized_keys[] = "/etc/xaios_authorized_keys";
  static const char client_identity[] = "/etc/xaios_ssh_client_identity";
  if (path == 0 || path[0] != '/') return -1;

  if (ssh_str_eq(path, host_key) || ssh_str_eq(path, password_users) ||
      ssh_str_eq(path, authorized_keys) || ssh_str_eq(path, client_identity)) {
    return -1;
  }
  uint32_t control_length = sizeof(control_prefix) - 1U;
  uint32_t path_length = ssh_str_len(path);
  if (path_length >= control_length) {
    uint32_t matches = 1U;
    for (uint32_t i = 0U; i < control_length; ++i) {
      if (path[i] != control_prefix[i]) {
        matches = 0U;
        break;
      }
    }
    if (matches != 0U &&
        (path[control_length] == '\0' || path[control_length] == '/')) {
      return -1;
    }
  }

  /* Require canonical absolute components before applying mount policies. */
  if (path[1] == '\0') return 0;
  uint32_t component_start = 1U;
  for (uint32_t index = 1U;; ++index) {
    if (path[index] != '/' && path[index] != '\0') continue;
    uint32_t length = index - component_start;
    if (length == 0U ||
        (length == 1U && path[component_start] == '.') ||
        (length == 2U && path[component_start] == '.' &&
         path[component_start + 1U] == '.')) {
      return -1;
    }
    if (path[index] == '\0') break;
    component_start = index + 1U;
  }
  
  return 0;
}

/* Allocate new handle */
sftp_file_handle_t *sftp_alloc_handle(int sockfd) {
  for (uint32_t i = 0; i < SFTP_MAX_HANDLES; ++i) {
    if (!g_sftp_handles[i].is_open) {
      g_sftp_handles[i].is_open = 1;
      g_sftp_handles[i].handle_id = g_next_handle_id++;
      g_sftp_handles[i].offset = 0;
      g_sftp_handles[i].fd = -1;
      g_sftp_handles[i].is_dir = 0;
      g_sftp_handles[i].owner_sockfd = (uint64_t)(uint32_t)sockfd;
      g_sftp_handles[i].owner_channel_id = g_response_channel_id;
      return &g_sftp_handles[i];
    }
  }
  return 0;
}

/* Find handle by ID */
sftp_file_handle_t *sftp_find_handle(int sockfd, uint32_t handle_id) {
  for (uint32_t i = 0; i < SFTP_MAX_HANDLES; ++i) {
    if (g_sftp_handles[i].is_open &&
        g_sftp_handles[i].owner_sockfd == (uint64_t)(uint32_t)sockfd &&
        g_sftp_handles[i].owner_channel_id == g_response_channel_id &&
        g_sftp_handles[i].handle_id == handle_id) {
      return &g_sftp_handles[i];
    }
  }
  return 0;
}

void sftp_close_channel(int sockfd, uint32_t remote_channel_id) {
  for (uint32_t i = 0; i < SFTP_MAX_HANDLES; ++i) {
    sftp_file_handle_t *handle = &g_sftp_handles[i];
    if (handle->is_open &&
        handle->owner_sockfd == (uint64_t)(uint32_t)sockfd &&
        handle->owner_channel_id == remote_channel_id) {
      if (handle->fd >= 0) {
        (void)xaios_fs_close(handle->fd);
      }
      ssh_mem_zero(handle, sizeof(*handle));
    }
  }
}

/* ---- Packet Parsing ---- */
uint32_t sftp_read_u32(const uint8_t *p) {
  return ssh_read_u32_be(p);
}

void sftp_write_u32(uint8_t *p, uint32_t v) {
  ssh_write_u32_be(p, v);
}

void sftp_write_u64(uint8_t *p, uint64_t v) {
  sftp_write_u32(p, (uint32_t)(v >> 32));
  sftp_write_u32(p + 4, (uint32_t)v);
}

int sftp_read_string_at(const uint8_t *data, uint32_t len, uint32_t offset,
                          const uint8_t **out, uint32_t *out_len,
                          uint32_t *next_offset) {
  if (data == 0 || out == 0 || out_len == 0 || next_offset == 0 ||
      offset > len || len - offset < 4U) {
    return -1;
  }
  uint32_t string_len = sftp_read_u32(data + offset);
  if (string_len > len - offset - 4U) return -1;
  *out = data + offset + 4U;
  *out_len = string_len;
  *next_offset = offset + 4U + string_len;
  return 0;
}

/* ---- Response Builders ---- */
int sftp_send_status(int sockfd, uint32_t request_id, uint32_t status_code,
                       const char *message) {
  uint8_t buf[256];
  uint32_t pos = 0;
  
  buf[pos++] = SSH_FXP_STATUS;
  sftp_write_u32(buf + pos, request_id); pos += 4;
  sftp_write_u32(buf + pos, status_code); pos += 4;
  
  /* Error message */
  uint32_t msg_len = message ? ssh_str_len(message) : 0;
  sftp_write_u32(buf + pos, msg_len); pos += 4;
  if (msg_len > 0) {
    ssh_mem_copy(buf + pos, message, msg_len);
    pos += msg_len;
  }
  
  /* Language tag (empty) */
  sftp_write_u32(buf + pos, 0); pos += 4;
  
  return sftp_send_packet(sockfd, buf, pos);
}

int sftp_send_handle(int sockfd, uint32_t request_id, uint32_t handle_id) {
  uint8_t buf[64];
  uint32_t pos = 0;
  
  buf[pos++] = SSH_FXP_HANDLE;
  sftp_write_u32(buf + pos, request_id); pos += 4;
  
  /* Handle as string */
  sftp_write_u32(buf + pos, 4); pos += 4;
  sftp_write_u32(buf + pos, handle_id); pos += 4;
  
  return sftp_send_packet(sockfd, buf, pos);
}

/* Static buffer to avoid 32KB stack allocations (Fix 5c) */
static uint8_t g_sftp_send_buf[SFTP_MAX_PACKET_SIZE];

int sftp_send_data(int sockfd, uint32_t request_id, const uint8_t *data,
                     uint32_t data_len) {
  if (data_len + 9 > SFTP_MAX_PACKET_SIZE) return -1;
  uint8_t *buf = g_sftp_send_buf;
  uint32_t pos = 0;
  
  buf[pos++] = SSH_FXP_DATA;
  sftp_write_u32(buf + pos, request_id); pos += 4;
  sftp_write_u32(buf + pos, data_len); pos += 4;
  ssh_mem_copy(buf + pos, data, data_len); pos += data_len;
  
  return sftp_send_packet(sockfd, buf, pos);
}

/* ---- Main SFTP Message Handler ---- */
int sftp_handle_message(int sockfd, uint32_t remote_channel_id,
                        const uint8_t *data, uint32_t len) {
  if (len == 0) return -1;
  g_response_channel_id = remote_channel_id;
  
  uint8_t msg_type = data[0];
  
  switch (msg_type) {
    case SSH_FXP_INIT:
      /* Client sends version, we reply with our version */
      {
        static const char extension[] = "fsync@openssh.com";
        uint8_t buf[64];
        uint32_t pos = 0U;
        buf[pos++] = SSH_FXP_VERSION;
        sftp_write_u32(buf + pos, SFTP_VERSION); pos += 4U;
        sftp_write_u32(buf + pos, sizeof(extension) - 1U); pos += 4U;
        ssh_mem_copy(buf + pos, extension, sizeof(extension) - 1U);
        pos += sizeof(extension) - 1U;
        sftp_write_u32(buf + pos, 1U); pos += 4U;
        buf[pos++] = '1';
        return sftp_send_packet(sockfd, buf, pos);
      }
    
    case SSH_FXP_OPEN:
      return sftp_handle_open(sockfd, data + 1, len - 1);
    
    case SSH_FXP_CLOSE:
      return sftp_handle_close(sockfd, data + 1, len - 1);
    
    case SSH_FXP_READ:
      return sftp_handle_read(sockfd, data + 1, len - 1);
    
    case SSH_FXP_WRITE:
      return sftp_handle_write(sockfd, data + 1, len - 1);
    
    case SSH_FXP_OPENDIR:
      return sftp_handle_opendir(sockfd, data + 1, len - 1);
    
    case SSH_FXP_READDIR:
      return sftp_handle_readdir(sockfd, data + 1, len - 1);
    
    case SSH_FXP_REMOVE:
      return sftp_handle_remove(sockfd, data + 1, len - 1);

    case SSH_FXP_RMDIR:
      return sftp_handle_remove(sockfd, data + 1, len - 1);
    
    case SSH_FXP_MKDIR:
      return sftp_handle_mkdir(sockfd, data + 1, len - 1);
    
    case SSH_FXP_RENAME:
      return sftp_handle_rename(sockfd, data + 1, len - 1);
    
    case SSH_FXP_STAT:
    case SSH_FXP_LSTAT:
      return sftp_handle_stat(sockfd, data + 1, len - 1);

    case SSH_FXP_FSTAT:
      return sftp_handle_fstat(sockfd, data + 1, len - 1);

    case SSH_FXP_FSETSTAT:
      return sftp_handle_fsetstat(sockfd, data + 1, len - 1);

    case SSH_FXP_REALPATH:
      return sftp_handle_realpath(sockfd, data + 1, len - 1);

    case SSH_FXP_EXTENDED:
      return sftp_handle_extended(sockfd, data + 1, len - 1);
    
    default:
      /* Unsupported operation */
      return sftp_send_status(sockfd, len >= 5U ? sftp_read_u32(data + 1U) : 0U,
                         SSH_FX_OP_UNSUPPORTED,
                         "Operation not supported");
  }
}
