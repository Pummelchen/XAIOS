#include "ssh_protocol.h"
#include "ssh_channel.h"
#include "ssh_utils.h"
#include "sftp_server.h"
#include <xaios_user.h>

/* SFTP Protocol Constants */
#define SFTP_VERSION 3
#define SFTP_MAX_PACKET_SIZE SSH_CHANNEL_SFTP_REQUEST_MAX
#define SFTP_MAX_HANDLES 64

/* SFTP Message Types */
#define SSH_FXP_INIT        1
#define SSH_FXP_VERSION     2
#define SSH_FXP_OPEN        3
#define SSH_FXP_CLOSE       4
#define SSH_FXP_READ        5
#define SSH_FXP_WRITE       6
#define SSH_FXP_LSTAT       7
#define SSH_FXP_FSTAT       8
#define SSH_FXP_SETSTAT     9
#define SSH_FXP_FSETSTAT   10
#define SSH_FXP_OPENDIR    11
#define SSH_FXP_READDIR    12
#define SSH_FXP_REMOVE     13
#define SSH_FXP_MKDIR      14
#define SSH_FXP_RMDIR      15
#define SSH_FXP_REALPATH   16
#define SSH_FXP_STAT       17
#define SSH_FXP_RENAME     18
#define SSH_FXP_READLINK   19
#define SSH_FXP_SYMLINK    20
#define SSH_FXP_EXTENDED  200

/* SFTP Response Types */
#define SSH_FXP_STATUS      101
#define SSH_FXP_HANDLE      102
#define SSH_FXP_DATA        103
#define SSH_FXP_NAME        104
#define SSH_FXP_ATTRS       105

/* SFTP Status Codes */
#define SSH_FX_OK                0
#define SSH_FX_EOF               1
#define SSH_FX_NO_SUCH_FILE      2
#define SSH_FX_PERMISSION_DENIED 3
#define SSH_FX_FAILURE           4
#define SSH_FX_BAD_MESSAGE       5
#define SSH_FX_NO_CONNECTION     6
#define SSH_FX_CONNECTION_LOST   7
#define SSH_FX_OP_UNSUPPORTED    8

/* SFTP Open Flags */
#define SSH_FXF_READ    0x00000001
#define SSH_FXF_WRITE   0x00000002
#define SSH_FXF_APPEND  0x00000004
#define SSH_FXF_CREAT   0x00000008
#define SSH_FXF_TRUNC   0x00000010
#define SSH_FXF_EXCL    0x00000020

#define SSH_FILEXFER_ATTR_SIZE        0x00000001
#define SSH_FILEXFER_ATTR_UIDGID      0x00000002
#define SSH_FILEXFER_ATTR_PERMISSIONS 0x00000004
#define SSH_FILEXFER_ATTR_ACMODTIME    0x00000008
#define SSH_FILEXFER_ATTR_EXTENDED    0x80000000

/* Global State */
static sftp_file_handle_t g_sftp_handles[SFTP_MAX_HANDLES];
static uint32_t g_next_handle_id = 1;
static uint32_t g_response_channel_id;
static uint8_t g_sftp_wire_buf[SSH_MAX_PACKET_SIZE];

static int send_sftp_packet(int sockfd, const uint8_t *payload,
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
static int validate_path(const char *path) {
  static const char control_prefix[] = "/state/control";
  static const char host_key[] = "/state/xaios_host_key";
  static const char password_users[] = "/etc/xaios_sshd_users";
  static const char authorized_keys[] = "/etc/xaios_authorized_keys";
  if (path == 0 || path[0] != '/') return -1;

  if (ssh_str_eq(path, host_key) || ssh_str_eq(path, password_users) ||
      ssh_str_eq(path, authorized_keys)) {
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
static sftp_file_handle_t *alloc_handle(int sockfd) {
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
static sftp_file_handle_t *find_handle(int sockfd, uint32_t handle_id) {
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
static uint32_t read_u32(const uint8_t *p) {
  return ssh_read_u32_be(p);
}

static void write_u32(uint8_t *p, uint32_t v) {
  ssh_write_u32_be(p, v);
}

static void write_u64(uint8_t *p, uint64_t v) {
  write_u32(p, (uint32_t)(v >> 32));
  write_u32(p + 4, (uint32_t)v);
}

static int read_string_at(const uint8_t *data, uint32_t len, uint32_t offset,
                          const uint8_t **out, uint32_t *out_len,
                          uint32_t *next_offset) {
  if (data == 0 || out == 0 || out_len == 0 || next_offset == 0 ||
      offset > len || len - offset < 4U) {
    return -1;
  }
  uint32_t string_len = read_u32(data + offset);
  if (string_len > len - offset - 4U) return -1;
  *out = data + offset + 4U;
  *out_len = string_len;
  *next_offset = offset + 4U + string_len;
  return 0;
}

/* ---- Response Builders ---- */
static int send_status(int sockfd, uint32_t request_id, uint32_t status_code,
                       const char *message) {
  uint8_t buf[256];
  uint32_t pos = 0;
  
  buf[pos++] = SSH_FXP_STATUS;
  write_u32(buf + pos, request_id); pos += 4;
  write_u32(buf + pos, status_code); pos += 4;
  
  /* Error message */
  uint32_t msg_len = message ? ssh_str_len(message) : 0;
  write_u32(buf + pos, msg_len); pos += 4;
  if (msg_len > 0) {
    ssh_mem_copy(buf + pos, message, msg_len);
    pos += msg_len;
  }
  
  /* Language tag (empty) */
  write_u32(buf + pos, 0); pos += 4;
  
  return send_sftp_packet(sockfd, buf, pos);
}

static int send_handle(int sockfd, uint32_t request_id, uint32_t handle_id) {
  uint8_t buf[64];
  uint32_t pos = 0;
  
  buf[pos++] = SSH_FXP_HANDLE;
  write_u32(buf + pos, request_id); pos += 4;
  
  /* Handle as string */
  write_u32(buf + pos, 4); pos += 4;
  write_u32(buf + pos, handle_id); pos += 4;
  
  return send_sftp_packet(sockfd, buf, pos);
}

/* Static buffers to avoid 32KB stack allocations (Fix 5c) */
static uint8_t g_sftp_send_buf[SFTP_MAX_PACKET_SIZE];
static uint8_t g_sftp_read_buf[SFTP_MAX_PACKET_SIZE];

static int validate_open_attributes(const uint8_t *data, uint32_t length,
                                    uint32_t offset) {
  if (offset > length || length - offset < 4U) return -1;
  uint32_t flags = read_u32(data + offset);
  if ((flags & (SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_UIDGID |
                SSH_FILEXFER_ATTR_EXTENDED)) != 0U ||
      (flags & ~(SSH_FILEXFER_ATTR_SIZE | SSH_FILEXFER_ATTR_UIDGID |
                 SSH_FILEXFER_ATTR_PERMISSIONS |
                 SSH_FILEXFER_ATTR_ACMODTIME |
                 SSH_FILEXFER_ATTR_EXTENDED)) != 0U) {
    return 1;
  }
  uint32_t required = 4U;
  if ((flags & SSH_FILEXFER_ATTR_PERMISSIONS) != 0U) required += 4U;
  if ((flags & SSH_FILEXFER_ATTR_ACMODTIME) != 0U) required += 8U;
  return length - offset == required ? 0 : -1;
}

static int send_data(int sockfd, uint32_t request_id, const uint8_t *data,
                     uint32_t data_len) {
  if (data_len + 9 > SFTP_MAX_PACKET_SIZE) return -1;
  uint8_t *buf = g_sftp_send_buf;
  uint32_t pos = 0;
  
  buf[pos++] = SSH_FXP_DATA;
  write_u32(buf + pos, request_id); pos += 4;
  write_u32(buf + pos, data_len); pos += 4;
  ssh_mem_copy(buf + pos, data, data_len); pos += data_len;
  
  return send_sftp_packet(sockfd, buf, pos);
}

/* ---- SFTP Request Handlers ---- */
static int handle_open(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid OPEN");
  
  uint32_t request_id = read_u32(data);
  uint32_t path_len;
  const uint8_t *path_data;
  uint32_t next_offset;
  if (read_string_at(data, len, 4U, &path_data, &path_len, &next_offset) != 0 ||
      len - next_offset < 8U) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid OPEN");
  }
  
  if (path_len >= XAIOS_MFS_PATH_MAX) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "Path too long");
  }
  
  /* Validate path */
  char local_path[XAIOS_MFS_PATH_MAX];
  ssh_mem_copy(local_path, path_data, path_len);
  local_path[path_len] = '\0';
  
  if (ssh_str_len(local_path) != path_len || validate_path(local_path) != 0) {
    return send_status(sockfd, request_id, SSH_FX_PERMISSION_DENIED, "Invalid path");
  }
  
  /* Parse flags */
  uint32_t flags = read_u32(data + next_offset);
  int attribute_status =
      validate_open_attributes(data, len, next_offset + 4U);
  if ((flags & ~(SSH_FXF_READ | SSH_FXF_WRITE | SSH_FXF_APPEND |
                 SSH_FXF_CREAT | SSH_FXF_TRUNC)) != 0U ||
      attribute_status > 0) {
    return send_status(sockfd, request_id, SSH_FX_OP_UNSUPPORTED,
                       "Unsupported open flags");
  }
  if (attribute_status < 0) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE,
                       "Invalid open attributes");
  }
  if ((flags & (SSH_FXF_READ | SSH_FXF_WRITE)) == 0U ||
      ((flags & (SSH_FXF_CREAT | SSH_FXF_TRUNC)) != 0U &&
       (flags & SSH_FXF_WRITE) == 0U) ||
      ((flags & SSH_FXF_APPEND) != 0U &&
       (flags & SSH_FXF_WRITE) == 0U)) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE,
                       "Invalid open flags");
  }
  int fs_flags = 0;
  if ((flags & SSH_FXF_READ) != 0)  fs_flags |= XAIOS_MFS_OPEN_READ;
  if ((flags & SSH_FXF_WRITE) != 0) fs_flags |= XAIOS_MFS_OPEN_WRITE;
  if ((flags & SSH_FXF_CREAT) != 0) fs_flags |= XAIOS_MFS_OPEN_CREATE;
  if ((flags & SSH_FXF_TRUNC) != 0) fs_flags |= XAIOS_MFS_OPEN_TRUNCATE;
  if (fs_flags == 0) fs_flags = XAIOS_MFS_OPEN_READ;
  
  /* Allocate handle */
  sftp_file_handle_t *handle = alloc_handle(sockfd);
  if (handle == 0) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "No handles available");
  }

  ssh_mem_copy(handle->path, local_path, path_len + 1);
  handle->open_flags = fs_flags;
  handle->is_append = (flags & SSH_FXF_APPEND) != 0U;

  /* Actually open the file now */
  handle->fd = xaios_fs_open(handle->path, fs_flags);
  if (handle->fd < 0) {
    handle->is_open = 0;
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "Open failed");
  }
  if (handle->is_append != 0) {
    xaios_mfs_stat_user_t file_stat;
    if (xaios_fs_stat(handle->path, &file_stat) != 0 ||
        file_stat.type != XAIOS_FS_TYPE_FILE) {
      (void)xaios_fs_close(handle->fd);
      ssh_mem_zero(handle, sizeof(*handle));
      return send_status(sockfd, request_id, SSH_FX_FAILURE,
                         "Append stat failed");
    }
    handle->offset = file_stat.size;
  }

  return send_handle(sockfd, request_id, handle->handle_id);
}

static int handle_close(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid CLOSE");
  
  uint32_t request_id = read_u32(data);
  uint32_t handle_len;
  const uint8_t *handle_data;
  uint32_t next_offset;
  if (read_string_at(data, len, 4U, &handle_data, &handle_len, &next_offset) != 0) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid CLOSE");
  }
  
  if (handle_len != 4) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle");
  }
  
  uint32_t handle_id = read_u32((const uint8_t *)handle_data);
  sftp_file_handle_t *handle = find_handle(sockfd, handle_id);
  
  if (handle == 0) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle ID");
  }
  
  /* Close handle */
  int close_failed = 0;
  if (handle->fd >= 0) {
    /* The VFS backend owns durable-close semantics. ModelFS commits pending
     * chunks from close(), while MutableFS persists each mutation eagerly. */
    if (xaios_fs_close(handle->fd) != 0) close_failed = 1;
    handle->fd = -1;
  }
  handle->is_open = 0;
  ssh_mem_zero(handle, sizeof(sftp_file_handle_t));
  
  return send_status(sockfd, request_id,
                     close_failed ? SSH_FX_FAILURE : SSH_FX_OK,
                     close_failed ? "Durable close failed" : "Success");
}

static int handle_read(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid READ");
  
  uint32_t request_id = read_u32(data);
  uint32_t handle_len;
  const uint8_t *handle_data;
  uint32_t next_offset;
  if (read_string_at(data, len, 4U, &handle_data, &handle_len, &next_offset) != 0 ||
      len - next_offset != 12U) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid READ");
  }
  
  if (handle_len != 4) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle");
  }
  
  uint32_t handle_id = read_u32((const uint8_t *)handle_data);
  uint64_t offset = ((uint64_t)read_u32(data + next_offset) << 32) |
                    read_u32(data + next_offset + 4U);
  uint32_t read_len = read_u32(data + next_offset + 8U);
  
  sftp_file_handle_t *handle = find_handle(sockfd, handle_id);
  if (handle == 0 || handle->is_dir != 0) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle ID");
  }
  
  /* Read file data via userspace FS API */
  uint8_t *file_data = g_sftp_read_buf;
  uint32_t response_limit = SSH_CHANNEL_PENDING_SIZE - 13U;
  uint32_t clamped_len = read_len < response_limit ? read_len : response_limit;

  int fd = handle->fd;
  if (fd < 0) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "Handle not open");
  }

  s64 bytes_read = xaios_fs_pread(fd, file_data, clamped_len, offset);
  
  if (bytes_read < 0) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "Read failed");
  }
  if (bytes_read == 0) {
    return send_status(sockfd, request_id, SSH_FX_EOF, "End of file");
  }
  
  return send_data(sockfd, request_id, file_data, (uint32_t)bytes_read);
}

static int handle_write(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid WRITE");
  
  uint32_t request_id = read_u32(data);
  uint32_t handle_len;
  const uint8_t *handle_data;
  uint32_t next_offset;
  if (read_string_at(data, len, 4U, &handle_data, &handle_len, &next_offset) != 0 ||
      len - next_offset < 12U) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid WRITE");
  }
  
  if (handle_len != 4) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle");
  }
  
  uint32_t handle_id = read_u32((const uint8_t *)handle_data);
  uint64_t offset = ((uint64_t)read_u32(data + next_offset) << 32) |
                    read_u32(data + next_offset + 4U);
  uint32_t write_len = read_u32(data + next_offset + 8U);
  next_offset += 12U;
  if (write_len != len - next_offset || offset > UINT64_MAX - write_len) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid WRITE");
  }
  
  sftp_file_handle_t *handle = find_handle(sockfd, handle_id);
  if (handle == 0 || handle->is_dir != 0) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle ID");
  }
  
  /* Write file data via userspace FS API */
  if (handle->is_append != 0) offset = handle->offset;
  const uint8_t *write_data = data + next_offset;
  if (write_len > SFTP_MAX_PACKET_SIZE - 32U) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE,
                       "Write request too large");
  }

  int fd = handle->fd;
  if (fd < 0) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "Handle not open");
  }

  uint32_t completed = 0U;
  while (completed < write_len) {
    s64 written = xaios_fs_pwrite(fd, write_data + completed,
                                  write_len - completed, offset + completed);
    if (written <= 0 || (u64)written > write_len - completed) {
      return send_status(sockfd, request_id, SSH_FX_FAILURE, "Write failed");
    }
    completed += (uint32_t)written;
  }
  if (handle->is_append != 0) handle->offset = offset + completed;
  
  return send_status(sockfd, request_id, SSH_FX_OK, "Success");
}

static int handle_opendir(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid OPENDIR");
  
  uint32_t request_id = read_u32(data);
  uint32_t path_len;
  const uint8_t *path;
  uint32_t next_offset;
  if (read_string_at(data, len, 4U, &path, &path_len, &next_offset) != 0) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid OPENDIR");
  }
  
  if (path_len >= XAIOS_MFS_PATH_MAX) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "Path too long");
  }
  
  char local_path[XAIOS_MFS_PATH_MAX];
  ssh_mem_copy(local_path, path, path_len);
  local_path[path_len] = '\0';
  
  if (ssh_str_len(local_path) != path_len || validate_path(local_path) != 0) {
    return send_status(sockfd, request_id, SSH_FX_PERMISSION_DENIED, "Invalid path");
  }
  
  /* Allocate handle */
  sftp_file_handle_t *handle = alloc_handle(sockfd);
  if (handle == 0) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "No handles available");
  }
  
  ssh_mem_copy(handle->path, local_path, path_len + 1);
  handle->is_dir = 1;
  xaios_mfs_stat_user_t directory_stat;
  if (xaios_fs_stat(local_path, &directory_stat) != 0 ||
      directory_stat.type != XAIOS_FS_TYPE_DIRECTORY) {
    ssh_mem_zero(handle, sizeof(*handle));
    return send_status(sockfd, request_id, SSH_FX_NO_SUCH_FILE,
                       "Directory not found");
  }
  
  return send_handle(sockfd, request_id, handle->handle_id);
}

static int handle_readdir(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid READDIR");
  
  uint32_t request_id = read_u32(data);
  uint32_t handle_len;
  const uint8_t *handle_data;
  uint32_t next_offset;
  if (read_string_at(data, len, 4U, &handle_data, &handle_len, &next_offset) != 0) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid READDIR");
  }
  
  if (handle_len != 4) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle");
  }
  
  uint32_t handle_id = read_u32((const uint8_t *)handle_data);
  sftp_file_handle_t *handle = find_handle(sockfd, handle_id);
  
  if (handle == 0 || handle->is_dir == 0) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle ID");
  }
  
  /* List directory contents via userspace FS API */
  char list_buf[4096];
  u64 list_size = 0;
  int fs_status = xaios_fs_list(handle->path, list_buf,
      sizeof(list_buf), &list_size);
  
  if (fs_status != 0 || list_size == 0 || handle->offset >= list_size) {
    return send_status(sockfd, request_id, SSH_FX_EOF, "End of directory");
  }
  
  /* Build a bounded SSH_FXP_NAME page. The next READDIR resumes at offset. */
  uint8_t resp_buf[4096];
  uint32_t rpos = 0;
  resp_buf[rpos++] = SSH_FXP_NAME;
  write_u32(resp_buf + rpos, request_id); rpos += 4;
  uint32_t count_offset = rpos;
  write_u32(resp_buf + rpos, 0U); rpos += 4;
  uint32_t entry_count = 0;
  uint64_t cursor = handle->offset;
  while (cursor < list_size) {
    uint64_t name_start = cursor;
    while (cursor < list_size && list_buf[cursor] != '\n') ++cursor;
    uint32_t name_len = (uint32_t)(cursor - name_start);
    uint64_t next_cursor = cursor < list_size ? cursor + 1U : cursor;
    if (name_len == 0U) {
      cursor = next_cursor;
      handle->offset = cursor;
      continue;
    }
    uint32_t encoded_len = 12U + (2U * name_len);
    if (encoded_len > sizeof(resp_buf) - rpos) break;
    write_u32(resp_buf + rpos, name_len); rpos += 4U;
    ssh_mem_copy(resp_buf + rpos, list_buf + name_start, name_len);
    rpos += name_len;
    write_u32(resp_buf + rpos, name_len); rpos += 4U;
    ssh_mem_copy(resp_buf + rpos, list_buf + name_start, name_len);
    rpos += name_len;
    write_u32(resp_buf + rpos, 0U); rpos += 4U;
    ++entry_count;
    cursor = next_cursor;
    handle->offset = cursor;
  }
  if (entry_count == 0U) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE,
                       "Directory entry exceeds response limit");
  }
  write_u32(resp_buf + count_offset, entry_count);
  return send_sftp_packet(sockfd, resp_buf, rpos);
}

static int handle_mkdir(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid MKDIR");
  
  uint32_t request_id = read_u32(data);
  uint32_t path_len;
  const uint8_t *path;
  uint32_t next_offset;
  if (read_string_at(data, len, 4U, &path, &path_len, &next_offset) != 0) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid MKDIR");
  }
  
  if (path_len >= XAIOS_MFS_PATH_MAX) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "Path too long");
  }
  
  char local_path[XAIOS_MFS_PATH_MAX];
  ssh_mem_copy(local_path, path, path_len);
  local_path[path_len] = '\0';
  
  if (ssh_str_len(local_path) != path_len || validate_path(local_path) != 0) {
    return send_status(sockfd, request_id, SSH_FX_PERMISSION_DENIED, "Invalid path");
  }
  
  /* Create directory via userspace FS API */
  int fs_status = xaios_fs_mkdir(local_path);
  if (fs_status != 0) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "mkdir failed");
  }
  return send_status(sockfd, request_id, SSH_FX_OK, "Success");
}

static int handle_remove(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid REMOVE");
  
  uint32_t request_id = read_u32(data);
  uint32_t path_len;
  const uint8_t *path;
  uint32_t next_offset;
  if (read_string_at(data, len, 4U, &path, &path_len, &next_offset) != 0) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid REMOVE");
  }
  
  if (path_len >= XAIOS_MFS_PATH_MAX) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "Path too long");
  }
  
  char local_path[XAIOS_MFS_PATH_MAX];
  ssh_mem_copy(local_path, path, path_len);
  local_path[path_len] = '\0';
  
  if (ssh_str_len(local_path) != path_len || validate_path(local_path) != 0) {
    return send_status(sockfd, request_id, SSH_FX_PERMISSION_DENIED, "Invalid path");
  }
  
  /* Remove file via userspace FS API */
  int fs_status = xaios_fs_delete(local_path);
  if (fs_status != 0) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "remove failed");
  }
  return send_status(sockfd, request_id, SSH_FX_OK, "Success");
}

static int handle_rename(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid RENAME");
  
  uint32_t request_id = read_u32(data);
  uint32_t old_len;
  const uint8_t *old_path;
  uint32_t next_offset;
  if (read_string_at(data, len, 4U, &old_path, &old_len, &next_offset) != 0) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid RENAME");
  }
  uint32_t new_len;
  const uint8_t *new_path;
  uint32_t end_offset;
  if (read_string_at(data, len, next_offset, &new_path, &new_len,
                     &end_offset) != 0) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid RENAME");
  }
  
  char old_local[XAIOS_MFS_PATH_MAX];
  char new_local[XAIOS_MFS_PATH_MAX];
  
  if (old_len >= XAIOS_MFS_PATH_MAX || new_len >= XAIOS_MFS_PATH_MAX) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "Path too long");
  }
  
  ssh_mem_copy(old_local, old_path, old_len);
  old_local[old_len] = '\0';
  
  ssh_mem_copy(new_local, new_path, new_len);
  new_local[new_len] = '\0';
  
  if (ssh_str_len(old_local) != old_len ||
      ssh_str_len(new_local) != new_len ||
      validate_path(old_local) != 0 || validate_path(new_local) != 0) {
    return send_status(sockfd, request_id, SSH_FX_PERMISSION_DENIED, "Invalid path");
  }
  
  /* Rename file via userspace FS API */
  int fs_status = xaios_fs_rename(old_local, new_local);
  if (fs_status != 0) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "rename failed");
  }
  return send_status(sockfd, request_id, SSH_FX_OK, "Success");
}

static int handle_stat(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid STAT");
  
  uint32_t request_id = read_u32(data);
  uint32_t path_len;
  const uint8_t *path;
  uint32_t next_offset;
  if (read_string_at(data, len, 4U, &path, &path_len, &next_offset) != 0) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid STAT");
  }
  
  if (path_len >= XAIOS_MFS_PATH_MAX) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "Path too long");
  }
  
  char local_path[XAIOS_MFS_PATH_MAX];
  ssh_mem_copy(local_path, path, path_len);
  local_path[path_len] = '\0';
  
  if (ssh_str_len(local_path) != path_len || validate_path(local_path) != 0) {
    return send_status(sockfd, request_id, SSH_FX_NO_SUCH_FILE, "File not found");
  }
  
  /* Get file stat via userspace FS API */
  xaios_mfs_stat_user_t file_stat;
  int fs_status = xaios_fs_stat(local_path, &file_stat);
  
  uint8_t buf[64];
  uint32_t pos = 0;
  
  if (fs_status != 0) {
    return send_status(sockfd, request_id, SSH_FX_NO_SUCH_FILE, "File not found");
  }
  
  buf[pos++] = SSH_FXP_ATTRS;
  write_u32(buf + pos, request_id); pos += 4;
  
  /* Attributes: flags=SSH_FILEXFER_ATTR_SIZE, size=file_stat.size */
  write_u32(buf + pos, 0x00000001); pos += 4;
  write_u64(buf + pos, file_stat.size); pos += 8;
  
  return send_sftp_packet(sockfd, buf, pos);
}

static int handle_fstat(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid FSTAT");
  uint32_t request_id = read_u32(data);
  const uint8_t *handle_data;
  uint32_t handle_len;
  uint32_t next_offset;
  if (read_string_at(data, len, 4U, &handle_data, &handle_len, &next_offset) != 0 ||
      handle_len != 4U) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle");
  }
  sftp_file_handle_t *handle = find_handle(sockfd, read_u32(handle_data));
  if (handle == 0) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle ID");
  }

  xaios_mfs_stat_user_t file_stat;
  if (xaios_fs_stat(handle->path, &file_stat) != 0) {
    return send_status(sockfd, request_id, SSH_FX_NO_SUCH_FILE, "File not found");
  }
  uint8_t response[17];
  response[0] = SSH_FXP_ATTRS;
  write_u32(response + 1U, request_id);
  write_u32(response + 5U, 0x00000001U);
  write_u64(response + 9U, file_stat.size);
  return send_sftp_packet(sockfd, response, sizeof(response));
}

static int handle_realpath(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 8U) {
    return send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid REALPATH");
  }
  uint32_t request_id = read_u32(data);
  uint32_t path_len = read_u32(data + 4U);
  if (path_len > len - 8U || path_len >= XAIOS_MFS_PATH_MAX) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE,
                       "Invalid path");
  }

  char path[XAIOS_MFS_PATH_MAX];
  if (path_len == 0U || (path_len == 1U && data[8] == '.')) {
    path[0] = '/';
    path[1] = '\0';
    path_len = 1U;
  } else {
    uint32_t prefix = data[8] == '/' ? 0U : 1U;
    if (path_len + prefix >= sizeof(path)) {
      return send_status(sockfd, request_id, SSH_FX_FAILURE,
                         "Path too long");
    }
    if (prefix != 0U) path[0] = '/';
    ssh_mem_copy(path + prefix, data + 8U, path_len);
    path_len += prefix;
    path[path_len] = '\0';
  }
  if (ssh_str_len(path) != path_len || validate_path(path) != 0) {
    return send_status(sockfd, request_id, SSH_FX_PERMISSION_DENIED,
                       "Invalid path");
  }

  uint8_t response[2U * XAIOS_MFS_PATH_MAX + 32U];
  uint32_t pos = 0;
  response[pos++] = SSH_FXP_NAME;
  write_u32(response + pos, request_id); pos += 4U;
  write_u32(response + pos, 1U); pos += 4U;
  write_u32(response + pos, path_len); pos += 4U;
  ssh_mem_copy(response + pos, path, path_len); pos += path_len;
  write_u32(response + pos, path_len); pos += 4U;
  ssh_mem_copy(response + pos, path, path_len); pos += path_len;
  write_u32(response + pos, 0U); pos += 4U;
  return send_sftp_packet(sockfd, response, pos);
}

static int handle_extended(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) {
    return send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid EXTENDED");
  }
  uint32_t request_id = read_u32(data);
  const uint8_t *name;
  uint32_t name_len;
  uint32_t next_offset;
  if (read_string_at(data, len, 4U, &name, &name_len, &next_offset) != 0 ||
      name_len != sizeof("fsync@openssh.com") - 1U ||
      next_offset > len) {
    return send_status(sockfd, request_id, SSH_FX_OP_UNSUPPORTED,
                       "Unsupported extension");
  }
  static const uint8_t fsync_name[] = "fsync@openssh.com";
  for (uint32_t i = 0U; i < name_len; ++i) {
    if (name[i] != fsync_name[i]) {
      return send_status(sockfd, request_id, SSH_FX_OP_UNSUPPORTED,
                         "Unsupported extension");
    }
  }
  const uint8_t *handle_data;
  uint32_t handle_len;
  uint32_t end_offset;
  if (read_string_at(data, len, next_offset, &handle_data, &handle_len,
                     &end_offset) != 0 ||
      handle_len != 4U || end_offset != len) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE,
                       "Invalid fsync request");
  }
  sftp_file_handle_t *handle = find_handle(sockfd, read_u32(handle_data));
  if (handle == 0 || handle->fd < 0) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE,
                       "Invalid handle ID");
  }
  if (xaios_fs_fsync(handle->fd) != 0) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "fsync failed");
  }
  return send_status(sockfd, request_id, SSH_FX_OK, "Success");
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
        write_u32(buf + pos, SFTP_VERSION); pos += 4U;
        write_u32(buf + pos, sizeof(extension) - 1U); pos += 4U;
        ssh_mem_copy(buf + pos, extension, sizeof(extension) - 1U);
        pos += sizeof(extension) - 1U;
        write_u32(buf + pos, 1U); pos += 4U;
        buf[pos++] = '1';
        return send_sftp_packet(sockfd, buf, pos);
      }
    
    case SSH_FXP_OPEN:
      return handle_open(sockfd, data + 1, len - 1);
    
    case SSH_FXP_CLOSE:
      return handle_close(sockfd, data + 1, len - 1);
    
    case SSH_FXP_READ:
      return handle_read(sockfd, data + 1, len - 1);
    
    case SSH_FXP_WRITE:
      return handle_write(sockfd, data + 1, len - 1);
    
    case SSH_FXP_OPENDIR:
      return handle_opendir(sockfd, data + 1, len - 1);
    
    case SSH_FXP_READDIR:
      return handle_readdir(sockfd, data + 1, len - 1);
    
    case SSH_FXP_REMOVE:
      return handle_remove(sockfd, data + 1, len - 1);

    case SSH_FXP_RMDIR:
      return handle_remove(sockfd, data + 1, len - 1);
    
    case SSH_FXP_MKDIR:
      return handle_mkdir(sockfd, data + 1, len - 1);
    
    case SSH_FXP_RENAME:
      return handle_rename(sockfd, data + 1, len - 1);
    
    case SSH_FXP_STAT:
    case SSH_FXP_LSTAT:
      return handle_stat(sockfd, data + 1, len - 1);

    case SSH_FXP_FSTAT:
      return handle_fstat(sockfd, data + 1, len - 1);

    case SSH_FXP_REALPATH:
      return handle_realpath(sockfd, data + 1, len - 1);

    case SSH_FXP_EXTENDED:
      return handle_extended(sockfd, data + 1, len - 1);
    
    default:
      /* Unsupported operation */
      return send_status(sockfd, 0, SSH_FX_OP_UNSUPPORTED, "Operation not supported");
  }
}
