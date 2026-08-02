#include "ssh_protocol.h"
#include "ssh_utils.h"
#include "sftp_server.h"
#include <xaios_user.h>

/* SFTP Protocol Constants */
#define SFTP_VERSION 3
#define SFTP_MAX_PACKET_SIZE 32768
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

/* Global State */
static sftp_file_handle_t g_sftp_handles[SFTP_MAX_HANDLES];
static uint32_t g_next_handle_id = 1;
static uint32_t g_response_channel_id;
static uint8_t g_sftp_wire_buf[SSH_MAX_PACKET_SIZE];

static int send_sftp_packet(int sockfd, const uint8_t *payload,
                            uint32_t payload_len) {
  uint32_t channel_data_len = payload_len + 4U;
  if (payload == 0 || channel_data_len + 9U > sizeof(g_sftp_wire_buf)) {
    return -1;
  }
  g_sftp_wire_buf[0] = SSH_MSG_CHANNEL_DATA;
  ssh_write_u32_be(g_sftp_wire_buf + 1U, g_response_channel_id);
  ssh_write_u32_be(g_sftp_wire_buf + 5U, channel_data_len);
  ssh_write_u32_be(g_sftp_wire_buf + 9U, payload_len);
  ssh_mem_copy(g_sftp_wire_buf + 13U, payload, payload_len);
  return ssh_packet_write_encrypted(sockfd, g_sftp_wire_buf,
                                    payload_len + 13U);
}

/* Validate path - prevent directory traversal */
static int validate_path(const char *path) {
  if (path == 0 || path[0] != '/') return -1;
  
  /* Check for ".." components */
  const char *p = path;
  while (*p) {
    if (p[0] == '.' && p[1] == '.' && (p[2] == '/' || p[2] == '\0')) {
      return -1; /* Directory traversal attempt */
    }
    p++;
  }
  
  return 0;
}

/* Allocate new handle */
static sftp_file_handle_t *alloc_handle(void) {
  for (uint32_t i = 0; i < SFTP_MAX_HANDLES; ++i) {
    if (!g_sftp_handles[i].is_open) {
      g_sftp_handles[i].is_open = 1;
      g_sftp_handles[i].handle_id = g_next_handle_id++;
      g_sftp_handles[i].offset = 0;
      g_sftp_handles[i].fd = -1;
      g_sftp_handles[i].is_dir = 0;
      return &g_sftp_handles[i];
    }
  }
  return 0;
}

/* Find handle by ID */
static sftp_file_handle_t *find_handle(uint32_t handle_id) {
  for (uint32_t i = 0; i < SFTP_MAX_HANDLES; ++i) {
    if (g_sftp_handles[i].is_open && g_sftp_handles[i].handle_id == handle_id) {
      return &g_sftp_handles[i];
    }
  }
  return 0;
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
      len - next_offset < 4U) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid OPEN");
  }
  
  if (path_len >= XAIOS_MFS_PATH_MAX) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "Path too long");
  }
  
  /* Validate path */
  char local_path[XAIOS_MFS_PATH_MAX];
  ssh_mem_copy(local_path, path_data, path_len);
  local_path[path_len] = '\0';
  
  if (validate_path(local_path) != 0) {
    return send_status(sockfd, request_id, SSH_FX_PERMISSION_DENIED, "Invalid path");
  }
  
  /* Parse flags */
  uint32_t flags = read_u32(data + next_offset);
  int fs_flags = 0;
  if ((flags & SSH_FXF_READ) != 0)  fs_flags |= XAIOS_MFS_OPEN_READ;
  if ((flags & SSH_FXF_WRITE) != 0) fs_flags |= XAIOS_MFS_OPEN_WRITE;
  if ((flags & SSH_FXF_CREAT) != 0) fs_flags |= XAIOS_MFS_OPEN_CREATE;
  if ((flags & SSH_FXF_TRUNC) != 0) fs_flags |= XAIOS_MFS_OPEN_TRUNCATE;
  if (fs_flags == 0) fs_flags = XAIOS_MFS_OPEN_READ;
  
  /* Allocate handle */
  sftp_file_handle_t *handle = alloc_handle();
  if (handle == 0) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "No handles available");
  }

  ssh_mem_copy(handle->path, local_path, path_len + 1);
  handle->open_flags = fs_flags;

  /* Actually open the file now */
  handle->fd = xaios_fs_open(handle->path, fs_flags);
  if (handle->fd < 0) {
    handle->is_open = 0;
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "Open failed");
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
  sftp_file_handle_t *handle = find_handle(handle_id);
  
  if (handle == 0) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle ID");
  }
  
  /* Close handle */
  if (handle->fd >= 0) {
    xaios_fs_close(handle->fd);
    handle->fd = -1;
  }
  handle->is_open = 0;
  ssh_mem_zero(handle, sizeof(sftp_file_handle_t));
  
  return send_status(sockfd, request_id, SSH_FX_OK, "Success");
}

static int handle_read(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid READ");
  
  uint32_t request_id = read_u32(data);
  uint32_t handle_len;
  const uint8_t *handle_data;
  uint32_t next_offset;
  if (read_string_at(data, len, 4U, &handle_data, &handle_len, &next_offset) != 0 ||
      len - next_offset < 12U) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid READ");
  }
  
  if (handle_len != 4) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle");
  }
  
  uint32_t handle_id = read_u32((const uint8_t *)handle_data);
  uint64_t offset = ((uint64_t)read_u32(data + next_offset) << 32) |
                    read_u32(data + next_offset + 4U);
  uint32_t read_len = read_u32(data + next_offset + 8U);
  
  sftp_file_handle_t *handle = find_handle(handle_id);
  if (handle == 0) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle ID");
  }
  
  /* Read file data via userspace FS API */
  uint8_t *file_data = g_sftp_read_buf;
  uint32_t clamped_len = read_len < SFTP_MAX_PACKET_SIZE ? read_len : SFTP_MAX_PACKET_SIZE;

  int fd = handle->fd;
  if (fd < 0) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "Handle not open");
  }

  /* Seek to offset by reading and discarding */
  if (offset > 0) {
    uint8_t discard[256];
    uint64_t remaining_offset = offset;
    while (remaining_offset > 0) {
      uint64_t skip = remaining_offset < 256 ? remaining_offset : 256;
      int got = xaios_fs_read(fd, discard, skip);
      if (got <= 0) break;
      remaining_offset -= (uint64_t)got;
    }
  }

  int bytes_read = xaios_fs_read(fd, file_data, clamped_len);
  
  if (bytes_read <= 0) {
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
  if (write_len > len - next_offset) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid WRITE");
  }
  
  sftp_file_handle_t *handle = find_handle(handle_id);
  if (handle == 0) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle ID");
  }
  
  /* Write file data via userspace FS API */
  const uint8_t *write_data = data + next_offset;
  uint32_t clamped_len = write_len < (SFTP_MAX_PACKET_SIZE - 32) ? write_len : (SFTP_MAX_PACKET_SIZE - 32);

  int fd = handle->fd;
  if (fd < 0) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "Handle not open");
  }

  /* Seek to offset if non-zero */
  if (offset > 0) {
    uint8_t discard[256];
    uint64_t rem = offset;
    while (rem > 0) {
      uint64_t skip = rem < 256 ? rem : 256;
      int got = xaios_fs_read(fd, discard, skip);
      if (got <= 0) break;
      rem -= (uint64_t)got;
    }
  }

  int written = xaios_fs_write(fd, write_data, clamped_len);
  
  if (written < 0) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "Write failed");
  }
  
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
  
  if (validate_path(local_path) != 0) {
    return send_status(sockfd, request_id, SSH_FX_PERMISSION_DENIED, "Invalid path");
  }
  
  /* Allocate handle */
  sftp_file_handle_t *handle = alloc_handle();
  if (handle == 0) {
    return send_status(sockfd, request_id, SSH_FX_FAILURE, "No handles available");
  }
  
  ssh_mem_copy(handle->path, local_path, path_len + 1);
  handle->is_dir = 1;
  
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
  sftp_file_handle_t *handle = find_handle(handle_id);
  
  if (handle == 0) {
    return send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle ID");
  }
  
  /* List directory contents via userspace FS API */
  char list_buf[4096];
  u64 list_size = 0;
  int fs_status = xaios_fs_list(handle->path, list_buf,
      sizeof(list_buf), &list_size);
  
  if (fs_status != 0 || list_size == 0) {
    return send_status(sockfd, request_id, SSH_FX_EOF, "End of directory");
  }
  
  /* Build SSH_FXP_NAME response */
  uint8_t resp_buf[4096 + 4096 + 256]; /* 2x list_buf + overhead for name encoding */
  uint32_t rpos = 0;
  resp_buf[rpos++] = SSH_FXP_NAME;
  write_u32(resp_buf + rpos, request_id); rpos += 4;
  
  /* Count entries (newline-separated) */
  uint32_t entry_count = 0;
  for (uint64_t i = 0; i < list_size; ++i) {
    if (list_buf[i] == '\n' || i == list_size - 1) entry_count++;
  }
  write_u32(resp_buf + rpos, entry_count); rpos += 4;
  
  /* Encode each entry as (name, longname, attrs) */
  uint64_t name_start = 0;
  for (uint64_t i = 0; i < list_size; ++i) {
    if (list_buf[i] == '\n' || i == list_size - 1) {
      uint32_t name_len = (uint32_t)(i - name_start);
      if (list_buf[i] == '\n' && name_len == 0) { name_start = i + 1; continue; }
      /* filename */
      write_u32(resp_buf + rpos, name_len); rpos += 4;
      ssh_mem_copy(resp_buf + rpos, list_buf + name_start, name_len); rpos += name_len;
      /* longname (same as filename for simplicity) */
      write_u32(resp_buf + rpos, name_len); rpos += 4;
      ssh_mem_copy(resp_buf + rpos, list_buf + name_start, name_len); rpos += name_len;
      /* attrs: flags=0 (no attributes) */
      write_u32(resp_buf + rpos, 0); rpos += 4;
      name_start = i + 1;
    }
  }
  
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
  
  if (validate_path(local_path) != 0) {
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
  
  if (validate_path(local_path) != 0) {
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
  
  if (validate_path(old_local) != 0 || validate_path(new_local) != 0) {
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
  
  if (validate_path(local_path) != 0) {
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
  sftp_file_handle_t *handle = find_handle(read_u32(handle_data));
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
  if (validate_path(path) != 0) {
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
        uint8_t buf[16];
        buf[0] = SSH_FXP_VERSION;
        write_u32(buf + 1, SFTP_VERSION);
        return send_sftp_packet(sockfd, buf, 5);
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
    
    default:
      /* Unsupported operation */
      return send_status(sockfd, 0, SSH_FX_OP_UNSUPPORTED, "Operation not supported");
  }
}
