/*
 * SFTP file transfer path: OPEN, CLOSE, READ and WRITE for sftp_server.c.
 *
 * Split out of sftp_server.c to keep every source file under the repository's
 * 500-line limit. The wire format, status codes and handle lifetime are
 * unchanged; the handlers call the plumbing declared in
 * sftp_server_internal.h and defined once in sftp_server.c.
 */

#include "ssh_protocol.h"
#include "ssh_channel.h"
#include "ssh_utils.h"
#include "sftp_server.h"
#include <xaios_user.h>
#include "sftp_server_internal.h"

/* Static buffer to avoid 32KB stack allocations (Fix 5c) */
static uint8_t g_sftp_read_buf[SFTP_MAX_PACKET_SIZE];

static int validate_open_attributes(const uint8_t *data, uint32_t length,
                                    uint32_t offset) {
  if (offset > length || length - offset < 4U) return -1;
  uint32_t flags = sftp_read_u32(data + offset);
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

/* ---- SFTP Request Handlers ---- */
int sftp_handle_open(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return sftp_send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid OPEN");
  
  uint32_t request_id = sftp_read_u32(data);
  uint32_t path_len;
  const uint8_t *path_data;
  uint32_t next_offset;
  if (sftp_read_string_at(data, len, 4U, &path_data, &path_len, &next_offset) != 0 ||
      len - next_offset < 8U) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid OPEN");
  }
  
  if (path_len >= XAIOS_XBFS_PATH_MAX) {
    return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE, "Path too long");
  }
  
  /* Validate path */
  char local_path[XAIOS_XBFS_PATH_MAX];
  ssh_mem_copy(local_path, path_data, path_len);
  local_path[path_len] = '\0';
  
  if (ssh_str_len(local_path) != path_len || sftp_validate_path(local_path) != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_PERMISSION_DENIED, "Invalid path");
  }
  
  /* Parse flags */
  uint32_t flags = sftp_read_u32(data + next_offset);
  int attribute_status =
      validate_open_attributes(data, len, next_offset + 4U);
  if ((flags & ~(SSH_FXF_READ | SSH_FXF_WRITE | SSH_FXF_APPEND |
                 SSH_FXF_CREAT | SSH_FXF_TRUNC)) != 0U ||
      attribute_status > 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_OP_UNSUPPORTED,
                       "Unsupported open flags");
  }
  if (attribute_status < 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE,
                       "Invalid open attributes");
  }
  if ((flags & (SSH_FXF_READ | SSH_FXF_WRITE)) == 0U ||
      ((flags & (SSH_FXF_CREAT | SSH_FXF_TRUNC)) != 0U &&
       (flags & SSH_FXF_WRITE) == 0U) ||
      ((flags & SSH_FXF_APPEND) != 0U &&
       (flags & SSH_FXF_WRITE) == 0U)) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE,
                       "Invalid open flags");
  }
  int fs_flags = 0;
  if ((flags & SSH_FXF_READ) != 0)  fs_flags |= XAIOS_XBFS_OPEN_READ;
  if ((flags & SSH_FXF_WRITE) != 0) fs_flags |= XAIOS_XBFS_OPEN_WRITE;
  if ((flags & SSH_FXF_CREAT) != 0) fs_flags |= XAIOS_XBFS_OPEN_CREATE;
  if ((flags & SSH_FXF_TRUNC) != 0) fs_flags |= XAIOS_XBFS_OPEN_TRUNCATE;
  if (fs_flags == 0) fs_flags = XAIOS_XBFS_OPEN_READ;
  
  /* Allocate handle */
  sftp_file_handle_t *handle = sftp_alloc_handle(sockfd);
  if (handle == 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE, "No handles available");
  }

  ssh_mem_copy(handle->path, local_path, path_len + 1);
  handle->open_flags = fs_flags;
  handle->is_append = (flags & SSH_FXF_APPEND) != 0U;

  /* Actually open the file now */
  handle->fd = xaios_fs_open(handle->path, fs_flags);
  if (handle->fd < 0) {
    handle->is_open = 0;
    return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE, "Open failed");
  }
  if (handle->is_append != 0) {
    xaios_xbfs_stat_user_t file_stat;
    if (xaios_fs_stat(handle->path, &file_stat) != 0 ||
        file_stat.type != XAIOS_FS_TYPE_FILE) {
      (void)xaios_fs_close(handle->fd);
      ssh_mem_zero(handle, sizeof(*handle));
      return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE,
                         "Append stat failed");
    }
    handle->offset = file_stat.size;
  }

  return sftp_send_handle(sockfd, request_id, handle->handle_id);
}

int sftp_handle_close(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return sftp_send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid CLOSE");
  
  uint32_t request_id = sftp_read_u32(data);
  uint32_t handle_len;
  const uint8_t *handle_data;
  uint32_t next_offset;
  if (sftp_read_string_at(data, len, 4U, &handle_data, &handle_len, &next_offset) != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid CLOSE");
  }
  
  if (handle_len != 4) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle");
  }
  
  uint32_t handle_id = sftp_read_u32((const uint8_t *)handle_data);
  sftp_file_handle_t *handle = sftp_find_handle(sockfd, handle_id);
  
  if (handle == 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle ID");
  }
  
  /* Close handle */
  int close_failed = 0;
  if (handle->fd >= 0) {
    /* The VFS backend owns durable-close semantics. xaiFS commits pending
     * chunks from close(), while xaibootFS persists each mutation eagerly. */
    if (xaios_fs_close(handle->fd) != 0) close_failed = 1;
    handle->fd = -1;
  }
  handle->is_open = 0;
  ssh_mem_zero(handle, sizeof(sftp_file_handle_t));
  
  return sftp_send_status(sockfd, request_id,
                     close_failed ? SSH_FX_FAILURE : SSH_FX_OK,
                     close_failed ? "Durable close failed" : "Success");
}

int sftp_handle_read(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return sftp_send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid READ");
  
  uint32_t request_id = sftp_read_u32(data);
  uint32_t handle_len;
  const uint8_t *handle_data;
  uint32_t next_offset;
  if (sftp_read_string_at(data, len, 4U, &handle_data, &handle_len, &next_offset) != 0 ||
      len - next_offset != 12U) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid READ");
  }
  
  if (handle_len != 4) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle");
  }
  
  uint32_t handle_id = sftp_read_u32((const uint8_t *)handle_data);
  uint64_t offset = ((uint64_t)sftp_read_u32(data + next_offset) << 32) |
                    sftp_read_u32(data + next_offset + 4U);
  uint32_t read_len = sftp_read_u32(data + next_offset + 8U);
  
  sftp_file_handle_t *handle = sftp_find_handle(sockfd, handle_id);
  if (handle == 0 || handle->is_dir != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle ID");
  }
  
  /* Read file data via userspace FS API */
  uint8_t *file_data = g_sftp_read_buf;
  uint32_t response_limit = SSH_CHANNEL_PENDING_SIZE - 13U;
  uint32_t clamped_len = read_len < response_limit ? read_len : response_limit;

  int fd = handle->fd;
  if (fd < 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE, "Handle not open");
  }

  s64 bytes_read = xaios_fs_pread(fd, file_data, clamped_len, offset);
  
  if (bytes_read < 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE, "Read failed");
  }
  if (bytes_read == 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_EOF, "End of file");
  }
  
  return sftp_send_data(sockfd, request_id, file_data, (uint32_t)bytes_read);
}

int sftp_handle_write(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return sftp_send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid WRITE");
  
  uint32_t request_id = sftp_read_u32(data);
  uint32_t handle_len;
  const uint8_t *handle_data;
  uint32_t next_offset;
  if (sftp_read_string_at(data, len, 4U, &handle_data, &handle_len, &next_offset) != 0 ||
      len - next_offset < 12U) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid WRITE");
  }
  
  if (handle_len != 4) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle");
  }
  
  uint32_t handle_id = sftp_read_u32((const uint8_t *)handle_data);
  uint64_t offset = ((uint64_t)sftp_read_u32(data + next_offset) << 32) |
                    sftp_read_u32(data + next_offset + 4U);
  uint32_t write_len = sftp_read_u32(data + next_offset + 8U);
  next_offset += 12U;
  if (write_len != len - next_offset || offset > UINT64_MAX - write_len) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid WRITE");
  }
  
  sftp_file_handle_t *handle = sftp_find_handle(sockfd, handle_id);
  if (handle == 0 || handle->is_dir != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle ID");
  }
  
  /* Write file data via userspace FS API */
  if (handle->is_append != 0) offset = handle->offset;
  const uint8_t *write_data = data + next_offset;
  if (write_len > SFTP_MAX_PACKET_SIZE - 32U) {
    return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE,
                       "Write request too large");
  }

  int fd = handle->fd;
  if (fd < 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE, "Handle not open");
  }

  uint32_t completed = 0U;
  while (completed < write_len) {
    s64 written = xaios_fs_pwrite(fd, write_data + completed,
                                  write_len - completed, offset + completed);
    if (written <= 0 || (u64)written > write_len - completed) {
      return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE, "Write failed");
    }
    completed += (uint32_t)written;
  }
  if (handle->is_append != 0) handle->offset = offset + completed;
  
  return sftp_send_status(sockfd, request_id, SSH_FX_OK, "Success");
}
