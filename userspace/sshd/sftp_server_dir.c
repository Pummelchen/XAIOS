/*
 * SFTP directory and metadata requests for sftp_server.c: OPENDIR, READDIR,
 * MKDIR, REMOVE, RENAME, STAT, FSTAT, FSETSTAT, REALPATH and the fsync
 * extension.
 *
 * Split out of sftp_server.c to keep every source file under the repository's
 * 500-line limit. The SSH_FXP_NAME paging and every reply byte are unchanged.
 */

#include "ssh_protocol.h"
#include "ssh_channel.h"
#include "ssh_utils.h"
#include "sftp_server.h"
#include <xaios_user.h>
#include "sftp_server_internal.h"

int sftp_handle_opendir(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return sftp_send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid OPENDIR");
  
  uint32_t request_id = sftp_read_u32(data);
  uint32_t path_len;
  const uint8_t *path;
  uint32_t next_offset;
  if (sftp_read_string_at(data, len, 4U, &path, &path_len, &next_offset) != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid OPENDIR");
  }
  
  if (path_len >= XAIOS_XBFS_PATH_MAX) {
    return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE, "Path too long");
  }
  
  char local_path[XAIOS_XBFS_PATH_MAX];
  ssh_mem_copy(local_path, path, path_len);
  local_path[path_len] = '\0';
  
  if (ssh_str_len(local_path) != path_len || sftp_validate_path(local_path) != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_PERMISSION_DENIED, "Invalid path");
  }
  
  /* Allocate handle */
  sftp_file_handle_t *handle = sftp_alloc_handle(sockfd);
  if (handle == 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE, "No handles available");
  }
  
  ssh_mem_copy(handle->path, local_path, path_len + 1);
  handle->is_dir = 1;
  xaios_xbfs_stat_user_t directory_stat;
  if (xaios_fs_stat(local_path, &directory_stat) != 0 ||
      directory_stat.type != XAIOS_FS_TYPE_DIRECTORY) {
    ssh_mem_zero(handle, sizeof(*handle));
    return sftp_send_status(sockfd, request_id, SSH_FX_NO_SUCH_FILE,
                       "Directory not found");
  }
  
  return sftp_send_handle(sockfd, request_id, handle->handle_id);
}

int sftp_handle_readdir(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return sftp_send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid READDIR");
  
  uint32_t request_id = sftp_read_u32(data);
  uint32_t handle_len;
  const uint8_t *handle_data;
  uint32_t next_offset;
  if (sftp_read_string_at(data, len, 4U, &handle_data, &handle_len, &next_offset) != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid READDIR");
  }
  
  if (handle_len != 4) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle");
  }
  
  uint32_t handle_id = sftp_read_u32((const uint8_t *)handle_data);
  sftp_file_handle_t *handle = sftp_find_handle(sockfd, handle_id);
  
  if (handle == 0 || handle->is_dir == 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle ID");
  }
  
  /* List directory contents via userspace FS API */
  char list_buf[4096];
  u64 list_size = 0;
  int fs_status = xaios_fs_list(handle->path, list_buf,
      sizeof(list_buf), &list_size);
  
  if (fs_status != 0 || list_size == 0 || handle->offset >= list_size) {
    return sftp_send_status(sockfd, request_id, SSH_FX_EOF, "End of directory");
  }
  
  /* Build a bounded SSH_FXP_NAME page. The next READDIR resumes at offset. */
  uint8_t resp_buf[4096];
  uint32_t rpos = 0;
  resp_buf[rpos++] = SSH_FXP_NAME;
  sftp_write_u32(resp_buf + rpos, request_id); rpos += 4;
  uint32_t count_offset = rpos;
  sftp_write_u32(resp_buf + rpos, 0U); rpos += 4;
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
    sftp_write_u32(resp_buf + rpos, name_len); rpos += 4U;
    ssh_mem_copy(resp_buf + rpos, list_buf + name_start, name_len);
    rpos += name_len;
    sftp_write_u32(resp_buf + rpos, name_len); rpos += 4U;
    ssh_mem_copy(resp_buf + rpos, list_buf + name_start, name_len);
    rpos += name_len;
    sftp_write_u32(resp_buf + rpos, 0U); rpos += 4U;
    ++entry_count;
    cursor = next_cursor;
    handle->offset = cursor;
  }
  if (entry_count == 0U) {
    return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE,
                       "Directory entry exceeds response limit");
  }
  sftp_write_u32(resp_buf + count_offset, entry_count);
  return sftp_send_packet(sockfd, resp_buf, rpos);
}

int sftp_handle_mkdir(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return sftp_send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid MKDIR");
  
  uint32_t request_id = sftp_read_u32(data);
  uint32_t path_len;
  const uint8_t *path;
  uint32_t next_offset;
  if (sftp_read_string_at(data, len, 4U, &path, &path_len, &next_offset) != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid MKDIR");
  }
  
  if (path_len >= XAIOS_XBFS_PATH_MAX) {
    return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE, "Path too long");
  }
  
  char local_path[XAIOS_XBFS_PATH_MAX];
  ssh_mem_copy(local_path, path, path_len);
  local_path[path_len] = '\0';
  
  if (ssh_str_len(local_path) != path_len || sftp_validate_path(local_path) != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_PERMISSION_DENIED, "Invalid path");
  }
  
  /* Create directory via userspace FS API */
  int fs_status = xaios_fs_mkdir(local_path);
  if (fs_status != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE, "mkdir failed");
  }
  return sftp_send_status(sockfd, request_id, SSH_FX_OK, "Success");
}

int sftp_handle_remove(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return sftp_send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid REMOVE");
  
  uint32_t request_id = sftp_read_u32(data);
  uint32_t path_len;
  const uint8_t *path;
  uint32_t next_offset;
  if (sftp_read_string_at(data, len, 4U, &path, &path_len, &next_offset) != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid REMOVE");
  }
  
  if (path_len >= XAIOS_XBFS_PATH_MAX) {
    return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE, "Path too long");
  }
  
  char local_path[XAIOS_XBFS_PATH_MAX];
  ssh_mem_copy(local_path, path, path_len);
  local_path[path_len] = '\0';
  
  if (ssh_str_len(local_path) != path_len || sftp_validate_path(local_path) != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_PERMISSION_DENIED, "Invalid path");
  }
  
  /* Remove file via userspace FS API */
  int fs_status = xaios_fs_delete(local_path);
  if (fs_status != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE, "remove failed");
  }
  return sftp_send_status(sockfd, request_id, SSH_FX_OK, "Success");
}

int sftp_handle_rename(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return sftp_send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid RENAME");
  
  uint32_t request_id = sftp_read_u32(data);
  uint32_t old_len;
  const uint8_t *old_path;
  uint32_t next_offset;
  if (sftp_read_string_at(data, len, 4U, &old_path, &old_len, &next_offset) != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid RENAME");
  }
  uint32_t new_len;
  const uint8_t *new_path;
  uint32_t end_offset;
  if (sftp_read_string_at(data, len, next_offset, &new_path, &new_len,
                     &end_offset) != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid RENAME");
  }
  
  char old_local[XAIOS_XBFS_PATH_MAX];
  char new_local[XAIOS_XBFS_PATH_MAX];
  
  if (old_len >= XAIOS_XBFS_PATH_MAX || new_len >= XAIOS_XBFS_PATH_MAX) {
    return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE, "Path too long");
  }
  
  ssh_mem_copy(old_local, old_path, old_len);
  old_local[old_len] = '\0';
  
  ssh_mem_copy(new_local, new_path, new_len);
  new_local[new_len] = '\0';
  
  if (ssh_str_len(old_local) != old_len ||
      ssh_str_len(new_local) != new_len ||
      sftp_validate_path(old_local) != 0 || sftp_validate_path(new_local) != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_PERMISSION_DENIED, "Invalid path");
  }
  
  /* Rename file via userspace FS API */
  int fs_status = xaios_fs_rename(old_local, new_local);
  if (fs_status != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE, "rename failed");
  }
  return sftp_send_status(sockfd, request_id, SSH_FX_OK, "Success");
}

int sftp_handle_stat(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return sftp_send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid STAT");
  
  uint32_t request_id = sftp_read_u32(data);
  uint32_t path_len;
  const uint8_t *path;
  uint32_t next_offset;
  if (sftp_read_string_at(data, len, 4U, &path, &path_len, &next_offset) != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid STAT");
  }
  
  if (path_len >= XAIOS_XBFS_PATH_MAX) {
    return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE, "Path too long");
  }
  
  char local_path[XAIOS_XBFS_PATH_MAX];
  ssh_mem_copy(local_path, path, path_len);
  local_path[path_len] = '\0';
  
  if (ssh_str_len(local_path) != path_len || sftp_validate_path(local_path) != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_NO_SUCH_FILE, "File not found");
  }
  
  /* Get file stat via userspace FS API */
  xaios_xbfs_stat_user_t file_stat;
  int fs_status = xaios_fs_stat(local_path, &file_stat);
  
  uint8_t buf[64];
  uint32_t pos = 0;
  
  if (fs_status != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_NO_SUCH_FILE, "File not found");
  }
  
  buf[pos++] = SSH_FXP_ATTRS;
  sftp_write_u32(buf + pos, request_id); pos += 4;
  
  /* Attributes: flags=SSH_FILEXFER_ATTR_SIZE, size=file_stat.size */
  sftp_write_u32(buf + pos, 0x00000001); pos += 4;
  sftp_write_u64(buf + pos, file_stat.size); pos += 8;
  
  return sftp_send_packet(sockfd, buf, pos);
}

int sftp_handle_fstat(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) return sftp_send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid FSTAT");
  uint32_t request_id = sftp_read_u32(data);
  const uint8_t *handle_data;
  uint32_t handle_len;
  uint32_t next_offset;
  if (sftp_read_string_at(data, len, 4U, &handle_data, &handle_len, &next_offset) != 0 ||
      handle_len != 4U) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle");
  }
  sftp_file_handle_t *handle = sftp_find_handle(sockfd, sftp_read_u32(handle_data));
  if (handle == 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE, "Invalid handle ID");
  }

  xaios_xbfs_stat_user_t file_stat;
  if (xaios_fs_stat(handle->path, &file_stat) != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_NO_SUCH_FILE, "File not found");
  }
  uint8_t response[17];
  response[0] = SSH_FXP_ATTRS;
  sftp_write_u32(response + 1U, request_id);
  sftp_write_u32(response + 5U, 0x00000001U);
  sftp_write_u64(response + 9U, file_stat.size);
  return sftp_send_packet(sockfd, response, sizeof(response));
}

int sftp_handle_fsetstat(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 12U) {
    uint32_t request_id = len >= 4U ? sftp_read_u32(data) : 0U;
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE,
                       "Invalid FSETSTAT");
  }
  uint32_t request_id = sftp_read_u32(data);
  const uint8_t *handle_data;
  uint32_t handle_len;
  uint32_t next_offset;
  if (sftp_read_string_at(data, len, 4U, &handle_data, &handle_len,
                     &next_offset) != 0 ||
      handle_len != 4U || len - next_offset < 4U) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE,
                       "Invalid handle");
  }
  sftp_file_handle_t *handle = sftp_find_handle(sockfd, sftp_read_u32(handle_data));
  if (handle == 0 || handle->is_dir != 0 || handle->fd < 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE,
                       "Invalid handle ID");
  }

  uint32_t flags = sftp_read_u32(data + next_offset);
  next_offset += 4U;
  if (flags == 0U && next_offset == len) {
    return sftp_send_status(sockfd, request_id, SSH_FX_OK, "Success");
  }
  if (flags != SSH_FILEXFER_ATTR_SIZE || len - next_offset != 8U) {
    return sftp_send_status(sockfd, request_id, SSH_FX_OP_UNSUPPORTED,
                       "Unsupported attributes");
  }
  uint64_t requested_size = ((uint64_t)sftp_read_u32(data + next_offset) << 32U) |
                            sftp_read_u32(data + next_offset + 4U);
  xaios_xbfs_stat_user_t file_stat;
  if (xaios_fs_stat(handle->path, &file_stat) != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_NO_SUCH_FILE,
                       "File not found");
  }
  if (file_stat.size != requested_size) {
    return sftp_send_status(sockfd, request_id, SSH_FX_OP_UNSUPPORTED,
                       "Resize not supported");
  }
  return sftp_send_status(sockfd, request_id, SSH_FX_OK, "Success");
}

int sftp_handle_realpath(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 8U) {
    return sftp_send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid REALPATH");
  }
  uint32_t request_id = sftp_read_u32(data);
  uint32_t path_len = sftp_read_u32(data + 4U);
  if (path_len > len - 8U || path_len >= XAIOS_XBFS_PATH_MAX) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE,
                       "Invalid path");
  }

  char path[XAIOS_XBFS_PATH_MAX];
  if (path_len == 0U || (path_len == 1U && data[8] == '.')) {
    path[0] = '/';
    path[1] = '\0';
    path_len = 1U;
  } else {
    uint32_t prefix = data[8] == '/' ? 0U : 1U;
    if (path_len + prefix >= sizeof(path)) {
      return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE,
                         "Path too long");
    }
    if (prefix != 0U) path[0] = '/';
    ssh_mem_copy(path + prefix, data + 8U, path_len);
    path_len += prefix;
    path[path_len] = '\0';
  }
  if (ssh_str_len(path) != path_len || sftp_validate_path(path) != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_PERMISSION_DENIED,
                       "Invalid path");
  }

  uint8_t response[2U * XAIOS_XBFS_PATH_MAX + 32U];
  uint32_t pos = 0;
  response[pos++] = SSH_FXP_NAME;
  sftp_write_u32(response + pos, request_id); pos += 4U;
  sftp_write_u32(response + pos, 1U); pos += 4U;
  sftp_write_u32(response + pos, path_len); pos += 4U;
  ssh_mem_copy(response + pos, path, path_len); pos += path_len;
  sftp_write_u32(response + pos, path_len); pos += 4U;
  ssh_mem_copy(response + pos, path, path_len); pos += path_len;
  sftp_write_u32(response + pos, 0U); pos += 4U;
  return sftp_send_packet(sockfd, response, pos);
}

int sftp_handle_extended(int sockfd, const uint8_t *data, uint32_t len) {
  if (len < 4U) {
    return sftp_send_status(sockfd, 0, SSH_FX_BAD_MESSAGE, "Invalid EXTENDED");
  }
  uint32_t request_id = sftp_read_u32(data);
  const uint8_t *name;
  uint32_t name_len;
  uint32_t next_offset;
  if (sftp_read_string_at(data, len, 4U, &name, &name_len, &next_offset) != 0 ||
      name_len != sizeof("fsync@openssh.com") - 1U ||
      next_offset > len) {
    return sftp_send_status(sockfd, request_id, SSH_FX_OP_UNSUPPORTED,
                       "Unsupported extension");
  }
  static const uint8_t fsync_name[] = "fsync@openssh.com";
  for (uint32_t i = 0U; i < name_len; ++i) {
    if (name[i] != fsync_name[i]) {
      return sftp_send_status(sockfd, request_id, SSH_FX_OP_UNSUPPORTED,
                         "Unsupported extension");
    }
  }
  const uint8_t *handle_data;
  uint32_t handle_len;
  uint32_t end_offset;
  if (sftp_read_string_at(data, len, next_offset, &handle_data, &handle_len,
                     &end_offset) != 0 ||
      handle_len != 4U || end_offset != len) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE,
                       "Invalid fsync request");
  }
  sftp_file_handle_t *handle = sftp_find_handle(sockfd, sftp_read_u32(handle_data));
  if (handle == 0 || handle->fd < 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_BAD_MESSAGE,
                       "Invalid handle ID");
  }
  if (xaios_fs_fsync(handle->fd) != 0) {
    return sftp_send_status(sockfd, request_id, SSH_FX_FAILURE, "fsync failed");
  }
  return sftp_send_status(sockfd, request_id, SSH_FX_OK, "Success");
}
