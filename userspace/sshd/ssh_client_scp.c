/* The SSH client's scp transfer path, split out of `ssh_client.c`.
 *
 * One contiguous run moved unchanged: the big-endian 64-bit writer, the
 * deadline helper, the local/remote path helpers, the upload and download
 * walkers and `sshclient_scp_transfer`. Every `XAIOS_SSH_CLIENT_APP`
 * conditional region in `ssh_client.c` sits above this block, so the moved
 * code is unconditional. `write_u64_be` came along because the two SCP file
 * walkers are its only callers. `client_deadline` is still declared in
 * `ssh_sftp.h`, where the SFTP half reads it.
 */

#include "ssh_client_scp.h"

#include "ssh_protocol.h"
#include "ssh_utils.h"
#include <xaios_user.h>

#define SSH_CLIENT_SCP_DEPTH_MAX 8U
#define SSH_CLIENT_DIRECTORY_LIST_MAX 16384U

static void write_u64_be(uint8_t *buffer, uint64_t value) {
  ssh_write_u32_be(buffer, (uint32_t)(value >> 32U));
  ssh_write_u32_be(buffer + 4U, (uint32_t)value);
}

uint64_t client_deadline(void) {
  return xaios_clock_nanos() + SSH_CLIENT_TIMEOUT_NS;
}

static int path_component_valid(const char *name) {
  if (name == 0 || name[0] == '\0' || ssh_str_eq(name, ".") ||
      ssh_str_eq(name, "..")) return 0;
  for (uint32_t i = 0U; name[i] != '\0'; ++i) {
    if (name[i] == '/' || name[i] == '\\') return 0;
  }
  return 1;
}

static const char *path_basename(const char *path) {
  const char *base = path;
  for (uint32_t i = 0U; path[i] != '\0'; ++i)
    if (path[i] == '/' && path[i + 1U] != '\0') base = path + i + 1U;
  return base;
}

static int path_join(char *output, uint32_t capacity, const char *parent,
                     const char *name) {
  uint32_t parent_length = ssh_str_len(parent);
  uint32_t name_length = ssh_str_len(name);
  uint32_t separator = parent_length != 0U && parent[parent_length - 1U] != '/';
  if (!path_component_valid(name) || parent_length + separator + name_length + 1U > capacity)
    return -1;
  ssh_mem_copy(output, parent, parent_length);
  uint32_t position = parent_length;
  if (separator != 0U) output[position++] = '/';
  ssh_mem_copy(output + position, name, name_length + 1U);
  return 0;
}

static int scp_upload_file(ssh_client_context_t *client, const char *local_path,
                           const char *remote_path, uint64_t deadline) {
  xaios_xbfs_stat_user_t stat;
  if (xaios_fs_stat(local_path, &stat) != 0 || stat.type != 2U) {
    xaios_log("ssh-client: scp local source stat failed\n");
    return -21;
  }
  int local = xaios_fs_open(local_path, XAIOS_XBFS_OPEN_READ);
  if (local < 0) {
    xaios_log("ssh-client: scp local source open failed\n");
    return -22;
  }
  uint8_t handle[64];
  uint32_t handle_length = 0U;
  if (sftp_open_remote(client, remote_path, 2U | 8U | 16U,
                       handle, &handle_length, deadline) != 0) {
    xaios_log("ssh-client: scp remote destination open failed\n");
    (void)xaios_fs_close(local);
    return -23;
  }
  uint8_t *request = client->request_workspace;
  uint64_t offset = 0U;
  int result = 0;
  while (offset < stat.size) {
    uint32_t chunk = (uint32_t)(stat.size - offset);
    if (chunk > 8192U) chunk = 8192U;
    int bytes = xaios_fs_read(local, request + 21U + handle_length, chunk);
    if (bytes != (int)chunk) {
      xaios_log("ssh-client: scp local source read failed\n");
      result = -24; break;
    }
    uint32_t request_id = ++client->sftp_request_id;
    request[0] = 6U;
    ssh_write_u32_be(request + 1U, request_id);
    ssh_write_u32_be(request + 5U, handle_length);
    ssh_mem_copy(request + 9U, handle, handle_length);
    write_u64_be(request + 9U + handle_length, offset);
    ssh_write_u32_be(request + 17U + handle_length, chunk);
    uint32_t request_length = 21U + handle_length + chunk;
    if (sftp_send_message(client, request, request_length) != 0) {
      xaios_log("ssh-client: scp remote write send failed\n");
      result = -25; break;
    }
    uint32_t response_length = 0U;
    if (sftp_receive_message(client, request, SSH_CLIENT_PACKET, &response_length,
                             deadline) != 0 ||
        sftp_expect_status(request, response_length, request_id, 0U) != 0) {
      xaios_log("ssh-client: scp remote write status failed\n");
      result = -26; break;
    }
    offset += chunk;
  }
  if (xaios_fs_close(local) != 0) result = -27;
  if (sftp_close_remote(client, handle, handle_length, deadline) != 0) {
    xaios_log("ssh-client: scp remote close failed\n");
    result = -28;
  }
  return result;
}

static int write_all_file(int fd, const uint8_t *data, uint32_t length) {
  uint32_t written = 0U;
  while (written < length) {
    int bytes = xaios_fs_write(fd, data + written, length - written);
    if (bytes <= 0) return -1;
    written += (uint32_t)bytes;
  }
  return 0;
}

static int scp_download_file(ssh_client_context_t *client,
                             const char *remote_path, const char *local_path,
                             uint64_t deadline) {
  uint8_t handle[64];
  uint32_t handle_length = 0U;
  if (sftp_open_remote(client, remote_path, 1U, handle,
                       &handle_length, deadline) != 0) return -1;
  int local = xaios_fs_open(local_path,
                            XAIOS_XBFS_OPEN_WRITE | XAIOS_XBFS_OPEN_CREATE |
                                XAIOS_XBFS_OPEN_TRUNCATE);
  if (local < 0) {
    (void)sftp_close_remote(client, handle, handle_length, deadline);
    return -32;
  }
  uint8_t *request = client->request_workspace;
  uint64_t offset = 0U;
  int result = 0;
  for (;;) {
    uint32_t request_id = ++client->sftp_request_id;
    request[0] = 5U;
    ssh_write_u32_be(request + 1U, request_id);
    ssh_write_u32_be(request + 5U, handle_length);
    ssh_mem_copy(request + 9U, handle, handle_length);
    write_u64_be(request + 9U + handle_length, offset);
    ssh_write_u32_be(request + 17U + handle_length, 8192U);
    if (sftp_send_message(client, request, 21U + handle_length) != 0) {
      result = -1; break;
    }
    uint32_t response_length = 0U;
    if (sftp_receive_message(client, request, SSH_CLIENT_PACKET, &response_length,
                             deadline) != 0 || response_length < 5U ||
        ssh_read_u32_be(request + 1U) != request_id) {
      result = -1; break;
    }
    if (request[0] == 101U) {
      if (response_length < 9U || ssh_read_u32_be(request + 5U) != 1U)
        result = -1;
      break;
    }
    if (request[0] != 103U || response_length < 9U) {
      result = -1; break;
    }
    uint32_t data_length = ssh_read_u32_be(request + 5U);
    if (data_length == 0U || data_length > response_length - 9U ||
        write_all_file(local, request + 9U, data_length) != 0) {
      result = -1; break;
    }
    offset += data_length;
  }
  if (xaios_fs_fsync(local) != 0 || xaios_fs_close(local) != 0) result = -1;
  if (sftp_close_remote(client, handle, handle_length, deadline) != 0)
    result = -1;
  return result;
}

static int ensure_local_directory(const char *path) {
  if (xaios_fs_mkdir(path) == 0) return 0;
  xaios_xbfs_stat_user_t stat;
  return xaios_fs_stat(path, &stat) == 0 &&
                 stat.type == XAIOS_FS_TYPE_DIRECTORY
             ? 0
             : -1;
}

static int scp_upload_path(ssh_client_context_t *client,
                           const char *local_path, const char *remote_path,
                           uint32_t depth) {
  xaios_xbfs_stat_user_t stat;
  if (xaios_fs_stat(local_path, &stat) != 0) return -21;
  if (stat.type == XAIOS_FS_TYPE_FILE)
    return scp_upload_file(client, local_path, remote_path, client_deadline());
  if (stat.type != XAIOS_FS_TYPE_DIRECTORY || client->recursive == 0U)
    return -29;
  if (depth >= SSH_CLIENT_SCP_DEPTH_MAX ||
      sftp_make_directory(client, remote_path) != 0) return -30;

  char listing[SSH_CLIENT_DIRECTORY_LIST_MAX];
  u64 listing_size = 0U;
  if (xaios_fs_list(local_path, listing, sizeof(listing), &listing_size) < 0 ||
      listing_size > sizeof(listing)) return -31;
  uint32_t start = 0U;
  while (start < listing_size) {
    uint32_t end = start;
    while (end < listing_size && listing[end] != '\n') ++end;
    uint32_t name_length = end - start;
    if (name_length != 0U) {
      char name[SSH_CLIENT_PATH_MAX];
      char local_child[SSH_CLIENT_PATH_MAX];
      char remote_child[SSH_CLIENT_PATH_MAX];
      if (name_length + 1U > sizeof(name)) return -31;
      ssh_mem_copy(name, listing + start, name_length);
      name[name_length] = '\0';
      if (path_join(local_child, sizeof(local_child), local_path, name) != 0 ||
          path_join(remote_child, sizeof(remote_child), remote_path, name) != 0)
        return -31;
      int result = scp_upload_path(client, local_child, remote_child, depth + 1U);
      if (result != 0) return result;
    }
    start = end + 1U;
  }
  return 0;
}

static int read_sftp_string(const uint8_t *message, uint32_t length,
                            uint32_t *position, char *output,
                            uint32_t capacity) {
  if (*position > length || length - *position < 4U) return -1;
  uint32_t value_length = ssh_read_u32_be(message + *position);
  *position += 4U;
  if (value_length >= capacity || value_length > length - *position) return -1;
  ssh_mem_copy(output, message + *position, value_length);
  output[value_length] = '\0';
  *position += value_length;
  return 0;
}

static int skip_sftp_string(const uint8_t *message, uint32_t length,
                            uint32_t *position) {
  if (*position > length || length - *position < 4U) return -1;
  uint32_t value_length = ssh_read_u32_be(message + *position);
  *position += 4U;
  if (value_length > length - *position) return -1;
  *position += value_length;
  return 0;
}

static int scp_download_path(ssh_client_context_t *client,
                             const char *remote_path, const char *local_path,
                             uint32_t depth) {
  sftp_file_info_t info;
  if (sftp_stat_remote(client, remote_path, &info) != 0) return -33;
  if (info.type == XAIOS_FS_TYPE_FILE)
    return scp_download_file(client, remote_path, local_path,
                             client_deadline());
  if (info.type != XAIOS_FS_TYPE_DIRECTORY || client->recursive == 0U)
    return -29;
  if (depth >= SSH_CLIENT_SCP_DEPTH_MAX ||
      ensure_local_directory(local_path) != 0) return -30;

  uint8_t handle[64];
  uint32_t handle_length = 0U;
  if (sftp_open_directory(client, remote_path, handle, &handle_length) != 0)
    return -33;
  int result = 0;
  for (;;) {
    uint8_t message[SSH_CLIENT_PACKET];
    uint32_t length = 0U;
    int read_result = sftp_read_directory(client, handle, handle_length,
                                          message, sizeof(message), &length);
    if (read_result == 1) break;
    if (read_result != 0) { result = -33; break; }
    uint32_t count = ssh_read_u32_be(message + 5U);
    uint32_t position = 9U;
    for (uint32_t entry = 0U; entry < count; ++entry) {
      char name[SSH_CLIENT_PATH_MAX];
      sftp_file_info_t child_info;
      if (read_sftp_string(message, length, &position, name, sizeof(name)) != 0 ||
          skip_sftp_string(message, length, &position) != 0 ||
          sftp_parse_attributes(message, length, &position, &child_info) != 0) {
        result = -33;
        break;
      }
      if (ssh_str_eq(name, ".") || ssh_str_eq(name, "..")) continue;
      char remote_child[SSH_CLIENT_PATH_MAX];
      char local_child[SSH_CLIENT_PATH_MAX];
      if (path_join(remote_child, sizeof(remote_child), remote_path, name) != 0 ||
          path_join(local_child, sizeof(local_child), local_path, name) != 0) {
        result = -31;
        break;
      }
      int child_result = scp_download_path(client, remote_child, local_child,
                                           depth + 1U);
      if (child_result != 0) {
        result = child_result;
        break;
      }
    }
    if (result != 0) break;
  }
  if (sftp_close_remote(client, handle, handle_length, client_deadline()) != 0 &&
      result == 0) result = -28;
  return result;
}

int sshclient_scp_transfer(ssh_client_context_t *client) {
  uint64_t deadline = client_deadline();
  int initialize = sftp_initialize(client, deadline);
  if (initialize != 0) {
    xaios_log("ssh-client: SFTP initialization failed\n");
    return initialize;
  }
  if (client->mode == SSH_CLIENT_MODE_SCP_UPLOAD) {
    sftp_file_info_t destination;
    char remote_path[SSH_CLIENT_PATH_MAX];
    sshclient_string_copy(remote_path, sizeof(remote_path), client->remote_path);
    if (sftp_stat_remote(client, remote_path, &destination) == 0 &&
        destination.type == XAIOS_FS_TYPE_DIRECTORY &&
        path_join(remote_path, sizeof(remote_path), client->remote_path,
                  path_basename(client->local_path)) != 0) return -31;
    return scp_upload_path(client, client->local_path, remote_path, 0U);
  }
  char local_path[SSH_CLIENT_PATH_MAX];
  sshclient_string_copy(local_path, sizeof(local_path), client->local_path);
  xaios_xbfs_stat_user_t destination;
  if (xaios_fs_stat(local_path, &destination) == 0 &&
      destination.type == XAIOS_FS_TYPE_DIRECTORY &&
      path_join(local_path, sizeof(local_path), client->local_path,
                path_basename(client->remote_path)) != 0) return -31;
  return scp_download_path(client, client->remote_path, local_path, 0U);
}
