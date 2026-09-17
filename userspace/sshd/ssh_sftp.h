#ifndef XAIOS_SSH_SFTP_H
#define XAIOS_SSH_SFTP_H

/* The SSH client's context and the SFTP client's surface.
 *
 * `ssh_client.c` was one file; its eleven `sftp_*` functions moved to
 * `ssh_sftp.c` unchanged. Every one of them takes the client pointer and
 * touches neither of the client's two file-scope objects -- `g_clients` and
 * `g_client_app_cwd` -- which stay in `ssh_client.c`. The context and the
 * buffer sizes live here because both halves index the same buffers, and the
 * four helpers below stayed behind because the session and scp halves call
 * them too.
 *
 * Private to those two translation units; nothing outside them includes this.
 */

#include <xaios/types.h>

#include "ssh_connection.h"
#include "ssh_utils.h"

#define SSH_CLIENT_COMMAND_MAX 256U
#define SSH_CLIENT_HOST_MAX 128U
#define SSH_CLIENT_USER_MAX 64U
#define SSH_CLIENT_PASSWORD_MAX 128U
#define SSH_CLIENT_PATH_MAX 256U
#define SSH_CLIENT_WINDOW UINT32_C(65536)
#define SSH_CLIENT_PACKET UINT32_C(10240)
#define SSH_CLIENT_SFTP_BUFFER (SSH_MAX_PACKET_SIZE + 4U)

typedef struct ssh_client_context {
  uint32_t active;
  uint32_t prompting;
  /* -o BatchMode=yes: a credential that would have been asked for is an
     error instead. */
  uint32_t batch_mode;
  uint64_t prompt_deadline;
  uint32_t connected;
  uint32_t mode;
  u64 outer_sockfd;
  uint32_t outer_remote_id;
  u64 sockfd;
  ssh_connection_t *transport;
  uint16_t port;
  uint32_t local_channel;
  uint32_t remote_channel;
  uint32_t remote_window;
  uint32_t remote_max_packet;
  uint32_t receive_window;
  uint32_t close_sent;
  uint32_t exit_status;
  uint32_t recursive;
  uint32_t use_identity;
  uint32_t use_agent;
  uint32_t proxy_enabled;
  uint32_t proxy_established;
  uint32_t target_use_identity;
  uint32_t password_length;
  char password[SSH_CLIENT_PASSWORD_MAX + 1U];
  char identity_path[SSH_CLIENT_PATH_MAX];
  char host[SSH_CLIENT_HOST_MAX];
  char user[SSH_CLIENT_USER_MAX];
  char target_host[SSH_CLIENT_HOST_MAX];
  char target_user[SSH_CLIENT_USER_MAX];
  uint16_t target_port;
  char proxy_host[SSH_CLIENT_HOST_MAX];
  char proxy_user[SSH_CLIENT_USER_MAX];
  uint16_t proxy_port;
  u64 proxy_sockfd;
  ssh_connection_t *proxy_transport;
  uint32_t proxy_local_channel;
  uint32_t proxy_remote_channel;
  uint32_t proxy_remote_window;
  uint32_t proxy_remote_max_packet;
  uint32_t proxy_receive_window;
  uint32_t proxy_rx_used;
  uint8_t proxy_rx[SSH_MAX_PACKET_SIZE];
  ssh_packet_t proxy_packet_workspace;
  char command[SSH_CLIENT_COMMAND_MAX];
  char local_path[SSH_CLIENT_PATH_MAX];
  char remote_path[SSH_CLIENT_PATH_MAX];
  uint32_t sftp_used;
  uint32_t sftp_request_id;
  uint8_t sftp_buffer[SSH_CLIENT_SFTP_BUFFER];
  ssh_packet_t packet_workspace;
  uint8_t frame_workspace[SSH_CLIENT_SFTP_BUFFER];
  uint8_t request_workspace[SSH_CLIENT_PACKET];
} ssh_client_context_t;

/* Still in ssh_client.c; the SFTP half calls them. */
uint32_t append_string(uint8_t *buffer, uint32_t position, uint32_t capacity,
                       const uint8_t *value, uint32_t value_length);
int wait_encrypted_packet(ssh_client_context_t *client, ssh_packet_t *packet,
                          uint64_t deadline);
int send_channel_data(ssh_client_context_t *client, const uint8_t *data,
                      uint32_t length);
uint64_t client_deadline(void);

/* The SFTP client, moved here from ssh_client.c. */
typedef struct sftp_file_info {
  uint32_t type;
  uint64_t size;
} sftp_file_info_t;

int sftp_send_message(ssh_client_context_t *client, const uint8_t *payload,
                      uint32_t payload_length);
int sftp_receive_message(ssh_client_context_t *client, uint8_t *output,
                         uint32_t capacity, uint32_t *out_length,
                         uint64_t deadline);
int sftp_expect_status(const uint8_t *message, uint32_t length,
                       uint32_t request_id, uint32_t expected_code);
int sftp_open_remote(ssh_client_context_t *client, const char *path,
                     uint32_t flags, uint8_t *handle,
                     uint32_t *handle_length, uint64_t deadline);
int sftp_close_remote(ssh_client_context_t *client, const uint8_t *handle,
                      uint32_t handle_length, uint64_t deadline);
int sftp_initialize(ssh_client_context_t *client, uint64_t deadline);
int sftp_parse_attributes(const uint8_t *message, uint32_t length,
                          uint32_t *position, sftp_file_info_t *info);
int sftp_stat_remote(ssh_client_context_t *client, const char *path,
                     sftp_file_info_t *info);
int sftp_make_directory(ssh_client_context_t *client, const char *path);
int sftp_open_directory(ssh_client_context_t *client, const char *path,
                        uint8_t *handle, uint32_t *handle_length);
int sftp_read_directory(ssh_client_context_t *client, const uint8_t *handle,
                        uint32_t handle_length, uint8_t *message,
                        uint32_t capacity, uint32_t *length);

#endif
