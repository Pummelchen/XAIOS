#ifndef SSH_CHANNEL_H
#define SSH_CHANNEL_H

#include <xaios/types.h>
#include "ssh_protocol.h"

#define SSH_CHANNELS_PER_CONNECTION 2U
#define SSH_CHANNEL_MAX 8U
#define SSH_CHANNEL_PENDING_SIZE 8704U
#define SSH_CHANNEL_INITIAL_WINDOW 65536U
#define SSH_CHANNEL_MAX_PACKET 10240U
#define SSH_CHANNEL_SFTP_REQUEST_MAX SSH_MAX_PACKET_SIZE
#define SSH_CHANNEL_SFTP_BUFFER_SIZE \
  (SSH_CHANNEL_SFTP_REQUEST_MAX + SSH_CHANNEL_MAX_PACKET)

typedef struct ssh_channel {
  uint32_t active;
  uint64_t owner_sockfd;
  uint32_t local_id;
  uint32_t remote_id;
  uint32_t window_size;
  uint32_t remote_window;
  uint32_t remote_max_packet;
  uint32_t pending_offset;
  uint32_t pending_used;
  uint32_t close_after_flush;
  uint32_t close_sent;
  uint32_t exit_status;
  uint32_t is_sftp;
  uint32_t pty_requested;
  uint32_t terminal_columns;
  uint32_t terminal_rows;
  uint32_t sftp_rx_used;
  uint8_t sftp_rx[SSH_CHANNEL_SFTP_BUFFER_SIZE];
  uint8_t pending[SSH_CHANNEL_PENDING_SIZE];
} ssh_channel_t;

void ssh_channel_init(void);
void ssh_channel_close_connection(int sockfd);
int ssh_channel_handle_packet(int sockfd, const ssh_packet_t *pkt);
int ssh_channel_send_data(int sockfd, uint32_t remote_id,
                          const uint8_t *data, uint32_t len);

#endif
