#ifndef SSH_CHANNEL_H
#define SSH_CHANNEL_H

#include <xaios/types.h>
#include "ssh_protocol.h"

#define SSH_CHANNEL_MAX 4U
#define SSH_CHANNEL_SFTP_BUFFER_SIZE 16388U

/* Channel request message types */
#define SSH_MSG_CHANNEL_REQUEST       98U
#define SSH_MSG_CHANNEL_SUCCESS       99U
#define SSH_MSG_CHANNEL_FAILURE       100U
#define SSH_MSG_CHANNEL_WINDOW_ADJUST 93U

typedef struct ssh_channel {
  uint32_t active;
  uint64_t owner_sockfd;
  uint32_t local_id;
  uint32_t remote_id;
  uint32_t window_size;
  uint32_t remote_window;
  uint32_t bytes_consumed;
  uint32_t is_sftp;
  uint32_t sftp_rx_used;
  uint8_t sftp_rx[SSH_CHANNEL_SFTP_BUFFER_SIZE];
} ssh_channel_t;

void ssh_channel_init(void);
void ssh_channel_close_connection(int sockfd);
int ssh_channel_handle_packet(int sockfd, const ssh_packet_t *pkt);

#endif
