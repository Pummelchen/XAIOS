#ifndef SFTP_SERVER_H
#define SFTP_SERVER_H

#include <xaios/types.h>

#define XAIOS_MFS_PATH_MAX 256U

typedef struct {
  uint32_t handle_id;
  char path[XAIOS_MFS_PATH_MAX];
  uint64_t offset;
  int open_flags;
  int fd;
  int is_open;
  int is_dir;
  uint64_t owner_sockfd;
  uint32_t owner_channel_id;
} sftp_file_handle_t;

int sftp_handle_message(int sockfd, uint32_t remote_channel_id,
                        const uint8_t *data, uint32_t len);
void sftp_close_channel(int sockfd, uint32_t remote_channel_id);

#endif
