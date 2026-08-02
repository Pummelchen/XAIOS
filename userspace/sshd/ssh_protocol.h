#ifndef SSH_PROTOCOL_H
#define SSH_PROTOCOL_H

#include <xaios/types.h>

#define SSH_MAX_PACKET_SIZE 35000U
#define SSH_VERSION_SERVER "SSH-2.0-XAIOS_1.0"
#define SSH_MSG_KEXINIT 20
#define SSH_MSG_KEXDH_INIT 30
#define SSH_MSG_KEXDH_REPLY 31
#define SSH_MSG_NEWKEYS 21
#define SSH_MSG_SERVICE_REQUEST 5
#define SSH_MSG_SERVICE_ACCEPT 6
#define SSH_MSG_USERAUTH_REQUEST 50
#define SSH_MSG_USERAUTH_SUCCESS 52
#define SSH_MSG_USERAUTH_FAILURE 51
#define SSH_MSG_USERAUTH_PK_OK 60
#define SSH_MSG_GLOBAL_REQUEST 80
#define SSH_MSG_REQUEST_SUCCESS 81
#define SSH_MSG_REQUEST_FAILURE 82
#define SSH_MSG_DISCONNECT 1
#define SSH_MSG_CHANNEL_OPEN 90
#define SSH_MSG_CHANNEL_OPEN_CONFIRM 91
#define SSH_MSG_CHANNEL_OPEN_FAILURE 92
#define SSH_MSG_CHANNEL_WINDOW_ADJUST 93
#define SSH_MSG_CHANNEL_DATA 94
#define SSH_MSG_CHANNEL_EXTENDED_DATA 95
#define SSH_MSG_CHANNEL_EOF 96
#define SSH_MSG_CHANNEL_CLOSE 97
#define SSH_MSG_CHANNEL_REQUEST 98
#define SSH_MSG_CHANNEL_SUCCESS 99
#define SSH_MSG_CHANNEL_FAILURE 100

#define SSH_EXTENDED_DATA_STDERR 1

#define SSH_DISCONNECT_BY_APPLICATION 11

typedef struct ssh_packet {
  uint8_t data[SSH_MAX_PACKET_SIZE];
  uint32_t len;
} ssh_packet_t;

/* Version exchange */
int ssh_send_version(int sockfd);
int ssh_recv_version(int sockfd, uint8_t *buf, uint32_t buf_size,
                     uint32_t *out_len);

/* Binary packet protocol */
int ssh_packet_read(int sockfd, ssh_packet_t *pkt);
int ssh_packet_write(int sockfd, const uint8_t *data, uint32_t len);

/* Encrypted packet I/O (used after NEWKEYS) */
int ssh_packet_write_encrypted(int sockfd, const uint8_t *data, uint32_t len);
int ssh_packet_read_encrypted(int sockfd, ssh_packet_t *out_pkt);

/* Helpers */
uint32_t ssh_read_u32_be(const uint8_t *p);
void ssh_write_u32_be(uint8_t *p, uint32_t v);
uint32_t ssh_read_string_len(const uint8_t *p);

#endif
