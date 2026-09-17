#ifndef SFTP_SERVER_INTERNAL_H
#define SFTP_SERVER_INTERNAL_H

/*
 * Private declarations for the SFTP server implementation split across
 * sftp_server.c (wire plumbing, handle table, request dispatch),
 * sftp_server_file.c (the file transfer path: OPEN, CLOSE, READ, WRITE) and
 * sftp_server_dir.c (the directory and metadata requests). The wire constants,
 * the response builders and the handler entry points are declared here exactly
 * once and included from all three translation units.
 */

#include "ssh_channel.h"
#include "sftp_server.h"

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

/* Packet parsing and response builders, defined in sftp_server.c. */
uint32_t sftp_read_u32(const uint8_t *p);
void sftp_write_u32(uint8_t *p, uint32_t v);
void sftp_write_u64(uint8_t *p, uint64_t v);
int sftp_read_string_at(const uint8_t *data, uint32_t len, uint32_t offset,
                        const uint8_t **out, uint32_t *out_len,
                        uint32_t *next_offset);
int sftp_send_packet(int sockfd, const uint8_t *payload, uint32_t payload_len);
int sftp_send_status(int sockfd, uint32_t request_id, uint32_t status_code,
                     const char *message);
int sftp_send_handle(int sockfd, uint32_t request_id, uint32_t handle_id);
int sftp_send_data(int sockfd, uint32_t request_id, const uint8_t *data,
                   uint32_t data_len);

/* Path policy and handle table, defined in sftp_server.c. */
int sftp_validate_path(const char *path);
sftp_file_handle_t *sftp_alloc_handle(int sockfd);
sftp_file_handle_t *sftp_find_handle(int sockfd, uint32_t handle_id);

/* Request handlers, defined in sftp_server_file.c and sftp_server_dir.c. */
int sftp_handle_open(int sockfd, const uint8_t *data, uint32_t len);
int sftp_handle_close(int sockfd, const uint8_t *data, uint32_t len);
int sftp_handle_read(int sockfd, const uint8_t *data, uint32_t len);
int sftp_handle_write(int sockfd, const uint8_t *data, uint32_t len);
int sftp_handle_opendir(int sockfd, const uint8_t *data, uint32_t len);
int sftp_handle_readdir(int sockfd, const uint8_t *data, uint32_t len);
int sftp_handle_mkdir(int sockfd, const uint8_t *data, uint32_t len);
int sftp_handle_remove(int sockfd, const uint8_t *data, uint32_t len);
int sftp_handle_rename(int sockfd, const uint8_t *data, uint32_t len);
int sftp_handle_stat(int sockfd, const uint8_t *data, uint32_t len);
int sftp_handle_fstat(int sockfd, const uint8_t *data, uint32_t len);
int sftp_handle_fsetstat(int sockfd, const uint8_t *data, uint32_t len);
int sftp_handle_realpath(int sockfd, const uint8_t *data, uint32_t len);
int sftp_handle_extended(int sockfd, const uint8_t *data, uint32_t len);

#endif /* SFTP_SERVER_INTERNAL_H */
