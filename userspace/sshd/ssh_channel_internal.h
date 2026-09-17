#ifndef XAIOS_SSH_CHANNEL_INTERNAL_H
#define XAIOS_SSH_CHANNEL_INTERNAL_H

/* The channel table's crossing points, shared between
 * `ssh_channel_table.c`, `ssh_channel_request.c` and `ssh_channel.c`.
 *
 * The table -- the row array, the next-local-id counter and the outbound
 * forward buffer -- lives in `ssh_channel_table.c` after the split, because
 * the tick loop walks the rows and every lookup hands out a row pointer.
 * Those lookups are declared here rather than in the public `ssh_channel.h`:
 * they are private to the three channel translation units, and no other file
 * can reach the table.
 *
 * sshd runs its channel work from one cooperative loop, so there is no lock
 * over this state and no row pointer is held across a critical section.
 */

#include "ssh_channel.h"

/* Allocate a row for one connection, or null at the per-connection limit. */
ssh_channel_t *ssh_channel_alloc(int sockfd);

/* Find an active row by its local id on one connection. */
ssh_channel_t *ssh_channel_find_local(int sockfd, uint32_t local_id);

/* The agent channel opened on behalf of a session, if there is one. */
ssh_channel_t *ssh_channel_find_agent(const ssh_channel_t *session);

/* Open an auth-agent channel for a session; 0 on success. */
int ssh_channel_open_agent(ssh_channel_t *session);

/* Dispatch one CHANNEL_REQUEST (type 98) packet. */
int ssh_channel_handle_request(int sockfd, const ssh_packet_t *pkt);

/* Whether a length-prefixed wire string holds a zero byte. */
int ssh_channel_packet_has_zero(const uint8_t *value, uint32_t value_len);

#endif /* XAIOS_SSH_CHANNEL_INTERNAL_H */
