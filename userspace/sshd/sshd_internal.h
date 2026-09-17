#ifndef SSHD_INTERNAL_H
#define SSHD_INTERNAL_H

/*
 * Declarations shared between sshd.c and the modules split out of it.
 *
 * sshd.h stays the public header for callers outside this directory; what
 * crosses between sshd.c, sshd_rate_limit.c and sshd_kex.c is private to the
 * server and belongs here. The first two groups to leave sshd.c were the
 * per-address rate-limit table and the key-exchange/crypto glue.
 */

#include <stdint.h>
#include <xaios_user.h>

#include "sshd.h"
#include "ssh_connection.h"
#include "ssh_protocol.h"

/*
 * From sshd_rate_limit.c. The table itself lives there; these are the four
 * operations sshd.c performs on it. They take the peer's address rather than a
 * connection so the accept path, which has no ssh_connection_t yet, can record
 * an attempt.
 */
int record_connection_attempt(const xaios_ip_addr_user_t *client_addr);
int check_rate_limit(const xaios_ip_addr_user_t *client_addr);
void record_auth_failure(const xaios_ip_addr_user_t *client_addr);
void record_auth_success(const xaios_ip_addr_user_t *client_addr);

/*
 * From sshd_kex.c. The key exchange drives itself from sshd.c's connection
 * state machine, and the per-connection encryption it derives is used by the
 * packet paths there.
 */
int conn_init_encryption(ssh_connection_t *conn);
int conn_packet_write_encrypted(ssh_connection_t *conn, const uint8_t *data,
                                uint32_t len);
int conn_packet_read_encrypted(ssh_connection_t *conn, ssh_packet_t *out_pkt);
int validate_client_kexinit(ssh_connection_t *conn,
                            const ssh_packet_t *pkt);
void init_exchange_hash(ssh_connection_t *conn,
                        const ssh_packet_t *client_kexinit);
int send_server_kexinit(ssh_connection_t *conn, int encrypted);
int handle_kexdh_init(ssh_connection_t *conn, const ssh_packet_t *pkt,
                      int encrypted);
int begin_client_rekey(ssh_connection_t *conn,
                       const ssh_packet_t *client_kexinit, int resume_state,
                       uint64_t now);
int begin_server_rekey(ssh_connection_t *conn, int resume_state, uint64_t now);

/* The constant-time-ish byte compare the key exchange shares with sshd.c's
   version and authorized-key parsing. Named to keep the common `bytes_equal`
   from becoming a link-visible symbol. */
int sshd_bytes_equal(const uint8_t *left, const uint8_t *right,
                     uint32_t length);

#endif /* SSHD_INTERNAL_H */
