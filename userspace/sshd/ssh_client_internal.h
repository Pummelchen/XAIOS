#ifndef XAIOS_SSH_CLIENT_INTERNAL_H
#define XAIOS_SSH_CLIENT_INTERNAL_H

/* Declarations shared by the halves of the outbound SSH client.
 *
 * `ssh_client.c` still owns the client contexts, the credential and prompt
 * path, the authentication exchanges and the channel-data path.
 * `ssh_client_kex.c` owns packet framing, the derived crypto channel keys, the
 * key exchange and host key verification; `ssh_client_handshake.c` owns the
 * session and direct-tcpip channel setup and the handshake orchestration.
 *
 * This header is private to those three translation units. Nothing declared
 * here hands back a pointer into mutable file-scope state: every helper either
 * fills a caller-owned buffer or writes into the client context the caller
 * passed, except `sshclient_wait_encrypted_packet_fd`, whose caller passes in
 * the packet it wants filled.
 */

#include <xaios/types.h>

#include "ssh_connection.h"
#include "ssh_identity.h"
#include "ssh_protocol.h"
#include "ssh_sftp.h"
#include <xaios_user.h>

struct ssh_channel;

/* Still defined in ssh_client.c; both extracted modules call them. */
int sshclient_bytes_equal(const uint8_t *a, const uint8_t *b, uint32_t length);
int sshclient_output_text(const ssh_client_context_t *client, const char *text);

/* Authentication, still defined in ssh_client.c; the handshake module calls
   it. The agent exchange exists only in the app build, exactly as in
   ssh_client.c. */
int sshclient_authenticate_password(ssh_client_context_t *client,
                                    uint64_t deadline);
int sshclient_authenticate_public_key(ssh_client_context_t *client,
                                      uint64_t deadline,
                                      const ssh_identity_t *identity);
#if defined(XAIOS_SSH_CLIENT_APP)
int sshclient_authenticate_agent(ssh_client_context_t *client,
                                 uint64_t deadline);
#endif

/* Packet framing, derived crypto, key exchange and known hosts, moved to
   `ssh_client_kex.c`. */
int sshclient_derive_crypto(ssh_connection_t *connection);
int sshclient_wait_plain_packet(ssh_client_context_t *client,
                                ssh_packet_t *packet, uint64_t deadline);
int sshclient_wait_encrypted_packet_fd(int sockfd, ssh_packet_t *packet,
                                       uint64_t deadline);
int sshclient_build_kexinit(uint8_t *buffer, uint32_t capacity,
                            uint32_t *out_length);
int sshclient_validate_server_kexinit(const ssh_packet_t *packet,
                                      uint32_t *hybrid);
int sshclient_resolve_host(const char *host, xaios_ip_addr_user_t *address,
                           uint64_t deadline);
int sshclient_parse_kex_reply(ssh_client_context_t *client,
                              const ssh_packet_t *packet,
                              const uint8_t *client_version,
                              uint32_t client_version_length,
                              const uint8_t *server_version,
                              uint32_t server_version_length,
                              const uint8_t *client_kex,
                              uint32_t client_kex_length,
                              const uint8_t *server_kex,
                              uint32_t server_kex_length,
                              const uint8_t client_private[32],
                              const uint8_t *client_public,
                              uint32_t client_public_length,
                              const uint8_t *mlkem_secret_key);

/* Channel setup and the handshake, moved to `ssh_client_handshake.c`. */
int sshclient_handshake(ssh_client_context_t *client,
                        const struct ssh_channel *outer);

#endif

/* The relay socket the handshake opens. */
#define SSH_CLIENT_RELAY_SOCKET UINT32_C(0x7fff0001)
