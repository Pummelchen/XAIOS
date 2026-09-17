#ifndef XAIOS_SSH_CLIENT_SHARED_H
#define XAIOS_SSH_CLIENT_SHARED_H

/* Declarations shared by the three halves of the outbound SSH client after
 * the authentication and command-line splits.
 *
 * `ssh_client.c` still owns the client-slot registry, the authentication
 * attempt loop and the channel-data/tick/close path. `ssh_client_auth.c` owns
 * the authentication exchanges and the credential/prompt path.
 * `ssh_client_command.c` owns option parsing and `ssh_client_prepare`.
 *
 * This header is private to those three translation units. The allocator is
 * the one symbol that hands back a pointer into the registry: it is a lease on
 * the single client slot it has just reserved, not an accessor, and every
 * other helper here either fills a caller-owned buffer or writes into the
 * client context the caller passed.
 */

#include <xaios/types.h>

#include "ssh_client.h"
#include "ssh_sftp.h"

struct ssh_channel;

/* How long a credential prompt waits for an answer before giving up.
 *
 * B-37. This client cannot ask whether the session it was launched in has a
 * terminal: the child is handed a channel id, a working directory and a
 * command line, and nothing else -- no PTY flag reaches it. So a prompt
 * written into a session nobody is sitting at, which is every script and
 * every CI job, used to wait for an answer that could not arrive, and the
 * caller saw a command that never returned. A bounded wait turns that into a
 * failure with a reason, which a script can act on. The clock measures
 * silence rather than total time: every byte typed at the prompt restarts
 * it, so a person part-way through a passphrase is never cut off mid-word.
 */
#define SSH_CLIENT_PROMPT_IDLE_NS UINT64_C(60000000000)

/* The client-slot registry, still defined in ssh_client.c; the command module
   calls the allocator and both new modules call the release. */
ssh_client_context_t *sshclient_client_allocate(struct ssh_channel *channel);
void sshclient_client_release(struct ssh_channel *channel,
                              ssh_client_context_t *client);

/* The authentication attempt loop, still defined in ssh_client.c; the command
   module calls it. */
int sshclient_client_proceed(ssh_client_context_t *client,
                             struct ssh_channel *channel, int echo_newline);

/* Credential acquisition, moved to ssh_client_auth.c; ssh_client.c and
   ssh_client_command.c call it. */
int sshclient_request_credential(ssh_client_context_t *client,
                                 struct ssh_channel *channel);

/* Local path resolution, still defined in ssh_client.c; the command module
   calls it. It fills the caller's buffer and reads no file-scope state
   beyond the app working directory that ssh_client.c already owns. */
int sshclient_resolve_local_path(const struct ssh_channel *channel,
                                 const char *input, char *output,
                                 uint32_t capacity);

#endif
