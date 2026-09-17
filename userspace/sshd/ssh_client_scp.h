#ifndef XAIOS_SSH_CLIENT_SCP_H
#define XAIOS_SSH_CLIENT_SCP_H

/* The SSH client's scp half, split out of `ssh_client.c`.
 *
 * One contiguous run -- the local/remote path helpers, the upload and
 * download walkers and `sshclient_scp_transfer` -- moved to
 * `ssh_client_scp.c` unchanged. It shares the context, the buffer sizes and
 * `client_deadline()` with the SFTP half through `ssh_sftp.h`, and it needs
 * only the mode enum and one string helper from the half that stayed.
 *
 * Private to ssh_client.c and ssh_client_scp.c; nothing outside them includes
 * it.
 */

#include <xaios/types.h>

#include "ssh_sftp.h"

/* How long any single protocol exchange may wait. Used by ssh_client.c too. */
#define SSH_CLIENT_TIMEOUT_NS UINT64_C(15000000000)

enum ssh_client_mode {
  SSH_CLIENT_MODE_SHELL = 1,
  SSH_CLIENT_MODE_EXEC = 2,
  SSH_CLIENT_MODE_SCP_UPLOAD = 3,
  SSH_CLIENT_MODE_SCP_DOWNLOAD = 4
};

/* Still in ssh_client.c; the scp half calls it. */
uint32_t sshclient_string_copy(char *output, uint32_t capacity,
                               const char *input);

/* The SCP transfer path, moved to ssh_client_scp.c. */
int sshclient_scp_transfer(ssh_client_context_t *client);

#endif
