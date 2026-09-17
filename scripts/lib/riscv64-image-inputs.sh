# The development account, so the machine has something to log into and the
# boot does not stop at a setup prompt with nobody standing in front of it.
# Development only: a release medium packages no credential anybody outside
# the build has, and setup makes one on first boot instead.
CREDENTIAL_ARGS=""
if [ "$SSH_USERS_FILE" != "" ]; then
  # A caller's own account list wins over the development one. A gate that
  # mints a credential and then expects to log in with it has to be able to
  # put that credential in the image; without this it could reach two
  # machines out of three and the third refused the password it was given.
  if [ ! -f "$SSH_USERS_FILE" ]; then
    printf '%s\n' "error: SSH users file not found: $SSH_USERS_FILE" >&2
    exit 1
  fi
  CREDENTIAL_ARGS="/etc/xaios_sshd_users=$SSH_USERS_FILE"
  CREDENTIAL_ARGS="$CREDENTIAL_ARGS /etc/xaios_console_pin=$ROOT_DIR/config/development-console-pin"
elif [ "${XAIOS_SSH_USERS_FILE:-}" != "none" ] && \
     [ "${XAIOS_RISCV64_MODE:-development}" = development ]; then
  CREDENTIAL_ARGS="/etc/xaios_sshd_users=$ROOT_DIR/config/development-sshd-users"
  CREDENTIAL_ARGS="$CREDENTIAL_ARGS /etc/xaios_console_pin=$ROOT_DIR/config/development-console-pin"
fi

# A public key the SSH server will accept, when a caller supplies one. The
# other builder has taken this since sshd grew key authentication; this one
# had not, so every gate that logs in with a key it generated itself could
# reach two machines out of three.
AUTHORIZED_KEYS_ARGS=""
if [ "${XAIOS_AUTHORIZED_KEYS_FILE:-}" != "" ]; then
  if [ ! -f "$XAIOS_AUTHORIZED_KEYS_FILE" ]; then
    printf '%s\n' \
      "error: authorized keys file not found: $XAIOS_AUTHORIZED_KEYS_FILE" >&2
    exit 1
  fi
  AUTHORIZED_KEYS_ARGS="/etc/xaios_authorized_keys=$XAIOS_AUTHORIZED_KEYS_FILE"
fi

# A private key this machine dials *out* with, when a caller supplies one.
#
# The other builder has taken this for as long as the guest has had an SSH
# client. Without it a RISC-V guest can be logged into and cannot log into
# anything, which is half a network stack -- and it is the half the
# bidirectional interoperability suite is entirely about.
CLIENT_IDENTITY_ARGS=""
if [ "${XAIOS_SSH_CLIENT_IDENTITY_FILE:-}" != "" ]; then
  if [ ! -f "$XAIOS_SSH_CLIENT_IDENTITY_FILE" ]; then
    printf '%s\n' \
      "error: SSH client identity not found: $XAIOS_SSH_CLIENT_IDENTITY_FILE" \
      >&2
    exit 1
  fi
  CLIENT_IDENTITY_ARGS="/etc/xaios_ssh_client_identity=$XAIOS_SSH_CLIENT_IDENTITY_FILE"
fi
