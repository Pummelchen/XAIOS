# The same credential policy the other builder enforces, because the rule is
# about what an image is allowed to carry and not about which machine it runs
# on. Without it this architecture would accept a packaged password record
# that AArch64 and x86-64 refuse -- which is the kind of gap that only shows
# up when someone ships from the wrong builder.
BUILD_MODE="${XAIOS_BUILD_MODE:-development}"
case "$BUILD_MODE" in
  development|release) ;;
  *)
    printf '%s\n' "error: XAIOS_BUILD_MODE must be development or release" >&2
    exit 2 ;;
esac
SSH_USERS_FILE="${XAIOS_SSH_USERS_FILE:-}"
# "none" asks for a development image that packages no account, so the first
# boot runs setup exactly as a release image does. The other builder has taken
# it since setup existed; this one treated it as the *name of a file*, so the
# credential policy demanded a password switch for an image that was asking
# for no credential at all -- and the setup gate could not be run here.
if [ "$SSH_USERS_FILE" = "none" ]; then
  SSH_USERS_FILE=""
fi
if [ "$SSH_USERS_FILE" != "" ]; then
  if [ "${XAIOS_SSH_PASSWORD_AUTH:-}" != "1" ] && \
     [ "$SSH_USERS_FILE" != "$ROOT_DIR/config/development-sshd-users" ]; then
    printf '%s\n' \
      "error: password credentials require XAIOS_SSH_PASSWORD_AUTH=1" >&2
    exit 2
  fi
  if [ "$BUILD_MODE" = release ]; then
    printf '%s\n' \
      "error: a release image must not package a password credential." \
      "       Password support is compiled in and /bin/xaios-setup creates" \
      "       the account on first boot; a packaged record would be a" \
      "       credential every copy of the download shares." >&2
    exit 2
  fi
elif [ "${XAIOS_SSH_PASSWORD_AUTH:-0}" != "0" ]; then
  printf '%s\n' \
    "error: XAIOS_SSH_PASSWORD_AUTH requires XAIOS_SSH_USERS_FILE" >&2
  exit 2
fi
