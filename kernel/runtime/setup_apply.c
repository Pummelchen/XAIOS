/* Install what /bin/xaios-setup collected, on the boot that collected it.
 *
 * Userspace cannot write /etc. That is deliberate and worth keeping: a
 * process able to rewrite the password file is a process that owns the
 * machine, and security_authorize_fs_write refuses the whole tree, credential
 * paths by name. Setup therefore writes what a person entered to a file under
 * /state, which it is allowed to write, and this moves it into place.
 *
 * The move is only enrolment, never replacement. It runs when the machine has
 * no account at all, which is the one moment where "whoever is at the console"
 * and "whoever this machine belongs to" are the same person. On a machine that
 * already has an account the handoff is deleted unread, so a later process
 * that drops one gains nothing by it.
 *
 * What is handed over is already hashed. Setup does the PBKDF2 with the same
 * code sshd verifies against, so no plaintext password is written anywhere,
 * including here.
 */

#include <xaios/setup_apply.h>

#include <xaios/klog.h>
#include <xaios/remote_login.h>
#include <xaios/xaiboot_fs.h>

#define SETUP_PENDING_PATH "/state/setup-pending"
#define SETUP_USERS_PATH "/etc/xaios_sshd_users"
#define SETUP_PIN_PATH "/etc/xaios_console_pin"
#define SETUP_HOSTNAME_PATH "/etc/xaios_hostname"
#define SETUP_AUTOLOGIN_PATH "/etc/xaios_autologin"
#define SETUP_SERVICES_PATH "/etc/xaios_services"
#define SETUP_PENDING_MAX 2048U

static int text_starts_with(const char *text, uint64_t length,
                            const char *prefix, uint64_t *out_offset) {
  uint64_t i = 0U;
  while (prefix[i] != '\0') {
    if (i >= length || text[i] != prefix[i]) return 0;
    ++i;
  }
  *out_offset = i;
  return 1;
}

/* A credential record is written into a file sshd parses field by field, so
   what may appear in one is exactly what its grammar allows. Anything else --
   a colon that would forge a field, a newline that would forge a record, a
   control byte that would not survive being read back -- is refused, and the
   whole handoff with it rather than the offending line alone: a setup that
   produced one bad record produced it somehow, and installing the rest would
   be acting on a file that is not what it claims to be. */
static int record_is_printable(const char *text, uint64_t length) {
  if (length == 0U) return 0;
  for (uint64_t i = 0U; i < length; ++i) {
    if (text[i] < 0x21 || text[i] > 0x7E) return 0;
  }
  return 1;
}

/* A hostname goes on the login prompt. It may not carry anything that moves
   the cursor or colours the line. */
static int hostname_is_valid(const char *text, uint64_t length) {
  if (length == 0U || length > 32U) return 0;
  for (uint64_t i = 0U; i < length; ++i) {
    char c = text[i];
    int ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
             c == '_';
    if (!ok) return 0;
  }
  return 1;
}

static void discard_pending(void) {
  if (xaiboot_fs_delete(SETUP_PENDING_PATH) != XAIOS_OK) {
    klog("setup: could not remove %s\n", SETUP_PENDING_PATH);
  }
}

void setup_apply_pending(void) {
  xaios_xbfs_stat_t stat;
  if (xaiboot_fs_stat(SETUP_PENDING_PATH, &stat) != XAIOS_OK) return;

  /* Enrolment only. A machine with an account already has an owner, and this
     is not the path by which that changes. */
  xaios_xbfs_stat_t existing;
  if (xaiboot_fs_stat(SETUP_USERS_PATH, &existing) == XAIOS_OK) {
    klog("setup: this machine already has an account; handoff discarded\n");
    discard_pending();
    return;
  }

  char buffer[SETUP_PENDING_MAX];
  uint64_t read_bytes = 0U;
  if (stat.size == 0U || stat.size >= sizeof(buffer) ||
      xaiboot_fs_read(SETUP_PENDING_PATH, buffer, sizeof(buffer) - 1U,
                      &read_bytes) != XAIOS_OK ||
      read_bytes != stat.size) {
    klog("setup: handoff unreadable; nothing applied\n");
    discard_pending();
    return;
  }
  buffer[read_bytes] = '\0';

  /* Parse first, write second. A handoff with one bad line applies none of
     itself: half an account is a machine somebody can log into with a
     password they were not asked to confirm. */
  const char *user = 0;
  uint64_t user_length = 0U;
  const char *pin = 0;
  uint64_t pin_length = 0U;
  const char *hostname = 0;
  uint64_t hostname_length = 0U;
  const char *services = 0;
  uint64_t services_length = 0U;
  int services_seen = 0;
  int autologin = 0;
  int malformed = 0;

  uint64_t start = 0U;
  for (uint64_t i = 0U; i <= read_bytes; ++i) {
    if (i != read_bytes && buffer[i] != '\n') continue;
    uint64_t length = i - start;
    const char *line = buffer + start;
    start = i + 1U;
    if (length == 0U) continue;
    uint64_t value = 0U;
    if (text_starts_with(line, length, "user=", &value)) {
      user = line + value;
      user_length = length - value;
    } else if (text_starts_with(line, length, "pin=", &value)) {
      pin = line + value;
      pin_length = length - value;
    } else if (text_starts_with(line, length, "hostname=", &value)) {
      hostname = line + value;
      hostname_length = length - value;
    } else if (text_starts_with(line, length, "services=", &value)) {
      /* An empty value is a machine told to start none of them, which is a
         real answer and not a missing one. */
      services = line + value;
      services_length = length - value;
      services_seen = 1;
    } else if (text_starts_with(line, length, "autologin=", &value)) {
      /* Only the exact word enables it. Anything else is a handoff that did
         not come from setup, and the safe reading of a value nobody
         recognises is "no". */
      autologin = (length - value == 3U && line[value] == 'y' &&
                   line[value + 1U] == 'e' && line[value + 2U] == 's');
    } else {
      malformed = 1;
    }
  }

  if (malformed != 0 || user == 0 ||
      !record_is_printable(user, user_length) ||
      (pin != 0 && !record_is_printable(pin, pin_length)) ||
      (hostname != 0 && !hostname_is_valid(hostname, hostname_length))) {
    klog("setup: handoff rejected; nothing applied\n");
    discard_pending();
    return;
  }

  /* Written with the trailing newline each file's parser expects. */
  char line[1024];
  uint64_t used = 0U;
  for (uint64_t i = 0U; i < user_length && used + 2U < sizeof(line); ++i) {
    line[used++] = user[i];
  }
  line[used++] = '\n';
  if (xaiboot_fs_write(SETUP_USERS_PATH, line, used) != XAIOS_OK) {
    klog("setup: could not write the account; this machine has none\n");
    discard_pending();
    return;
  }
  /* The command dispatcher caches which account this machine has, and boot
     self-tests filled that cache before this account existed. */
  remote_login_forget_account();
  klog("setup: account installed\n");

  if (pin != 0) {
    used = 0U;
    for (uint64_t i = 0U; i < pin_length && used + 2U < sizeof(line); ++i) {
      line[used++] = pin[i];
    }
    line[used++] = '\n';
    if (xaiboot_fs_write(SETUP_PIN_PATH, line, used) != XAIOS_OK) {
      klog("setup: could not write the quick login PIN\n");
    } else {
      klog("setup: quick login installed\n");
    }
  }

  if (hostname != 0) {
    used = 0U;
    for (uint64_t i = 0U; i < hostname_length && used + 2U < sizeof(line);
         ++i) {
      line[used++] = hostname[i];
    }
    line[used++] = '\n';
    if (xaiboot_fs_write(SETUP_HOSTNAME_PATH, line, used) != XAIOS_OK) {
      klog("setup: could not write the hostname\n");
    }
  }

  if (services_seen != 0) {
    used = 0U;
    for (uint64_t i = 0U; i < services_length && used + 2U < sizeof(line);
         ++i) {
      char c = services[i];
      /* Names only, and the separator between them. */
      int ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
               c == '_' || c == ',';
      if (!ok) { used = 0U; break; }
      line[used++] = c;
    }
    line[used++] = '\n';
    if (xaiboot_fs_write(SETUP_SERVICES_PATH, line, used) != XAIOS_OK) {
      klog("setup: could not record which services to start\n");
    } else {
      klog("setup: services recorded bytes=%lu\n", used);
    }
  }

  if (autologin != 0) {
    static const char enabled[] = "yes\n";
    if (xaiboot_fs_write(SETUP_AUTOLOGIN_PATH, enabled,
                         sizeof(enabled) - 1U) != XAIOS_OK) {
      klog("setup: could not enable automatic login\n");
    } else {
      klog("setup: automatic console login enabled\n");
    }
  }

  discard_pending();
}
