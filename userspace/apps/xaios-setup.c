/* First-boot setup: what a person does with a machine that has no account yet.
 *
 * XAIOS reaches a login prompt and asks for a username. On a machine nobody
 * has set up, that prompt is a dead end -- there is no account to give it,
 * and the only way one ever appeared was for a build to package a credential,
 * which is exactly what a release image must not do. So the machine has to be
 * able to make one, and this is where that happens.
 *
 * It runs before sshd, and only when there is no user database, which is the
 * same question as "has anyone set this machine up". That makes it invisible
 * on a machine that is already configured, and on every gate image, which
 * package credentials and therefore never reach it.
 *
 * The console is a shared ring: whoever reads it gets the keystroke. Only one
 * program may drive it at a time, which is why this runs to completion and
 * exits before sshd starts rather than living beside it.
 *
 * Two situations arrive here and they want different things:
 *
 *   Booted from media, with a disk in the machine. The person either wants to
 *   look at the machine without touching it, or wants XAIOS on that disk.
 *   Both are offered; neither is assumed.
 *
 *   Booted from a disk XAIOS was just installed onto. There is nothing to
 *   choose -- the machine is already where it is going to live -- so it goes
 *   straight to making the account.
 */

#include <xaios_user.h>
#include <xaios_control_client.h>
#include <ssh_crypto.h>
#include "xaios-setup-internal.h"

/* Matches what sshd's parser accepts and what the development records use.
   A different figure here would produce credentials this system rejects. */
#define SETUP_PBKDF2_ITERATIONS 200000U
#define SETUP_SALT_BYTES 16U
#define SETUP_PIN_DIGITS 6U
#define SETUP_PASSWORD_MIN 8U

/* Setup does not write /etc. It cannot: userspace may write only /tmp, /home,
   /apps, /state, /logs and /update, and credential paths are refused by name.
   That rule is worth keeping -- a process that can rewrite the password file
   is a process that owns the machine -- so setup writes what it collected to
   its own file under /state, and the kernel installs it.

   The kernel does that only when the machine has no account, which is the
   only moment this is enrolment rather than a way to replace someone else's
   credentials. */
/* Flat under /state, not /state/setup/: a write needs its parent directory to
   exist already, and nothing creates that one. */
#define SETUP_PENDING_PATH "/state/setup-pending"

static char g_pending[2048];
static u64 g_pending_used;

/* ------------------------------------------------------------- collected */

/* Collect one "key=value" line for the kernel to act on. */
static void pending_add(const char *key, const char *value) {
  xsetup_append(g_pending, sizeof(g_pending), &g_pending_used, key);
  xsetup_append(g_pending, sizeof(g_pending), &g_pending_used, "=");
  xsetup_append(g_pending, sizeof(g_pending), &g_pending_used, value);
  xsetup_append(g_pending, sizeof(g_pending), &g_pending_used, "\n");
}

/* --------------------------------------------------------- credentials */

static int all_digits(const char *text, u64 length) {
  if (length == 0ULL) return 0;
  for (u64 i = 0ULL; i < length; ++i) {
    if (text[i] < '0' || text[i] > '9') return 0;
  }
  return 1;
}

static int username_valid(const char *name, u64 length) {
  if (length == 0ULL || length > 32ULL) return 0;
  for (u64 i = 0ULL; i < length; ++i) {
    char c = name[i];
    int ok = (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' ||
             c == '_';
    /* A colon would end the field and let a typed name forge the rest of the
       record. Rejecting the whole class is cheaper than escaping it. */
    if (!ok) return 0;
  }
  return 1;
}

/* Build "pbkdf2-sha256:<iterations>:<salt>:<hash>", the record sshd parses.
   The salt is fresh per credential: two machines set up with the same
   password must not produce the same record, or one hash covers both. */
static int build_credential(const char *secret, u64 secret_length, char *out,
                            u64 capacity, u64 *offset) {
  unsigned char salt[SETUP_SALT_BYTES];
  unsigned char hash[32];
  if (xaios_random(salt, sizeof(salt)) != 0) return -1;
  if (pbkdf2_hmac_sha256((const unsigned char *)secret, (u32)secret_length,
                         salt, (u32)sizeof(salt), SETUP_PBKDF2_ITERATIONS,
                         hash) != 0) {
    return -1;
  }
  xsetup_append(out, capacity, offset, "pbkdf2-sha256:");
  xsetup_append_u32(out, capacity, offset, SETUP_PBKDF2_ITERATIONS);
  xsetup_append(out, capacity, offset, ":");
  xsetup_append_hex(out, capacity, offset, salt, sizeof(salt));
  xsetup_append(out, capacity, offset, ":");
  xsetup_append_hex(out, capacity, offset, hash, sizeof(hash));
  return 0;
}

/* Ask for a secret twice and only accept it when both agree. Typing a
   password blind and getting it wrong once produces a machine nobody can log
   into, which on an installed system means reinstalling it. */
static int read_secret_twice(const char *first_prompt,
                             const char *second_prompt, char *out,
                             u64 capacity, u64 minimum, int digits_only) {
  char again[SETUP_LINE_MAX];
  for (;;) {
    u64 length = xsetup_prompt(first_prompt, out, capacity, 1);
    if (length < minimum) {
      xsetup_say("  Too short.\n");
      continue;
    }
    if (digits_only && !all_digits(out, length)) {
      xsetup_say("  Digits only.\n");
      continue;
    }
    u64 confirm_length = xsetup_prompt(second_prompt, again, sizeof(again), 1);
    if (confirm_length != length) {
      xsetup_say("  They did not match.\n");
      continue;
    }
    u64 i = 0ULL;
    while (i < length && out[i] == again[i]) ++i;
    if (i != length) {
      xsetup_say("  They did not match.\n");
      continue;
    }
    return (int)length;
  }
}

/* ---------------------------------------------------------------- steps */

static void step_account(void) {
  char username[SETUP_LINE_MAX];
  char password[SETUP_LINE_MAX];
  char record[512];
  u64 offset = 0ULL;

  xsetup_say("\n-- Account --\n"
             "The account you will log in with, on this console and over SSH.\n\n");
  for (;;) {
    u64 length = xsetup_prompt("Username: ", username, sizeof(username), 0);
    if (username_valid(username, length)) break;
    xsetup_say("  Use lower-case letters, digits, - or _, up to 32 characters.\n");
  }

  xsetup_say("\nPasswords are not shown as you type them, and must be at least\n"
             "eight characters.\n\n");
  int length = read_secret_twice("Password: ", "Repeat password: ", password,
                                 sizeof(password), SETUP_PASSWORD_MIN, 0);

  xsetup_append(record, sizeof(record), &offset, username);
  xsetup_append(record, sizeof(record), &offset, ":");
  if (length <= 0 ||
      build_credential(password, (u64)length, record, sizeof(record),
                       &offset) != 0) {
    xsetup_say("\nCould not create the credential. The account was not made.\n");
    return;
  }

  /* Overwrite the typed password before it sits in memory any longer than the
     hash needed it. */
  for (u64 i = 0ULL; i < sizeof(password); ++i) password[i] = '\0';

  pending_add("user", record);
  for (u64 i = 0ULL; i < sizeof(record); ++i) record[i] = '\0';
  xsetup_say("\nAccount created.\n");
}

static void step_pin(void) {
  char pin[SETUP_LINE_MAX];
  char record[512];
  u64 offset = 0ULL;

  xsetup_say("\n-- Quick login --\n"
             "A six digit PIN for this console only. It is never accepted over SSH,\n"
             "and the prompt that takes it is rate limited, because six digits is a\n"
             "small enough space to try exhaustively otherwise.\n\n");
  if (!xsetup_prompt_yes("Set a quick login PIN? [y/N]: ")) {
    xsetup_say("No PIN set. The password is the only way in.\n");
    return;
  }

  int length = read_secret_twice("PIN (6 digits): ", "Repeat PIN: ", pin,
                                 sizeof(pin), SETUP_PIN_DIGITS, 1);
  if (length != (int)SETUP_PIN_DIGITS) {
    xsetup_say("A PIN is exactly six digits. None was set.\n");
    return;
  }
  if (build_credential(pin, (u64)length, record, sizeof(record), &offset) !=
      0) {
    xsetup_say("Could not create the PIN.\n");
    return;
  }
  xsetup_append(record, sizeof(record), &offset, "\n");
  for (u64 i = 0ULL; i < sizeof(pin); ++i) pin[i] = '\0';

  pending_add("pin", record);
  for (u64 i = 0ULL; i < sizeof(record); ++i) record[i] = '\0';
  xsetup_say("Quick login set.\n");
}

/* Which background services this machine starts.

   Only remote access is selectable today. The console is not offered as a
   choice: it is how a person reaches a machine whose network is wrong, and a
   switch that turns it off can strand a machine nobody can reach. The
   machine's other background work is not optional either, so listing it here
   as though it were would be a menu that does nothing.

   Written as an enabled list, so a service added later is off until a machine
   is told to run it rather than appearing on machines already in service. */
static void step_services(void) {
  xsetup_say("\n-- Background services --\n"
             "The console is always available. What is optional is whether this\n"
             "machine answers on the network.\n\n");
  if (xsetup_prompt_yes("Allow logging in over SSH? [Y/n]: ") ||
      !xsetup_prompt_yes("Are you sure you want SSH off? [y/N]: ")) {
    pending_add("services", "ssh");
    xsetup_say("Remote access enabled.\n");
    return;
  }
  pending_add("services", "");
  xsetup_say("Remote access off. The console will be the only way into this\n"
             "machine, so do not lose access to it.\n");
}

/* Skipping the login prompt on this machine.

   Worth being blunt about: the console is a physical thing, and a machine
   that opens a shell without asking gives one to whoever is standing at it.
   That is a reasonable trade for an appliance in a locked rack and a bad one
   for a laptop, and only the person setting it up knows which this is. So the
   question says what it costs and the default is no.

   It does not touch SSH. A remote login still authenticates; this is the
   local console only, which is the one an attacker has to be present to
   use. */
static void step_autologin(void) {
  xsetup_say("\n-- Automatic login --\n"
             "This machine can skip the console login prompt and open a shell when\n"
             "it finishes booting, with its background services started.\n\n"
             "Anyone who can reach the keyboard then has that shell, without the\n"
             "password or the PIN. SSH is unaffected and still authenticates.\n\n");
  if (!xsetup_prompt_yes("Log in automatically on this console? [y/N]: ")) {
    xsetup_say("The login prompt stays. This is the safer answer.\n");
    return;
  }
  pending_add("autologin", "yes");
  xsetup_say("Automatic login enabled. The password and PIN still work over SSH and\n"
             "after logging out.\n");
}

static void step_identity(void) {
  char hostname[SETUP_LINE_MAX];

  xsetup_say("\n-- Name --\n"
             "What this machine calls itself. It appears on the login prompt, so a\n"
             "person in front of a rack can tell which machine they are typing at.\n\n");
  u64 length = xsetup_prompt("Hostname [xaios]: ", hostname, sizeof(hostname), 0);
  if (length != 0ULL) {
    if (!username_valid(hostname, length)) {
      xsetup_say("  Use lower-case letters, digits, - or _. Keeping xaios.\n");
    } else {
      pending_add("hostname", hostname);
    }
  }

  /* Report the network rather than offering to configure it. XAIOS takes an
     address by DHCP and has no static configuration to write, so a question
     here would be a question whose answer nothing reads -- worse than not
     asking, because it would look like it had been set. */
  xsetup_say("\n-- Network --\n");
  u32 address = xaios_net_local_ipv4();
  if (address == 0U) {
    xsetup_say("No IPv4 address yet. XAIOS asks for one by DHCP as it comes up;\n"
               "if this machine needs a fixed address, that is set on your network\n"
               "rather than here.\n");
  } else {
    xsetup_say("Address taken by DHCP. XAIOS has no static configuration to set\n"
               "here; a fixed address is a reservation on your network.\n");
  }
}

/* ----------------------------------------------------------------- main */

int main(void) {
  xsetup_say("\n"
             "=====================================================\n"
             "  XAIOS setup\n"
             "=====================================================\n\n"
             "This machine has no account yet, so nobody can log in to it.\n"
             "Setting one up takes a minute and happens once.\n");

  int can_install = xsetup_install_is_possible();
  if (!can_install) {
    xsetup_say("\nNo disk to install onto was found, so this machine is being set up\n"
               "to run as it booted.\n");
  }
  if (can_install) {
    char choice[SETUP_LINE_MAX];
    xsetup_say("\nThis system is running from the medium you booted, and there is a\n"
               "disk in the machine.\n\n"
               "  1) Run from this medium\n"
               "     Nothing is written to any disk. Anything you change is lost\n"
               "     when the machine is turned off.\n\n"
               "  2) Install onto a disk\n"
               "     Erases a disk you choose, and puts XAIOS on it to stay.\n\n");
    for (;;) {
      (void)xsetup_prompt("Choose [1/2]: ", choice, sizeof(choice), 0);
      if (xsetup_text_equal(choice, "1")) break;
      if (xsetup_text_equal(choice, "2")) {
        xsetup_step_install();
        xsetup_say("\nSetup finished.\n\n");
        xaios_exit(0);
        return 0;
      }
      xsetup_say("  Answer 1 or 2.\n");
    }
    xsetup_say("\nRunning from this medium. The account below lasts until the\n"
               "machine is turned off.\n");
  }

  step_identity();
  step_account();
  step_pin();
  step_services();
  step_autologin();

  /* Hand what was collected to the kernel, which installs it. Nothing was
     saved before this point, so a setup that is interrupted leaves the
     machine exactly as it was rather than half-configured. */
  if (g_pending_used == 0ULL) {
    xsetup_say("\nNothing to save. This machine still has no account.\n\n");
    xaios_exit(0);
    return 0;
  }
  /* Returns the byte count, not zero, so only a negative result is a
     failure. Reading it as "non-zero means it went wrong" reported every
     successful save as a failure while the save had in fact happened. */
  if (xaios_write_file(SETUP_PENDING_PATH, g_pending) < 0) {
    xsetup_say("\nCould not save what you entered, so none of it was applied.\n\n");
    xaios_exit(1);
    return 1;
  }
  for (u64 i = 0ULL; i < sizeof(g_pending); ++i) g_pending[i] = '\0';

  xsetup_say("\nSetup finished. The login prompt follows.\n\n");
  xaios_exit(0);
  return 0;
}
