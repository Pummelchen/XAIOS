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

#define SETUP_LINE_MAX 128U
#define SETUP_OUTPUT_MAX 8192U
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

static char g_output[SETUP_OUTPUT_MAX];
static char g_pending[2048];
static u64 g_pending_used;

/* ------------------------------------------------------------------ text */

static u64 text_length(const char *text) {
  u64 length = 0ULL;
  while (text[length] != '\0') ++length;
  return length;
}

static void say(const char *text) {
  (void)xaios_console_write(text, text_length(text));
}

static int text_equal(const char *a, const char *b) {
  u64 i = 0ULL;
  while (a[i] != '\0' && a[i] == b[i]) ++i;
  return a[i] == '\0' && b[i] == '\0';
}

static void append(char *out, u64 capacity, u64 *offset, const char *text) {
  for (u64 i = 0ULL; text[i] != '\0'; ++i) {
    if (*offset + 1ULL >= capacity) return;
    out[(*offset)++] = text[i];
  }
  out[*offset] = '\0';
}

/* Collect one "key=value" line for the kernel to act on. */
static void pending_add(const char *key, const char *value) {
  append(g_pending, sizeof(g_pending), &g_pending_used, key);
  append(g_pending, sizeof(g_pending), &g_pending_used, "=");
  append(g_pending, sizeof(g_pending), &g_pending_used, value);
  append(g_pending, sizeof(g_pending), &g_pending_used, "\n");
}

static void append_hex(char *out, u64 capacity, u64 *offset,
                       const unsigned char *bytes, u64 count) {
  static const char digits[] = "0123456789abcdef";
  for (u64 i = 0ULL; i < count; ++i) {
    if (*offset + 2ULL >= capacity) return;
    out[(*offset)++] = digits[(bytes[i] >> 4) & 0x0FU];
    out[(*offset)++] = digits[bytes[i] & 0x0FU];
  }
  out[*offset] = '\0';
}

static void append_u32(char *out, u64 capacity, u64 *offset, u32 value) {
  char digits[12];
  u32 count = 0U;
  if (value == 0U) {
    digits[count++] = '0';
  }
  while (value != 0U) {
    digits[count++] = (char)('0' + (value % 10U));
    value /= 10U;
  }
  while (count != 0U) {
    if (*offset + 1ULL >= capacity) return;
    out[(*offset)++] = digits[--count];
  }
  out[*offset] = '\0';
}

/* ----------------------------------------------------------------- input */

/* Read one line. `mask` suppresses the echo, for a secret being typed in
   front of whoever is standing there. Backspace is handled because a person
   typing a password they cannot see will use it, and a setup routine that
   ignores it produces an account whose password nobody knows. */
static u64 read_line(char *buffer, u64 capacity, int mask) {
  u64 length = 0ULL;
  for (;;) {
    char value = 0;
    if (xaios_console_read(&value) != 1) {
      /* Nothing waiting. There is no yield to make here -- sshd polls the
         same ring the same way -- and setup is a short interactive program
         with nothing else to run. */
      continue;
    }
    if (value == '\r' || value == '\n') {
      say("\n");
      buffer[length] = '\0';
      return length;
    }
    if (value == 0x7F || value == 0x08) {
      if (length != 0ULL) {
        --length;
        if (!mask) say("\b \b");
      }
      continue;
    }
    /* Anything below space is a control code; a setup answer has none, and
       letting them through puts escape sequences into a credential file. */
    if (value < 0x20 || length + 1ULL >= capacity) continue;
    buffer[length++] = value;
    if (mask) {
      say("*");
    } else {
      (void)xaios_console_write(&value, 1ULL);
    }
  }
}

static u64 prompt(const char *question, char *buffer, u64 capacity, int mask) {
  say(question);
  return read_line(buffer, capacity, mask);
}

/* A yes/no question where the default is the safe answer. */
static int prompt_yes(const char *question) {
  char answer[SETUP_LINE_MAX];
  (void)prompt(question, answer, sizeof(answer), 0);
  return answer[0] == 'y' || answer[0] == 'Y';
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
  append(out, capacity, offset, "pbkdf2-sha256:");
  append_u32(out, capacity, offset, SETUP_PBKDF2_ITERATIONS);
  append(out, capacity, offset, ":");
  append_hex(out, capacity, offset, salt, sizeof(salt));
  append(out, capacity, offset, ":");
  append_hex(out, capacity, offset, hash, sizeof(hash));
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
    u64 length = prompt(first_prompt, out, capacity, 1);
    if (length < minimum) {
      say("  Too short.\n");
      continue;
    }
    if (digits_only && !all_digits(out, length)) {
      say("  Digits only.\n");
      continue;
    }
    u64 confirm_length = prompt(second_prompt, again, sizeof(again), 1);
    if (confirm_length != length) {
      say("  They did not match.\n");
      continue;
    }
    u64 i = 0ULL;
    while (i < length && out[i] == again[i]) ++i;
    if (i != length) {
      say("  They did not match.\n");
      continue;
    }
    return (int)length;
  }
}

/* ------------------------------------------------------------- storage */

/* Run one control command and leave its output in g_output.
   `xaios_control_run` parses a whole command line, program name included --
   it rejects anything whose first word is not "xaiosctl" -- so callers pass
   the command from "storage" onwards and this supplies the rest. Discovered
   by having the failure say what it was rather than assuming. */
static int control(const char *command) {
  char line[512];
  u64 offset = 0ULL;
  u64 size = 0ULL;
  g_output[0] = '\0';
  append(line, sizeof(line), &offset, "xaiosctl ");
  append(line, sizeof(line), &offset, command);
  int result = xaios_control_run(line, g_output, sizeof(g_output), &size);
  return result;
}

static void show_disks(void) {
  if (control("storage device list") != 0) {
    say("  Could not list the disks in this machine.\n");
    return;
  }
  say(g_output);
}

/* ---------------------------------------------------------------- steps */

/* The account XAIOS authenticates is named "admin", and that name is not a
   parser detail -- it is threaded through the console session, the SSH
   username check and the remote-login identity. Asking for a name here and
   then writing a record sshd refuses would produce a machine that completes
   setup and still cannot be logged into, which is worse than saying so. */
#define SETUP_ACCOUNT_NAME "admin"

static void step_account(void) {
  char password[SETUP_LINE_MAX];
  char record[512];
  u64 offset = 0ULL;

  say("\n-- Account --\n"
      "The account you will log in with, on this console and over SSH.\n"
      "It is named " SETUP_ACCOUNT_NAME " on this build; only the password is\n"
      "yours to choose.\n\n"
      "Passwords are not shown as you type them, and must be at least eight\n"
      "characters.\n\n");
  int length = read_secret_twice("Password: ", "Repeat password: ", password,
                                 sizeof(password), SETUP_PASSWORD_MIN, 0);

  append(record, sizeof(record), &offset, SETUP_ACCOUNT_NAME);
  append(record, sizeof(record), &offset, ":");
  if (length <= 0 ||
      build_credential(password, (u64)length, record, sizeof(record),
                       &offset) != 0) {
    say("\nCould not create the credential. The account was not made.\n");
    return;
  }

  /* Overwrite the typed password before it sits in memory any longer than the
     hash needed it. */
  for (u64 i = 0ULL; i < sizeof(password); ++i) password[i] = '\0';

  pending_add("user", record);
  for (u64 i = 0ULL; i < sizeof(record); ++i) record[i] = '\0';
  say("\nAccount created.\n");
}

static void step_pin(void) {
  char pin[SETUP_LINE_MAX];
  char record[512];
  u64 offset = 0ULL;

  say("\n-- Quick login --\n"
      "A six digit PIN for this console only. It is never accepted over SSH,\n"
      "and the prompt that takes it is rate limited, because six digits is a\n"
      "small enough space to try exhaustively otherwise.\n\n");
  if (!prompt_yes("Set a quick login PIN? [y/N]: ")) {
    say("No PIN set. The password is the only way in.\n");
    return;
  }

  int length = read_secret_twice("PIN (6 digits): ", "Repeat PIN: ", pin,
                                 sizeof(pin), SETUP_PIN_DIGITS, 1);
  if (length != (int)SETUP_PIN_DIGITS) {
    say("A PIN is exactly six digits. None was set.\n");
    return;
  }
  if (build_credential(pin, (u64)length, record, sizeof(record), &offset) !=
      0) {
    say("Could not create the PIN.\n");
    return;
  }
  append(record, sizeof(record), &offset, "\n");
  for (u64 i = 0ULL; i < sizeof(pin); ++i) pin[i] = '\0';

  pending_add("pin", record);
  for (u64 i = 0ULL; i < sizeof(record); ++i) record[i] = '\0';
  say("Quick login set.\n");
}

static void step_identity(void) {
  char hostname[SETUP_LINE_MAX];

  say("\n-- Name --\n"
      "What this machine calls itself. It appears on the login prompt, so a\n"
      "person in front of a rack can tell which machine they are typing at.\n\n");
  u64 length = prompt("Hostname [xaios]: ", hostname, sizeof(hostname), 0);
  if (length != 0ULL) {
    if (!username_valid(hostname, length)) {
      say("  Use lower-case letters, digits, - or _. Keeping xaios.\n");
    } else {
      pending_add("hostname", hostname);
    }
  }

  /* Report the network rather than offering to configure it. XAIOS takes an
     address by DHCP and has no static configuration to write, so a question
     here would be a question whose answer nothing reads -- worse than not
     asking, because it would look like it had been set. */
  say("\n-- Network --\n");
  u32 address = xaios_net_local_ipv4();
  if (address == 0U) {
    say("No IPv4 address yet. XAIOS asks for one by DHCP as it comes up;\n"
        "if this machine needs a fixed address, that is set on your network\n"
        "rather than here.\n");
  } else {
    say("Address taken by DHCP. XAIOS has no static configuration to set\n"
        "here; a fixed address is a reservation on your network.\n");
  }
}

static void step_install(void) {
  char target[SETUP_LINE_MAX];
  char source[SETUP_LINE_MAX];
  char confirmation[SETUP_LINE_MAX];
  char command[512];
  u64 offset = 0ULL;

  say("\n-- Install --\n"
      "The disks this machine has:\n\n");
  show_disks();

  say("\nInstalling erases the disk you choose, completely.\n"
      "The disk you booted from cannot be chosen.\n\n");
  if (prompt("Disk to install onto (blank to cancel): ", target,
             sizeof(target), 0) == 0ULL) {
    say("Nothing was installed.\n");
    return;
  }

  offset = 0ULL;
  append(command, sizeof(command), &offset, "storage partition verify ");
  append(command, sizeof(command), &offset, target);
  if (control(command) != 0) {
    say("\nThat disk could not be read. Nothing was installed.\n");
    return;
  }
  say("\n");
  say(g_output);

  say("\nThe disk's own identity is shown above as disk_guid. Typing it is\n"
      "what confirms this: it cannot be guessed, so the disk has to have\n"
      "been looked at.\n\n");
  if (prompt("disk_guid: ", confirmation, sizeof(confirmation), 0) == 0ULL) {
    say("Nothing was installed.\n");
    return;
  }
  if (prompt("EFI partition to copy from: ", source, sizeof(source), 0) ==
      0ULL) {
    say("Nothing was installed.\n");
    return;
  }

  offset = 0ULL;
  append(command, sizeof(command), &offset, "storage install ");
  append(command, sizeof(command), &offset, target);
  append(command, sizeof(command), &offset, " from ");
  append(command, sizeof(command), &offset, source);
  append(command, sizeof(command), &offset, " --principal setup");
  append(command, sizeof(command), &offset, " --confirm-device ");
  append(command, sizeof(command), &offset, confirmation);
  append(command, sizeof(command), &offset, " --operation-id 1");

  say("\nInstalling. This writes the partition table, formats the EFI\n"
      "partition and copies the system.\n\n");
  if (control(command) != 0) {
    say(g_output);
    say("\nThe install did not finish. Nothing on the target disk should be\n"
        "relied on; run setup again.\n");
    return;
  }
  say(g_output);
  say("\nInstalled.\n\n"
      "Power the machine off, remove the medium you booted from, and start\n"
      "it again. Setup runs once more on that first boot to make the account,\n"
      "on the disk that will keep it.\n");
}

/* ----------------------------------------------------------------- main */

/* Whether there is anywhere to install to.

   `storage device list` prints one "device=" line per device with a
   "read_only=" field on it. A read-only device is the medium being booted
   from, which is never an install target, so a writable one is what makes the
   question worth asking. Counted from the rendered output rather than
   guessed: the answer differs between a live stick, a netbooted machine and
   an installed one, and getting it wrong offers to erase the wrong thing.

   Offering the choice is all this decides. Which disk, and whether to go
   ahead, are the operator's, and install_to_disk refuses the disk it is
   reading from however this answers. */
static int install_is_possible(void) {
  if (control("storage device list") != 0) {
    /* Say so rather than going quietly to account setup. A machine that could
       have been installed and was never offered the choice looks identical to
       one that had no disk, and the person in front of it cannot tell which
       happened. */
    say("\nThe disks in this machine could not be listed, so installing is\n"
        "not offered here. ");
    say(g_output[0] != '\0' ? g_output : "The storage service gave no reason.\n");
    return 0;
  }
  u64 writable = 0ULL;
  for (u64 i = 0ULL; g_output[i] != '\0'; ++i) {
    if (g_output[i] != 'r') continue;
    const char *marker = "read_only=0";
    u64 j = 0ULL;
    while (marker[j] != '\0' && g_output[i + j] == marker[j]) ++j;
    if (marker[j] == '\0') ++writable;
  }
  return writable != 0ULL ? 1 : 0;
}

int main(void) {
  say("\n"
      "=====================================================\n"
      "  XAIOS setup\n"
      "=====================================================\n\n"
      "This machine has no account yet, so nobody can log in to it.\n"
      "Setting one up takes a minute and happens once.\n");

  int can_install = install_is_possible();
  if (!can_install) {
    say("\nNo disk to install onto was found, so this machine is being set up\n"
        "to run as it booted.\n");
  }
  if (can_install) {
    char choice[SETUP_LINE_MAX];
    say("\nThis system is running from the medium you booted, and there is a\n"
        "disk in the machine.\n\n"
        "  1) Run from this medium\n"
        "     Nothing is written to any disk. Anything you change is lost\n"
        "     when the machine is turned off.\n\n"
        "  2) Install onto a disk\n"
        "     Erases a disk you choose, and puts XAIOS on it to stay.\n\n");
    for (;;) {
      (void)prompt("Choose [1/2]: ", choice, sizeof(choice), 0);
      if (text_equal(choice, "1")) break;
      if (text_equal(choice, "2")) {
        step_install();
        say("\nSetup finished.\n\n");
        xaios_exit(0);
        return 0;
      }
      say("  Answer 1 or 2.\n");
    }
    say("\nRunning from this medium. The account below lasts until the\n"
        "machine is turned off.\n");
  }

  step_identity();
  step_account();
  step_pin();

  /* Hand what was collected to the kernel, which installs it. Nothing was
     saved before this point, so a setup that is interrupted leaves the
     machine exactly as it was rather than half-configured. */
  if (g_pending_used == 0ULL) {
    say("\nNothing to save. This machine still has no account.\n\n");
    xaios_exit(0);
    return 0;
  }
  /* Returns the byte count, not zero, so only a negative result is a
     failure. Reading it as "non-zero means it went wrong" reported every
     successful save as a failure while the save had in fact happened. */
  if (xaios_write_file(SETUP_PENDING_PATH, g_pending) < 0) {
    say("\nCould not save what you entered, so none of it was applied.\n\n");
    xaios_exit(1);
    return 1;
  }
  for (u64 i = 0ULL; i < sizeof(g_pending); ++i) g_pending[i] = '\0';

  say("\nSetup finished. The login prompt follows.\n\n");
  xaios_exit(0);
  return 0;
}
