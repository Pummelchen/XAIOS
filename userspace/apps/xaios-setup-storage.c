/* The storage and ESP preparation layer of setup.
 *
 * Split out of xaios-setup.c for the file-size budget: this is everything that
 * asks the control plane about the machine's disks and everything that writes
 * a chosen one -- listing devices, deciding whether installing is offered at
 * all, and the install that copies the partition this machine booted from.
 * xaios-setup.c keeps the interactive steps and main; the private interface is
 * xaios-setup-internal.h.
 *
 * One control command's rendered output is held in g_output between the call
 * that fills it and the say() that shows it, which is the same file-scope
 * buffer the original file kept -- now owned by the only code that renders
 * into it, and never handed out.
 */

#include <xaios_user.h>
#include <xaios_control_client.h>
#include "xaios-setup-internal.h"

static char g_output[SETUP_OUTPUT_MAX];

/* ------------------------------------------------------------- storage */

/* Run one control command and leave its output in g_output.
   `xaios_control_run` parses a whole command line, program name included --
   it rejects anything whose first word is not "xaiosctl" -- so callers pass
   the command from "storage" onwards and this supplies the rest. Discovered
   by having the failure say what it was rather than assuming. */
static int xsetup_control(const char *command) {
  char line[512];
  u64 offset = 0ULL;
  u64 size = 0ULL;
  g_output[0] = '\0';
  xsetup_append(line, sizeof(line), &offset, "xaiosctl ");
  xsetup_append(line, sizeof(line), &offset, command);
  /* As an administrator, and saying who is asking.

     xaios_control_run runs as "local-observer" with the observer role, which
     can read but cannot partition a disk -- and the actor is not something a
     --principal flag sets: that flag names the principal being *managed* by
     an auth command, which is a different field entirely. Passing it and
     expecting the install to be authorised is how this first failed, with the
     client reporting a missing principal for a command that carried one.

     "setup" is the actor recorded in the audit trail, which is what should
     appear against a partition table written before the machine had a
     person. */
  int result = xaios_control_run_as(line, XAIOS_CONTROL_ROLE_ADMIN, "setup",
                                    g_output, sizeof(g_output), &size);
  return result;
}

static void xsetup_show_disks(void) {
  if (xsetup_control("storage device list") != 0) {
    xsetup_say("  Could not list the disks in this machine.\n");
    return;
  }
  xsetup_say(g_output);
}

void xsetup_step_install(void) {
  char target[SETUP_LINE_MAX];
  char source[SETUP_LINE_MAX];
  char confirmation[SETUP_LINE_MAX];
  char command[512];
  u64 offset = 0ULL;

  xsetup_say("\n-- Install --\n"
             "The disks this machine has:\n\n");
  xsetup_show_disks();

  xsetup_say("\nInstalling erases the disk you choose, completely.\n"
             "The disk you booted from cannot be chosen.\n\n");
  if (xsetup_prompt("Disk to install onto (blank to cancel): ", target,
                    sizeof(target), 0) == 0ULL) {
    xsetup_say("Nothing was installed.\n");
    return;
  }

  offset = 0ULL;
  xsetup_append(command, sizeof(command), &offset, "storage partition verify ");
  xsetup_append(command, sizeof(command), &offset, target);
  if (xsetup_control(command) != 0) {
    xsetup_say("\nThat disk could not be read. Nothing was installed.\n");
    return;
  }
  xsetup_say("\n");
  xsetup_say(g_output);

  xsetup_say("\nThe disk's own identity is shown above as disk_guid. Typing it is\n"
             "what confirms this: it cannot be guessed, so the disk has to have\n"
             "been looked at.\n\n");
  if (xsetup_prompt("disk_guid: ", confirmation, sizeof(confirmation), 0) ==
      0ULL) {
    xsetup_say("Nothing was installed.\n");
    return;
  }
  /* The partition this machine booted, which is what an install copies. The
     kernel records it because only the kernel knows it, and a person should
     not have to work it out from a list of block devices. */
  char boot_esp[SETUP_LINE_MAX];
  int esp_length = xaios_read_file("/state/boot-esp", boot_esp,
                                   sizeof(boot_esp) - 1U);
  u64 esp_used = 0ULL;
  if (esp_length > 0) {
    while (esp_used < (u64)esp_length && boot_esp[esp_used] > 0x20) ++esp_used;
  }
  boot_esp[esp_used] = '\0';

  if (esp_used != 0ULL) {
    xsetup_say("\nCopying from ");
    xsetup_say(boot_esp);
    xsetup_say(", the partition this machine booted.\n");
    xsetup_say("Press enter to accept it, or name another.\n\n");
  } else {
    xsetup_say("\nThis machine did not boot from an EFI System Partition, so there\n"
               "is nothing here to copy. An install needs media that has one.\n\n");
  }
  u64 typed =
      xsetup_prompt("EFI partition to copy from: ", source, sizeof(source), 0);
  if (typed == 0ULL) {
    if (esp_used == 0ULL) {
      xsetup_say("Nothing was installed.\n");
      return;
    }
    for (u64 i = 0ULL; i <= esp_used; ++i) source[i] = boot_esp[i];
  }

  offset = 0ULL;
  xsetup_append(command, sizeof(command), &offset, "storage install ");
  xsetup_append(command, sizeof(command), &offset, target);
  xsetup_append(command, sizeof(command), &offset, " from ");
  xsetup_append(command, sizeof(command), &offset, source);
  xsetup_append(command, sizeof(command), &offset, " --confirm-device ");
  xsetup_append(command, sizeof(command), &offset, confirmation);
  xsetup_append(command, sizeof(command), &offset, " --operation-id 1");

  xsetup_say("\nInstalling. This writes the partition table, formats the EFI\n"
             "partition and copies the system.\n\n");
  if (xsetup_control(command) != 0) {
    xsetup_say(g_output);
    xsetup_say("\nThe install did not finish. Nothing on the target disk should be\n"
               "relied on; run setup again.\n");
    return;
  }
  xsetup_say(g_output);
  xsetup_say("\nInstalled.\n\n"
             "Power the machine off, remove the medium you booted from, and start\n"
             "it again. Setup runs once more on that first boot to make the account,\n"
             "on the disk that will keep it.\n");
}

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
int xsetup_install_is_possible(void) {
  if (xsetup_control("storage device list") != 0) {
    /* Say so rather than going quietly to account setup. A machine that could
       have been installed and was never offered the choice looks identical to
       one that had no disk, and the person in front of it cannot tell which
       happened. */
    xsetup_say("\nThe disks in this machine could not be listed, so installing is\n"
               "not offered here. ");
    xsetup_say(g_output[0] != '\0' ? g_output
                                   : "The storage service gave no reason.\n");
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
