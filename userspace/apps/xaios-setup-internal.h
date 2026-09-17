#ifndef XAIOS_APPS_XAIOS_SETUP_INTERNAL_H
#define XAIOS_APPS_XAIOS_SETUP_INTERNAL_H

/*
 * Private interface between xaios-setup.c and the two modules split out of it
 * for the file-size budget.
 *
 * xaios-setup-console.c owns the text formatters and the interactive prompt
 * layer: it writes to the console ring and reads keystrokes back, including
 * the masked read a password or a PIN is typed into. xaios-setup-storage.c
 * owns the control-plane queries that list this machine's disks, the decision
 * whether installing is offered at all, and the copy that writes a chosen
 * disk from the partition this machine booted. xaios-setup.c keeps what a
 * person is asked and what is collected for the kernel: the account, the PIN,
 * the services, the identity, and main.
 *
 * Setup is one ELF built by the generic app loop in
 * scripts/lib/user-apps.sh and scripts/lib/riscv64-user-apps.sh; the two
 * modules are extra objects on this app's link list, not applications of
 * their own, and nothing declared here is part of any image ABI.
 */

#include <xaios_user.h>

/* Shared limits. SETUP_LINE_MAX is the capacity of a typed answer;
   SETUP_OUTPUT_MAX is the capacity of one control command's rendered
   output. */
#define SETUP_LINE_MAX 128U
#define SETUP_OUTPUT_MAX 8192U

/* xaios-setup-console.c */
void xsetup_say(const char *text);
int xsetup_text_equal(const char *a, const char *b);
void xsetup_append(char *out, u64 capacity, u64 *offset, const char *text);
void xsetup_append_hex(char *out, u64 capacity, u64 *offset,
                       const unsigned char *bytes, u64 count);
void xsetup_append_u32(char *out, u64 capacity, u64 *offset, u32 value);
u64 xsetup_prompt(const char *question, char *buffer, u64 capacity, int mask);
int xsetup_prompt_yes(const char *question);

/* xaios-setup-storage.c */
void xsetup_step_install(void);
int xsetup_install_is_possible(void);

#endif /* XAIOS_APPS_XAIOS_SETUP_INTERNAL_H */
