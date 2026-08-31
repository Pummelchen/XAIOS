#ifndef XAIOS_SETUP_APPLY_H
#define XAIOS_SETUP_APPLY_H

/* Install the account /bin/xaios-setup collected, if it collected one.

   Called once, after setup returns and before sshd starts. Does nothing when
   there is no handoff, and refuses one on a machine that already has an
   account. */
void setup_apply_pending(void);

#endif
