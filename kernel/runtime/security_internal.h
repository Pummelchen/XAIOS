/*
 * Private interface shared by the translation units of the security policy,
 * after kernel/runtime/security.c was split so no source file exceeds 500
 * lines.
 *
 * security.c keeps the capability and path authorization checks, the
 * credential-material scanner's callers, the denial counters with their
 * accessors, and the boot self-test. The signed-update policy -- the pinned
 * key material, the release key, the last accepted generation and the
 * "xaios-update:v2:" signature grammar -- lives in security_update.c, and the
 * credential field patterns and the two reject entry points that own them
 * live in security_credential.c.
 *
 * Everything that crosses a file boundary is declared here. The names carry
 * the module's security_ prefix because they are new global symbols; the
 * public names in xaios/security.h are unchanged and still defined exactly
 * once.
 *
 * Counter ownership. Every denial counter stays static in security.c, beside
 * the accessors that read it and the self-test that checks it. The other two
 * translation units reach them through the security_note_* seeds below, each
 * of which performs exactly the one atomic increment the unsplit file
 * performed inline, at the same point in the same order. These counters take
 * no lock before or after, so no critical section changes shape.
 */
#ifndef XAIOS_RUNTIME_SECURITY_INTERNAL_H
#define XAIOS_RUNTIME_SECURITY_INTERNAL_H

#include <xaios/security.h>
#include <xaios/status.h>
#include <xaios/types.h>

/* Text primitives shared by the path checks, the credential scanner and the
   update-signature grammar; defined once in security.c. */
int security_starts_with(const char *text, const char *prefix);
int security_contains(const char *text, const char *needle);
uint64_t security_cstr_length(const char *text);

/* Denial logging and the denied-operation total; defined once in security.c. */
xaios_status_t reject_security_operation(const char *reason);

/* Counter seeds, defined once in security.c. Each performs the single atomic
   increment the unsplit file performed inline. */
void security_note_credential_reject(void);
void security_note_signature_reject(void);
void security_note_update_policy_reject(void);
void security_note_key_reject(void);
void security_note_update_replay_reject(void);
void security_note_key_accept(void);
void security_note_signature_accept(void);
void security_note_update_authorization(void);

/* Restore the built-in development release key and forget the last accepted
   update generation; defined once in security_update.c and called from
   security_policy_init() in security.c at the point the unsplit file reset
   those two objects. */
void security_reset_update_key_state(void);

#endif /* XAIOS_RUNTIME_SECURITY_INTERNAL_H */
