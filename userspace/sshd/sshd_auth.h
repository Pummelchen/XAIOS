#ifndef SSHD_AUTH_H
#define SSHD_AUTH_H

/*
 * Declarations shared between sshd.c, sshd_auth.c and sshd_keys.c.
 *
 * These are private to the server, like sshd_internal.h: sshd.h stays the
 * public header for callers outside this directory. The credential checks --
 * the password user database, the local console PIN and the console lockout --
 * live in sshd_auth.c; the authorized-key store and its generation-keyed cache
 * live in sshd_keys.c. sshd.c keeps the console login state machine and
 * process_connection(), which call into both.
 *
 * No accessor here returns a pointer into module state. sshd_auth_account_name()
 * and sshd_keys_lookup() copy into a buffer or struct the caller owns, so no
 * pointer into the user table or the key table can outlive the call that took
 * it. sshd.c's console session name buffer stays its own.
 */

#include <stdint.h>
#include <xaios_user.h>

#include "sshd.h"

#ifndef XAIOS_PASSWORD_AUTH_AVAILABLE
#define XAIOS_PASSWORD_AUTH_AVAILABLE 0
#endif

/*
 * From sshd.c. The durable-volume helpers the runtime-config reader and the
 * authorized-key loader both use: an exact-size read, and the checksum fold
 * over a record with one field zeroed. They are defined once, in the parent,
 * and exported here rather than duplicated in the modules that split out.
 */
uint64_t sshd_fnv1a64_zero_range(const void *data, uint64_t size,
                                 uint64_t zero_offset, uint64_t zero_size);
int sshd_read_exact_file(const char *path, void *buffer, uint64_t size);

/*
 * From sshd_auth.c: the password user database, the password and PIN checks,
 * and the console lockout. The loaders take the "password authentication is
 * enabled" decision as an argument because it is sshd.c's
 * load_runtime_config() that owns it.
 */
int sshd_auth_load_users(uint32_t password_auth_enabled);
int sshd_auth_load_pin(uint32_t password_auth_enabled);
uint32_t sshd_auth_user_count(void);
int sshd_auth_user_exists(const char *username);
int sshd_auth_password_verify(const char *username, const char *password);
uint32_t sshd_auth_account_name(char *out, uint32_t capacity);

/* Nonzero while a local console PIN record was loaded. A value, not the parsed
   credential: the salt and hash stay in the module. */
int sshd_auth_pin_available(void);
int sshd_auth_pin_verify(const char *pin);
int sshd_auth_pin_prefix(const char *text, uint32_t length);
int sshd_auth_pin_matches(const char *text, uint32_t length);

/* The console lockout policy. sshd.c's console_auth_failed() and
   console_submit_auth() drive it; the counters and the clock compare live
   here. sshd_auth_console_locked_out() clears an expired lockout as it
   reports one, exactly as the in-sshd.c original did. */
int sshd_auth_console_locked_out(void);
int sshd_auth_console_lockout_active(void);
void sshd_auth_console_record_failure(void);
void sshd_auth_console_clear_failures(void);

/*
 * From sshd_keys.c: the authorized-key table and its cache. sshd_keys_entry_t
 * is the copy a lookup hands back -- the fields process_connection() needs to
 * fill in the connection's principal -- not a handle on the table.
 */
typedef struct {
  uint8_t key[32];
  uint8_t fingerprint[32];
  char principal[XAIOS_ADMIN_PRINCIPAL_MAX];
  uint32_t role;
} sshd_keys_entry_t;

/* Parse an ssh-ed25519 public-key blob (the wire format) into a 32-byte key. */
int sshd_keys_blob_parse(const uint8_t *blob, uint32_t blob_len,
                         uint8_t key[32]);

/* Load or revalidate the keys. Returns 0 when at least one key is available. */
int sshd_keys_load(void);

/* Copy the active key matching `pubkey` into `out`. Returns 0 on a match, -1
   when no active key matches. `out` is copied only on a match. */
int sshd_keys_lookup(const uint8_t *pubkey, sshd_keys_entry_t *out);

/* Nonzero when the managed key database was present but rejected. */
int sshd_keys_database_invalid(void);

/* The loader's share of the durable cost, for log_durable_cost(). */
void sshd_keys_load_stats(uint32_t *calls, uint32_t *file_reads, uint64_t *ns);

#endif /* SSHD_AUTH_H */
