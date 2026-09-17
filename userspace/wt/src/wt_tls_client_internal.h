/* The declarations shared across the TLS 1.3 client handshake's modules.
 *
 * `wt_tls_client.c` holds the public state machine: the accessors, the
 * ClientHello, the dispatcher, and the small helpers every message handler
 * needs. The RFC 8446 message handlers live in `wt_tls_client_messages.c` and
 * the client's response flight with the server's Finished in
 * `wt_tls_client_finish.c`, and both files include this one. Nothing here is
 * part of the module's public interface -- `wt_tls_client.h` is -- and no
 * caller outside `userspace/wt/src/` has a reason to include it.
 *
 * Three things cross the cut and so are defined exactly once, in
 * `wt_tls_client.c`: the refusal helper every handler returns through, the
 * key-availability bit that ServerHello and Finished both set, and the two
 * list-membership checks the ServerHello, EncryptedExtensions and
 * CertificateVerify handlers need. Each keeps the module's prefix because a
 * `static` symbol that now crosses a translation unit has to be named like
 * what it is.
 */

#ifndef WT_TLS_CLIENT_INTERNAL_H
#define WT_TLS_CLIENT_INTERNAL_H

#include <stddef.h>
#include <stdint.h>

#include "wt_tls_client.h"

/* Fail the handshake, with the alert RFC 8446 section 6.2 names for this
 * refusal and a reason a human can act on. Always returns -1 so handlers can
 * `return wt_tls_client_fail(...)`. */
int wt_tls_client_fail(wt_tls_client_t *handshake, uint8_t alert,
                       const char *reason);

/* One bit per (level, direction). Kept as a mask rather than inferred from the
 * keys, because a zeroed traffic key is indistinguishable from a real one and
 * "these keys exist" is a fact about the handshake, not about the bytes. */
unsigned int wt_tls_client_key_bit(wt_tls_level_t level, int from_server);

/* Whether `value` is in an array of `count` 16-bit values. Used for the cipher
 * suite, the group and the signature scheme, all of which the server must have
 * picked from what the client offered. */
int wt_tls_client_in_uint16_list(const uint16_t *list, size_t count,
                                 uint16_t value);

/* Whether `protocol` (length-prefixed entries, RFC 7301) contains a name equal
 * to `name`/`name_len`. The client's ALPN offer is a byte string of
 * `opaque<1..255>` entries, so this walks it rather than comparing whole
 * buffers. */
int wt_tls_client_alpn_list_contains(const uint8_t *list, size_t list_len,
                                     const uint8_t *name, size_t name_len);

/* The server's handshake messages, in `wt_tls_client_messages.c`. Each is
 * called by the dispatcher in `wt_tls_client.c` with the same arguments the
 * dispatcher itself was handed. */
int wt_tls_client_handle_server_hello(wt_tls_client_t *handshake,
                                      const uint8_t *message,
                                      size_t message_len, const uint8_t **out,
                                      size_t *out_len,
                                      wt_tls_level_t *out_level);

int wt_tls_client_handle_encrypted_extensions(
    wt_tls_client_t *handshake, const uint8_t *message, size_t message_len,
    const uint8_t **out, size_t *out_len, wt_tls_level_t *out_level);

int wt_tls_client_handle_certificate_request(
    wt_tls_client_t *handshake, const uint8_t *message, size_t message_len,
    const uint8_t **out, size_t *out_len, wt_tls_level_t *out_level);

int wt_tls_client_handle_certificate(wt_tls_client_t *handshake,
                                     const uint8_t *message, size_t message_len,
                                     const uint8_t **out, size_t *out_len,
                                     wt_tls_level_t *out_level);

int wt_tls_client_handle_certificate_verify(
    wt_tls_client_t *handshake, const uint8_t *message, size_t message_len,
    const uint8_t **out, size_t *out_len, wt_tls_level_t *out_level);

/* The server's Finished, which derives the application keys and produces the
 * client's response flight. In `wt_tls_client_finish.c`. */
int wt_tls_client_handle_finished(wt_tls_client_t *handshake,
                                  const uint8_t *message, size_t message_len,
                                  const uint8_t **out, size_t *out_len,
                                  wt_tls_level_t *out_level);

#endif /* WT_TLS_CLIENT_INTERNAL_H */
