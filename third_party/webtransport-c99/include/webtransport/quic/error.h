/* QUIC transport error codes (RFC 9000 section 20) and the ranges around them.
 *
 * A QUIC connection that fails sends a CONNECTION_CLOSE carrying a code from
 * this list, and the code is the only thing the peer is told. So a codec that
 * detects a malformed frame has to say *which* code the connection closes with,
 * not merely that it failed -- "the peer sent something bad" is not actionable
 * and "the peer sent a frame type this endpoint does not know" is.
 *
 * The codes are returned separately from wt_status_t rather than folded into it
 * because they are two different questions. wt_status_t says how the call went
 * for the caller: a truncated buffer, a limit, a protocol error. This says what
 * the connection should tell the peer, and several call-failures map to the same
 * transport code while one call-failure can map to different codes depending on
 * which field was wrong.
 *
 * The reserved range is RFC 9000 section 20.1: 0x0100 to 0x01ff is reserved for
 * the TLS layer, where the value is 0x0100 plus a TLS alert. That is how a
 * handshake failure becomes a transport close.
 */

#ifndef WEBTRANSPORT_QUIC_ERROR_H
#define WEBTRANSPORT_QUIC_ERROR_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* A QUIC transport error code. Values are the wire values. */
typedef uint64_t wt_quic_error_t;

#define WT_QUIC_NO_ERROR ((wt_quic_error_t)0x00)
#define WT_QUIC_INTERNAL_ERROR ((wt_quic_error_t)0x01)
#define WT_QUIC_CONNECTION_REFUSED ((wt_quic_error_t)0x02)
#define WT_QUIC_FLOW_CONTROL_ERROR ((wt_quic_error_t)0x03)
#define WT_QUIC_STREAM_LIMIT_ERROR ((wt_quic_error_t)0x04)
#define WT_QUIC_STREAM_STATE_ERROR ((wt_quic_error_t)0x05)
#define WT_QUIC_FINAL_SIZE_ERROR ((wt_quic_error_t)0x06)
#define WT_QUIC_FRAME_ENCODING_ERROR ((wt_quic_error_t)0x07)
#define WT_QUIC_TRANSPORT_PARAMETER_ERROR ((wt_quic_error_t)0x08)
#define WT_QUIC_CONNECTION_ID_LIMIT_ERROR ((wt_quic_error_t)0x09)
#define WT_QUIC_PROTOCOL_VIOLATION ((wt_quic_error_t)0x0a)
#define WT_QUIC_INVALID_TOKEN ((wt_quic_error_t)0x0b)
#define WT_QUIC_APPLICATION_ERROR ((wt_quic_error_t)0x0c)
#define WT_QUIC_CRYPTO_BUFFER_EXCEEDED ((wt_quic_error_t)0x0d)
#define WT_QUIC_KEY_UPDATE_ERROR ((wt_quic_error_t)0x0e)
#define WT_QUIC_AEAD_LIMIT_REACHED ((wt_quic_error_t)0x0f)
#define WT_QUIC_NO_VIABLE_PATH ((wt_quic_error_t)0x10)

/* The TLS alert range (RFC 9000 section 20.1). `alert` is a TLS alert
 * description, so 0x0100 + 120 is no_application_protocol. */
#define WT_QUIC_CRYPTO_ERROR_BASE ((wt_quic_error_t)0x0100)
#define WT_QUIC_CRYPTO_ERROR_LAST ((wt_quic_error_t)0x01ff)

/* The CRYPTO_ERROR a TLS alert becomes. Refuses an alert that would leave the
 * range, because a code outside it is a different error class to the peer. */
wt_status_t wt_quic_crypto_error(uint8_t tls_alert, wt_quic_error_t *out);

/* Whether a code is in the TLS alert range. A caller mapping a close to a
 * message needs this: below the range the code is a QUIC error, inside it the
 * low byte is a TLS alert. */
int wt_quic_error_is_crypto(wt_quic_error_t error);

/* A short stable name for the codes above, or "crypto" for the TLS range and
 * "unknown" otherwise. Never NULL. */
const char *wt_quic_error_name(wt_quic_error_t error);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_QUIC_ERROR_H */
