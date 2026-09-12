/* The TLS 1.3 client handshake for QUIC (RFC 8446, RFC 9001 section 4.1).
 *
 * Every other file in `userspace/wt/` answers one question: the key schedule
 * derives secrets, the packet module protects a packet, the handshake module
 * frames and hashes, the certificate module checks a signature, the pin module
 * decides which key is trusted. This file is what turns those into a
 * connection. It is the state machine, and its whole job is to call the others
 * at the right moments and refuse the connection when any of them says no.
 *
 * WHAT IT IS NOT. It does not read or write packets. QUIC owns the UDP socket,
 * the packet numbers, the CRYPTO streams and the retransmission; this module
 * takes handshake messages in the order QUIC has already reassembled them and
 * hands back the bytes that go into a CRYPTO frame. That boundary is RFC 9001
 * section 4.1.3's interface, and it is what makes this testable on a host with
 * no network at all.
 *
 * THE ORDER OF THE HANDSHAKE, as RFC 9001 section 4.1.5's figure shows it for
 * a client:
 *
 *   1. Get Handshake        -> ClientHello, sent at the Initial level
 *   2. receive ServerHello  -> derive handshake keys, report them available
 *   3. receive EncryptedExtensions, Certificate, CertificateVerify, Finished,
 *      each under the handshake keys
 *   4. on the server's Finished -> derive application keys, produce the
 *      client's Finished (and an empty Certificate if the server asked for
 *      client authentication), report the handshake complete
 *   5. after this the handshake is passive; anything sent is post-handshake,
 *      and this client supports none of it
 *
 * EVERY REFUSAL CARRIES AN ALERT. RFC 9001 section 4.8 turns a TLS alert into a
 * QUIC CONNECTION_CLOSE code of 0x0100 + alert, so "the handshake failed" is
 * not enough to tell a peer what was wrong or an operator what to look at. Each
 * refusal here records the alert description RFC 8446 section 6.2 names.
 *
 * THE CHECKS THAT MATTER, because they are the ones a plausible implementation
 * leaves out and a working one cannot:
 *
 *   - the cipher suite and key share the server selected were ones this client
 *     offered, and this module can actually perform;
 *   - EncryptedExtensions carries the QUIC transport parameters (RFC 9001
 *     section 8.2 makes that mandatory and its absence fatal) and an ALPN
 *     protocol the client offered (RFC 7301 section 3.2: anything else is
 *     no_application_protocol);
 *   - the certificate's key is the pinned operator key AND the transcript is
 *     signed by that key -- either check alone accepts something it should not;
 *   - the CertificateVerify scheme was one the client offered;
 *   - the server's Finished MAC verifies before any secret derived from the
 *     transcript through it is used.
 */

#ifndef WT_TLS_CLIENT_H
#define WT_TLS_CLIENT_H

#include <stddef.h>
#include <stdint.h>

#include "bearssl.h"
#include "wt_tls.h"
#include "wt_tls_cert.h"
#include "wt_tls_handshake.h"
#include "wt_tls_pin.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The one cipher suite this module implements, and the only one RFC 9001
 * section 5.1 makes mandatory. ChaCha20-Poly1305 has no AEAD here (see
 * wt_crypto.h), so a server that selects it cannot be talked to, and saying so
 * is better than deriving keys for a suite that cannot protect a packet. */
#define WT_TLS_CIPHER_AES_128_GCM_SHA256 0x1301U

/* The one group implemented (RFC 7748). */
#define WT_TLS_GROUP_X25519 0x001DU

/* RFC 8446 section 6.2 alert descriptions this driver can produce. RFC 9001
 * section 4.8 maps each to QUIC error 0x0100 + the value. */
#define WT_TLS_ALERT_UNEXPECTED_MESSAGE 10U
#define WT_TLS_ALERT_HANDSHAKE_FAILURE 40U
#define WT_TLS_ALERT_BAD_CERTIFICATE 42U
#define WT_TLS_ALERT_ILLEGAL_PARAMETER 47U
#define WT_TLS_ALERT_UNKNOWN_CA 48U
#define WT_TLS_ALERT_DECODE_ERROR 50U
#define WT_TLS_ALERT_DECRYPT_ERROR 51U
#define WT_TLS_ALERT_INTERNAL_ERROR 80U
#define WT_TLS_ALERT_MISSING_EXTENSION 109U
#define WT_TLS_ALERT_UNSUPPORTED_EXTENSION 110U
#define WT_TLS_ALERT_NO_APPLICATION_PROTOCOL 120U

/* RFC 9001 section 4.1.3. There is no early-data level: 0-RTT needs a PSK and a
 * session-ticket store, and this module has neither, so the enum has no member
 * for it rather than a member that is always unavailable. */
typedef enum wt_tls_level {
  WT_TLS_LEVEL_INITIAL = 0,
  WT_TLS_LEVEL_HANDSHAKE = 1,
  WT_TLS_LEVEL_APPLICATION = 2
} wt_tls_level_t;

typedef enum wt_tls_state {
  /* Nothing produced yet. `wt_tls_client_start` leaves this. */
  WT_TLS_STATE_START = 0,
  /* The ClientHello is out; a ServerHello is expected at the Initial level. */
  WT_TLS_STATE_WAIT_SERVER_HELLO,
  /* Handshake keys are installed; EncryptedExtensions is expected. */
  WT_TLS_STATE_WAIT_ENCRYPTED_EXTENSIONS,
  /* EncryptedExtensions is in; Certificate, or a CertificateRequest first. */
  WT_TLS_STATE_WAIT_CERTIFICATE,
  WT_TLS_STATE_WAIT_CERTIFICATE_VERIFY,
  WT_TLS_STATE_WAIT_FINISHED,
  /* The client's Finished has been produced. The handshake is complete from
   * this side, which is what RFC 9001 section 4.1.1 means by complete. */
  WT_TLS_STATE_CONNECTED,
  /* A refusal. `wt_tls_client_alert` and `wt_tls_client_fail_reason` say why,
   * and the state is terminal. */
  WT_TLS_STATE_FAILED
} wt_tls_state_t;

/* What the caller must supply. Everything is borrowed and must outlive the
 * handshake: `params` describes the ClientHello, `pin` is the trust decision,
 * and `client_key_private` is the scalar for the key share `params` offers.
 *
 * The private key is a separate argument rather than part of `params` because
 * `params` is the message -- it is what goes on the wire -- and a private key
 * must never be one field away from being serialised by accident. RFC 8446 also
 * requires the private key to be destroyed when the handshake ends; the caller
 * owns it and this module never copies it. */
typedef struct wt_tls_client_config {
  const wt_tls_client_hello_params_t *params;
  const wt_tls_pinned_key_t *pin;
  const uint8_t *client_key_private;
  size_t client_key_private_len;
} wt_tls_client_config_t;

/* A response flight this module can produce is bounded, and the bound is
 * provable rather than chosen: an empty Certificate is `4 + 1 + context +
 * 3 + 2` with the certificate_request_context at most 255 bytes (RFC 8446
 * section 4.4.2 gives it a one-byte length), and a Finished is 36. The largest
 * possible flight is therefore 301 bytes. The buffer is fixed rather than
 * caller-supplied so that a caller cannot hand in one that is too small for a
 * message whose size depends on what the peer sent. */
#define WT_TLS_CLIENT_MAX_FLIGHT 512U

/* ALPN protocol names are `opaque<1..255>` (RFC 7301), so the selected one
 * always fits here, and copying it means it does not point into a receive
 * buffer that the caller will reuse. */
#define WT_TLS_CLIENT_MAX_ALPN 255U

typedef struct wt_tls_client {
  /* Configuration, borrowed. */
  const wt_tls_client_hello_params_t *params;
  const wt_tls_pinned_key_t *pin;
  const uint8_t *client_key_private;
  size_t client_key_private_len;

  wt_tls_state_t state;
  uint8_t alert;
  const char *fail_reason;

  wt_tls_transcript_t transcript;

  /* The full schedule once the server's Finished has been verified; before
   * that only the first phase's fields are meaningful, which is the point of
   * the two-phase call. */
  wt_tls_secrets_t secrets;
  wt_tls_traffic_keys_t client_handshake_keys;
  wt_tls_traffic_keys_t server_handshake_keys;
  wt_tls_traffic_keys_t client_application_keys;
  wt_tls_traffic_keys_t server_application_keys;
  /* Which of the four are derived, as a bitmask over level*2 + from_server.
     Kept separately from the keys because a zeroed key is a valid-looking key
     and "available" is not something a key can say about itself. */
  unsigned int keys_available;

  /* Negotiated values. */
  uint16_t cipher_suite;
  uint16_t group;
  int transport_parameters_seen;
  /* Where the peer's transport parameters were seen, borrowed from the
   * EncryptedExtensions message the caller passed in. Only exposed once the
   * handshake has completed, because until then they are not authenticated
   * (RFC 9001 section 8.2) -- and this is a getter rather than a struct field
   * so that the rule is enforced rather than documented. */
  const uint8_t *transport_parameters;
  size_t transport_parameters_len;

  uint8_t alpn[WT_TLS_CLIENT_MAX_ALPN];
  size_t alpn_len;
  int alpn_selected;

  /* Set when the server asked for a client certificate. This client has none,
   * so it answers with an empty Certificate (RFC 8446 section 4.4.2) and sends
   * no CertificateVerify, which is what the RFC requires of a client without a
   * suitable certificate. */
  int client_auth_requested;
  uint8_t certificate_request_context[255];
  size_t certificate_request_context_len;

  /* The leaf certificate, borrowed from the Certificate message the caller
     passed in. It must stay valid until the CertificateVerify has been checked,
     which is why wt_tls_client_receive documents that the message buffer is
     borrowed for the handshake's lifetime. It is not copied because a
     certificate chain has no small bound: copying it would need either an
     allocation or a limit that refuses a valid certificate. */
  const uint8_t *leaf_certificate;
  size_t leaf_certificate_len;

  /* The response flight, owned here. See WT_TLS_CLIENT_MAX_FLIGHT. */
  uint8_t flight[WT_TLS_CLIENT_MAX_FLIGHT];
  size_t flight_len;
  wt_tls_level_t flight_level;
} wt_tls_client_t;

/* Start a client handshake: encode the ClientHello into `out`, absorb it into
 * the transcript, and leave the handshake waiting for a ServerHello.
 *
 * `out` must have room for `wt_tls_client_hello_size(config->params)` bytes.
 * Returns the number of bytes to send at the Initial level, or 0 on a refusal
 * -- in which case the handshake is in WT_TLS_STATE_FAILED and the reason is
 * available. A ClientHello is never zero bytes long, so 0 is unambiguous.
 *
 * Four things are refused before a byte is sent, because each of them would
 * otherwise produce a handshake that cannot succeed and could look like it was
 * trying: no configuration, no pinned operator key, a private key that is not
 * 32 bytes (the only key share this module offers), and an output buffer too
 * small for the ClientHello. */
size_t wt_tls_client_start(wt_tls_client_t *handshake,
                           const wt_tls_client_config_t *config, uint8_t *out,
                           size_t out_capacity);

/* Feed one complete handshake message, reassembled by QUIC at `level`.
 *
 * `message` is one message with its `type || uint24 length` header, which is
 * what a CRYPTO stream's bytes are: QUIC delivers handshake bytes in order, and
 * this module requires that. A caller that has a partial message buffers it
 * until it is complete; this function refuses a truncated message rather than
 * holding state for it, so a caller cannot accidentally treat two messages as
 * one.
 *
 * On success, `*out_len` is the length of a response flight to send at
 * `*out_level`, or 0 when the handshake has nothing to say. The response points
 * into the handshake's own buffer, so it is valid until the next call. Returns
 * 0 on success and -1 on a refusal.
 *
 * A refusal is terminal: the state becomes WT_TLS_STATE_FAILED and every later
 * call returns -1. A peer that sent one bad message does not get a second
 * chance in the same connection.
 *
 * THE BUFFER IS BORROWED FOR THE HANDSHAKE'S LIFETIME. The Certificate message
 * is held as a view and read again when CertificateVerify arrives, because
 * copying a certificate chain to avoid that would need an unbounded buffer. The
 * transport parameters are borrowed the same way. A QUIC stack reassembles
 * handshake bytes into a CRYPTO stream buffer that outlives one message, which
 * is exactly the lifetime this needs; a caller that hands in a per-read scratch
 * buffer must copy these two things out first. */
int wt_tls_client_receive(wt_tls_client_t *handshake, wt_tls_level_t level,
                          const uint8_t *message, size_t message_len,
                          const uint8_t **out, size_t *out_len,
                          wt_tls_level_t *out_level);

/* Whether keys at `level` for `from_server` have been derived. QUIC asks this
 * after every call, because RFC 9001 section 4.1.4 makes key availability a
 * result of providing input rather than something that can be predicted. */
int wt_tls_client_keys_available(const wt_tls_client_t *handshake,
                                 wt_tls_level_t level, int from_server);

/* The traffic keys for one direction and level. Returns 0 on success and -1
 * when they are not available, which is a refusal and not an empty key. */
int wt_tls_client_keys(const wt_tls_client_t *handshake, wt_tls_level_t level,
                       int from_server, wt_tls_traffic_keys_t *out);

/* The AEAD the connection negotiated, for QUIC's packet protection. Only
 * WT_TLS_AEAD_AES_128_GCM can be negotiated by this module. */
wt_tls_aead_t wt_tls_client_aead(const wt_tls_client_t *handshake);

/* State, alert and reason. `wt_tls_client_fail_reason` returns NULL unless the
 * handshake is in WT_TLS_STATE_FAILED, and a fixed literal once it is -- never
 * NULL then, so a caller logging it cannot get a null pointer from a handshake
 * that failed. */
wt_tls_state_t wt_tls_client_state(const wt_tls_client_t *handshake);
uint8_t wt_tls_client_alert(const wt_tls_client_t *handshake);
const char *wt_tls_client_fail_reason(const wt_tls_client_t *handshake);

/* The ALPN protocol the server selected, or NULL when none was selected. The
 * bytes are copied, so the caller may use them after the receive buffer is
 * gone. */
const uint8_t *wt_tls_client_alpn(const wt_tls_client_t *handshake,
                                  size_t *out_len);

/* The server's QUIC transport parameters, or NULL unless the handshake has
 * completed. RFC 9001 section 8.2: their value is authenticated by the
 * handshake, so before the Finished verifies they are attacker-controlled
 * bytes -- returning them only afterwards is what stops a caller from acting on
 * them early by mistake. The bytes point into the EncryptedExtensions message
 * that was passed to `wt_tls_client_receive`; the caller must have kept that
 * buffer, or copied them, until the handshake completes. */
const uint8_t *wt_tls_client_peer_transport_parameters(
    const wt_tls_client_t *handshake, size_t *out_len);

/* Zero everything derived: the transcript, the secrets, the traffic keys, the
 * private-key view, the negotiated values and the borrowed views -- and return
 * the handshake to WT_TLS_STATE_START, so it reports nothing about a connection
 * that has ended. The configuration pointers stay, because they are the
 * caller's and a cleared handshake is configured but unstarted rather than
 * unusable. Called when a connection ends; safe on a NULL handshake. */
void wt_tls_client_clear(wt_tls_client_t *handshake);

#ifdef __cplusplus
}
#endif

#endif /* WT_TLS_CLIENT_H */
