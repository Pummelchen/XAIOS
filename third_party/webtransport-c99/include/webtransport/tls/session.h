/* The TLS 1.3 client handshake, as a state machine over whole handshake messages.
 *
 * WHAT THIS LAYER DOES AND WHAT IT DOES NOT. It sequences the messages, keeps the
 * transcript, derives the schedule's secrets, checks the server's Finished, and gates every
 * secret on the condition that makes it trustworthy. It does not encrypt anything: a QUIC
 * connection hands it decrypted handshake messages and takes the secrets back, because the
 * record layer for QUIC is QUIC's packet protection (RFC 9001) rather than TLS's own. That
 * split is why this file has no buffer of ciphertext in it.
 *
 * THE GATE IS THE POINT. RFC 8446 section 7.1 derives the application secrets from the
 * Master Secret and a transcript, and neither of those is evidence that the peer is who it
 * says it is. So `wt_tls_client_application_secrets` answers only in the CONNECTED state,
 * and CONNECTED is reached only after the certificate chain has been trusted, the
 * CertificateVerify signature has been checked, the server's Finished has verified, the
 * ALPN the caller asked for has been confirmed, and -- when the caller says it is a QUIC
 * handshake -- the peer's transport parameters have arrived. Every one of those is a
 * required step in the state machine rather than a check a caller is trusted to perform,
 * which is what the phase's completion criterion asks for: application keys are unavailable
 * until every security condition is satisfied.
 *
 * THE CLIENTHELLO IS THE CALLER'S TO PROVIDE. `wt_tls_client_begin` is handed the bytes that
 * went on the wire, because the transcript is over those bytes and nothing else -- a machine
 * that built its own hello and assumed it was the one sent would produce secrets that match
 * no server. `wt_tls_client_begin_built` is the convenience for the common case: it builds
 * the ClientHello this implementation sends and starts the transcript with it, so a caller
 * that has no opinion about extensions needs one call. A test that replays a recorded
 * handshake uses the first form, which is how RFC 8448's own flight is checked against this
 * machine.
 */

#ifndef WEBTRANSPORT_TLS_SESSION_H
#define WEBTRANSPORT_TLS_SESSION_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/status.h"
#include "webtransport/tls/extension.h"
#include "webtransport/tls/handshake.h"
#include "webtransport/tls/keyschedule.h"
#include "webtransport/tls/keyshare.h"
#include "webtransport/tls/trust.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum wt_tls_client_state {
  /* Nothing has been sent. */
  WT_TLS_CLIENT_START = 0,
  WT_TLS_CLIENT_WAIT_SERVER_HELLO,
  WT_TLS_CLIENT_WAIT_ENCRYPTED_EXTENSIONS,
  WT_TLS_CLIENT_WAIT_CERTIFICATE,
  WT_TLS_CLIENT_WAIT_CERTIFICATE_VERIFY,
  WT_TLS_CLIENT_WAIT_FINISHED,
  /* The handshake is complete and the application secrets are available. */
  WT_TLS_CLIENT_CONNECTED,
  /* A message was refused and the handshake cannot continue. */
  WT_TLS_CLIENT_FAILED
} wt_tls_client_state_t;

typedef struct wt_tls_client_config {
  /* The name the certificate must be valid for, and the name sent in server_name. May be
   * NULL, which is only useful with a pinned or development trust policy. */
  const char *host_name;

  /* The protocols offered in ALPN. When this list is not empty the server's answer must be
   * exactly one of them -- RFC 8446 section 4.2 allows a server to send one -- and a server
   * that answers with nothing or with something else fails the handshake. A QUIC client sets
   * this to "h3" and has no reason to leave it empty. */
  const char *const *alpn;
  size_t alpn_count;

  /* Whether the peer must send quic_transport_parameters (RFC 9001 section 8.2). A QUIC
   * handshake sets this; a plain TLS trace such as RFC 8448's does not carry them. */
  int require_transport_parameters;

  /* Our own transport parameters, which go in the ClientHello. */
  const uint8_t *transport_parameters;
  size_t transport_parameters_len;

  /* The trust policy the server's chain is validated against. */
  wt_tls_trust_policy_t trust;

  /* The session id to offer. RFC 8446 allows an empty one, which is what the ClientHello
   * this implementation builds sends when this is NULL. */
  const uint8_t *session_id;
  size_t session_id_len;

  /* The x25519 private key to use. NULL means the machine generates one. It exists for a
   * caller that manages its own keys and for tests that replay a recorded handshake, where
   * the recorded server flight is only decryptable with the recorded client key. */
  const uint8_t *x25519_private;
} wt_tls_client_config_t;

/* The largest ClientHello this implementation builds, for a caller sizing a buffer. The
 * transport parameters are the part that varies, so a caller with unusual ones should size
 * from `wt_tls_client_hello_size` instead of guessing. */
#define WT_TLS_CLIENT_HELLO_MAX 1024U

typedef struct wt_tls_client {
  /* A marker that says this struct belongs to a handshake that has begun. It exists because a
   * caller-owned struct cannot be told from an uninitialised one: without it, starting a
   * second handshake on a machine that is still holding the first one's transcript would
   * either leak the hash context or be refused in a way that depends on what the stack
   * happened to hold. With it, `wt_tls_client_begin` releases what a previous handshake left
   * and starts over, deterministically. */
  uint64_t live;
  wt_tls_client_config_t config;
  wt_tls_client_state_t state;
  wt_tls13_transcript_t transcript;
  uint8_t private_key[WT_TLS_X25519_KEY_LEN];
  uint8_t public_key[WT_TLS_X25519_KEY_LEN];
  uint8_t handshake_secret[WT_TLS13_SECRET_LEN];
  uint8_t master_secret[WT_TLS13_SECRET_LEN];
  uint8_t client_handshake_secret[WT_TLS13_SECRET_LEN];
  uint8_t server_handshake_secret[WT_TLS13_SECRET_LEN];
  uint8_t client_application_secret[WT_TLS13_SECRET_LEN];
  uint8_t server_application_secret[WT_TLS13_SECRET_LEN];
  uint8_t peer_spki[WT_TLS_SPKI_MAX];
  size_t peer_spki_len;
  /* Views into the message that produced them, valid until the next call. */
  const uint8_t *peer_transport_parameters;
  size_t peer_transport_parameters_len;
  const uint8_t *negotiated_alpn;
  size_t negotiated_alpn_len;
} wt_tls_client_t;

/* Start a handshake from the ClientHello that was sent. The bytes are absorbed into the
 * transcript exactly as given, and the caller's buffer must stay valid only for this call:
 * the transcript is a hash, not a copy.
 *
 * Called on a machine that is already mid-handshake, this releases what that handshake held
 * and starts a new one -- a caller that abandons a handshake should not have to remember to
 * release it first, and a struct whose bytes are indeterminate cannot be asked whether it is
 * live. It is a fresh start either way, never a continuation. */
wt_status_t wt_tls_client_begin(wt_tls_client_t *client,
                                const wt_tls_client_config_t *config,
                                const uint8_t *client_hello,
                                size_t client_hello_len);

/* Build the ClientHello this implementation sends and start from it. Writes the message to
 * `out` and reports its length. */
wt_status_t wt_tls_client_begin_built(wt_tls_client_t *client,
                                      const wt_tls_client_config_t *config,
                                      uint8_t *out, size_t out_capacity,
                                      size_t *out_len);

/* Consume one server handshake message. When the message is the server's Finished, the
 * client's own Finished is written to `out`, which is the only output this machine ever
 * produces; `*out_len` is zero for every other message.
 *
 * The statuses are the protocol's own distinctions: WT_ERR_STATE for a message that is not
 * the one the state machine is waiting for, WT_ERR_TLS for a well-formed message the
 * handshake cannot continue from (the wrong ciphersuite, a version that is not 1.3, an ALPN
 * the caller did not offer, missing transport parameters, a Finished that does not verify),
 * WT_ERR_TRUST for a certificate the policy refuses, WT_ERR_AUTHENTICATION for a
 * CertificateVerify that does not verify, and WT_ERR_PROTOCOL for bytes that are not the
 * message they claim to be. A failure moves the machine to FAILED, and every later call
 * answers WT_ERR_STATE. */
wt_status_t wt_tls_client_receive(wt_tls_client_t *client, const uint8_t *message,
                                  size_t len, uint8_t *out, size_t out_capacity,
                                  size_t *out_len);

wt_tls_client_state_t wt_tls_client_state(const wt_tls_client_t *client);

/* The handshake traffic secrets, available once the ServerHello has been processed: the
 * read secret is the server's, the write secret is the client's. WT_ERR_STATE before that,
 * because using a secret the handshake has not derived yet is the mistake this exists to
 * make impossible. */
wt_status_t wt_tls_client_handshake_secrets(const wt_tls_client_t *client,
                                            uint8_t read_out[WT_TLS13_SECRET_LEN],
                                            uint8_t write_out[WT_TLS13_SECRET_LEN]);

/* The application traffic secrets, available only in the CONNECTED state, which is what
 * makes every check above a precondition for them. */
wt_status_t wt_tls_client_application_secrets(const wt_tls_client_t *client,
                                              uint8_t read_out[WT_TLS13_SECRET_LEN],
                                              uint8_t write_out[WT_TLS13_SECRET_LEN]);

/* The protocol the server chose, and the transport parameters it sent. Both are views into
 * the message that carried them and are valid until the next `wt_tls_client_receive`; a
 * caller that keeps either copies it. */
const uint8_t *wt_tls_client_alpn(const wt_tls_client_t *client, size_t *out_len);
const uint8_t *wt_tls_client_transport_parameters(const wt_tls_client_t *client,
                                                  size_t *out_len);

/* Release everything the handshake held. Called when a handshake ends, successfully or not,
 * so that secrets are not left in a reusable structure.
 *
 * A CALLER THAT ZEROES A MACHINE INSTEAD OF CLEARING IT LOSES THE HASH CONTEXT, because the
 * context is a pointer the marker refers to. `clear` is safe on a machine that never began --
 * it checks the marker itself -- so there is no reason to zero one by hand. */
void wt_tls_client_clear(wt_tls_client_t *client);

/* ============================================================== the server
 *
 * The other half of the same handshake, and deliberately the same shape: the ClientHello is
 * checked for the version, a key share, the ciphersuite, the ALPN the server is willing to
 * speak and the transport parameters QUIC requires; the flight is built in the order the
 * client's checks expect; the client's Finished gates the application secrets exactly as the
 * server's does on the client. A server that skipped one of those checks would complete a
 * handshake whose secrets a client would refuse, and the mismatch would surface as a tag
 * failure rather than as the missing check.
 *
 * THE FLIGHT IS TWO CALLS BECAUSE QUIC HAS TWO LEVELS. The ServerHello is protected with the
 * Initial keys, which both sides derive from the connection ID before TLS says anything; the
 * rest of the flight is protected with the handshake keys the ServerHello itself derives. A
 * server that returned one buffer would leave the caller to parse TLS framing to find the
 * boundary, and a caller that got it wrong would send the handshake records under the wrong
 * keys -- a failure that looks like a broken cipher rather than a misplaced boundary.
 */

typedef struct wt_tls_server_identity {
  /* The chain to send, leaf first. DER views into the caller's memory. */
  const uint8_t *certificate[WT_TLS_CERTIFICATE_MAX_ENTRIES];
  size_t certificate_len[WT_TLS_CERTIFICATE_MAX_ENTRIES];
  size_t certificate_count;
  /* The private key for the leaf, as DER (PKCS#8 or PKCS#1), and the scheme to sign with. */
  const uint8_t *private_key;
  size_t private_key_len;
  uint16_t signature_scheme;
} wt_tls_server_identity_t;

typedef struct wt_tls_server_config {
  const wt_tls_server_identity_t *identity;
  /* The protocol to select. It must be one the client offered, and the server sends exactly
   * one: a QUIC server sets this to "h3". */
  const char *alpn;
  /* Whether the client must send quic_transport_parameters, and what we send. */
  int require_transport_parameters;
  const uint8_t *transport_parameters;
  size_t transport_parameters_len;
  /* The x25519 private key to use for this handshake. NULL means generate one. */
  const uint8_t *x25519_private;
} wt_tls_server_config_t;

typedef enum wt_tls_server_state {
  WT_TLS_SERVER_START = 0,
  WT_TLS_SERVER_WAIT_CLIENT_HELLO,
  /* The ServerHello has been produced; the rest of the flight is fetched with
   * `wt_tls_server_flight`, and the client's Finished is what ends the handshake. */
  WT_TLS_SERVER_WAIT_CLIENT_FINISHED,
  WT_TLS_SERVER_CONNECTED,
  WT_TLS_SERVER_FAILED
} wt_tls_server_state_t;

typedef struct wt_tls_server {
  uint64_t live;
  wt_tls_server_config_t config;
  wt_tls_server_state_t state;
  wt_tls13_transcript_t transcript;
  uint8_t private_key[WT_TLS_X25519_KEY_LEN];
  uint8_t public_key[WT_TLS_X25519_KEY_LEN];
  uint8_t handshake_secret[WT_TLS13_SECRET_LEN];
  uint8_t master_secret[WT_TLS13_SECRET_LEN];
  uint8_t client_handshake_secret[WT_TLS13_SECRET_LEN];
  uint8_t server_handshake_secret[WT_TLS13_SECRET_LEN];
  uint8_t client_application_secret[WT_TLS13_SECRET_LEN];
  uint8_t server_application_secret[WT_TLS13_SECRET_LEN];
  uint8_t server_random[WT_TLS_RANDOM_LEN];
  uint8_t session_id[WT_TLS_SESSION_ID_MAX];
  size_t session_id_len;
  /* Whether the flight after the ServerHello has been built. It is built once: the
   * CertificateVerify's signature is not deterministic for RSA-PSS, so a second flight would
   * not match the transcript the first one signed, and QUIC retransmits CRYPTO data from its
   * own send buffer rather than by asking TLS again. */
  int flight_built;
  /* The client's transport parameters, a view valid until the next call. */
  const uint8_t *peer_transport_parameters;
  size_t peer_transport_parameters_len;
  const uint8_t *negotiated_alpn;
  size_t negotiated_alpn_len;
} wt_tls_server_t;

/* Start a handshake. Nothing is sent until a ClientHello arrives. */
wt_status_t wt_tls_server_begin(wt_tls_server_t *server,
                                const wt_tls_server_config_t *config);

/* Consume a handshake message from the client. On the ClientHello it writes the ServerHello and
 * moves to the state where the rest of the flight can be fetched; on the client's Finished it
 * verifies it, derives the application secrets, and writes nothing.
 *
 * A machine that is already mid-handshake may be restarted, exactly as the client's may. */
wt_status_t wt_tls_server_receive(wt_tls_server_t *server, const uint8_t *message,
                                  size_t len, uint8_t *out, size_t out_capacity,
                                  size_t *out_len);

/* The rest of the flight -- EncryptedExtensions, Certificate, CertificateVerify and Finished,
 * concatenated -- which the caller sends under handshake keys after the ServerHello. Valid once
 * the ClientHello has been processed, and buildable once: an RSA-PSS signature is randomised, so
 * a second flight would not match the transcript the first one signed, and QUIC retransmits
 * CRYPTO data from its own send buffer rather than by asking TLS again. A second call is
 * WT_ERR_STATE. */
wt_status_t wt_tls_server_flight(wt_tls_server_t *server, uint8_t *out,
                                 size_t out_capacity, size_t *out_len);

wt_tls_server_state_t wt_tls_server_state(const wt_tls_server_t *server);

/* The handshake traffic secrets, available once the ClientHello has been processed: the read
 * secret is the client's, the write secret is the server's. */
wt_status_t wt_tls_server_handshake_secrets(const wt_tls_server_t *server,
                                            uint8_t read_out[WT_TLS13_SECRET_LEN],
                                            uint8_t write_out[WT_TLS13_SECRET_LEN]);

/* The application traffic secrets, available only in the CONNECTED state, which is reached only
 * after the client's Finished has verified. */
wt_status_t wt_tls_server_application_secrets(const wt_tls_server_t *server,
                                              uint8_t read_out[WT_TLS13_SECRET_LEN],
                                              uint8_t write_out[WT_TLS13_SECRET_LEN]);

const uint8_t *wt_tls_server_alpn(const wt_tls_server_t *server, size_t *out_len);
const uint8_t *wt_tls_server_transport_parameters(const wt_tls_server_t *server,
                                                  size_t *out_len);
void wt_tls_server_clear(wt_tls_server_t *server);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_TLS_SESSION_H */
