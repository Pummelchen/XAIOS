/* The TLS 1.3 client handshake for QUIC. See wt_tls_client.h for the design.
 *
 * The shape of this file is the shape of the handshake: the accessors, the
 * ClientHello, a dispatcher that refuses a message that does not belong where
 * it arrived, and the refusal and list-membership helpers every handler needs.
 * The handlers themselves -- one per message the server can send -- are in
 * `wt_tls_client_messages.c`, and the client's response flight with the
 * server's Finished is in `wt_tls_client_finish.c`. Every check that decides
 * whether the connection proceeds is in a handler, and each one names the RFC
 * section it comes from, because the interesting thing about this code is not
 * what it does when everything is right.
 */

#include "wt_tls_client.h"

#include "wt_tls_client_internal.h"

#include "wt_crypto.h"

#include <string.h>

/* One bit per (level, direction). Kept as a mask rather than inferred from the
 * keys, because a zeroed traffic key is indistinguishable from a real one and
 * "these keys exist" is a fact about the handshake, not about the bytes. */
unsigned int wt_tls_client_key_bit(wt_tls_level_t level,
                                   int from_server) {
  return 1U << ((unsigned int)level * 2U + (from_server ? 1U : 0U));
}

wt_tls_state_t wt_tls_client_state(const wt_tls_client_t *handshake) {
  if (handshake == NULL) return WT_TLS_STATE_FAILED;
  return handshake->state;
}

uint8_t wt_tls_client_alert(const wt_tls_client_t *handshake) {
  if (handshake == NULL) return WT_TLS_ALERT_HANDSHAKE_FAILURE;
  return handshake->alert;
}

const char *wt_tls_client_fail_reason(const wt_tls_client_t *handshake) {
  /* NULL unless the handshake has actually failed. The header states that
     contract and an earlier version broke it: `wt_tls_client_start` recorded a
     reason before it knew whether it would succeed, and left it there
     afterwards, so a healthy handshake reported "the handshake was never
     started" to anyone who asked. Gating on the state rather than on the
     string being set is what makes the contract hold no matter what the
     failure path wrote. */
  if (handshake == NULL) return NULL;
  if (handshake->state != WT_TLS_STATE_FAILED) return NULL;
  return handshake->fail_reason == NULL ? "the handshake failed"
                                        : handshake->fail_reason;
}

int wt_tls_client_keys_available(const wt_tls_client_t *handshake,
                                 wt_tls_level_t level, int from_server) {
  if (handshake == NULL) return 0;
  /* The level is checked rather than trusted because `wt_tls_client_key_bit`
     shifts by it: a caller that passed something outside the enum would shift
     by an amount the C standard does not define, which is a wrong answer at
     best and undefined behaviour at worst. Three named levels and no others is
     the whole domain. */
  if (level != WT_TLS_LEVEL_INITIAL && level != WT_TLS_LEVEL_HANDSHAKE &&
      level != WT_TLS_LEVEL_APPLICATION) {
    return 0;
  }
  return (handshake->keys_available &
          wt_tls_client_key_bit(level, from_server)) != 0U;
}

int wt_tls_client_keys(const wt_tls_client_t *handshake, wt_tls_level_t level,
                       int from_server, wt_tls_traffic_keys_t *out) {
  if (handshake == NULL || out == NULL) return -1;
  memset(out, 0, sizeof(*out));
  if (!wt_tls_client_keys_available(handshake, level, from_server)) return -1;
  if (level == WT_TLS_LEVEL_HANDSHAKE) {
    *out = from_server ? handshake->server_handshake_keys
                       : handshake->client_handshake_keys;
    return 0;
  }
  if (level == WT_TLS_LEVEL_APPLICATION) {
    *out = from_server ? handshake->server_application_keys
                       : handshake->client_application_keys;
    return 0;
  }
  /* The Initial keys are not TLS's. RFC 9001 section 5.2 derives them from the
     connection ID, with no input from this module, so a caller that asked here
     made a mistake that should not look like a success. */
  return -1;
}

wt_tls_aead_t wt_tls_client_aead(const wt_tls_client_t *handshake) {
  if (handshake == NULL) return WT_TLS_AEAD_AES_128_GCM;
  /* The only suite this module can negotiate. Returning the one value rather
     than a "negotiated" field is deliberate: there is no state in which this
     could be something else, because a ServerHello selecting anything else is
     refused. */
  return WT_TLS_AEAD_AES_128_GCM;
}

const uint8_t *wt_tls_client_alpn(const wt_tls_client_t *handshake,
                                  size_t *out_len) {
  if (out_len != NULL) *out_len = 0U;
  if (handshake == NULL) return NULL;
  if (!handshake->alpn_selected) return NULL;
  if (out_len != NULL) *out_len = handshake->alpn_len;
  return handshake->alpn;
}

const uint8_t *wt_tls_client_flight(const wt_tls_client_t *handshake,
                                    size_t *out_len,
                                    wt_tls_level_t *out_level) {
  if (out_len != NULL) *out_len = 0U;
  if (out_level != NULL) *out_level = WT_TLS_LEVEL_INITIAL;
  if (handshake == NULL || handshake->flight_len == 0U) return NULL;
  if (out_len != NULL) *out_len = handshake->flight_len;
  if (out_level != NULL) *out_level = handshake->flight_level;
  return handshake->flight;
}

const uint8_t *wt_tls_client_peer_transport_parameters(
    const wt_tls_client_t *handshake, size_t *out_len) {
  if (out_len != NULL) *out_len = 0U;
  if (handshake == NULL) return NULL;
  /* RFC 9001 section 8.2: transport parameters are only authenticated once the
     handshake completes. Handing them out earlier would let a caller act on
     bytes an attacker chose, which is the one thing the extension exists to
     prevent, so this returns nothing until the Finished has verified. */
  if (handshake->state != WT_TLS_STATE_CONNECTED) return NULL;
  if (!handshake->transport_parameters_seen) return NULL;
  if (out_len != NULL) *out_len = handshake->transport_parameters_len;
  return handshake->transport_parameters;
}

void wt_tls_client_clear(wt_tls_client_t *handshake) {
  if (handshake == NULL) return;
  /* The configuration pointers are borrowed and the private key is the
     caller's; everything derived is wiped. wt_secure_zero rather than memset
     because the compiler is otherwise free to remove a write to storage that is
     never read again -- and a secret that survived the connection is the whole
     failure this function exists to prevent. */
  wt_tls_secrets_clear(&handshake->secrets);
  wt_tls_traffic_keys_clear(&handshake->client_handshake_keys);
  wt_tls_traffic_keys_clear(&handshake->server_handshake_keys);
  wt_tls_traffic_keys_clear(&handshake->client_application_keys);
  wt_tls_traffic_keys_clear(&handshake->server_application_keys);
  wt_secure_zero(&handshake->transcript, sizeof(handshake->transcript));
  wt_secure_zero(handshake->flight, sizeof(handshake->flight));
  wt_secure_zero(handshake->alpn, sizeof(handshake->alpn));
  wt_secure_zero(handshake->certificate_request_context,
                 sizeof(handshake->certificate_request_context));
  handshake->flight_len = 0U;
  handshake->alpn_len = 0U;
  handshake->alpn_selected = 0;
  handshake->keys_available = 0U;
  handshake->client_key_private = NULL;
  handshake->client_key_private_len = 0U;
  /* The negotiated values and the bytes the client kept go too. A cleared
     handshake that still reported WT_TLS_STATE_CONNECTED would keep handing out
     the peer's transport parameters through the getter, which gates on exactly
     that state -- so clearing the secrets but not the state leaves the
     authenticated-looking bytes readable from a connection that no longer
     exists. */
  handshake->state = WT_TLS_STATE_START;
  handshake->alert = 0U;
  handshake->fail_reason = NULL;
  handshake->cipher_suite = 0U;
  handshake->group = 0U;
  wt_secure_zero(handshake->transport_parameters,
                 sizeof(handshake->transport_parameters));
  handshake->transport_parameters_len = 0U;
  handshake->transport_parameters_seen = 0;
  wt_tls_public_key_clear(&handshake->leaf_public_key);
  handshake->client_auth_requested = 0;
  handshake->certificate_request_context_len = 0U;
}

/* Fail the handshake, with the alert RFC 8446 section 6.2 names for this
 * refusal and a reason a human can act on. Always returns -1 so handlers can
 * `return wt_tls_client_fail(...)`. */
int wt_tls_client_fail(wt_tls_client_t *handshake, uint8_t alert,
                       const char *reason) {
  handshake->state = WT_TLS_STATE_FAILED;
  handshake->alert = alert;
  handshake->fail_reason = reason;
  /* Nothing derived is usable after a refusal, and leaving it in place invites
     a caller that ignores the return value to use it. The transcript and the
     negotiated values go too; the configuration pointers stay, because they are
     the caller's. */
  wt_tls_secrets_clear(&handshake->secrets);
  wt_tls_traffic_keys_clear(&handshake->client_handshake_keys);
  wt_tls_traffic_keys_clear(&handshake->server_handshake_keys);
  wt_tls_traffic_keys_clear(&handshake->client_application_keys);
  wt_tls_traffic_keys_clear(&handshake->server_application_keys);
  handshake->keys_available = 0U;
  handshake->flight_len = 0U;
  return -1;
}

/* Whether `value` is in an array of `count` 16-bit values. Used for the cipher
 * suite, the group and the signature scheme, all of which the server must have
 * picked from what the client offered. */
int wt_tls_client_in_uint16_list(const uint16_t *list, size_t count,
                                 uint16_t value) {
  size_t i;
  if (list == NULL) return 0;
  for (i = 0U; i < count; i++) {
    if (list[i] == value) return 1;
  }
  return 0;
}

/* Whether `protocol` (length-prefixed entries, RFC 7301) contains a name equal
 * to `name`/`name_len`. The client's ALPN offer is a byte string of
 * `opaque<1..255>` entries, so this walks it rather than comparing whole
 * buffers. */
int wt_tls_client_alpn_list_contains(const uint8_t *list, size_t list_len,
                                     const uint8_t *name, size_t name_len) {
  size_t offset = 0U;
  if (list == NULL || name == NULL) return 0;
  if (name_len == 0U || name_len > 255U) return 0;
  while (offset < list_len) {
    size_t entry_len = list[offset];
    offset += 1U;
    if (entry_len == 0U) return 0;
    if (entry_len > list_len - offset) return 0;
    if (entry_len == name_len &&
        memcmp(list + offset, name, name_len) == 0) {
      return 1;
    }
    offset += entry_len;
  }
  return 0;
}

/* ------------------------------------------------------------ ClientHello */

size_t wt_tls_client_start(wt_tls_client_t *handshake,
                           const wt_tls_client_config_t *config, uint8_t *out,
                           size_t out_capacity) {
  size_t needed;
  size_t hello_len;

  if (handshake == NULL || config == NULL) return 0U;
  memset(handshake, 0, sizeof(*handshake));
  handshake->state = WT_TLS_STATE_START;
  handshake->alert = WT_TLS_ALERT_HANDSHAKE_FAILURE;
  handshake->fail_reason = "the handshake was never started";

  /* Every refusal here is one that would otherwise produce a handshake that
     cannot succeed, and a caller that got a ClientHello back would have no
     reason to suspect it. */
  if (config->params == NULL) {
    wt_tls_client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                "the client handshake has no ClientHello parameters");
    return 0U;
  }
  if (config->pin == NULL || !wt_tls_pinned_key_is_set(config->pin)) {
    /* Refused at the start rather than at Certificate time, because a
       connection with no trust decision configured should not be attempted at
       all -- and because catching it here means no bytes derived from a
       handshake that could never be trusted are ever produced. */
    wt_tls_client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                "no operator key is pinned, so no server can be trusted");
    return 0U;
  }
  if (config->client_key_private == NULL ||
      config->client_key_private_len != 32U) {
    wt_tls_client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                "the key share has no 32-byte x25519 private key");
    return 0U;
  }
  /* RFC 9001 section 8.2 makes the transport parameters mandatory in the
     ClientHello as well as in EncryptedExtensions, and a server that does not
     see them closes the connection. Refusing here means a caller that forgot
     them finds out at the call, rather than by watching a peer hang up. */
  if (config->params->quic_transport_parameters == NULL ||
      config->params->quic_transport_parameters_len == 0U) {
    wt_tls_client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                "the ClientHello carries no QUIC transport parameters");
    return 0U;
  }

  /* The configuration is copied in, so a caller that reuses the struct it
     passed cannot change what this handshake is halfway through. The buffers
     those fields point at stay the caller's, which the header states. */
  handshake->params = config->params;
  handshake->pin = config->pin;
  handshake->client_key_private = config->client_key_private;
  handshake->client_key_private_len = config->client_key_private_len;

  if (wt_tls_transcript_init(&handshake->transcript) != 0) {
    wt_tls_client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                "the transcript could not be started");
    return 0U;
  }

  needed = wt_tls_client_hello_size(config->params);
  if (needed == 0U) {
    wt_tls_client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                "the ClientHello parameters are not usable");
    return 0U;
  }
  if (out == NULL || out_capacity < needed) {
    wt_tls_client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                "the ClientHello buffer is too small");
    return 0U;
  }
  hello_len = wt_tls_encode_client_hello(config->params, out, out_capacity);
  if (hello_len == 0U) {
    wt_tls_client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                "the ClientHello could not be built");
    return 0U;
  }

  /* The ClientHello is the first message in the transcript, so a transcript
     that did not start with it would make every later hash wrong. */
  if (wt_tls_transcript_absorb(&handshake->transcript, out, hello_len) != 0) {
    wt_tls_client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                "the ClientHello could not be hashed");
    return 0U;
  }

  handshake->state = WT_TLS_STATE_WAIT_SERVER_HELLO;
  return hello_len;
}

/* ------------------------------------------------------------- dispatcher */

int wt_tls_client_receive(wt_tls_client_t *handshake, wt_tls_level_t level,
                          const uint8_t *message, size_t message_len,
                          const uint8_t **out, size_t *out_len,
                          wt_tls_level_t *out_level) {
  uint8_t type = 0U;
  size_t body_len = 0U;
  size_t body_offset = 0U;

  if (out != NULL) *out = NULL;
  if (out_len != NULL) *out_len = 0U;
  if (out_level != NULL) *out_level = WT_TLS_LEVEL_HANDSHAKE;
  if (handshake == NULL || message == NULL || out == NULL || out_len == NULL ||
      out_level == NULL) {
    return -1;
  }
  /* A refusal is terminal: a peer that sent one bad message does not get a
     second chance in the same connection, and a state machine that could
     recover would be a state machine with a path back into a partially
     completed handshake. */
  if (handshake->state == WT_TLS_STATE_FAILED) return -1;
  if (handshake->state == WT_TLS_STATE_CONNECTED) {
    /* The handshake is passive after completion (RFC 9001 section 4.1.3). This
       client offers no psk_key_exchange_modes, so a compliant server sends no
       NewSessionTicket, and anything else here is a message this client has no
       use for. */
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                       "a handshake message arrived after the handshake "
                       "completed");
  }
  if (handshake->state == WT_TLS_STATE_START) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                       "the handshake was never started");
  }

  if (wt_tls_decode_handshake_header(message, message_len, &type, &body_len,
                                     &body_offset) != 0) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
                       "the handshake message did not frame");
  }
  (void)body_len;
  (void)body_offset;

  switch (handshake->state) {
    case WT_TLS_STATE_WAIT_SERVER_HELLO:
      /* RFC 9001 section 4.1.3: the ServerHello is carried at the Initial
         level, under Initial keys, and nothing else may be. */
      if (level != WT_TLS_LEVEL_INITIAL) {
        return wt_tls_client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                           "the ServerHello did not arrive at the Initial "
                           "encryption level");
      }
      if (type != WT_TLS_HS_SERVER_HELLO) {
        return wt_tls_client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                           "a message other than ServerHello arrived where a "
                           "ServerHello was expected");
      }
      return wt_tls_client_handle_server_hello(handshake, message, message_len,
                                               out, out_len, out_level);

    case WT_TLS_STATE_WAIT_ENCRYPTED_EXTENSIONS:
      if (level != WT_TLS_LEVEL_HANDSHAKE) {
        return wt_tls_client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                           "EncryptedExtensions did not arrive at the "
                           "Handshake encryption level");
      }
      if (type != WT_TLS_HS_ENCRYPTED_EXTENSIONS) {
        return wt_tls_client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                           "a message other than EncryptedExtensions arrived "
                           "where EncryptedExtensions was expected");
      }
      return wt_tls_client_handle_encrypted_extensions(handshake, message,
                                                       message_len, out, out_len,
                                                       out_level);

    case WT_TLS_STATE_WAIT_CERTIFICATE:
      if (level != WT_TLS_LEVEL_HANDSHAKE) {
        return wt_tls_client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                           "a message did not arrive at the Handshake "
                           "encryption level");
      }
      if (type == WT_TLS_HS_CERTIFICATE_REQUEST) {
        return wt_tls_client_handle_certificate_request(handshake, message,
                                                        message_len, out, out_len,
                                                        out_level);
      }
      if (type != WT_TLS_HS_CERTIFICATE) {
        return wt_tls_client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                           "a message other than Certificate arrived where a "
                           "Certificate was expected");
      }
      return wt_tls_client_handle_certificate(handshake, message, message_len,
                                              out, out_len, out_level);

    case WT_TLS_STATE_WAIT_CERTIFICATE_VERIFY:
      if (level != WT_TLS_LEVEL_HANDSHAKE ||
          type != WT_TLS_HS_CERTIFICATE_VERIFY) {
        return wt_tls_client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                           "a message other than CertificateVerify arrived "
                           "where CertificateVerify was expected");
      }
      return wt_tls_client_handle_certificate_verify(handshake, message,
                                                     message_len, out, out_len,
                                                     out_level);

    case WT_TLS_STATE_WAIT_FINISHED:
      if (level != WT_TLS_LEVEL_HANDSHAKE || type != WT_TLS_HS_FINISHED) {
        return wt_tls_client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                           "a message other than Finished arrived where "
                           "Finished was expected");
      }
      return wt_tls_client_handle_finished(handshake, message, message_len,
                                           out, out_len, out_level);

    default:
      return wt_tls_client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                         "the handshake is in a state that accepts no "
                         "message");
  }
}
