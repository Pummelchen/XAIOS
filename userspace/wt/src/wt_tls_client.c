/* The TLS 1.3 client handshake for QUIC. See wt_tls_client.h for the design.
 *
 * The shape of this file is the shape of the handshake: one handler per message
 * the server can send, a dispatcher that refuses a message that does not belong
 * where it arrived, and a small number of "derive and install" steps between
 * them. Every check that decides whether the connection proceeds is in a
 * handler, and each one names the RFC section it comes from, because the
 * interesting thing about this code is not what it does when everything is
 * right.
 */

#include "wt_tls_client.h"

#include "wt_crypto.h"

#include <string.h>

/* RFC 8446 section 4.1.3: a HelloRetryRequest is a ServerHello whose random is
 * SHA-256("HelloRetryRequest"). Recognising it is worth doing explicitly: a
 * caller that treated it as a ServerHello would derive keys from a key share
 * the server never accepted, and the failure would appear as a Finished
 * mismatch with no hint of the real cause. */
static const uint8_t wt_tls_hello_retry_request_random[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C,
    0x02, 0x1E, 0x65, 0xB8, 0x91, 0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB,
    0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

/* One bit per (level, direction). Kept as a mask rather than inferred from the
 * keys, because a zeroed traffic key is indistinguishable from a real one and
 * "these keys exist" is a fact about the handshake, not about the bytes. */
static unsigned int key_bit(wt_tls_level_t level, int from_server) {
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
     contract and an earlier version broke it: `wt_tls_client_start` wrote a
     placeholder reason before it knew whether it would succeed, and left it
     there afterwards, so a healthy handshake reported "the handshake was never
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
  return (handshake->keys_available & key_bit(level, from_server)) != 0U;
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
  /* The negotiated values and the borrowed views go too. A cleared handshake
     that still reported WT_TLS_STATE_CONNECTED would keep handing out the
     peer's transport parameters through the getter, which gates on exactly
     that state -- so clearing the secrets but not the state leaves the
     authenticated-looking bytes readable from a connection that no longer
     exists. */
  handshake->state = WT_TLS_STATE_START;
  handshake->alert = 0U;
  handshake->fail_reason = NULL;
  handshake->cipher_suite = 0U;
  handshake->group = 0U;
  handshake->transport_parameters = NULL;
  handshake->transport_parameters_len = 0U;
  handshake->transport_parameters_seen = 0;
  handshake->leaf_certificate = NULL;
  handshake->leaf_certificate_len = 0U;
  handshake->client_auth_requested = 0;
  handshake->certificate_request_context_len = 0U;
}

/* Fail the handshake, with the alert RFC 8446 section 6.2 names for this
 * refusal and a reason a human can act on. Always returns -1 so handlers can
 * `return client_fail(...)`. */
static int client_fail(wt_tls_client_t *handshake, uint8_t alert,
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
static int in_uint16_list(const uint16_t *list, size_t count, uint16_t value) {
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
static int alpn_list_contains(const uint8_t *list, size_t list_len,
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
    client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                "the client handshake has no ClientHello parameters");
    return 0U;
  }
  if (config->pin == NULL || !wt_tls_pinned_key_is_set(config->pin)) {
    /* Refused at the start rather than at Certificate time, because a
       connection with no trust decision configured should not be attempted at
       all -- and because catching it here means no bytes derived from a
       handshake that could never be trusted are ever produced. */
    client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                "no operator key is pinned, so no server can be trusted");
    return 0U;
  }
  if (config->client_key_private == NULL ||
      config->client_key_private_len != 32U) {
    client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                "the key share has no 32-byte x25519 private key");
    return 0U;
  }
  /* RFC 9001 section 8.2 makes the transport parameters mandatory in the
     ClientHello as well as in EncryptedExtensions, and a server that does not
     see them closes the connection. Refusing here means a caller that forgot
     them finds out at the call, rather than by watching a peer hang up. */
  if (config->params->quic_transport_parameters == NULL ||
      config->params->quic_transport_parameters_len == 0U) {
    client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
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
    client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                "the transcript could not be started");
    return 0U;
  }

  needed = wt_tls_client_hello_size(config->params);
  if (needed == 0U) {
    client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                "the ClientHello parameters are not usable");
    return 0U;
  }
  if (out == NULL || out_capacity < needed) {
    client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                "the ClientHello buffer is too small");
    return 0U;
  }
  hello_len = wt_tls_encode_client_hello(config->params, out, out_capacity);
  if (hello_len == 0U) {
    client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                "the ClientHello could not be built");
    return 0U;
  }

  /* The ClientHello is the first message in the transcript, so a transcript
     that did not start with it would make every later hash wrong. */
  if (wt_tls_transcript_absorb(&handshake->transcript, out, hello_len) != 0) {
    client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                "the ClientHello could not be hashed");
    return 0U;
  }

  handshake->state = WT_TLS_STATE_WAIT_SERVER_HELLO;
  return hello_len;
}

/* --------------------------------------------------------- message handlers */

/* RFC 8446 section 4.1.3. Everything the key schedule needs, and every check
 * that decides whether this ServerHello is answering the ClientHello that was
 * sent. */
static int handle_server_hello(wt_tls_client_t *handshake,
                               const uint8_t *message, size_t message_len,
                               const uint8_t **out, size_t *out_len,
                               wt_tls_level_t *out_level) {
  wt_tls_server_hello_t hello;
  uint8_t transcript_hash[WT_TLS_HASH_LEN];
  uint8_t ecdh[32];
  int status;

  (void)out;
  (void)out_len;
  (void)out_level;

  /* A HelloRetryRequest is a ServerHello carrying a magic random. Refusing it
     by name is worth the four lines: RFC 8446 allows a server to send one, this
     client does not implement it, and a caller deserves to be told that rather
     than to see a key schedule derived from a key share the server rejected. */
  if (message_len >= 38U && message[0] == WT_TLS_HS_SERVER_HELLO &&
      memcmp(message + 6U, wt_tls_hello_retry_request_random, 32U) == 0) {
    return client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                       "the server sent a HelloRetryRequest, which this client "
                       "does not implement");
  }

  /* The QUIC client sends an empty legacy_session_id (RFC 9001 section 8.4
     prohibits middlebox compatibility mode), so the echo must be empty too. */
  if (wt_tls_parse_server_hello(message, message_len, NULL, 0U, &hello) != 0) {
    return client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
                       "the ServerHello did not parse");
  }

  /* RFC 8446 section 4.1.3: the server selects a cipher suite the client
     offered. Selecting one that was not offered is a protocol violation, and
     selecting one that was offered but that this module cannot perform is a
     local limitation -- both are refusals, and they are told apart because the
     second one is an operator's problem. */
  if (!in_uint16_list(handshake->params->cipher_suites,
                      handshake->params->cipher_suite_count,
                      hello.cipher_suite)) {
    return client_fail(handshake, WT_TLS_ALERT_ILLEGAL_PARAMETER,
                       "the server selected a cipher suite that was not "
                       "offered");
  }
  if (hello.cipher_suite != WT_TLS_CIPHER_AES_128_GCM_SHA256) {
    return client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                       "the server selected a cipher suite this client cannot "
                       "perform");
  }
  handshake->cipher_suite = hello.cipher_suite;

  /* The group must be one this client sent a key share for. A server that
     selects a group from supported_groups without a matching key share is
     asking for a HelloRetryRequest, which is refused above by its own name. */
  if (hello.group != WT_TLS_GROUP_X25519) {
    return client_fail(handshake, WT_TLS_ALERT_ILLEGAL_PARAMETER,
                       "the server selected a key exchange group this client "
                       "cannot perform");
  }
  {
    size_t i;
    int offered = 0;
    for (i = 0U; i < handshake->params->key_share_count; i++) {
      if (handshake->params->key_shares[i].group == hello.group) offered = 1;
    }
    if (!offered) {
      return client_fail(handshake, WT_TLS_ALERT_ILLEGAL_PARAMETER,
                         "the server selected a group that was not offered in "
                         "a key share");
    }
  }
  handshake->group = hello.group;

  /* x25519 public keys are 32 bytes and never all zeros (RFC 7748 section 6.1;
     an all-zero result is the low-order-point output and would be the same
     secret for every private key). */
  if (hello.key_share_len != 32U) {
    return client_fail(handshake, WT_TLS_ALERT_ILLEGAL_PARAMETER,
                       "the server's x25519 key share is not 32 bytes");
  }
  if (!wt_x25519_public_key_is_valid(hello.key_share)) {
    return client_fail(handshake, WT_TLS_ALERT_ILLEGAL_PARAMETER,
                       "the server's x25519 key share is all zeros");
  }

  /* From here the handshake is committed: the ServerHello is in the transcript
     and the handshake secrets come from that transcript, so nothing checked
     after this point can be checked before it. */
  if (wt_tls_transcript_absorb_and_hash(&handshake->transcript, message,
                                        message_len,
                                        transcript_hash) != 0) {
    return client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the ServerHello could not be hashed");
  }

  if (wt_x25519_shared_secret(handshake->client_key_private, hello.key_share,
                              ecdh) != 0) {
    return client_fail(handshake, WT_TLS_ALERT_ILLEGAL_PARAMETER,
                       "the x25519 shared secret could not be computed");
  }
  status = wt_tls_handshake_key_schedule(ecdh, sizeof(ecdh), transcript_hash,
                                         &handshake->secrets);
  wt_secure_zero(ecdh, sizeof(ecdh));
  if (status != 0) {
    return client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                       "the handshake key schedule failed");
  }

  if (wt_tls_traffic_keys(handshake->secrets.client_handshake_traffic,
                          WT_TLS_AEAD_AES_128_GCM,
                          &handshake->client_handshake_keys) != 0 ||
      wt_tls_traffic_keys(handshake->secrets.server_handshake_traffic,
                          WT_TLS_AEAD_AES_128_GCM,
                          &handshake->server_handshake_keys) != 0) {
    return client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                       "the handshake traffic keys could not be derived");
  }
  handshake->keys_available |=
      key_bit(WT_TLS_LEVEL_HANDSHAKE, 0) |
      key_bit(WT_TLS_LEVEL_HANDSHAKE, 1);

  handshake->state = WT_TLS_STATE_WAIT_ENCRYPTED_EXTENSIONS;
  return 0;
}

/* RFC 8446 section 4.3.1 and RFC 9001 section 8.2. */
static int handle_encrypted_extensions(wt_tls_client_t *handshake,
                                       const uint8_t *message,
                                       size_t message_len, const uint8_t **out,
                                       size_t *out_len,
                                       wt_tls_level_t *out_level) {
  wt_tls_encrypted_extensions_t ee;
  wt_tls_ee_reject_t reject = WT_TLS_EE_OK;
  uint16_t offender = 0U;

  (void)out;
  (void)out_len;
  (void)out_level;

  if (wt_tls_parse_encrypted_extensions(message, message_len, &ee) != 0) {
    /* The parser's own reasons map onto the two alerts RFC 8446 uses for this
       message: an extension in the wrong place is illegal_parameter, and
       everything structural is decode_error. */
    if (ee.reject == WT_TLS_EE_DUPLICATE_EXTENSION ||
        ee.reject == WT_TLS_EE_FORBIDDEN_EXTENSION) {
      return client_fail(handshake, WT_TLS_ALERT_ILLEGAL_PARAMETER,
                         "the EncryptedExtensions is not well formed");
    }
    return client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
                       "the EncryptedExtensions did not parse");
  }

  if (wt_tls_encrypted_extensions_check(&ee, handshake->params, &reject,
                                        &offender) != 0) {
    if (reject == WT_TLS_EE_UNSOLICITED_EXTENSION) {
      return client_fail(handshake, WT_TLS_ALERT_UNSUPPORTED_EXTENSION,
                         "the server sent an extension the client did not "
                         "offer");
    }
    return client_fail(handshake, WT_TLS_ALERT_ILLEGAL_PARAMETER,
                       "the server sent an extension that does not belong in "
                       "EncryptedExtensions");
  }

  /* RFC 9001 section 8.2: a QUIC client that receives EncryptedExtensions
     without the transport parameters MUST close the connection, and the error
     is the one a fatal missing_extension alert would produce. This is checked
     before ALPN because without transport parameters there is no connection to
     negotiate a protocol for. */
  if (!ee.has_transport_parameters) {
    return client_fail(handshake, WT_TLS_ALERT_MISSING_EXTENSION,
                       "the server did not send QUIC transport parameters");
  }
  handshake->transport_parameters = ee.transport_parameters;
  handshake->transport_parameters_len = ee.transport_parameters_len;
  handshake->transport_parameters_seen = 1;

  /* RFC 7301 section 3.2: if the client offered ALPN, the server must select
     one of the offered protocols, and a client that receives anything else
     aborts with no_application_protocol. Selecting nothing is the same
     refusal -- and for HTTP/3 it is fatal, because "h3" is how the server says
     it speaks HTTP/3 at all. */
  if (handshake->params->alpn_protocols_len != 0U) {
    if (!ee.has_alpn) {
      return client_fail(handshake, WT_TLS_ALERT_NO_APPLICATION_PROTOCOL,
                         "the server selected no ALPN protocol");
    }
    if (!alpn_list_contains(handshake->params->alpn_protocols,
                            handshake->params->alpn_protocols_len, ee.alpn,
                            ee.alpn_len)) {
      return client_fail(handshake, WT_TLS_ALERT_NO_APPLICATION_PROTOCOL,
                         "the server selected an ALPN protocol that was not "
                         "offered");
    }
    /* Copied, not borrowed: the message buffer is the caller's and may be
       reused before the caller asks what was negotiated. */
    if (ee.alpn_len > sizeof(handshake->alpn)) {
      return client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                         "the selected ALPN protocol does not fit");
    }
    memcpy(handshake->alpn, ee.alpn, ee.alpn_len);
    handshake->alpn_len = ee.alpn_len;
    handshake->alpn_selected = 1;
  }

  /* RFC 8446 section 4.4.1: EncryptedExtensions is in the transcript. */
  if (wt_tls_transcript_absorb(&handshake->transcript, message, message_len) !=
      0) {
    return client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the EncryptedExtensions could not be hashed");
  }
  handshake->state = WT_TLS_STATE_WAIT_CERTIFICATE;
  return 0;
}

/* RFC 8446 section 4.3.2. The next message from the server, if it sends one, is
 * a CertificateRequest, and it comes before the Certificate. */
static int handle_certificate_request(wt_tls_client_t *handshake,
                                      const uint8_t *message,
                                      size_t message_len, const uint8_t **out,
                                      size_t *out_len,
                                      wt_tls_level_t *out_level) {
  uint8_t type = 0U;
  size_t body_len = 0U;
  size_t body_offset = 0U;
  uint8_t context_len;

  (void)out;
  (void)out_len;
  (void)out_level;

  if (wt_tls_decode_handshake_header(message, message_len, &type, &body_len,
                                     &body_offset) != 0) {
    return client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
                       "the CertificateRequest did not parse");
  }
  if (type != WT_TLS_HS_CERTIFICATE_REQUEST) {
    return client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                       "a message other than CertificateRequest arrived where "
                       "a CertificateRequest was expected");
  }
  if (body_len < 1U) {
    return client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
                       "the CertificateRequest has no context length");
  }
  context_len = message[body_offset];
  if ((size_t)context_len > body_len - 1U) {
    return client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
                       "the CertificateRequest context does not fit");
  }
  /* RFC 8446 section 4.3.2: the message is the context followed by an
     extension list, whose own length field must account for the rest. This
     client acts on none of the extensions a CertificateRequest can carry -- it
     has no certificate to choose with them -- but a message whose lengths do
     not add up is malformed, and absorbing it would make the handshake fail
     later for a reason several messages away from its cause. */
  {
    size_t after_context = 1U + (size_t)context_len;
    size_t extensions_len;
    if (body_len < after_context + 2U) {
      return client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
                         "the CertificateRequest has no extension list");
    }
    extensions_len = ((size_t)message[body_offset + after_context] << 8) |
                     (size_t)message[body_offset + after_context + 1U];
    if (extensions_len != body_len - after_context - 2U) {
      return client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
                         "the CertificateRequest extension list does not match "
                         "its length");
    }
  }

  /* This client holds no certificate and cannot sign, so it answers with an
     empty Certificate message, which is what RFC 8446 section 4.4.2 requires of
     a client with no suitable certificate. The context must be echoed, so it is
     copied out of the message rather than read again later: by the time the
     flight is built, the caller's buffer may be gone. */
  if ((size_t)context_len > sizeof(handshake->certificate_request_context)) {
    return client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
                       "the CertificateRequest context is too long");
  }
  memcpy(handshake->certificate_request_context, message + body_offset + 1U,
         (size_t)context_len);
  handshake->certificate_request_context_len = (size_t)context_len;
  handshake->client_auth_requested = 1;

  /* RFC 8446 section 4.4.1: CertificateRequest is in the transcript. */
  if (wt_tls_transcript_absorb(&handshake->transcript, message, message_len) !=
      0) {
    return client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the CertificateRequest could not be hashed");
  }
  return 0;
}

/* RFC 8446 section 4.4.2, and the two checks that decide whether the peer is
 * who the operator pinned.
 *
 * The signature check is not here: CertificateVerify carries it, and doing the
 * pin check here and the signature check there is what keeps them separable.
 * Both have to pass. A pin alone would accept a certificate anybody could copy;
 * a signature alone would accept any self-signed key an attacker generated and
 * signed with. */
static int handle_certificate(wt_tls_client_t *handshake,
                              const uint8_t *message, size_t message_len,
                              const uint8_t **out, size_t *out_len,
                              wt_tls_level_t *out_level) {
  wt_tls_certificate_chain_t chain;
  wt_tls_pin_result_t pin;

  (void)out;
  (void)out_len;
  (void)out_level;

  if (wt_tls_parse_certificate(message, message_len, &chain) != 0) {
    return client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
                       "the Certificate did not parse");
  }
  /* `chain.count` is at least one here without a check, because
     `wt_tls_parse_certificate` refuses an empty certificate_list itself: a
     server authenticates with a certificate, so an empty list is not a server
     that declined to authenticate but a malformed message, and the parser
     reports it as one (decode_error) before this is reached. That guarantee is
     asserted in tests/security/test_wt_tls_cert.c. */

  /* RFC 8446 section 4.4.2: the sender's own certificate is first. The chain
     after it is not walked: a pinned key needs the leaf and nothing else, and
     pretending to validate a chain while checking one key would be worse than
     saying what is checked. */
  pin = wt_tls_pinned_key_accepts_certificate(
      handshake->pin, chain.entries[0], chain.lengths[0]);
  if (pin == WT_TLS_PIN_NO_PIN) {
    /* A configuration failure, not a judgment about the peer: this client has
       no operator key to compare against, so no server could be accepted. */
    return client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                       "no operator key is pinned, so no server can be "
                       "trusted");
  }
  if (pin == WT_TLS_PIN_BAD_CERTIFICATE) {
    return client_fail(handshake, WT_TLS_ALERT_BAD_CERTIFICATE,
                       "the server's certificate could not be read");
  }
  if (pin == WT_TLS_PIN_WRONG_KEY_TYPE) {
    return client_fail(handshake, WT_TLS_ALERT_UNKNOWN_CA,
                       "the server's key type is not the pinned key's type");
  }
  if (pin != WT_TLS_PIN_ACCEPTED) {
    return client_fail(handshake, WT_TLS_ALERT_UNKNOWN_CA,
                       "the server's key is not the pinned operator key");
  }

  /* The leaf is a view into the caller's buffer and must stay one, because the
     signature check two messages later needs the whole certificate and copying
     an unbounded certificate to avoid a dangling view would trade a documented
     lifetime for an unbounded allocation. The header states this. */
  handshake->leaf_certificate = chain.entries[0];
  handshake->leaf_certificate_len = chain.lengths[0];

  if (wt_tls_transcript_absorb(&handshake->transcript, message, message_len) !=
      0) {
    return client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the Certificate could not be hashed");
  }
  handshake->state = WT_TLS_STATE_WAIT_CERTIFICATE_VERIFY;
  return 0;
}

/* RFC 8446 section 4.4.3. This is where the transcript is tied to the key. */
static int handle_certificate_verify(wt_tls_client_t *handshake,
                                     const uint8_t *message,
                                     size_t message_len, const uint8_t **out,
                                     size_t *out_len,
                                     wt_tls_level_t *out_level) {
  wt_tls_certificate_verify_t verify;
  uint8_t transcript_hash[WT_TLS_HASH_LEN];
  uint8_t content[64U + 33U + 1U + WT_TLS_HASH_LEN];
  size_t content_len = 0U;
  int verified;

  (void)out;
  (void)out_len;
  (void)out_level;

  if (wt_tls_parse_certificate_verify(message, message_len, &verify) != 0) {
    return client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
                       "the CertificateVerify did not parse");
  }

  /* RFC 8446 section 4.4.3: "the client MUST verify that the signature scheme
     is one it offered". A server that signs with a scheme the client never
     offered is not merely inconvenient -- the scheme list is the client's
     statement of what it can check, so accepting an unoffered scheme means
     accepting a signature that was never meant to be trustworthy. */
  if (!in_uint16_list(handshake->params->signature_algorithms,
                      handshake->params->signature_algorithm_count,
                      verify.scheme)) {
    return client_fail(handshake, WT_TLS_ALERT_ILLEGAL_PARAMETER,
                       "the server signed with a scheme that was not offered");
  }

  /* The transcript hash is taken BEFORE this message: RFC 8446 hashes a message
     into the transcript after its own signature has been checked, and a caller
     that absorbed first would never verify anything. */
  if (wt_tls_transcript_hash(&handshake->transcript, transcript_hash) != 0) {
    return client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the transcript could not be read");
  }
  if (wt_tls_certificate_verify_content(
          wt_tls_server_certificate_verify_context, transcript_hash, content,
          sizeof(content), &content_len) != 0) {
    return client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the signed content could not be built");
  }

  verified = wt_tls_certificate_verify_signature(
      handshake->leaf_certificate, handshake->leaf_certificate_len, &verify,
      content, content_len);
  if (verified != 1) {
    /* 0 and -1 are both refusals and both mean the same thing to the peer: the
       handshake did not authenticate. RFC 8446 section 6.2 names decrypt_error
       for "unable to correctly verify a signature". */
    return client_fail(handshake, WT_TLS_ALERT_DECRYPT_ERROR,
                       "the server's signature over the transcript did not "
                       "verify");
  }

  if (wt_tls_transcript_absorb(&handshake->transcript, message, message_len) !=
      0) {
    return client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the CertificateVerify could not be hashed");
  }
  handshake->state = WT_TLS_STATE_WAIT_FINISHED;
  return 0;
}

/* Append the client's response flight: an empty Certificate if the server asked
 * for one, then the Finished. Both are built by hand because they are the only
 * two messages this client sends after the ClientHello.
 *
 * The order matters: RFC 8446 section 4.4.4 hashes a message into the transcript
 * before the Finished MAC is computed over it, so the empty Certificate is
 * absorbed first and only then is the Finished built. */
static int build_client_flight(wt_tls_client_t *handshake,
                               const uint8_t **out, size_t *out_len,
                               wt_tls_level_t *out_level) {
  uint8_t transcript_hash[WT_TLS_HASH_LEN];
  uint8_t verify_data[WT_TLS_FINISHED_LEN];
  size_t offset = 0U;

  handshake->flight_len = 0U;

  if (handshake->client_auth_requested) {
    /* Certificate: `0b || uint24 length || context || CertificateEntry list ||
       extensions`. With no certificate the list is empty and so is the
       extension block, which is `00 00 00` for the list length and `00 00` for
       the extensions. */
    size_t context_len = handshake->certificate_request_context_len;
    size_t body_len = 1U + context_len + 3U + 2U;
    uint8_t *p = handshake->flight;

    if (4U + body_len > sizeof(handshake->flight)) {
      return client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                         "the client's Certificate does not fit");
    }
    p[0] = WT_TLS_HS_CERTIFICATE;
    p[1] = (uint8_t)((body_len >> 16) & 0xFFU);
    p[2] = (uint8_t)((body_len >> 8) & 0xFFU);
    p[3] = (uint8_t)(body_len & 0xFFU);
    offset = 4U;
    p[offset++] = (uint8_t)context_len;
    if (context_len != 0U) {
      memcpy(p + offset, handshake->certificate_request_context, context_len);
      offset += context_len;
    }
    /* certificate_list: three zero bytes, then the empty extensions. */
    p[offset++] = 0x00U;
    p[offset++] = 0x00U;
    p[offset++] = 0x00U;
    p[offset++] = 0x00U;
    p[offset++] = 0x00U;

    if (wt_tls_transcript_absorb(&handshake->transcript, p, offset) != 0) {
      return client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                         "the client's Certificate could not be hashed");
    }
    handshake->flight_len = offset;
  }

  /* The Finished MAC is over the transcript through the server's Finished,
     including the client's Certificate when there is one. */
  if (wt_tls_transcript_hash(&handshake->transcript, transcript_hash) != 0) {
    return client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the transcript could not be read");
  }
  if (wt_tls_finished_compute(handshake->secrets.client_handshake_traffic,
                              transcript_hash, verify_data) != 0) {
    return client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the client's Finished could not be computed");
  }

  {
    uint8_t *p = handshake->flight + handshake->flight_len;
    size_t remaining = sizeof(handshake->flight) - handshake->flight_len;
    if (remaining < 4U + WT_TLS_FINISHED_LEN) {
      return client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                         "the client's Finished does not fit");
    }
    wt_tls_encode_handshake_header(WT_TLS_HS_FINISHED, WT_TLS_FINISHED_LEN, p);
    memcpy(p + 4U, verify_data, WT_TLS_FINISHED_LEN);
    handshake->flight_len += 4U + WT_TLS_FINISHED_LEN;
  }

  /* The client's own Finished is part of the transcript that a resumption
     master secret is derived from, so it is absorbed even though this module
     has no session tickets to use it with: a transcript that is one message
     short is a wrong transcript, and a wrong transcript is the kind of defect
     that only appears much later and somewhere else. */
  if (wt_tls_transcript_absorb(&handshake->transcript,
                               handshake->flight + handshake->flight_len -
                                   (4U + WT_TLS_FINISHED_LEN),
                               4U + WT_TLS_FINISHED_LEN) != 0) {
    return client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the client's Finished could not be hashed");
  }

  *out = handshake->flight;
  *out_len = handshake->flight_len;
  /* RFC 9001 section 4.1.5: the client's second flight goes at the Handshake
     level, under handshake keys. The application keys derived alongside it are
     reported available in the same call, because RFC 9001 has the client
     install 1-RTT keys once its Finished is produced. */
  *out_level = WT_TLS_LEVEL_HANDSHAKE;
  return 0;
}

/* RFC 8446 section 4.4.4. */
static int handle_finished(wt_tls_client_t *handshake, const uint8_t *message,
                           size_t message_len, const uint8_t **out,
                           size_t *out_len, wt_tls_level_t *out_level) {
  uint8_t transcript_hash[WT_TLS_HASH_LEN];
  uint8_t after_server_finished[WT_TLS_HASH_LEN];
  wt_tls_secrets_t application_phase;
  int verified;

  /* The hash is taken BEFORE the Finished is absorbed; RFC 8446 hashes a
     message into the transcript after its own MAC has been checked, so a caller
     that absorbed first would verify a MAC that covers itself and could never
     succeed. */
  if (wt_tls_transcript_hash(&handshake->transcript, transcript_hash) != 0) {
    return client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the transcript could not be read");
  }
  verified = wt_tls_finished_verify(handshake->secrets.server_handshake_traffic,
                                    transcript_hash, message, message_len);
  if (verified != 1) {
    return client_fail(handshake, WT_TLS_ALERT_DECRYPT_ERROR,
                       "the server's Finished did not verify");
  }

  if (wt_tls_transcript_absorb_and_hash(&handshake->transcript, message,
                                        message_len,
                                        after_server_finished) != 0) {
    return client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the server's Finished could not be hashed");
  }

  /* The application traffic secrets come from the transcript through the
     server's Finished, which exists exactly now. Deriving them any earlier
     would derive them from the wrong transcript; the two-phase schedule is what
     makes that impossible to get wrong by accident. */
  if (wt_tls_application_key_schedule(&handshake->secrets,
                                      after_server_finished,
                                      &application_phase) != 0) {
    return client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                       "the application key schedule failed");
  }
  handshake->secrets = application_phase;
  wt_secure_zero(&application_phase, sizeof(application_phase));

  if (wt_tls_traffic_keys(handshake->secrets.client_application_traffic,
                          WT_TLS_AEAD_AES_128_GCM,
                          &handshake->client_application_keys) != 0 ||
      wt_tls_traffic_keys(handshake->secrets.server_application_traffic,
                          WT_TLS_AEAD_AES_128_GCM,
                          &handshake->server_application_keys) != 0) {
    return client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                       "the application traffic keys could not be derived");
  }
  handshake->keys_available |=
      key_bit(WT_TLS_LEVEL_APPLICATION, 0) |
      key_bit(WT_TLS_LEVEL_APPLICATION, 1);

  if (build_client_flight(handshake, out, out_len, out_level) != 0) {
    return -1;
  }

  /* RFC 9001 section 4.1.1: the handshake is complete at an endpoint once it
     has both sent its Finished and verified the peer's. Both are true here, so
     the state says so rather than waiting for the socket. */
  handshake->state = WT_TLS_STATE_CONNECTED;
  return 0;
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
    return client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                       "a handshake message arrived after the handshake "
                       "completed");
  }
  if (handshake->state == WT_TLS_STATE_START) {
    return client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                       "the handshake was never started");
  }

  if (wt_tls_decode_handshake_header(message, message_len, &type, &body_len,
                                     &body_offset) != 0) {
    return client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
                       "the handshake message did not frame");
  }
  (void)body_len;
  (void)body_offset;

  switch (handshake->state) {
    case WT_TLS_STATE_WAIT_SERVER_HELLO:
      /* RFC 9001 section 4.1.3: the ServerHello is carried at the Initial
         level, under Initial keys, and nothing else may be. */
      if (level != WT_TLS_LEVEL_INITIAL) {
        return client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                           "the ServerHello did not arrive at the Initial "
                           "encryption level");
      }
      if (type != WT_TLS_HS_SERVER_HELLO) {
        return client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                           "a message other than ServerHello arrived where a "
                           "ServerHello was expected");
      }
      return handle_server_hello(handshake, message, message_len, out, out_len,
                                 out_level);

    case WT_TLS_STATE_WAIT_ENCRYPTED_EXTENSIONS:
      if (level != WT_TLS_LEVEL_HANDSHAKE) {
        return client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                           "EncryptedExtensions did not arrive at the "
                           "Handshake encryption level");
      }
      if (type != WT_TLS_HS_ENCRYPTED_EXTENSIONS) {
        return client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                           "a message other than EncryptedExtensions arrived "
                           "where EncryptedExtensions was expected");
      }
      return handle_encrypted_extensions(handshake, message, message_len, out,
                                         out_len, out_level);

    case WT_TLS_STATE_WAIT_CERTIFICATE:
      if (level != WT_TLS_LEVEL_HANDSHAKE) {
        return client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                           "a message did not arrive at the Handshake "
                           "encryption level");
      }
      if (type == WT_TLS_HS_CERTIFICATE_REQUEST) {
        return handle_certificate_request(handshake, message, message_len, out,
                                          out_len, out_level);
      }
      if (type != WT_TLS_HS_CERTIFICATE) {
        return client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                           "a message other than Certificate arrived where a "
                           "Certificate was expected");
      }
      return handle_certificate(handshake, message, message_len, out, out_len,
                                out_level);

    case WT_TLS_STATE_WAIT_CERTIFICATE_VERIFY:
      if (level != WT_TLS_LEVEL_HANDSHAKE ||
          type != WT_TLS_HS_CERTIFICATE_VERIFY) {
        return client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                           "a message other than CertificateVerify arrived "
                           "where CertificateVerify was expected");
      }
      return handle_certificate_verify(handshake, message, message_len, out,
                                       out_len, out_level);

    case WT_TLS_STATE_WAIT_FINISHED:
      if (level != WT_TLS_LEVEL_HANDSHAKE || type != WT_TLS_HS_FINISHED) {
        return client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                           "a message other than Finished arrived where "
                           "Finished was expected");
      }
      return handle_finished(handshake, message, message_len, out, out_len,
                             out_level);

    default:
      return client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                         "the handshake is in a state that accepts no "
                         "message");
  }
}
