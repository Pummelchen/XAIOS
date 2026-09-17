/* The server's handshake messages for the QUIC TLS 1.3 client.
 *
 * These are the five RFC 8446 messages a server can send between its
 * ServerHello and its Finished, split out of `wt_tls_client.c` so that file
 * stays readable. Each handler is called by the dispatcher there, which is
 * what enforces the order: this file checks that a message is well formed and
 * that what it says was offered, and refuses the connection by name when it is
 * not. The shared refusal helper and the list-membership checks it uses are
 * declared in `wt_tls_client_internal.h` and defined in `wt_tls_client.c`.
 */

#include "wt_tls_client_internal.h"

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

/* --------------------------------------------------------- message handlers */

/* RFC 8446 section 4.1.3. Everything the key schedule needs, and every check
 * that decides whether this ServerHello is answering the ClientHello that was
 * sent. */
int wt_tls_client_handle_server_hello(wt_tls_client_t *handshake,
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
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                       "the server sent a HelloRetryRequest, which this client "
                       "does not implement");
  }

  /* The QUIC client sends an empty legacy_session_id (RFC 9001 section 8.4
     prohibits middlebox compatibility mode), so the echo must be empty too. */
  if (wt_tls_parse_server_hello(message, message_len, NULL, 0U, &hello) != 0) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
                       "the ServerHello did not parse");
  }

  /* RFC 8446 section 4.1.3: the server selects a cipher suite the client
     offered. Selecting one that was not offered is a protocol violation, and
     selecting one that was offered but that this module cannot perform is a
     local limitation -- both are refusals, and they are told apart because the
     second one is an operator's problem. */
  if (!wt_tls_client_in_uint16_list(handshake->params->cipher_suites,
                      handshake->params->cipher_suite_count,
                      hello.cipher_suite)) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_ILLEGAL_PARAMETER,
                       "the server selected a cipher suite that was not "
                       "offered");
  }
  if (hello.cipher_suite != WT_TLS_CIPHER_AES_128_GCM_SHA256) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                       "the server selected a cipher suite this client cannot "
                       "perform");
  }
  handshake->cipher_suite = hello.cipher_suite;

  /* The group must be one this client sent a key share for. A server that
     selects a group from supported_groups without a matching key share is
     asking for a HelloRetryRequest, which is refused above by its own name. */
  if (hello.group != WT_TLS_GROUP_X25519) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_ILLEGAL_PARAMETER,
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
      return wt_tls_client_fail(handshake, WT_TLS_ALERT_ILLEGAL_PARAMETER,
                         "the server selected a group that was not offered in "
                         "a key share");
    }
  }
  handshake->group = hello.group;

  /* x25519 public keys are 32 bytes and never all zeros (RFC 7748 section 6.1;
     an all-zero result is the low-order-point output and would be the same
     secret for every private key). */
  if (hello.key_share_len != 32U) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_ILLEGAL_PARAMETER,
                       "the server's x25519 key share is not 32 bytes");
  }
  if (!wt_x25519_public_key_is_valid(hello.key_share)) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_ILLEGAL_PARAMETER,
                       "the server's x25519 key share is all zeros");
  }

  /* From here the handshake is committed: the ServerHello is in the transcript
     and the handshake secrets come from that transcript, so nothing checked
     after this point can be checked before it. */
  if (wt_tls_transcript_absorb_and_hash(&handshake->transcript, message,
                                        message_len,
                                        transcript_hash) != 0) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the ServerHello could not be hashed");
  }

  if (wt_x25519_shared_secret(handshake->client_key_private, hello.key_share,
                              ecdh) != 0) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_ILLEGAL_PARAMETER,
                       "the x25519 shared secret could not be computed");
  }
  status = wt_tls_handshake_key_schedule(ecdh, sizeof(ecdh), transcript_hash,
                                         &handshake->secrets);
  wt_secure_zero(ecdh, sizeof(ecdh));
  if (status != 0) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                       "the handshake key schedule failed");
  }

  if (wt_tls_traffic_keys(handshake->secrets.client_handshake_traffic,
                          WT_TLS_AEAD_AES_128_GCM,
                          &handshake->client_handshake_keys) != 0 ||
      wt_tls_traffic_keys(handshake->secrets.server_handshake_traffic,
                          WT_TLS_AEAD_AES_128_GCM,
                          &handshake->server_handshake_keys) != 0) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                       "the handshake traffic keys could not be derived");
  }
  handshake->keys_available |=
      wt_tls_client_key_bit(WT_TLS_LEVEL_HANDSHAKE, 0) |
      wt_tls_client_key_bit(WT_TLS_LEVEL_HANDSHAKE, 1);

  handshake->state = WT_TLS_STATE_WAIT_ENCRYPTED_EXTENSIONS;
  return 0;
}

/* RFC 8446 section 4.3.1 and RFC 9001 section 8.2. */
int wt_tls_client_handle_encrypted_extensions(wt_tls_client_t *handshake,
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
      return wt_tls_client_fail(handshake, WT_TLS_ALERT_ILLEGAL_PARAMETER,
                         "the EncryptedExtensions is not well formed");
    }
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
                       "the EncryptedExtensions did not parse");
  }

  if (wt_tls_encrypted_extensions_check(&ee, handshake->params, &reject,
                                        &offender) != 0) {
    if (reject == WT_TLS_EE_UNSOLICITED_EXTENSION) {
      return wt_tls_client_fail(handshake, WT_TLS_ALERT_UNSUPPORTED_EXTENSION,
                         "the server sent an extension the client did not "
                         "offer");
    }
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_ILLEGAL_PARAMETER,
                       "the server sent an extension that does not belong in "
                       "EncryptedExtensions");
  }

  /* RFC 9001 section 8.2: a QUIC client that receives EncryptedExtensions
     without the transport parameters MUST close the connection, and the error
     is the one a fatal missing_extension alert would produce. This is checked
     before ALPN because without transport parameters there is no connection to
     negotiate a protocol for. */
  if (!ee.has_transport_parameters) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_MISSING_EXTENSION,
                       "the server did not send QUIC transport parameters");
  }
  /* Copied rather than borrowed: the caller's EncryptedExtensions buffer is
     the caller's to read into again the moment this call returns, and a getter
     handing back a view into it would be handing back whatever the caller put
     there next. The copy is bounded, and a peer whose parameters do not fit is
     refused here rather than truncated, because truncating them would silently
     drop flow-control limits the peer is relying on. */
  if (ee.transport_parameters_len >
      sizeof(handshake->transport_parameters)) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
                       "the peer's transport parameters are larger than this "
                       "client will hold");
  }
  if (ee.transport_parameters_len > 0U) {
    memcpy(handshake->transport_parameters, ee.transport_parameters,
           ee.transport_parameters_len);
  }
  handshake->transport_parameters_len = ee.transport_parameters_len;
  handshake->transport_parameters_seen = 1;

  /* RFC 7301 section 3.2: if the client offered ALPN, the server must select
     one of the offered protocols, and a client that receives anything else
     aborts with no_application_protocol. Selecting nothing is the same
     refusal -- and for HTTP/3 it is fatal, because "h3" is how the server says
     it speaks HTTP/3 at all. */
  if (handshake->params->alpn_protocols_len != 0U) {
    if (!ee.has_alpn) {
      return wt_tls_client_fail(handshake, WT_TLS_ALERT_NO_APPLICATION_PROTOCOL,
                         "the server selected no ALPN protocol");
    }
    if (!wt_tls_client_alpn_list_contains(handshake->params->alpn_protocols,
                            handshake->params->alpn_protocols_len, ee.alpn,
                            ee.alpn_len)) {
      return wt_tls_client_fail(handshake, WT_TLS_ALERT_NO_APPLICATION_PROTOCOL,
                         "the server selected an ALPN protocol that was not "
                         "offered");
    }
    /* Copied, not borrowed: the message buffer is the caller's and may be
       reused before the caller asks what was negotiated. */
    if (ee.alpn_len > sizeof(handshake->alpn)) {
      return wt_tls_client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                         "the selected ALPN protocol does not fit");
    }
    memcpy(handshake->alpn, ee.alpn, ee.alpn_len);
    handshake->alpn_len = ee.alpn_len;
    handshake->alpn_selected = 1;
  }

  /* RFC 8446 section 4.4.1: EncryptedExtensions is in the transcript. */
  if (wt_tls_transcript_absorb(&handshake->transcript, message, message_len) !=
      0) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the EncryptedExtensions could not be hashed");
  }
  handshake->state = WT_TLS_STATE_WAIT_CERTIFICATE;
  return 0;
}

/* RFC 8446 section 4.3.2. The next message from the server, if it sends one, is
 * a CertificateRequest, and it comes before the Certificate. */
int wt_tls_client_handle_certificate_request(wt_tls_client_t *handshake,
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
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
                       "the CertificateRequest did not parse");
  }
  if (type != WT_TLS_HS_CERTIFICATE_REQUEST) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_UNEXPECTED_MESSAGE,
                       "a message other than CertificateRequest arrived where "
                       "a CertificateRequest was expected");
  }
  if (body_len < 1U) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
                       "the CertificateRequest has no context length");
  }
  context_len = message[body_offset];
  if ((size_t)context_len > body_len - 1U) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
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
      return wt_tls_client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
                         "the CertificateRequest has no extension list");
    }
    extensions_len = ((size_t)message[body_offset + after_context] << 8) |
                     (size_t)message[body_offset + after_context + 1U];
    if (extensions_len != body_len - after_context - 2U) {
      return wt_tls_client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
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
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
                       "the CertificateRequest context is too long");
  }
  memcpy(handshake->certificate_request_context, message + body_offset + 1U,
         (size_t)context_len);
  handshake->certificate_request_context_len = (size_t)context_len;
  handshake->client_auth_requested = 1;

  /* RFC 8446 section 4.4.1: CertificateRequest is in the transcript. */
  if (wt_tls_transcript_absorb(&handshake->transcript, message, message_len) !=
      0) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
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
int wt_tls_client_handle_certificate(wt_tls_client_t *handshake,
                              const uint8_t *message, size_t message_len,
                              const uint8_t **out, size_t *out_len,
                              wt_tls_level_t *out_level) {
  wt_tls_certificate_chain_t chain;
  wt_tls_pin_result_t pin;

  (void)out;
  (void)out_len;
  (void)out_level;

  if (wt_tls_parse_certificate(message, message_len, &chain) != 0) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
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
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                       "no operator key is pinned, so no server can be "
                       "trusted");
  }
  if (pin == WT_TLS_PIN_BAD_CERTIFICATE) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_BAD_CERTIFICATE,
                       "the server's certificate could not be read");
  }
  if (pin == WT_TLS_PIN_WRONG_KEY_TYPE) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_UNKNOWN_CA,
                       "the server's key type is not the pinned key's type");
  }
  if (pin != WT_TLS_PIN_ACCEPTED) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_UNKNOWN_CA,
                       "the server's key is not the pinned operator key");
  }

  /* The key is taken out of the certificate now, while the Certificate message
     is in hand, because the signature that uses it does not arrive for another
     two messages and the caller's buffer is the caller's to reuse. The key is
     bounded and the certificate is not, so the certificate is the thing that
     gets released. A certificate whose key cannot be read is refused with the
     alert a bad certificate gets, because that is what it is. */
  if (wt_tls_certificate_public_key(chain.entries[0], chain.lengths[0],
                                    &handshake->leaf_public_key) != 0) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_BAD_CERTIFICATE,
                       "the server's public key could not be read");
  }

  if (wt_tls_transcript_absorb(&handshake->transcript, message, message_len) !=
      0) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the Certificate could not be hashed");
  }
  handshake->state = WT_TLS_STATE_WAIT_CERTIFICATE_VERIFY;
  return 0;
}

/* RFC 8446 section 4.4.3. This is where the transcript is tied to the key. */
int wt_tls_client_handle_certificate_verify(wt_tls_client_t *handshake,
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
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_DECODE_ERROR,
                       "the CertificateVerify did not parse");
  }

  /* RFC 8446 section 4.4.3: "the client MUST verify that the signature scheme
     is one it offered". A server that signs with a scheme the client never
     offered is not merely inconvenient -- the scheme list is the client's
     statement of what it can check, so accepting an unoffered scheme means
     accepting a signature that was never meant to be trustworthy. */
  if (!wt_tls_client_in_uint16_list(handshake->params->signature_algorithms,
                      handshake->params->signature_algorithm_count,
                      verify.scheme)) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_ILLEGAL_PARAMETER,
                       "the server signed with a scheme that was not offered");
  }

  /* The transcript hash is taken BEFORE this message: RFC 8446 hashes a message
     into the transcript after its own signature has been checked, and a caller
     that absorbed first would never verify anything. */
  if (wt_tls_transcript_hash(&handshake->transcript, transcript_hash) != 0) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the transcript could not be read");
  }
  if (wt_tls_certificate_verify_content(
          wt_tls_server_certificate_verify_context, transcript_hash, content,
          sizeof(content), &content_len) != 0) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the signed content could not be built");
  }

  verified = wt_tls_certificate_verify_signature_with_key(
      &handshake->leaf_public_key, &verify, content, content_len);
  if (verified != 1) {
    /* 0 and -1 are both refusals and both mean the same thing to the peer: the
       handshake did not authenticate. RFC 8446 section 6.2 names decrypt_error
       for "unable to correctly verify a signature". */
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_DECRYPT_ERROR,
                       "the server's signature over the transcript did not "
                       "verify");
  }

  if (wt_tls_transcript_absorb(&handshake->transcript, message, message_len) !=
      0) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the CertificateVerify could not be hashed");
  }
  handshake->state = WT_TLS_STATE_WAIT_FINISHED;
  return 0;
}
