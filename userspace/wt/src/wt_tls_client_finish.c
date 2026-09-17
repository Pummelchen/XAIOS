/* The client's response flight and the server's Finished for the QUIC TLS 1.3
 * client.
 *
 * Split out of `wt_tls_client.c`. `build_client_flight` builds the empty
 * Certificate (when the server asked for one) and the client's Finished into
 * the handshake's own buffer, in the order RFC 8446 section 4.4.4 requires;
 * `wt_tls_client_handle_finished` verifies the server's Finished, derives the
 * application keys and only then calls it. That order is the reason the two
 * live together. Both are called from `wt_tls_client.c` through the
 * declarations in `wt_tls_client_internal.h`.
 */

#include "wt_tls_client_internal.h"

#include "wt_crypto.h"

#include <string.h>

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
      return wt_tls_client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
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
      return wt_tls_client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                         "the client's Certificate could not be hashed");
    }
    handshake->flight_len = offset;
  }

  /* The Finished MAC is over the transcript through the server's Finished,
     including the client's Certificate when there is one. */
  if (wt_tls_transcript_hash(&handshake->transcript, transcript_hash) != 0) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the transcript could not be read");
  }
  if (wt_tls_finished_compute(handshake->secrets.client_handshake_traffic,
                              transcript_hash, verify_data) != 0) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the client's Finished could not be computed");
  }

  {
    uint8_t *p = handshake->flight + handshake->flight_len;
    size_t remaining = sizeof(handshake->flight) - handshake->flight_len;
    if (remaining < 4U + WT_TLS_FINISHED_LEN) {
      return wt_tls_client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
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
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the client's Finished could not be hashed");
  }

  *out = handshake->flight;
  *out_len = handshake->flight_len;
  /* RFC 9001 section 4.1.5: the client's second flight goes at the Handshake
     level, under handshake keys. The application keys derived alongside it are
     reported available in the same call, because RFC 9001 has the client
     install 1-RTT keys once its Finished is produced. The level is kept as well
     as returned, because the flight outlives this call and a caller that asks
     for it again needs to know where to send it -- which is what the field was
     declared for and, until B-93, never set. */
  handshake->flight_level = WT_TLS_LEVEL_HANDSHAKE;
  *out_level = handshake->flight_level;
  return 0;
}

/* RFC 8446 section 4.4.4. */
int wt_tls_client_handle_finished(wt_tls_client_t *handshake, const uint8_t *message,
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
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the transcript could not be read");
  }
  verified = wt_tls_finished_verify(handshake->secrets.server_handshake_traffic,
                                    transcript_hash, message, message_len);
  if (verified != 1) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_DECRYPT_ERROR,
                       "the server's Finished did not verify");
  }

  if (wt_tls_transcript_absorb_and_hash(&handshake->transcript, message,
                                        message_len,
                                        after_server_finished) != 0) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_INTERNAL_ERROR,
                       "the server's Finished could not be hashed");
  }

  /* The application traffic secrets come from the transcript through the
     server's Finished, which exists exactly now. Deriving them any earlier
     would derive them from the wrong transcript; the two-phase schedule is what
     makes that impossible to get wrong by accident. */
  if (wt_tls_application_key_schedule(&handshake->secrets,
                                      after_server_finished,
                                      &application_phase) != 0) {
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
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
    return wt_tls_client_fail(handshake, WT_TLS_ALERT_HANDSHAKE_FAILURE,
                       "the application traffic keys could not be derived");
  }
  handshake->keys_available |=
      wt_tls_client_key_bit(WT_TLS_LEVEL_APPLICATION, 0) |
      wt_tls_client_key_bit(WT_TLS_LEVEL_APPLICATION, 1);

  if (build_client_flight(handshake, out, out_len, out_level) != 0) {
    return -1;
  }

  /* RFC 9001 section 4.1.1: the handshake is complete at an endpoint once it
     has both sent its Finished and verified the peer's. Both are true here, so
     the state says so rather than waiting for the socket. */
  handshake->state = WT_TLS_STATE_CONNECTED;
  return 0;
}
