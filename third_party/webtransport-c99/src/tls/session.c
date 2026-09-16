/* The TLS 1.3 client handshake. See webtransport/tls/session.h. */

#include "webtransport/tls/session.h"

#include <stdio.h>
#include <stdlib.h>

#include "webtransport/crypto/crypto.h"

#include <string.h>

/* The ciphersuite this implementation offers, which is the only one it has a schedule for
 * (RFC 8446 section 9.1 makes it mandatory). */
#define WT_TLS_CIPHER_SUITE WT_TLS_CIPHER_AES_128_GCM_SHA256

/* The marker `wt_tls_client_t.live` carries. An arbitrary constant: it only has to be a value
 * a zeroed or uninitialised struct is unlikely to hold. */
#define WT_TLS_CLIENT_LIVE UINT64_C(0x5a17e7c3d94b0286)

/* A message that the handshake refuses moves the machine here, so a caller cannot keep
 * feeding it and cannot read a secret out of a failed handshake.
 *
 * A FAILED MACHINE HOLDS NOTHING. The transcript is released rather than left for a caller to
 * release, because the one thing a caller does after a failure is move on, and a hash context
 * that only a `clear` call would free is a leak waiting for the caller who does not make it.
 * LeakSanitizer on the Linux CI leg found exactly that: a test that reused a client struct
 * after a failed begin leaked the context the begin had allocated. */
/* Every secret this machine derived goes with the failure, because the comment above says a FAILED MACHINE
 * HOLDS NOTHING and the first version released only the transcript. What was left -- the handshake and master
 * secrets, both directions' traffic secrets and the private key -- is unreachable through the API (every entry
 * point rejects FAILED) but it is still key material sitting in a caller-owned struct, and a struct is memory a
 * caller may reuse. `wt_secure_zero` rather than `memset`, because a compiler is free to delete a memset of a
 * buffer that is never read again. */
static void client_scrub(wt_tls_client_t *client) {
  wt_secure_zero(client->handshake_secret, sizeof(client->handshake_secret));
  wt_secure_zero(client->master_secret, sizeof(client->master_secret));
  wt_secure_zero(client->client_handshake_secret, sizeof(client->client_handshake_secret));
  wt_secure_zero(client->server_handshake_secret, sizeof(client->server_handshake_secret));
  wt_secure_zero(client->client_application_secret, sizeof(client->client_application_secret));
  wt_secure_zero(client->server_application_secret, sizeof(client->server_application_secret));
  wt_secure_zero(client->private_key, sizeof(client->private_key));
}

static wt_status_t fail(wt_tls_client_t *client, wt_status_t status) {
  wt_tls13_transcript_clear(&client->transcript);
  client_scrub(client);
  client->state = WT_TLS_CLIENT_FAILED;
  return status;
}

/* Every entry point into the state machine checks this first: a failed handshake is over,
 * and what it derived is not to be used. */
static wt_status_t live(const wt_tls_client_t *client) {
  if (client == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (client->state == WT_TLS_CLIENT_FAILED) return WT_ERR_STATE;
  return WT_OK;
}

/* Derive the shared secret and the two handshake traffic secrets from a ServerHello's key
 * share, and the master secret that the application secrets will come from.
 *
 * THE TRANSCRIPT IS READ AFTER THE SERVERHELLO IS ABSORBED, because RFC 8446 section 7.1
 * defines both handshake traffic secrets as Derive-Secret(Handshake Secret, label,
 * Transcript-Hash(ClientHello...ServerHello)) -- the ServerHello is part of the transcript
 * they are over. Reading one message early produces two secrets that are wrong and a
 * handshake that fails at the first record with a tag error that names nothing.
 *
 * The chain is also this file's only use of the Early Secret: with no pre-shared key it is
 * HKDF-Extract over a zero PSK, which is where the schedule begins. */
static wt_status_t derive_after_server_hello(wt_tls_client_t *client,
                                             const wt_tls_key_share_t *share) {
  uint8_t early_secret[WT_TLS13_SECRET_LEN];
  uint8_t ecdhe[WT_TLS_X25519_KEY_LEN];
  uint8_t transcript_hash[WT_TLS13_SECRET_LEN];
  wt_status_t status;

  status = wt_tls_key_share_shared_secret(WT_TLS_GROUP_X25519, client->private_key,
                                         share->key, share->key_len, ecdhe);
  if (status != WT_OK) return status;
  status = wt_tls13_early_secret(NULL, 0U, early_secret);
  if (status != WT_OK) {
    wt_secure_zero(ecdhe, sizeof(ecdhe));
    return status;
  }
  status = wt_tls13_handshake_secret(early_secret, ecdhe, sizeof(ecdhe),
                                     client->handshake_secret);
  wt_secure_zero(early_secret, sizeof(early_secret));
  wt_secure_zero(ecdhe, sizeof(ecdhe));
  if (status != WT_OK) return status;
  status = wt_tls13_transcript_hash(&client->transcript, transcript_hash);
  if (status != WT_OK) return status;
  status = wt_tls13_handshake_traffic_secrets(
      client->handshake_secret, transcript_hash, client->client_handshake_secret,
      client->server_handshake_secret);
  wt_secure_zero(transcript_hash, sizeof(transcript_hash));
  if (status != WT_OK) return status;
  return wt_tls13_master_secret(client->handshake_secret, client->master_secret);
}

/* The two application secrets, derived from the transcript through the server's Finished,
 * which is the point RFC 8446 section 7.1 names for them. */
static wt_status_t derive_application_secrets(wt_tls_client_t *client) {
  uint8_t transcript_hash[WT_TLS13_SECRET_LEN];
  wt_status_t status;

  status = wt_tls13_transcript_hash(&client->transcript, transcript_hash);
  if (status != WT_OK) return status;
  status = wt_tls13_application_traffic_secrets(
      client->master_secret, transcript_hash, client->client_application_secret,
      client->server_application_secret);
  wt_secure_zero(transcript_hash, sizeof(transcript_hash));
  return status;
}

/* Handle a ServerHello: the version, the ciphersuite, the session id echo and the key
 * share, then the secrets that depend on it. */
static wt_status_t receive_server_hello(wt_tls_client_t *client,
                                        const uint8_t *message, size_t len) {
  wt_tls_server_hello_t hello;
  const wt_tls_extension_t *extension;
  wt_tls_key_share_t share;
  uint16_t version = 0U;
  wt_status_t status;

  status = wt_tls_server_hello_parse(message, len, &hello);
  if (status != WT_OK) return status;
  /* RFC 8446 section 4.1.3: the ciphersuite must be one the client offered. This
   * implementation offers one, so anything else is a server choosing something the
   * schedule here cannot derive. */
  if (hello.cipher_suite != WT_TLS_CIPHER_SUITE) return WT_ERR_TLS;
  /* The session id must be echoed, which is how a server says it is answering this
   * handshake and not another. */
  if (hello.session_id_len != client->config.session_id_len) return WT_ERR_TLS;
  if (hello.session_id_len != 0U &&
      memcmp(hello.session_id, client->config.session_id, hello.session_id_len) != 0) {
    return WT_ERR_TLS;
  }
  /* TLS 1.3 is negotiated in supported_versions, and its absence means the server chose
   * something older (RFC 8446 section 4.2.1). */
  extension = wt_tls_extensions_find(&hello.extensions,
                                     WT_TLS_EXTENSION_SUPPORTED_VERSIONS);
  if (extension == NULL) return WT_ERR_TLS;
  status = wt_tls_supported_versions_server(extension, &version);
  if (status != WT_OK) return status;
  if (version != WT_TLS_VERSION_1_3) return WT_ERR_TLS;

  extension = wt_tls_extensions_find(&hello.extensions, WT_TLS_EXTENSION_KEY_SHARE);
  if (extension == NULL) return WT_ERR_TLS;
  status = wt_tls_key_share_server(extension, &share);
  if (status != WT_OK) return status;
  /* The group must be the one we offered a share for. A server that picks another group
   * would need a second round trip, and this implementation refuses HelloRetryRequest
   * rather than handling it, so a group we cannot complete ends the handshake. */
  if (share.group != WT_TLS_GROUP_X25519) return WT_ERR_TLS;

  /* Absorbed first, because the handshake traffic secrets are over the transcript through
   * this message. */
  status = wt_tls13_transcript_append(&client->transcript, message, len);
  if (status != WT_OK) return status;
  status = derive_after_server_hello(client, &share);
  if (status != WT_OK) return status;
  client->state = WT_TLS_CLIENT_WAIT_ENCRYPTED_EXTENSIONS;
  return WT_OK;
}

/* Handle EncryptedExtensions: ALPN first, because a protocol the caller did not ask for is
 * a server that would be speaking something else, and then the transport parameters QUIC
 * requires. */
static wt_status_t receive_encrypted_extensions(wt_tls_client_t *client,
                                               const uint8_t *message, size_t len) {
  wt_tls_extension_list_t extensions;
  const wt_tls_extension_t *extension;
  wt_status_t status;

  status = wt_tls_encrypted_extensions_parse(message, len, &extensions);
  if (status != WT_OK) return status;

  if (client->config.alpn_count != 0U) {
    wt_tls_alpn_t alpn;
    size_t i;
    int matched = 0;

    extension = wt_tls_extensions_find(&extensions, WT_TLS_EXTENSION_ALPN);
    /* RFC 8446 section 4.2: a server that does not select a protocol MUST NOT send the
     * extension, and a client that asked for one must fail the handshake. */
    if (extension == NULL) return WT_ERR_TLS;
    status = wt_tls_alpn_parse(extension, &alpn);
    if (status != WT_OK) return status;
    /* "The server MUST NOT send more than one ProtocolName" -- so exactly one name, and it
     * must be one of ours. */
    if (alpn.count != 1U) return WT_ERR_TLS;
    for (i = 0U; i < client->config.alpn_count; i++) {
      size_t offered = strlen(client->config.alpn[i]);
      if (offered == (size_t)alpn.lengths[0] &&
          memcmp(alpn.names[0], client->config.alpn[i], offered) == 0) {
        matched = 1;
      }
    }
    if (!matched) return WT_ERR_TLS;
    client->negotiated_alpn = alpn.names[0];
    client->negotiated_alpn_len = (size_t)alpn.lengths[0];
  }

  if (client->config.require_transport_parameters) {
    const uint8_t *parameters = NULL;
    size_t parameters_len = 0U;
    extension = wt_tls_extensions_find(
        &extensions, WT_TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS);
    /* RFC 9001 section 8.2: an endpoint MUST treat the absence of the extension as a
     * handshake failure rather than as a peer with no parameters. */
    if (extension == NULL) return WT_ERR_TLS;
    status = wt_tls_transport_parameters(extension, &parameters, &parameters_len);
    if (status != WT_OK) return status;
    if (parameters_len == 0U) return WT_ERR_TLS;
    /* A view into the caller's message, valid until the next call. The QUIC layer reads it
     * before then, which is what its own contract says. */
    client->peer_transport_parameters = parameters;
    client->peer_transport_parameters_len = parameters_len;
  } else {
    extension = wt_tls_extensions_find(
        &extensions, WT_TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS);
    if (extension != NULL) {
      const uint8_t *parameters = NULL;
      size_t parameters_len = 0U;
      if (wt_tls_transport_parameters(extension, &parameters, &parameters_len) ==
          WT_OK) {
        client->peer_transport_parameters = parameters;
        client->peer_transport_parameters_len = parameters_len;
      }
    }
  }

  status = wt_tls13_transcript_append(&client->transcript, message, len);
  if (status != WT_OK) return status;
  client->state = WT_TLS_CLIENT_WAIT_CERTIFICATE;
  return WT_OK;
}

/* Handle the server's Certificate: validate the chain and keep the leaf's public key for
 * the CertificateVerify that must follow. */
static wt_status_t receive_certificate(wt_tls_client_t *client, const uint8_t *message,
                                       size_t len) {
  wt_tls_certificate_t certificate;
  wt_status_t status;

  status = wt_tls_certificate_parse(message, len, &certificate);
  if (status != WT_OK) return status;
  /* RFC 8446 section 4.4.2: the server's Certificate has an empty request context. */
  if (certificate.request_context_len != 0U) return WT_ERR_PROTOCOL;
  if (certificate.count == 0U) return WT_ERR_TRUST;
  status = wt_tls_trust_verify(&client->config.trust, &certificate, client->peer_spki,
                               &client->peer_spki_len);
  if (status != WT_OK) return status;
  status = wt_tls13_transcript_append(&client->transcript, message, len);
  if (status != WT_OK) return status;
  client->state = WT_TLS_CLIENT_WAIT_CERTIFICATE_VERIFY;
  return WT_OK;
}

/* Handle CertificateVerify: the signature is over the transcript THROUGH the Certificate,
 * so the hash is taken before this message is absorbed. */
static wt_status_t receive_certificate_verify(wt_tls_client_t *client,
                                              const uint8_t *message, size_t len) {
  wt_tls_certificate_verify_t verify;
  uint8_t transcript_hash[WT_TLS13_SECRET_LEN];
  uint8_t content[WT_TLS_CERTIFICATE_VERIFY_CONTENT_LEN];
  wt_status_t status;

  status = wt_tls_certificate_verify_parse(message, len, &verify);
  if (status != WT_OK) return status;
  status = wt_tls13_transcript_hash(&client->transcript, transcript_hash);
  if (status != WT_OK) return status;
  status = wt_tls_certificate_verify_content(1, transcript_hash, content);
  wt_secure_zero(transcript_hash, sizeof(transcript_hash));
  if (status != WT_OK) return status;
  status = wt_tls_signature_verify(client->peer_spki, client->peer_spki_len,
                                   verify.scheme, content, sizeof(content),
                                   verify.signature, verify.signature_len);
  wt_secure_zero(content, sizeof(content));
  if (status != WT_OK) return status;
  status = wt_tls13_transcript_append(&client->transcript, message, len);
  if (status != WT_OK) return status;
  client->state = WT_TLS_CLIENT_WAIT_FINISHED;
  return WT_OK;
}

/* Handle the server's Finished: verify it, derive the application secrets, and produce the
 * client's Finished. This is where the handshake becomes usable, so it is the only place
 * the application secrets are derived. */
static wt_status_t receive_finished(wt_tls_client_t *client, const uint8_t *message,
                                    size_t len, uint8_t *out, size_t out_capacity,
                                    size_t *out_len) {
  uint8_t verify_data[WT_TLS13_FINISHED_LEN];
  uint8_t through_certificate_verify[WT_TLS13_SECRET_LEN];
  uint8_t through_server_finished[WT_TLS13_SECRET_LEN];
  uint8_t ours[WT_TLS13_FINISHED_LEN];
  wt_status_t status;

  status = wt_tls_finished_parse(message, len, verify_data);
  if (status != WT_OK) return status;

  /* THE SERVER'S FINISHED IS OVER THE TRANSCRIPT THROUGH CERTIFICATEVERIFY. This message is
   * not part of what it authenticates, so the hash is taken before it is absorbed -- and
   * the client's Finished below is over the transcript through THIS message, so that hash is
   * taken after. The one-message difference between the two is the whole reason the two
   * hashes exist separately here. */
  status = wt_tls13_transcript_hash(&client->transcript, through_certificate_verify);
  if (status != WT_OK) return status;
  status = wt_tls13_finished_check(client->server_handshake_secret,
                                   through_certificate_verify, verify_data,
                                   sizeof(verify_data));
  wt_secure_zero(through_certificate_verify, sizeof(through_certificate_verify));
  if (status != WT_OK) return status;
  status = wt_tls13_transcript_append(&client->transcript, message, len);
  if (status != WT_OK) return status;

  /* The application secrets come from the transcript through the server's Finished, which
   * is now the current state; `derive_application_secrets` reads that hash itself. */
  status = derive_application_secrets(client);
  if (status != WT_OK) return status;
  status = wt_tls13_transcript_hash(&client->transcript, through_server_finished);
  if (status != WT_OK) return status;
  status = wt_tls13_finished_verify_data(client->client_handshake_secret,
                                         through_server_finished, ours);
  wt_secure_zero(through_server_finished, sizeof(through_server_finished));
  if (status != WT_OK) return status;
  status = wt_tls_finished_build(ours, out, out_capacity, out_len);
  wt_secure_zero(ours, sizeof(ours));
  if (status != WT_OK) return status;
  /* The transcript for anything that follows the handshake -- a session ticket, a key
   * update's confirmation -- includes the client's Finished. */
  status = wt_tls13_transcript_append(&client->transcript, out, *out_len);
  if (status != WT_OK) return status;
  client->state = WT_TLS_CLIENT_CONNECTED;
  return WT_OK;
}

/* ---------------------------------------------------------------- the API */

static wt_status_t begin_common(wt_tls_client_t *client,
                                const wt_tls_client_config_t *config) {
  wt_status_t status;

  if (client == NULL || config == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (config->session_id == NULL && config->session_id_len != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (config->session_id_len > WT_TLS_SESSION_ID_MAX) return WT_ERR_LIMIT;
  if (config->alpn == NULL && config->alpn_count != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (config->transport_parameters == NULL &&
      config->transport_parameters_len != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* Anything a previous handshake on this machine left is released first: beginning again is
   * a fresh start, and the marker is what makes that a release rather than a leak. For a
   * struct the caller has not used yet the marker will not match, so nothing is released and
   * nothing uninitialised is read beyond the marker itself. */
  if (client->live == WT_TLS_CLIENT_LIVE) {
    wt_tls13_transcript_clear(&client->transcript);
  }
  memset(client, 0, sizeof(*client));
  client->config = *config;
  if (config->x25519_private != NULL) {
    memcpy(client->private_key, config->x25519_private, WT_TLS_X25519_KEY_LEN);
    status = wt_tls_key_share_public_key(WT_TLS_GROUP_X25519, client->private_key,
                                         client->public_key);
  } else {
    status = wt_tls_key_share_generate(WT_TLS_GROUP_X25519, client->private_key,
                                       client->public_key);
  }
  /* Neither failure below has anything to release: the key pair is bytes in the caller's
   * struct and the transcript is not initialised until the last line. */
  if (status != WT_OK) {
    client->state = WT_TLS_CLIENT_FAILED;
    return status;
  }
  status = wt_tls13_transcript_init(&client->transcript);
  if (status != WT_OK) {
    client->state = WT_TLS_CLIENT_FAILED;
    return status;
  }
  /* Marked last, once there is something to release: a machine that failed before this point
   * holds nothing, and a marker set early would make the next begin release a context that
   * was never made. */
  client->live = WT_TLS_CLIENT_LIVE;
  return WT_OK;
}

wt_status_t wt_tls_client_begin(wt_tls_client_t *client,
                                const wt_tls_client_config_t *config,
                                const uint8_t *client_hello,
                                size_t client_hello_len) {
  wt_status_t status;

  status = begin_common(client, config);
  if (status != WT_OK) return status;
  if (client_hello == NULL || client_hello_len == 0U) {
    return fail(client, WT_ERR_INVALID_ARGUMENT);
  }
  /* The transcript is over the bytes that were sent. A ClientHello that is not a
   * ClientHello is refused here rather than after a round trip, because every secret this
   * handshake derives depends on these bytes being the ones the server saw. */
  status = wt_tls13_transcript_append(&client->transcript, client_hello,
                                      client_hello_len);
  if (status != WT_OK) return fail(client, status);
  /* A DIAGNOSTIC, gated by the same environment variable as the other two: the ClientHello this client HASHED, so
   * that it can be compared byte for byte with the one that went out on the wire (decrypted independently from
   * its Initial packet). A transcript that hashes bytes other than the ones it sent is invisible to a pair of the
   * same code and fatal to a peer, which is the shape this investigation has been narrowing to (WT-135). */
  {
    const char *transcript_log_path = getenv("WT_TLS_TRANSCRIPT_LOG");
    if (transcript_log_path != NULL) {
      FILE *transcript_log = fopen(transcript_log_path, "a");
      if (transcript_log != NULL) {
        size_t index;
        fprintf(transcript_log, "hashed-clienthello length=%zu bytes=", client_hello_len);
        for (index = 0U; index < client_hello_len; index++) {
          fprintf(transcript_log, "%02x", client_hello[index]);
        }
        fprintf(transcript_log, "\n");
        (void)fclose(transcript_log);
      }
    }
  }
  client->state = WT_TLS_CLIENT_WAIT_SERVER_HELLO;
  return WT_OK;
}

wt_status_t wt_tls_client_begin_built(wt_tls_client_t *client,
                                      const wt_tls_client_config_t *config,
                                      uint8_t *out, size_t out_capacity,
                                      size_t *out_len) {
  wt_tls_client_hello_params_t params;
  static const uint16_t groups[] = {WT_TLS_GROUP_X25519};
  static const uint16_t schemes[] = {WT_TLS_SIGNATURE_ECDSA_SECP256R1_SHA256,
                                     WT_TLS_SIGNATURE_RSA_PSS_RSAE_SHA256,
                                     WT_TLS_SIGNATURE_ED25519};
  static const uint16_t cipher_suites[] = {WT_TLS_CIPHER_SUITE};
  wt_tls_key_share_t share;
  uint8_t random[WT_TLS_RANDOM_LEN];
  uint8_t hello[WT_TLS_CLIENT_HELLO_MAX];
  size_t hello_len = 0U;
  wt_status_t status;

  if (out == NULL || out_len == NULL) return WT_ERR_INVALID_ARGUMENT;
  *out_len = 0U;
  status = begin_common(client, config);
  if (status != WT_OK) return status;

  status = wt_random_bytes(random, sizeof(random));
  if (status != WT_OK) return fail(client, status);
  share.group = WT_TLS_GROUP_X25519;
  share.key = client->public_key;
  share.key_len = sizeof(client->public_key);
  memset(&params, 0, sizeof(params));
  params.random = random;
  params.session_id = config->session_id;
  params.session_id_len = config->session_id_len;
  params.cipher_suites = cipher_suites;
  params.cipher_suite_count = 1U;
  params.host_name = config->host_name;
  params.supported_groups = groups;
  params.supported_group_count = 1U;
  params.signature_schemes = schemes;
  params.signature_scheme_count = 3U;
  params.key_shares = &share;
  params.key_share_count = 1U;
  params.alpn = config->alpn;
  params.alpn_count = config->alpn_count;
  params.transport_parameters = config->transport_parameters;
  params.transport_parameters_len = config->transport_parameters_len;

  /* Built into a local first, so that a refusal leaves the caller's buffer untouched and
   * the transcript is only seeded with a message that exists. */
  status = wt_tls_client_hello_build(&params, hello, sizeof(hello), &hello_len);
  if (status != WT_OK) return fail(client, status);
  /* The buffer is checked before anything is copied or absorbed, so a refusal here leaves
   * the caller's bytes untouched and the machine holding nothing. */
  if (out_capacity < hello_len) return fail(client, WT_ERR_LIMIT);
  memcpy(out, hello, hello_len);
  *out_len = hello_len;
  status = wt_tls13_transcript_append(&client->transcript, out, hello_len);
  if (status != WT_OK) return fail(client, status);
  /* The same diagnostic as the other entry point: whichever way the ClientHello is built, what matters is which
   * BYTES were hashed (WT-135). */
  {
    const char *transcript_log_path = getenv("WT_TLS_TRANSCRIPT_LOG");
    if (transcript_log_path != NULL) {
      FILE *transcript_log = fopen(transcript_log_path, "a");
      if (transcript_log != NULL) {
        size_t index;
        fprintf(transcript_log, "hashed-clienthello length=%zu bytes=", hello_len);
        for (index = 0U; index < hello_len; index++) {
          fprintf(transcript_log, "%02x", out[index]);
        }
        fprintf(transcript_log, "\n");
        (void)fclose(transcript_log);
      }
    }
  }
  client->state = WT_TLS_CLIENT_WAIT_SERVER_HELLO;
  return WT_OK;
}

wt_status_t wt_tls_client_receive(wt_tls_client_t *client, const uint8_t *message,
                                  size_t len, uint8_t *out, size_t out_capacity,
                                  size_t *out_len) {
  wt_tls_handshake_header_t header;
  wt_cursor_t cursor;
  wt_status_t status;

  if (out == NULL || out_len == NULL) return WT_ERR_INVALID_ARGUMENT;
  *out_len = 0U;
  status = live(client);
  if (status != WT_OK) return status;
  if (message == NULL || len < WT_TLS_HANDSHAKE_HEADER_LEN) {
    return fail(client, WT_ERR_TRUNCATED);
  }
  cursor = wt_cursor_init(message, len);
  status = wt_tls_handshake_header_parse(&cursor, &header);
  if (status != WT_OK) return fail(client, status);

  /* The message must be the one the state machine is waiting for. This is the check that
   * makes the order a property of the machine rather than of the caller's care, and it is
   * why a missing or reordered message cannot produce a handshake that looks complete. */
  switch (client->state) {
    case WT_TLS_CLIENT_WAIT_SERVER_HELLO:
      if (header.type != WT_TLS_HANDSHAKE_SERVER_HELLO) {
        return fail(client, WT_ERR_STATE);
      }
      status = receive_server_hello(client, message, len);
      break;
    case WT_TLS_CLIENT_WAIT_ENCRYPTED_EXTENSIONS:
      if (header.type != WT_TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS) {
        return fail(client, WT_ERR_STATE);
      }
      status = receive_encrypted_extensions(client, message, len);
      break;
    case WT_TLS_CLIENT_WAIT_CERTIFICATE:
      if (header.type != WT_TLS_HANDSHAKE_CERTIFICATE) {
        return fail(client, WT_ERR_STATE);
      }
      status = receive_certificate(client, message, len);
      break;
    case WT_TLS_CLIENT_WAIT_CERTIFICATE_VERIFY:
      if (header.type != WT_TLS_HANDSHAKE_CERTIFICATE_VERIFY) {
        return fail(client, WT_ERR_STATE);
      }
      status = receive_certificate_verify(client, message, len);
      break;
    case WT_TLS_CLIENT_WAIT_FINISHED:
      if (header.type != WT_TLS_HANDSHAKE_FINISHED) {
        return fail(client, WT_ERR_STATE);
      }
      status = receive_finished(client, message, len, out, out_capacity, out_len);
      break;
    case WT_TLS_CLIENT_START:
      return fail(client, WT_ERR_STATE);
    case WT_TLS_CLIENT_CONNECTED:
      /* RFC 8446 section 4.6: the handshake is not the end of the CRYPTO stream. A server sends
       * NewSessionTicket (4) afterwards, and a client that does not resume MUST accept and ignore it -- refusing
       * it is not a security property but a defect a third-party peer found: quinn's ticket made this endpoint
       * fail the handshake with CRYPTO_ERROR/unexpected_message (alert 10, code 266), so the session never
       * started (WT-145). The handshake header's own length covers the whole message, so skipping it is exact
       * and no body needs parsing. Everything else really is unexpected here: a CONNECTED client has no
       * post-handshake authentication to answer (13), and KeyUpdate (24) would change the keys, which this tree
       * does not implement -- calling that unexpected is the honest answer rather than silently ignoring it and
       * then failing to decrypt the peer's next packet. */
      if (header.type != WT_TLS_HANDSHAKE_NEW_SESSION_TICKET) {
        return fail(client, WT_ERR_STATE);
      }
      break;
    case WT_TLS_CLIENT_FAILED:
    default:
      return fail(client, WT_ERR_STATE);
  }
  if (status != WT_OK) return fail(client, status);
  return WT_OK;
}

wt_tls_client_state_t wt_tls_client_state(const wt_tls_client_t *client) {
  return (client == NULL) ? WT_TLS_CLIENT_FAILED : client->state;
}

wt_status_t wt_tls_client_handshake_secrets(const wt_tls_client_t *client,
                                            uint8_t read_out[WT_TLS13_SECRET_LEN],
                                            uint8_t write_out[WT_TLS13_SECRET_LEN]) {
  if (client == NULL || read_out == NULL || write_out == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* Available from the ServerHello onward: the handshake's remaining messages are
   * protected with them, so a state machine that withheld them could not proceed. */
  if (client->state < WT_TLS_CLIENT_WAIT_ENCRYPTED_EXTENSIONS ||
      client->state == WT_TLS_CLIENT_FAILED) {
    return WT_ERR_STATE;
  }
  memcpy(read_out, client->server_handshake_secret, WT_TLS13_SECRET_LEN);
  memcpy(write_out, client->client_handshake_secret, WT_TLS13_SECRET_LEN);
  /* There was a diagnostic here that appended both handshake traffic secrets to the file named by the
   * `WT_TLS_SECRET_LOG` environment variable. It is GONE, and the reason is a rule rather than a
   * preference: the plan's Phase 13 asks for "no sensitive logs", and an environment variable is not a
   * log LEVEL -- it is set in the environment of any process that inherits it, it writes key material to a
   * path of the setter's choosing, and a library that can be made to do that is not one a caller can audit
   * by reading its own configuration. The field it read is still filled, so a caller that wants to trace
   * its own handshake can read `wt_tls_client_handshake_secrets` and decide for itself where that goes. */
  return WT_OK;
}

wt_status_t wt_tls_client_application_secrets(
    const wt_tls_client_t *client, uint8_t read_out[WT_TLS13_SECRET_LEN],
    uint8_t write_out[WT_TLS13_SECRET_LEN]) {
  if (client == NULL || read_out == NULL || write_out == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* CONNECTED is the only state in which every security condition has been met, which is
   * why this asks for the state rather than for a flag: there is no flag to forget to
   * check. */
  if (client->state != WT_TLS_CLIENT_CONNECTED) return WT_ERR_STATE;
  memcpy(read_out, client->server_application_secret, WT_TLS13_SECRET_LEN);
  memcpy(write_out, client->client_application_secret, WT_TLS13_SECRET_LEN);
  return WT_OK;
}

const uint8_t *wt_tls_client_alpn(const wt_tls_client_t *client, size_t *out_len) {
  if (client == NULL || out_len == NULL) return NULL;
  *out_len = client->negotiated_alpn_len;
  return client->negotiated_alpn;
}

const uint8_t *wt_tls_client_transport_parameters(const wt_tls_client_t *client,
                                                  size_t *out_len) {
  if (client == NULL || out_len == NULL) return NULL;
  *out_len = client->peer_transport_parameters_len;
  return client->peer_transport_parameters;
}

void wt_tls_client_clear(wt_tls_client_t *client) {
  if (client == NULL) return;
  /* The transcript is released through its own clear, which is what frees the backend's hash
   * context; the rest is a zeroing. */
  wt_tls13_transcript_clear(&client->transcript);
  wt_secure_zero(client, sizeof(*client));
}

/* =============================================================== the server
 *
 * The other half of the same handshake, and deliberately the same shape: the ClientHello is
 * checked for the version, the ciphersuite, a key share this server can use, the ALPN it is
 * willing to speak and the transport parameters QUIC requires; the flight is built in the
 * order the client's checks expect; and the client's Finished gates the application secrets
 * exactly as the server's does on the client. A server that skipped one of those checks would
 * produce a handshake a client refuses, and the mismatch would surface as a tag failure rather
 * than as the missing check.
 */

/* The marker `wt_tls_server_t.live` carries, for the same reason the client has one. */
#define WT_TLS_SERVER_LIVE UINT64_C(0x3c9e51a7b0d4f286)

static void server_scrub(wt_tls_server_t *server) {
  wt_secure_zero(server->handshake_secret, sizeof(server->handshake_secret));
  wt_secure_zero(server->master_secret, sizeof(server->master_secret));
  wt_secure_zero(server->client_handshake_secret, sizeof(server->client_handshake_secret));
  wt_secure_zero(server->server_handshake_secret, sizeof(server->server_handshake_secret));
  wt_secure_zero(server->client_application_secret, sizeof(server->client_application_secret));
  wt_secure_zero(server->server_application_secret, sizeof(server->server_application_secret));
  wt_secure_zero(server->private_key, sizeof(server->private_key));
}

static wt_status_t server_fail(wt_tls_server_t *server, wt_status_t status) {
  wt_tls13_transcript_clear(&server->transcript);
  server_scrub(server);
  server->state = WT_TLS_SERVER_FAILED;
  return status;
}

static wt_status_t server_live(const wt_tls_server_t *server) {
  if (server == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (server->state == WT_TLS_SERVER_FAILED) return WT_ERR_STATE;
  return WT_OK;
}

/* Whether the client offered the ciphersuite this implementation has a schedule for. */
static int offers_cipher_suite(const wt_tls_client_hello_t *hello) {
  size_t i;
  for (i = 0U; i < hello->cipher_suite_count; i++) {
    if (hello->cipher_suites[i] == WT_TLS_CIPHER_SUITE) return 1;
  }
  return 0;
}

/* The client's x25519 key share. RFC 8446 section 4.2.8 allows a client to send shares for
 * several groups; this server can complete one of them, and a client that offered no share it
 * can use would need a HelloRetryRequest to be asked for one -- which this implementation
 * refuses rather than sending. */
static wt_status_t client_x25519_share(const wt_tls_client_hello_t *hello,
                                       wt_tls_key_share_t *out) {
  const wt_tls_extension_t *extension;
  wt_tls_key_share_t shares[WT_TLS_MAX_KEY_SHARES];
  size_t count = 0U;
  size_t i;
  wt_status_t status;

  extension = wt_tls_extensions_find(&hello->extensions, WT_TLS_EXTENSION_KEY_SHARE);
  if (extension == NULL) return WT_ERR_TLS;
  status = wt_tls_key_share_client(extension, shares, WT_TLS_MAX_KEY_SHARES, &count);
  if (status != WT_OK) return status;
  for (i = 0U; i < count; i++) {
    if (shares[i].group == WT_TLS_GROUP_X25519) {
      *out = shares[i];
      return WT_OK;
    }
  }
  return WT_ERR_TLS;
}

/* The ALPN we are willing to speak, and the client's transport parameters when QUIC requires
 * them. Both are views into the client's message, valid until the next call. */
static wt_status_t check_client_extensions(wt_tls_server_t *server,
                                           const wt_tls_client_hello_t *hello) {
  const wt_tls_extension_t *extension;
  wt_status_t status;

  if (server->config.alpn != NULL) {
    wt_tls_alpn_t alpn;
    size_t wanted = strlen(server->config.alpn);
    size_t i;
    int offered = 0;

    extension = wt_tls_extensions_find(&hello->extensions, WT_TLS_EXTENSION_ALPN);
    /* RFC 8446 section 4.2: a server must not select a protocol the client did not offer, and a
     * client that offered none cannot be answered with one. */
    if (extension == NULL) return WT_ERR_TLS;
    status = wt_tls_alpn_parse(extension, &alpn);
    if (status != WT_OK) return status;
    for (i = 0U; i < alpn.count; i++) {
      if ((size_t)alpn.lengths[i] == wanted &&
          memcmp(alpn.names[i], server->config.alpn, wanted) == 0) {
        offered = 1;
        server->negotiated_alpn = alpn.names[i];
        server->negotiated_alpn_len = (size_t)alpn.lengths[i];
      }
    }
    if (!offered) return WT_ERR_TLS;
  }

  if (server->config.require_transport_parameters) {
    const uint8_t *parameters = NULL;
    size_t parameters_len = 0U;
    extension = wt_tls_extensions_find(
        &hello->extensions, WT_TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS);
    /* RFC 9001 section 8.2: their absence is a handshake failure, not a peer with none. */
    if (extension == NULL) return WT_ERR_TLS;
    status = wt_tls_transport_parameters(extension, &parameters, &parameters_len);
    if (status != WT_OK) return status;
    if (parameters_len == 0U) return WT_ERR_TLS;
    server->peer_transport_parameters = parameters;
    server->peer_transport_parameters_len = parameters_len;
  }
  return WT_OK;
}

/* The handshake secrets, from the client's key share. The transcript has already absorbed the
 * ClientHello and the ServerHello, because RFC 8446 section 7.1 derives the handshake traffic
 * secrets from the transcript through the ServerHello. */
static wt_status_t server_derive_handshake(wt_tls_server_t *server,
                                           const wt_tls_key_share_t *share) {
  uint8_t early_secret[WT_TLS13_SECRET_LEN];
  uint8_t ecdhe[WT_TLS_X25519_KEY_LEN];
  uint8_t transcript_hash[WT_TLS13_SECRET_LEN];
  wt_status_t status;

  status = wt_tls_key_share_shared_secret(WT_TLS_GROUP_X25519, server->private_key,
                                         share->key, share->key_len, ecdhe);
  if (status != WT_OK) return status;
  status = wt_tls13_early_secret(NULL, 0U, early_secret);
  if (status != WT_OK) {
    wt_secure_zero(ecdhe, sizeof(ecdhe));
    return status;
  }
  status = wt_tls13_handshake_secret(early_secret, ecdhe, sizeof(ecdhe),
                                     server->handshake_secret);
  wt_secure_zero(early_secret, sizeof(early_secret));
  wt_secure_zero(ecdhe, sizeof(ecdhe));
  if (status != WT_OK) return status;
  status = wt_tls13_transcript_hash(&server->transcript, transcript_hash);
  if (status != WT_OK) return status;
  status = wt_tls13_handshake_traffic_secrets(
      server->handshake_secret, transcript_hash, server->client_handshake_secret,
      server->server_handshake_secret);
  wt_secure_zero(transcript_hash, sizeof(transcript_hash));
  if (status != WT_OK) return status;
  return wt_tls13_master_secret(server->handshake_secret, server->master_secret);
}

/* The two application secrets, from the transcript through the server's Finished. */
static wt_status_t server_derive_application(wt_tls_server_t *server) {
  uint8_t transcript_hash[WT_TLS13_SECRET_LEN];
  wt_status_t status;

  status = wt_tls13_transcript_hash(&server->transcript, transcript_hash);
  if (status != WT_OK) return status;
  status = wt_tls13_application_traffic_secrets(
      server->master_secret, transcript_hash, server->client_application_secret,
      server->server_application_secret);
  wt_secure_zero(transcript_hash, sizeof(transcript_hash));
  return status;
}

/* The EncryptedExtensions' extension list, built from the configuration. The caller supplies
 * the two data buffers the views point into, so nothing outlives the call. */
static wt_status_t server_encrypted_extensions(
    const wt_tls_server_t *server, uint8_t *alpn_buffer, size_t alpn_capacity,
    wt_tls_extension_list_t *out) {
  memset(out, 0, sizeof(*out));
  if (server->config.alpn != NULL) {
    size_t length = strlen(server->config.alpn);
    /* RFC 7301 section 3.1: the extension data is a ProtocolNameList -- a two-byte list length,
     * then a one-byte name length and the name. A server that wrote only the name and its own
     * length would send three bytes where five belong, and the client's parser would refuse the
     * extension: well-formed enough to look like a protocol name, and not one. */
    if (length == 0U || length > alpn_capacity - 3U) return WT_ERR_INVALID_ARGUMENT;
    alpn_buffer[0] = (uint8_t)((1U + length) >> 8);
    alpn_buffer[1] = (uint8_t)((1U + length) & 0xFFU);
    alpn_buffer[2] = (uint8_t)length;
    memcpy(alpn_buffer + 3U, server->config.alpn, length);
    out->entries[out->count].type = WT_TLS_EXTENSION_ALPN;
    out->entries[out->count].data = alpn_buffer;
    out->entries[out->count].len = 3U + length;
    out->count++;
  }
  if (server->config.transport_parameters_len != 0U) {
    out->entries[out->count].type = WT_TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS;
    out->entries[out->count].data = server->config.transport_parameters;
    out->entries[out->count].len = server->config.transport_parameters_len;
    out->count++;
  }
  return WT_OK;
}

static wt_status_t server_receive_client_hello(wt_tls_server_t *server,
                                               const uint8_t *message, size_t len,
                                               uint8_t *out, size_t out_capacity,
                                               size_t *out_len) {
  wt_tls_client_hello_t hello;
  const wt_tls_extension_t *extension;
  wt_tls_key_share_t share;
  wt_tls_server_hello_params_t params;
  wt_tls_key_share_t ours;
  uint16_t versions[WT_TLS_MAX_NAMED_GROUPS];
  size_t version_count = 0U;
  size_t i;
  int offers_13 = 0;
  wt_status_t status;

  status = wt_tls_client_hello_parse(message, len, &hello);
  if (status != WT_OK) return status;
  if (!offers_cipher_suite(&hello)) return WT_ERR_TLS;
  /* RFC 8446 section 4.2.1: a TLS 1.3 client says 0x0303 in legacy_version and offers 1.3 in
   * supported_versions, so the extension is the only place the version is really negotiated. */
  extension = wt_tls_extensions_find(&hello.extensions,
                                     WT_TLS_EXTENSION_SUPPORTED_VERSIONS);
  if (extension == NULL) return WT_ERR_TLS;
  status = wt_tls_supported_versions_client(extension, versions,
                                            WT_TLS_MAX_NAMED_GROUPS, &version_count);
  if (status != WT_OK) return status;
  for (i = 0U; i < version_count; i++) {
    if (versions[i] == WT_TLS_VERSION_1_3) offers_13 = 1;
  }
  if (!offers_13) return WT_ERR_TLS;
  status = client_x25519_share(&hello, &share);
  if (status != WT_OK) return status;
  status = check_client_extensions(server, &hello);
  if (status != WT_OK) return status;

  /* Our own key pair: supplied by the caller, or generated for this handshake. */
  if (server->config.x25519_private != NULL) {
    memcpy(server->private_key, server->config.x25519_private, WT_TLS_X25519_KEY_LEN);
    status = wt_tls_key_share_public_key(WT_TLS_GROUP_X25519, server->private_key,
                                         server->public_key);
  } else {
    status = wt_tls_key_share_generate(WT_TLS_GROUP_X25519, server->private_key,
                                       server->public_key);
  }
  if (status != WT_OK) return status;

  /* The session id is echoed, which is how the client knows this ServerHello answers its
   * ClientHello (RFC 8446 section 4.1.3). */
  memcpy(server->session_id, hello.session_id, hello.session_id_len);
  server->session_id_len = hello.session_id_len;

  ours.group = WT_TLS_GROUP_X25519;
  ours.key = server->public_key;
  ours.key_len = sizeof(server->public_key);
  memset(&params, 0, sizeof(params));
  params.random = server->server_random;
  params.session_id = server->session_id;
  params.session_id_len = server->session_id_len;
  params.cipher_suite = WT_TLS_CIPHER_SUITE;
  params.supported_version = WT_TLS_VERSION_1_3;
  params.key_share = &ours;
  status = wt_tls_server_hello_build(&params, out, out_capacity, out_len);
  if (status != WT_OK) return status;

  /* Both messages are absorbed before the secrets are derived, because the handshake traffic
   * secrets are over the transcript through the ServerHello. */
  status = wt_tls13_transcript_append(&server->transcript, message, len);
  if (status != WT_OK) return status;
  status = wt_tls13_transcript_append(&server->transcript, out, *out_len);
  if (status != WT_OK) return status;
  status = server_derive_handshake(server, &share);
  if (status != WT_OK) return status;
  server->state = WT_TLS_SERVER_WAIT_CLIENT_FINISHED;
  return WT_OK;
}

static wt_status_t server_receive_finished(wt_tls_server_t *server,
                                           const uint8_t *message, size_t len) {
  uint8_t verify_data[WT_TLS13_FINISHED_LEN];
  uint8_t through_server_finished[WT_TLS13_SECRET_LEN];
  wt_status_t status;

  status = wt_tls_finished_parse(message, len, verify_data);
  if (status != WT_OK) return status;
  /* The client's Finished is over the transcript through the server's Finished, which is what
   * the transcript holds now: the flight has been absorbed and this message has not. */
  status = wt_tls13_transcript_hash(&server->transcript, through_server_finished);
  if (status != WT_OK) return status;
  status = wt_tls13_finished_check(server->client_handshake_secret,
                                   through_server_finished, verify_data,
                                   sizeof(verify_data));
  wt_secure_zero(through_server_finished, sizeof(through_server_finished));
  if (status != WT_OK) return status;
  /* The application secrets come from the transcript through the server's Finished, which is
   * still the current state: the client's Finished is not part of them. */
  status = server_derive_application(server);
  if (status != WT_OK) return status;
  status = wt_tls13_transcript_append(&server->transcript, message, len);
  if (status != WT_OK) return status;
  server->state = WT_TLS_SERVER_CONNECTED;
  return WT_OK;
}

wt_status_t wt_tls_server_begin(wt_tls_server_t *server,
                                const wt_tls_server_config_t *config) {
  wt_status_t status;

  if (server == NULL || config == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (config->identity == NULL || config->identity->certificate_count == 0U ||
      config->identity->certificate_count > WT_TLS_CERTIFICATE_MAX_ENTRIES) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (config->identity->private_key == NULL || config->identity->private_key_len == 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (config->transport_parameters == NULL && config->transport_parameters_len != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* Anything a previous handshake left is released first, exactly as on the client. */
  if (server->live == WT_TLS_SERVER_LIVE) {
    wt_tls13_transcript_clear(&server->transcript);
  }
  memset(server, 0, sizeof(*server));
  server->config = *config;
  status = wt_random_bytes(server->server_random, sizeof(server->server_random));
  if (status != WT_OK) {
    server->state = WT_TLS_SERVER_FAILED;
    return status;
  }
  status = wt_tls13_transcript_init(&server->transcript);
  if (status != WT_OK) {
    server->state = WT_TLS_SERVER_FAILED;
    return status;
  }
  server->live = WT_TLS_SERVER_LIVE;
  server->state = WT_TLS_SERVER_WAIT_CLIENT_HELLO;
  return WT_OK;
}

wt_status_t wt_tls_server_flight(wt_tls_server_t *server, uint8_t *out,
                                 size_t out_capacity, size_t *out_len) {
  const wt_tls_server_identity_t *identity;
  wt_tls_extension_list_t encrypted;
  /* A ProtocolNameList for one name: two bytes of list length, one of name length, the name. */
  uint8_t alpn_buffer[WT_TLS_MAX_PROTOCOL_NAME + 3U];
  uint8_t content[WT_TLS_CERTIFICATE_VERIFY_CONTENT_LEN];
  uint8_t transcript_hash[WT_TLS13_SECRET_LEN];
  uint8_t signature[1024];
  uint8_t verify_data[WT_TLS13_FINISHED_LEN];
  uint8_t finished[WT_TLS13_FINISHED_LEN + WT_TLS_HANDSHAKE_HEADER_LEN];
  size_t signature_len = 0U;
  size_t finished_len = 0U;
  size_t mark;
  wt_writer_t w;
  wt_status_t status;

  if (server == NULL || out == NULL || out_len == NULL) return WT_ERR_INVALID_ARGUMENT;
  *out_len = 0U;
  status = server_live(server);
  if (status != WT_OK) return status;
  if (server->state != WT_TLS_SERVER_WAIT_CLIENT_FINISHED) return WT_ERR_STATE;
  /* Once: RSA-PSS signatures are randomised, so a second flight would not match the transcript
   * the first one signed. QUIC retransmits CRYPTO data from its own buffer. */
  if (server->flight_built) return WT_ERR_STATE;
  identity = server->config.identity;

  w = wt_writer_init(out, out_capacity);

  /* EncryptedExtensions. Absorbed as soon as it is written, because the CertificateVerify's
   * signature is over the transcript that includes it. */
  status = server_encrypted_extensions(server, alpn_buffer, sizeof(alpn_buffer),
                                       &encrypted);
  if (status != WT_OK) return status;
  status = wt_tls_encrypted_extensions_encode(&encrypted, &w);
  if (status != WT_OK) return status;
  mark = 0U;
  status = wt_tls13_transcript_append(&server->transcript, out,
                                      wt_writer_offset(&w) - mark);
  if (status != WT_OK) return status;

  /* Certificate. */
  {
    wt_tls_certificate_t certificate;
    size_t i;
    memset(&certificate, 0, sizeof(certificate));
    certificate.count = identity->certificate_count;
    for (i = 0U; i < identity->certificate_count; i++) {
      certificate.entries[i].der = identity->certificate[i];
      certificate.entries[i].der_len = identity->certificate_len[i];
    }
    mark = wt_writer_offset(&w);
    status = wt_tls_certificate_encode(&certificate, &w);
    if (status != WT_OK) return status;
    status = wt_tls13_transcript_append(&server->transcript, out + mark,
                                        wt_writer_offset(&w) - mark);
    if (status != WT_OK) return status;
  }

  /* CertificateVerify: the signature is over the transcript through the Certificate. */
  status = wt_tls13_transcript_hash(&server->transcript, transcript_hash);
  if (status != WT_OK) return status;
  status = wt_tls_certificate_verify_content(1, transcript_hash, content);
  wt_secure_zero(transcript_hash, sizeof(transcript_hash));
  if (status != WT_OK) return status;
  status = wt_tls_signature_sign(identity->private_key, identity->private_key_len,
                                 identity->signature_scheme, content, sizeof(content),
                                 signature, sizeof(signature), &signature_len);
  wt_secure_zero(content, sizeof(content));
  if (status != WT_OK) return status;
  {
    wt_tls_certificate_verify_t certificate_verify;
    certificate_verify.scheme = identity->signature_scheme;
    certificate_verify.signature = signature;
    certificate_verify.signature_len = signature_len;
    mark = wt_writer_offset(&w);
    status = wt_tls_certificate_verify_encode(&certificate_verify, &w);
  }
  wt_secure_zero(signature, sizeof(signature));
  if (status != WT_OK) return status;
  status = wt_tls13_transcript_append(&server->transcript, out + mark,
                                      wt_writer_offset(&w) - mark);
  if (status != WT_OK) return status;

  /* Finished: over the transcript through the CertificateVerify this flight just wrote. */
  status = wt_tls13_transcript_hash(&server->transcript, transcript_hash);
  if (status != WT_OK) return status;
  status = wt_tls13_finished_verify_data(server->server_handshake_secret, transcript_hash,
                                         verify_data);
  wt_secure_zero(transcript_hash, sizeof(transcript_hash));
  if (status != WT_OK) return status;
  status = wt_tls_finished_build(verify_data, finished, sizeof(finished), &finished_len);
  wt_secure_zero(verify_data, sizeof(verify_data));
  if (status != WT_OK) return status;
  wt_writer_bytes(&w, finished, finished_len);
  if (!wt_writer_ok(&w)) return WT_ERR_LIMIT;
  status = wt_tls13_transcript_append(&server->transcript, finished, finished_len);
  if (status != WT_OK) return status;

  server->flight_built = 1;
  *out_len = wt_writer_offset(&w);
  return WT_OK;
}

wt_status_t wt_tls_server_receive(wt_tls_server_t *server, const uint8_t *message,
                                  size_t len, uint8_t *out, size_t out_capacity,
                                  size_t *out_len) {
  wt_tls_handshake_header_t header;
  wt_cursor_t cursor;
  wt_status_t status;

  if (out == NULL || out_len == NULL) return WT_ERR_INVALID_ARGUMENT;
  *out_len = 0U;
  status = server_live(server);
  if (status != WT_OK) return status;
  if (message == NULL || len < WT_TLS_HANDSHAKE_HEADER_LEN) {
    return server_fail(server, WT_ERR_TRUNCATED);
  }
  cursor = wt_cursor_init(message, len);
  status = wt_tls_handshake_header_parse(&cursor, &header);
  if (status != WT_OK) return server_fail(server, status);

  switch (server->state) {
    case WT_TLS_SERVER_WAIT_CLIENT_HELLO:
      if (header.type != WT_TLS_HANDSHAKE_CLIENT_HELLO) {
        return server_fail(server, WT_ERR_STATE);
      }
      status = server_receive_client_hello(server, message, len, out, out_capacity,
                                           out_len);
      break;
    case WT_TLS_SERVER_WAIT_CLIENT_FINISHED:
      if (header.type != WT_TLS_HANDSHAKE_FINISHED) {
        return server_fail(server, WT_ERR_STATE);
      }
      status = server_receive_finished(server, message, len);
      break;
    case WT_TLS_SERVER_START:
    case WT_TLS_SERVER_CONNECTED:
    case WT_TLS_SERVER_FAILED:
    default:
      return server_fail(server, WT_ERR_STATE);
  }
  if (status != WT_OK) return server_fail(server, status);
  return WT_OK;
}

wt_tls_server_state_t wt_tls_server_state(const wt_tls_server_t *server) {
  return (server == NULL) ? WT_TLS_SERVER_FAILED : server->state;
}

wt_status_t wt_tls_server_handshake_secrets(const wt_tls_server_t *server,
                                            uint8_t read_out[WT_TLS13_SECRET_LEN],
                                            uint8_t write_out[WT_TLS13_SECRET_LEN]) {
  if (server == NULL || read_out == NULL || write_out == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (server->state != WT_TLS_SERVER_WAIT_CLIENT_FINISHED &&
      server->state != WT_TLS_SERVER_CONNECTED) {
    return WT_ERR_STATE;
  }
  memcpy(read_out, server->client_handshake_secret, WT_TLS13_SECRET_LEN);
  memcpy(write_out, server->server_handshake_secret, WT_TLS13_SECRET_LEN);
  return WT_OK;
}

wt_status_t wt_tls_server_application_secrets(
    const wt_tls_server_t *server, uint8_t read_out[WT_TLS13_SECRET_LEN],
    uint8_t write_out[WT_TLS13_SECRET_LEN]) {
  if (server == NULL || read_out == NULL || write_out == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (server->state != WT_TLS_SERVER_CONNECTED) return WT_ERR_STATE;
  memcpy(read_out, server->client_application_secret, WT_TLS13_SECRET_LEN);
  memcpy(write_out, server->server_application_secret, WT_TLS13_SECRET_LEN);
  return WT_OK;
}

const uint8_t *wt_tls_server_alpn(const wt_tls_server_t *server, size_t *out_len) {
  if (server == NULL || out_len == NULL) return NULL;
  *out_len = server->negotiated_alpn_len;
  return server->negotiated_alpn;
}

const uint8_t *wt_tls_server_transport_parameters(const wt_tls_server_t *server,
                                                  size_t *out_len) {
  if (server == NULL || out_len == NULL) return NULL;
  *out_len = server->peer_transport_parameters_len;
  return server->peer_transport_parameters;
}

void wt_tls_server_clear(wt_tls_server_t *server) {
  if (server == NULL) return;
  wt_tls13_transcript_clear(&server->transcript);
  wt_secure_zero(server, sizeof(*server));
}
