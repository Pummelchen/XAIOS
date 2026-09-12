/* TLS 1.3 key schedule and QUIC traffic key derivation.
 *
 * Every function here is a direct transcription of RFC 8446 section 7.1 or
 * RFC 9001 section 5, and each is pinned to a published intermediate value in
 * tests/security/test_wt_tls.c. The comments name the RFC step so a reader can
 * check the code against the specification rather than against the tests.
 *
 * See wt_tls.h for what this deliberately does not do.
 */

#include "wt_tls.h"

#include <string.h>

const uint8_t wt_tls_empty_hash[WT_TLS_HASH_LEN] = {
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14,
    0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c,
    0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
};

/* HKDF-Expand-Label (RFC 8446 section 7.1):
 *
 *   struct {
 *       uint16 length;
 *       opaque label<7..255>;    // one length byte, then "tls13 " + label
 *       opaque context<0..255>;  // one length byte, then the context
 *   } HkdfLabel;
 *
 * The length prefixes are the whole difficulty: a wrong one still produces
 * well-formed output of the right size, so the vectors are the only thing that
 * distinguishes a right implementation from a plausible one. */
int wt_tls_expand_label(const uint8_t *secret, size_t secret_len,
                        const char *label, const uint8_t *context,
                        size_t context_len, uint8_t *out, size_t out_len) {
  uint8_t info[2U + 1U + 255U + 1U + 255U];
  size_t label_len;
  size_t full_len;
  size_t info_len;
  int status;

  if (secret == NULL || label == NULL || out == NULL) return -1;
  if (context == NULL && context_len != 0U) return -1;

  label_len = strlen(label);
  /* "tls13 " plus the label, and the one length byte has to hold it. */
  if (label_len > 255U - 6U) return -1;
  full_len = 6U + label_len;
  if (context_len > 255U) return -1;
  /* out_len is checked against the HKDF bound by wt_hkdf_expand_sha256. */
  if (out_len > 0xFFFFU) return -1;

  info[0] = (uint8_t)((out_len >> 8) & 0xFFU);
  info[1] = (uint8_t)(out_len & 0xFFU);
  info[2] = (uint8_t)full_len;
  memcpy(info + 3U, "tls13 ", 6U);
  memcpy(info + 9U, label, label_len);
  info[3U + full_len] = (uint8_t)context_len;
  if (context_len != 0U) {
    memcpy(info + 4U + full_len, context, context_len);
  }
  info_len = 4U + full_len + context_len;

  status = wt_hkdf_expand_sha256(secret, secret_len, info, info_len, out,
                                 out_len);
  wt_secure_zero(info, sizeof(info));
  return status;
}

int wt_tls_derive_secret(const uint8_t *secret, size_t secret_len,
                         const char *label,
                         const uint8_t transcript_hash[WT_TLS_HASH_LEN],
                         uint8_t out[WT_TLS_HASH_LEN]) {
  if (transcript_hash == NULL) return -1;
  /* Derive-Secret(Secret, Label, Messages) is
     HKDF-Expand-Label(Secret, Label, Hash(Messages), Hash.length). */
  return wt_tls_expand_label(secret, secret_len, label, transcript_hash,
                             WT_TLS_HASH_LEN, out, WT_TLS_HASH_LEN);
}

/* RFC 8446 section 7.1, the full schedule with no pre-shared key:
 *
 *   early_secret           = HKDF-Extract(0, 0)
 *   0 -> derived -> handshake_secret = HKDF-Extract(derived, ECDHE)
 *   handshake_secret -> derived -> master_secret = HKDF-Extract(derived, 0)
 *
 * with the two traffic-secret pairs and the exporter taken from the handshake
 * and master secrets respectively. The resumption master secret is taken from
 * the master secret over the transcript through the *client's* Finished, which
 * the caller supplies as `transcript_after_server_finished` only when there is
 * no client Finished (a server-side abort); for a complete handshake the caller
 * must recompute it over the true transcript. That is stated here rather than
 * silently producing a plausible value. */
int wt_tls_key_schedule(
    const uint8_t *ecdh_secret, size_t ecdh_len,
    const uint8_t transcript_after_server_hello[WT_TLS_HASH_LEN],
    const uint8_t transcript_after_server_finished[WT_TLS_HASH_LEN],
    wt_tls_secrets_t *out) {
  uint8_t derived[WT_TLS_HASH_LEN];
  static const uint8_t zero[WT_TLS_HASH_LEN] = {0};

  if (out == NULL) return -1;
  /* Cleared before anything else, so every refusal below leaves a caller that
     ignored the return value with an unusable schedule rather than a
     partially derived one. */
  memset(out, 0, sizeof(*out));
  if (transcript_after_server_hello == NULL ||
      transcript_after_server_finished == NULL) {
    return -1;
  }
  if (ecdh_secret == NULL && ecdh_len != 0U) return -1;

  /* early_secret = HKDF-Extract(salt = 0, IKM = 0). HKDF's own definition of
     a zero-length salt is an all-zero HashLen salt, which
     wt_hkdf_extract_sha256 applies; passing NULL is not the same as passing
     a zero-length buffer to a naive HMAC, which pads differently. */
  if (wt_hkdf_extract_sha256(NULL, 0, zero, sizeof(zero), out->early) != 0) {
    goto fail;
  }

  /* derived = Derive-Secret(early_secret, "derived", "") */
  if (wt_tls_derive_secret(out->early, sizeof(out->early), "derived",
                           wt_tls_empty_hash, derived) != 0) {
    goto fail;
  }

  /* handshake_secret = HKDF-Extract(salt = derived, IKM = ECDHE) */
  if (wt_hkdf_extract_sha256(derived, sizeof(derived), ecdh_secret, ecdh_len,
                             out->handshake) != 0) {
    goto fail;
  }

  /* Handshake traffic secrets, over the transcript through ServerHello. */
  if (wt_tls_derive_secret(out->handshake, sizeof(out->handshake),
                           "c hs traffic", transcript_after_server_hello,
                           out->client_handshake_traffic) != 0) {
    goto fail;
  }
  if (wt_tls_derive_secret(out->handshake, sizeof(out->handshake),
                           "s hs traffic", transcript_after_server_hello,
                           out->server_handshake_traffic) != 0) {
    goto fail;
  }

  /* derived = Derive-Secret(handshake_secret, "derived", "") */
  if (wt_tls_derive_secret(out->handshake, sizeof(out->handshake), "derived",
                           wt_tls_empty_hash, derived) != 0) {
    goto fail;
  }

  /* master_secret = HKDF-Extract(salt = derived, IKM = 0) */
  if (wt_hkdf_extract_sha256(derived, sizeof(derived), zero, sizeof(zero),
                             out->master) != 0) {
    goto fail;
  }

  /* Application traffic secrets and the exporter, over the transcript through
     the server's Finished. */
  if (wt_tls_derive_secret(out->master, sizeof(out->master), "c ap traffic",
                           transcript_after_server_finished,
                           out->client_application_traffic) != 0) {
    goto fail;
  }
  if (wt_tls_derive_secret(out->master, sizeof(out->master), "s ap traffic",
                           transcript_after_server_finished,
                           out->server_application_traffic) != 0) {
    goto fail;
  }
  if (wt_tls_derive_secret(out->master, sizeof(out->master), "exp master",
                           transcript_after_server_finished,
                           out->exporter_master) != 0) {
    goto fail;
  }
  if (wt_tls_derive_secret(out->master, sizeof(out->master), "res master",
                           transcript_after_server_finished,
                           out->resumption_master) != 0) {
    goto fail;
  }

  wt_secure_zero(derived, sizeof(derived));
  return 0;

fail:
  /* A partially derived schedule is worse than none: a caller that ignored
     the return value would send with a secret that was never completed. */
  wt_secure_zero(derived, sizeof(derived));
  wt_secure_zero(out, sizeof(*out));
  return -1;
}

/* The struct must hold the larger of the two header protection keys. A
   build-time check, because the failure it prevents -- a 32-byte write into a
   16-byte field -- corrupts the struct and surfaces as a wrong value somewhere
   else entirely. */
typedef char wt_tls_hp_len_fits[WT_TLS_HP_LEN >= 32U ? 1 : -1];

/* The header protection key length for a suite. RFC 9001 section 5.1: the hp
   key uses the AEAD's own key size, so it is 16 for AES-128-GCM and 32 for
   ChaCha20-Poly1305. */
static size_t aead_hp_len(wt_tls_aead_t aead) {
  switch (aead) {
    case WT_TLS_AEAD_AES_128_GCM: return 16U;
    case WT_TLS_AEAD_CHACHA20_POLY1305: return 32U;
    default: return 0U;
  }
}

int wt_tls_traffic_keys(const uint8_t secret[WT_TLS_HASH_LEN],
                        wt_tls_aead_t aead, wt_tls_traffic_keys_t *out) {
  size_t hp_len = aead_hp_len(aead);
  if (secret == NULL || out == NULL || hp_len == 0U) return -1;
  memset(out, 0, sizeof(*out));
  memcpy(out->secret, secret, WT_TLS_HASH_LEN);
  out->hp_len = hp_len;
  /* RFC 9001 section 5.1: all three come from the traffic secret with QUIC's
     own labels, with an empty context. */
  if (wt_tls_expand_label(secret, WT_TLS_HASH_LEN, "quic key", NULL, 0,
                          out->key, WT_TLS_KEY_LEN) != 0) {
    goto fail;
  }
  if (wt_tls_expand_label(secret, WT_TLS_HASH_LEN, "quic iv", NULL, 0,
                          out->iv, WT_TLS_IV_LEN) != 0) {
    goto fail;
  }
  if (wt_tls_expand_label(secret, WT_TLS_HASH_LEN, "quic hp", NULL, 0,
                          out->hp, hp_len) != 0) {
    goto fail;
  }
  return 0;

fail:
  wt_secure_zero(out, sizeof(*out));
  return -1;
}

int wt_tls_key_update(const uint8_t secret[WT_TLS_HASH_LEN],
                      wt_tls_aead_t aead, wt_tls_traffic_keys_t *out) {
  uint8_t next[WT_TLS_HASH_LEN];
  if (secret == NULL || out == NULL) return -1;
  /* RFC 9001 section 6: the next secret is HKDF-Expand-Label of the current
     one on the "quic ku" label, and the keys are then derived from it in the
     ordinary way. */
  if (wt_tls_expand_label(secret, WT_TLS_HASH_LEN, "quic ku", NULL, 0, next,
                          WT_TLS_HASH_LEN) != 0) {
    return -1;
  }
  if (wt_tls_traffic_keys(next, aead, out) != 0) {
    wt_secure_zero(next, sizeof(next));
    return -1;
  }
  wt_secure_zero(next, sizeof(next));
  return 0;
}

int wt_tls_initial_secret(const uint8_t *salt, size_t salt_len,
                          const uint8_t *dcid, size_t dcid_len,
                          uint8_t out[WT_TLS_HASH_LEN]) {
  /* RFC 9001 section 5.2:
     initial_secret = HKDF-Extract(initial_salt, client_dst_connection_id) */
  if (salt == NULL || out == NULL) return -1;
  if (dcid == NULL && dcid_len != 0U) return -1;
  return wt_hkdf_extract_sha256(salt, salt_len, dcid, dcid_len, out);
}

int wt_tls_initial_traffic_keys(const uint8_t initial_secret[WT_TLS_HASH_LEN],
                                int from_server, wt_tls_aead_t aead,
                                wt_tls_traffic_keys_t *out) {
  uint8_t secret[WT_TLS_HASH_LEN];
  if (initial_secret == NULL || out == NULL) return -1;
  /* The label is the only difference between the two directions: "client in"
     and "server in". */
  if (wt_tls_expand_label(initial_secret, WT_TLS_HASH_LEN,
                          from_server ? "server in" : "client in", NULL, 0,
                          secret, WT_TLS_HASH_LEN) != 0) {
    return -1;
  }
  if (wt_tls_traffic_keys(secret, aead, out) != 0) {
    wt_secure_zero(secret, sizeof(secret));
    return -1;
  }
  wt_secure_zero(secret, sizeof(secret));
  return 0;
}

/* RFC 9001 section 5.8. The AEAD is AES-128-GCM with a fixed key and nonce,
   the plaintext is empty, and the associated data is the pseudo-packet:
 *
 *   pseudo-packet = odcid_length || odcid || Retry-without-its-tag
 *
 * The original destination connection ID is included even though it is not in
 * the Retry on the wire. That is what binds the tag to the connection the
 * Retry answers, and leaving it out produces a tag that is wrong in every byte
 * while looking exactly like a tag. */
int wt_tls_retry_integrity_tag(const uint8_t retry_aead_key[16],
                               const uint8_t retry_aead_nonce[12],
                               const uint8_t *original_dcid, size_t dcid_len,
                               const uint8_t *retry_without_tag,
                               size_t retry_len, uint8_t out_tag[16]) {
  uint8_t pseudo[1U + 255U];
  uint8_t empty_plaintext = 0U;
  uint8_t scratch = 0U;
  size_t pseudo_len;

  if (retry_aead_key == NULL || retry_aead_nonce == NULL || out_tag == NULL) {
    return -1;
  }
  if (retry_without_tag == NULL && retry_len != 0U) return -1;
  /* A connection ID longer than 20 bytes cannot occur on the wire (RFC 9000
     section 17.2), and the length byte has to hold this one. */
  if (dcid_len > 20U) return -1;
  if (original_dcid == NULL && dcid_len != 0U) return -1;

  pseudo[0] = (uint8_t)dcid_len;
  if (dcid_len != 0U) memcpy(pseudo + 1U, original_dcid, dcid_len);
  if (retry_len != 0U) {
    memcpy(pseudo + 1U + dcid_len, retry_without_tag, retry_len);
  }
  pseudo_len = 1U + dcid_len + retry_len;

  {
    int status = wt_aes128_gcm_encrypt(retry_aead_key, retry_aead_nonce, pseudo,
                                       pseudo_len, &empty_plaintext, 0U,
                                       &scratch, out_tag);
    wt_secure_zero(pseudo, sizeof(pseudo));
    return status;
  }
}

int wt_tls_verify_retry_integrity_tag(const uint8_t retry_aead_key[16],
                                      const uint8_t retry_aead_nonce[12],
                                      const uint8_t *original_dcid,
                                      size_t dcid_len,
                                      const uint8_t *retry_packet,
                                      size_t retry_len) {
  uint8_t expected[16];
  const uint8_t *received;
  size_t body_len;
  int equal;

  /* A Retry is at least the tag plus a token and the fixed fields. */
  if (retry_packet == NULL || retry_len < 16U) return -1;

  /* The tag is the last 16 bytes and is not covered by the pseudo-packet. */
  body_len = retry_len - 16U;
  received = retry_packet + body_len;

  if (wt_tls_retry_integrity_tag(retry_aead_key, retry_aead_nonce,
                                 original_dcid, dcid_len, retry_packet,
                                 body_len, expected) != 0) {
    return -1;
  }
  /* Constant time: a tag comparison that returns early is a forgery oracle. */
  equal = wt_ct_equal(expected, received, 16U);
  wt_secure_zero(expected, sizeof(expected));
  return equal;
}

void wt_tls_secrets_clear(wt_tls_secrets_t *secrets) {
  if (secrets != NULL) wt_secure_zero(secrets, sizeof(*secrets));
}

void wt_tls_traffic_keys_clear(wt_tls_traffic_keys_t *keys) {
  if (keys != NULL) wt_secure_zero(keys, sizeof(*keys));
}
