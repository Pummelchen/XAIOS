/* TLS 1.3 handshake framing, the transcript hash, and ServerHello parsing.
 *
 * RFC 8446 sections 4 and 4.1.3. See wt_tls_handshake.h for the scope.
 */

#include "wt_tls_handshake.h"

#include <string.h>

/* TLS 1.3's wire version. The legacy_version field is always 0x0303 -- "TLS
 * 1.2" -- and the real version is negotiated in supported_versions. A reader
 * that trusted legacy_version would accept a downgrade. */
#define WT_TLS_LEGACY_VERSION 0x0303U
#define WT_TLS_VERSION_13 0x0304U

size_t wt_tls_encode_handshake_header(uint8_t type, size_t body_len,
                                      uint8_t out[4]) {
  if (out == NULL) return 0U;
  if (body_len > WT_TLS_MAX_HANDSHAKE_MESSAGE) return 0U;
  out[0] = type;
  out[1] = (uint8_t)((body_len >> 16) & 0xFFU);
  out[2] = (uint8_t)((body_len >> 8) & 0xFFU);
  out[3] = (uint8_t)(body_len & 0xFFU);
  return 4U;
}

int wt_tls_decode_handshake_header(const uint8_t *message, size_t message_len,
                                   uint8_t *out_type, size_t *out_body_len,
                                   size_t *out_body_offset) {
  size_t body_len;
  if (message == NULL || out_type == NULL || out_body_len == NULL ||
      out_body_offset == NULL) {
    return -1;
  }
  if (message_len < 4U) return -1;
  body_len = ((size_t)message[1] << 16) | ((size_t)message[2] << 8) |
             (size_t)message[3];
  /* The declared length must fit the buffer. A reader that trusted it would
     read past the end of whatever the peer sent. */
  if (body_len > message_len - 4U) return -1;
  *out_type = message[0];
  *out_body_len = body_len;
  *out_body_offset = 4U;
  return 0;
}

int wt_tls_transcript_init(wt_tls_transcript_t *transcript) {
  if (transcript == NULL) return -1;
  memset(transcript, 0, sizeof(*transcript));
  return wt_sha256_init(&transcript->hash);
}

int wt_tls_transcript_absorb(wt_tls_transcript_t *transcript,
                             const uint8_t *message, size_t message_len) {
  uint8_t type = 0U;
  size_t body_len = 0U;
  size_t body_offset = 0U;

  if (transcript == NULL || message == NULL) return -1;
  /* A message that does not frame is refused rather than hashed: hashing a
     malformed message produces a transcript that cannot be reproduced by the
     peer, and the failure would appear as a Finished mismatch with no hint
     that the real problem was three messages earlier. */
  if (wt_tls_decode_handshake_header(message, message_len, &type, &body_len,
                                     &body_offset) != 0) {
    return -1;
  }
  (void)body_len;
  (void)body_offset;
  /* RFC 8446 section 4.4.1: a HelloRetryRequest is a ServerHello with the
     special random, and it is not absorbed directly -- the transcript becomes
     a synthetic message_hash first. Refusing is the honest answer; absorbing
     it would produce a transcript no peer agrees with. */
  return wt_sha256_update(&transcript->hash, message, message_len);
}

int wt_tls_transcript_hash(const wt_tls_transcript_t *transcript,
                           uint8_t out[WT_TLS_HASH_LEN]) {
  wt_sha256_ctx_t copy;
  if (transcript == NULL || out == NULL) return -1;
  /* Hashed from a copy, so the transcript can keep absorbing afterwards. */
  memcpy(&copy, &transcript->hash, sizeof(copy));
  return wt_sha256_final(&copy, out);
}

int wt_tls_transcript_absorb_and_hash(wt_tls_transcript_t *transcript,
                                      const uint8_t *message,
                                      size_t message_len,
                                      uint8_t out[WT_TLS_HASH_LEN]) {
  if (wt_tls_transcript_absorb(transcript, message, message_len) != 0) {
    return -1;
  }
  return wt_tls_transcript_hash(transcript, out);
}

/* A cursor over the body of a handshake message. Every read is bounds-checked,
 * because the whole body is peer-controlled. */
typedef struct reader {
  const uint8_t *data;
  size_t len;
  size_t offset;
  int failed;
} reader_t;

static void reader_init(reader_t *r, const uint8_t *data, size_t len) {
  r->data = data;
  r->len = len;
  r->offset = 0U;
  r->failed = 0;
}

static const uint8_t *reader_take(reader_t *r, size_t n) {
  const uint8_t *result;
  if (r->failed) return NULL;
  if (n > r->len - r->offset) {
    r->failed = 1;
    return NULL;
  }
  result = r->data + r->offset;
  r->offset += n;
  return result;
}

static uint8_t reader_u8(reader_t *r) {
  const uint8_t *p = reader_take(r, 1U);
  return p == NULL ? 0U : p[0];
}

static uint16_t reader_u16(reader_t *r) {
  const uint8_t *p = reader_take(r, 2U);
  return p == NULL ? 0U : (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

/* RFC 8446 section 4.1.3:
 *
 *   struct {
 *       ProtocolVersion legacy_version = 0x0303;
 *       Random random;                       // 32 bytes
 *       opaque legacy_session_id_echo<0..32>;
 *       CipherSuite cipher_suite;            // 2 bytes
 *       uint8 legacy_compression_method = 0;
 *       Extension extensions<6..2^16-1>;
 *   } ServerHello;
 */
int wt_tls_parse_server_hello(const uint8_t *message, size_t message_len,
                              const uint8_t *expected_legacy_session_id,
                              size_t legacy_session_id_len,
                              wt_tls_server_hello_t *out) {
  uint8_t type = 0U;
  size_t body_len = 0U;
  size_t body_offset = 0U;
  const uint8_t *body;
  reader_t r;

  if (message == NULL || out == NULL) return -1;
  if (expected_legacy_session_id == NULL && legacy_session_id_len != 0U) {
    return -1;
  }
  if (legacy_session_id_len > 32U) return -1;
  memset(out, 0, sizeof(*out));

  if (wt_tls_decode_handshake_header(message, message_len, &type, &body_len,
                                     &body_offset) != 0) {
    return -1;
  }
  if (type != WT_TLS_HS_SERVER_HELLO) return -1;

  body = message + body_offset;
  reader_init(&r, body, body_len);

  /* legacy_version: RFC 8446 says it is 0x0303 and that it must be ignored
     except for the downgrade check, because the negotiated version is in
     supported_versions. A message that does not say 0x0303 is malformed. */
  if (reader_u16(&r) != WT_TLS_LEGACY_VERSION) return -1;

  /* random: 32 bytes, which this parser does not use. A HelloRetryRequest is
     signalled here by a special value, and is refused rather than treated as a
     ServerHello. */
  {
    const uint8_t *random = reader_take(&r, 32U);
    static const uint8_t hello_retry_request_random[32] = {
        0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
        0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
        0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
        0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
    };
    if (random == NULL) return -1;
    if (memcmp(random, hello_retry_request_random, 32U) == 0) {
      /* Not a ServerHello. The caller must handle it, and handling it means
         rewriting the transcript with a synthetic message_hash. */
      return -1;
    }
  }

  /* legacy_session_id_echo must match what the client sent, or a middlebox
     has altered the handshake (RFC 8446 section 4.1.3). */
  {
    uint8_t echo_len = reader_u8(&r);
    const uint8_t *echo = reader_take(&r, echo_len);
    if (echo == NULL) return -1;
    if (echo_len != legacy_session_id_len) return -1;
    if (echo_len != 0U &&
        memcmp(echo, expected_legacy_session_id, echo_len) != 0) {
      return -1;
    }
  }

  out->cipher_suite = reader_u16(&r);

  /* legacy_compression_method must be zero in TLS 1.3. */
  if (reader_u8(&r) != 0U) return -1;

  /* extensions<6..2^16-1>: a two-byte length then that many bytes. */
  {
    uint16_t extensions_len = reader_u16(&r);
    const uint8_t *extensions = reader_take(&r, extensions_len);
    reader_t ext;
    if (extensions == NULL) return -1;
    /* RFC 8446 requires at least one extension in a ServerHello. */
    if (extensions_len < 6U) return -1;
    reader_init(&ext, extensions, extensions_len);
    while (ext.offset < ext.len) {
      uint16_t ext_type = reader_u16(&ext);
      uint16_t ext_len = reader_u16(&ext);
      const uint8_t *ext_data = reader_take(&ext, ext_len);
      if (ext.failed) return -1;
      if (ext_type == WT_TLS_EXT_SUPPORTED_VERSIONS) {
        /* The negotiated version, which must be 1.3. Anything else here is a
           downgrade attempt. */
        if (ext_len != 2U) return -1;
        out->selected_version = (uint16_t)(((uint16_t)ext_data[0] << 8) |
                                           (uint16_t)ext_data[1]);
        out->has_supported_versions = 1;
        if (out->selected_version != WT_TLS_VERSION_13) return -1;
      } else if (ext_type == WT_TLS_EXT_KEY_SHARE) {
        /* KeyShareServerHello: a KeyShareEntry, which is group || len || key. */
        reader_t ks;
        uint16_t key_len;
        reader_init(&ks, ext_data, ext_len);
        out->group = reader_u16(&ks);
        key_len = reader_u16(&ks);
        out->key_share = reader_take(&ks, key_len);
        if (ks.failed || out->key_share == NULL) return -1;
        out->key_share_len = key_len;
        out->has_key_share = 1;
      }
      /* Every other extension is ignored here. */
    }
    if (ext.failed) return -1;
  }

  if (r.failed) return -1;
  /* Both are mandatory in a QUIC ServerHello: the version because a server
     that omits it is answering with something other than TLS 1.3, and the key
     share because without it there is no key exchange and the schedule would
     be derived from nothing. */
  if (!out->has_supported_versions) return -1;
  if (!out->has_key_share) return -1;
  return 0;
}

/* ---------------------------------------------------------------------------
 * EncryptedExtensions (RFC 8446 section 4.3.1, RFC 9001 section 8.2)
 * ------------------------------------------------------------------------- */

/* Whether `type` is one of the extensions this parser decodes and validates
 * the body of.
 *
 * This is a DECODE list and not a permission list. Permission depends on the
 * ClientHello and is decided by `wt_tls_encrypted_extensions_check`; asking
 * this function whether an extension is allowed in EncryptedExtensions would
 * be asking the wrong question, and a whitelist here would have to track every
 * extension any RFC ever adds to that message.
 *
 * What is here is what this module can actually check: ALPN, the QUIC
 * transport parameters, and the small fixed shapes. An extension whose body is
 * not decoded is still recorded in `out->types`, so it is not ignored -- it
 * just is not validated, because nothing in this module acts on it. */
static int ee_extension_is_decoded(uint16_t type) {
  switch (type) {
    case WT_TLS_EXT_SERVER_NAME:
    case WT_TLS_EXT_MAX_FRAGMENT_LENGTH:
    case WT_TLS_EXT_SUPPORTED_GROUPS:
    case WT_TLS_EXT_USE_SRTP:
    case WT_TLS_EXT_HEARTBEAT:
    case WT_TLS_EXT_ALPN:
    case WT_TLS_EXT_CLIENT_CERTIFICATE_TYPE:
    case WT_TLS_EXT_SERVER_CERTIFICATE_TYPE:
    case WT_TLS_EXT_EARLY_DATA:
    case WT_TLS_EXT_QUIC_TRANSPORT_PARAMETERS:
      return 1;
    default:
      return 0;
  }
}

/* Whether RFC 8446 section 4.2 lists `type` as valid in EncryptedExtensions.
 *
 * This only ever decides between `illegal_parameter` and acceptance for an
 * extension the client offered, so it does not have to be complete: anything
 * missing from it is either not offered (refused a step earlier as
 * unsupported_extension) or is a type this module offers and has classified
 * here. `record_size_limit` (RFC 8449) is included because it is legal there
 * and RFC 8448's trace carries it; `renegotiation_info` is not, because
 * RFC 9001 section 8.4 prohibits it under QUIC and it is never offered. */
static int ee_extension_is_permitted(uint16_t type) {
  switch (type) {
    case WT_TLS_EXT_SERVER_NAME:
    case WT_TLS_EXT_MAX_FRAGMENT_LENGTH:
    case WT_TLS_EXT_SUPPORTED_GROUPS:
    case WT_TLS_EXT_USE_SRTP:
    case WT_TLS_EXT_HEARTBEAT:
    case WT_TLS_EXT_ALPN:
    case WT_TLS_EXT_CLIENT_CERTIFICATE_TYPE:
    case WT_TLS_EXT_SERVER_CERTIFICATE_TYPE:
    case WT_TLS_EXT_RECORD_SIZE_LIMIT:
    case WT_TLS_EXT_EARLY_DATA:
    case WT_TLS_EXT_QUIC_TRANSPORT_PARAMETERS:
      return 1;
    default:
      return 0;
  }
}

static void ee_reject(wt_tls_encrypted_extensions_t *out,
                      wt_tls_ee_reject_t reason, uint16_t extension) {
  memset(out, 0, sizeof(*out));
  out->reject = reason;
  out->reject_extension = extension;
}

/* Parse the body of one permitted extension whose shape this module checks.
 * `data`/`len` is that extension's body. Returns 0 or -1. */
static int ee_parse_extension_body(wt_tls_encrypted_extensions_t *out,
                                   uint16_t type, const uint8_t *data,
                                   size_t len) {
  switch (type) {
    case WT_TLS_EXT_ALPN:
      /* RFC 7301 section 3.1: the server's ProtocolNameList carries exactly one
         ProtocolName, `opaque protocol_name<1..255>`. Two names is not a
         preference order to pick from -- it is a server that has not decided,
         and a client that picked the first would be agreeing to something the
         server did not choose. An empty name is refused too: length zero is not
         a valid ProtocolName. */
      if (len < 1U) return -1;
      if ((size_t)data[0] != len - 1U) return -1;
      if (len == 1U) return -1;
      out->alpn = data + 1U;
      out->alpn_len = len - 1U;
      out->has_alpn = 1;
      return 0;

    case WT_TLS_EXT_QUIC_TRANSPORT_PARAMETERS:
      /* Zero length is legal: a server with nothing to say still sends the
         extension, and RFC 9001 section 8.2 requires it to be present, not
         non-empty. */
      if (len > 0U && data == NULL) return -1;
      out->transport_parameters = data;
      out->transport_parameters_len = len;
      out->has_transport_parameters = 1;
      return 0;

    case WT_TLS_EXT_SERVER_NAME:
      /* RFC 6066 section 3: the server's response carries no body. A
         server_name with content is a server answering a request it was not
         sent. */
      if (len != 0U) return -1;
      out->has_server_name = 1;
      return 0;

    case WT_TLS_EXT_MAX_FRAGMENT_LENGTH:
      /* RFC 6066 section 4: one byte, 1 (2^9) through 4 (2^12). */
      if (len != 1U) return -1;
      if (data[0] < 1U || data[0] > 4U) return -1;
      out->max_fragment_length = data[0];
      out->has_max_fragment_length = 1;
      return 0;

    case WT_TLS_EXT_EARLY_DATA:
      /* RFC 8446 section 4.2.10: in EncryptedExtensions this is an empty
         indication that the server accepted the 0-RTT data. This module does
         not offer 0-RTT, so a server sending it is answering a ClientHello
         that did not ask -- which the offered-check catches -- but the shape is
         still checked here. */
      if (len != 0U) return -1;
      out->has_early_data = 1;
      return 0;

    case WT_TLS_EXT_CLIENT_CERTIFICATE_TYPE:
      /* RFC 7250 section 4.2: one byte, from the CertificateType registry. */
      if (len != 1U) return -1;
      out->client_certificate_type = data[0];
      out->has_client_certificate_type = 1;
      return 0;

    case WT_TLS_EXT_SERVER_CERTIFICATE_TYPE:
      if (len != 1U) return -1;
      out->server_certificate_type = data[0];
      out->has_server_certificate_type = 1;
      return 0;

    case WT_TLS_EXT_SUPPORTED_GROUPS:
    case WT_TLS_EXT_USE_SRTP:
    case WT_TLS_EXT_HEARTBEAT:
      /* Permitted, and nothing this module acts on. Recorded so a caller can
         see what the server sent; the body is not decoded. */
      if (type == WT_TLS_EXT_SUPPORTED_GROUPS) out->has_supported_groups = 1;
      if (type == WT_TLS_EXT_USE_SRTP) out->has_use_srtp = 1;
      if (type == WT_TLS_EXT_HEARTBEAT) out->has_heartbeat = 1;
      return 0;

    default:
      /* Unreachable: the caller has already applied the whitelist. Refusing
         rather than returning success keeps that true if the two ever drift. */
      return -1;
  }
}

int wt_tls_parse_encrypted_extensions(const uint8_t *message,
                                      size_t message_len,
                                      wt_tls_encrypted_extensions_t *out) {
  uint8_t type = 0U;
  size_t body_len = 0U;
  size_t body_offset = 0U;
  const uint8_t *body;
  size_t extensions_len;
  reader_t r;

  if (message == NULL || out == NULL) return -1;
  memset(out, 0, sizeof(*out));
  out->reject = WT_TLS_EE_OK;

  if (wt_tls_decode_handshake_header(message, message_len, &type, &body_len,
                                     &body_offset) != 0) {
    ee_reject(out, WT_TLS_EE_MALFORMED, 0U);
    return -1;
  }
  /* RFC 8446 section 4.3.1: the message IS the extension list. A declared
     length that is not exactly the list plus its two-byte length prefix is a
     message with trailing bytes, which is how a second message gets smuggled
     into one that the transcript then hashes as a whole. */
  if (type != WT_TLS_HS_ENCRYPTED_EXTENSIONS) {
    ee_reject(out, WT_TLS_EE_MALFORMED, 0U);
    return -1;
  }
  if (body_len < 2U) {
    ee_reject(out, WT_TLS_EE_MALFORMED, 0U);
    return -1;
  }
  body = message + body_offset;
  extensions_len = ((size_t)body[0] << 8) | (size_t)body[1];
  if (extensions_len != body_len - 2U) {
    ee_reject(out, WT_TLS_EE_MALFORMED, 0U);
    return -1;
  }

  reader_init(&r, body + 2U, extensions_len);
  for (;;) {
    uint16_t ext_type;
    uint16_t ext_len;
    const uint8_t *ext_data;

    /* The list is self-delimiting: read until the reader is exhausted, and
       refuse a type or length that runs past the end rather than stopping. */
    if (r.offset == r.len) break;
    if (r.failed) {
      ee_reject(out, WT_TLS_EE_MALFORMED, 0U);
      return -1;
    }
    if (out->type_count >= WT_TLS_MAX_ENCRYPTED_EXTENSIONS) {
      ee_reject(out, WT_TLS_EE_TOO_MANY_EXTENSIONS, 0U);
      return -1;
    }
    ext_type = reader_u16(&r);
    ext_len = reader_u16(&r);
    if (r.failed) {
      ee_reject(out, WT_TLS_EE_MALFORMED, ext_type);
      return -1;
    }
    ext_data = reader_take(&r, (size_t)ext_len);
    if (r.failed) {
      ee_reject(out, WT_TLS_EE_MALFORMED, ext_type);
      return -1;
    }
    if (ee_extension_is_decoded(ext_type)) {
      if (ee_parse_extension_body(out, ext_type, ext_data, (size_t)ext_len) !=
          0) {
        ee_reject(out, WT_TLS_EE_BAD_EXTENSION, ext_type);
        return -1;
      }
    }
    out->types[out->type_count++] = ext_type;
  }

  /* RFC 8446 section 4.2: "There MUST NOT be more than one extension of the
     same type in a given extension block." Checked over the list just built,
     which is bounded and so cannot loop over peer-controlled length. A second
     copy is not harmless: two ALPN answers leave which one binds ambiguous,
     and the transcript would still verify. */
  {
    size_t i;
    size_t j;
    for (i = 0U; i < out->type_count; i++) {
      for (j = i + 1U; j < out->type_count; j++) {
        if (out->types[i] == out->types[j]) {
          ee_reject(out, WT_TLS_EE_DUPLICATE_EXTENSION, out->types[i]);
          return -1;
        }
      }
    }
  }
  return 0;
}

int wt_tls_encrypted_extensions_check(
    const wt_tls_encrypted_extensions_t *ee,
    const wt_tls_client_hello_params_t *offered, wt_tls_ee_reject_t *out_reject,
    uint16_t *out_extension) {
  size_t i;

  if (out_reject != NULL) *out_reject = WT_TLS_EE_OK;
  if (out_extension != NULL) *out_extension = 0U;
  if (ee == NULL || offered == NULL) {
    if (out_reject != NULL) *out_reject = WT_TLS_EE_MALFORMED;
    return -1;
  }
  /* `type_count` is written only by the parser and bounded by the array, so
     this loop is over peer-influenced data with a length this code chose. */
  if (ee->type_count > WT_TLS_MAX_ENCRYPTED_EXTENSIONS) {
    if (out_reject != NULL) *out_reject = WT_TLS_EE_TOO_MANY_EXTENSIONS;
    return -1;
  }
  for (i = 0U; i < ee->type_count; i++) {
    uint16_t type = ee->types[i];
    /* Rule 1: the client must have asked for it. This is checked first because
       it is the rule that covers extensions this module has never heard of. */
    if (wt_tls_client_hello_offers(offered, type) != 1) {
      if (out_reject != NULL) *out_reject = WT_TLS_EE_UNSOLICITED_EXTENSION;
      if (out_extension != NULL) *out_extension = type;
      return -1;
    }
    /* Rule 2: it must belong in this message. */
    if (!ee_extension_is_permitted(type)) {
      if (out_reject != NULL) *out_reject = WT_TLS_EE_FORBIDDEN_EXTENSION;
      if (out_extension != NULL) *out_extension = type;
      return -1;
    }
  }
  return 0;
}

int wt_tls_client_hello_offers(const wt_tls_client_hello_params_t *params,
                               uint16_t type) {
  if (params == NULL) return -1;
  switch (type) {
    case WT_TLS_EXT_SERVER_NAME:
      return params->server_name != NULL ? 1 : 0;
    case WT_TLS_EXT_SUPPORTED_GROUPS:
      return (params->supported_groups != NULL &&
              params->supported_group_count > 0U)
                 ? 1
                 : 0;
    case WT_TLS_EXT_SIGNATURE_ALGORITHMS:
      return (params->signature_algorithms != NULL &&
              params->signature_algorithm_count > 0U)
                 ? 1
                 : 0;
    case WT_TLS_EXT_ALPN:
      return (params->alpn_protocols != NULL && params->alpn_protocols_len > 0U)
                 ? 1
                 : 0;
    case WT_TLS_EXT_QUIC_TRANSPORT_PARAMETERS:
      return (params->quic_transport_parameters != NULL &&
              params->quic_transport_parameters_len > 0U)
                 ? 1
                 : 0;
    case WT_TLS_EXT_SUPPORTED_VERSIONS:
      /* The builder emits this unconditionally: TLS 1.3 is the only version
         this speaks, so it is not conditional on anything the caller sets. */
      return 1;
    case WT_TLS_EXT_KEY_SHARE:
      return (params->key_shares != NULL && params->key_share_count > 0U) ? 1
                                                                         : 0;
    default:
      /* Anything else is not in this client's ClientHello, so a server sending
         it is answering a request that was never made. */
      return 0;
  }
}

/* ---------------------------------------------------------------------------
 * ClientHello construction (RFC 8446 section 4.1.2)
 *
 * A writer with a bound on every length. The message is built in two passes:
 * the size function walks the same structure and sums, and the encoder refuses
 * if the buffer is smaller than the sum said. Building it blind and truncating
 * would produce a message that is short by however much the buffer was, and a
 * peer would reject it for a reason that looks like a protocol error.
 */

typedef struct writer {
  uint8_t *out;
  size_t capacity;
  size_t offset;
  int overflow;
  /* Whether to copy or only to count. A NULL `out` means the measuring pass,
     and the writer must NOT memcpy from it: the guard here used to test the
     SOURCE pointer, which is never NULL for the writes that matter, so the
     measuring pass dereferenced NULL and crashed. Testing the destination is
     the correct guard and this flag makes it explicit rather than implied by
     `out` being non-NULL. */
  int copy;
} writer_t;

/* A capacity larger than any ClientHello can be, used by the measuring pass.
   Every write fits, so the writer counts and never overflows, and nothing is
   copied because `out` is NULL.
 *
 * It is a large finite number and not (size_t)-1: the writer tests
 * `len > capacity - offset`, so a capacity of SIZE_MAX wraps that subtraction
 * and the test passes for any length. The measuring pass then copied into a
 * NULL buffer, which is how this was found -- as a segmentation fault rather
 * than as a wrong size. The value is a whole handshake message plus the
 * extension overhead, which is the largest this function can legitimately
 * build. */
#define WT_WRITER_MEASURE ((size_t)0x1000000U)

static void w_bytes(writer_t *w, const void *data, size_t len) {
  if (w->overflow) return;
  if (len > w->capacity - w->offset) {
    w->overflow = 1;
    return;
  }
  if (w->copy && len != 0U) {
    /* `data` may legitimately be NULL only for a zero-length write, which the
       length test above excludes. */
    memcpy(w->out + w->offset, data, len);
  }
  w->offset += len;
}

static void w_u8(writer_t *w, uint8_t value) { w_bytes(w, &value, 1U); }

static void w_u16(writer_t *w, uint16_t value) {
  uint8_t bytes[2];
  bytes[0] = (uint8_t)(value >> 8);
  bytes[1] = (uint8_t)(value & 0xFFU);
  w_bytes(w, bytes, 2U);
}

static void w_u24(writer_t *w, size_t value) {
  uint8_t bytes[3];
  bytes[0] = (uint8_t)((value >> 16) & 0xFFU);
  bytes[1] = (uint8_t)((value >> 8) & 0xFFU);
  bytes[2] = (uint8_t)(value & 0xFFU);
  w_bytes(w, bytes, 3U);
}

/* The extensions block, built into `out` when it is non-NULL and measured when
 * it is NULL. Both callers walk the same code, so the measurement and the
 * encoding cannot disagree. */
static size_t build_extensions(const wt_tls_client_hello_params_t *p,
                               uint8_t *out, size_t capacity, int *ok) {
  writer_t w;
  size_t i;

  w.out = out;
  w.capacity = capacity;
  w.offset = 0U;
  w.overflow = 0;
  w.copy = (out != NULL);

  /* server_name (RFC 6066). The SNI is carried so a server can pick a
     certificate; an empty name is not sent. */
  if (p->server_name != NULL) {
    size_t name_len = strlen(p->server_name);
    if (name_len == 0U || name_len > 65535U) {
      *ok = 0;
      return 0U;
    }
    {
      size_t entry_len = 1U + 2U + name_len; /* type || name length || name */
      size_t list_len = entry_len;
      if (list_len > 65535U) {
        *ok = 0;
        return 0U;
      }
      w_u16(&w, WT_TLS_EXT_SERVER_NAME);
      w_u16(&w, (uint16_t)(2U + list_len));
      w_u16(&w, (uint16_t)list_len);
      w_u8(&w, 0U); /* NameType host_name */
      w_u16(&w, (uint16_t)name_len);
      w_bytes(&w, p->server_name, name_len);
    }
  }

  /* supported_groups (RFC 8446 section 4.2.7). */
  if (p->supported_group_count != 0U) {
    size_t list_len = p->supported_group_count * 2U;
    if (list_len > 65535U) {
      *ok = 0;
      return 0U;
    }
    w_u16(&w, WT_TLS_EXT_SUPPORTED_GROUPS);
    w_u16(&w, (uint16_t)(2U + list_len));
    w_u16(&w, (uint16_t)list_len);
    for (i = 0U; i < p->supported_group_count; i++) {
      w_u16(&w, p->supported_groups[i]);
    }
  }

  /* signature_algorithms (RFC 8446 section 4.2.3). */
  if (p->signature_algorithm_count != 0U) {
    size_t list_len = p->signature_algorithm_count * 2U;
    if (list_len > 65535U) {
      *ok = 0;
      return 0U;
    }
    w_u16(&w, WT_TLS_EXT_SIGNATURE_ALGORITHMS);
    w_u16(&w, (uint16_t)(2U + list_len));
    w_u16(&w, (uint16_t)list_len);
    for (i = 0U; i < p->signature_algorithm_count; i++) {
      w_u16(&w, p->signature_algorithms[i]);
    }
  }

  /* application_layer_protocol_negotiation (RFC 7301). The list is already
     length-prefixed per protocol by the caller, which is the form on the wire;
     this adds the outer list length only. */
  if (p->alpn_protocols != NULL && p->alpn_protocols_len != 0U) {
    if (p->alpn_protocols_len > 65535U) {
      *ok = 0;
      return 0U;
    }
    w_u16(&w, WT_TLS_EXT_ALPN);
    w_u16(&w, (uint16_t)(2U + p->alpn_protocols_len));
    w_u16(&w, (uint16_t)p->alpn_protocols_len);
    w_bytes(&w, p->alpn_protocols, p->alpn_protocols_len);
  }

  /* supported_versions (RFC 8446 section 4.2.1): a one-byte length then the
     versions, most preferred first. TLS 1.3 must be offered. */
  {
    static const uint16_t versions[1] = {WT_TLS_VERSION_13};
    w_u16(&w, WT_TLS_EXT_SUPPORTED_VERSIONS);
    w_u16(&w, (uint16_t)(1U + sizeof(versions)));
    w_u8(&w, (uint8_t)sizeof(versions));
    for (i = 0U; i < sizeof(versions) / sizeof(versions[0]); i++) {
      w_u16(&w, versions[i]);
    }
  }

  /* key_share (RFC 8446 section 4.2.8): ClientHello carries a list of shares,
     each group || key length || key. */
  if (p->key_share_count != 0U) {
    size_t shares_len = 0U;
    for (i = 0U; i < p->key_share_count; i++) {
      if (p->key_shares[i].public_key == NULL ||
          p->key_shares[i].public_key_len == 0U ||
          p->key_shares[i].public_key_len > 65535U) {
        *ok = 0;
        return 0U;
      }
      shares_len += 2U + 2U + p->key_shares[i].public_key_len;
    }
    if (shares_len > 65535U) {
      *ok = 0;
      return 0U;
    }
    w_u16(&w, WT_TLS_EXT_KEY_SHARE);
    w_u16(&w, (uint16_t)(2U + shares_len));
    w_u16(&w, (uint16_t)shares_len);
    for (i = 0U; i < p->key_share_count; i++) {
      w_u16(&w, p->key_shares[i].group);
      w_u16(&w, (uint16_t)p->key_shares[i].public_key_len);
      w_bytes(&w, p->key_shares[i].public_key,
              p->key_shares[i].public_key_len);
    }
  }

  /* quic_transport_parameters (RFC 9001 section 8.2). Mandatory in a QUIC
     ClientHello; a server that does not see it closes the connection. */
  if (p->quic_transport_parameters != NULL &&
      p->quic_transport_parameters_len != 0U) {
    if (p->quic_transport_parameters_len > 65535U) {
      *ok = 0;
      return 0U;
    }
    w_u16(&w, WT_TLS_EXT_QUIC_TRANSPORT_PARAMETERS);
    w_u16(&w, (uint16_t)p->quic_transport_parameters_len);
    w_bytes(&w, p->quic_transport_parameters,
            p->quic_transport_parameters_len);
  }

  if (w.overflow) {
    *ok = 0;
    return 0U;
  }
  *ok = 1;
  return w.offset;
}

/* The body length and the extension bytes. Returns 0 on invalid parameters. */
static size_t client_hello_body_size(const wt_tls_client_hello_params_t *p,
                                     size_t *extensions_len) {
  int ok = 0;
  size_t body;

  if (p == NULL || p->random == NULL) return 0U;
  if (p->cipher_suite_count == 0U || p->cipher_suites == NULL) return 0U;
  /* At least one key share. Zero is legal TLS -- it invites a
     HelloRetryRequest -- and a QUIC handshake is not willing to spend the
     round trip, so this builder requires one and a caller that wants the retry
     has to ask for it another way. */
  if (p->key_share_count == 0U || p->key_shares == NULL) return 0U;
  /* RFC 8446 section 4.1.2 allows a ClientHello to carry a legacy session ID,
     but RFC 9001 section 8.4 PROHIBITS it for QUIC: a server must treat a
     non-empty one as a PROTOCOL_VIOLATION. Refusing here rather than sending
     one means a caller cannot accidentally ask for middlebox compatibility
     mode on a protocol that has no middleboxes. */
  if (p->legacy_session_id_len != 0U) return 0U;
  if ((p->supported_group_count != 0U && p->supported_groups == NULL) ||
      (p->signature_algorithm_count != 0U &&
       p->signature_algorithms == NULL) ||
      (p->key_share_count != 0U && p->key_shares == NULL)) {
    return 0U;
  }
  if (p->alpn_protocols_len > 65535U ||
      p->quic_transport_parameters_len > 65535U) {
    return 0U;
  }

  /* legacy_version(2) || random(32) || session_id_len(1) ||
     cipher_suites_len(2) + suites || compression_len(1) + methods(1) ||
     extensions_len(2) + extensions */
  body = 2U + 32U + 1U;
  body += 2U + p->cipher_suite_count * 2U;
  body += 1U + 1U;
  body += 2U;
  /* MEASURE, not a zero-capacity buffer. Passing 0 here means the first write
     is "longer than the space left", which sets the overflow flag and makes
     every measurement report a malformed parameter set -- so every ClientHello
     measured 0 bytes and none could be built. The measurement pass needs a
     writer that never overflows and only counts. */
  *extensions_len = build_extensions(p, NULL, WT_WRITER_MEASURE, &ok);
  if (!ok) return 0U;
  body += *extensions_len;
  return body;
}

size_t wt_tls_client_hello_size(const wt_tls_client_hello_params_t *params) {
  size_t extensions_len = 0U;
  size_t body = client_hello_body_size(params, &extensions_len);
  if (body == 0U) return 0U;
  if (body > WT_TLS_MAX_HANDSHAKE_MESSAGE) return 0U;
  return 4U + body;
}

size_t wt_tls_encode_client_hello(const wt_tls_client_hello_params_t *params,
                                  uint8_t *out, size_t out_capacity) {
  size_t extensions_len = 0U;
  size_t body;
  size_t total;
  writer_t w;
  int ok = 0;

  body = client_hello_body_size(params, &extensions_len);
  if (body == 0U || body > WT_TLS_MAX_HANDSHAKE_MESSAGE) return 0U;
  total = 4U + body;
  if (out == NULL || out_capacity < total) return 0U;

  w.out = out;
  w.capacity = out_capacity;
  w.offset = 0U;
  w.overflow = 0;
  w.copy = (out != NULL);

  w_u8(&w, WT_TLS_HS_CLIENT_HELLO);
  w_u24(&w, body);

  /* legacy_version: 0x0303, always, with the real version in
     supported_versions. A client that wrote 0x0304 here would be speaking a
     protocol that does not exist. */
  w_u16(&w, WT_TLS_LEGACY_VERSION);
  w_bytes(&w, params->random, 32U);
  w_u8(&w, 0U); /* empty legacy_session_id, required for QUIC */

  w_u16(&w, (uint16_t)(params->cipher_suite_count * 2U));
  for (size_t i = 0U; i < params->cipher_suite_count; i++) {
    w_u16(&w, params->cipher_suites[i]);
  }

  /* legacy_compression_method: one byte, null compression, and nothing else in
     TLS 1.3. */
  w_u8(&w, 1U);
  w_u8(&w, 0U);

  w_u16(&w, (uint16_t)extensions_len);
  {
    size_t written = build_extensions(params, out + w.offset,
                                      out_capacity - w.offset, &ok);
    /* The measuring pass and the encoding pass walk the same code, so a
       disagreement means one of them took a different branch. Refusing is the
       only safe answer: the alternative is a message whose length field does
       not describe its body. */
    if (!ok || written != extensions_len) return 0U;
    w.offset += written;
  }

  if (w.overflow || w.offset != total) return 0U;
  return total;
}

/* ----------------------------------------------------------------- Finished */

int wt_tls_finished_compute(const uint8_t traffic_secret[WT_TLS_HASH_LEN],
                            const uint8_t transcript_hash[WT_TLS_HASH_LEN],
                            uint8_t out[WT_TLS_FINISHED_LEN]) {
  uint8_t finished_key[WT_TLS_HASH_LEN];

  if (traffic_secret == NULL || transcript_hash == NULL || out == NULL) {
    return -1;
  }
  /* finished_key = HKDF-Expand-Label(secret, "finished", "", Hash.length) */
  if (wt_tls_expand_label(traffic_secret, WT_TLS_HASH_LEN, "finished", NULL, 0,
                          finished_key, sizeof(finished_key)) != 0) {
    return -1;
  }
  /* verify_data = HMAC(finished_key, Transcript-Hash(...)) */
  if (wt_hmac_sha256(finished_key, sizeof(finished_key), transcript_hash,
                     WT_TLS_HASH_LEN, out) != 0) {
    wt_secure_zero(finished_key, sizeof(finished_key));
    return -1;
  }
  wt_secure_zero(finished_key, sizeof(finished_key));
  return 0;
}

int wt_tls_finished_verify(const uint8_t traffic_secret[WT_TLS_HASH_LEN],
                           const uint8_t transcript_hash[WT_TLS_HASH_LEN],
                           const uint8_t *message, size_t message_len) {
  uint8_t expected[WT_TLS_FINISHED_LEN];
  uint8_t type = 0U;
  size_t body_len = 0U;
  size_t body_offset = 0U;
  int equal;

  if (traffic_secret == NULL || transcript_hash == NULL || message == NULL) {
    return -1;
  }
  /* The message must be a Finished of exactly the right body length, so a
     caller cannot pass a truncated one and have the first 32 bytes of
     something else compared. */
  if (wt_tls_decode_handshake_header(message, message_len, &type, &body_len,
                                     &body_offset) != 0) {
    return -1;
  }
  if (type != WT_TLS_HS_FINISHED) return -1;
  if (body_len != WT_TLS_FINISHED_LEN) return -1;
  if (message_len != body_offset + body_len) return -1;

  if (wt_tls_finished_compute(traffic_secret, transcript_hash, expected) != 0) {
    return -1;
  }
  equal = wt_ct_equal(expected, message + body_offset,
                      WT_TLS_FINISHED_LEN);
  wt_secure_zero(expected, sizeof(expected));
  return equal;
}
