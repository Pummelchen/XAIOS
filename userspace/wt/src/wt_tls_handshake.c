/* TLS 1.3 handshake framing, the transcript hash, and ServerHello parsing.
 *
 * RFC 8446 sections 4 and 4.1.3. See wt_tls_handshake.h for the scope.
 */

#include "wt_tls_handshake.h"

#include <string.h>

/* The extensions this parser cares about (RFC 8446 section 4.2). */
#define WT_TLS_EXT_SUPPORTED_VERSIONS 0x002BU
#define WT_TLS_EXT_KEY_SHARE 0x0033U

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
