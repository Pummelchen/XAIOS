/* TLS 1.3 handshake messages. See webtransport/tls/handshake.h. */

#include "webtransport/tls/handshake.h"

#include <string.h>

/* A TLS 1.3 ClientHello and ServerHello both claim 0x0303 in `legacy_version` and
 * negotiate 1.3 in `supported_versions` (RFC 8446 section 4.1.2), so that a middlebox
 * which understands only this field is not given a reason to interfere. */
#define WT_TLS_LEGACY_VERSION 0x0303U

wt_status_t wt_tls_handshake_header_parse(wt_cursor_t *cursor,
                                          wt_tls_handshake_header_t *out) {
  uint8_t type;
  uint32_t length;

  if (cursor == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  type = wt_cursor_u8(cursor);
  length = wt_cursor_u24(cursor);
  if (wt_cursor_failed(cursor)) return WT_ERR_TRUNCATED;
  /* The declared length must be the rest of the buffer exactly. A caller with several
   * messages in one buffer slices them itself; accepting a longer buffer here would
   * let a parser read a second message's bytes as this one's body. */
  if (wt_cursor_remaining(cursor) != (size_t)length) return WT_ERR_PROTOCOL;
  out->type = type;
  out->length = (size_t)length;
  return WT_OK;
}

wt_status_t wt_tls_handshake_header_encode(wt_writer_t *w, uint8_t type,
                                           size_t body_len) {
  if (w == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (body_len > WT_TLS_HANDSHAKE_MAX_BODY) return WT_ERR_LIMIT;
  wt_writer_u8(w, type);
  wt_writer_u24(w, (uint32_t)body_len);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

size_t wt_tls_handshake_message_len(const uint8_t *buffer, size_t len) {
  size_t body;
  if (buffer == NULL || len < WT_TLS_HANDSHAKE_HEADER_LEN) return 0U;
  body = ((size_t)buffer[1] << 16) | ((size_t)buffer[2] << 8) | (size_t)buffer[3];
  if (body > len - WT_TLS_HANDSHAKE_HEADER_LEN) return 0U;
  return body + WT_TLS_HANDSHAKE_HEADER_LEN;
}

const char *wt_tls_handshake_type_name(uint8_t type) {
  switch (type) {
    case WT_TLS_HANDSHAKE_CLIENT_HELLO:
      return "client-hello";
    case WT_TLS_HANDSHAKE_SERVER_HELLO:
      return "server-hello";
    case WT_TLS_HANDSHAKE_NEW_SESSION_TICKET:
      return "new-session-ticket";
    case WT_TLS_HANDSHAKE_END_OF_EARLY_DATA:
      return "end-of-early-data";
    case WT_TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS:
      return "encrypted-extensions";
    case WT_TLS_HANDSHAKE_CERTIFICATE:
      return "certificate";
    case WT_TLS_HANDSHAKE_CERTIFICATE_REQUEST:
      return "certificate-request";
    case WT_TLS_HANDSHAKE_CERTIFICATE_VERIFY:
      return "certificate-verify";
    case WT_TLS_HANDSHAKE_FINISHED:
      return "finished";
    case WT_TLS_HANDSHAKE_KEY_UPDATE:
      return "key-update";
    case WT_TLS_HANDSHAKE_MESSAGE_HASH:
      return "message-hash";
    default:
      return "unknown";
  }
}

/* ===================================================================== bodies
 *
 * Each body is written by one function, and every encoder runs that function twice:
 * once into a measuring writer to learn its length, then into the message. The length
 * prefix is therefore the length the same code produced, which is the whole reason the
 * writer has two modes. A body nested behind its own length -- the extension block --
 * is written by a function that measures its own contents the same way.
 */

/* Everything of a ClientHello except the extension block. */
static void client_hello_prefix_body(const wt_tls_client_hello_t *hello,
                                     wt_writer_t *w) {
  size_t i;
  wt_writer_u16(w, hello->legacy_version);
  wt_writer_bytes(w, hello->random, WT_TLS_RANDOM_LEN);
  wt_writer_u8(w, (uint8_t)hello->session_id_len);
  wt_writer_bytes(w, hello->session_id, hello->session_id_len);
  wt_writer_u16(w, (uint16_t)(2U * hello->cipher_suite_count));
  for (i = 0U; i < hello->cipher_suite_count; i++) {
    wt_writer_u16(w, hello->cipher_suites[i]);
  }
  wt_writer_u8(w, (uint8_t)hello->compression_method_count);
  for (i = 0U; i < hello->compression_method_count; i++) {
    wt_writer_u8(w, hello->compression_methods[i]);
  }
}

/* Everything of a ServerHello except the extension block. */
static void server_hello_prefix_body(const wt_tls_server_hello_t *hello,
                                     wt_writer_t *w) {
  wt_writer_u16(w, hello->legacy_version);
  wt_writer_bytes(w, hello->random, WT_TLS_RANDOM_LEN);
  wt_writer_u8(w, (uint8_t)hello->session_id_len);
  wt_writer_bytes(w, hello->session_id, hello->session_id_len);
  wt_writer_u16(w, hello->cipher_suite);
  wt_writer_u8(w, hello->compression_method);
}

/* The extensions our client offers, in the order a QUIC client sends them, behind
 * their own two-byte length. RFC 9001 section 8.2 makes quic_transport_parameters
 * mandatory in a ClientHello, and RFC 8446 section 9.2 makes supported_versions
 * mandatory as soon as TLS 1.3 may be negotiated. */
static wt_status_t client_hello_extensions(
    const wt_tls_client_hello_params_t *params, wt_writer_t *w) {
  uint16_t version = WT_TLS_VERSION_1_3;
  wt_writer_t measure;

  /* The block's length, measured by running the same calls below. */
  measure = wt_writer_measure();
  if (params->host_name != NULL) {
    wt_tls_extension_server_name(&measure, params->host_name);
  }
  if (params->supported_group_count != 0U) {
    wt_tls_extension_u16_list(&measure, WT_TLS_EXTENSION_SUPPORTED_GROUPS,
                              params->supported_groups,
                              params->supported_group_count);
  }
  if (params->signature_scheme_count != 0U) {
    wt_tls_extension_u16_list(&measure, WT_TLS_EXTENSION_SIGNATURE_ALGORITHMS,
                              params->signature_schemes,
                              params->signature_scheme_count);
  }
  wt_tls_extension_supported_versions_client(&measure, &version, 1U);
  if (params->key_share_count != 0U) {
    wt_tls_extension_key_share_client(&measure, params->key_shares,
                                      params->key_share_count);
  }
  if (params->alpn_count != 0U) {
    wt_tls_extension_alpn(&measure, params->alpn, params->alpn_count);
  }
  wt_tls_extension_psk_key_exchange_modes(&measure);
  if (params->transport_parameters_len != 0U) {
    wt_tls_extension_transport_parameters(&measure, params->transport_parameters,
                                          params->transport_parameters_len);
  }
  if (!wt_writer_ok(&measure)) return WT_ERR_LIMIT;
  /* A block whose length does not fit its two-byte field is refused before anything is
   * written: half a block is not a block. */
  if (wt_writer_offset(&measure) > 0xFFFFU) return WT_ERR_LIMIT;
  wt_writer_u16(w, (uint16_t)wt_writer_offset(&measure));
  if (params->host_name != NULL) {
    wt_tls_extension_server_name(w, params->host_name);
  }
  if (params->supported_group_count != 0U) {
    wt_tls_extension_u16_list(w, WT_TLS_EXTENSION_SUPPORTED_GROUPS,
                              params->supported_groups,
                              params->supported_group_count);
  }
  if (params->signature_scheme_count != 0U) {
    wt_tls_extension_u16_list(w, WT_TLS_EXTENSION_SIGNATURE_ALGORITHMS,
                              params->signature_schemes,
                              params->signature_scheme_count);
  }
  wt_tls_extension_supported_versions_client(w, &version, 1U);
  if (params->key_share_count != 0U) {
    wt_tls_extension_key_share_client(w, params->key_shares,
                                      params->key_share_count);
  }
  if (params->alpn_count != 0U) {
    wt_tls_extension_alpn(w, params->alpn, params->alpn_count);
  }
  wt_tls_extension_psk_key_exchange_modes(w);
  if (params->transport_parameters_len != 0U) {
    wt_tls_extension_transport_parameters(w, params->transport_parameters,
                                          params->transport_parameters_len);
  }
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

/* The extensions our server answers with: the version it chose and its key share. */
static wt_status_t server_hello_extensions(
    const wt_tls_server_hello_params_t *params, wt_writer_t *w) {
  wt_writer_t measure = wt_writer_measure();

  if (params->key_share->key == NULL || params->key_share->key_len == 0U ||
      params->key_share->key_len > 0xFFFFU) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  wt_tls_extension_supported_versions_server(&measure, params->supported_version);
  wt_tls_extension_key_share_server(&measure, params->key_share);
  if (!wt_writer_ok(&measure)) return WT_ERR_LIMIT;
  if (wt_writer_offset(&measure) > 0xFFFFU) return WT_ERR_LIMIT;
  wt_writer_u16(w, (uint16_t)wt_writer_offset(&measure));
  wt_tls_extension_supported_versions_server(w, params->supported_version);
  wt_tls_extension_key_share_server(w, params->key_share);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

/* ------------------------------------------------------------------- encoders */

wt_status_t wt_tls_client_hello_encode(const wt_tls_client_hello_t *hello,
                                       wt_writer_t *w) {
  wt_writer_t measure;
  size_t body_len;

  if (hello == NULL || w == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (hello->session_id == NULL && hello->session_id_len != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* The parser never produces a message outside these bounds, so a structure that
   * violates one was built by hand -- and refusing here keeps the encoder from writing
   * a length field that cannot hold what follows it. */
  if (hello->session_id_len > WT_TLS_SESSION_ID_MAX) return WT_ERR_LIMIT;
  if (hello->cipher_suite_count == 0U ||
      hello->cipher_suite_count > WT_TLS_CIPHER_SUITES_MAX) {
    return WT_ERR_LIMIT;
  }
  if (hello->compression_method_count == 0U ||
      hello->compression_method_count > WT_TLS_COMPRESSION_METHODS_MAX) {
    return WT_ERR_LIMIT;
  }
  measure = wt_writer_measure();
  client_hello_prefix_body(hello, &measure);
  (void)wt_tls_extensions_encode(&measure, &hello->extensions);
  if (!wt_writer_ok(&measure)) return WT_ERR_LIMIT;
  body_len = wt_writer_offset(&measure);
  if (body_len > WT_TLS_HANDSHAKE_MAX_BODY) return WT_ERR_LIMIT;

  if (wt_tls_handshake_header_encode(w, WT_TLS_HANDSHAKE_CLIENT_HELLO, body_len) !=
      WT_OK) {
    return WT_ERR_LIMIT;
  }
  client_hello_prefix_body(hello, w);
  if (wt_tls_extensions_encode(w, &hello->extensions) != WT_OK) {
    return WT_ERR_LIMIT;
  }
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

wt_status_t wt_tls_server_hello_encode(const wt_tls_server_hello_t *hello,
                                       wt_writer_t *w) {
  wt_writer_t measure;
  size_t body_len;

  if (hello == NULL || w == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (hello->session_id == NULL && hello->session_id_len != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (hello->session_id_len > WT_TLS_SESSION_ID_MAX) return WT_ERR_LIMIT;
  measure = wt_writer_measure();
  server_hello_prefix_body(hello, &measure);
  (void)wt_tls_extensions_encode(&measure, &hello->extensions);
  if (!wt_writer_ok(&measure)) return WT_ERR_LIMIT;
  body_len = wt_writer_offset(&measure);
  if (body_len > WT_TLS_HANDSHAKE_MAX_BODY) return WT_ERR_LIMIT;

  if (wt_tls_handshake_header_encode(w, WT_TLS_HANDSHAKE_SERVER_HELLO, body_len) !=
      WT_OK) {
    return WT_ERR_LIMIT;
  }
  server_hello_prefix_body(hello, w);
  if (wt_tls_extensions_encode(w, &hello->extensions) != WT_OK) {
    return WT_ERR_LIMIT;
  }
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

/* ------------------------------------------------------------------- builders
 *
 * The builders do not go through a parsed structure, because that structure holds
 * views and the extension writers take values. They run the same prefix-body function
 * the encoders use and an extension writer of their own, so a message that was built
 * and a message that was parsed have the same layout by construction rather than by
 * having been written out twice.
 */

wt_status_t wt_tls_client_hello_build(const wt_tls_client_hello_params_t *params,
                                      uint8_t *out, size_t capacity,
                                      size_t *out_len) {
  wt_tls_client_hello_t fixed;
  wt_writer_t extensions;
  wt_writer_t measure;
  size_t body_len;
  size_t total;

  if (params == NULL || out == NULL || out_len == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *out_len = 0U;
  if (params->random == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (params->session_id == NULL && params->session_id_len != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (params->session_id_len > WT_TLS_SESSION_ID_MAX) return WT_ERR_LIMIT;
  if (params->cipher_suites == NULL || params->cipher_suite_count == 0U ||
      params->cipher_suite_count > WT_TLS_CIPHER_SUITES_MAX) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (params->supported_groups == NULL && params->supported_group_count != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (params->signature_schemes == NULL && params->signature_scheme_count != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (params->key_shares == NULL && params->key_share_count != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (params->alpn == NULL && params->alpn_count != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (params->transport_parameters == NULL &&
      params->transport_parameters_len != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }

  memset(&fixed, 0, sizeof(fixed));
  fixed.legacy_version = WT_TLS_LEGACY_VERSION;
  memcpy(fixed.random, params->random, WT_TLS_RANDOM_LEN);
  fixed.session_id = params->session_id;
  fixed.session_id_len = params->session_id_len;
  memcpy(fixed.cipher_suites, params->cipher_suites,
         params->cipher_suite_count * sizeof(fixed.cipher_suites[0]));
  fixed.cipher_suite_count = params->cipher_suite_count;
  fixed.compression_methods[0] = 0U;
  fixed.compression_method_count = 1U;

  /* Pass one: how long the extension block is, and then how long the whole body is.
   * The extension writer measures its own contents, so this call counts the block
   * including its length field. */
  extensions = wt_writer_measure();
  {
    wt_status_t status = client_hello_extensions(params, &extensions);
    if (status != WT_OK) return status;
  }
  measure = wt_writer_measure();
  client_hello_prefix_body(&fixed, &measure);
  if (!wt_writer_ok(&measure)) return WT_ERR_LIMIT;
  body_len = wt_writer_offset(&measure) + wt_writer_offset(&extensions);
  if (body_len > WT_TLS_HANDSHAKE_MAX_BODY) return WT_ERR_LIMIT;
  total = body_len + WT_TLS_HANDSHAKE_HEADER_LEN;
  if (capacity < total) return WT_ERR_LIMIT;

  /* Pass two: the same functions, into the message. */
  {
    wt_writer_t w = wt_writer_init(out, capacity);
    if (wt_tls_handshake_header_encode(&w, WT_TLS_HANDSHAKE_CLIENT_HELLO,
                                       body_len) != WT_OK) {
      return WT_ERR_LIMIT;
    }
    client_hello_prefix_body(&fixed, &w);
    if (client_hello_extensions(params, &w) != WT_OK) return WT_ERR_LIMIT;
    if (wt_writer_offset(&w) != total) {
      /* The measuring pass and the writing pass disagree, which is a bug in this file
       * rather than in the caller's input. A message whose length field is wrong is
       * worse than a refusal, so the buffer is cleared and nothing is returned. */
      memset(out, 0, total);
      return WT_ERR_STATE;
    }
  }
  *out_len = total;
  return WT_OK;
}

wt_status_t wt_tls_server_hello_build(const wt_tls_server_hello_params_t *params,
                                      uint8_t *out, size_t capacity,
                                      size_t *out_len) {
  wt_tls_server_hello_t fixed;
  wt_writer_t extensions;
  wt_writer_t measure;
  size_t body_len;
  size_t total;

  if (params == NULL || out == NULL || out_len == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *out_len = 0U;
  if (params->random == NULL || params->key_share == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (params->session_id == NULL && params->session_id_len != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (params->session_id_len > WT_TLS_SESSION_ID_MAX) return WT_ERR_LIMIT;

  memset(&fixed, 0, sizeof(fixed));
  fixed.legacy_version = WT_TLS_LEGACY_VERSION;
  memcpy(fixed.random, params->random, WT_TLS_RANDOM_LEN);
  fixed.session_id = params->session_id;
  fixed.session_id_len = params->session_id_len;
  fixed.cipher_suite = params->cipher_suite;
  fixed.compression_method = 0U;

  extensions = wt_writer_measure();
  {
    wt_status_t status = server_hello_extensions(params, &extensions);
    if (status != WT_OK) return status;
  }
  measure = wt_writer_measure();
  server_hello_prefix_body(&fixed, &measure);
  if (!wt_writer_ok(&measure)) return WT_ERR_LIMIT;
  body_len = wt_writer_offset(&measure) + wt_writer_offset(&extensions);
  if (body_len > WT_TLS_HANDSHAKE_MAX_BODY) return WT_ERR_LIMIT;
  total = body_len + WT_TLS_HANDSHAKE_HEADER_LEN;
  if (capacity < total) return WT_ERR_LIMIT;

  {
    wt_writer_t w = wt_writer_init(out, capacity);
    if (wt_tls_handshake_header_encode(&w, WT_TLS_HANDSHAKE_SERVER_HELLO,
                                       body_len) != WT_OK) {
      return WT_ERR_LIMIT;
    }
    server_hello_prefix_body(&fixed, &w);
    if (server_hello_extensions(params, &w) != WT_OK) return WT_ERR_LIMIT;
    if (wt_writer_offset(&w) != total) {
      memset(out, 0, total);
      return WT_ERR_STATE;
    }
  }
  *out_len = total;
  return WT_OK;
}

/* -------------------------------------------------------------------- parsing */

/* The two fields every Hello starts with, checked for the one legal legacy version. */
static wt_status_t hello_prefix(wt_cursor_t *cursor, uint16_t *version,
                                const uint8_t **random) {
  *version = wt_cursor_u16(cursor);
  *random = wt_cursor_bytes(cursor, WT_TLS_RANDOM_LEN);
  if (*random == NULL) return WT_ERR_PROTOCOL;
  if (*version != WT_TLS_LEGACY_VERSION) return WT_ERR_PROTOCOL;
  return WT_OK;
}

/* A length-delimited region of the message as its own cursor.
 *
 * WT_ERR_PROTOCOL when the region does not fit, NOT WT_ERR_TRUNCATED: every caller of
 * this function has already checked that the framing outside the region is complete --
 * a handshake message whose declared length is the buffer's, an extension block whose
 * declared length is the cursor's -- so a region that overruns is a length that lies
 * rather than bytes that have not arrived yet. The distinction is the one that decides
 * whether a receiver gives up on the connection or waits for more. */
static wt_status_t sub_cursor(wt_cursor_t *cursor, size_t len, wt_cursor_t *out) {
  const uint8_t *bytes = wt_cursor_bytes(cursor, len);
  if (bytes == NULL) return WT_ERR_PROTOCOL;
  *out = wt_cursor_init(bytes, len);
  return WT_OK;
}

/* The body of one message, with the framing checked: header, declared type, declared
 * length, and bytes. */
static wt_status_t message_body(const uint8_t *message, size_t len, uint8_t type,
                                wt_cursor_t *body) {
  wt_cursor_t cursor;
  wt_tls_handshake_header_t header;
  const uint8_t *bytes;
  wt_status_t status;

  if (message == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (len < WT_TLS_HANDSHAKE_HEADER_LEN) return WT_ERR_TRUNCATED;
  cursor = wt_cursor_init(message, len);
  status = wt_tls_handshake_header_parse(&cursor, &header);
  if (status != WT_OK) return status;
  if (header.type != type) return WT_ERR_PROTOCOL;
  bytes = wt_cursor_bytes(&cursor, header.length);
  if (bytes == NULL) return WT_ERR_TRUNCATED;
  *body = wt_cursor_init(bytes, header.length);
  return WT_OK;
}

wt_status_t wt_tls_client_hello_parse(const uint8_t *message, size_t len,
                                      wt_tls_client_hello_t *out) {
  wt_cursor_t body;
  uint16_t version;
  const uint8_t *random;
  uint8_t session_id_len;
  uint16_t cipher_suites_len;
  uint8_t compression_len;
  size_t i;
  wt_status_t status;

  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));
  status = message_body(message, len, WT_TLS_HANDSHAKE_CLIENT_HELLO, &body);
  if (status != WT_OK) return status;
  status = hello_prefix(&body, &version, &random);
  if (status != WT_OK) return status;
  out->legacy_version = version;
  memcpy(out->random, random, WT_TLS_RANDOM_LEN);

  session_id_len = wt_cursor_u8(&body);
  if (wt_cursor_failed(&body)) return WT_ERR_PROTOCOL;
  if (session_id_len > WT_TLS_SESSION_ID_MAX) return WT_ERR_PROTOCOL;
  out->session_id = wt_cursor_bytes(&body, (size_t)session_id_len);
  if (out->session_id == NULL) return WT_ERR_PROTOCOL;
  out->session_id_len = (size_t)session_id_len;

  cipher_suites_len = wt_cursor_u16(&body);
  if (wt_cursor_failed(&body)) return WT_ERR_PROTOCOL;
  /* RFC 8446 section 4.1.2: the vector is 2..2^16-2 bytes, which is at least one suite
   * and an even number of bytes. */
  if (cipher_suites_len == 0U || (cipher_suites_len % 2U) != 0U) {
    return WT_ERR_PROTOCOL;
  }
  out->cipher_suite_count = (size_t)cipher_suites_len / 2U;
  if (out->cipher_suite_count > WT_TLS_CIPHER_SUITES_MAX) return WT_ERR_LIMIT;
  for (i = 0U; i < out->cipher_suite_count; i++) {
    out->cipher_suites[i] = wt_cursor_u16(&body);
  }
  if (wt_cursor_failed(&body)) return WT_ERR_PROTOCOL;

  compression_len = wt_cursor_u8(&body);
  if (wt_cursor_failed(&body)) return WT_ERR_PROTOCOL;
  /* RFC 8446 section 4.1.2: "for every TLS 1.3 ClientHello, this vector MUST contain
   * exactly one byte, set to zero". A client that says otherwise is speaking a version
   * this implementation does not implement, so it is refused rather than negotiated
   * with. */
  if (compression_len != 1U) return WT_ERR_PROTOCOL;
  /* ONE byte, written by index rather than by a loop over the peer's count. The loop was describing generality
   * this message does not have -- a TLS 1.3 ClientHello's vector is one byte set to zero -- and GCC's Release
   * build is what insisted on the difference: it could not prove `i` stayed inside `compression_methods[4]`
   * and said so with -Wstringop-overflow, which clang's optimiser had not. An explicit bound check did not
   * satisfy it either, because the index came from a struct member; writing the one byte does, and it is what
   * the RFC says. */
  out->compression_method_count = 1U;
  out->compression_methods[0] = wt_cursor_u8(&body);
  if (wt_cursor_failed(&body)) return WT_ERR_PROTOCOL;
  if (out->compression_methods[0] != 0U) return WT_ERR_PROTOCOL;

  status = wt_tls_extensions_parse(&body, &out->extensions);
  if (status != WT_OK) return status;
  /* The body ends where the extensions do: trailing bytes are a peer disagreeing with
   * the RFC's field list, and accepting them would mean guessing which reading was
   * meant. */
  return wt_cursor_at_end(&body) ? WT_OK : WT_ERR_PROTOCOL;
}

wt_status_t wt_tls_server_hello_parse(const uint8_t *message, size_t len,
                                      wt_tls_server_hello_t *out) {
  wt_cursor_t body;
  uint16_t version;
  const uint8_t *random;
  uint8_t session_id_len;
  wt_status_t status;

  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));
  status = message_body(message, len, WT_TLS_HANDSHAKE_SERVER_HELLO, &body);
  if (status != WT_OK) return status;
  status = hello_prefix(&body, &version, &random);
  if (status != WT_OK) return status;
  out->legacy_version = version;
  memcpy(out->random, random, WT_TLS_RANDOM_LEN);

  session_id_len = wt_cursor_u8(&body);
  if (wt_cursor_failed(&body)) return WT_ERR_PROTOCOL;
  if (session_id_len > WT_TLS_SESSION_ID_MAX) return WT_ERR_PROTOCOL;
  out->session_id = wt_cursor_bytes(&body, (size_t)session_id_len);
  if (out->session_id == NULL) return WT_ERR_PROTOCOL;
  out->session_id_len = (size_t)session_id_len;

  out->cipher_suite = wt_cursor_u16(&body);
  out->compression_method = wt_cursor_u8(&body);
  if (wt_cursor_failed(&body)) return WT_ERR_PROTOCOL;
  if (out->compression_method != 0U) return WT_ERR_PROTOCOL;

  status = wt_tls_extensions_parse(&body, &out->extensions);
  if (status != WT_OK) return status;
  return wt_cursor_at_end(&body) ? WT_OK : WT_ERR_PROTOCOL;
}

/* ==================================== Certificate, CertificateVerify, Finished
 *
 * The three messages whose bodies are a certificate chain, a signature and a verify
 * value. Each is written by one body function, measured and then written, exactly like
 * the Hellos above. Nothing here looks inside a certificate or a signature: framing is
 * this layer's question, trust is the layer above.
 */

static void certificate_body(const wt_tls_certificate_t *certificate,
                             wt_writer_t *w) {
  size_t i;
  size_t list_len = 0U;

  for (i = 0U; i < certificate->count; i++) {
    list_len += 3U + certificate->entries[i].der_len + 2U +
                certificate->entries[i].extensions_len;
  }
  wt_writer_u8(w, (uint8_t)certificate->request_context_len);
  wt_writer_bytes(w, certificate->request_context,
                  certificate->request_context_len);
  wt_writer_u24(w, (uint32_t)list_len);
  for (i = 0U; i < certificate->count; i++) {
    const wt_tls_certificate_entry_t *entry = &certificate->entries[i];
    wt_writer_u24(w, (uint32_t)entry->der_len);
    wt_writer_bytes(w, entry->der, entry->der_len);
    wt_writer_u16(w, (uint16_t)entry->extensions_len);
    wt_writer_bytes(w, entry->extensions, entry->extensions_len);
  }
}

static void certificate_verify_body(
    const wt_tls_certificate_verify_t *certificate_verify, wt_writer_t *w) {
  wt_writer_u16(w, certificate_verify->scheme);
  wt_writer_u16(w, (uint16_t)certificate_verify->signature_len);
  wt_writer_bytes(w, certificate_verify->signature,
                  certificate_verify->signature_len);
}

/* The same measure-then-write shape every encoder here uses. `body` writes the body and
 * returns the status the values themselves deserve; the framing checks only need to
 * happen once, before the measuring pass. */
static wt_status_t frame_and_write(const void *structure, void (*body)(const void *,
                                                                     wt_writer_t *),
                                   uint8_t type, wt_writer_t *w) {
  wt_writer_t measure;
  size_t body_len;

  if (structure == NULL || w == NULL) return WT_ERR_INVALID_ARGUMENT;
  measure = wt_writer_measure();
  body(structure, &measure);
  if (!wt_writer_ok(&measure)) return WT_ERR_LIMIT;
  body_len = wt_writer_offset(&measure);
  if (body_len > WT_TLS_HANDSHAKE_MAX_BODY) return WT_ERR_LIMIT;
  if (wt_tls_handshake_header_encode(w, type, body_len) != WT_OK) {
    return WT_ERR_LIMIT;
  }
  body(structure, w);
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

static void certificate_body_thunk(const void *structure, wt_writer_t *w) {
  certificate_body((const wt_tls_certificate_t *)structure, w);
}

static void certificate_verify_body_thunk(const void *structure, wt_writer_t *w) {
  certificate_verify_body((const wt_tls_certificate_verify_t *)structure, w);
}

/* The framing this layer refuses before anything is written: a count or a length that
 * cannot be expressed in the field that will hold it. */
static wt_status_t certificate_check(const wt_tls_certificate_t *certificate) {
  size_t i;
  size_t list_len = 0U;

  if (certificate->request_context == NULL &&
      certificate->request_context_len != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* RFC 8446 section 4.4.2: the context is 0..255 bytes, one length octet. */
  if (certificate->request_context_len > 255U) return WT_ERR_LIMIT;
  if (certificate->count > WT_TLS_CERTIFICATE_MAX_ENTRIES) return WT_ERR_LIMIT;
  for (i = 0U; i < certificate->count; i++) {
    const wt_tls_certificate_entry_t *entry = &certificate->entries[i];
    if (entry->der == NULL || entry->der_len == 0U) {
      /* An entry with no certificate is not an empty certificate: RFC 8446 section 4.4.2
       * frames each one as a three-octet length, and zero is a malformed entry rather
       * than a chain with a hole in it. */
      return WT_ERR_INVALID_ARGUMENT;
    }
    if (entry->der_len > WT_TLS_HANDSHAKE_MAX_BODY) return WT_ERR_LIMIT;
    if (entry->extensions == NULL && entry->extensions_len != 0U) {
      return WT_ERR_INVALID_ARGUMENT;
    }
    if (entry->extensions_len > 0xFFFFU) return WT_ERR_LIMIT;
    list_len += 3U + entry->der_len + 2U + entry->extensions_len;
  }
  if (list_len > WT_TLS_HANDSHAKE_MAX_BODY) return WT_ERR_LIMIT;
  return WT_OK;
}

wt_status_t wt_tls_certificate_encode(const wt_tls_certificate_t *certificate,
                                      wt_writer_t *w) {
  wt_status_t status;
  if (certificate == NULL) return WT_ERR_INVALID_ARGUMENT;
  status = certificate_check(certificate);
  if (status != WT_OK) return status;
  return frame_and_write(certificate, certificate_body_thunk,
                         WT_TLS_HANDSHAKE_CERTIFICATE, w);
}

wt_status_t wt_tls_certificate_build(const wt_tls_certificate_params_t *params,
                                     uint8_t *out, size_t capacity,
                                     size_t *out_len) {
  wt_tls_certificate_t certificate;

  if (params == NULL || out == NULL || out_len == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *out_len = 0U;
  if (params->entries == NULL && params->count != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (params->count > WT_TLS_CERTIFICATE_MAX_ENTRIES) return WT_ERR_LIMIT;

  memset(&certificate, 0, sizeof(certificate));
  certificate.request_context = params->request_context;
  certificate.request_context_len = params->request_context_len;
  certificate.count = params->count;
  /* An empty certificate list is legal, so the copy is guarded: that is what keeps
   * a NULL with a zero count away from `memcpy`'s nonnull parameters. */
  if (params->count != 0U) {
    memcpy(certificate.entries, params->entries,
           params->count * sizeof(certificate.entries[0]));
  }

  {
    wt_writer_t w = wt_writer_init(out, capacity);
    wt_status_t status = wt_tls_certificate_encode(&certificate, &w);
    if (status != WT_OK) {
      memset(out, 0, capacity < 64U ? capacity : 64U);
      return status;
    }
    *out_len = wt_writer_offset(&w);
  }
  return WT_OK;
}

wt_status_t wt_tls_certificate_verify_encode(
    const wt_tls_certificate_verify_t *certificate_verify, wt_writer_t *w) {
  if (certificate_verify == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (certificate_verify->signature == NULL &&
      certificate_verify->signature_len != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  /* RFC 8446 section 4.4.3: the signature is 0..2^16-1 bytes. Zero is legal for an
   * algorithm with an empty signature, and the trust layer is what refuses a scheme it
   * does not implement. */
  if (certificate_verify->signature_len > 0xFFFFU) return WT_ERR_LIMIT;
  return frame_and_write(certificate_verify, certificate_verify_body_thunk,
                         WT_TLS_HANDSHAKE_CERTIFICATE_VERIFY, w);
}

wt_status_t wt_tls_certificate_verify_build(uint16_t scheme,
                                            const uint8_t *signature,
                                            size_t signature_len, uint8_t *out,
                                            size_t capacity, size_t *out_len) {
  wt_tls_certificate_verify_t certificate_verify;
  wt_writer_t w;
  wt_status_t status;

  if (out == NULL || out_len == NULL) return WT_ERR_INVALID_ARGUMENT;
  *out_len = 0U;
  if (signature == NULL && signature_len != 0U) return WT_ERR_INVALID_ARGUMENT;
  certificate_verify.scheme = scheme;
  certificate_verify.signature = signature;
  certificate_verify.signature_len = signature_len;
  w = wt_writer_init(out, capacity);
  status = wt_tls_certificate_verify_encode(&certificate_verify, &w);
  if (status != WT_OK) return status;
  *out_len = wt_writer_offset(&w);
  return WT_OK;
}

wt_status_t wt_tls_finished_build(const uint8_t verify_data[WT_TLS13_FINISHED_LEN],
                                  uint8_t *out, size_t capacity, size_t *out_len) {
  wt_writer_t w;

  if (verify_data == NULL || out == NULL || out_len == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *out_len = 0U;
  if (capacity < WT_TLS13_FINISHED_LEN + WT_TLS_HANDSHAKE_HEADER_LEN) {
    return WT_ERR_LIMIT;
  }
  w = wt_writer_init(out, capacity);
  if (wt_tls_handshake_header_encode(&w, WT_TLS_HANDSHAKE_FINISHED,
                                     WT_TLS13_FINISHED_LEN) != WT_OK) {
    return WT_ERR_LIMIT;
  }
  wt_writer_bytes(&w, verify_data, WT_TLS13_FINISHED_LEN);
  if (!wt_writer_ok(&w)) return WT_ERR_LIMIT;
  *out_len = wt_writer_offset(&w);
  return WT_OK;
}

/* ------------------------------------------------------------------ parsing */

wt_status_t wt_tls_certificate_parse(const uint8_t *message, size_t len,
                                     wt_tls_certificate_t *out) {
  wt_cursor_t body;
  uint8_t context_len;
  uint32_t list_len;
  wt_cursor_t entries;
  wt_status_t status;

  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));
  status = message_body(message, len, WT_TLS_HANDSHAKE_CERTIFICATE, &body);
  if (status != WT_OK) return status;
  context_len = wt_cursor_u8(&body);
  if (wt_cursor_failed(&body)) return WT_ERR_PROTOCOL;
  out->request_context = wt_cursor_bytes(&body, (size_t)context_len);
  if (out->request_context == NULL) return WT_ERR_PROTOCOL;
  out->request_context_len = (size_t)context_len;
  list_len = wt_cursor_u24(&body);
  if (wt_cursor_failed(&body)) return WT_ERR_PROTOCOL;
  {
    wt_status_t region = sub_cursor(&body, (size_t)list_len, &entries);
    if (region != WT_OK) return region;
  }

  while (!wt_cursor_at_end(&entries)) {
    uint32_t der_len;
    uint16_t extensions_len;
    wt_tls_certificate_entry_t *entry;

    if (out->count == WT_TLS_CERTIFICATE_MAX_ENTRIES) return WT_ERR_LIMIT;
    entry = &out->entries[out->count];
    der_len = wt_cursor_u24(&entries);
    if (wt_cursor_failed(&entries)) return WT_ERR_PROTOCOL;
    if (der_len == 0U) return WT_ERR_PROTOCOL;
    entry->der = wt_cursor_bytes(&entries, (size_t)der_len);
    if (entry->der == NULL) return WT_ERR_PROTOCOL;
    entry->der_len = (size_t)der_len;
    extensions_len = wt_cursor_u16(&entries);
    if (wt_cursor_failed(&entries)) return WT_ERR_PROTOCOL;
    entry->extensions = wt_cursor_bytes(&entries, (size_t)extensions_len);
    if (entry->extensions == NULL) return WT_ERR_PROTOCOL;
    entry->extensions_len = (size_t)extensions_len;
    out->count++;
  }
  /* The body ends where the entry list does. */
  return wt_cursor_at_end(&body) ? WT_OK : WT_ERR_PROTOCOL;
}

wt_status_t wt_tls_certificate_verify_parse(
    const uint8_t *message, size_t len, wt_tls_certificate_verify_t *out) {
  wt_cursor_t body;
  uint16_t signature_len;
  wt_status_t status;

  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));
  status = message_body(message, len, WT_TLS_HANDSHAKE_CERTIFICATE_VERIFY, &body);
  if (status != WT_OK) return status;
  out->scheme = wt_cursor_u16(&body);
  signature_len = wt_cursor_u16(&body);
  if (wt_cursor_failed(&body)) return WT_ERR_PROTOCOL;
  out->signature = wt_cursor_bytes(&body, (size_t)signature_len);
  if (out->signature == NULL) return WT_ERR_PROTOCOL;
  out->signature_len = (size_t)signature_len;
  return wt_cursor_at_end(&body) ? WT_OK : WT_ERR_PROTOCOL;
}

wt_status_t wt_tls_finished_parse(const uint8_t *message, size_t len,
                                  uint8_t out[WT_TLS13_FINISHED_LEN]) {
  wt_cursor_t body;
  const uint8_t *verify_data;
  wt_status_t status;

  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  status = message_body(message, len, WT_TLS_HANDSHAKE_FINISHED, &body);
  if (status != WT_OK) return status;
  /* RFC 8446 section 4.4.4: the body is exactly Hash.length bytes. A longer one is not a
   * Finished with extra data, it is a different message. */
  if (body.len != WT_TLS13_FINISHED_LEN) return WT_ERR_PROTOCOL;
  verify_data = wt_cursor_bytes(&body, WT_TLS13_FINISHED_LEN);
  if (verify_data == NULL) return WT_ERR_PROTOCOL;
  memcpy(out, verify_data, WT_TLS13_FINISHED_LEN);
  return wt_cursor_at_end(&body) ? WT_OK : WT_ERR_PROTOCOL;
}

wt_status_t wt_tls_encrypted_extensions_encode(
    const wt_tls_extension_list_t *extensions, wt_writer_t *w) {
  wt_writer_t measure;
  size_t body_len;

  if (extensions == NULL || w == NULL) return WT_ERR_INVALID_ARGUMENT;
  measure = wt_writer_measure();
  (void)wt_tls_extensions_encode(&measure, extensions);
  if (!wt_writer_ok(&measure)) return WT_ERR_LIMIT;
  body_len = wt_writer_offset(&measure);
  if (body_len > WT_TLS_HANDSHAKE_MAX_BODY) return WT_ERR_LIMIT;
  if (wt_tls_handshake_header_encode(w, WT_TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS,
                                     body_len) != WT_OK) {
    return WT_ERR_LIMIT;
  }
  if (wt_tls_extensions_encode(w, extensions) != WT_OK) return WT_ERR_LIMIT;
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

wt_status_t wt_tls_encrypted_extensions_build(
    const wt_tls_extension_list_t *extensions, uint8_t *out, size_t capacity,
    size_t *out_len) {
  wt_writer_t w;
  wt_status_t status;

  if (extensions == NULL || out == NULL || out_len == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *out_len = 0U;
  w = wt_writer_init(out, capacity);
  status = wt_tls_encrypted_extensions_encode(extensions, &w);
  if (status != WT_OK) return status;
  *out_len = wt_writer_offset(&w);
  return WT_OK;
}

wt_status_t wt_tls_encrypted_extensions_parse(const uint8_t *message, size_t len,
                                              wt_tls_extension_list_t *out) {
  wt_cursor_t body;
  wt_status_t status;

  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));
  status = message_body(message, len, WT_TLS_HANDSHAKE_ENCRYPTED_EXTENSIONS, &body);
  if (status != WT_OK) return status;
  status = wt_tls_extensions_parse(&body, out);
  if (status != WT_OK) return status;
  return wt_cursor_at_end(&body) ? WT_OK : WT_ERR_PROTOCOL;
}
