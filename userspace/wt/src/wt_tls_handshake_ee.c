/* EncryptedExtensions parsing and the ClientHello-offered check.
 *
 * RFC 8446 section 4.3.1 and RFC 9001 section 8.2, plus RFC 8446 section 4.2's
 * rule that a server may only answer an extension the client offered. The
 * cursor this walks is shared with the rest of the handshake and defined in
 * `wt_tls_handshake.c`; see `wt_tls_handshake_internal.h`.
 *
 * This was split out of `wt_tls_handshake.c`, which keeps the framing, the
 * transcript hash, the ServerHello parser and the Finished MAC. The public
 * prototypes are unchanged and remain in `wt_tls_handshake.h`.
 */

#include "wt_tls_handshake.h"

#include "wt_tls_handshake_internal.h"

#include <string.h>

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
    case WT_TLS_EXT_ALPN: {
      /* RFC 7301 section 3.1: "The 'extension_data' field of the
         ('application_layer_protocol_negotiation(16)') extension is structured
         the same as described above for the client 'extension_data', except
         that the 'ProtocolNameList' MUST contain exactly one 'ProtocolName'."
         So the server's answer is a LIST of one, not a bare name:
         two bytes of list length, then the name's own one-byte length, then
         the name.
         
         This parser first read it as a bare `protocol_name<1..255>` -- one byte
         of length then the name -- which is the flattening that the structure
         looks like it wants and is not what the extension carries. It would
         have refused every conformant server's answer and accepted a
         non-conformant one, and it survived because no RFC trace carries ALPN:
         RFC 8448's EncryptedExtensions has none. What found it was
         regenerating the QUIC flight fixture from an independent
         implementation, which encoded the list form and disagreed.
         
         Two names is not a preference order to pick from -- it is a server
         that has not decided, and a client that took the first would be
         agreeing to something the server did not choose. An empty name is
         refused too: RFC 7301 says empty strings MUST NOT be included. */
      size_t list_len;
      size_t name_len;
      if (len < 4U) return -1;
      list_len = ((size_t)data[0] << 8) | (size_t)data[1];
      if (list_len != len - 2U) return -1;
      name_len = data[2];
      if (name_len == 0U) return -1;
      /* Exactly one name, so the list is the name's length byte plus the name
         and nothing else -- and there is no second entry to be confused
         about. */
      if (name_len + 1U != list_len) return -1;
      out->alpn = data + 3U;
      out->alpn_len = name_len;
      out->has_alpn = 1;
      return 0;
    }

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
  wt_tls_reader_t r;

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

  wt_tls_reader_init(&r, body + 2U, extensions_len);
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
    ext_type = wt_tls_reader_u16(&r);
    ext_len = wt_tls_reader_u16(&r);
    if (r.failed) {
      ee_reject(out, WT_TLS_EE_MALFORMED, ext_type);
      return -1;
    }
    ext_data = wt_tls_reader_take(&r, (size_t)ext_len);
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
