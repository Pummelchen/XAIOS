/* ClientHello construction (RFC 8446 section 4.1.2).
 *
 * A writer with a bound on every length, and the two-pass measure-then-encode
 * discipline that keeps the declared body length honest. Split out of
 * `wt_tls_handshake.c`, which keeps the framing, the transcript hash, the
 * ServerHello parser and the Finished MAC; the version constants it reads come
 * from `wt_tls_handshake_internal.h`, and the public prototypes
 * `wt_tls_client_hello_size` and `wt_tls_encode_client_hello` are unchanged and
 * remain in `wt_tls_handshake.h`.
 */

#include "wt_tls_handshake.h"

#include "wt_tls_handshake_internal.h"

#include <string.h>

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
