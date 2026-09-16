/* An HTTP/3 request or response header section (RFC 9114 section 4.1), which is a
 * QPACK-encoded field section that has passed section 4.3's rules.
 *
 * This is the join between the two layers built so far: QPACK produces resolved
 * fields, the header validator decides whether they are a legal message, and what a
 * caller usually wants is the handful of values that say which message it is -- the
 * method, the scheme, the path, the authority or the status. Recovering those here
 * keeps every later layer (the CONNECT request that begins a WebTransport session,
 * for one) from walking the fields again.
 *
 * A section that needs insertions this endpoint has not received is BLOCKED, not
 * malformed (RFC 9204 section 2.1.2), and is reported as WT_ERR_AGAIN so the caller
 * can wait for the encoder stream. Everything else that fails is H3_MESSAGE_ERROR,
 * except a QPACK failure, which keeps QPACK's own code: section 8 of RFC 9204 makes
 * those HTTP/3 application errors, so they travel in the same place.
 */

#ifndef WEBTRANSPORT_HTTP3_MESSAGE_H
#define WEBTRANSPORT_HTTP3_MESSAGE_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/http3/headers.h"
#include "webtransport/http3/qpack.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef struct wt_http3_message {
  wt_http3_header_message_t type;
  /* The pseudo-header values, as views into the QPACK tables or the caller's
   * scratch. Absent ones are NULL with length zero. */
  const uint8_t *method;
  size_t method_length;
  const uint8_t *scheme;
  size_t scheme_length;
  const uint8_t *path;
  size_t path_length;
  const uint8_t *authority;
  size_t authority_length;
  /* The extended CONNECT's :protocol value (RFC 9220 section 3), absent otherwise. */
  const uint8_t *protocol;
  size_t protocol_length;
  /* The status, when the message is a response and it parsed as section 4.3 requires:
   * three digits, 100 to 599. */
  uint64_t status;
  int has_status;
  /* What the validator saw, left for a caller that wants to know which pseudo-headers
   * were present without comparing the views above against NULL. */
  wt_http3_header_validation_t validation;
} wt_http3_message_t;

/* Decode one HEADERS frame's payload.
 *
 * `table` and `max_entries` are the dynamic table and the window this endpoint
 * advertised; `known_insert_count` is how many insertions it has received. `scratch` is
 * where Huffman-coded strings are decoded, exactly as in the QPACK layer. */
wt_status_t wt_http3_message_decode(wt_http3_message_t *message, wt_http3_header_message_t type,
                                    const uint8_t *payload, size_t length,
                                    const wt_qpack_dynamic_table_t *table, uint64_t max_entries,
                                    uint64_t known_insert_count, uint8_t *scratch,
                                    size_t scratch_capacity, wt_http3_error_t *out_error);

/* Encode one field section: the prefix, then one literal line per field this message
 * carries, for a caller that is building a request or a response rather than reading one.
 *
 * `max_entries` is the PEER's advertised dynamic-table capacity in units of 32, exactly as
 * the decoder's is this endpoint's: the prefix's Required Insert Count and Base are encoded
 * against the peer's number, not against anything this endpoint chose. A message that
 * references no dynamic entry encodes a Required Insert Count of zero, which every peer can
 * read whatever table it advertised.
 *
 * The lines are LITERAL -- the name and the value are spelled out rather than indexed --
 * which is always valid and never needs the dynamic table, and which is why this encoder can
 * be used before a dynamic table exists on either side. It is larger on the wire than a
 * static-table reference would be; that is a compression decision with a correct simple
 * answer here and an upgrade path, rather than a protocol one. Strings are written as they
 * are given, never Huffman-coded, so the bytes are readable and the size is predictable.
 *
 * The message's fields are written in the order a request must present them: the
 * pseudo-headers first. A message that names neither a method (a request) nor a status (a
 * response) is refused rather than written as a section nothing can decode. */
wt_status_t wt_http3_message_encode(wt_writer_t *w, const wt_http3_message_t *message,
                                    uint64_t max_entries, wt_http3_error_t *out_error);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_HTTP3_MESSAGE_H */
