/* HTTP/3 message header sections (RFC 9114 sections 4.1 to 4.4).
 *
 * A field section is QPACK's; what makes it a REQUEST or a RESPONSE is HTTP/3's, and
 * the rules are about the fields themselves rather than the framing:
 *
 *   - pseudo-header fields (the ones starting with ':') come first, and a regular
 *     field before one is H3_MESSAGE_ERROR (section 4.3);
 *   - each pseudo-header appears at most once, and only the ones the message type
 *     defines -- :method, :scheme, :path, :authority and (RFC 9220 section 3) :protocol
 *     for a request, :status for a response (sections 4.1 and 4.3);
 *   - a request carries :method, :scheme and :path, except CONNECT, which carries
 *     only :method and :authority (section 4.4);
 *   - field names are lowercase (section 4.2), a name that is not is H3_MESSAGE_ERROR;
 *   - the connection-specific fields are forbidden (section 4.2), and `te` is allowed
 *     only with the value `trailers`.
 *
 * The validator consumes one resolved field at a time, because that is what the QPACK
 * decoder produces and because the rules are about order. `finish` then checks what was
 * absent, which cannot be known before the last field.
 */

#ifndef WEBTRANSPORT_HTTP3_HEADERS_H
#define WEBTRANSPORT_HTTP3_HEADERS_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/http3/frame.h"
#include "webtransport/http3/role.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Which message the section belongs to. A request stream carries a request from the
 * client and, on the same stream, a response from the server, so the caller says which
 * half it is reading. */
typedef enum wt_http3_header_message {
  WT_HTTP3_HEADER_REQUEST = 0,
  WT_HTTP3_HEADER_RESPONSE = 1
} wt_http3_header_message_t;

/* The pseudo-headers a request may carry, as bits in `pseudo_seen`. */
#define WT_HTTP3_PSEUDO_METHOD ((uint32_t)1U << 0)
#define WT_HTTP3_PSEUDO_SCHEME ((uint32_t)1U << 1)
#define WT_HTTP3_PSEUDO_PATH ((uint32_t)1U << 2)
#define WT_HTTP3_PSEUDO_AUTHORITY ((uint32_t)1U << 3)
#define WT_HTTP3_PSEUDO_STATUS ((uint32_t)1U << 4)
/* RFC 9220 section 3: the pseudo-header that makes a CONNECT an EXTENDED one. It is a
 * request pseudo-header, and a response carrying it is a message error. */
#define WT_HTTP3_PSEUDO_PROTOCOL ((uint32_t)1U << 5)

typedef struct wt_http3_header_validation {
  wt_http3_header_message_t message;
  /* A regular field has been seen, so no pseudo-header may follow it. */
  int saw_regular;
  /* Which pseudo-headers have appeared, by the bits above. */
  uint32_t pseudo_seen;
  /* The request method was CONNECT, which changes what the rest must be. */
  int is_connect;
} wt_http3_header_validation_t;

void wt_http3_header_validation_init(wt_http3_header_validation_t *validation,
                                     wt_http3_header_message_t message);

/* Check one field. Any rule broken is H3_MESSAGE_ERROR, which section 4.1.2 makes the
 * code for a message that cannot be understood. */
wt_status_t wt_http3_header_validate(wt_http3_header_validation_t *validation, const uint8_t *name,
                                     size_t name_length, const uint8_t *value, size_t value_length,
                                     wt_http3_error_t *out_error);

/* Check what the section did not carry. A request without :method, :scheme or :path
 * (or, for CONNECT, without :authority) is H3_MESSAGE_ERROR; a response without
 * :status is too. */
wt_status_t wt_http3_header_finish(const wt_http3_header_validation_t *validation,
                                   wt_http3_error_t *out_error);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_HTTP3_HEADERS_H */
