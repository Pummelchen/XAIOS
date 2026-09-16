/* WebTransport sub-protocol negotiation (draft-ietf-webtrans-http3-16 section 3.2).
 *
 * A WebTransport session may carry a sub-protocol, and the two endpoints agree on one with the
 * `wt-protocol` header field: the request carries a LIST of the tokens the client offers, and the response
 * carries the single token the server selected. Both values are HTTP Structured Fields strings
 * (RFC 8941), which is what makes them unambiguous rather than comma-split by hand.
 *
 * The rules this file exists to keep in one place, because two endpoints that disagree about them disagree
 * about application semantics:
 *
 *   - a token is a non-empty run of visible bytes that excludes `"`, `,` and `\`. The exclusion is not
 *     cosmetic: those are the three bytes the Structured Fields grammar gives meaning to, so a token
 *     containing one could not be encoded without escaping and would decide a different protocol on the
 *     other side;
 *   - a token may not be repeated in one list, because a peer that offers it twice is confused about what
 *     it is asking for;
 *   - the selected token is the FIRST the client offered that the server supports, so both ends compute the
 *     same answer from the same two lists rather than trusting the order to be incidental;
 *   - a list longer than this endpoint will hold is refused as a bound (WT_ERR_LIMIT) rather than truncated,
 *     and a value that is not a Structured Fields string is malformed (WT_ERR_PROTOCOL).
 *
 * Decoded tokens are VIEWS into the value the caller supplied, as everywhere else in this library: nothing
 * is copied, and nothing is allocated. That is possible without an unescaping step because a valid token can
 * contain neither `"` nor `\`, so an escape sequence in a field value cannot decode to a valid token and is
 * refused rather than decoded into a buffer this library would have to own.
 */

#ifndef WEBTRANSPORT_WEBTRANSPORT_PROTOCOL_H
#define WEBTRANSPORT_WEBTRANSPORT_PROTOCOL_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/status.h"
#include "webtransport/writer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The header both directions of the negotiation travel in, spelled once. */
#define WT_WEBTRANSPORT_PROTOCOL_HEADER "wt-protocol"

/* How many tokens one field may carry, and how long one may be. Both are this endpoint's bounds rather than
 * the peer's: a peer that offers more is refused as excessive load rather than grown for. */
#define WT_WEBTRANSPORT_PROTOCOL_MAX 16U
#define WT_WEBTRANSPORT_PROTOCOL_TOKEN_MAX 64U

/* One token, as a view into bytes the caller owns. */
typedef struct wt_webtransport_protocol_token {
  const uint8_t *bytes;
  size_t length;
} wt_webtransport_protocol_token_t;

/* A parsed list of tokens. The array is fixed at WT_WEBTRANSPORT_PROTOCOL_MAX, so a peer cannot make this
 * endpoint allocate. */
typedef struct wt_webtransport_protocol_list {
  wt_webtransport_protocol_token_t tokens[WT_WEBTRANSPORT_PROTOCOL_MAX];
  size_t count;
} wt_webtransport_protocol_list_t;

/* Whether one token may be a sub-protocol name: non-empty, at most the bound, and no `"`, `,` or `\`. A
 * caller validating its own configuration uses this; a decoded list is validated by the decoder. */
int wt_webtransport_protocol_token_valid(const uint8_t *token, size_t length);

/* Every token valid, none repeated, and the count within the bound. WT_ERR_PROTOCOL for a token or a repeat,
 * WT_ERR_LIMIT for a count over the bound. */
wt_status_t wt_webtransport_protocol_validate(const wt_webtransport_protocol_list_t *list);

/* One Structured Fields string ITEM -- `"chat.v1"` -- as the response carries it. */
wt_status_t wt_webtransport_protocol_encode_item(wt_writer_t *w,
                                                 const wt_webtransport_protocol_token_t *token);
wt_status_t wt_webtransport_protocol_decode_item(const uint8_t *value, size_t length,
                                                 wt_webtransport_protocol_token_t *out);

/* A list of them, separated by `, ` as RFC 8941 writes a list, which is what the request carries. */
wt_status_t wt_webtransport_protocol_encode_list(wt_writer_t *w, const wt_webtransport_protocol_list_t *list);
wt_status_t wt_webtransport_protocol_decode_list(const uint8_t *value, size_t length,
                                                 wt_webtransport_protocol_list_t *out);

/* A list built from this endpoint's own configuration, which is a list of NUL-terminated strings rather than
 * views: this is the bridge between a server's configuration and the wire. An invalid token is
 * WT_ERR_PROTOCOL and a count past the table is WT_ERR_LIMIT, so a misconfigured endpoint finds out here
 * rather than by sending a field its peer refuses. */
wt_status_t wt_webtransport_protocol_list_from_strings(wt_webtransport_protocol_list_t *out,
                                                       const char *const *protocols, size_t count);

/* The whole field LINE -- the name `wt-protocol` and the value as a Structured Fields string -- for a caller
 * that is building a response and has to append it to a field section it already wrote. The value is the
 * quoted form, so this is not the same call as `encode_item`. */
wt_status_t wt_webtransport_protocol_write_field(wt_writer_t *w,
                                                 const wt_webtransport_protocol_token_t *token);

/* The token both endpoints must compute the same answer for: the first of `requested` that `supported`
 * carries. Returns 1 and writes `out` when one was selected, 0 when the two lists do not overlap -- in which
 * case `out` is cleared, so a caller cannot read a stale token as a selection. */
int wt_webtransport_protocol_select(const wt_webtransport_protocol_list_t *requested,
                                    const wt_webtransport_protocol_list_t *supported,
                                    wt_webtransport_protocol_token_t *out);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_WEBTRANSPORT_PROTOCOL_H */
