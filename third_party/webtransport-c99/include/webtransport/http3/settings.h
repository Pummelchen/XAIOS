/* HTTP/3 SETTINGS (RFC 9114 section 7.2.4).
 *
 * A SETTINGS payload is a sequence of identifier and value pairs, both varints,
 * and it is the first frame of each control stream. Three rules shape this
 * module, and each is a rule about a peer rather than about this endpoint:
 *
 *   - **A reserved identifier is an error.** The identifiers HTTP/2 defined that
 *     HTTP/3 has no use for (`0x02` to `0x05`) MUST NOT be sent, and receiving
 *     one is H3_SETTINGS_ERROR (section 7.2.4.1).
 *   - **A duplicate identifier is an error here.** The section makes it a MAY
 *     ("MAY treat ... as a connection error of type H3_SETTINGS_ERROR"); this
 *     implementation takes the option, because a peer that names the same
 *     setting twice is a peer disagreeing with itself and there is no reading of
 *     the frame that is not a guess.
 *   - **Everything else is ignored**, not stored and not refused: unknown
 *     identifiers are how HTTP/3 grows, and the `0x1f * N + 0x21` identifiers
 *     exist purely to exercise that rule (a sender SHOULD include one, and every
 *     receiver MUST ignore it). Identifiers are still remembered so that a
 *     duplicate of an UNKNOWN setting is caught, which is the reason the table
 *     holds identifiers rather than only the values this build understands.
 *
 * The table is fixed. A peer that sends more settings than this endpoint will
 * hold gets H3_EXCESSIVE_LOAD, which is the code HTTP/3 defines for a peer
 * asking for more resources than it was given; a heap-allocated map would make
 * the bound the peer's choice instead.
 */

#ifndef WEBTRANSPORT_HTTP3_SETTINGS_H
#define WEBTRANSPORT_HTTP3_SETTINGS_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/http3/frame.h"
#include "webtransport/status.h"
#include "webtransport/writer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The setting identifiers this build has a use for (RFC 9114 section 7.2.4.1,
 * RFC 9204 section 5, RFC 9220 section 3 and RFC 9297 section 2.1). The others
 * are ignored on receipt and cannot be set through this API; the ones that
 * arrive later, such as the WebTransport draft's, are added when the layer that
 * uses them lands. */
#define WT_HTTP3_SETTING_QPACK_MAX_TABLE_CAPACITY ((uint64_t)0x01)
#define WT_HTTP3_SETTING_MAX_FIELD_SECTION_SIZE ((uint64_t)0x06)
#define WT_HTTP3_SETTING_QPACK_BLOCKED_STREAMS ((uint64_t)0x07)
#define WT_HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL ((uint64_t)0x08)
#define WT_HTTP3_SETTING_H3_DATAGRAM ((uint64_t)0x33)

/* The first identifier of the reserved exercise range, `0x1f * N + 0x21` with
 * N = 0. A sender SHOULD include one so that its peer's "ignore what you do not
 * know" rule is exercised at least once per connection. */
/* The RESERVED identifier from the arithmetic above: a peer must never send it, and a receiver that gets one
 * MUST treat it as H3_SETTINGS_ERROR (section 7.2.4.1). It exists in this header so that rule can be TESTED
 * rather than described. */
#define WT_HTTP3_SETTING_EXERCISER ((uint64_t)0x21)

/* An identifier this version does not know and that is NOT reserved -- the shape a future setting has, and the
 * one a round trip must use. The difference between this and the reserved value above is the whole of section
 * 7.2.4.1, and a fixture that used the reserved one as its example of a legal unknown setting hid a bug. */
#define WT_HTTP3_SETTING_UNKNOWN ((uint64_t)0x22)

/* How many settings this endpoint will hold. Real peers send a handful; a peer
 * that sends more is refused rather than grown for. */
#define WT_HTTP3_SETTINGS_MAX_ENTRIES 16U

typedef struct wt_http3_settings {
  uint64_t identifiers[WT_HTTP3_SETTINGS_MAX_ENTRIES];
  uint64_t values[WT_HTTP3_SETTINGS_MAX_ENTRIES];
  size_t count;
} wt_http3_settings_t;

/* An empty set: no setting has a value, which is what the RFC calls the initial
 * value of every setting. */
void wt_http3_settings_init(wt_http3_settings_t *settings);

/* True for the identifiers HTTP/2 defined and HTTP/3 reserved: 0x02 to 0x05.
 * Sending one is forbidden and receiving one is H3_SETTINGS_ERROR. */
int wt_http3_setting_is_reserved_http2(uint64_t identifier);

/* True for the exercise identifiers `0x1f * N + 0x21`: meaningless on purpose,
 * and to be ignored (their arithmetic is the same as the reserved frame types of
 * section 7.2.8, but the consequence is the opposite). */
int wt_http3_setting_is_exerciser(uint64_t identifier);

/* Add a setting. Refuses an identifier or value the varint cannot carry, a
 * reserved HTTP/2 identifier, an ENABLE_CONNECT_PROTOCOL above one (RFC 9220
 * section 3), an identifier already present -- so the encoder cannot produce a
 * frame this module would refuse to read -- and a full table (WT_ERR_LIMIT). */
wt_status_t wt_http3_settings_set(wt_http3_settings_t *settings, uint64_t identifier, uint64_t value);

/* The value of a setting, or 0 with `*out_present` clear. */
uint64_t wt_http3_settings_get(const wt_http3_settings_t *settings, uint64_t identifier,
                               int *out_present);

/* Decode a SETTINGS frame's payload. `out` is filled from a fresh empty set, so
 * a caller cannot inherit values from a previous parse. Sets `out_error` to
 * H3_SETTINGS_ERROR for a malformed or reserved setting, and to
 * H3_EXCESSIVE_LOAD when the table is full. */
wt_status_t wt_http3_settings_parse(const uint8_t *payload, size_t length,
                                    wt_http3_settings_t *out, wt_http3_error_t *out_error);

/* Encode a SETTINGS frame's payload in ascending identifier order, so the same
 * set always produces the same bytes. */
wt_status_t wt_http3_settings_encode_payload(wt_writer_t *w, const wt_http3_settings_t *settings);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_HTTP3_SETTINGS_H */
