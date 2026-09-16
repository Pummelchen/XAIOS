/* The WebTransport session request: an extended CONNECT (draft-ietf-webtrans-http3-16
 * section 3.1, over RFC 9220's extended CONNECT).
 *
 * A WebTransport session begins with a request that is a CONNECT carrying the
 * `:protocol` pseudo-header with the value `webtransport-h3` (section 3.2); the
 * pre-draft value `webtransport`, which section 2.1.2 gives to WebTransport over
 * HTTP/2, is also accepted, for the interoperability reason stated below. Four rules
 * decide what a decoded request is, and only the last is this layer's own:
 *
 *   - a CONNECT without `:protocol` is an ordinary CONNECT, which is not this layer's
 *     business at all;
 *   - a `:protocol` naming another protocol belongs to that protocol, and RFC 9220
 *     section 3 has the server answer it with a status rather than an error;
 *   - an extended CONNECT carries `:scheme`, `:authority` and `:path` -- RFC 9114
 *     section 4.1's CONNECT exception covers the plain CONNECT, so requiring the scheme
 *     and path is this layer's job;
 *   - and the draft has a server refuse a session it did not advertise support for.
 *
 * The outcome is a DECISION rather than an error: "not mine" and "mine, but refused"
 * are ordinary answers with status codes, and a malformed request is already the
 * message error the HTTP/3 layer raised.
 */

#ifndef WEBTRANSPORT_WEBTRANSPORT_SESSION_REQUEST_H
#define WEBTRANSPORT_WEBTRANSPORT_SESSION_REQUEST_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/http3/message.h"
#include "webtransport/http3/settings.h"
#include "webtransport/webtransport/protocol.h"
#include "webtransport/status.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The `:protocol` value that makes a CONNECT a WebTransport request, and the one this endpoint SENDS.
 * Draft-ietf-webtrans-http3-16 sections 3.2 and 9.1 name it `webtransport-h3`; the Swift reference's draft-16
 * constants use the same string (Swift/Sources/WebTransportHTTP3Core/HTTP3Constants.swift). */
#define WT_WEBTRANSPORT_PROTOCOL_TOKEN "webtransport-h3"

/* The PRE-DRAFT token draft-16 renamed away from: `webtransport` is the WebTransport-over-HTTP/2 token of
 * draft-16 section 2.1.2, a DIFFERENT string from the HTTP/3 token above. This server deliberately ACCEPTS it as
 * well as the draft-16 one, and that acceptance is not a courtesy: four of the five independent implementations
 * this tree interoperates with were written against the earlier drafts, and a server that refused the old token
 * would refuse every one of them -- the same split the Swift reference calls its interoperable mode. Both tokens
 * are accepted; only the draft-16 token is sent. */
#define WT_WEBTRANSPORT_PROTOCOL_TOKEN_LEGACY "webtransport"

/* Which of the two tokens THIS endpoint puts on its OWN CONNECT.
 *
 * The choice exists because the token cannot be negotiated, only sent. Draft-16 section 3.2 renamed the HTTP/3
 * token to `webtransport-h3`, but a peer written against an earlier draft knows only `webtransport`, and it
 * refuses the extended CONNECT with H3_MESSAGE_ERROR before it reads any SETTINGS -- so an endpoint that always
 * sends the draft-16 value reaches no pre-draft peer at all, and one that always sends the old value claims to
 * speak a version it does not. The default is the draft-16 token, which is what a conforming client must send
 * (section 3.2: the `:protocol` value is `webtransport-h3`) and what the Swift reference sends even in its
 * interoperable modes (Swift/Sources/WebTransportHTTP3Core/HTTP3Connection.swift, `upgradeToken`); the legacy
 * value is the explicit, per-peer accommodation for the implementations that predate the rename. Zero is the
 * draft-16 default, so a zeroed structure and `wt_http3_driver_init` both start out sending the current token. */
typedef enum wt_webtransport_upgrade_token {
  /* `webtransport-h3`, the DEFAULT. */
  WT_WEBTRANSPORT_UPGRADE_TOKEN_DRAFT16 = 0,
  /* `webtransport`, the pre-draft value of draft-16 section 2.1.2, for a peer that predates the rename. */
  WT_WEBTRANSPORT_UPGRADE_TOKEN_LEGACY = 1
} wt_webtransport_upgrade_token_t;

/* The string one selection puts on the wire. Never NULL: a value outside the enum is reported as the draft-16
 * token rather than as a NULL a caller would dereference, so the only two selections above are also the only two
 * strings this returns. */
const char *wt_webtransport_upgrade_token_value(wt_webtransport_upgrade_token_t token);

/* Where a CLIENT offers its sub-protocols (draft-16 section 3.3). `wt-protocol` -- the name in protocol.h -- is
 * the RESPONSE field that names the one the server selected (section 9.7); the pre-draft shape used `wt-protocol`
 * for both, which is why this constant exists next to the parser that only knows the value. */
#define WT_WEBTRANSPORT_AVAILABLE_PROTOCOLS_HEADER "wt-available-protocols"

/* The draft-16 setting a server advertises to say it can serve WebTransport at all. */
#define WT_HTTP3_SETTING_WT_ENABLED ((uint64_t)0x2c7cf000)

/* The enabling codepoints a peer implementing the "max sessions" era of the draft looks for
 * (`WEBTRANSPORT_MAX_SESSIONS`, and the pair it replaced in draft 06). Draft-16 section 7.1 is explicit that
 * every draft version has its own codepoint and that an endpoint supporting several versions sends one per
 * version, so these are how a session is negotiated with a peer that predates the rename -- and the session,
 * stream and datagram wire formats this tree uses are the ones those codepoints describe. Without them a peer
 * that gates WebTransport on the setting IT knows never treats the extended CONNECT as a session and answers
 * nothing, which is exactly what `quinn`/`web-transport` did (WT-145). */
#define WT_HTTP3_SETTING_WT_MAX_SESSIONS ((uint64_t)0xc671706a)
#define WT_HTTP3_SETTING_WT_ENABLE_DEPRECATED ((uint64_t)0x2b603742)
#define WT_HTTP3_SETTING_WT_MAX_SESSIONS_DEPRECATED ((uint64_t)0x2b603743)


/* The draft-16 settings that carry a session's INITIAL flow-control limits (section 5.1).
 * They are what turns the session's own flow control on: an endpoint that omits all three
 * is not doing it, and a session enabled by one of them starts the other two at zero. */
#define WT_HTTP3_SETTING_WT_INITIAL_MAX_DATA ((uint64_t)0x2b61)
#define WT_HTTP3_SETTING_WT_INITIAL_MAX_STREAMS_UNI ((uint64_t)0x2b64)
#define WT_HTTP3_SETTING_WT_INITIAL_MAX_STREAMS_BIDI ((uint64_t)0x2b65)

/* The status a refusal carries when the authority or path is not one this server
 * serves. */
#define WT_WEBTRANSPORT_REJECT_NOT_FOUND ((uint32_t)404)
/* And when the request is WebTransport but this server did not advertise it. */
#define WT_WEBTRANSPORT_REJECT_NOT_IMPLEMENTED ((uint32_t)501)
/* And when a sub-protocol was REQUIRED and the two lists do not meet (section 3.2). */
#define WT_WEBTRANSPORT_REJECT_PROTOCOL_REQUIRED ((uint32_t)400)

typedef enum wt_webtransport_request_outcome {
  /* A WebTransport request this server accepts. */
  WT_WEBTRANSPORT_REQUEST_ACCEPT = 0,
  /* Not a WebTransport request: an ordinary request, or an extended CONNECT for
   * another protocol. The caller answers it as it would any other request. */
  WT_WEBTRANSPORT_REQUEST_NOT_WEBTRANSPORT = 1,
  /* A WebTransport request this server refuses, with `status` as the answer. */
  WT_WEBTRANSPORT_REQUEST_REJECT = 2
} wt_webtransport_request_outcome_t;

/* What the server is willing to serve, and whether it said so. */
typedef struct wt_webtransport_request_policy {
  /* The authority and path this server serves, compared EXACTLY: a prefix match would
   * let one host's request be served as another's. */
  const char *authority;
  const char *path;
  /* False when the server did not advertise WT_ENABLED, which the draft makes a reason
   * to refuse a session rather than serve one the client could not have known about. */
  int wt_enabled;
} wt_webtransport_request_policy_t;

typedef struct wt_webtransport_session_request {
  wt_webtransport_request_outcome_t outcome;
  const uint8_t *authority;
  size_t authority_length;
  const uint8_t *path;
  size_t path_length;
  /* The answer to send when the outcome is a rejection. */
  uint32_t status;
  /* The sub-protocol selected from the request's list, as a view into the caller's bytes (section 3.2).
   * Absent -- NULL with length zero -- when nothing was offered, nothing matched, or none was required. */
  const uint8_t *selected_protocol;
  size_t selected_protocol_length;
} wt_webtransport_session_request_t;

/* The sub-protocol decision, which needs the request's `wt-protocol` field and therefore a parsed list
 * rather than the pseudo-headers `validate` sees (section 3.2).
 *
 * `offered` is what the request carried and `supported` is this server's configuration; both are lists of
 * tokens, and the answer is the FIRST token offered that is supported, so a client and a server compute the
 * same choice from the same two lists. A rejection the caller already decided is left alone: a request this
 * server will not serve is not negotiated with.
 *
 * When nothing can be selected and `require_selection` is set, the decision becomes a rejection with
 * WT_WEBTRANSPORT_REJECT_PROTOCOL_REQUIRED -- the draft's own "requirements not met" answer -- rather than a
 * session that quietly speaks no sub-protocol while the client believes one was chosen. */
wt_status_t wt_webtransport_session_request_negotiate(wt_webtransport_session_request_t *decision,
                                                      const wt_webtransport_protocol_list_t *offered,
                                                      const wt_webtransport_protocol_list_t *supported,
                                                      int require_selection);

/* The client's side of the same conversation: the response's `wt-protocol` value, which must name a token
 * THIS CLIENT offered. A value that names anything else is WT_ERR_PROTOCOL, because accepting it would leave
 * the two ends speaking different sub-protocols. */
wt_status_t wt_webtransport_session_response_selected_protocol(
    const uint8_t *value, size_t length, const wt_webtransport_protocol_list_t *offered,
    wt_webtransport_protocol_token_t *out);

/* Decide what a decoded request is. `message` must have come from
 * `wt_http3_message_decode` with WT_HTTP3_HEADER_REQUEST. */
wt_status_t wt_webtransport_session_request_validate(
    const wt_http3_message_t *message, const wt_webtransport_request_policy_t *policy,
    wt_webtransport_session_request_t *out, wt_http3_error_t *out_error);

/* What a WebTransport endpoint MUST advertise in its SETTINGS (section 3.1), in one place -- the same rule the
 * mandatory transport parameters follow in `wt_quic_transport_parameters_build`, and for the same reason: a
 * caller that had to remember each one eventually forgets one, and this call forgot
 * `SETTINGS_H3_DATAGRAM` (WT-145). A server sends `SETTINGS_ENABLE_CONNECT_PROTOCOL` too, because an extended
 * CONNECT is only legal once the peer has advertised RFC 9220 (section 3.1's list for servers). */
wt_status_t wt_webtransport_settings_apply(wt_http3_settings_t *settings, int is_server);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_WEBTRANSPORT_SESSION_REQUEST_H */
