/* The WebTransport session request (draft-ietf-webtrans-http3-16 section 3.1). */

#include "webtransport/webtransport/session_request.h"

#include <string.h>

static int token_is(const uint8_t *bytes, size_t length, const char *text) {
  size_t text_length = strlen(text);
  return length == text_length && memcmp(bytes, text, text_length) == 0;
}

const char *wt_webtransport_upgrade_token_value(wt_webtransport_upgrade_token_t token) {
  /* The two selections are the only two strings, and the default is the draft-16 token: a value that is not the
   * legacy one -- including an out-of-range int a caller cast -- sends the current token rather than a NULL. */
  return token == WT_WEBTRANSPORT_UPGRADE_TOKEN_LEGACY ? WT_WEBTRANSPORT_PROTOCOL_TOKEN_LEGACY
                                                       : WT_WEBTRANSPORT_PROTOCOL_TOKEN;
}

/* Whether a request's `:authority` names the host this server serves.
 *
 * RFC 9114 section 4.3.1 makes `:authority` the authority of the target URI, and an authority carries the port
 * whenever it is not the scheme's default -- `localhost:54070`, `[::1]:8443`. The policy names a HOST, because
 * that is what a server can know about itself; comparing the whole authority refused every real client that named
 * the port it was actually talking to, which is every real client (WT-153). A NULL or empty policy means this
 * server serves any authority, which is the honest default for a listener: the transport has already proved the
 * client reached this port.
 *
 * The port is found from the END, and only outside a bracketed IPv6 literal, because `::1` is full of colons that
 * are not port separators. */
static int authority_matches(const uint8_t *bytes, size_t length, const char *expected) {
  size_t host_length = length;
  size_t i;
  size_t bracket = 0U;
  int has_bracket = 0;

  if (expected == NULL || expected[0] == '\0') return 1;
  for (i = length; i > 0U; i--) {
    if (bytes[i - 1U] == ']') {
      bracket = i - 1U;
      has_bracket = 1;
      break;
    }
  }
  for (i = length; i > 0U; i--) {
    if (bytes[i - 1U] == ':') {
      /* A colon after the closing bracket is the port; inside one it is part of the address. */
      if (!has_bracket || (i - 1U) > bracket) host_length = i - 1U;
      break;
    }
  }
  return token_is(bytes, host_length, expected);
}

wt_status_t wt_webtransport_settings_apply(wt_http3_settings_t *settings, int is_server) {
  wt_status_t status;

  if (settings == NULL) return WT_ERR_INVALID_ARGUMENT;

  /* Section 3.1's list for BOTH roles, and the first is the one this function exists because of: an endpoint
   * that omits SETTINGS_H3_DATAGRAM is not a WebTransport endpoint in draft-16's terms, and a peer that checks
   * -- `web-transport`'s `supports_webtransport()` requires it plus a WebTransport setting -- will not accept
   * the session at all (WT-145). */
  status = wt_http3_settings_set(settings, WT_HTTP3_SETTING_H3_DATAGRAM, 1U);
  if (status != WT_OK) return status;

  /* The draft-specific codepoint that identifies the version this tree implements. Section 7.1 makes it
   * mandatory for a client of a draft version, and a server sends it too. */
  status = wt_http3_settings_set(settings, WT_HTTP3_SETTING_WT_ENABLED, 1U);
  if (status != WT_OK) return status;

  /* The same negotiation for a peer that predates the rename: one codepoint per version, which is what section
   * 7.1 asks of an endpoint that supports several. The value is the number of sessions this endpoint will
   * accept on the connection, and one is what this tree's tools serve. */
  status = wt_http3_settings_set(settings, WT_HTTP3_SETTING_WT_MAX_SESSIONS, 1U);
  if (status != WT_OK) return status;
  status = wt_http3_settings_set(settings, WT_HTTP3_SETTING_WT_ENABLE_DEPRECATED, 1U);
  if (status != WT_OK) return status;
  if (is_server) {
    /* Only the server sets this half of the pair it replaced: the client sends ENABLE, the server answers with a
     * limit. */
    status = wt_http3_settings_set(settings, WT_HTTP3_SETTING_WT_MAX_SESSIONS_DEPRECATED, 1U);
    if (status != WT_OK) return status;
    /* RFC 9220 section 3: a client may only send `:protocol` once the server has advertised that it handles
     * extended CONNECT, so a server that serves WebTransport at all has to say so (section 3.1's server list). */
    status = wt_http3_settings_set(settings, WT_HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL, 1U);
    if (status != WT_OK) return status;
  }
  return WT_OK;
}

wt_status_t wt_webtransport_session_request_validate(
    const wt_http3_message_t *message, const wt_webtransport_request_policy_t *policy,
    wt_webtransport_session_request_t *out, wt_http3_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (message == NULL || policy == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;

  memset(out, 0, sizeof(*out));
  out->status = WT_WEBTRANSPORT_REJECT_NOT_FOUND;

  /* Not a request, or not a CONNECT: not this layer's business. An ordinary GET is a
   * perfectly good request that simply is not a session. */
  if (message->type != WT_HTTP3_HEADER_REQUEST || message->method_length != 7U ||
      memcmp(message->method, "CONNECT", 7U) != 0) {
    out->outcome = WT_WEBTRANSPORT_REQUEST_NOT_WEBTRANSPORT;
    return WT_OK;
  }

  /* A CONNECT with no :protocol is RFC 9114's plain CONNECT -- a tunnel, not a
   * session -- and a :protocol naming something else belongs to whoever defined it. */
  /* BOTH tokens name a WebTransport request. Draft-16 section 3.2 defines `webtransport-h3` and the drafts before
   * it used `webtransport`; refusing either one makes this server unreachable from a conforming peer of the other
   * era -- the Swift implementation and the browsers send the draft-16 token, and four of this tree's five
   * interop peers send the older one. Accepting both is what "interoperable" has to mean at a server. */
  if (message->protocol_length == 0U ||
      !(token_is(message->protocol, message->protocol_length, WT_WEBTRANSPORT_PROTOCOL_TOKEN) ||
        token_is(message->protocol, message->protocol_length, WT_WEBTRANSPORT_PROTOCOL_TOKEN_LEGACY))) {
    out->outcome = WT_WEBTRANSPORT_REQUEST_NOT_WEBTRANSPORT;
    return WT_OK;
  }

  /* It IS a WebTransport request, so from here the draft applies. An extended CONNECT
   * carries :scheme, :authority and :path; the message decoder required only the
   * authority, because that is all a plain CONNECT requires. */
  if (message->scheme_length == 0U || message->authority_length == 0U ||
      message->path_length == 0U) {
    out->outcome = WT_WEBTRANSPORT_REQUEST_REJECT;
    out->status = WT_WEBTRANSPORT_REJECT_NOT_FOUND;
    return WT_OK;
  }

  /* A server that did not advertise WT_ENABLED must not accept a session: the client
   * could not have known this endpoint serves WebTransport, and accepting anyway would
   * make the setting meaningless. */
  if (!policy->wt_enabled) {
    out->outcome = WT_WEBTRANSPORT_REQUEST_REJECT;
    out->status = WT_WEBTRANSPORT_REJECT_NOT_IMPLEMENTED;
    return WT_OK;
  }

  if (!authority_matches(message->authority, message->authority_length, policy->authority) ||
      (policy->path != NULL && policy->path[0] != '\0' &&
       !token_is(message->path, message->path_length, policy->path))) {
    out->outcome = WT_WEBTRANSPORT_REQUEST_REJECT;
    out->status = WT_WEBTRANSPORT_REJECT_NOT_FOUND;
    return WT_OK;
  }

  out->outcome = WT_WEBTRANSPORT_REQUEST_ACCEPT;
  out->authority = message->authority;
  out->authority_length = message->authority_length;
  out->path = message->path;
  out->path_length = message->path_length;
  return WT_OK;
}

wt_status_t wt_webtransport_session_request_negotiate(wt_webtransport_session_request_t *decision,
                                                      const wt_webtransport_protocol_list_t *offered,
                                                      const wt_webtransport_protocol_list_t *supported,
                                                      int require_selection) {
  wt_webtransport_protocol_token_t selected;
  wt_status_t status;

  if (decision == NULL || offered == NULL || supported == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* Both lists come from the wire or from a configuration, so both are validated here: a caller that decoded
   * a field section and forgot to check it must not be able to negotiate with nonsense. */
  status = wt_webtransport_protocol_validate(offered);
  if (status != WT_OK) return status;
  status = wt_webtransport_protocol_validate(supported);
  if (status != WT_OK) return status;

  /* A request this server has already refused is not negotiated with: its answer is the refusal, and changing
   * it here would give the caller two different answers to send. */
  if (decision->outcome != WT_WEBTRANSPORT_REQUEST_ACCEPT) return WT_OK;

  if (wt_webtransport_protocol_select(offered, supported, &selected) != 0) {
    decision->selected_protocol = selected.bytes;
    decision->selected_protocol_length = selected.length;
    return WT_OK;
  }

  if (require_selection) {
    decision->outcome = WT_WEBTRANSPORT_REQUEST_REJECT;
    decision->status = WT_WEBTRANSPORT_REJECT_PROTOCOL_REQUIRED;
    decision->selected_protocol = NULL;
    decision->selected_protocol_length = 0U;
  }
  return WT_OK;
}

wt_status_t wt_webtransport_session_response_selected_protocol(
    const uint8_t *value, size_t length, const wt_webtransport_protocol_list_t *offered,
    wt_webtransport_protocol_token_t *out) {
  wt_webtransport_protocol_token_t selected;
  size_t index;
  wt_status_t status;

  if (offered == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  status = wt_webtransport_protocol_decode_item(value, length, &selected);
  if (status != WT_OK) return status;
  for (index = 0U; index < offered->count; index++) {
    if (offered->tokens[index].length == selected.length &&
        memcmp(offered->tokens[index].bytes, selected.bytes, selected.length) == 0) {
      *out = selected;
      return WT_OK;
    }
  }
  /* The server named a sub-protocol this client never offered. Accepting it would leave the two ends speaking
   * different protocols, which is the failure the negotiation exists to prevent. */
  out->bytes = NULL;
  out->length = 0U;
  return WT_ERR_PROTOCOL;
}
