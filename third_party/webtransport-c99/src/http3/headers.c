/* HTTP/3 message header section rules (RFC 9114 sections 4.1 to 4.4). */

#include "webtransport/http3/headers.h"

#include <string.h>

void wt_http3_header_validation_init(wt_http3_header_validation_t *validation,
                                     wt_http3_header_message_t message) {
  if (validation == NULL) return;
  validation->message = message;
  validation->saw_regular = 0;
  validation->pseudo_seen = 0U;
  validation->is_connect = 0;
}

static int equals(const uint8_t *bytes, size_t length, const char *text) {
  size_t text_length = strlen(text);
  return length == text_length && memcmp(bytes, text, text_length) == 0;
}

/* The connection-specific fields of section 4.2, and `te`, whose only legal value is
 * `trailers`. A field a proxy would act on has no meaning over HTTP/3, where the
 * connection is already multiplexed. */
/* Whether a field name is a `token` (RFC 9110 section 5.6.2) with the uppercase letters HTTP/3 forbids left
 * out. A colon, a space, a control byte or an uppercase letter all fail: a name is a token, and section 10.3
 * makes a name that is not one a malformed message. */
static int field_name_is_valid(const uint8_t *name, size_t length) {
  size_t i;

  if (length == 0U) return 0;
  for (i = 0U; i < length; i++) {
    uint8_t c = name[i];
    if ((c >= (uint8_t)'a' && c <= (uint8_t)'z') || (c >= (uint8_t)'0' && c <= (uint8_t)'9')) continue;
    switch (c) {
      case '!':
      case '#':
      case '$':
      case '%':
      case '&':
      case '\'':
      case '*':
      case '+':
      case '-':
      case '.':
      case '^':
      case '_':
      case '`':
      case '|':
      case '~':
        continue;
      default:
        return 0;
    }
  }
  return 1;
}

/* Whether a field value is `field-content` (RFC 9110 section 5.5): visible bytes, spaces and horizontal tabs,
 * with the C0 controls other than HTAB and the DEL byte refused. Bytes above 0x7f are `obs-text` and are legal.
 * CR and LF are the two that matter most -- they are how a value becomes a second field. */
static int field_value_is_valid(const uint8_t *value, size_t length) {
  size_t i;

  for (i = 0U; i < length; i++) {
    uint8_t c = value[i];
    if (c == (uint8_t)0x09U || c == (uint8_t)0x20U) continue;
    if (c < (uint8_t)0x21U || c == (uint8_t)0x7fU) return 0;
  }
  return 1;
}

static int is_connection_specific(const uint8_t *name, size_t name_length) {
  return equals(name, name_length, "connection") || equals(name, name_length, "transfer-encoding") ||
         equals(name, name_length, "keep-alive") || equals(name, name_length, "upgrade") ||
         equals(name, name_length, "proxy-connection");
}

wt_status_t wt_http3_header_validate(wt_http3_header_validation_t *validation, const uint8_t *name,
                                     size_t name_length, const uint8_t *value, size_t value_length,
                                     wt_http3_error_t *out_error) {
  uint32_t bit = 0U;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (validation == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (name == NULL && name_length != 0U) return WT_ERR_INVALID_ARGUMENT;

  if (name_length != 0U && name[0] == (uint8_t)':') {
    /* A pseudo-header. After a regular field there is no place for one, and the same
     * one twice is a message that says two different things (section 4.3). */
    if (validation->saw_regular) {
      if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
      return WT_ERR_PROTOCOL;
    }
    if (validation->message == WT_HTTP3_HEADER_REQUEST) {
      if (equals(name, name_length, ":method")) {
        bit = WT_HTTP3_PSEUDO_METHOD;
      } else if (equals(name, name_length, ":scheme")) {
        bit = WT_HTTP3_PSEUDO_SCHEME;
      } else if (equals(name, name_length, ":path")) {
        bit = WT_HTTP3_PSEUDO_PATH;
      } else if (equals(name, name_length, ":authority")) {
        bit = WT_HTTP3_PSEUDO_AUTHORITY;
      } else if (equals(name, name_length, ":protocol")) {
        /* RFC 9220 section 3: an extended CONNECT names the protocol it is for here.
         * Without this the WebTransport request would be an unknown pseudo-header and
         * therefore H3_MESSAGE_ERROR, which is the wrong answer to a legal request. */
        bit = WT_HTTP3_PSEUDO_PROTOCOL;
      }
      if (bit == WT_HTTP3_PSEUDO_METHOD && equals(value, value_length, "CONNECT")) {
        /* Section 4.4: CONNECT is the one method without :scheme and :path, and it
         * requires :authority instead. */
        validation->is_connect = 1;
      }
    } else if (equals(name, name_length, ":status")) {
      bit = WT_HTTP3_PSEUDO_STATUS;
    }
    if (bit == 0U) {
      /* A pseudo-header this message type does not define: a response with :path, or
       * anything at all that HTTP/3 has not named. */
      if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
      return WT_ERR_PROTOCOL;
    }
    if ((validation->pseudo_seen & bit) != 0U) {
      if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
      return WT_ERR_PROTOCOL;
    }
    /* A pseudo-header's value is a field value: RFC 9114 section 4.3.1 defines the pseudo-header fields in
     * terms of the field grammar, and section 10.3 makes "a character not permitted in a field value" a
     * malformed message. This branch used to return without any grammar check, so `:path` or `:authority`
     * could carry a CR, LF or NUL that a later writer would turn into a second field; the regular-field branch
     * below has always checked. The NAME cannot be malformed here because only names this message type defines
     * reach this point. */
    if (!field_value_is_valid(value, value_length)) {
      if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
      return WT_ERR_PROTOCOL;
    }
    validation->pseudo_seen |= bit;
    return WT_OK;
  }

  /* A regular field. Section 4.2: field names are lowercase, and section 10.3 makes a name or a value that is
   * not a valid field at all a MALFORMED message: "A request or response that contains a character not permitted
   * in a field value MUST be treated as malformed. ... Likewise, a field name that contains uppercase characters
   * or characters that are not permitted in a field name MUST be treated as malformed."
   *
   * The first version checked uppercase and nothing else, so a name with a space or a colon in it and a value
   * carrying CR, LF or NUL all passed -- which an audit demonstrated with a value of "a\r\nX: y" and a name of
   * "bad name". That is the classic intermediary-encapsulation shape: a value this layer accepts and a later
   * writer turns into a new field. Two functions rather than one loop because the two grammars are different
   * (`field-name` is a token, `field-content` allows spaces and visible bytes). */
  if (!field_name_is_valid(name, name_length) || !field_value_is_valid(value, value_length)) {
    if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
    return WT_ERR_PROTOCOL;
  }
  if (is_connection_specific(name, name_length)) {
    if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
    return WT_ERR_PROTOCOL;
  }
  if (equals(name, name_length, "te") && !equals(value, value_length, "trailers")) {
    /* Section 4.2: `te` is allowed, but only for trailers: anything else would be a
     * hop-by-hop negotiation over a connection that is already multiplexed. */
    if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
    return WT_ERR_PROTOCOL;
  }
  validation->saw_regular = 1;
  return WT_OK;
}

wt_status_t wt_http3_header_finish(const wt_http3_header_validation_t *validation,
                                   wt_http3_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (validation == NULL) return WT_ERR_INVALID_ARGUMENT;

  if (validation->message == WT_HTTP3_HEADER_RESPONSE) {
    if ((validation->pseudo_seen & WT_HTTP3_PSEUDO_STATUS) == 0U) {
      if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
      return WT_ERR_PROTOCOL;
    }
    return WT_OK;
  }

  /* A request. Section 4.1: the method is required; :scheme and :path are required
   * unless the method is CONNECT, which requires :authority instead. */
  if ((validation->pseudo_seen & WT_HTTP3_PSEUDO_METHOD) == 0U) {
    if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
    return WT_ERR_PROTOCOL;
  }
  if (validation->is_connect) {
    if ((validation->pseudo_seen & WT_HTTP3_PSEUDO_AUTHORITY) == 0U) {
      if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
      return WT_ERR_PROTOCOL;
    }
    return WT_OK;
  }
  if ((validation->pseudo_seen & (WT_HTTP3_PSEUDO_SCHEME | WT_HTTP3_PSEUDO_PATH)) !=
      (WT_HTTP3_PSEUDO_SCHEME | WT_HTTP3_PSEUDO_PATH)) {
    if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
    return WT_ERR_PROTOCOL;
  }
  return WT_OK;
}
