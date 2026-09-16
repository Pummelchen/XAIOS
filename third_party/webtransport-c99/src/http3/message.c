/* HTTP/3 request and response header sections (RFC 9114 section 4.1). */

#include "webtransport/http3/message.h"

#include <string.h>

/* A pseudo-header's value, remembered as a view into whatever holds it. */
static void remember(const wt_qpack_resolved_field_t *field, const uint8_t **out, size_t *out_length) {
  *out = field->value;
  *out_length = field->value_length;
}

/* Section 4.3.2: a status is three digits from 100 to 599. Anything else is a message
 * error rather than a status this layer declines to look at. */
static int parse_status(const uint8_t *value, size_t length, uint64_t *out_status) {
  uint64_t status = 0U;
  size_t i;

  if (length != 3U) return 0;
  for (i = 0U; i < 3U; i++) {
    if (value[i] < (uint8_t)'0' || value[i] > (uint8_t)'9') return 0;
    status = status * 10U + (uint64_t)(value[i] - (uint8_t)'0');
  }
  if (status < 100U || status > 599U) return 0;
  *out_status = status;
  return 1;
}

/* The two error enums do not share a zero value: QPACK's is 0 and HTTP/3's is 0x0100.
 * Passing one through as the other would leave a caller with "no error" that is not the
 * no-error of the type it holds, so every QPACK result is translated here. The codes
 * themselves are HTTP/3 application errors (RFC 9204 section 8), so only the zero needs
 * mapping. */
static void map_qpack_error(wt_qpack_error_t from, wt_http3_error_t *out_error) {
  if (out_error == NULL) return;
  *out_error = from == WT_QPACK_ERROR_NONE ? WT_HTTP3_NO_ERROR : (wt_http3_error_t)from;
}

static int name_is(const wt_qpack_resolved_field_t *field, const char *text) {
  size_t text_length = strlen(text);
  return field->name_length == text_length && memcmp(field->name, text, text_length) == 0;
}

wt_status_t wt_http3_message_decode(wt_http3_message_t *message, wt_http3_header_message_t type,
                                    const uint8_t *payload, size_t length,
                                    const wt_qpack_dynamic_table_t *table, uint64_t max_entries,
                                    uint64_t known_insert_count, uint8_t *scratch,
                                    size_t scratch_capacity, wt_http3_error_t *out_error) {
  wt_qpack_field_section_decoder_t decoder;
  wt_qpack_resolved_field_t field;
  wt_qpack_error_t qpack_error = WT_QPACK_ERROR_NONE;
  wt_status_t status;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (message == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(message, 0, sizeof(*message));
  message->type = type;
  wt_http3_header_validation_init(&message->validation, type);

  status = wt_qpack_field_section_begin(&decoder, table, max_entries, payload, length,
                                        known_insert_count, &qpack_error);
  if (status != WT_OK) {
    map_qpack_error(qpack_error, out_error);
    return status;
  }

  for (;;) {
    status = wt_qpack_field_section_decoder_next(&decoder, scratch, scratch_capacity, &field,
                                                 &qpack_error);
    if (status == WT_ERR_CLOSED) break;
    if (status == WT_ERR_TRUNCATED) return status;
    if (status != WT_OK) {
      map_qpack_error(qpack_error, out_error);
      return status;
    }

    status = wt_http3_header_validate(&message->validation, field.name, field.name_length,
                                      field.value, field.value_length, out_error);
    if (status != WT_OK) return status;

    /* Keep the values the rest of the stack needs. A field with a name this layer does
     * not name is ordinary: the validator has already refused the ones that are not
     * allowed at all. */
    if (name_is(&field, ":method")) {
      remember(&field, &message->method, &message->method_length);
    } else if (name_is(&field, ":scheme")) {
      remember(&field, &message->scheme, &message->scheme_length);
    } else if (name_is(&field, ":path")) {
      remember(&field, &message->path, &message->path_length);
    } else if (name_is(&field, ":authority")) {
      remember(&field, &message->authority, &message->authority_length);
    } else if (name_is(&field, ":protocol")) {
      remember(&field, &message->protocol, &message->protocol_length);
    } else if (name_is(&field, ":status")) {
      if (!parse_status(field.value, field.value_length, &message->status)) {
        if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
        return WT_ERR_PROTOCOL;
      }
      message->has_status = 1;
    }
  }

  status = wt_http3_header_finish(&message->validation, out_error);
  if (status != WT_OK) return status;

  /* Section 4.3: the values that have to be there are not allowed to be empty. The
   * validator checked presence; this checks the content, which is what a caller would
   * otherwise have to remember to do. */
  if (type == WT_HTTP3_HEADER_REQUEST) {
    if (message->method_length == 0U || message->scheme_length == 0U) {
      if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
      return WT_ERR_PROTOCOL;
    }
    /* CONNECT carries no :path; every other method must have a non-empty one. */
    if (!(message->method_length == 7U && memcmp(message->method, "CONNECT", 7U) == 0) &&
        message->path_length == 0U) {
      if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
      return WT_ERR_PROTOCOL;
    }
  }
  return WT_OK;
}

/* ---------------------------------------------- encoding a field section */

/* The most fields one message can carry here: the five pseudo-headers and the status. */
#define WT_HTTP3_MESSAGE_MAX_FIELDS 6U

static void set_line(wt_qpack_field_line_t *line, const char *name, const uint8_t *value,
                     size_t value_length) {
  line->kind = WT_QPACK_FIELD_LITERAL_LITERAL_NAME;
  line->never_indexed = 0;
  line->index = 0U;
  line->name_huffman = 0;
  line->name = (const uint8_t *)name;
  line->name_length = strlen(name);
  line->value = value;
  line->value_length = value_length;
  line->value_huffman = 0;
  line->bytes_consumed = 0U;
}

static size_t add_pseudo(wt_qpack_field_line_t *lines, size_t count, const char *name,
                         const uint8_t *value, size_t value_length) {
  if (value == NULL) return count;
  set_line(&lines[count], name, value, value_length);
  return count + 1U;
}

wt_status_t wt_http3_message_encode(wt_writer_t *w, const wt_http3_message_t *message,
                                    uint64_t max_entries, wt_http3_error_t *out_error) {
  wt_qpack_header_prefix_t prefix;
  wt_qpack_field_line_t lines[WT_HTTP3_MESSAGE_MAX_FIELDS];
  char status_text[4];
  size_t count = 0U;
  uint8_t scratch[1];
  wt_status_t status;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (w == NULL || message == NULL) return WT_ERR_INVALID_ARGUMENT;

  if (message->type == WT_HTTP3_HEADER_REQUEST) {
    if (message->method == NULL) {
      /* A request without a method is not a request: writing it would produce a section
       * whose peer must report H3_MESSAGE_ERROR, which is worse than saying so here. */
      if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
      return WT_ERR_INVALID_ARGUMENT;
    }
    count = add_pseudo(lines, count, ":method", message->method, message->method_length);
    count = add_pseudo(lines, count, ":scheme", message->scheme, message->scheme_length);
    count = add_pseudo(lines, count, ":authority", message->authority, message->authority_length);
    count = add_pseudo(lines, count, ":path", message->path, message->path_length);
    /* The extended CONNECT's protocol (RFC 9220 section 3) rides with the request line, in
     * the order section 4.3.1 requires of pseudo-headers: before any regular field. */
    count = add_pseudo(lines, count, ":protocol", message->protocol, message->protocol_length);
  } else {
    if (!message->has_status) {
      if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
      return WT_ERR_INVALID_ARGUMENT;
    }
    /* Written by hand rather than with a formatter: a status is three digits, and the
     * library does not own `snprintf` on every target it builds for. */
    if (message->status > 999U) {
      if (out_error != NULL) *out_error = WT_HTTP3_MESSAGE_ERROR;
      return WT_ERR_LIMIT;
    }
    status_text[0] = (char)('0' + (int)((message->status / 100U) % 10U));
    status_text[1] = (char)('0' + (int)((message->status / 10U) % 10U));
    status_text[2] = (char)('0' + (int)(message->status % 10U));
    status_text[3] = '\0';
    count = add_pseudo(lines, count, ":status", (const uint8_t *)status_text, 3U);
  }

  /* Nothing indexed and nothing referenced, so the prefix says so: Required Insert Count 0
   * and Base 0 are readable by every peer, including one that advertised no dynamic
   * table. */
  prefix.required_insert_count = 0U;
  prefix.base = 0U;

  /* The scratch is unused because no line asks for Huffman coding, but the encoder's
   * signature requires one: passing a one-byte buffer makes that explicit rather than
   * hiding a dependency on the current coding choice. */
  status = wt_qpack_field_section_encode(w, &prefix, max_entries, lines, count, scratch,
                                         sizeof(scratch));
  /* No error code is attached to a failure here: the section encoder's refusals are about
   * this endpoint's own input or buffer -- a message with no method or status is refused
   * above with the message code -- and inventing a wire code for them would tell a peer's
   * story about a local mistake. */
  (void)out_error;
  return status;
}
