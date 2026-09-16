/* WebTransport sub-protocol negotiation: the `wt-protocol` field's Structured Fields values. */

#include "webtransport/webtransport/protocol.h"

#include <string.h>

#include "webtransport/http3/qpack.h"

int wt_webtransport_protocol_token_valid(const uint8_t *token, size_t length) {
  size_t index;
  if (token == NULL || length == 0U || length > (size_t)WT_WEBTRANSPORT_PROTOCOL_TOKEN_MAX) return 0;
  for (index = 0U; index < length; index++) {
    uint8_t byte = token[index];
    /* Visible ASCII minus the three bytes the Structured Fields grammar gives meaning to: a quote would end
     * the string, a backslash would start an escape, and a comma would end the item. */
    if (byte < 0x21U || byte > 0x7eU || byte == 0x22U || byte == 0x2cU || byte == 0x5cU) return 0;
  }
  return 1;
}

wt_status_t wt_webtransport_protocol_validate(const wt_webtransport_protocol_list_t *list) {
  size_t index;
  size_t other;
  if (list == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (list->count > (size_t)WT_WEBTRANSPORT_PROTOCOL_MAX) return WT_ERR_LIMIT;
  for (index = 0U; index < list->count; index++) {
    if (wt_webtransport_protocol_token_valid(list->tokens[index].bytes, list->tokens[index].length) == 0) {
      return WT_ERR_PROTOCOL;
    }
    for (other = 0U; other < index; other++) {
      if (list->tokens[other].length == list->tokens[index].length &&
          memcmp(list->tokens[other].bytes, list->tokens[index].bytes, list->tokens[index].length) == 0) {
        return WT_ERR_PROTOCOL;
      }
    }
  }
  return WT_OK;
}

wt_status_t wt_webtransport_protocol_encode_item(wt_writer_t *w,
                                                 const wt_webtransport_protocol_token_t *token) {
  if (w == NULL || token == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* An invalid token is REFUSED rather than escaped into a valid-looking one: it could not have come from a
   * configuration that means anything, and escaping it would write a field whose value is not the token the
   * caller passed. */
  if (wt_webtransport_protocol_token_valid(token->bytes, token->length) == 0) return WT_ERR_PROTOCOL;
  wt_writer_u8(w, (uint8_t)'"');
  wt_writer_bytes(w, token->bytes, token->length);
  wt_writer_u8(w, (uint8_t)'"');
  return wt_writer_ok(w) != 0 ? WT_OK : WT_ERR_LIMIT;
}

wt_status_t wt_webtransport_protocol_encode_list(wt_writer_t *w, const wt_webtransport_protocol_list_t *list) {
  size_t index;
  wt_status_t status;
  if (w == NULL || list == NULL) return WT_ERR_INVALID_ARGUMENT;
  status = wt_webtransport_protocol_validate(list);
  if (status != WT_OK) return status;
  for (index = 0U; index < list->count; index++) {
    if (index > 0U) wt_writer_bytes(w, ", ", 2U);
    status = wt_webtransport_protocol_encode_item(w, &list->tokens[index]);
    if (status != WT_OK) return status;
  }
  return WT_OK;
}

wt_status_t wt_webtransport_protocol_decode_item(const uint8_t *value, size_t length,
                                                 wt_webtransport_protocol_token_t *out) {
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  out->bytes = NULL;
  out->length = 0U;
  if (value == NULL) return length == 0U ? WT_ERR_PROTOCOL : WT_ERR_INVALID_ARGUMENT;
  /* A Structured Fields string, and nothing else: no bare token, no number, no parameters. */
  if (length < 2U || value[0] != (uint8_t)'"' || value[length - 1U] != (uint8_t)'"') return WT_ERR_PROTOCOL;
  if (length - 2U > (size_t)WT_WEBTRANSPORT_PROTOCOL_TOKEN_MAX) return WT_ERR_LIMIT;
  /* A backslash would be an escape, and an escaped byte could only ever decode to something this file
   * refuses as a token (`"` or `\`), so the escape is malformed rather than decoded into a buffer. */
  if (memchr(value + 1U, (int)'\\', length - 2U) != NULL) return WT_ERR_PROTOCOL;
  if (memchr(value + 1U, (int)'"', length - 2U) != NULL) return WT_ERR_PROTOCOL;
  if (wt_webtransport_protocol_token_valid(value + 1U, length - 2U) == 0) return WT_ERR_PROTOCOL;
  out->bytes = value + 1U;
  out->length = length - 2U;
  return WT_OK;
}

wt_status_t wt_webtransport_protocol_decode_list(const uint8_t *value, size_t length,
                                                 wt_webtransport_protocol_list_t *out) {
  size_t position = 0U;
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));
  if (value == NULL) return length == 0U ? WT_ERR_PROTOCOL : WT_ERR_INVALID_ARGUMENT;

  for (;;) {
    size_t start;
    size_t end;
    /* Optional whitespace before an item: SP or HTAB, which is what RFC 8941 allows around a comma. */
    while (position < length && (value[position] == (uint8_t)' ' || value[position] == (uint8_t)'\t')) {
      position++;
    }
    if (position >= length) return WT_ERR_PROTOCOL;
    if (value[position] != (uint8_t)'"') return WT_ERR_PROTOCOL;
    start = position;
    position++;
    /* Up to the closing quote. A quote inside is the end of THIS string, so a following non-comma byte is
     * caught by the separator check below rather than read as part of the token. */
    while (position < length && value[position] != (uint8_t)'"') {
      if (value[position] == (uint8_t)'\\') return WT_ERR_PROTOCOL;
      position++;
    }
    if (position >= length) return WT_ERR_PROTOCOL;
    end = position; /* the closing quote */
    if (out->count >= (size_t)WT_WEBTRANSPORT_PROTOCOL_MAX) return WT_ERR_LIMIT;
    if (end - start + 1U > (size_t)WT_WEBTRANSPORT_PROTOCOL_TOKEN_MAX + 2U) return WT_ERR_LIMIT;
    {
      wt_status_t status = wt_webtransport_protocol_decode_item(value + start, end - start + 1U,
                                                                &out->tokens[out->count]);
      if (status != WT_OK) return status;
    }
    out->count++;
    position = end + 1U;
    while (position < length && (value[position] == (uint8_t)' ' || value[position] == (uint8_t)'\t')) {
      position++;
    }
    if (position >= length) break;
    if (value[position] != (uint8_t)',') return WT_ERR_PROTOCOL;
    position++;
  }
  return wt_webtransport_protocol_validate(out);
}

int wt_webtransport_protocol_select(const wt_webtransport_protocol_list_t *requested,
                                    const wt_webtransport_protocol_list_t *supported,
                                    wt_webtransport_protocol_token_t *out) {
  size_t index;
  size_t other;
  if (out != NULL) {
    out->bytes = NULL;
    out->length = 0U;
  }
  if (requested == NULL || supported == NULL || out == NULL) return 0;
  /* The FIRST the client offered, so both endpoints compute the same answer: a server that scanned its own
   * list instead would select a different protocol whenever a client offers two it supports. */
  for (index = 0U; index < requested->count; index++) {
    for (other = 0U; other < supported->count; other++) {
      if (requested->tokens[index].length == supported->tokens[other].length &&
          memcmp(requested->tokens[index].bytes, supported->tokens[other].bytes,
                 requested->tokens[index].length) == 0) {
        *out = requested->tokens[index];
        return 1;
      }
    }
  }
  return 0;
}

wt_status_t wt_webtransport_protocol_list_from_strings(wt_webtransport_protocol_list_t *out,
                                                       const char *const *protocols, size_t count) {
  size_t index;
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));
  if (count == 0U) return WT_OK;
  if (protocols == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* The bound is checked FIRST so a configuration longer than the table is refused as a bound rather than
   * truncated into a shorter list, which would be a different configuration. */
  if (count > (size_t)WT_WEBTRANSPORT_PROTOCOL_MAX) return WT_ERR_LIMIT;
  for (index = 0U; index < count; index++) {
    size_t length;
    if (protocols[index] == NULL) return WT_ERR_INVALID_ARGUMENT;
    length = strlen(protocols[index]);
    if (wt_webtransport_protocol_token_valid((const uint8_t *)protocols[index], length) == 0) {
      return WT_ERR_PROTOCOL;
    }
    out->tokens[index].bytes = (const uint8_t *)protocols[index];
    out->tokens[index].length = length;
    out->count = index + 1U;
  }
  return WT_OK;
}

wt_status_t wt_webtransport_protocol_write_field(wt_writer_t *w,
                                                 const wt_webtransport_protocol_token_t *token) {
  uint8_t value[WT_WEBTRANSPORT_PROTOCOL_TOKEN_MAX + 2U];
  wt_writer_t value_writer;
  wt_qpack_field_line_t line;

  if (w == NULL || token == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* The value is the QUOTED form: the field carries a Structured Fields string, not the bare token, and a
   * peer that read the bare form would be reading a different kind of item. */
  value_writer = wt_writer_init(value, sizeof(value));
  {
    wt_status_t status = wt_webtransport_protocol_encode_item(&value_writer, token);
    if (status != WT_OK) return status;
  }

  memset(&line, 0, sizeof(line));
  line.kind = WT_QPACK_FIELD_LITERAL_LITERAL_NAME;
  line.name = (const uint8_t *)WT_WEBTRANSPORT_PROTOCOL_HEADER;
  line.name_length = strlen(WT_WEBTRANSPORT_PROTOCOL_HEADER);
  line.value = value;
  line.value_length = wt_writer_offset(&value_writer);
  return wt_qpack_field_line_encode(w, &line);
}
