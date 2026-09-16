/* TLS 1.3 extensions. See webtransport/tls/extension.h. */

#include "webtransport/tls/extension.h"

#include <string.h>

/* A length-delimited region of the message as its own cursor.
 *
 * WT_ERR_PROTOCOL when the region does not fit, NOT WT_ERR_TRUNCATED: every caller of
 * this function has already checked that the framing outside the region is complete --
 * a handshake message whose declared length is the buffer's, an extension block whose
 * declared length is the cursor's -- so a region that overruns is a length that lies
 * rather than bytes that have not arrived yet. The distinction is the one that decides
 * whether a receiver gives up on the connection or waits for more. */
static wt_status_t sub_cursor(wt_cursor_t *cursor, size_t len, wt_cursor_t *out) {
  const uint8_t *bytes = wt_cursor_bytes(cursor, len);
  if (bytes == NULL) return WT_ERR_PROTOCOL;
  *out = wt_cursor_init(bytes, len);
  return WT_OK;
}

wt_status_t wt_tls_extensions_parse(wt_cursor_t *cursor,
                                    wt_tls_extension_list_t *out) {
  wt_cursor_t block;
  uint16_t total;
  size_t i;

  if (cursor == NULL || out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));
  total = wt_cursor_u16(cursor);
  if (wt_cursor_failed(cursor)) return WT_ERR_PROTOCOL;
  {
    wt_status_t region = sub_cursor(cursor, (size_t)total, &block);
    if (region != WT_OK) return region;
  }

  while (!wt_cursor_at_end(&block)) {
    uint16_t type;
    uint16_t length;
    wt_cursor_t body;
    if (out->count == WT_TLS_MAX_EXTENSIONS) return WT_ERR_LIMIT;
    type = wt_cursor_u16(&block);
    length = wt_cursor_u16(&block);
    if (wt_cursor_failed(&block)) return WT_ERR_PROTOCOL;
    {
      wt_status_t region = sub_cursor(&block, (size_t)length, &body);
      if (region != WT_OK) return region;
    }
    /* RFC 8446 section 4.2: "There MUST NOT be more than one extension of the same
     * type in a given extension block." A second one is not "the last wins": the two
     * endpoints would disagree about which, so it is refused. */
    for (i = 0U; i < out->count; i++) {
      if (out->entries[i].type == type) return WT_ERR_PROTOCOL;
    }
    out->entries[out->count].type = type;
    out->entries[out->count].data = body.data;
    out->entries[out->count].len = body.len;
    out->count++;
  }
  return WT_OK;
}

wt_status_t wt_tls_extensions_encode(wt_writer_t *w,
                                     const wt_tls_extension_list_t *list) {
  size_t i;
  size_t total = 0U;

  if (w == NULL || list == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (list->count > WT_TLS_MAX_EXTENSIONS) return WT_ERR_LIMIT;
  for (i = 0U; i < list->count; i++) {
    const wt_tls_extension_t *entry = &list->entries[i];
    if (entry->len > 0xFFFFU) return WT_ERR_LIMIT;
    if (entry->data == NULL && entry->len != 0U) return WT_ERR_INVALID_ARGUMENT;
    total += 4U + entry->len;
  }
  if (total > 0xFFFFU) return WT_ERR_LIMIT;
  wt_writer_u16(w, (uint16_t)total);
  for (i = 0U; i < list->count; i++) {
    const wt_tls_extension_t *entry = &list->entries[i];
    wt_writer_u16(w, entry->type);
    wt_writer_u16(w, (uint16_t)entry->len);
    wt_writer_bytes(w, entry->data, entry->len);
  }
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}

const wt_tls_extension_t *wt_tls_extensions_find(
    const wt_tls_extension_list_t *list, uint16_t type) {
  size_t i;
  if (list == NULL) return NULL;
  for (i = 0U; i < list->count; i++) {
    if (list->entries[i].type == type) return &list->entries[i];
  }
  return NULL;
}

int wt_tls_extensions_contains(const wt_tls_extension_list_t *list,
                               uint16_t type) {
  return wt_tls_extensions_find(list, type) != NULL;
}

/* ------------------------------------------------------------ typed readers */

/* The extension's own bytes as a cursor. A reader that forgets this would parse the
 * bytes after the extension, which is why every reader below starts with it. */
static wt_status_t extension_cursor(const wt_tls_extension_t *extension,
                                    wt_cursor_t *out) {
  if (extension == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (extension->data == NULL && extension->len != 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *out = wt_cursor_init(extension->data, extension->len);
  return WT_OK;
}

/* Every reader ends here: the extension must have been consumed exactly. An
 * extension with trailing bytes is a peer disagreeing with the RFC's field list, and
 * accepting it would mean guessing which reading was meant. */
static wt_status_t extension_end(const wt_cursor_t *cursor) {
  return wt_cursor_at_end(cursor) ? WT_OK : WT_ERR_PROTOCOL;
}

wt_status_t wt_tls_supported_versions_client(const wt_tls_extension_t *extension,
                                             uint16_t *versions, size_t capacity,
                                             size_t *count) {
  wt_cursor_t cursor;
  uint8_t length;
  size_t entries;
  size_t i;
  wt_status_t status;

  if (versions == NULL || count == NULL || capacity == 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *count = 0U;
  status = extension_cursor(extension, &cursor);
  if (status != WT_OK) return status;
  length = wt_cursor_u8(&cursor);
  if (wt_cursor_failed(&cursor)) return WT_ERR_PROTOCOL;
  /* RFC 8446 section 4.2.1: the vector is 2..254 bytes, so its length is even and
   * not zero. */
  if (length == 0U || (length % 2U) != 0U) return WT_ERR_PROTOCOL;
  entries = (size_t)length / 2U;
  if (entries > capacity) return WT_ERR_LIMIT;
  for (i = 0U; i < entries; i++) {
    versions[i] = wt_cursor_u16(&cursor);
  }
  if (wt_cursor_failed(&cursor)) return WT_ERR_PROTOCOL;
  *count = entries;
  return extension_end(&cursor);
}

wt_status_t wt_tls_supported_versions_server(const wt_tls_extension_t *extension,
                                             uint16_t *version) {
  wt_cursor_t cursor;
  wt_status_t status;

  if (version == NULL) return WT_ERR_INVALID_ARGUMENT;
  status = extension_cursor(extension, &cursor);
  if (status != WT_OK) return status;
  *version = wt_cursor_u16(&cursor);
  if (wt_cursor_failed(&cursor)) return WT_ERR_PROTOCOL;
  return extension_end(&cursor);
}

wt_status_t wt_tls_u16_list_parse(const wt_tls_extension_t *extension,
                                  uint16_t *values, size_t capacity,
                                  size_t *count) {
  wt_cursor_t cursor;
  uint16_t length;
  size_t entries;
  size_t i;
  wt_status_t status;

  if (values == NULL || count == NULL || capacity == 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *count = 0U;
  status = extension_cursor(extension, &cursor);
  if (status != WT_OK) return status;
  length = wt_cursor_u16(&cursor);
  if (wt_cursor_failed(&cursor)) return WT_ERR_PROTOCOL;
  /* RFC 8446 sections 4.2.7 and 4.2.3: the vector is 2..2^16-2 bytes, so it is even
   * and not empty. */
  if (length == 0U || (length % 2U) != 0U) return WT_ERR_PROTOCOL;
  entries = (size_t)length / 2U;
  if (entries > capacity) return WT_ERR_LIMIT;
  for (i = 0U; i < entries; i++) {
    values[i] = wt_cursor_u16(&cursor);
  }
  if (wt_cursor_failed(&cursor)) return WT_ERR_PROTOCOL;
  *count = entries;
  return extension_end(&cursor);
}

/* One KeyShareEntry: a group and a one-byte-prefixed key. */
static wt_status_t key_share_entry(wt_cursor_t *cursor, wt_tls_key_share_t *out) {
  uint16_t key_len;
  const uint8_t *key;

  out->group = wt_cursor_u16(cursor);
  key_len = wt_cursor_u16(cursor);
  if (wt_cursor_failed(cursor)) return WT_ERR_PROTOCOL;
  /* RFC 8446 section 4.2.8: key_exchange is 1..2^16-1 bytes. A zero-length share is
   * not an empty share, it is a malformed one. */
  if (key_len == 0U) return WT_ERR_PROTOCOL;
  key = wt_cursor_bytes(cursor, (size_t)key_len);
  if (key == NULL) return WT_ERR_PROTOCOL;
  out->key = key;
  out->key_len = (size_t)key_len;
  return WT_OK;
}

wt_status_t wt_tls_key_share_client(const wt_tls_extension_t *extension,
                                    wt_tls_key_share_t *shares, size_t capacity,
                                    size_t *count) {
  wt_cursor_t cursor;
  uint16_t total;
  wt_cursor_t block;
  wt_status_t status;

  if (shares == NULL || count == NULL || capacity == 0U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  *count = 0U;
  status = extension_cursor(extension, &cursor);
  if (status != WT_OK) return status;
  total = wt_cursor_u16(&cursor);
  if (wt_cursor_failed(&cursor)) return WT_ERR_PROTOCOL;
  {
    wt_status_t region = sub_cursor(&cursor, (size_t)total, &block);
    if (region != WT_OK) return region;
  }
  while (!wt_cursor_at_end(&block)) {
    if (*count == capacity) return WT_ERR_LIMIT;
    status = key_share_entry(&block, &shares[*count]);
    if (status != WT_OK) return status;
    (*count)++;
  }
  return extension_end(&cursor);
}

wt_status_t wt_tls_key_share_server(const wt_tls_extension_t *extension,
                                    wt_tls_key_share_t *share) {
  wt_cursor_t cursor;
  wt_status_t status;

  if (share == NULL) return WT_ERR_INVALID_ARGUMENT;
  status = extension_cursor(extension, &cursor);
  if (status != WT_OK) return status;
  /* RFC 8446 section 4.2.8: the server's key_share is one entry, not a list. */
  status = key_share_entry(&cursor, share);
  if (status != WT_OK) return status;
  return extension_end(&cursor);
}

wt_status_t wt_tls_alpn_parse(const wt_tls_extension_t *extension,
                              wt_tls_alpn_t *out) {
  wt_cursor_t cursor;
  uint16_t total;
  wt_cursor_t block;
  wt_status_t status;

  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  memset(out, 0, sizeof(*out));
  status = extension_cursor(extension, &cursor);
  if (status != WT_OK) return status;
  total = wt_cursor_u16(&cursor);
  if (wt_cursor_failed(&cursor)) return WT_ERR_PROTOCOL;
  /* RFC 7301 section 3.1: ProtocolNameList is 2..2^16-1 bytes and carries at least
   * one name. */
  if (total < 2U) return WT_ERR_PROTOCOL;
  {
    wt_status_t region = sub_cursor(&cursor, (size_t)total, &block);
    if (region != WT_OK) return region;
  }
  while (!wt_cursor_at_end(&block)) {
    uint8_t length;
    const uint8_t *name;
    if (out->count == WT_TLS_MAX_PROTOCOLS) return WT_ERR_LIMIT;
    length = wt_cursor_u8(&block);
    if (wt_cursor_failed(&block)) return WT_ERR_PROTOCOL;
    /* A protocol name is 1..255 bytes; an empty one would make "no ALPN" and "ALPN
     * with an empty name" the same bytes. */
    if (length == 0U) return WT_ERR_PROTOCOL;
    name = wt_cursor_bytes(&block, (size_t)length);
    if (name == NULL) return WT_ERR_PROTOCOL;
    out->names[out->count] = name;
    out->lengths[out->count] = length;
    out->count++;
  }
  return extension_end(&cursor);
}

wt_status_t wt_tls_transport_parameters(const wt_tls_extension_t *extension,
                                        const uint8_t **data, size_t *len) {
  if (extension == NULL || data == NULL || len == NULL) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  if (extension->data == NULL) return WT_ERR_INVALID_ARGUMENT;
  *data = extension->data;
  *len = extension->len;
  return WT_OK;
}

/* ------------------------------------------------------------ typed writers */

/* The two-byte length of an extension body is written before the body, so it is
 * computed from the values by the same function that writes them: a length that was
 * remembered would be a second source of truth. `wt_writer_measure` is how the
 * generic case does it, and the shaped extensions compute it directly because their
 * layout is fixed. */

void wt_tls_extension_supported_versions_client(wt_writer_t *w,
                                                const uint16_t *versions,
                                                size_t count) {
  size_t i;
  if (versions == NULL || count == 0U || count > 127U) {
    /* A client that offers no version cannot complete a handshake, and 127 is where
     * the one-byte length runs out. Writing nothing is the honest answer; the caller
     * checks the writer. */
    return;
  }
  wt_writer_u16(w, WT_TLS_EXTENSION_SUPPORTED_VERSIONS);
  wt_writer_u16(w, (uint16_t)(1U + 2U * count));
  wt_writer_u8(w, (uint8_t)(2U * count));
  for (i = 0U; i < count; i++) {
    wt_writer_u16(w, versions[i]);
  }
}

void wt_tls_extension_supported_versions_server(wt_writer_t *w, uint16_t version) {
  wt_writer_u16(w, WT_TLS_EXTENSION_SUPPORTED_VERSIONS);
  wt_writer_u16(w, 2U);
  wt_writer_u16(w, version);
}

void wt_tls_extension_u16_list(wt_writer_t *w, uint16_t type,
                               const uint16_t *values, size_t count) {
  size_t i;
  if (values == NULL || count == 0U || count > 0x7FFFU) return;
  wt_writer_u16(w, type);
  wt_writer_u16(w, (uint16_t)(2U + 2U * count));
  wt_writer_u16(w, (uint16_t)(2U * count));
  for (i = 0U; i < count; i++) {
    wt_writer_u16(w, values[i]);
  }
}

void wt_tls_extension_key_share_client(wt_writer_t *w,
                                       const wt_tls_key_share_t *shares,
                                       size_t count) {
  size_t i;
  size_t total = 0U;

  if (shares == NULL || count == 0U || count > 0x7FFFU) return;
  for (i = 0U; i < count; i++) {
    if (shares[i].key == NULL || shares[i].key_len == 0U ||
        shares[i].key_len > 0xFFFFU) {
      return;
    }
    total += 4U + shares[i].key_len;
  }
  if (total > 0xFFFFU) return;
  wt_writer_u16(w, WT_TLS_EXTENSION_KEY_SHARE);
  wt_writer_u16(w, (uint16_t)(2U + total));
  wt_writer_u16(w, (uint16_t)total);
  /* If the header did not fit, the writer's overflow flag makes every write below a
   * no-op, so there is nothing to undo -- only to stop. */
  if (!wt_writer_ok(w)) return;
  for (i = 0U; i < count; i++) {
    wt_writer_u16(w, shares[i].group);
    wt_writer_u16(w, (uint16_t)shares[i].key_len);
    wt_writer_bytes(w, shares[i].key, shares[i].key_len);
  }
}

void wt_tls_extension_key_share_server(wt_writer_t *w,
                                       const wt_tls_key_share_t *share) {
  if (share == NULL || share->key == NULL || share->key_len == 0U ||
      share->key_len > 0xFFFFU) {
    return;
  }
  wt_writer_u16(w, WT_TLS_EXTENSION_KEY_SHARE);
  wt_writer_u16(w, (uint16_t)(4U + share->key_len));
  wt_writer_u16(w, share->group);
  wt_writer_u16(w, (uint16_t)share->key_len);
  wt_writer_bytes(w, share->key, share->key_len);
}

void wt_tls_extension_alpn(wt_writer_t *w, const char *const *names, size_t count) {
  size_t i;
  size_t total = 0U;

  if (names == NULL || count == 0U || count > 0x7FFFU) return;
  for (i = 0U; i < count; i++) {
    size_t len;
    if (names[i] == NULL) return;
    len = strlen(names[i]);
    /* A protocol name is 1..255 bytes (RFC 7301 section 3.1). An empty name would
     * encode as a zero length, which is not a name. */
    if (len == 0U || len > WT_TLS_MAX_PROTOCOL_NAME) return;
    total += 1U + len;
  }
  if (total > 0xFFFFU) return;
  wt_writer_u16(w, WT_TLS_EXTENSION_ALPN);
  wt_writer_u16(w, (uint16_t)(2U + total));
  wt_writer_u16(w, (uint16_t)total);
  for (i = 0U; i < count; i++) {
    size_t len = strlen(names[i]);
    wt_writer_u8(w, (uint8_t)len);
    wt_writer_bytes(w, names[i], len);
  }
}

void wt_tls_extension_transport_parameters(wt_writer_t *w, const uint8_t *data,
                                           size_t len) {
  if (data == NULL && len != 0U) return;
  if (len > 0xFFFFU) return;
  wt_writer_u16(w, WT_TLS_EXTENSION_QUIC_TRANSPORT_PARAMETERS);
  wt_writer_u16(w, (uint16_t)len);
  wt_writer_bytes(w, data, len);
}

void wt_tls_extension_psk_key_exchange_modes(wt_writer_t *w) {
  wt_writer_u16(w, WT_TLS_EXTENSION_PSK_KEY_EXCHANGE_MODES);
  wt_writer_u16(w, 2U);
  /* A one-byte vector length and one mode. */
  wt_writer_u8(w, 1U);
  wt_writer_u8(w, (uint8_t)WT_TLS_PSK_MODE_PSK_DHE_KE);
}

void wt_tls_extension_server_name(wt_writer_t *w, const char *host_name) {
  size_t len;
  if (host_name == NULL) return;
  len = strlen(host_name);
  /* RFC 6066 section 3: the list is 1..2^16-1 bytes, the name type is 0 and the
   * name itself is 1..2^16-1 bytes. */
  if (len == 0U || len > 0xFFFEU) return;
  wt_writer_u16(w, WT_TLS_EXTENSION_SERVER_NAME);
  wt_writer_u16(w, (uint16_t)(2U + 1U + 2U + len));
  wt_writer_u16(w, (uint16_t)(1U + 2U + len));
  wt_writer_u8(w, 0U);
  wt_writer_u16(w, (uint16_t)len);
  wt_writer_bytes(w, host_name, len);
}
