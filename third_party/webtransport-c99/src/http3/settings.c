/* HTTP/3 SETTINGS. See webtransport/http3/settings.h. */

#include "webtransport/http3/settings.h"

#include <string.h>

#include "webtransport/quic/varint.h"

void wt_http3_settings_init(wt_http3_settings_t *settings) {
  if (settings == NULL) return;
  memset(settings, 0, sizeof(*settings));
}

int wt_http3_setting_is_reserved_http2(uint64_t identifier) {
  /* RFC 9114 section 11.2.2: the HTTP/2 settings HTTP/3 has no equivalent for.
   * They are values a peer might send from an HTTP/2 implementation, and the
   * section makes receipt of one H3_SETTINGS_ERROR rather than something to
   * ignore, precisely because ignoring them would silently change behaviour. */
  /* (The HTTP/2 identifiers above; the RESERVED ones are `wt_http3_setting_is_exerciser` below.) */
  return identifier == (uint64_t)0x02 || identifier == (uint64_t)0x03 ||
         identifier == (uint64_t)0x04 || identifier == (uint64_t)0x05;
}

int wt_http3_setting_is_exerciser(uint64_t identifier) {
  /* RFC 9114 section 7.2.4.1: "Setting identifiers of the format 0x1f * N + 0x21 for non-negative integer values
   * of N are reserved to exercise the requirement that unknown identifiers be ignored. Such settings have no
   * defined meaning. Endpoints SHOULD include at least one such setting in their SETTINGS frame. Endpoints MUST
   * NOT consider such settings to have any meaning upon receipt."
   *
   * So an exerciser is IGNORED, and the comment that used to be here said the opposite -- that a receiver MUST
   * treat one as H3_SETTINGS_ERROR -- which is the rule for the HTTP/2-derived family (0x02..0x05), not for this
   * one. `WT-137` corrected a fixture that used an exerciser as its example of a legal unknown setting and made
   * the parser refuse it; this reverses that, because a peer that follows the RFC's SHOULD was being refused.
   * The tree's own conformance scenario asserted the wrong rule too, which is what a test written from the same
   * misreading as the code does. */
  if (identifier < (uint64_t)0x21) return 0;
  return ((identifier - (uint64_t)0x21) % (uint64_t)0x1f) == 0U;
}

wt_status_t wt_http3_settings_set(wt_http3_settings_t *settings, uint64_t identifier,
                                  uint64_t value) {
  size_t i;

  if (settings == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (identifier > WT_QUIC_VARINT_MAX || value > WT_QUIC_VARINT_MAX) return WT_ERR_INVALID_ARGUMENT;
  /* The HTTP/2 identifiers this version has no equivalent for are values a peer must never send, so refusing
   * them at the SETTER keeps the encoder from producing a frame the parser would refuse. EXERCISERS are the
   * opposite: the RFC says a SETTINGS frame SHOULD carry one, so the setter accepts them and the parser ignores
   * them (see `wt_http3_setting_is_exerciser`). */
  if (wt_http3_setting_is_reserved_http2(identifier)) return WT_ERR_INVALID_ARGUMENT;
  /* RFC 9220 section 3: ENABLE_CONNECT_PROTOCOL is a boolean, and any other
   * value MUST be treated as H3_SETTINGS_ERROR. Refusing it at the setter keeps
   * the encoder from producing a frame the parser would refuse. */
  if (identifier == WT_HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL && value > 1U) {
    return WT_ERR_INVALID_ARGUMENT;
  }
  for (i = 0U; i < settings->count; i++) {
    /* Already present. Refused rather than overwritten: the encoder must not be
     * able to produce a frame with a duplicate identifier, which is what this
     * module refuses to read. */
    if (settings->identifiers[i] == identifier) return WT_ERR_STATE;
  }
  if (settings->count >= WT_HTTP3_SETTINGS_MAX_ENTRIES) return WT_ERR_LIMIT;

  settings->identifiers[settings->count] = identifier;
  settings->values[settings->count] = value;
  settings->count++;
  return WT_OK;
}

uint64_t wt_http3_settings_get(const wt_http3_settings_t *settings, uint64_t identifier,
                               int *out_present) {
  size_t i;

  if (out_present != NULL) *out_present = 0;
  if (settings == NULL) return 0U;
  for (i = 0U; i < settings->count; i++) {
    if (settings->identifiers[i] == identifier) {
      if (out_present != NULL) *out_present = 1;
      return settings->values[i];
    }
  }
  return 0U;
}

wt_status_t wt_http3_settings_parse(const uint8_t *payload, size_t length,
                                    wt_http3_settings_t *out, wt_http3_error_t *out_error) {
  wt_cursor_t c;
  wt_http3_settings_t parsed;
  wt_status_t status;

  if (out_error != NULL) *out_error = WT_HTTP3_NO_ERROR;
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (payload == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;

  wt_http3_settings_init(&parsed);
  c = wt_cursor_init(payload, length);
  while (!wt_cursor_at_end(&c)) {
    uint64_t identifier;
    uint64_t value;

    if (wt_quic_varint_decode(&c, &identifier) != WT_OK ||
        wt_quic_varint_decode(&c, &value) != WT_OK) {
      /* A parameter is an identifier AND a value: a payload that ends between
       * them is a malformed SETTINGS frame, which is H3_SETTINGS_ERROR and not a
       * short read, because HTTP/3 has no partial frame. */
      if (out_error != NULL) *out_error = WT_HTTP3_SETTINGS_ERROR;
      return WT_ERR_TRUNCATED;
    }
    if (wt_http3_setting_is_reserved_http2(identifier)) {
      /* The HTTP/2-derived family: "These reserved settings MUST NOT be sent, and their receipt MUST be treated
       * as a connection error of type H3_SETTINGS_ERROR." */
      if (out_error != NULL) *out_error = WT_HTTP3_SETTINGS_ERROR;
      return WT_ERR_PROTOCOL;
    }
    if (wt_http3_setting_is_exerciser(identifier)) {
      /* An exerciser: IGNORED, not stored and not an error, which is what the section quoted at the predicate
       * says a receiver must do. Ignoring rather than storing is also what keeps a peer from filling this
       * endpoint's settings table with values that mean nothing. */
      continue;
    }
    if (identifier == WT_HTTP3_SETTING_ENABLE_CONNECT_PROTOCOL && value > 1U) {
      if (out_error != NULL) *out_error = WT_HTTP3_SETTINGS_ERROR;
      return WT_ERR_PROTOCOL;
    }
    status = wt_http3_settings_set(&parsed, identifier, value);
    if (status == WT_ERR_LIMIT) {
      /* The table is this endpoint's bound, and a peer that exceeds it is asking
       * for more than it was given: that is what H3_EXCESSIVE_LOAD names. */
      if (out_error != NULL) *out_error = WT_HTTP3_EXCESSIVE_LOAD;
      return status;
    }
    if (status == WT_ERR_STATE) {
      /* The duplicate case the section makes a MAY and this build takes. */
      if (out_error != NULL) *out_error = WT_HTTP3_SETTINGS_ERROR;
      return WT_ERR_PROTOCOL;
    }
    if (status != WT_OK) {
      if (out_error != NULL) *out_error = WT_HTTP3_SETTINGS_ERROR;
      return status;
    }
  }
  *out = parsed;
  return WT_OK;
}

wt_status_t wt_http3_settings_encode_payload(wt_writer_t *w, const wt_http3_settings_t *settings) {
  size_t written = 0U;

  if (w == NULL || settings == NULL) return WT_ERR_INVALID_ARGUMENT;

  /* Ascending identifier order, so the same set is always the same bytes: a test
   * or a release note can quote them, and two runs are comparable. A selection
   * sort over at most WT_HTTP3_SETTINGS_MAX_ENTRIES entries needs no memory and
   * cannot be made to allocate by a peer. */
  {
    /* The entries are all distinct -- `wt_http3_settings_set` refuses a repeat --
     * so selecting the smallest not yet written is what produces ascending
     * order, and the flags are what keep an entry from being written twice. */
    int emitted[WT_HTTP3_SETTINGS_MAX_ENTRIES];
    memset(emitted, 0, sizeof(emitted));
    while (written < settings->count) {
      size_t best = settings->count;
      size_t i;

      for (i = 0U; i < settings->count; i++) {
        if (emitted[i]) continue;
        if (best == settings->count || settings->identifiers[i] < settings->identifiers[best]) {
          best = i;
        }
      }
      if (best == settings->count) break;
      (void)wt_quic_writer_varint(w, settings->identifiers[best]);
      (void)wt_quic_writer_varint(w, settings->values[best]);
      emitted[best] = 1;
      written++;
    }
  }
  return wt_writer_ok(w) ? WT_OK : WT_ERR_LIMIT;
}
