/* Whole QPACK field sections (RFC 9204 sections 4.5, 4.5.1 and 2.1.2). */

#include "webtransport/http3/qpack.h"

wt_status_t wt_qpack_field_section_begin(wt_qpack_field_section_decoder_t *decoder,
                                         const wt_qpack_dynamic_table_t *table, uint64_t max_entries,
                                         const uint8_t *bytes, size_t length,
                                         uint64_t known_insert_count, wt_qpack_error_t *out_error) {
  wt_status_t status;

  if (out_error != NULL) *out_error = WT_QPACK_ERROR_NONE;
  if (decoder == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (bytes == NULL && length != 0U) return WT_ERR_INVALID_ARGUMENT;

  decoder->table = table;
  decoder->cursor = wt_cursor_init(bytes, length);
  /* The cursor into the caller's scratch belongs to the SECTION: every field this decoder resolves has to stay
   * readable until the caller is done with the section (WT-154). */
  decoder->scratch_used = 0U;
  status = wt_qpack_header_prefix_decode(&decoder->cursor, max_entries, known_insert_count,
                                         &decoder->prefix, out_error);
  if (status != WT_OK) return status;

  /* Section 2.1.2: a section that needs insertions this decoder has not received is
   * BLOCKED, not broken. The caller can wait -- the encoder stream is what will
   * unblock it -- so this is WT_ERR_AGAIN with no error code rather than a
   * decompression failure, which would close the connection over an instruction that
   * is still in flight. */
  if (decoder->prefix.required_insert_count > known_insert_count) return WT_ERR_AGAIN;
  return WT_OK;
}

wt_status_t wt_qpack_field_section_decoder_next(wt_qpack_field_section_decoder_t *decoder,
                                                uint8_t *scratch, size_t scratch_capacity,
                                                wt_qpack_resolved_field_t *out,
                                                wt_qpack_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_QPACK_ERROR_NONE;
  if (decoder == NULL) return WT_ERR_INVALID_ARGUMENT;
  return wt_qpack_field_section_next(&decoder->cursor, &decoder->prefix, decoder->table, scratch,
                                     scratch_capacity, &decoder->scratch_used, out, out_error);
}

wt_status_t wt_qpack_field_section_encode(wt_writer_t *w, const wt_qpack_header_prefix_t *prefix,
                                         uint64_t max_entries,
                                         const wt_qpack_field_line_t *lines, size_t line_count,
                                         uint8_t *scratch, size_t scratch_capacity) {
  size_t i;

  if (w == NULL || prefix == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (lines == NULL && line_count != 0U) return WT_ERR_INVALID_ARGUMENT;

  if (wt_qpack_header_prefix_encode(w, prefix->required_insert_count, prefix->base, max_entries) !=
      WT_OK) {
    return WT_ERR_LIMIT;
  }
  for (i = 0U; i < line_count; i++) {
    wt_status_t status = wt_qpack_field_line_encode_coded(w, &lines[i], scratch, scratch_capacity);
    if (status != WT_OK) return status;
  }
  return WT_OK;
}
