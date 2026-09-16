/* QPACK's encoder bookkeeping: what may be evicted (RFC 9204 section 2.1.1). */

#include "webtransport/http3/qpack.h"

void wt_qpack_encoder_state_init(wt_qpack_encoder_state_t *state, wt_qpack_dynamic_table_t *table) {
  if (state == NULL) return;
  state->table = table;
  state->known_received_count = 0U;
  state->outstanding_count = 0U;
  {
    size_t i;
    for (i = 0U; i < (size_t)WT_QPACK_MAX_OUTSTANDING_SECTIONS; i++) {
      state->outstanding[i].in_use = 0;
      state->outstanding[i].stream_id = 0U;
      state->outstanding[i].required_insert_count = 0U;
    }
  }
}

/* The record for a stream, or NULL. A stream carries one field section at a time, so
 * the stream id is the key. */
static wt_qpack_outstanding_section_t *find_section(wt_qpack_encoder_state_t *state,
                                                    uint64_t stream_id) {
  size_t i;
  for (i = 0U; i < (size_t)WT_QPACK_MAX_OUTSTANDING_SECTIONS; i++) {
    if (state->outstanding[i].in_use && state->outstanding[i].stream_id == stream_id) {
      return &state->outstanding[i];
    }
  }
  return NULL;
}

static void forget(wt_qpack_encoder_state_t *state, wt_qpack_outstanding_section_t *section) {
  section->in_use = 0;
  section->stream_id = 0U;
  section->required_insert_count = 0U;
  state->outstanding_count--;
}

wt_status_t wt_qpack_encoder_state_begin_section(wt_qpack_encoder_state_t *state, uint64_t stream_id,
                                                 int references_dynamic,
                                                 wt_qpack_header_prefix_t *out_prefix) {
  size_t i;

  if (state == NULL || out_prefix == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (state->table == NULL) return WT_ERR_STATE;

  if (!references_dynamic) {
    /* Nothing to hold back, so nothing is recorded: a section with a zero required
     * insert count cannot be blocking anything. */
    out_prefix->required_insert_count = 0U;
    out_prefix->base = 0U;
    return WT_OK;
  }

  /* One section per stream: replacing the record is correct because the previous
   * section on that stream was decoded before the next one could be sent, and its
   * acknowledgement (or the new section) supersedes it. */
  {
    wt_qpack_outstanding_section_t *existing = find_section(state, stream_id);
    if (existing != NULL) forget(state, existing);
  }
  for (i = 0U; i < (size_t)WT_QPACK_MAX_OUTSTANDING_SECTIONS; i++) {
    if (!state->outstanding[i].in_use) {
      state->outstanding[i].in_use = 1;
      state->outstanding[i].stream_id = stream_id;
      state->outstanding[i].required_insert_count = state->table->insert_count;
      state->outstanding_count++;
      /* The Base is the required insert count, so the newest entry is dynamic index
       * zero and post-base indices count up from here (section 3.2.5). */
      out_prefix->required_insert_count = state->table->insert_count;
      out_prefix->base = state->table->insert_count;
      return WT_OK;
    }
  }
  return WT_ERR_LIMIT;
}

wt_status_t wt_qpack_encoder_state_section_acknowledged(wt_qpack_encoder_state_t *state,
                                                        uint64_t stream_id) {
  wt_qpack_outstanding_section_t *section;

  if (state == NULL) return WT_ERR_INVALID_ARGUMENT;
  section = find_section(state, stream_id);
  /* An acknowledgement for a stream with nothing outstanding is the encoder
   * disagreeing with its own records, so it is reported rather than ignored. */
  if (section == NULL) return WT_ERR_CLOSED;
  forget(state, section);
  return WT_OK;
}

wt_status_t wt_qpack_encoder_state_stream_cancelled(wt_qpack_encoder_state_t *state,
                                                    uint64_t stream_id) {
  wt_qpack_outstanding_section_t *section;

  if (state == NULL) return WT_ERR_INVALID_ARGUMENT;
  section = find_section(state, stream_id);
  /* A cancellation for a stream that never had a section is ordinary -- a peer may
   * cancel anything -- so it is not an error. */
  if (section == NULL) return WT_OK;
  forget(state, section);
  return WT_OK;
}

wt_status_t wt_qpack_encoder_state_on_insert_count_increment(wt_qpack_encoder_state_t *state,
                                                             uint64_t increment,
                                                             wt_qpack_error_t *out_error) {
  if (out_error != NULL) *out_error = WT_QPACK_ERROR_NONE;
  if (state == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (increment == 0U) {
    if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECODER_STREAM;
    return WT_ERR_PROTOCOL;
  }
  if (state->known_received_count > UINT64_MAX - increment) {
    if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECODER_STREAM;
    return WT_ERR_PROTOCOL;
  }
  if (state->table != NULL &&
      state->known_received_count + increment > state->table->insert_count) {
    if (out_error != NULL) *out_error = WT_QPACK_ERROR_DECODER_STREAM;
    return WT_ERR_PROTOCOL;
  }
  state->known_received_count += increment;
  return WT_OK;
}

uint64_t wt_qpack_encoder_state_evictable_below(const wt_qpack_encoder_state_t *state) {
  uint64_t below;
  size_t i;

  if (state == NULL || state->table == NULL) return 0U;
  /* With nothing outstanding every entry is evictable, which is the table's own
   * insert count: an index is always below the number of insertions. */
  below = state->table->insert_count;
  for (i = 0U; i < (size_t)WT_QPACK_MAX_OUTSTANDING_SECTIONS; i++) {
    if (!state->outstanding[i].in_use) continue;
    /* The smallest required insert count wins: every outstanding section holds back
     * everything below its own count, so the earliest one is the binding limit. */
    if (state->outstanding[i].required_insert_count < below) {
      below = state->outstanding[i].required_insert_count;
    }
  }
  return below;
}
