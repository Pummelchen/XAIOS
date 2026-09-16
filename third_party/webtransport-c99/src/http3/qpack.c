/* QPACK's static table. See webtransport/http3/qpack.h. */

#include "webtransport/http3/qpack.h"

#include <string.h>

#include "qpack_static_table.h"

/* The generated table's entry as this module's public view. */
static wt_qpack_static_entry_t view(size_t index) {
  wt_qpack_static_entry_t entry;
  entry.name = WT_RFC9204_STATIC_TABLE[index].name;
  entry.name_length = strlen(WT_RFC9204_STATIC_TABLE[index].name);
  entry.value = WT_RFC9204_STATIC_TABLE[index].value;
  entry.value_length = strlen(WT_RFC9204_STATIC_TABLE[index].value);
  return entry;
}

wt_status_t wt_qpack_static_entry(uint64_t index, wt_qpack_static_entry_t *out) {
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (index >= (uint64_t)WT_QPACK_STATIC_TABLE_SIZE) return WT_ERR_LIMIT;
  *out = view((size_t)index);
  return WT_OK;
}

wt_status_t wt_qpack_static_find(const char *name, size_t name_length, const char *value,
                                 size_t value_length, uint64_t *out_index) {
  size_t i;

  if (out_index == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (name == NULL && name_length != 0U) return WT_ERR_INVALID_ARGUMENT;
  if (value == NULL && value_length != 0U) return WT_ERR_INVALID_ARGUMENT;

  for (i = 0U; i < (size_t)WT_QPACK_STATIC_TABLE_SIZE; i++) {
    wt_qpack_static_entry_t entry = view(i);
    if (entry.name_length != name_length || entry.value_length != value_length) continue;
    /* The lengths already agree, so a zero length compares equal without the
     * call: the guard is what keeps a NULL with a zero length away from
     * `memcmp`'s nonnull parameters. */
    if (name_length != 0U && memcmp(entry.name, name, name_length) != 0) continue;
    if (value_length != 0U && memcmp(entry.value, value, value_length) != 0) continue;
    *out_index = (uint64_t)i;
    return WT_OK;
  }
  /* Not in the table: the caller writes a literal (or a name reference) instead,
   * which is the ordinary outcome rather than an error. */
  return WT_ERR_CLOSED;
}

wt_status_t wt_qpack_static_find_name(const char *name, size_t name_length, uint64_t *out_index) {
  size_t i;

  if (out_index == NULL) return WT_ERR_INVALID_ARGUMENT;
  if (name == NULL && name_length != 0U) return WT_ERR_INVALID_ARGUMENT;

  for (i = 0U; i < (size_t)WT_QPACK_STATIC_TABLE_SIZE; i++) {
    wt_qpack_static_entry_t entry = view(i);
    if (entry.name_length != name_length) continue;
    if (name_length != 0U && memcmp(entry.name, name, name_length) != 0) continue;
    /* The first match, which is what RFC 9204 section 4.5.4's encoder does: the
     * table keeps the most common value of a name first, so "first" is also the
     * cheapest choice among equals. */
    *out_index = (uint64_t)i;
    return WT_OK;
  }
  return WT_ERR_CLOSED;
}
