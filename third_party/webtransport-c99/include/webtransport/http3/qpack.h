/* QPACK's static table and error codes (RFC 9204 sections 3.1, 4.5 and 8).
 *
 * The static table is 99 name/value pairs that every implementation must agree on
 * byte for byte: an encoder that indexes entry 17 as one field and a decoder that
 * reads it as another produce two different header sections, and nothing in the
 * exchange would say so. The table is therefore generated from RFC 9204 appendix
 * A by `tests/vectors/extract_rfc9204_static_table.py` and checked by
 * `check-vectors.sh`, not typed into C.
 *
 * This part is the table and its lookups. The prefixed-integer and prefixed-string
 * codecs, the dynamic table and the field-line representations build on it and
 * come next, which is why nothing here encodes or decodes a header section yet.
 */

#ifndef WEBTRANSPORT_HTTP3_QPACK_H
#define WEBTRANSPORT_HTTP3_QPACK_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/cursor.h"
#include "webtransport/status.h"
#include "webtransport/writer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The number of entries, which RFC 9204 section 3.1 fixes at 99. */
#define WT_QPACK_STATIC_TABLE_SIZE 99U

/* The error codes of RFC 9204 section 8, which travel as HTTP/3 application
 * errors. DECOMPRESSION_FAILED is a connection error; the two stream errors are
 * fatal to their stream only. */
#define WT_QPACK_DECOMPRESSION_FAILED ((uint64_t)0x0200)
#define WT_QPACK_ENCODER_STREAM_ERROR ((uint64_t)0x0201)
#define WT_QPACK_DECODER_STREAM_ERROR ((uint64_t)0x0202)

/* One static entry, as a view into the generated table: neither string is
 * terminated data the caller owns, and the value may be empty (many entries are
 * name-only). */
typedef struct wt_qpack_static_entry {
  const char *name;
  size_t name_length;
  const char *value;
  size_t value_length;
} wt_qpack_static_entry_t;

/* The entry at this index. An index outside 0..98 is WT_ERR_LIMIT: it is a peer's
 * or a caller's arithmetic that went wrong, not a malformed frame. */
wt_status_t wt_qpack_static_entry(uint64_t index, wt_qpack_static_entry_t *out);

/* The first entry with this name and exactly this value, for an indexed field
 * line. WT_ERR_CLOSED when the table has no such entry -- the pair is not there,
 * which is an ordinary answer for a header a table does not carry. */
wt_status_t wt_qpack_static_find(const char *name, size_t name_length, const char *value,
                                 size_t value_length, uint64_t *out_index);

/* The first entry with this name, whatever its value, for a literal field line
 * with a name reference. WT_ERR_CLOSED when the name is not in the table. */
wt_status_t wt_qpack_static_find_name(const char *name, size_t name_length, uint64_t *out_index);

/* ------------------------------------------------ RFC 9204 section 4.1's primitives */

/* An integer with an N-bit prefix, as every QPACK field line and the dynamic
 * table use: the first byte carries as much of the value as fits in the prefix,
 * and a prefix full of ones means "keep reading seven bits at a time".
 *
 * `prefix_bits` is 1..8. Values are limited to 62 bits (section 4.1.1); a peer's
 * integer that exceeds that, or one whose continuation never ends, is
 * QPACK_DECOMPRESSION_FAILED, which is what section 8 makes of a malformed
 * representation. */
wt_status_t wt_qpack_integer_decode(wt_cursor_t *c, unsigned prefix_bits, uint64_t *out_value);

/* The same integer, on the wire. `prefix_flags` are the bits above the prefix --
 * the field line's own pattern, already shifted into place -- and only those bits
 * are written, so a caller cannot accidentally encode part of the value there.
 * Refuses a value whose low `prefix_bits` would collide with the flags. */
wt_status_t wt_qpack_integer_encode(wt_writer_t *w, unsigned prefix_bits, uint8_t prefix_flags,
                                    uint64_t value);

/* A string: a length as an integer with a seven-bit prefix, then that many bytes
 * (section 4.1.2). The length field's top bit is the H bit, so the bytes may be
 * Huffman-coded; this returns the bytes as they are on the wire and says which,
 * because decoding them is the Huffman part's job and a caller that ignored the
 * flag would read coded bytes as field content. */
wt_status_t wt_qpack_string_decode(wt_cursor_t *c, const uint8_t **out_bytes, size_t *out_length,
                                   int *out_huffman);

/* Write a string that is not Huffman-coded. The Huffman encoder is a later part,
 * so this is what every representation written by this build looks like. */
wt_status_t wt_qpack_string_encode(wt_writer_t *w, const uint8_t *bytes, size_t length);

/* The same string, Huffman-coded when `huffman` is set. The coded bytes have to be
 * built before the length that precedes them is known, so the caller supplies the
 * buffer; WT_ERR_LIMIT means it was too small, which is the caller's bound rather
 * than anything about the peer. `wt_qpack_string_encode` is this with `huffman`
 * clear. */
wt_status_t wt_qpack_string_encode_coded(wt_writer_t *w, const uint8_t *bytes, size_t length,
                                        int huffman, uint8_t *scratch, size_t scratch_capacity);

/* Decode a Huffman-coded string (RFC 7541 appendix B, which RFC 9204 section
 * 4.1.2 adopts). The code comes from the RFC table generated into the source tree.
 *
 * Refuses the EOS symbol -- a string that carries it is malformed, and a decoder
 * that produced anything for it would accept a representation the peer could not
 * have meant -- a padding longer than seven bits or one that is not all ones
 * (section 5.2 makes padding the EOS prefix), and an output larger than the
 * caller's buffer (WT_ERR_LIMIT), because the decoded size is the peer's to choose
 * and the caller's to bound. */
wt_status_t wt_qpack_huffman_decode(const uint8_t *coded, size_t coded_length, uint8_t *out,
                                    size_t capacity, size_t *out_length);

/* The bytes a Huffman encoding of these bytes occupies, so a caller can size the
 * buffer it hands to the encoder without guessing (the code is not a fixed width,
 * and the final byte is padded with one-bits to the boundary). */
wt_status_t wt_qpack_huffman_encoded_size(const uint8_t *bytes, size_t length, size_t *out_size);

/* Encode a string with the same table. Refuses an output buffer that cannot hold
 * the result (WT_ERR_LIMIT) rather than writing part of it: a half-written string
 * is a representation the peer would decode into something else. */
wt_status_t wt_qpack_huffman_encode(const uint8_t *bytes, size_t length, uint8_t *out,
                                    size_t capacity, size_t *out_length);

/* ------------------------------------------- RFC 9204 section 4.5's field lines */

/* The five representations of section 4.5, split by what a decoder needs to resolve
 * them: the two that name a static entry need only the static table, the two that
 * name a dynamic one need the dynamic table, and the two post-base forms need the
 * header block's base. Modelling the difference in the type is what keeps a decoder
 * from resolving a dynamic index against the static table by accident -- the bug
 * that would silently produce a different header section. */
typedef enum wt_qpack_field_kind {
  /* 1 1 index(6+): an entry of the static table. */
  WT_QPACK_FIELD_INDEXED_STATIC = 0,
  /* 1 0 index(6+): an entry of the dynamic table. */
  WT_QPACK_FIELD_INDEXED_DYNAMIC = 1,
  /* 01 N 1 index(4+) then a value string. */
  WT_QPACK_FIELD_LITERAL_NAME_REF_STATIC = 2,
  /* 01 N 0 index(4+) then a value string. */
  WT_QPACK_FIELD_LITERAL_NAME_REF_DYNAMIC = 3,
  /* 001 N H name-length(3+) then the name and the value. */
  WT_QPACK_FIELD_LITERAL_LITERAL_NAME = 4,
  /* 0001 index(4+): a dynamic entry counted from the base. */
  WT_QPACK_FIELD_POST_BASE_INDEX = 5,
  /* 0000 N index(3+) then a value string. */
  WT_QPACK_FIELD_POST_BASE_NAME_REF = 6
} wt_qpack_field_kind_t;

typedef struct wt_qpack_field_line {
  wt_qpack_field_kind_t kind;
  /* The N bit: the field must never be put in a dynamic table. */
  int never_indexed;
  /* The index, whose meaning depends on the kind. */
  uint64_t index;
  /* The inline name, for the literal-literal form only. */
  int name_huffman;
  const uint8_t *name;
  size_t name_length;
  /* The value, which every form except the indexed ones carries. Its H bit is
   * reported rather than acted on, for the reason the string primitive gives. */
  const uint8_t *value;
  size_t value_length;
  int value_huffman;
  /* How many bytes the representation occupies, so a caller can walk a field
   * section without re-deriving it. */
  size_t bytes_consumed;
} wt_qpack_field_line_t;

/* Read one field line. A truncated representation is WT_ERR_TRUNCATED and a
 * malformed one WT_ERR_PROTOCOL; the caller maps both to QPACK_DECOMPRESSION_FAILED
 * (section 8), because a field section that does not parse is not recoverable. */
wt_status_t wt_qpack_field_line_decode(wt_cursor_t *c, wt_qpack_field_line_t *out);

/* Write one, writing only plain strings: a line whose flags ask for Huffman coding is
 * REFUSED (WT_ERR_STATE) rather than written plainly, because the flags are part of
 * the representation and a plain string with the H bit clear is a different one. */
wt_status_t wt_qpack_field_line_encode(wt_writer_t *w, const wt_qpack_field_line_t *line);

/* Write one with the line's own H bits honoured, Huffman-coding the strings into the
 * caller's scratch as `wt_qpack_string_encode_coded` does. */
wt_status_t wt_qpack_field_line_encode_coded(wt_writer_t *w, const wt_qpack_field_line_t *line,
                                            uint8_t *scratch, size_t scratch_capacity);

/* The name of a static-referencing line, from the static table or from the line
 * itself. WT_ERR_STATE for the kinds that need the dynamic table or a base. */
wt_status_t wt_qpack_field_line_static_name(const wt_qpack_field_line_t *line, const char **out_name,
                                            size_t *out_length);

/* -------------------------------------------- RFC 9204 section 3.2's dynamic table */

/* The table's bounds. A dynamic table is peer-driven state, so it is bounded like
 * every other table in this library: a peer that inserts more than this, or an
 * entry bigger than this endpoint's capacity, is refused rather than grown for. */
#define WT_QPACK_DYNAMIC_MAX_ENTRIES 32U
#define WT_QPACK_DYNAMIC_MAX_BYTES 4096U

/* One entry's size is its name and value plus 32 (section 3.2.1), which is what
 * the capacity counts. */
#define WT_QPACK_DYNAMIC_ENTRY_OVERHEAD 32U

typedef struct wt_qpack_dynamic_entry_meta {
  /* The absolute index of this entry: insertions are numbered from zero for the
   * life of the connection, so an index never changes meaning (section 3.2.3). */
  uint64_t absolute_index;
  uint32_t offset;
  uint16_t name_length;
  uint16_t value_length;
} wt_qpack_dynamic_entry_meta_t;

typedef struct wt_qpack_dynamic_table {
  /* The live entries, oldest first, with their bytes in `bytes`. */
  wt_qpack_dynamic_entry_meta_t entries[WT_QPACK_DYNAMIC_MAX_ENTRIES];
  uint8_t bytes[WT_QPACK_DYNAMIC_MAX_BYTES];
  size_t used;
  size_t count;
  /* The sum of the live entries' sizes, which the capacity bounds. */
  size_t size;
  /* The maximum, from SETTINGS_QPACK_MAX_TABLE_CAPACITY. Zero means the peer may
   * not use a dynamic table at all. */
  size_t capacity;
  /* How many insertions have happened, which is the absolute index the NEXT one
   * will carry. */
  uint64_t insert_count;
  /* How many entries have been evicted, so the oldest live entry's absolute index
   * is known without storing it twice. */
  uint64_t dropped;
} wt_qpack_dynamic_table_t;

/* An empty table with this capacity. Capacity is the peer's to choose through
 * SETTINGS; zero is legal and means no dynamic table. */
void wt_qpack_dynamic_init(wt_qpack_dynamic_table_t *table, size_t capacity);

/* Change the capacity (section 3.2.2): entries are evicted from the oldest end
 * until the size fits, and a shrinking capacity can empty the table. */
void wt_qpack_dynamic_set_capacity(wt_qpack_dynamic_table_t *table, size_t capacity);

/* Insert an entry and return its absolute index. WT_ERR_LIMIT when the entry is
 * larger than the capacity (section 3.2.1: "the encoder MUST NOT insert an entry
 * that is larger than the maximum capacity") or when the fixed table is full. */
wt_status_t wt_qpack_dynamic_insert(wt_qpack_dynamic_table_t *table, const uint8_t *name,
                                    size_t name_length, const uint8_t *value, size_t value_length,
                                    uint64_t *out_absolute_index);

/* The entry at an absolute index, or WT_ERR_CLOSED when it has been evicted. */
wt_status_t wt_qpack_dynamic_entry(const wt_qpack_dynamic_table_t *table, uint64_t absolute_index,
                                   const uint8_t **out_name, size_t *out_name_length,
                                   const uint8_t **out_value, size_t *out_value_length);

/* One of the three QPACK error codes, for the two stream kinds and for a header
 * block that does not decompress (RFC 9204 section 8). */
typedef enum wt_qpack_error {
  /* Named apart from the raw codes above because those are macros: an enumerator
   * with the same name would be replaced by its own macro before the compiler saw
   * it. The values are the same codes. */
  WT_QPACK_ERROR_NONE = 0,
  WT_QPACK_ERROR_DECOMPRESSION_FAILED = 0x0200,
  WT_QPACK_ERROR_ENCODER_STREAM = 0x0201,
  WT_QPACK_ERROR_DECODER_STREAM = 0x0202
} wt_qpack_error_t;

/* --------------------------------------- RFC 9204 section 4.3's encoder stream */

/* The four instructions an encoder sends on its encoder stream, applied in order:
 * the capacity, an insertion whose name comes from a table, an insertion whose
 * name is written out, and a duplication of an existing entry.
 *
 * Every error here is QPACK_ENCODER_STREAM_ERROR (section 4.3), and the interesting
 * ones are the two the table alone cannot catch: a capacity above the limit this
 * endpoint advertised, and an index that names an entry the table has already
 * evicted. */
typedef struct wt_qpack_encoder_stream {
  /* The table the instructions drive, owned by the caller. */
  wt_qpack_dynamic_table_t *table;
  /* The capacity this endpoint advertised in SETTINGS: an instruction above it is
   * an error, because a peer may not use more than it was granted. */
  size_t max_capacity;
} wt_qpack_encoder_stream_t;

void wt_qpack_encoder_stream_init(wt_qpack_encoder_stream_t *stream,
                                  wt_qpack_dynamic_table_t *table, size_t max_capacity);

/* Apply one instruction, advancing the cursor past it. */
wt_status_t wt_qpack_encoder_stream_apply(wt_qpack_encoder_stream_t *stream, wt_cursor_t *c,
                                          wt_qpack_error_t *out_error);

/* Write each instruction, for the encoder side of this implementation. Refuses what
 * the decoder above would refuse, so this build cannot emit an instruction it could
 * not read back. */
wt_status_t wt_qpack_encoder_stream_write_capacity(wt_writer_t *w, size_t capacity);
wt_status_t wt_qpack_encoder_stream_write_insert_name_reference(wt_writer_t *w, int from_static,
                                                               uint64_t index, const uint8_t *value,
                                                               size_t value_length);
wt_status_t wt_qpack_encoder_stream_write_insert_literal(wt_writer_t *w, const uint8_t *name,
                                                        size_t name_length, const uint8_t *value,
                                                        size_t value_length);
wt_status_t wt_qpack_encoder_stream_write_duplicate(wt_writer_t *w, uint64_t relative_index);

/* --------------------------------------- RFC 9204 section 4.4's decoder stream */

/* The three instructions a decoder sends back to an encoder, which are what let
 * the encoder know it may evict: a section acknowledgement (this header block is
 * decoded), a stream cancellation (nothing more will be decoded on that stream),
 * and an insert count increment (these insertions have been processed).
 *
 * This is the bookkeeping half. The per-section REFERENCE tracking that decides
 * HOW MUCH of the table is safe to evict -- the smallest absolute index among the
 * outstanding sections -- belongs with the encoder that created those sections, so
 * the two counters here are what that part will read. */
typedef struct wt_qpack_decoder_stream {
  /* Insertions the decoder has confirmed processing, as a total. */
  uint64_t acknowledged_insert_count;
  /* Instructions seen, for diagnostics: a section acknowledgement or a
   * cancellation for a stream still outstanding is the encoder's bookkeeping to
   * check, not this parser's. */
  uint64_t sections_acknowledged;
  uint64_t streams_cancelled;
} wt_qpack_decoder_stream_t;

void wt_qpack_decoder_stream_init(wt_qpack_decoder_stream_t *stream);

/* Apply one instruction, advancing the cursor past it. `table` may be NULL; when
 * it is given, an increment that would take the acknowledged count past the number
 * of insertions is the error section 4.4.3 names. */
wt_status_t wt_qpack_decoder_stream_apply(wt_qpack_decoder_stream_t *stream,
                                          const wt_qpack_dynamic_table_t *table, wt_cursor_t *c,
                                          wt_qpack_error_t *out_error);

wt_status_t wt_qpack_decoder_stream_write_section_acknowledgement(wt_writer_t *w,
                                                                 uint64_t section_id);
wt_status_t wt_qpack_decoder_stream_write_stream_cancellation(wt_writer_t *w, uint64_t stream_id);
/* Refuses a zero increment, which section 4.4.3 makes an error rather than a
 * no-op. */
wt_status_t wt_qpack_decoder_stream_write_insert_count_increment(wt_writer_t *w,
                                                                uint64_t increment);

/* --------------------------------------- RFC 9204 section 4.5.1's header prefix */

/* Every encoded field section starts with two values: the Required Insert Count,
 * which says how much of the dynamic table the section needs, and the Base, which
 * anchors the relative indices inside it. Both are encoded against MaxEntries --
 * the dynamic table's capacity in units of 32 -- which is why the prefix cannot be
 * read without knowing the capacity this endpoint advertised.
 *
 * MaxEntries is zero when the capacity is below 32, and then no section may
 * reference the dynamic table at all: an encoder with one would be writing against
 * a table its peer does not have. */
typedef struct wt_qpack_header_prefix {
  uint64_t required_insert_count;
  uint64_t base;
} wt_qpack_header_prefix_t;

/* MaxEntries for a capacity: the number of 32-byte entries it can hold. */
uint64_t wt_qpack_max_entries(size_t capacity);

wt_status_t wt_qpack_header_prefix_encode(wt_writer_t *w, uint64_t required_insert_count,
                                          uint64_t base, uint64_t max_entries);

/* Read the prefix. `known_insert_count` is how many insertions this endpoint has
 * received, which is what bounds the wrapped value; the section's two error exits
 * (an encoded count larger than the full range, and a required count that cannot
 * describe anything the encoder could have sent) are QPACK_DECOMPRESSION_FAILED. An
 * incomplete prefix is WT_ERR_TRUNCATED with no error code, like the stream
 * instructions: a field section arrives in pieces. */
wt_status_t wt_qpack_header_prefix_decode(wt_cursor_t *c, uint64_t max_entries,
                                          uint64_t known_insert_count,
                                          wt_qpack_header_prefix_t *out,
                                          wt_qpack_error_t *out_error);

/* The resolved field a caller reads after decoding one line: a name and a value, as
 * views into the tables the field section was decoded against, or into the caller's
 * scratch buffer when an inline (possibly Huffman-coded) string had to be decoded.
 * Nothing here is owned by this module. */
typedef struct wt_qpack_resolved_field {
  const uint8_t *name;
  size_t name_length;
  const uint8_t *value;
  size_t value_length;
} wt_qpack_resolved_field_t;

/* Decode the next field line of a field section and resolve it against the static
 * table, the dynamic table and the section's prefix.
 *
 * The index arithmetic is where QPACK's dynamic references live: a dynamic index is
 * relative to the Base, so an absolute index is `base - index - 1`, and a post-base
 * index counts UP from the Base (`base + index`). A reference to an entry the table
 * has evicted, or one past the end of what exists, is QPACK_DECOMPRESSION_FAILED --
 * the code section 4.5.1 gives a decoder that cannot resolve the section it was
 * sent. `scratch` holds the decoded inline strings; WT_ERR_LIMIT means it was too
 * small, which is the caller's bound rather than the peer's error.
 *
 * `scratch_used` is the cursor INTO that buffer and it belongs to the SECTION, not to the call: the caller
 * starts it at zero and passes the same variable for every line, because what a resolved field points at must
 * stay valid until the caller has finished with the section. A cursor reset per line is a real defect and a
 * third-party one -- every literal value was decoded into the same bytes, so a later field overwrote an earlier
 * one and the earlier field's pointer then read the new value's head over the old value's tail
 * ("localhostort" for ":protocol webtransport", WT-154).
 *
 * WT_ERR_CLOSED from the cursor's end is the ordinary "the section is finished". */
wt_status_t wt_qpack_field_section_next(wt_cursor_t *c, const wt_qpack_header_prefix_t *prefix,
                                        const wt_qpack_dynamic_table_t *table, uint8_t *scratch,
                                        size_t scratch_capacity, size_t *scratch_used,
                                        wt_qpack_resolved_field_t *out,
                                        wt_qpack_error_t *out_error);

/* A whole field section: the prefix, then lines until the bytes run out. The state
 * is small enough to live on the caller's stack, and `begin` is separate from `next`
 * because the prefix carries the one decision a caller has to make before it can read
 * anything -- whether this section is BLOCKED.
 *
 * RFC 9204 section 2.1.2: a section whose Required Insert Count is above the number of
 * insertions received so far can still be decoded, once the encoder stream catches up,
 * so `begin` reports WT_ERR_AGAIN (with no error code) rather than a decompression
 * failure. A decoder that treated "not yet" as "no" would close a connection over an
 * instruction that is merely in flight. */
typedef struct wt_qpack_field_section_decoder {
  wt_qpack_header_prefix_t prefix;
  const wt_qpack_dynamic_table_t *table;
  wt_cursor_t cursor;
  /* How much of the caller's scratch the fields resolved so far have used, so that every one of them stays
   * readable until the section is finished (see the note on `_next` above). */
  size_t scratch_used;
} wt_qpack_field_section_decoder_t;

/* Read the section's prefix. `known_insert_count` is how many insertions this endpoint
 * has received. WT_ERR_AGAIN means blocked: the section is well formed but needs
 * insertions that have not arrived. */
wt_status_t wt_qpack_field_section_begin(wt_qpack_field_section_decoder_t *decoder,
                                         const wt_qpack_dynamic_table_t *table, uint64_t max_entries,
                                         const uint8_t *bytes, size_t length,
                                         uint64_t known_insert_count, wt_qpack_error_t *out_error);

/* The next field, or WT_ERR_CLOSED when the section is finished. */
wt_status_t wt_qpack_field_section_decoder_next(wt_qpack_field_section_decoder_t *decoder,
                                                uint8_t *scratch, size_t scratch_capacity,
                                                wt_qpack_resolved_field_t *out,
                                                wt_qpack_error_t *out_error);

/* Write a whole section: the prefix, then one line per field. The lines carry their own
 * kinds and indices, so the caller decides what is indexed and what is literal; the
 * reference tracking that decides the Required Insert Count and Base is the encoder's,
 * and it is what the caller passes in. Strings are coded into `scratch` when the line
 * asks for it. */
wt_status_t wt_qpack_field_section_encode(wt_writer_t *w, const wt_qpack_header_prefix_t *prefix,
                                         uint64_t max_entries,
                                         const wt_qpack_field_line_t *lines, size_t line_count,
                                         uint8_t *scratch, size_t scratch_capacity);

/* ------------------------------------- RFC 9204 section 2.1.1's encoder bookkeeping */

/* An encoder may not evict an entry an unacknowledged section might reference, which
 * means it has to remember what it has sent and what the decoder has confirmed. That
 * is the state here: one record per outstanding section, the decoder's insert count
 * increments, and the arithmetic that says how far down the table is safe to evict.
 *
 * The bound is this endpoint's, like every other table: an encoder that has this many
 * sections in flight without an acknowledgement is not going to be helped by room for
 * one more.
 */
#define WT_QPACK_MAX_OUTSTANDING_SECTIONS 16U

typedef struct wt_qpack_outstanding_section {
  int in_use;
  uint64_t stream_id;
  /* The count that section was written with: anything below it may be referenced by
   * it, so nothing below it may be evicted until the section is acknowledged. */
  uint64_t required_insert_count;
} wt_qpack_outstanding_section_t;

typedef struct wt_qpack_encoder_state {
  wt_qpack_dynamic_table_t *table;
  /* Insertions the decoder has confirmed processing (section 4.4.3). */
  uint64_t known_received_count;
  wt_qpack_outstanding_section_t outstanding[WT_QPACK_MAX_OUTSTANDING_SECTIONS];
  size_t outstanding_count;
} wt_qpack_encoder_state_t;

void wt_qpack_encoder_state_init(wt_qpack_encoder_state_t *state, wt_qpack_dynamic_table_t *table);

/* The prefix to write for a section on this stream. `references_dynamic` says whether
 * the section will use dynamic indices: when it will not, the prefix is zero and
 * nothing is recorded, because a section that references nothing holds nothing back.
 * When it will, the required insert count is the table's current insert count and the
 * Base is the same, so the most recent entry is dynamic index 0 (section 3.2.5). A
 * second outstanding section on the same stream replaces the first: a stream carries
 * one field section at a time. */
wt_status_t wt_qpack_encoder_state_begin_section(wt_qpack_encoder_state_t *state, uint64_t stream_id,
                                                 int references_dynamic,
                                                 wt_qpack_header_prefix_t *out_prefix);

/* A Section Acknowledgement: that stream's section is decoded and may be forgotten. */
wt_status_t wt_qpack_encoder_state_section_acknowledged(wt_qpack_encoder_state_t *state,
                                                        uint64_t stream_id);

/* A Stream Cancellation: nothing more will be decoded there, so its section is
 * forgotten too (section 4.4.2). */
wt_status_t wt_qpack_encoder_state_stream_cancelled(wt_qpack_encoder_state_t *state,
                                                    uint64_t stream_id);

/* An Insert Count Increment. An increment that would pass the table's insert count is
 * QPACK_DECODER_STREAM_ERROR, the same rule the instruction parser enforces. */
wt_status_t wt_qpack_encoder_state_on_insert_count_increment(wt_qpack_encoder_state_t *state,
                                                             uint64_t increment,
                                                             wt_qpack_error_t *out_error);

/* The highest absolute index plus one that may be evicted: the smallest required
 * insert count among outstanding sections, or the table's insert count when nothing is
 * outstanding. Entries at or above it must survive until an acknowledgement. */
uint64_t wt_qpack_encoder_state_evictable_below(const wt_qpack_encoder_state_t *state);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_HTTP3_QPACK_H */
