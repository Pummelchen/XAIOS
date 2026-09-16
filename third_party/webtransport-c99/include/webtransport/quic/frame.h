/* QUIC frames (RFC 9000 section 19, RFC 9221 for DATAGRAM).
 *
 * A frame is a type byte followed by a body whose layout depends on the type.
 * The type is a variable-length integer, which is what leaves room for the
 * extension frames QUIC expects to grow: the values that are multiples of 0x1f
 * plus 0x21 are reserved for extensions, and an endpoint that receives one it
 * does not know is required to close the connection rather than skip it.
 *
 * THE PARSER DOES NOT COPY FRAME PAYLOAD. `wt_quic_frame_t` holds pointers into
 * the packet buffer it was parsed from, so a frame is valid exactly as long as
 * that buffer is, and nothing is allocated to parse a packet at all. That is the
 * right shape for a packet: a packet is a short-lived thing that is either
 * processed or dropped, and a parser that allocated per frame would put an
 * allocation on the receive path of every packet. The fields are explicit about
 * which are views -- every one is a `const uint8_t *` beside a length, and none
 * of them is ever freed by the caller.
 *
 * A UNION WITH A TAG, not a callback or a variant visitor. C has no pattern
 * matching, so the reader of a frame switches on `frame->type`; because every
 * union member is laid out explicitly here, a reader that switches on the type
 * and reads the matching member is reading a field whose offset the compiler
 * computed rather than a reinterpretation of bytes. `-Wswitch-enum` is on, so a
 * reader that forgets a frame type does not compile.
 */

#ifndef WEBTRANSPORT_QUIC_FRAME_H
#define WEBTRANSPORT_QUIC_FRAME_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/cursor.h"
#include "webtransport/quic/error.h"
#include "webtransport/quic/varint.h"
#include "webtransport/status.h"
#include "webtransport/writer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Frame type codes, as they appear on the wire. The STREAM range is eight
 * values whose low three bits are flags rather than part of the type, so a
 * decoder must mask before comparing and an encoder must build the byte from the
 * flags. */
#define WT_QUIC_FRAME_PADDING ((uint64_t)0x00)
#define WT_QUIC_FRAME_PING ((uint64_t)0x01)
#define WT_QUIC_FRAME_ACK ((uint64_t)0x02)
#define WT_QUIC_FRAME_ACK_ECN ((uint64_t)0x03)
#define WT_QUIC_FRAME_RESET_STREAM ((uint64_t)0x04)
#define WT_QUIC_FRAME_STOP_SENDING ((uint64_t)0x05)
#define WT_QUIC_FRAME_CRYPTO ((uint64_t)0x06)
#define WT_QUIC_FRAME_NEW_TOKEN ((uint64_t)0x07)
#define WT_QUIC_FRAME_STREAM_BASE ((uint64_t)0x08)
#define WT_QUIC_FRAME_STREAM_LAST ((uint64_t)0x0f)
#define WT_QUIC_FRAME_MAX_DATA ((uint64_t)0x10)
#define WT_QUIC_FRAME_MAX_STREAM_DATA ((uint64_t)0x11)
#define WT_QUIC_FRAME_MAX_STREAMS_BIDI ((uint64_t)0x12)
#define WT_QUIC_FRAME_MAX_STREAMS_UNI ((uint64_t)0x13)
#define WT_QUIC_FRAME_DATA_BLOCKED ((uint64_t)0x14)
#define WT_QUIC_FRAME_STREAM_DATA_BLOCKED ((uint64_t)0x15)
#define WT_QUIC_FRAME_STREAMS_BLOCKED_BIDI ((uint64_t)0x16)
#define WT_QUIC_FRAME_STREAMS_BLOCKED_UNI ((uint64_t)0x17)
#define WT_QUIC_FRAME_NEW_CONNECTION_ID ((uint64_t)0x18)
#define WT_QUIC_FRAME_RETIRE_CONNECTION_ID ((uint64_t)0x19)
#define WT_QUIC_FRAME_PATH_CHALLENGE ((uint64_t)0x1a)
#define WT_QUIC_FRAME_PATH_RESPONSE ((uint64_t)0x1b)
#define WT_QUIC_FRAME_CONNECTION_CLOSE_TRANSPORT ((uint64_t)0x1c)
#define WT_QUIC_FRAME_CONNECTION_CLOSE_APPLICATION ((uint64_t)0x1d)
#define WT_QUIC_FRAME_HANDSHAKE_DONE ((uint64_t)0x1e)
#define WT_QUIC_FRAME_RESET_STREAM_AT ((uint64_t)0x24)
#define WT_QUIC_FRAME_DATAGRAM ((uint64_t)0x30)
#define WT_QUIC_FRAME_DATAGRAM_LEN ((uint64_t)0x31)

/* The STREAM flags. A type in 0x08..0x0f carries these in its low three bits. */
#define WT_QUIC_STREAM_FLAG_FIN ((uint8_t)0x01)
#define WT_QUIC_STREAM_FLAG_LEN ((uint8_t)0x02)
#define WT_QUIC_STREAM_FLAG_OFF ((uint8_t)0x04)

/* The bounded quantities a frame can carry that RFC 9000 gives a maximum. */
#define WT_QUIC_MAX_CONNECTION_ID_LENGTH 20U
#define WT_QUIC_STATELESS_RESET_TOKEN_LENGTH 16U
#define WT_QUIC_PATH_CHALLENGE_LENGTH 8U

/* The one type tag a parsed frame carries. Every wire type maps to exactly one
 * tag, and the tag is what a reader switches on: the STREAM flags are fields of
 * the stream member rather than eight tags, and the two CONNECTION_CLOSE forms
 * are two tags because they carry different fields. */
typedef enum wt_quic_frame_type {
  WT_QUIC_FRAME_KIND_PADDING = 0,
  WT_QUIC_FRAME_KIND_PING,
  WT_QUIC_FRAME_KIND_ACK,
  WT_QUIC_FRAME_KIND_RESET_STREAM,
  WT_QUIC_FRAME_KIND_STOP_SENDING,
  WT_QUIC_FRAME_KIND_CRYPTO,
  WT_QUIC_FRAME_KIND_NEW_TOKEN,
  WT_QUIC_FRAME_KIND_STREAM,
  WT_QUIC_FRAME_KIND_MAX_DATA,
  WT_QUIC_FRAME_KIND_MAX_STREAM_DATA,
  WT_QUIC_FRAME_KIND_MAX_STREAMS,
  WT_QUIC_FRAME_KIND_DATA_BLOCKED,
  WT_QUIC_FRAME_KIND_STREAM_DATA_BLOCKED,
  WT_QUIC_FRAME_KIND_STREAMS_BLOCKED,
  WT_QUIC_FRAME_KIND_NEW_CONNECTION_ID,
  WT_QUIC_FRAME_KIND_RETIRE_CONNECTION_ID,
  WT_QUIC_FRAME_KIND_PATH_CHALLENGE,
  WT_QUIC_FRAME_KIND_PATH_RESPONSE,
  WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_TRANSPORT,
  WT_QUIC_FRAME_KIND_CONNECTION_CLOSE_APPLICATION,
  WT_QUIC_FRAME_KIND_HANDSHAKE_DONE,
  WT_QUIC_FRAME_KIND_RESET_STREAM_AT,
  WT_QUIC_FRAME_KIND_DATAGRAM
} wt_quic_frame_type_t;

/* A stream direction, for the frames that carry one. */
typedef enum wt_quic_stream_direction {
  WT_QUIC_STREAM_BIDIRECTIONAL = 0,
  WT_QUIC_STREAM_UNIDIRECTIONAL = 1
} wt_quic_stream_direction_t;

/* One ACK range: how many packets are missing before this range, and how many
 * this range covers. RFC 9000 section 19.3.1. */
typedef struct wt_quic_ack_range {
  uint64_t gap;
  uint64_t length;
} wt_quic_ack_range_t;

typedef struct wt_quic_frame {
  wt_quic_frame_type_t kind;

  union {
    struct {
      uint64_t largest;
      uint64_t delay;
      uint64_t first_range;
      /* The additional ranges, as the wire bytes rather than decoded: an ACK
       * can carry hundreds and an array of them would be an allocation on the
       * receive path. `wt_quic_frame_ack_range_at` decodes one on demand. */
      const uint8_t *ranges;
      size_t ranges_len;
      uint64_t range_count;
      /* RFC 9000 section 19.3.2. Present only for an ACK_ECN frame; the
       * transport may use ECN counts and this parser only reports them. */
      int has_ecn;
      uint64_t ect0;
      uint64_t ect1;
      uint64_t ecn_ce;
    } ack;

    struct {
      uint64_t offset;
      const uint8_t *data;
      size_t length;
    } crypto;

    struct {
      uint64_t id;
      uint64_t offset;
      int has_offset;
      int fin;
      /* `has_length` is false for a STREAM frame without the LEN bit, which
       * means the data runs to the end of the packet. The parser resolves it to
       * `length` either way, so a reader never has to know; the flag is kept
       * because an encoder must reproduce it. */
      int has_length;
      const uint8_t *data;
      size_t length;
    } stream;

    struct {
      uint64_t token_length;
      const uint8_t *token;
      size_t length;
    } new_token;

    struct {
      uint64_t id;
      uint64_t application_error_code;
      uint64_t final_size;
    } reset_stream;

    struct {
      uint64_t id;
      uint64_t application_error_code;
      uint64_t final_size;
      uint64_t reliable_size;
    } reset_stream_at;

    struct {
      uint64_t id;
      uint64_t application_error_code;
    } stop_sending;

    struct {
      uint64_t maximum;
    } max_data;

    struct {
      uint64_t id;
      uint64_t maximum;
    } max_stream_data;

    struct {
      wt_quic_stream_direction_t direction;
      uint64_t maximum;
    } max_streams;

    struct {
      uint64_t maximum;
    } data_blocked;

    struct {
      uint64_t id;
      uint64_t offset;
    } stream_data_blocked;

    struct {
      wt_quic_stream_direction_t direction;
      uint64_t maximum;
    } streams_blocked;

    struct {
      uint64_t sequence;
      uint64_t retire_prior_to;
      const uint8_t *connection_id;
      size_t connection_id_length;
      /* The 16-byte token, a view. RFC 9000 section 19.15 gives it a fixed
       * length, so there is no length field. */
      const uint8_t *stateless_reset_token;
    } new_connection_id;

    struct {
      uint64_t sequence;
    } retire_connection_id;

    struct {
      const uint8_t *data; /* WT_QUIC_PATH_CHALLENGE_LENGTH bytes */
    } path_challenge;

    struct {
      const uint8_t *data; /* WT_QUIC_PATH_CHALLENGE_LENGTH bytes */
    } path_response;

    struct {
      /* The application close form carries no frame type, and the transport form
       * does; `has_frame_type` is what tells a reader which it is, since a
       * frame_type of 0 is a legitimate value. */
      int has_frame_type;
      uint64_t error_code;
      uint64_t frame_type;
      const uint8_t *reason;
      size_t reason_length;
    } connection_close;

    struct {
      const uint8_t *data;
      size_t length;
    } datagram;

    /* PADDING, PING and HANDSHAKE_DONE carry nothing, and a union with no
     * members would be a GCC extension, so they share this: a frame that says
     * it carries nothing carries nothing. */
    struct {
      int unused;
    } none;
  } as;
} wt_quic_frame_t;

/* Parse one frame from `c`, advancing past it. Returns WT_OK, or a status:
 *
 *   WT_ERR_TRUNCATED  the cursor ran out; the frame may be well formed and the
 *                     rest of it simply has not arrived, which for a
 *                     stream-oriented protocol is ordinary.
 *   WT_ERR_PROTOCOL   the frame is malformed or its type is unknown. RFC 9000
 *                     section 12.4 makes an unknown frame type a
 *                     FRAME_ENCODING_ERROR rather than something to skip.
 *
 * `out_error` is set to the transport error code the connection should close
 * with. It is written on failure and on WT_OK it is left alone, because a
 * successful parse has no error to report.
 *
 * WHY THE ERROR CODE IS AN OUT-PARAMETER RATHER THAN THE RETURN VALUE: the
 * status says how the call went, which is what a caller's control flow needs;
 * the code says what to tell the peer, which is what the close path needs. A
 * caller that ignores the code still gets a correct refusal, and one that
 * reports it gets the RFC's code rather than a generic one. */
wt_status_t wt_quic_frame_decode(wt_cursor_t *c, wt_quic_frame_t *out,
                                 wt_quic_error_t *out_error);

/* Parse every frame in a buffer. Calls `visit` for each in order, stopping at
 * the first refusal and returning it. The visitor returns WT_OK to continue or
 * any other status to stop, which is how a caller that has seen enough -- a
 * connection close, say -- ends the walk without the parser knowing why.
 *
 * The frames share one structure that is reused for each call, so a visitor
 * that needs to keep a frame must copy what it needs. */
typedef wt_status_t (*wt_quic_frame_visitor_fn)(void *context,
                                                const wt_quic_frame_t *frame);

wt_status_t wt_quic_frames_decode(const uint8_t *data, size_t length,
                                  wt_quic_frame_visitor_fn visit, void *context,
                                  wt_quic_error_t *out_error);

/* Decode the ACK range at `index`, which must be below the frame's
 * `range_count`. Returns WT_ERR_INVALID_ARGUMENT for an index past the end.
 *
 * The cost is a walk from the start of the range list, because the ranges are
 * kept as wire bytes rather than decoded into an array -- the alternative is an
 * allocation sized by a peer-controlled count. A caller that walks every range
 * pays quadratic time in the number of ranges, which is why the frames decoder
 * hands the whole frame to a visitor that can walk the list once; this accessor
 * is for a caller that wants one range. */
wt_status_t wt_quic_frame_ack_range_at(const wt_quic_frame_t *frame,
                                       uint64_t index,
                                       wt_quic_ack_range_t *out);

/* Encode a frame through a writer. Returns WT_OK, or WT_ERR_INVALID_ARGUMENT
 * for a field the frame's own rules forbid -- a RESET_STREAM_AT whose reliable
 * size exceeds its final size, a connection ID of length 0 or above 20, a
 * NEW_TOKEN with an empty token. Refusing to encode a frame this library would
 * refuse to decode is deliberate: a library that can produce a message it
 * cannot read has a defect that shows up as an interoperability failure.
 *
 * On a measuring writer the same call counts, so a caller sizes a buffer with
 * the same code that fills it. Check wt_writer_ok afterwards. */
wt_status_t wt_quic_frame_encode(wt_writer_t *w, const wt_quic_frame_t *frame);

/* Fill a frame structure with a type and nothing else, for an encoder that is
 * written at the call site:
 *
 *   wt_quic_frame_t frame = wt_quic_frame_make(WT_QUIC_FRAME_KIND_MAX_DATA);
 *   frame.as.max_data.maximum = limit;
 *
 * The whole structure is cleared, so every byte of a frame is defined and a
 * caller may copy, compare or log one without reading indeterminate memory --
 * including the union members the kind does not use. The same is true of a frame
 * the parser produces. That costs a memset of about 150 bytes per frame, against
 * a packet decryption that is orders of magnitude more, and it is the difference
 * between a value type and a trap. */
wt_quic_frame_t wt_quic_frame_make(wt_quic_frame_type_t kind);

/* A short stable name for a frame kind: "padding", "stream", and so on. Never
 * NULL. */
const char *wt_quic_frame_kind_name(wt_quic_frame_type_t kind);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_QUIC_FRAME_H */
