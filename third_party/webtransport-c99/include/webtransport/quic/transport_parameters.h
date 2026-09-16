/* QUIC transport parameters (RFC 9000 section 18).
 *
 * A transport parameter is a varint identifier, a varint length and that many
 * bytes of value. The set is carried in a TLS extension, so its framing is TLS's
 * business and its contents are QUIC's: a peer may send a parameter this build
 * does not model, and RFC 9000 section 7.4.2 requires an unknown one to be
 * IGNORED rather than refused, which is why this parser refuses only framing
 * errors and duplicates and leaves the value rules to an opt-in check.
 *
 * THAT SPLIT IS THE DESIGN. `wt_quic_transport_parameters_decode` validates what
 * every peer must get right -- the encoding, and that no identifier appears
 * twice, which RFC 9000 section 7.4 makes a TRANSPORT_PARAMETER_ERROR. Separately,
 * `wt_quic_transport_parameters_check` applies the rules of section 18.2 that a
 * caller who wants the connection-error judgement asks for: a maximum UDP
 * payload below 1200, an ack delay exponent above 20, an active connection ID
 * limit below 2, a stateless reset token that is not sixteen bytes, a connection
 * ID above twenty. A parser that raised PROTOCOL_VIOLATION for those on its own
 * would make the extension parser refuse messages the TLS layer must accept and
 * hand to QUIC to judge.
 *
 * The parameters are kept as a bounded array of views, sorted by identifier, so
 * a lookup is a binary search and nothing is allocated. A peer-controlled count
 * cannot make this parser allocate, which is the rule the plan sets for every
 * parser here.
 */

#ifndef WEBTRANSPORT_QUIC_TRANSPORT_PARAMETERS_H
#define WEBTRANSPORT_QUIC_TRANSPORT_PARAMETERS_H

#include <stddef.h>
#include <stdint.h>

#include "webtransport/quic/error.h"
#include "webtransport/quic/varint.h"
#include "webtransport/status.h"
#include "webtransport/writer.h"

#ifdef __cplusplus
extern "C" {
#endif

/* The parameter identifiers of RFC 9000 section 18.2, plus the two from RFC 9221
 * and RFC 9368 that a WebTransport endpoint uses. */
#define WT_QUIC_TP_ORIGINAL_DESTINATION_CONNECTION_ID ((uint64_t)0x00)
#define WT_QUIC_TP_MAX_IDLE_TIMEOUT ((uint64_t)0x01)
#define WT_QUIC_TP_STATELESS_RESET_TOKEN ((uint64_t)0x02)
#define WT_QUIC_TP_MAX_UDP_PAYLOAD_SIZE ((uint64_t)0x03)
#define WT_QUIC_TP_INITIAL_MAX_DATA ((uint64_t)0x04)
#define WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_LOCAL ((uint64_t)0x05)
#define WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_BIDI_REMOTE ((uint64_t)0x06)
#define WT_QUIC_TP_INITIAL_MAX_STREAM_DATA_UNI ((uint64_t)0x07)
#define WT_QUIC_TP_INITIAL_MAX_STREAMS_BIDI ((uint64_t)0x08)
#define WT_QUIC_TP_INITIAL_MAX_STREAMS_UNI ((uint64_t)0x09)
#define WT_QUIC_TP_ACK_DELAY_EXPONENT ((uint64_t)0x0a)
#define WT_QUIC_TP_MAX_ACK_DELAY ((uint64_t)0x0b)
#define WT_QUIC_TP_DISABLE_ACTIVE_MIGRATION ((uint64_t)0x0c)
#define WT_QUIC_TP_PREFERRED_ADDRESS ((uint64_t)0x0d)
#define WT_QUIC_TP_ACTIVE_CONNECTION_ID_LIMIT ((uint64_t)0x0e)
/* The reliable-stream-reset extension's parameter, which WebTransport over HTTP/3 REQUIRES of both roles
 * (draft-ietf-webtrans-http3-16 section 3.1) because a WebTransport stream's prefix must be delivered even when
 * the stream is reset: `reset_stream_at`. Its value is EMPTY -- it is a flag, and a peer that understands it must
 * treat a non-empty value as TRANSPORT_PARAMETER_ERROR (draft-ietf-quic-reliable-stream-reset, "Negotiating
 * Extension Use"). The identifier is the REGISTERED one, 0x1d (draft-ietf-quic-reliable-stream-reset-09 section
 * 8.1); the pre-registration value 0x17f7586d2cb570 this tree once advertised is greased, not registered, and a
 * conforming draft-16 peer that looks for 0x1d never saw the extension. */
#define WT_QUIC_TP_RESET_STREAM_AT ((uint64_t)0x1d)
#define WT_QUIC_TP_INITIAL_SOURCE_CONNECTION_ID ((uint64_t)0x0f)
#define WT_QUIC_TP_RETRY_SOURCE_CONNECTION_ID ((uint64_t)0x10)
/* RFC 9221 section 3. */
#define WT_QUIC_TP_MAX_DATAGRAM_FRAME_SIZE ((uint64_t)0x20)
/* RFC 9368 section 3, which WebTransport's datagrams depend on. */
#define WT_QUIC_TP_GREASE_QUIC_BIT ((uint64_t)0x2ab2)

/* The default maximum UDP payload RFC 9000 section 18.2 gives for a peer that
 * does not send the parameter: 65527, the largest a UDP datagram can carry. */
#define WT_QUIC_DEFAULT_MAX_UDP_PAYLOAD_SIZE ((uint64_t)65527)
/* The smallest a peer may advertise, RFC 9000 section 18.2. */
#define WT_QUIC_MIN_MAX_UDP_PAYLOAD_SIZE ((uint64_t)1200)
/* The plan's bound on how many parameters are kept. RFC 9000 defines seventeen
 * and a peer may add unknown ones; 32 leaves room for those without letting a
 * peer decide how much memory this parser uses. A message with more than this is
 * refused as a PROTOCOL_VIOLATION rather than truncated, because a parameter
 * that is silently dropped is a limit the peer is not told about. */
#define WT_QUIC_MAX_TRANSPORT_PARAMETERS 32U

typedef struct wt_quic_transport_parameter {
  uint64_t id;
  /* A view into the extension's bytes. */
  const uint8_t *value;
  size_t length;
} wt_quic_transport_parameter_t;

typedef struct wt_quic_transport_parameters {
  wt_quic_transport_parameter_t entries[WT_QUIC_MAX_TRANSPORT_PARAMETERS];
  /* Storage for the values an integer parameter is encoded into by
   * `wt_quic_transport_parameters_add_integer`. A parameter's value is a view,
   * so an integer this library encodes has to live somewhere the structure owns;
   * eight bytes is the longest a varint can be, and one slot per parameter is
   * the most that can be needed. A byte-valued parameter added with
   * `add_bytes` uses the caller's bytes instead, which is why this is not the
   * only way a value can be stored. */
  uint8_t integer_storage[WT_QUIC_MAX_TRANSPORT_PARAMETERS * 8U];
  size_t integer_slots_used;
  size_t count;
  /* Set when the list arrived sorted by identifier, which is what an encoder
   * here produces and what makes a duplicate detectable in one pass. A list that
   * is not sorted is still valid on the wire -- RFC 9000 section 18 does not
   * order the parameters -- so the count is what a lookup scans when this is
   * clear. */
  int sorted;
} wt_quic_transport_parameters_t;

/* Parse the contents of a transport-parameters extension: a sequence of
 * identifier, length, value. Returns WT_OK, or a status:
 *
 *   WT_ERR_TRUNCATED   a parameter's declared length runs past the end.
 *   WT_ERR_PROTOCOL    a duplicate identifier, or more parameters than the
 *                      structure holds. `out_error` is set to
 *                      TRANSPORT_PARAMETER_ERROR, which is the code RFC 9000
 *                      section 7.4 requires for both.
 *
 * An unknown identifier is kept, not refused: RFC 9000 section 7.4.2 requires it
 * to be ignored, and ignoring it means a caller can see it and choose. */
wt_status_t wt_quic_transport_parameters_decode(
    const uint8_t *data, size_t length, wt_quic_transport_parameters_t *out,
    wt_quic_error_t *out_error);

/* Look a parameter up by identifier. Returns WT_OK and writes the value and its
 * length when the parameter is present, or WT_ERR_INVALID_ARGUMENT when it is
 * absent.
 *
 * PRESENCE IS THE STATUS, NOT THE POINTER. A parameter may legitimately have a
 * zero-length value -- `disable_active_migration` is exactly that -- and a
 * function that answered with a pointer could not distinguish "the peer sent
 * this with an empty value" from "the peer did not send this". The first version
 * of this API made that mistake, and the check for
 * `original_destination_connection_id` passed an empty value as absent: an
 * endpoint could have advertised a zero-length original destination connection
 * ID, which RFC 9000 section 7.2 forbids, and the check would not have seen
 * it. */
wt_status_t wt_quic_transport_parameters_get(
    const wt_quic_transport_parameters_t *params, uint64_t id,
    const uint8_t **out_value, size_t *out_length);

/* The same, for a parameter whose value is a varint. Returns WT_OK and the
 * value, WT_ERR_TRUNCATED when the value is not a varint, or
 * WT_ERR_INVALID_ARGUMENT when the parameter is absent -- absent and zero are
 * different answers, so they are different statuses. */
wt_status_t wt_quic_transport_parameters_integer(
    const wt_quic_transport_parameters_t *params, uint64_t id, uint64_t *out);

/* The rules of RFC 9000 section 18.2 that make a parameter an error rather than
 * something to ignore. Returns WT_OK, or WT_ERR_PROTOCOL with `out_error` set to
 * TRANSPORT_PARAMETER_ERROR and `out_offender` set to the identifier at fault
 * when one is.
 *
 * `peer_is_client` is which ROLE sent the list, and it is explicit because one
 * of the rules depends on it: `stateless_reset_token` is valid only for a
 * server, and a server MUST treat receipt of one as TRANSPORT_PARAMETER_ERROR.
 * A caller that does not know the sending role passes 0, which leaves that one
 * rule out -- every other rule here is independent of who sent the list. */
wt_status_t wt_quic_transport_parameters_check(
    const wt_quic_transport_parameters_t *params, int peer_is_client,
    wt_quic_error_t *out_error, uint64_t *out_offender);

/* Encode a parameter list through a writer. The entries are written in the order
 * given, and a caller building one should use
 * `wt_quic_transport_parameters_add_integer` to fill the structure, which keeps
 * it sorted.
 *
 * A duplicate identifier is refused: a library that can emit a message it would
 * refuse to read has a defect, and RFC 9000 section 7.4 makes a duplicate a
 * connection error. */
wt_status_t wt_quic_transport_parameters_encode(
    wt_writer_t *w, const wt_quic_transport_parameters_t *params);

/* Build a parameter list. Empty it first with
 * `wt_quic_transport_parameters_init`. */
void wt_quic_transport_parameters_init(wt_quic_transport_parameters_t *params);

/* Add an integer-valued parameter, which is encoded into storage the structure
 * owns so the caller does not have to keep the bytes. Refuses a duplicate
 * identifier and a list that is full. Keeps the list sorted by identifier, so a
 * lookup is a binary search and a duplicate is found by the check. */
wt_status_t wt_quic_transport_parameters_add_integer(
    wt_quic_transport_parameters_t *params, uint64_t id, uint64_t value);

/* Add a byte-valued parameter, whose bytes must outlive the list. */
wt_status_t wt_quic_transport_parameters_add_bytes(
    wt_quic_transport_parameters_t *params, uint64_t id, const uint8_t *value,
    size_t length);

/* The parameter list an endpoint MUST send (RFC 9000 section 7.3), built in ONE place so a caller cannot leave
 * a mandatory parameter out.
 *
 * A client sends `initial_source_connection_id`, set to the Source Connection ID it uses in its Initial packets.
 * A server sends that too, AND `original_destination_connection_id`, set to the Destination Connection ID the
 * client's first Initial carried. A peer that receives neither is entitled to close with
 * TRANSPORT_PARAMETER_ERROR -- which is exactly what aioquic did to this client, and the reason this function
 * exists: two callers built the block by hand, both omitted the parameter, and only a peer this project shares
 * no code with could name the omission (WT-141).
 *
 * `is_server` is explicit rather than inferred from a NULL: a server that forgets its original destination ID
 * must be refused here, not treated as a client. The limits this library advertises are added too, so two
 * callers cannot drift apart about them either.
 *
 * `retry_source_connection_id` is the one parameter a server sends ONLY when it sent a Retry (RFC 9000 section
 * 7.3), set to the Source Connection ID of the Retry packet -- the connection ID the client's next Initial was
 * addressed to. `retried` says which case this is, because the two mistakes are opposite and both are close
 * errors: a server that retried and omits the parameter is refused by a checking client, and a server that did
 * not retry and sends one is refused just the same ("if a server sends a Retry packet, ... the server MUST also
 * send the retry_source_connection_id transport parameter", and section 7.3 makes a present one without a Retry
 * a TRANSPORT_PARAMETER_ERROR on the client). */
wt_status_t wt_quic_transport_parameters_build(wt_quic_transport_parameters_t *params, int is_server,
                                               const uint8_t *source_connection_id, size_t source_length,
                                               const uint8_t *original_destination_connection_id,
                                               size_t original_length, int retried,
                                               const uint8_t *retry_source_connection_id,
                                               size_t retry_source_length);

/* A short stable name for the identifiers above, or "unknown". Never NULL. */
const char *wt_quic_transport_parameter_name(uint64_t id);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_QUIC_TRANSPORT_PARAMETERS_H */
