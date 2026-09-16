/* WebTransport C99: status and error codes.
 *
 * Every public operation in this library returns a wt_status_t, and every
 * out-parameter is written only when the return value is WT_OK -- unless the
 * function's OWN documentation says otherwise, which three of them do on
 * purpose: `wt_udp_receive` and `wt_udp_peek` ZERO their length outputs on
 * every failure so a caller cannot read a stale length as a fresh one, and
 * `wt_buf_reserve_tail` may answer NULL for a zero-length request on an empty
 * buffer. A blanket rule that the exceptions contradict is worse than no rule,
 * so the rule is stated with them. That rule is
 * what lets a caller write
 *
 *     if (wt_buf_reserve(&buf, 16) != WT_OK) { ... }
 *
 * without also having to ask whether the buffer was modified, which is the
 * first thing that goes wrong in a language with no exceptions.
 *
 * The first seven values are the ones this project's C99 plan fixed as the
 * public shape, in that order, so that a caller compiled against an earlier
 * header keeps the meaning it was compiled with. The rest were added as the
 * protocol work needed to distinguish failures that a single "protocol error"
 * would have merged: a peer that sent a malformed frame, a caller that asked
 * for something before the state allowed it, and a resource limit that was
 * reached are three different problems with three different remedies.
 */

#ifndef WEBTRANSPORT_STATUS_H
#define WEBTRANSPORT_STATUS_H

#ifdef __cplusplus
extern "C" {
#endif

typedef enum wt_status {
  /* Success. Zero, so that a caller may test the result directly. */
  WT_OK = 0,

  /* A caller's argument is unusable: a NULL where a pointer is required, a
   * length that cannot be satisfied, a value outside its documented range.
   * Never returned for anything a peer sent. */
  WT_ERR_INVALID_ARGUMENT,

  /* An allocation failed. The allocator's own return value is the only source
   * of this, and it is never returned for a peer-controlled size that was
   * merely refused -- that is WT_ERR_LIMIT. */
  WT_ERR_OUT_OF_MEMORY,

  /* A deadline passed. Timeouts are the caller's or the connection's, never a
   * wall-clock date. */
  WT_ERR_TIMEOUT,

  /* The peer sent something this implementation refuses: a malformed frame, a
   * value outside its protocol range, an ordering the specification forbids.
   * The connection is unusable afterwards. */
  WT_ERR_PROTOCOL,

  /* The TLS layer refused, or reported that the handshake cannot continue.
   * Distinguished from WT_ERR_PROTOCOL because the remedy is a trust or
   * certificate question rather than a QUIC question. */
  WT_ERR_TLS,

  /* The connection, stream, or session is closed, either by this endpoint or
   * by the peer. Operations other than destroy and the close accessors fail
   * with this once it is set. */
  WT_ERR_CLOSED,

  /* Not an error, and deliberately not folded into WT_OK: the operation would
   * make progress but cannot right now -- an empty receive queue, a full send
   * buffer, a handshake waiting for the peer. A caller that treats this as a
   * failure is wrong, and a caller that ignores it in a loop will spin, so it
   * is named. */
  WT_ERR_AGAIN,

  /* A byte cursor ran out of input, or a writer ran out of room. Separate from
   * WT_ERR_PROTOCOL: the bytes may be perfectly well formed and simply not all
   * here yet, which for a stream-oriented protocol is the ordinary case. */
  WT_ERR_TRUNCATED,

  /* A configured limit was reached: a table is full, a buffer's bound was hit,
   * a peer asked for more than it is allowed. The limit is this
   * implementation's, not the peer's. */
  WT_ERR_LIMIT,

  /* An integer computation would have overflowed, or a narrowing conversion
   * would have lost bits. Checked arithmetic returns this rather than the
   * wrapped value, so a size derived from a peer's length fields can never
   * become the size of an allocation of the wrong size. */
  WT_ERR_OVERFLOW,

  /* The operation is not valid in the object's current state: a handshake step
   * out of order, a stream opened before the session, a close on something
   * already closed. */
  WT_ERR_STATE,

  /* The peer's identity was refused by the configured trust policy. Always the
   * result of a policy decision, never of an interactive prompt: this library
   * has none. */
  WT_ERR_TRUST,

  /* Something is not implemented or not compiled in. Returned rather than
   * asserted so that a caller on a platform without a feature can degrade
   * deliberately. */
  WT_ERR_UNSUPPORTED,

  /* An authentication tag did not verify. Deliberately not WT_ERR_PROTOCOL: the
   * bytes may be perfectly well formed and were simply not produced by the
   * holder of the key -- forged, or corrupted in transit, which is the ordinary
   * case on a lossy or hostile network rather than a violation of the protocol.
   * The authenticated data is discarded, never parsed. Added after the values
   * above so that a caller compiled against an earlier header keeps the meaning
   * it was compiled with. */
  WT_ERR_AUTHENTICATION,

  /* The platform refused an I/O operation for a reason this layer does not
   * classify. Added when the POSIX socket layer arrived: a syscall can fail for
   * reasons that are neither the caller's argument, nor the protocol, nor a
   * resource this library watches, and mapping those onto a name that means
   * something else would turn "the kernel said no" into a wrong diagnosis. A
   * caller that needs the reason asks the platform; a caller that needs to
   * classify has the specific statuses above. Appended for the same ABI reason
   * as WT_ERR_AUTHENTICATION. */
  WT_ERR_IO
} wt_status_t;

/* A short, stable, lower-case name for a status: "ok", "protocol", and so on.
 * For logs and diagnostics. Never NULL, including for a value that is not a
 * wt_status_t at all, which is answered with "unknown". */
const char *wt_status_name(wt_status_t status);

/* Whether the status represents a failure. WT_ERR_AGAIN is a failure in this
 * sense -- the operation did not happen -- which is why a caller must handle it
 * explicitly rather than testing for "not WT_OK". */
int wt_status_is_error(wt_status_t status);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_STATUS_H */
