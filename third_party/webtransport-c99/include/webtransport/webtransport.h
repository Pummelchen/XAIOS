/* The one header a consumer of this library includes.
 *
 * It pulls in every public module and states the three rules that hold across all of
 * them, because each of those rules is a place where a caller's mistake would otherwise
 * look like a protocol error from the peer:
 *
 *   - **Nothing is allocated for a peer.** Every table, buffer and queue has a bound this
 *     endpoint chose, and a peer that exceeds one is refused -- with a code that says the
 *     bound was reached, never with a peer error. The two are told apart in the status
 *     and in the error code, and a caller that conflates them will close connections over
 *     its own limits.
 *   - **Incomplete is not malformed on a stream.** A stream delivers its units in pieces,
 *     so a partial frame, a partial instruction, a partial capsule or a partial prefix is
 *     WT_ERR_TRUNCATED with no error code, and the caller that sees the stream END
 *     mid-unit is what reports the error. A packet is the exception: a datagram IS the
 *     unit, so anything short is malformed.
 *   - **A refusal that came from the peer keeps the peer's code.** RFC 9000's transport
 *     codes, RFC 9114's H3_* codes and RFC 9204's QPACK codes all travel as QUIC
 *     application error codes, and this library does not rewrite them: a caller reports
 *     what the peer said.
 *
 * The layers are, from the wire inward: `quic/` (frames, packets, protection, the
 * connection runtime), `tls/` and `crypto/` (the handshake and the primitives it needs),
 * `http3/` (frames, streams, QPACK, messages) and `webtransport/` (the draft-16 session:
 * its request, its capsules, its lifecycle and its framing). A consumer that wants only
 * one layer may include that layer's header instead; this one exists so that the whole
 * surface is reachable from one place, and so that the order of the layers is written
 * down.
 *
 * Ownership is uniform: a function that produces bytes writes into a caller-supplied
 * buffer, and a function that reads returns views INTO THE CALLER'S BYTES. Nothing here
 * owns memory, so nothing here frees it, and no view outlives the buffer it points into.
 */

#ifndef WEBTRANSPORT_WEBTRANSPORT_H
#define WEBTRANSPORT_WEBTRANSPORT_H

#include "webtransport/version.h"

/* The core: status, checked arithmetic, byte order, cursors, writers, buffers,
 * allocators, logging and time. */
#include "webtransport/allocator.h"
#include "webtransport/buffer.h"
#include "webtransport/checked.h"
#include "webtransport/cursor.h"
#include "webtransport/endian.h"
#include "webtransport/log.h"
#include "webtransport/status.h"
#include "webtransport/time.h"
#include "webtransport/writer.h"

/* The crypto primitives and the TLS 1.3 handshake that runs over QUIC's CRYPTO
 * stream. */
#include "webtransport/crypto/crypto.h"
#include "webtransport/tls/extension.h"
#include "webtransport/tls/handshake.h"
#include "webtransport/tls/keyschedule.h"
#include "webtransport/tls/keyshare.h"
#include "webtransport/tls/session.h"
#include "webtransport/tls/trust.h"

/* QUIC: the wire core and the connection runtime. */
#include "webtransport/quic/close.h"
#include "webtransport/quic/congestion.h"
#include "webtransport/quic/connection.h"
#include "webtransport/quic/connection_id.h"
#include "webtransport/quic/crypto_stream.h"
#include "webtransport/quic/datagram.h"
#include "webtransport/quic/error.h"
#include "webtransport/quic/frame.h"
#include "webtransport/quic/handshake.h"
#include "webtransport/quic/loss.h"
#include "webtransport/quic/packet.h"
#include "webtransport/quic/packet_io.h"
#include "webtransport/quic/packet_number.h"
#include "webtransport/quic/pn_space.h"
#include "webtransport/quic/protection.h"
#include "webtransport/quic/stream.h"
#include "webtransport/quic/transport_parameters.h"
#include "webtransport/quic/varint.h"

/* The UDP runtime, which is the only place this library touches the operating
 * system. */
#include "webtransport/runtime/udp.h"

/* HTTP/3, including QPACK. */
#include "webtransport/http3/control.h"
#include "webtransport/http3/driver.h"
#include "webtransport/http3/endpoint.h"
#include "webtransport/http3/frame.h"
#include "webtransport/http3/goaway.h"
#include "webtransport/http3/headers.h"
#include "webtransport/http3/message.h"
#include "webtransport/http3/qpack.h"
#include "webtransport/http3/request.h"
#include "webtransport/http3/role.h"
#include "webtransport/http3/settings.h"
#include "webtransport/http3/streams.h"

/* The draft-16 WebTransport session layer. */
#include "webtransport/webtransport/capsule.h"
#include "webtransport/webtransport/framing.h"
#include "webtransport/webtransport/session.h"
#include "webtransport/webtransport/session_request.h"

/* The public consumer API. It comes last because it is the layer a program is written
 * against rather than a layer this library is written in: everything above it is the
 * machinery it turns into `create`, feed and callback. */
#include "webtransport/api/endpoint.h"
#include "webtransport/api/events.h"
#include "webtransport/api/flow.h"
#include "webtransport/api/session.h"

#endif /* WEBTRANSPORT_WEBTRANSPORT_H */
