/* The HTTP/3 driver's transport, bound to a real QUIC connection. */

#include <string.h>

#include "webtransport/http3/driver.h"
#include "webtransport/quic/connection.h"
#include "webtransport/quic/stream.h"

static wt_status_t quic_open_stream(void *context, int bidirectional, uint64_t *out_stream_id,
                                   uint64_t now) {
  (void)now;
  /* The connection's own limits decide whether a stream may be opened, and they are the
   * peer's SETTINGS: refusing here is not this layer's business. */
  return wt_quic_connection_open_stream((wt_quic_connection_t *)context, bidirectional,
                                        out_stream_id);
}

static wt_status_t quic_send_stream(void *context, uint64_t stream_id, const uint8_t *data,
                                   size_t length, int fin, uint64_t now) {
  wt_quic_connection_t *connection = context;
  wt_quic_stream_t *stream = wt_quic_connection_stream(connection, stream_id);
  uint64_t offset;

  if (stream == NULL) {
    /* A stream this connection does not know: the caller's accounting, and the connection's
     * own open call is the only way one comes to exist. */
    return WT_ERR_STATE;
  }
  /* Where the stream is, from the stream itself: an adapter that tracked its own offsets
   * would be a second opinion about a number the connection already owns. */
  offset = stream->send_offset;
  {
    wt_status_t status = wt_quic_connection_send_stream(connection, stream_id, offset, data, length,
                                                        fin, now);
    if (status != WT_OK) return status;
  }

  /* RECORDING THE SEND IS THE CALLER'S, and it is not bookkeeping this layer may skip: the connection
   * writes the frame and leaves the stream's `send_offset` and final size to whoever asked for the send
   * (`wt_quic_stream_on_data_sent`: "the caller has already had the frame written, so this records it").
   * Without it the stream never learns it has data, the NEXT send goes at the same offset, and the peer
   * sees a stream whose offsets repeat -- which is a protocol error, not a slow stream. */
  {
    wt_status_t status = wt_quic_stream_on_data_sent(stream, (uint64_t)length);
    if (status != WT_OK) return status;
  }
  if (fin != 0) return wt_quic_stream_on_fin_sent(stream);
  return WT_OK;
}

static wt_status_t quic_send_datagram(void *context, const uint8_t *data, size_t length) {
  /* A datagram has no stream state and no offset: it is one unit, which is why QUIC's
   * DATAGRAM frame has no retransmission either. */
  return wt_quic_connection_send_datagram((wt_quic_connection_t *)context, data, length, 0U);
}

void wt_http3_driver_quic_transport(wt_quic_connection_t *connection,
                                    wt_http3_driver_transport_t *out_transport) {
  if (out_transport == NULL) return;
  memset(out_transport, 0, sizeof(*out_transport));
  out_transport->open_stream = quic_open_stream;
  out_transport->send_stream = quic_send_stream;
  out_transport->send_datagram = quic_send_datagram;
  out_transport->context = connection;
}
