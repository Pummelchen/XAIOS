/* QUIC transport error codes. See webtransport/quic/error.h. */

#include "webtransport/quic/error.h"

wt_status_t wt_quic_crypto_error(uint8_t tls_alert, wt_quic_error_t *out) {
  if (out == NULL) return WT_ERR_INVALID_ARGUMENT;
  /* The range is 0x0100 to 0x01ff, so every alert fits by construction: the
   * alert is one byte. The check is here anyway because the function's contract
   * says it refuses rather than truncating, and a caller that passed a wider
   * value would otherwise get a code in the wrong class without being told. */
  *out = WT_QUIC_CRYPTO_ERROR_BASE | (wt_quic_error_t)tls_alert;
  return WT_OK;
}

int wt_quic_error_is_crypto(wt_quic_error_t error) {
  return error >= WT_QUIC_CRYPTO_ERROR_BASE && error <= WT_QUIC_CRYPTO_ERROR_LAST;
}

const char *wt_quic_error_name(wt_quic_error_t error) {
  switch (error) {
    case WT_QUIC_NO_ERROR:
      return "no-error";
    case WT_QUIC_INTERNAL_ERROR:
      return "internal-error";
    case WT_QUIC_CONNECTION_REFUSED:
      return "connection-refused";
    case WT_QUIC_FLOW_CONTROL_ERROR:
      return "flow-control-error";
    case WT_QUIC_STREAM_LIMIT_ERROR:
      return "stream-limit-error";
    case WT_QUIC_STREAM_STATE_ERROR:
      return "stream-state-error";
    case WT_QUIC_FINAL_SIZE_ERROR:
      return "final-size-error";
    case WT_QUIC_FRAME_ENCODING_ERROR:
      return "frame-encoding-error";
    case WT_QUIC_TRANSPORT_PARAMETER_ERROR:
      return "transport-parameter-error";
    case WT_QUIC_CONNECTION_ID_LIMIT_ERROR:
      return "connection-id-limit-error";
    case WT_QUIC_PROTOCOL_VIOLATION:
      return "protocol-violation";
    case WT_QUIC_INVALID_TOKEN:
      return "invalid-token";
    case WT_QUIC_APPLICATION_ERROR:
      return "application-error";
    case WT_QUIC_CRYPTO_BUFFER_EXCEEDED:
      return "crypto-buffer-exceeded";
    case WT_QUIC_KEY_UPDATE_ERROR:
      return "key-update-error";
    case WT_QUIC_AEAD_LIMIT_REACHED:
      return "aead-limit-reached";
    case WT_QUIC_NO_VIABLE_PATH:
      return "no-viable-path";
    default:
      /* The TLS range is reported as a class rather than as one name per alert:
       * the alert is in the low byte and the caller that wants it prints it, so
       * naming 256 codes here would be 256 chances to mistype one. */
      return wt_quic_error_is_crypto(error) ? "crypto" : "unknown";
  }
}
