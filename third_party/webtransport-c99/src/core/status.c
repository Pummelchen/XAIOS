/* Status names and classification. See webtransport/status.h. */

#include "webtransport/status.h"

const char *wt_status_name(wt_status_t status) {
  switch (status) {
    case WT_OK:
      return "ok";
    case WT_ERR_INVALID_ARGUMENT:
      return "invalid-argument";
    case WT_ERR_OUT_OF_MEMORY:
      return "out-of-memory";
    case WT_ERR_TIMEOUT:
      return "timeout";
    case WT_ERR_PROTOCOL:
      return "protocol";
    case WT_ERR_TLS:
      return "tls";
    case WT_ERR_CLOSED:
      return "closed";
    case WT_ERR_AGAIN:
      return "again";
    case WT_ERR_TRUNCATED:
      return "truncated";
    case WT_ERR_LIMIT:
      return "limit";
    case WT_ERR_OVERFLOW:
      return "overflow";
    case WT_ERR_STATE:
      return "state";
    case WT_ERR_TRUST:
      return "trust";
    case WT_ERR_UNSUPPORTED:
      return "unsupported";
    case WT_ERR_AUTHENTICATION:
      return "authentication";
    case WT_ERR_IO:
      return "io";
    default:
      /* A value that is not a status reaches here from a caller that cast
       * something else, or from a header mismatch across an ABI change. A name
       * is more useful than an assertion, because the caller is already in a
       * diagnostic path when it asks. */
      return "unknown";
  }
}

int wt_status_is_error(wt_status_t status) { return status != WT_OK; }
