/* WebTransport C99: the logging surface.
 *
 * The library never writes to a stream, a file or stderr. It hands a message to
 * a callback the caller supplied, and does nothing at all when that callback is
 * absent -- which is the default, and is why a library that is linked into a
 * process cannot surprise it with output.
 *
 * WHAT IS DELIBERATELY NOT HERE: formatted output. There is no
 * wt_log_writef(logger, "peer sent %s", peer_data). The plan forbids sensitive
 * protocol data in logs, and a printf-shaped surface makes that a rule someone
 * has to remember at every call site. A message here is a fixed string chosen by
 * this library, or a caller's own text; a value from the wire reaches a log only
 * if a caller deliberately formats it into its own message, where the decision
 * is visible in the caller's code.
 *
 * The levels are ordered, and a logger has a threshold: a message below it is
 * dropped before the callback is called, so a caller that installs a callback in
 * production pays nothing for debug messages that are never wanted.
 */

#ifndef WEBTRANSPORT_LOG_H
#define WEBTRANSPORT_LOG_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum wt_log_level {
  /* Something is wrong and the operation failed. */
  WT_LOG_ERROR = 0,
  /* Something is wrong and was recovered from, or a limit is close. */
  WT_LOG_WARN = 1,
  /* Connection-level lifecycle: a handshake completed, a session closed. */
  WT_LOG_INFO = 2,
  /* Protocol detail, off by default. Never carries key material, packet bytes,
   * datagrams, connection IDs or close messages. */
  WT_LOG_DEBUG = 3
} wt_log_level_t;

typedef void (*wt_log_fn)(void *context, wt_log_level_t level,
                          const char *message);

typedef struct wt_logger {
  void *context;
  wt_log_fn fn;
  wt_log_level_t level;
} wt_logger_t;

/* A logger that emits nothing. Returning a value rather than a pointer keeps a
 * caller from having to decide who frees it. */
wt_logger_t wt_logger_none(void);

/* A logger that calls `fn(context, level, message)` for messages at or above
 * `level`. A NULL `fn` is the same as wt_logger_none. */
wt_logger_t wt_logger_to(wt_log_fn fn, void *context, wt_log_level_t level);

/* Emit `message`, which must be a NUL-terminated string, if the logger's level
 * admits it. `message` is never NULL when this returns. Safe on a NULL logger or
 * one with no callback: nothing happens. */
void wt_log_emit(const wt_logger_t *logger, wt_log_level_t level,
                 const char *message);

/* Whether a message at `level` would reach the callback. For a caller that would
 * otherwise build a string to throw it away. */
int wt_log_enabled(const wt_logger_t *logger, wt_log_level_t level);

/* A short stable name for a level: "error", "warn", "info", "debug". Never
 * NULL, including for a value that is not a level. */
const char *wt_log_level_name(wt_log_level_t level);

#ifdef __cplusplus
}
#endif

#endif /* WEBTRANSPORT_LOG_H */
