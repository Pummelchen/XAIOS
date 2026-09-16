/* The logging surface. See webtransport/log.h. */

#include "webtransport/log.h"

wt_logger_t wt_logger_none(void) {
  wt_logger_t logger;
  logger.context = NULL;
  logger.fn = NULL;
  /* The threshold is the bottom of the range, so that wt_log_enabled on a
   * logger with no callback answers for the callback's absence and not for a
   * level that happens to be high. */
  logger.level = WT_LOG_ERROR;
  return logger;
}

wt_logger_t wt_logger_to(wt_log_fn fn, void *context, wt_log_level_t level) {
  wt_logger_t logger;
  logger.context = context;
  logger.fn = fn;
  logger.level = level;
  return logger;
}

int wt_log_enabled(const wt_logger_t *logger, wt_log_level_t level) {
  if (logger == NULL || logger->fn == NULL) return 0;
  /* Ordinal comparison, so a level added below the current threshold is
   * admitted automatically and one added above it is not. */
  return (int)level <= (int)logger->level;
}

void wt_log_emit(const wt_logger_t *logger, wt_log_level_t level,
                 const char *message) {
  if (message == NULL) return;
  if (!wt_log_enabled(logger, level)) return;
  /* The callback is invoked with the level this library chose, so a caller that
   * routes by level does not have to re-derive it. */
  logger->fn(logger->context, level, message);
}

const char *wt_log_level_name(wt_log_level_t level) {
  switch (level) {
    case WT_LOG_ERROR:
      return "error";
    case WT_LOG_WARN:
      return "warn";
    case WT_LOG_INFO:
      return "info";
    case WT_LOG_DEBUG:
      return "debug";
    default:
      return "unknown";
  }
}
