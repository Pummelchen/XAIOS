#ifndef XAIOS_KLOG_RING_H
#define XAIOS_KLOG_RING_H

#include <xaios/status.h>
#include <xaios/types.h>

typedef enum xaios_log_level {
  XAIOS_LOG_DEBUG = 0,
  XAIOS_LOG_INFO = 1,
  XAIOS_LOG_WARN = 2,
  XAIOS_LOG_ERROR = 3,
  XAIOS_LOG_PANIC = 4,
} xaios_log_level_t;

#define XAIOS_KLOG_RING_SIZE UINT32_C(65536)
#define XAIOS_KLOG_LINE_MAX UINT32_C(256)
#define XAIOS_KLOG_FLUSH_MAX UINT32_C(8192)

/* Start in-memory capture. Safe to call as soon as klog works; depends on
   no other subsystem. */
void klog_ring_init(void);
/* Enable the persistent flush path once MutableFS is mounted. Capture is
   unaffected by this failing. */
xaios_status_t klog_ring_enable_persistence(void);
void klog_ring_write(const char *data, uint32_t length);
uint32_t klog_ring_read(char *out, uint32_t max_len);
uint32_t klog_ring_snapshot(char *out, uint32_t max_len,
                            uint64_t since_cursor, uint64_t *start_cursor,
                            uint64_t *next_cursor, uint64_t *latest_cursor);
/* Lock-free tail read, for the panic path only. May tear against a
   concurrent writer; every other reader should use klog_ring_snapshot. */
uint32_t klog_ring_panic_tail(char *out, uint32_t max_len);
void klog_ring_clear(void);
uint32_t klog_ring_count(void);
uint32_t klog_ring_overflow_count(void);
uint64_t klog_ring_total_written(void);

xaios_status_t klog_flush(void);
xaios_status_t klog_rotate(void);
uint64_t klog_persist_count(void);
uint64_t klog_rotate_count(void);
void klog_ring_self_test(void);

#endif
