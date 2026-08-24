#ifndef XAIOS_KLOG_H
#define XAIOS_KLOG_H

#include <xaios/boot_info.h>
#include <xaios/klog_ring.h>

typedef void (*xaios_klog_sink_t)(const char *data, uint64_t length);

void klog_init(const xaios_boot_info_t *boot);
/* Attach a second console for platforms with no UART. Bytes are delivered a
   line at a time. Passing 0 detaches. */
void klog_set_console_sink(xaios_klog_sink_t sink);
typedef int (*xaios_klog_source_t)(uint8_t *value);
/* Attach the matching input source. Passing 0 detaches. */
void klog_set_console_source(xaios_klog_source_t source);
void klog(const char *fmt, ...);
void klog_level(xaios_log_level_t level, const char *fmt, ...);
void klog_puts(const char *message);
void klog_write(const char *message, uint64_t length);
void klog_write_atomic(const char *message, uint64_t length);
void klog_console_set_log_output(uint32_t enabled);
void klog_console_write(const char *message, uint64_t length);
int klog_console_capture_begin(char *buffer, uint64_t capacity);
uint64_t klog_console_capture_end(void);
int klog_console_read_char(uint8_t *value);

#endif
