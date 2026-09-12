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
typedef int (*xaios_klog_poll_t)(void);
/* The source's peek: whether a read from it would return a byte. */
void klog_set_console_poll(xaios_klog_poll_t poll);
/* The format attribute is why a specifier that disagrees with its argument is
   a build failure rather than a diagnostic that lies at the moment it is read.
   panic_at has carried one since it was written; these two had not, so nothing
   checked them -- CodeQL found ten calls passing a 64-bit value to %u or a
   32-bit one to %lx, and the compiler found three more once told to look.

   It is asserted only for the freestanding build, and that is not a way of
   asking for less. `klog_vformat` reads %u and %x as unsigned, %lu and %lx as
   uint64_t, %d and %c as int, %s as a char pointer and %p as a void pointer.
   On all three kernel targets uint64_t is unsigned long, so the attribute
   describes what the formatter implements exactly. On a hosted build uint64_t
   is unsigned long long instead, and the attribute would then report 39
   disagreements between two 64-bit types in the handful of kernel files
   `hosted-test` compiles -- every one a typing accident of the host's
   <stdint.h>, none of them a defect, and none of them a width the formatter
   reads differently.

   Nothing goes unchecked by this. Every kernel source is compiled freestanding
   by `compile-check` on aarch64, x86_64 and riscv64, which is where the
   assertion belongs and where it now runs. */
#if defined(__STDC_HOSTED__) && __STDC_HOSTED__ == 1
#define XAIOS_KLOG_FORMAT(fmt_index, first_variadic)
#else
#define XAIOS_KLOG_FORMAT(fmt_index, first_variadic) \
  __attribute__((format(printf, fmt_index, first_variadic)))
#endif
void klog(const char *fmt, ...) XAIOS_KLOG_FORMAT(1, 2);
void klog_level(xaios_log_level_t level, const char *fmt, ...)
    XAIOS_KLOG_FORMAT(2, 3);
void klog_puts(const char *message);
void klog_write(const char *message, uint64_t length);
void klog_write_atomic(const char *message, uint64_t length);
void klog_console_set_log_output(uint32_t enabled);
void klog_console_write(const char *message, uint64_t length);
int klog_console_capture_begin(char *buffer, uint64_t capacity);
uint64_t klog_console_capture_end(void);
int klog_console_read_char(uint8_t *value);
/* Whether klog_console_read_char would return a byte, from any of the
   places it reads, without taking it. */
int klog_console_input_pending(void);

#endif
