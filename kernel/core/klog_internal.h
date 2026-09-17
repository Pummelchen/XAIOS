/* Private interface shared by klog.c, klog_console.c and klog_format.c.
 *
 * klog.c keeps the console lock and its contended-drop accounting, the panic
 * claim that makes the ordinary paths stand aside, the capture stack, the
 * public entry points (klog, klog_level, klog_puts, klog_write and
 * klog_write_atomic) and the console write path that takes the lock.
 * klog_console.c owns the byte transport: the UART register offsets and the
 * boot UART, the sink that stands in for a platform with no UART, the line
 * buffer the ring is fed from, and the input side that reads the same
 * console. klog_format.c owns the formatter the public entry points call.
 *
 * The formatter and the remaining console writers both need to emit one
 * character, and that is the only reason these symbols cross a translation
 * unit. Nothing here returns a pointer into file-scope state; a caller that
 * needs a value reads it into its own local, and every name carries the
 * module's `klog_` prefix so two modules cannot collide at link time.
 *
 * Locking is unchanged by the split. klog_console_emit and
 * klog_console_line_flush are called with the console lock held from klog.c,
 * exactly as the functions they replace were; klog_console_putc_raw is the
 * byte loop body of klog_console_write, which holds the same lock across it.
 * klog_console.c takes no lock of its own.
 */
#ifndef XAIOS_KERNEL_CORE_KLOG_INTERNAL_H
#define XAIOS_KERNEL_CORE_KLOG_INTERNAL_H

#include <stdarg.h>

#include <xaios/boot_info.h>
#include <xaios/types.h>

/* Bind the boot UART before any byte is written. klog_init calls this first,
   in the position where it assigned the UART registers itself. */
void klog_uart_bind(const xaios_boot_info_t *boot);

/* One byte to the UART and the console sink, with no line buffering and no
   '\n' translation. This is what klog_console_write loops over. */
void klog_console_putc_raw(char c);

/* One byte through the ordinary path: when output is enabled a '\n' is
   preceded by '\r', and the byte is also appended to the line buffer the ring
   is fed from. This is what klog_puts, klog_write and the formatter emit. */
void klog_console_emit(char c);

/* Hand the completed line buffer to the ring, on the architectures that have
   one, and reset its length. */
void klog_console_line_flush(void);

/* Format into the ordinary console path. Called by klog and klog_level. */
void klog_format_v(const char *fmt, va_list args);

/* Unsigned value in the given base, no padding. The drop report in klog.c
   counts in decimal through this. */
void klog_format_u64(uint64_t value, unsigned base);

#endif /* XAIOS_KERNEL_CORE_KLOG_INTERNAL_H */
