/* The kernel log's formatter.
 *
 * klog and klog_level both build their line through klog_vformat, which until
 * now was static in klog.c. It moves here whole: the width and padding
 * helpers, the signed writer and the specifier loop. The only thing it needs
 * from klog.c is a way to emit one character, so it calls klog_console_emit
 * and the public klog_puts, exactly as it called klog_char and klog_puts
 * before.
 *
 * No specifier, width, padding or byte order changed. Gates parse these lines.
 */
#include <stdarg.h>

#include <xaios/klog.h>
#include <xaios/types.h>

#include "klog_internal.h"

static void klog_u64_width(uint64_t value, unsigned base, unsigned width,
                           char padding) {
  char buffer[32];
  unsigned index = 0;

  if (value == 0) {
    while (width > 1U) {
      klog_console_emit(padding);
      --width;
    }
    klog_console_emit('0');
    return;
  }

  while (value != 0 && index < sizeof(buffer)) {
    unsigned digit = (unsigned)(value % base);
    buffer[index++] = (char)(digit < 10 ? '0' + digit : 'a' + (digit - 10));
    value /= base;
  }

  while (width > index) {
    klog_console_emit(padding);
    --width;
  }
  while (index != 0) {
    klog_console_emit(buffer[--index]);
  }
}

/* This was klog_u64. */
void klog_format_u64(uint64_t value, unsigned base) {
  klog_u64_width(value, base, 0, ' ');
}

static void klog_i64(int64_t value, unsigned width, char padding) {
  uint64_t magnitude = (uint64_t)value;
  if (value < 0) {
    klog_console_emit('-');
    magnitude = (uint64_t)(-(value + 1)) + 1U;
    if (width > 0U) {
      --width;
    }
  }
  klog_u64_width(magnitude, 10, width, padding);
}

/* This was klog_vformat. */
void klog_format_v(const char *fmt, va_list args) {
  for (const char *p = fmt; *p != '\0'; ++p) {
    if (*p != '%') {
      klog_console_emit(*p);
      continue;
    }

    ++p;
    if (*p == '\0') {
      break;
    }

    char padding = ' ';
    unsigned width = 0;
    if (*p == '0') {
      padding = '0';
      ++p;
    }
    while (*p >= '0' && *p <= '9') {
      width = (width * 10U) + (unsigned)(*p - '0');
      ++p;
    }

    if (*p == 's') {
      const char *s = va_arg(args, const char *);
      klog_puts(s == 0 ? "(null)" : s);
    } else if (*p == 'u') {
      klog_u64_width((uint64_t)va_arg(args, unsigned), 10, width, padding);
    } else if (*p == 'x') {
      klog_u64_width((uint64_t)va_arg(args, unsigned), 16, width, padding);
    } else if (*p == 'd') {
      klog_i64((int64_t)va_arg(args, int), width, padding);
    } else if (*p == 'c') {
      /* A single character, which this understood nowhere until a diagnostic
         needed it. initramfs prints the four magic bytes it found when a
         volume header does not validate, and without %c that line reported
         the literal text %c%c%c%c -- the one message whose whole job was to
         say what was actually on the disk said nothing at all. A format this
         does not implement is not a missing feature, it is a diagnostic that
         lies at exactly the moment it is read.
         Promoted to int by the default argument promotions, so read as int. */
      char c = (char)va_arg(args, int);
      klog_console_emit(c);
    } else if (*p == 'p') {
      klog_puts("0x");
      klog_format_u64((uint64_t)(uintptr_t)va_arg(args, void *), 16);
    } else if (*p == 'l' && p[1] == 'u') {
      ++p;
      klog_format_u64(va_arg(args, uint64_t), 10);
    } else if (*p == 'l' && p[1] == 'x') {
      ++p;
      klog_format_u64(va_arg(args, uint64_t), 16);
    } else if (*p == '%') {
      klog_console_emit('%');
    } else {
      klog_console_emit('%');
      klog_console_emit(*p);
    }
  }
}
