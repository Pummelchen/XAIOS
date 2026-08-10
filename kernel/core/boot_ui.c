#include <xaios/boot_ui.h>
#include <xaios/klog.h>

#ifndef XAIOS_BOOT_TEST_APPS
#define XAIOS_BOOT_TEST_APPS 0
#endif

#define BOOT_BAR_WIDTH UINT32_C(40)

static uint64_t text_length(const char *text) {
  uint64_t length = 0U;
  if (text == 0) return 0U;
  while (text[length] != '\0') ++length;
  return length;
}

static void write_text(const char *text) {
  klog_console_write(text, text_length(text));
}

static void write_uint(uint32_t value) {
  char digits[10];
  uint32_t count = 0U;
  if (value == 0U) {
    write_text("0");
    return;
  }
  while (value != 0U && count < sizeof(digits)) {
    digits[count++] = (char)('0' + (value % 10U));
    value /= 10U;
  }
  while (count != 0U) {
    --count;
    klog_console_write(&digits[count], 1U);
  }
}

static void write_int(int32_t value) {
  uint32_t magnitude;
  if (value < 0) {
    write_text("-");
    magnitude = (uint32_t)(-(value + 1)) + 1U;
  } else {
    magnitude = (uint32_t)value;
  }
  write_uint(magnitude);
}

#if !XAIOS_BOOT_TEST_APPS
static void write_brand(void) {
  write_text("\x1b[1;35mXAI\x1b[0m \x1b[1;36mOS\x1b[0m\n\n");
}
#endif

void boot_ui_begin(void) {
#if XAIOS_BOOT_TEST_APPS
  write_text("boot-ui: XAI OS\n");
#else
  klog_console_set_log_output(0U);
  write_text("\x1b[2J\x1b[H");
  write_brand();
#endif
}

void boot_ui_update(uint32_t percent, const char *loaded,
                    const char *loading, uint32_t remaining) {
  if (percent > 100U) percent = 100U;
#if XAIOS_BOOT_TEST_APPS
  write_text("boot-ui: progress=");
  write_uint(percent);
  write_text(" loaded=");
  write_text(loaded);
  write_text(" loading=");
  write_text(loading);
  write_text(" remaining=");
  write_uint(remaining);
  write_text("\n");
#else
  write_text("\x1b[H\x1b[J");
  write_brand();
  write_text("[");
  uint32_t filled = (percent * BOOT_BAR_WIDTH) / 100U;
  for (uint32_t i = 0U; i < BOOT_BAR_WIDTH; ++i) {
    write_text(i < filled ? "#" : ".");
  }
  write_text("] ");
  write_uint(percent);
  write_text("%\n\nLoaded: ");
  write_text(loaded);
  write_text("\nLoading: ");
  write_text(loading);
  write_text("\nRemaining: ");
  write_uint(remaining);
  write_text(" components\n");
#endif
}

void boot_ui_error(const char *component, int32_t status) {
  klog_console_set_log_output(1U);
  write_text("\n\x1b[1;31mBOOT ERROR\x1b[0m component=");
  write_text(component);
  write_text(" code=");
  write_int(status);
  write_text("\n");
}
