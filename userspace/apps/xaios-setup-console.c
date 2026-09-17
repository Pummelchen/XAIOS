/* The console text and prompt layer of setup.
 *
 * Split out of xaios-setup.c for the file-size budget: this is everything that
 * touches the console ring directly -- the formatters a record or a command
 * line is built with, the line reader that masks a secret as it is typed, and
 * the two prompt wrappers -- while xaios-setup.c keeps the questions and what
 * is collected. The private interface is xaios-setup-internal.h.
 *
 * Nothing here owns state: what it formats is written into buffers its callers
 * own, and every read goes into a caller-owned local.
 */

#include "xaios-setup-internal.h"

/* ------------------------------------------------------------------ text */

static u64 xsetup_text_length(const char *text) {
  u64 length = 0ULL;
  while (text[length] != '\0') ++length;
  return length;
}

void xsetup_say(const char *text) {
  (void)xaios_console_write(text, xsetup_text_length(text));
}

int xsetup_text_equal(const char *a, const char *b) {
  u64 i = 0ULL;
  while (a[i] != '\0' && a[i] == b[i]) ++i;
  return a[i] == '\0' && b[i] == '\0';
}

void xsetup_append(char *out, u64 capacity, u64 *offset, const char *text) {
  for (u64 i = 0ULL; text[i] != '\0'; ++i) {
    if (*offset + 1ULL >= capacity) return;
    out[(*offset)++] = text[i];
  }
  out[*offset] = '\0';
}

void xsetup_append_hex(char *out, u64 capacity, u64 *offset,
                       const unsigned char *bytes, u64 count) {
  static const char digits[] = "0123456789abcdef";
  for (u64 i = 0ULL; i < count; ++i) {
    if (*offset + 2ULL >= capacity) return;
    out[(*offset)++] = digits[(bytes[i] >> 4) & 0x0FU];
    out[(*offset)++] = digits[bytes[i] & 0x0FU];
  }
  out[*offset] = '\0';
}

void xsetup_append_u32(char *out, u64 capacity, u64 *offset, u32 value) {
  char digits[12];
  u32 count = 0U;
  if (value == 0U) {
    digits[count++] = '0';
  }
  while (value != 0U) {
    digits[count++] = (char)('0' + (value % 10U));
    value /= 10U;
  }
  while (count != 0U) {
    if (*offset + 1ULL >= capacity) return;
    out[(*offset)++] = digits[--count];
  }
  out[*offset] = '\0';
}

/* ----------------------------------------------------------------- input */

/* Read one line. `mask` suppresses the echo, for a secret being typed in
   front of whoever is standing there. Backspace is handled because a person
   typing a password they cannot see will use it, and a setup routine that
   ignores it produces an account whose password nobody knows. */
static u64 xsetup_read_line(char *buffer, u64 capacity, int mask) {
  u64 length = 0ULL;
  for (;;) {
    char value = 0;
    if (xaios_console_read(&value) != 1) {
      /* Nothing waiting. There is no yield to make here -- sshd polls the
         same ring the same way -- and setup is a short interactive program
         with nothing else to run. */
      continue;
    }
    if (value == '\r' || value == '\n') {
      xsetup_say("\n");
      buffer[length] = '\0';
      return length;
    }
    if (value == 0x7F || value == 0x08) {
      if (length != 0ULL) {
        --length;
        if (!mask) xsetup_say("\b \b");
      }
      continue;
    }
    /* Anything below space is a control code; a setup answer has none, and
       letting them through puts escape sequences into a credential file. */
    if (value < 0x20 || length + 1ULL >= capacity) continue;
    buffer[length++] = value;
    if (mask) {
      xsetup_say("*");
    } else {
      (void)xaios_console_write(&value, 1ULL);
    }
  }
}

u64 xsetup_prompt(const char *question, char *buffer, u64 capacity, int mask) {
  xsetup_say(question);
  return xsetup_read_line(buffer, capacity, mask);
}

/* A yes/no question where the default is the safe answer. */
int xsetup_prompt_yes(const char *question) {
  char answer[SETUP_LINE_MAX];
  (void)xsetup_prompt(question, answer, sizeof(answer), 0);
  return answer[0] == 'y' || answer[0] == 'Y';
}
