/*
 * The remote-login shell's text, parse and output primitives.
 *
 * Split out of remote_login.c, which keeps the dispatcher itself
 * (remote_login_exec) because the shell help catalog tests/repository/
 * check-user-docs.py reads lives in its body, and keeps remote_ensure_parent
 * and remote_login_log_failure, which are filesystem and logging helpers rather
 * than parsing. Everything here was already compiled in every configuration,
 * so nothing carries XAIOS_BOOT_TEST_APPS -- only copy_remainder changed
 * linkage, and that was to cross from remote_login.c into this file.
 */

#include "remote_login_internal.h"
#include "remote_login_parse_internal.h"

#include <xaios/status.h>
#include <xaios/types.h>

uint64_t cstr_len(const char *text) {
  uint64_t len = 0;
  if (text == 0) {
    return 0;
  }
  while (text[len] != '\0') {
    ++len;
  }
  return len;
}

int string_equal(const char *lhs, const char *rhs) {
  if (lhs == 0 || rhs == 0) {
    return 0;
  }
  for (uint64_t i = 0;; ++i) {
    if (lhs[i] != rhs[i]) {
      return 0;
    }
    if (lhs[i] == '\0') {
      return 1;
    }
  }
}

void output_append(char *output, uint64_t capacity, uint64_t *offset,
                   const char *text) {
  if (output == 0 || offset == 0 || text == 0 || capacity == 0) {
    return;
  }
  for (uint64_t i = 0; text[i] != '\0' && *offset + 1U < capacity; ++i) {
    output[*offset] = text[i];
    ++(*offset);
  }
  output[*offset] = '\0';
}

xaios_status_t copy_cstr_range(char *dst, uint64_t dst_capacity,
                               const char *src, uint64_t src_len) {
  if (dst == 0 || src == 0 || dst_capacity == 0U) {
    return XAIOS_ERR_INVALID;
  }
  if (src_len + 1U > dst_capacity) {
    return XAIOS_ERR_NO_MEMORY;
  }
  for (uint64_t i = 0; i < src_len; ++i) {
    dst[i] = src[i];
  }
  dst[src_len] = '\0';
  return XAIOS_OK;
}

xaios_status_t copy_cstr(char *dst, uint64_t dst_capacity, const char *src) {
  if (src == 0) {
    if (dst_capacity > 0U) {
      dst[0] = '\0';
    }
    return XAIOS_ERR_INVALID;
  }
  return copy_cstr_range(dst, dst_capacity, src, cstr_len(src));
}

void output_append_u64(char *output, uint64_t capacity, uint64_t *offset,
                             uint64_t value) {
  char digits[24];
  uint64_t count = 0;
  if (value == 0U) {
    output_append(output, capacity, offset, "0");
    return;
  }
  while (value != 0U && count < sizeof(digits)) {
    digits[count] = (char)('0' + (value % 10U));
    value /= 10U;
    ++count;
  }
  while (count != 0U) {
    char one[2];
    --count;
    one[0] = digits[count];
    one[1] = '\0';
    output_append(output, capacity, offset, one);
  }
}

static uint64_t skip_ws(const char *text, uint64_t index) {
  if (text == 0) {
    return 0;
  }
  while (text[index] == ' ' || text[index] == '\t' || text[index] == '\n' ||
         text[index] == '\r') {
    ++index;
  }
  return index;
}

xaios_status_t token_next(const char *text, uint64_t *index, char *token,
                               uint64_t capacity) {
  if (text == 0 || index == 0 || token == 0 || capacity == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint64_t i = skip_ws(text, *index);
  if (text[i] == '\0') {
    token[0] = '\0';
    *index = i;
    return XAIOS_ERR_NOT_FOUND;
  }
  uint64_t length = 0U;
  char quote = '\0';
  while (text[i] != '\0') {
    char value = text[i];
    if (quote == '\0' &&
        (value == ' ' || value == '\t' || value == '\n' || value == '\r')) {
      break;
    }
    if (value == '\\' && quote != '\'') {
      if (text[i + 1U] == '\0') {
        token[0] = '\0';
        *index = i;
        return XAIOS_ERR_INVALID;
      }
      value = text[++i];
    } else if ((value == '\'' || value == '"') &&
               (quote == '\0' || quote == value)) {
      quote = quote == '\0' ? value : '\0';
      ++i;
      continue;
    }
    if (length + 1U >= capacity) {
      token[0] = '\0';
      *index = i;
      return XAIOS_ERR_NO_MEMORY;
    }
    token[length++] = value;
    ++i;
  }
  if (quote != '\0') {
    token[0] = '\0';
    *index = i;
    return XAIOS_ERR_INVALID;
  }
  token[length] = '\0';
  *index = i;
  return XAIOS_OK;
}

xaios_status_t command_fail(char *output, uint64_t output_capacity,
                                 uint64_t *output_bytes,
                                 const char *message) {
  output_append(output, output_capacity, output_bytes, message);
  output_append(output, output_capacity, output_bytes, "\n");
  return XAIOS_ERR_INVALID;
}

xaios_status_t output_append_char(char *output, uint64_t capacity,
                                  uint64_t *offset, char value) {
  if (output == 0 || offset == 0 || capacity == 0U) {
    return XAIOS_ERR_INVALID;
  }
  if (*offset + 1U >= capacity) {
    return XAIOS_ERR_NO_MEMORY;
  }
  output[*offset] = value;
  ++(*offset);
  output[*offset] = '\0';
  return XAIOS_OK;
}

/* copy_remainder, now remote_login_remainder: see remote_login_parse_internal.h
   for why it crosses. */
void remote_login_remainder(const char *text, uint64_t index, char *out,
                            uint64_t out_capacity) {
  uint64_t i = 0;
  if (out == 0 || out_capacity == 0U) {
    return;
  }
  if (text == 0) {
    out[0] = '\0';
    return;
  }
  index = skip_ws(text, index);
  while (text[index] != '\0' && i + 1U < out_capacity) {
    out[i] = text[index];
    ++i;
    ++index;
  }
  out[i] = '\0';
}

int has_more_args(const char *text, uint64_t index) {
  return text != 0 && text[skip_ws(text, index)] != '\0';
}
