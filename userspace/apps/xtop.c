#include <xaios_user.h>
#include <xaios_screen.h>
#include <xaios/types.h>
#include "ssh_child_ipc.h"
#include "xtop_serve.h"
#include "xtop_render.h"
#include "xtop_glyph.h"
#include "xtop_draw.h"
#include "xtop_snapshot.h"

static unsigned char g_arena[XAIOS_XTOP_ARENA_BYTES];
static uint64_t g_arena_used;
/* The render arena is the renderer's; the session only clears it. */
void xtop_arena_reset(void) { g_arena_used = 0U; }
void xtop_bytes_zero(void *buffer, uint64_t size) {
  unsigned char *bytes = (unsigned char *)buffer;
  for (uint64_t i = 0U; i < size; ++i) bytes[i] = 0U;
}
static uint64_t align_up(uint64_t value, uint64_t alignment) {
  if (alignment == 0U) return value;
  uint64_t remainder = value % alignment;
  return remainder == 0U ? value : value + alignment - remainder;
}
void *xtop_arena_alloc(uint64_t size, uint64_t alignment) {
  uint64_t offset = align_up(g_arena_used, alignment);
  if (offset > sizeof(g_arena) || size > sizeof(g_arena) - offset) return 0;
  void *result = &g_arena[offset];
  xtop_bytes_zero(result, size);
  g_arena_used = offset + size;
  return result;
}
void xtop_arena_free(void *pointer) { (void)pointer; }
uint64_t xtop_cstr_len(const char *text) {
  uint64_t size = 0U;
  if (text == 0) return 0U;
  while (text[size] != '\0') ++size;
  return size;
}
int xtop_string_equal(const char *lhs, const char *rhs) {
  if (lhs == 0 || rhs == 0) return 0;
  while (*lhs != '\0' && *lhs == *rhs) {
    ++lhs;
    ++rhs;
  }
  return *lhs == *rhs;
}
int xtop_contains_substring(const char *text, const char *needle) {
  uint64_t needle_size = xtop_cstr_len(needle);
  if (needle_size == 0U) return 1;
  for (uint64_t i = 0U; text != 0 && text[i] != '\0'; ++i) {
    uint64_t j = 0U;
    while (j < needle_size && text[i + j] == needle[j]) ++j;
    if (j == needle_size) return 1;
  }
  return 0;
}
static xaios_status_t output_append_char(char *output, uint64_t capacity,
                                         uint64_t *offset, char value) {
  if (output == 0 || offset == 0 || *offset + 1U >= capacity)
    return XAIOS_ERR_NO_MEMORY;
  output[(*offset)++] = value;
  output[*offset] = '\0';
  return XAIOS_OK;
}
xaios_status_t xtop_output_append(char *output, uint64_t capacity,
                                  uint64_t *offset, const char *text) {
  if (text == 0) return XAIOS_ERR_INVALID;
  while (*text != '\0') {
    if (output_append_char(output, capacity, offset, *text++) != XAIOS_OK)
      return XAIOS_ERR_NO_MEMORY;
  }
  return XAIOS_OK;
}
xaios_status_t xtop_output_append_u64(char *output, uint64_t capacity,
                                      uint64_t *offset, uint64_t value) {
  char digits[24];
  uint32_t count = 0U;
  do {
    digits[count++] = (char)('0' + value % 10U);
    value /= 10U;
  } while (value != 0U);
  while (count != 0U) {
    if (output_append_char(output, capacity, offset, digits[--count]) !=
        XAIOS_OK)
      return XAIOS_ERR_NO_MEMORY;
  }
  return XAIOS_OK;
}
xaios_status_t xtop_command_fail(char *output, uint64_t capacity,
                                   uint64_t *offset, const char *message) {
  (void)xtop_output_append(output, capacity, offset, message);
  (void)xtop_output_append(output, capacity, offset, "\n");
  return XAIOS_ERR_INVALID;
}
static uint64_t skip_ws(const char *text, uint64_t index) {
  while (text[index] == ' ' || text[index] == '\t' ||
         text[index] == '\r' || text[index] == '\n')
    ++index;
  return index;
}
xaios_status_t xtop_token_next(const char *text, uint64_t *index,
                               char *token, uint64_t capacity) {
  uint64_t used = 0U;
  uint64_t i;
  char quote = '\0';
  if (text == 0 || index == 0 || token == 0 || capacity == 0U)
    return XAIOS_ERR_INVALID;
  i = skip_ws(text, *index);
  if (text[i] == '\0') return XAIOS_ERR_NOT_FOUND;
  if (text[i] == '\'' || text[i] == '"') quote = text[i++];
  while (text[i] != '\0') {
    if (quote != '\0') {
      if (text[i] == quote) {
        ++i;
        break;
      }
    } else if (text[i] == ' ' || text[i] == '\t' ||
               text[i] == '\r' || text[i] == '\n') {
      break;
    }
    if (used + 1U >= capacity) return XAIOS_ERR_NO_MEMORY;
    token[used++] = text[i++];
  }
  token[used] = '\0';
  *index = skip_ws(text, i);
  return XAIOS_OK;
}
static xaios_status_t parse_u64_token(const char *text, uint64_t *value,
                                      uint64_t *consumed) {
  uint64_t parsed = 0U;
  uint64_t index = 0U;
  if (text == 0 || value == 0 || consumed == 0 ||
      text[0] < '0' || text[0] > '9')
    return XAIOS_ERR_INVALID;
  while (text[index] >= '0' && text[index] <= '9') {
    uint64_t digit = (uint64_t)(text[index] - '0');
    if (parsed > (UINT64_MAX - digit) / 10U) return XAIOS_ERR_INVALID;
    parsed = parsed * 10U + digit;
    ++index;
  }
  *value = parsed;
  *consumed = index;
  return XAIOS_OK;
}
const char *xtop_state_name(uint32_t state) {
  switch (state) {
  case XAIOS_USER_PROCESS_LOADED:
    return "loaded";
  case XAIOS_USER_PROCESS_RUNNABLE:
    return "runnable";
  case XAIOS_USER_PROCESS_RUNNING:
    return "running";
  case XAIOS_USER_PROCESS_WAITING:
    return "waiting";
  case XAIOS_USER_PROCESS_EXITED:
    return "exited";
  case XAIOS_USER_PROCESS_FAILED:
    return "failed";
  default:
    return "unknown";
  }
}
int xtop_state_active(uint32_t state) {
  return state == XAIOS_USER_PROCESS_LOADED ||
         state == XAIOS_USER_PROCESS_RUNNABLE ||
         state == XAIOS_USER_PROCESS_RUNNING ||
         state == XAIOS_USER_PROCESS_WAITING;
}
const char *xtop_sort_name(xtop_sort_key_t key) {
  switch (key) {
  case XTOP_SORT_MEMORY:
    return "mem";
  case XTOP_SORT_TIME:
    return "time";
  case XTOP_SORT_PID:
    return "pid";
  case XTOP_SORT_STATE:
    return "state";
  case XTOP_SORT_SYSCALLS:
    return "syscalls";
  case XTOP_SORT_COMMAND:
    return "command";
  case XTOP_SORT_PARENT:
    return "parent";
  default:
    return "cpu";
  }
}
uint64_t xtop_ratio_tenths(uint64_t numerator,
                                  uint64_t denominator) {
  if (denominator == 0U || numerator == 0U) {
    return 0U;
  }
  if (numerator > UINT64_MAX / UINT64_C(1000)) {
    numerator /= UINT64_C(1000);
    denominator /= UINT64_C(1000);
    if (denominator == 0U) {
      return UINT64_C(1000);
    }
  }
  return (numerator * UINT64_C(1000)) / denominator;
}
uint64_t xtop_capacity_tenths(uint64_t numerator,
                                     uint64_t denominator) {
  uint64_t tenths = xtop_ratio_tenths(numerator, denominator);
  return tenths > UINT64_C(1000) ? UINT64_C(1000) : tenths;
}
void xtop_append_percent(char *output, uint64_t output_capacity,
                                uint64_t *output_bytes, uint64_t tenths) {
  xtop_output_append_u64(output, output_capacity, output_bytes, tenths / 10U);
  xtop_output_append(output, output_capacity, output_bytes, ".");
  xtop_output_append_u64(output, output_capacity, output_bytes, tenths % 10U);
  xtop_output_append(output, output_capacity, output_bytes, "%");
}
static void xtop_append_repeat(char *output, uint64_t output_capacity,
                               uint64_t *output_bytes, char value,
                               uint32_t count) {
  for (uint32_t i = 0U; i < count; ++i) {
    if (output_append_char(output, output_capacity, output_bytes, value) !=
        XAIOS_OK) {
      return;
    }
  }
}
void xtop_append_u64_width(char *output, uint64_t output_capacity,
                                  uint64_t *output_bytes, uint64_t value,
                                  uint32_t width) {
  uint64_t digits = xtop_u64_digits(value);
  if (digits < width) {
    xtop_append_repeat(output, output_capacity, output_bytes, ' ',
                       width - (uint32_t)digits);
  }
  xtop_output_append_u64(output, output_capacity, output_bytes, value);
}
xaios_status_t xtop_parse_u32_option(const char *args, uint64_t *index,
                                     uint32_t *value) {
  char token[24];
  uint64_t parsed = 0U;
  uint64_t consumed = 0U;
  if (xtop_token_next(args, index, token, sizeof(token)) != XAIOS_OK ||
      parse_u64_token(token, &parsed, &consumed) != XAIOS_OK ||
      consumed != xtop_cstr_len(token) || parsed > UINT32_MAX) {
    return XAIOS_ERR_INVALID;
  }
  *value = (uint32_t)parsed;
  return XAIOS_OK;
}
xaios_status_t xtop_parse_sort_option(const char *args, uint64_t *index,
                                      xtop_sort_key_t *key) {
  char value[24];
  if (xtop_token_next(args, index, value, sizeof(value)) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }
  if (xtop_string_equal(value, "cpu") == 1U) *key = XTOP_SORT_CPU;
  else if (xtop_string_equal(value, "mem") == 1U) *key = XTOP_SORT_MEMORY;
  else if (xtop_string_equal(value, "time") == 1U) *key = XTOP_SORT_TIME;
  else if (xtop_string_equal(value, "pid") == 1U) *key = XTOP_SORT_PID;
  else if (xtop_string_equal(value, "state") == 1U) *key = XTOP_SORT_STATE;
  else if (xtop_string_equal(value, "syscalls") == 1U) *key = XTOP_SORT_SYSCALLS;
  else if (xtop_string_equal(value, "command") == 1U) *key = XTOP_SORT_COMMAND;
  else if (xtop_string_equal(value, "parent") == 1U) *key = XTOP_SORT_PARENT;
  else return XAIOS_ERR_INVALID;
  return XAIOS_OK;
}
int main(int argc, char **argv) {
  if (argc == 4) {
    /* Started as a session's child: argv[1] is the channel, argv[3] the
       command the session built. */
    u64 channel = 0U;
    const char *text = argv[1];
    for (uint32_t i = 0U; text[i] != '\0'; ++i) {
      if (text[i] < '0' || text[i] > '9') { channel = 0U; break; }
      channel = channel * 10U + (u64)(text[i] - '0');
    }
    if (channel != 0U) return xtop_serve(channel, argv[3]);
  }
  static char output[XAIOS_XTOP_OUTPUT_BYTES];
  uint64_t output_size = 0U;
  const char *args = "";
  xtop_arena_reset();
  output[0] = '\0';
  if (argc > 2) return 2;
  if (argc == 2) args = argv[1];
  int status = xtop_handle(args, output, sizeof(output), &output_size);
  if (output_size != 0U)
    (void)xaios_console_write(output, output_size);
  return status == XAIOS_OK ? 0 : 1;
}
