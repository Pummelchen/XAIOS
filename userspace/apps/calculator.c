#include <xaios_user.h>

static void print(const char *text) {
  (void)xaios_console_write(text, xaios_strlen(text));
}

static int parse_integer(const char *text, s64 *value) {
  u64 cursor = 0U;
  u64 magnitude = 0U;
  int negative = 0;
  if (text == 0 || text[0] == '\0') return -1;
  if (text[cursor] == '-') {
    negative = 1;
    ++cursor;
  } else if (text[cursor] == '+') {
    ++cursor;
  }
  if (text[cursor] == '\0') return -1;
  while (text[cursor] != '\0') {
    u64 digit;
    if (text[cursor] < '0' || text[cursor] > '9') return -1;
    digit = (u64)(text[cursor] - '0');
    if (magnitude > (0x7fffffffffffffffULL + (u64)negative - digit) / 10U)
      return -1;
    magnitude = magnitude * 10U + digit;
    ++cursor;
  }
  if (negative != 0) {
    *value = magnitude == 0x8000000000000000ULL
                 ? (s64)0x8000000000000000ULL
                 : -(s64)magnitude;
  } else {
    *value = (s64)magnitude;
  }
  return 0;
}

static void print_integer(s64 value) {
  char output[32];
  u64 used = 0U;
  u64 magnitude;
  xaios_memzero(output, sizeof(output));
  if (value < 0) {
    output[used++] = '-';
    magnitude = (u64)(-(value + 1)) + 1U;
  } else {
    magnitude = (u64)value;
  }
  xaios_append_u64(output, sizeof(output), &used, magnitude);
  xaios_append_cstr(output, sizeof(output), &used, "\n");
  print(output);
}

static int add_overflow(s64 left, s64 right, s64 *result) {
  if ((right > 0 && left > (s64)0x7fffffffffffffffULL - right) ||
      (right < 0 && left < (s64)0x8000000000000000ULL - right))
    return -1;
  *result = left + right;
  return 0;
}

static int multiply_overflow(s64 left, s64 right, s64 *result) {
  const s64 maximum = (s64)0x7fffffffffffffffULL;
  const s64 minimum = (s64)0x8000000000000000ULL;
  if (left == 0 || right == 0) {
    *result = 0;
    return 0;
  }
  if ((left > 0 && right > 0 && left > maximum / right) ||
      (left > 0 && right < 0 && right < minimum / left) ||
      (left < 0 && right > 0 && left < minimum / right) ||
      (left < 0 && right < 0 && left < maximum / right)) {
    return -1;
  }
  *result = left * right;
  return 0;
}

int main(int argc, char **argv) {
  s64 left;
  s64 right;
  s64 result;
  if (argc != 4 || parse_integer(argv[1], &left) != 0 ||
      parse_integer(argv[3], &right) != 0 || argv[2][1] != '\0') {
    print("usage: calculator INTEGER [+|-|*|/|%] INTEGER\n");
    return 2;
  }
  if (argv[2][0] == '+') {
    if (add_overflow(left, right, &result) != 0) goto overflow;
  } else if (argv[2][0] == '-') {
    if (right == (s64)0x8000000000000000ULL ||
        add_overflow(left, -right, &result) != 0)
      goto overflow;
  } else if (argv[2][0] == '*') {
    if (multiply_overflow(left, right, &result) != 0) goto overflow;
  } else if (argv[2][0] == '/' || argv[2][0] == '%') {
    if (right == 0) {
      print("calculator: division by zero\n");
      return 1;
    }
    if (left == (s64)0x8000000000000000ULL && right == -1) goto overflow;
    result = argv[2][0] == '/' ? left / right : left % right;
  } else {
    print("calculator: unsupported operator\n");
    return 2;
  }
  print_integer(result);
  return 0;

overflow:
  print("calculator: signed 64-bit overflow\n");
  return 1;
}
