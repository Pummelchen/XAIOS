#include "operations_internal.h"

uint64_t ops_str_len(const char *value) {
  uint64_t length = 0U;
  if (value == 0) return 0U;
  while (value[length] != '\0') ++length;
  return length;
}

uint32_t ops_str_equal(const char *left, const char *right) {
  uint64_t i = 0U;
  if (left == 0 || right == 0) return 0U;
  while (left[i] != '\0' && right[i] != '\0' && left[i] == right[i]) ++i;
  return left[i] == '\0' && right[i] == '\0';
}

uint32_t ops_str_starts(const char *value, const char *prefix) {
  uint64_t i = 0U;
  if (value == 0 || prefix == 0) return 0U;
  while (prefix[i] != '\0' && value[i] == prefix[i]) ++i;
  return prefix[i] == '\0';
}

const char *ops_skip_spaces(const char *value) {
  while (*value == ' ' || *value == '\t') ++value;
  return value;
}

uint32_t ops_next_token(const char **cursor, char *token,
                        uint64_t capacity) {
  uint64_t i = 0U;
  const char *value = ops_skip_spaces(*cursor);
  if (*value == '\0' || capacity == 0U) return 0U;
  while (*value != '\0' && *value != ' ' && *value != '\t') {
    if (i + 1U >= capacity) return 0U;
    token[i++] = *value++;
  }
  token[i] = '\0';
  *cursor = value;
  return 1U;
}

void ops_append(char *output, uint64_t capacity, uint64_t *used,
                const char *value) {
  if (output == 0 || used == 0 || capacity == 0U || value == 0) return;
  while (*value != '\0' && *used + 1U < capacity) {
    output[*used] = *value++;
    ++*used;
  }
  output[*used] = '\0';
}

void ops_append_u64(char *output, uint64_t capacity, uint64_t *used,
                    uint64_t value) {
  char digits[21];
  uint32_t count = 0U;
  if (value == 0U) {
    ops_append(output, capacity, used, "0");
    return;
  }
  while (value != 0U && count < sizeof(digits)) {
    digits[count++] = (char)('0' + value % 10U);
    value /= 10U;
  }
  while (count != 0U) {
    char text[2] = {digits[--count], '\0'};
    ops_append(output, capacity, used, text);
  }
}

void ops_append_status(char *output, uint64_t capacity, uint64_t *used,
                       xaios_status_t status) {
  if (status == XAIOS_OK) ops_append(output, capacity, used, "ok");
  else {
    ops_append(output, capacity, used, "error(");
    ops_append_u64(output, capacity, used, (uint64_t)(uint32_t)(-status));
    ops_append(output, capacity, used, ")");
  }
}

void ops_append_ipv4(char *output, uint64_t capacity, uint64_t *used,
                     uint32_t ip) {
  ops_append_u64(output, capacity, used, ip >> 24U);
  ops_append(output, capacity, used, ".");
  ops_append_u64(output, capacity, used, (ip >> 16U) & 0xffU);
  ops_append(output, capacity, used, ".");
  ops_append_u64(output, capacity, used, (ip >> 8U) & 0xffU);
  ops_append(output, capacity, used, ".");
  ops_append_u64(output, capacity, used, ip & 0xffU);
}

void ops_append_hex16(char *output, uint64_t capacity, uint64_t *used,
                      uint16_t value) {
  static const char digits[] = "0123456789abcdef";
  char text[5];
  uint32_t position = 0U;
  uint32_t started = 0U;
  for (int32_t shift = 12; shift >= 0; shift -= 4) {
    uint8_t digit = (uint8_t)((value >> (uint32_t)shift) & 0x0fU);
    if (digit != 0U || started != 0U || shift == 0) {
      text[position++] = digits[digit];
      started = 1U;
    }
  }
  text[position] = '\0';
  ops_append(output, capacity, used, text);
}

void ops_append_ipv6(char *output, uint64_t capacity, uint64_t *used,
                     const xaios_ip_addr_t *address) {
  for (uint32_t group = 0U; group < 8U; ++group) {
    if (group != 0U) ops_append(output, capacity, used, ":");
    ops_append_hex16(output, capacity, used,
                     (uint16_t)(((uint16_t)address->addr[group * 2U] << 8U) |
                                address->addr[group * 2U + 1U]));
  }
}

xaios_status_t ops_parse_u64(const char *text, uint64_t *value) {
  uint64_t result = 0U;
  if (text == 0 || *text == '\0' || value == 0) return XAIOS_ERR_INVALID;
  while (*text != '\0') {
    if (*text < '0' || *text > '9' ||
        result > (UINT64_MAX - (uint64_t)(*text - '0')) / 10U)
      return XAIOS_ERR_INVALID;
    result = result * 10U + (uint64_t)(*text++ - '0');
  }
  *value = result;
  return XAIOS_OK;
}

xaios_status_t ops_parse_ipv4(const char *text, uint32_t *ip) {
  uint32_t result = 0U;
  if (text == 0 || ip == 0) return XAIOS_ERR_INVALID;
  for (uint32_t part = 0U; part < 4U; ++part) {
    uint32_t value = 0U;
    uint32_t digits = 0U;
    while (*text >= '0' && *text <= '9') {
      value = value * 10U + (uint32_t)(*text++ - '0');
      if (++digits > 3U || value > 255U) return XAIOS_ERR_INVALID;
    }
    if (digits == 0U || (part < 3U && *text++ != '.') ||
        (part == 3U && *text != '\0')) return XAIOS_ERR_INVALID;
    result = (result << 8U) | value;
  }
  *ip = result;
  return XAIOS_OK;
}

uint64_t ops_find_decimal(const char *text, const char *key) {
  uint64_t key_len = ops_str_len(key);
  if (text == 0) return 0U;
  for (uint64_t i = 0U; text[i] != '\0'; ++i) {
    uint64_t j = 0U;
    while (j < key_len && text[i + j] == key[j]) ++j;
    if (j == key_len) {
      uint64_t value = 0U;
      const char *cursor = text + i + key_len;
      while (*cursor >= '0' && *cursor <= '9')
        value = value * 10U + (uint64_t)(*cursor++ - '0');
      return value;
    }
  }
  return 0U;
}
