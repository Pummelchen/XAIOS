/*
 * fatFS's on-disk codec. See fat_internal.h.
 */

#include "fat_internal.h"

#include <xaios/fat.h>

void fat_bytes_zero(void *buffer, uint64_t length) {
  uint8_t *out = (uint8_t *)buffer;
  for (uint64_t index = 0U; index < length; ++index) out[index] = 0U;
}

void fat_bytes_copy(void *destination, const void *source,
                       uint64_t length) {
  uint8_t *out = (uint8_t *)destination;
  const uint8_t *in = (const uint8_t *)source;
  for (uint64_t index = 0U; index < length; ++index) out[index] = in[index];
}

int fat_bytes_equal(const void *left, const void *right, uint64_t length) {
  const uint8_t *a = (const uint8_t *)left;
  const uint8_t *b = (const uint8_t *)right;
  for (uint64_t index = 0U; index < length; ++index) {
    if (a[index] != b[index]) return 0;
  }
  return 1;
}

void fat_put16(uint8_t *out, uint16_t value) {
  out[0] = (uint8_t)(value & 0xFFU);
  out[1] = (uint8_t)((value >> 8) & 0xFFU);
}

void fat_put32(uint8_t *out, uint32_t value) {
  out[0] = (uint8_t)(value & 0xFFU);
  out[1] = (uint8_t)((value >> 8) & 0xFFU);
  out[2] = (uint8_t)((value >> 16) & 0xFFU);
  out[3] = (uint8_t)((value >> 24) & 0xFFU);
}

uint16_t fat_get16(const uint8_t *in) {
  return (uint16_t)((uint16_t)in[0] | ((uint16_t)in[1] << 8));
}

uint32_t fat_get32(const uint8_t *in) {
  return (uint32_t)in[0] | ((uint32_t)in[1] << 8) | ((uint32_t)in[2] << 16) |
         ((uint32_t)in[3] << 24);
}

char fat_upper(char value) {
  return (value >= 'a' && value <= 'z') ? (char)(value - 'a' + 'A') : value;
}

xaios_status_t fat_encode_name(const char *component, uint64_t length,
                                  uint8_t out[FAT_NAME_LENGTH]) {
  if (length == 0U) return XAIOS_ERR_INVALID;
  for (uint64_t index = 0U; index < FAT_NAME_LENGTH; ++index) out[index] = ' ';
  uint64_t dot = length;
  for (uint64_t index = 0U; index < length; ++index) {
    if (component[index] == '.') {
      /* The last dot separates the extension; an earlier one is not a legal
         8.3 name at all. "." and ".." are handled by the caller. */
      if (dot != length) return XAIOS_ERR_INVALID;
      dot = index;
    }
  }
  uint64_t base_length = dot;
  uint64_t extension_length = dot == length ? 0U : length - dot - 1U;
  if (base_length == 0U || base_length > 8U || extension_length > 3U) {
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t index = 0U; index < base_length; ++index) {
    char value = fat_upper(component[index]);
    if (value == '/' || value == '\\' || (uint8_t)value < 0x20U) {
      return XAIOS_ERR_INVALID;
    }
    out[index] = (uint8_t)value;
  }
  for (uint64_t index = 0U; index < extension_length; ++index) {
    out[8U + index] = (uint8_t)fat_upper(component[dot + 1U + index]);
  }
  return XAIOS_OK;
}

uint8_t fat_lfn_checksum(const uint8_t name[FAT_NAME_LENGTH]) {
  uint8_t sum = 0U;
  for (uint32_t index = 0U; index < FAT_NAME_LENGTH; ++index) {
    sum = (uint8_t)(((sum & 1U) != 0U ? 0x80U : 0U) + (sum >> 1) + name[index]);
  }
  return sum;
}

uint32_t fat_short_name_character(char value) {
  if (value >= 'A' && value <= 'Z') return 1U;
  if (value >= '0' && value <= '9') return 1U;
  return value == '_' || value == '-' || value == '$' || value == '~';
}

void fat_short_alias(const char *component, uint64_t length,
                        uint32_t ordinal, uint8_t out[FAT_NAME_LENGTH]) {
  for (uint32_t index = 0U; index < FAT_NAME_LENGTH; ++index) out[index] = ' ';
  uint64_t dot = length;
  for (uint64_t index = 0U; index < length; ++index) {
    if (component[index] == '.') dot = index;
  }
  uint32_t used = 0U;
  for (uint64_t index = 0U; index < dot && used < 6U; ++index) {
    char value = fat_upper(component[index]);
    if (fat_short_name_character(value) == 0U) continue;
    out[used++] = (uint8_t)value;
  }
  out[used++] = (uint8_t)'~';
  out[used++] = (uint8_t)('0' + (char)(ordinal % 10U));
  uint32_t extension = 0U;
  for (uint64_t index = dot + 1U; index < length && extension < 3U; ++index) {
    char value = fat_upper(component[index]);
    if (fat_short_name_character(value) == 0U) continue;
    out[8U + extension] = (uint8_t)value;
    ++extension;
  }
}

void fat_decode_entry(const uint8_t *raw, directory_entry_t *entry) {
  fat_bytes_copy(entry->name, raw, FAT_NAME_LENGTH);
  entry->attributes = raw[11];
  entry->first_cluster = fat_get16(&raw[26]);
  entry->size = fat_get32(&raw[28]);
}

uint32_t fat_lfn_gather(const uint8_t *raw, char *out, uint32_t capacity,
                           uint32_t *out_length) {
  uint32_t ordinal = raw[0] & 0x3FU;
  if (ordinal == 0U || ordinal > FAT_LFN_MAX_ENTRIES) return 0U;
  uint32_t base = (ordinal - 1U) * FAT_LFN_CHARS;
  for (uint32_t index = 0U; index < FAT_LFN_CHARS; ++index) {
    uint16_t value = fat_get16(&raw[fat_k_lfn_offsets[index]]);
    if (value == 0x0000U || value == 0xFFFFU) continue;
    if (value > 0x7FU) return 0U;
    uint32_t position = base + index;
    if (position >= capacity) return 0U;
    out[position] = (char)value;
    if (position + 1U > *out_length) *out_length = position + 1U;
  }
  return 1U;
}

uint32_t fat_names_equal_fold(const char *a, uint32_t a_length,
                                 const char *b, uint32_t b_length) {
  if (a_length != b_length) return 0U;
  for (uint32_t index = 0U; index < a_length; ++index) {
    if (fat_upper(a[index]) != fat_upper(b[index])) return 0U;
  }
  return 1U;
}

const uint8_t fat_k_lfn_offsets[FAT_LFN_CHARS] = {
    1U, 3U, 5U, 7U, 9U, 14U, 16U, 18U, 20U, 22U, 24U, 28U, 30U};

