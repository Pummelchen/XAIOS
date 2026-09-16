/*
 * The small helpers every part of xaibootFS uses. See xbfs_internal.h.
 */

#include "xbfs_internal.h"

void xbfs_bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

void xbfs_bytes_copy(void *dst, const void *src, uint64_t size) {
  uint8_t *out = (uint8_t *)dst;
  const uint8_t *in = (const uint8_t *)src;
  for (uint64_t i = 0; i < size; ++i) {
    out[i] = in[i];
  }
}

int xbfs_bytes_eq(const void *a, const void *b, uint64_t size) {
  const uint8_t *left = (const uint8_t *)a;
  const uint8_t *right = (const uint8_t *)b;
  for (uint64_t i = 0; i < size; ++i) {
    if (left[i] != right[i]) {
      return 0;
    }
  }
  return 1;
}

uint64_t xbfs_cstr_len(const char *value) {
  uint64_t len = 0;
  while (value[len] != '\0') {
    ++len;
  }
  return len;
}

int xbfs_str_eq(const char *a, const char *b) {
  while (*a != '\0' && *b != '\0') {
    if (*a != *b) {
      return 0;
    }
    ++a;
    ++b;
  }
  return *a == '\0' && *b == '\0';
}

xaios_status_t xbfs_append_char(char *buffer, uint64_t capacity,
                                 uint64_t *offset, char value) {
  if (buffer == 0 || offset == 0 || *offset + 1U >= capacity) {
    return XAIOS_ERR_NO_MEMORY;
  }
  buffer[*offset] = value;
  ++(*offset);
  buffer[*offset] = '\0';
  return XAIOS_OK;
}

xaios_status_t xbfs_append_cstr(char *buffer, uint64_t capacity,
                                 uint64_t *offset, const char *value) {
  if (value == 0) {
    return XAIOS_ERR_INVALID;
  }
  for (uint64_t i = 0; value[i] != '\0'; ++i) {
    if (xbfs_append_char(buffer, capacity, offset, value[i]) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
  }
  return XAIOS_OK;
}

xaios_status_t xbfs_append_u32(char *buffer, uint64_t capacity,
                                uint64_t *offset, uint32_t value) {
  char digits[10];
  uint32_t count = 0;
  if (value == 0) {
    return xbfs_append_char(buffer, capacity, offset, '0');
  }
  while (value != 0 && count < sizeof(digits)) {
    digits[count++] = (char)('0' + (value % 10U));
    value /= 10U;
  }
  while (count > 0) {
    --count;
    if (xbfs_append_char(buffer, capacity, offset, digits[count]) != XAIOS_OK) {
      return XAIOS_ERR_NO_MEMORY;
    }
  }
  return XAIOS_OK;
}

uint64_t xbfs_fnv1a64_extend(uint64_t hash, const void *buffer,
                               uint64_t size) {
  const uint8_t *bytes = (const uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    hash ^= bytes[i];
    hash *= FNV1A64_PRIME;
  }
  return hash;
}

uint64_t xbfs_fnv1a64(const void *buffer, uint64_t size) {
  return xbfs_fnv1a64_extend(FNV1A64_OFFSET, buffer, size);
}

uint64_t xbfs_mfs_checksum(const void *data, uint64_t size) {
  const uint8_t *bytes = (const uint8_t *)data;
  uint64_t hash = FNV1A64_OFFSET;
  for (uint64_t i = 0; i < size; ++i) {
    uint8_t value = (i >= XBFS_CHECKSUM_OFFSET &&
                     i < XBFS_CHECKSUM_OFFSET + sizeof(uint64_t))
                        ? 0U
                        : bytes[i];
    hash ^= value;
    hash *= FNV1A64_PRIME;
  }
  return hash;
}

void xbfs_copy_path(char dst[XBFS_PATH_MAX], const char *src) {
  uint32_t i = 0;
  while (i + 1U < XBFS_PATH_MAX && src[i] != '\0') {
    dst[i] = src[i];
    ++i;
  }
  dst[i] = '\0';
}

const char *xbfs_basename_of(const char *path) {
  const char *base = path;
  if (path == 0) {
    return 0;
  }
  for (uint32_t i = 0; path[i] != '\0'; ++i) {
    if (path[i] == '/' && path[i + 1U] != '\0') {
      base = &path[i + 1U];
    }
  }
  return base;
}

void xbfs_parent_path_of(const char *path, char parent[XBFS_PATH_MAX]) {
  uint32_t last_slash = 0;
  for (uint32_t i = 0; i < XBFS_PATH_MAX && path[i] != '\0'; ++i) {
    if (path[i] == '/') {
      last_slash = i;
    }
  }
  if (last_slash == 0) {
    parent[0] = '/';
    parent[1] = '\0';
    return;
  }
  for (uint32_t i = 0; i < last_slash; ++i) {
    parent[i] = path[i];
  }
  parent[last_slash] = '\0';
}

uint64_t xbfs_blocks_for_size(uint64_t size) {
  return (size + XBFS_SECTOR_SIZE - 1U) / XBFS_SECTOR_SIZE;
}

int xbfs_path_is_at_or_below(const char *path, const char *root) {
  uint64_t root_len = xbfs_cstr_len(root);
  return xbfs_str_eq(path, root) ||
         (xbfs_bytes_eq(path, root, root_len) && path[root_len] == '/');
}

int xbfs_direct_child_of(const char *parent, const char *child,
                           const char **name) {
  uint64_t parent_len = xbfs_cstr_len(parent);
  if (xbfs_str_eq(parent, "/")) {
    if (child[0] != '/' || child[1] == '\0') {
      return 0;
    }
    const char *tail = &child[1];
    for (uint64_t i = 0; tail[i] != '\0'; ++i) {
      if (tail[i] == '/') {
        return 0;
      }
    }
    *name = tail;
    return 1;
  }
  if (!xbfs_bytes_eq(parent, child, parent_len) || child[parent_len] != '/') {
    return 0;
  }
  const char *tail = &child[parent_len + 1U];
  if (*tail == '\0') {
    return 0;
  }
  for (uint64_t i = 0; tail[i] != '\0'; ++i) {
    if (tail[i] == '/') {
      return 0;
    }
  }
  *name = tail;
  return 1;
}
