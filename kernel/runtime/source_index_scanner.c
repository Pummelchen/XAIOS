/*
 * The C scanner of the source index, moved out of source_index.c so no source
 * file exceeds 500 lines. It walks one C translation unit, skips comments and
 * string and character literals, and records the typedef, struct, enum, union,
 * function and file-scope variable names it finds through the public
 * source_index_add_symbol(). The scan counter moved with the code that
 * increments it and source_index_scan_count() with the counter;
 * source_index_scanner_stats_reset() is the assignment
 * source_index_runtime_init() used to make inline, at the same point in the
 * same order. The only body change is the index-and-slot check at the top of
 * source_index_scan_source(), which now asks
 * source_index_file_is_scannable() instead of reaching the index table
 * directly; the checks, their order of effect and every return value are
 * unchanged. See source_index_internal.h.
 */

#include <xaios/klog.h>
#include <xaios/source_index.h>

#include "source_index_internal.h"

static uint64_t g_scan_count;

void source_index_scanner_stats_reset(void) {
  g_scan_count = 0;
}

static int c_is_alpha(char c) {
  return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
}

static int c_is_alnum(char c) {
  return c_is_alpha(c) || (c >= '0' && c <= '9');
}

static int c_keyword_at(const char *src, uint64_t pos, uint64_t len,
                        const char *kw) {
  uint32_t ki = 0;
  while (kw[ki] != '\0') {
    if (pos + ki >= len || src[pos + ki] != kw[ki]) {
      return 0;
    }
    ++ki;
  }
  if (pos + ki < len && c_is_alnum(src[pos + ki])) {
    return 0;
  }
  return 1;
}

static uint32_t c_extract_ident(const char *src, uint64_t pos, uint64_t len,
                                 char *name, uint32_t name_max) {
  uint32_t ni = 0;
  while (pos < len && c_is_alnum(src[pos]) && ni + 1U < name_max) {
    name[ni++] = src[pos++];
  }
  name[ni] = '\0';
  return ni;
}

static void c_skip_ws(const char *src, uint64_t *pos, uint64_t len) {
  while (*pos < len && (src[*pos] == ' ' || src[*pos] == '\t')) {
    ++(*pos);
  }
}

xaios_status_t source_index_scan_source(uint32_t index_id, uint32_t file_id,
                                       const char *source,
                                       uint64_t source_bytes) {
  if (!source_index_file_is_scannable(index_id, file_id) || source == 0 ||
      source_bytes == 0) {
    return XAIOS_ERR_INVALID;
  }

  uint32_t line = 1;
  uint32_t scanned = 0;
  uint64_t i = 0;

  while (i < source_bytes) {
    if (source[i] == '\n') {
      ++line;
      ++i;
      continue;
    }
    /* skip line comments */
    if (i + 1U < source_bytes && source[i] == '/' &&
        source[i + 1] == '/') {
      while (i < source_bytes && source[i] != '\n') { ++i; }
      continue;
    }
    /* skip block comments */
    if (i + 1U < source_bytes && source[i] == '/' &&
        source[i + 1] == '*') {
      i += 2;
      while (i + 1U < source_bytes &&
             !(source[i] == '*' && source[i + 1] == '/')) {
        if (source[i] == '\n') { ++line; }
        ++i;
      }
      if (i + 1U < source_bytes) { i += 2; }
      continue;
    }
    /* skip string/char literals */
    if (source[i] == '"' || source[i] == '\'') {
      char q = source[i++];
      while (i < source_bytes && source[i] != q) {
        if (source[i] == '\\' && i + 1U < source_bytes) { ++i; }
        ++i;
      }
      if (i < source_bytes) { ++i; }
      continue;
    }
    if (!c_is_alpha(source[i])) {
      ++i;
      continue;
    }
    /* identifier or keyword */
    uint64_t word_start = i;
    if (c_keyword_at(source, i, source_bytes, "typedef")) {
      i += 7;
      c_skip_ws(source, &i, source_bytes);
      /* skip type tokens until we find the alias name before ';' */
      while (i < source_bytes && source[i] != ';') {
        if (c_is_alpha(source[i])) {
          uint64_t ts = i;
          while (i < source_bytes && c_is_alnum(source[i])) { ++i; }
          uint64_t saved = i;
          c_skip_ws(source, &i, source_bytes);
          if (i < source_bytes && source[i] == ';') {
            char name[XAIOS_SOURCE_INDEX_SYMBOL_NAME_MAX];
            uint32_t nlen = c_extract_ident(source, ts, saved, name,
                                            sizeof(name));
            if (nlen > 0 &&
                source_index_add_symbol(index_id, file_id, name,
                    XAIOS_SOURCE_INDEX_SYMBOL_TYPE, line) == XAIOS_OK) {
              ++scanned;
            }
          }
          i = saved;
        } else {
          ++i;
        }
      }
      if (i < source_bytes) { ++i; }
      continue;
    }
    if (c_keyword_at(source, i, source_bytes, "struct") ||
        c_keyword_at(source, i, source_bytes, "enum") ||
        c_keyword_at(source, i, source_bytes, "union")) {
      i += 6;
      c_skip_ws(source, &i, source_bytes);
      if (i < source_bytes && c_is_alpha(source[i])) {
        char name[XAIOS_SOURCE_INDEX_SYMBOL_NAME_MAX];
        c_extract_ident(source, i, source_bytes, name, sizeof(name));
        if (source_index_add_symbol(index_id, file_id, name,
                XAIOS_SOURCE_INDEX_SYMBOL_TYPE, line) == XAIOS_OK) {
          ++scanned;
        }
      }
      while (i < source_bytes && source[i] != '{' && source[i] != ';') {
        ++i;
      }
      continue;
    }
    /* check for type keyword -> possible function def */
    int is_type_kw = 0;
    if (c_keyword_at(source, i, source_bytes, "void") ||
        c_keyword_at(source, i, source_bytes, "int") ||
        c_keyword_at(source, i, source_bytes, "char") ||
        c_keyword_at(source, i, source_bytes, "uint8_t") ||
        c_keyword_at(source, i, source_bytes, "uint16_t") ||
        c_keyword_at(source, i, source_bytes, "uint32_t") ||
        c_keyword_at(source, i, source_bytes, "uint64_t") ||
        c_keyword_at(source, i, source_bytes, "static") ||
        c_keyword_at(source, i, source_bytes, "xaios_status_t") ||
        c_keyword_at(source, i, source_bytes, "const")) {
      is_type_kw = 1;
    }
    if (is_type_kw) {
      /* skip type tokens until identifier+( or ; */
      while (i < source_bytes && c_is_alnum(source[i])) { ++i; }
      c_skip_ws(source, &i, source_bytes);
      /* skip pointer stars */
      while (i < source_bytes && source[i] == '*') {
        ++i;
        c_skip_ws(source, &i, source_bytes);
      }
      /* next identifier could be another type word or the function name */
      while (i < source_bytes && c_is_alpha(source[i])) {
        uint64_t id_start = i;
        uint32_t cur_line = line;
        char name[XAIOS_SOURCE_INDEX_SYMBOL_NAME_MAX];
        uint32_t nlen = c_extract_ident(source, i, source_bytes, name,
                                        sizeof(name));
        while (i < source_bytes && c_is_alnum(source[i])) { ++i; }
        c_skip_ws(source, &i, source_bytes);
        /* skip pointer stars after name */
        while (i < source_bytes && source[i] == '*') {
          ++i;
          c_skip_ws(source, &i, source_bytes);
        }
        if (i < source_bytes && source[i] == '(' && nlen > 0) {
          if (source_index_add_symbol(index_id, file_id, name,
                  XAIOS_SOURCE_INDEX_SYMBOL_FUNCTION, cur_line) == XAIOS_OK) {
            ++scanned;
          }
          break;
        }
        if (i < source_bytes && source[i] == ';') {
          if (nlen > 0 && id_start != word_start) {
            if (source_index_add_symbol(index_id, file_id, name,
                    XAIOS_SOURCE_INDEX_SYMBOL_VARIABLE, cur_line) == XAIOS_OK) {
              ++scanned;
            }
          }
          break;
        }
      }
      /* skip to end of statement or block */
      int depth = 0;
      while (i < source_bytes) {
        if (source[i] == '(') { ++depth; }
        if (source[i] == ')') {
          if (depth > 0) { --depth; }
        }
        if (source[i] == '{') { ++depth; }
        if (source[i] == '}') {
          if (depth > 0) { --depth; } else { ++i; break; }
        }
        if (depth == 0 && source[i] == ';') { ++i; break; }
        if (source[i] == '\n') { ++line; }
        ++i;
      }
      continue;
    }
    /* plain identifier - skip */
    while (i < source_bytes && c_is_alnum(source[i])) { ++i; }
  }

  ++g_scan_count;
  klog("source-index: %u scanned file=%u symbols=%lu lines=%u\n",
       index_id, file_id, (unsigned long)scanned, line);
  return XAIOS_OK;
}

uint64_t source_index_scan_count(void) {
  return g_scan_count;
}
