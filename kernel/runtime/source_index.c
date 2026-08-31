#include <xaios/arena.h>
#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/source_index.h>

#define MAX_SOURCE_INDEXES 3U
#define SOURCE_INDEX_ARENA_BASE 29U
#define SOURCE_INDEX_MAX_FILES 8U
#define SOURCE_INDEX_MAX_SYMBOLS 16U

#define SOURCE_INDEX_REVISION_MAX 32U

typedef enum {
  XAIOS_SOURCE_INDEX_SLOT_EMPTY = 0,
  XAIOS_SOURCE_INDEX_SLOT_USED = 1,
} xaios_source_index_record_state_t;

typedef struct {
  xaios_source_index_record_state_t state;
  uint32_t language;
  uint32_t file_id;
  uint64_t bytes;
  uint64_t content_hash;
  char path[XAIOS_SOURCE_INDEX_PATH_MAX];
} xaios_source_index_file_record_t;

typedef struct {
  xaios_source_index_record_state_t state;
  uint32_t file_id;
  uint32_t kind;
  uint32_t line;
  char name[XAIOS_SOURCE_INDEX_SYMBOL_NAME_MAX];
} xaios_source_index_symbol_record_t;

typedef struct {
  uint32_t revision_len;
  uint32_t file_count;
  uint32_t symbol_count;
  uint32_t update_count;
  char revision[SOURCE_INDEX_REVISION_MAX];
  xaios_source_index_file_record_t files[SOURCE_INDEX_MAX_FILES];
  xaios_source_index_symbol_record_t symbols[SOURCE_INDEX_MAX_SYMBOLS];
} xaios_source_index_storage_t;

typedef struct {
  xaios_source_index_state_t state;
  xaios_source_index_manifest_t manifest;
  uint32_t arena_id;
  uint64_t arena_base;
} xaios_source_index_t;

static xaios_source_index_t g_source_indexes[MAX_SOURCE_INDEXES];
static uint64_t g_active_count;
static uint64_t g_total_files;
static uint64_t g_total_symbols;
static uint64_t g_total_updates;
static uint64_t g_scan_count;

static int str_nonempty(const char *value) {
  return value != 0 && value[0] != '\0';
}

static int str_prefix(const char *value, const char *prefix) {
  if (!str_nonempty(value) || !str_nonempty(prefix)) {
    return 0;
  }
  while (*prefix != '\0') {
    if (*value != *prefix) {
      return 0;
    }
    ++value;
    ++prefix;
  }
  return 1;
}

static uint32_t string_length(const char *value) {
  uint32_t len = 0;
  while (value[len] != '\0') {
    ++len;
  }
  return len;
}

static int copy_if_fits(char *dst, uint32_t dst_size, const char *src,
                        uint32_t *out_len) {
  uint32_t len = 0;
  if (dst_size == 0) {
    return 0;
  }
  while (src[len] != '\0' && (len + 1U) < dst_size) {
    dst[len] = src[len];
    ++len;
  }
  dst[len] = '\0';
  if (src[len] != '\0') {
    return 0;
  }
  if (out_len != 0) {
    *out_len = len;
  }
  return 1;
}

static int paths_equal(const char *lhs, const char *rhs) {
  uint32_t i = 0;
  while (lhs[i] != '\0' && rhs[i] != '\0') {
    if (lhs[i] != rhs[i]) {
      return 0;
    }
    ++i;
  }
  return lhs[i] == rhs[i];
}

static xaios_source_index_t *lookup_index(uint32_t index_id) {
  if (index_id >= MAX_SOURCE_INDEXES) {
    return 0;
  }
  return &g_source_indexes[index_id];
}

static xaios_source_index_storage_t *storage_for(uint32_t index_id) {
  xaios_source_index_t *index = lookup_index(index_id);
  if (index == 0 || index->state == XAIOS_SOURCE_INDEX_EMPTY ||
      index->arena_base == 0) {
    return 0;
  }
  return (xaios_source_index_storage_t *)(uintptr_t)index->arena_base;
}

static void zero_storage(xaios_source_index_storage_t *storage) {
  uint8_t *bytes = (uint8_t *)storage;
  for (uint32_t i = 0; i < sizeof(xaios_source_index_storage_t); ++i) {
    bytes[i] = 0;
  }
}

static xaios_status_t validate_manifest(
    const xaios_source_index_manifest_t *manifest) {
  if (manifest == 0 || manifest->index_id >= MAX_SOURCE_INDEXES ||
      !str_prefix(manifest->repo_path, "/repo/") ||
      !str_nonempty(manifest->revision) ||
      string_length(manifest->revision) >= SOURCE_INDEX_REVISION_MAX ||
      manifest->source_arena_bytes < sizeof(xaios_source_index_storage_t)) {
    return XAIOS_ERR_INVALID;
  }
  return XAIOS_OK;
}

void source_index_runtime_init(void) {
  for (uint32_t i = 0; i < MAX_SOURCE_INDEXES; ++i) {
    g_source_indexes[i].state = XAIOS_SOURCE_INDEX_EMPTY;
    g_source_indexes[i].manifest.index_id = 0;
    g_source_indexes[i].manifest.cell_id = 0;
    g_source_indexes[i].manifest.repo_path = 0;
    g_source_indexes[i].manifest.revision = 0;
    g_source_indexes[i].manifest.source_arena_bytes = 0;
    g_source_indexes[i].arena_id = 0;
    g_source_indexes[i].arena_base = 0;
  }
  g_active_count = 0;
  g_total_files = 0;
  g_total_symbols = 0;
  g_total_updates = 0;
  g_scan_count = 0;
  klog("source-index: runtime initialized\n");
}

xaios_status_t source_index_create(const xaios_source_index_manifest_t *manifest) {
  if (validate_manifest(manifest) != XAIOS_OK) {
    return XAIOS_ERR_INVALID;
  }

  xaios_source_index_t *index = lookup_index(manifest->index_id);
  if (index->state != XAIOS_SOURCE_INDEX_EMPTY) {
    return XAIOS_ERR_BUSY;
  }

  uint32_t arena_id = SOURCE_INDEX_ARENA_BASE + manifest->index_id;
  const xaios_arena_t *arena = 0;
  if (arena_create(arena_id, XAIOS_ARENA_SOURCE_INDEX, manifest->index_id,
                   "source-index", manifest->source_arena_bytes, 0,
                   &arena) != XAIOS_OK) {
    return XAIOS_ERR_NO_MEMORY;
  }

  index->state = XAIOS_SOURCE_INDEX_CREATED;
  index->manifest.index_id = manifest->index_id;
  index->manifest.cell_id = manifest->cell_id;
  index->manifest.repo_path = manifest->repo_path;
  index->manifest.revision = manifest->revision;
  index->manifest.source_arena_bytes = manifest->source_arena_bytes;
  index->arena_id = arena_id;
  index->arena_base = arena->base;

  xaios_source_index_storage_t *storage = storage_for(manifest->index_id);
  if (storage == 0) {
    kassert(arena_destroy(arena_id) == XAIOS_OK);
    index->state = XAIOS_SOURCE_INDEX_EMPTY;
    index->arena_base = 0;
    return XAIOS_ERR_INVALID;
  }

  zero_storage(storage);
  if (copy_if_fits(storage->revision, sizeof(storage->revision),
                   manifest->revision, &storage->revision_len) == 0) {
    kassert(arena_destroy(arena_id) == XAIOS_OK);
    index->state = XAIOS_SOURCE_INDEX_EMPTY;
    index->arena_base = 0;
    index->arena_id = 0;
    return XAIOS_ERR_INVALID;
  }

  ++g_active_count;
  klog("source-index: created id=%u cell=%u repo=%s arena_id=%u revision=%s\n",
       manifest->index_id, manifest->cell_id, manifest->repo_path,
       arena_id, storage->revision);
  return XAIOS_OK;
}

xaios_status_t source_index_add_file(uint32_t index_id, const char *path,
                                   uint32_t language, uint64_t bytes,
                                   uint64_t content_hash) {
  xaios_source_index_t *index = lookup_index(index_id);
  if (index == 0 || index->state != XAIOS_SOURCE_INDEX_CREATED ||
      !str_prefix(path, "/repo/") || bytes == 0 || content_hash == 0 ||
      language > XAIOS_SOURCE_INDEX_LANG_RUST) {
    return XAIOS_ERR_INVALID;
  }

  if (string_length(path) >= XAIOS_SOURCE_INDEX_PATH_MAX) {
    return XAIOS_ERR_INVALID;
  }

  xaios_source_index_storage_t *storage = storage_for(index_id);
  if (storage == 0 || storage->file_count >= SOURCE_INDEX_MAX_FILES) {
    return XAIOS_ERR_NO_MEMORY;
  }

  for (uint32_t i = 0; i < storage->file_count; ++i) {
    if (paths_equal(storage->files[i].path, path)) {
      return XAIOS_ERR_BUSY;
    }
  }

  uint32_t slot = storage->file_count;
  storage->files[slot].state = XAIOS_SOURCE_INDEX_SLOT_USED;
  storage->files[slot].file_id = slot;
  storage->files[slot].language = language;
  storage->files[slot].bytes = bytes;
  storage->files[slot].content_hash = content_hash;
  copy_if_fits(storage->files[slot].path, XAIOS_SOURCE_INDEX_PATH_MAX, path, 0);
  ++storage->file_count;
  ++g_total_files;

  klog("source-index: %u add file id=%u path=%s language=%u bytes=%lu\n",
       index_id, storage->files[slot].file_id, storage->files[slot].path,
       language, bytes);
  return XAIOS_OK;
}

xaios_status_t source_index_add_symbol(uint32_t index_id, uint32_t file_id,
                                     const char *name,
                                     uint32_t kind, uint32_t line) {
  xaios_source_index_t *index = lookup_index(index_id);
  if (index == 0 || index->state != XAIOS_SOURCE_INDEX_CREATED ||
      !str_nonempty(name) ||
      string_length(name) >= XAIOS_SOURCE_INDEX_SYMBOL_NAME_MAX ||
      kind > XAIOS_SOURCE_INDEX_SYMBOL_VARIABLE || line == 0) {
    return XAIOS_ERR_INVALID;
  }

  xaios_source_index_storage_t *storage = storage_for(index_id);
  if (storage == 0 || storage->symbol_count >= SOURCE_INDEX_MAX_SYMBOLS ||
      file_id >= storage->file_count ||
      storage->files[file_id].state != XAIOS_SOURCE_INDEX_SLOT_USED) {
    return XAIOS_ERR_INVALID;
  }

  for (uint32_t i = 0; i < storage->symbol_count; ++i) {
    if (storage->symbols[i].state == XAIOS_SOURCE_INDEX_SLOT_USED &&
        storage->symbols[i].file_id == file_id &&
        storage->symbols[i].kind == kind &&
        storage->symbols[i].line == line &&
        paths_equal(storage->symbols[i].name, name)) {
      return XAIOS_ERR_BUSY;
    }
  }

  uint32_t slot = storage->symbol_count;
  storage->symbols[slot].state = XAIOS_SOURCE_INDEX_SLOT_USED;
  storage->symbols[slot].file_id = file_id;
  storage->symbols[slot].kind = kind;
  storage->symbols[slot].line = line;
  copy_if_fits(storage->symbols[slot].name,
               XAIOS_SOURCE_INDEX_SYMBOL_NAME_MAX, name, 0);
  ++storage->symbol_count;
  ++g_total_symbols;

  klog("source-index: %u add symbol id=%u file=%u kind=%u line=%u\n",
       index_id, slot, file_id, kind, line);
  return XAIOS_OK;
}

xaios_status_t source_index_incremental_update(uint32_t index_id,
                                            const char *revision) {
  xaios_source_index_t *index = lookup_index(index_id);
  if (index == 0 || index->state != XAIOS_SOURCE_INDEX_CREATED ||
      !str_nonempty(revision) ||
      string_length(revision) >= SOURCE_INDEX_REVISION_MAX) {
    return XAIOS_ERR_INVALID;
  }

  xaios_source_index_storage_t *storage = storage_for(index_id);
  if (storage == 0) {
    return XAIOS_ERR_INVALID;
  }

  if (paths_equal(storage->revision, revision)) {
    return XAIOS_ERR_INVALID;
  }

  if (copy_if_fits(storage->revision, sizeof(storage->revision), revision,
                   &storage->revision_len) == 0) {
    return XAIOS_ERR_INVALID;
  }

  ++storage->update_count;
  ++g_total_updates;
  klog("source-index: %u update revision=%s count=%u\n", index_id,
       storage->revision, storage->update_count);
  return XAIOS_OK;
}

uint64_t source_index_active_count(void) {
  return g_active_count;
}

uint64_t source_index_total_file_records(void) {
  return g_total_files;
}

uint64_t source_index_total_symbol_records(void) {
  return g_total_symbols;
}

uint64_t source_index_total_updates(void) {
  return g_total_updates;
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
  xaios_source_index_t *index = lookup_index(index_id);
  if (index == 0 || index->state != XAIOS_SOURCE_INDEX_CREATED ||
      source == 0 || source_bytes == 0) {
    return XAIOS_ERR_INVALID;
  }

  xaios_source_index_storage_t *storage = storage_for(index_id);
  if (storage == 0 || file_id >= storage->file_count ||
      storage->files[file_id].state != XAIOS_SOURCE_INDEX_SLOT_USED) {
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

uint64_t source_index_query_symbol_count(uint32_t index_id, uint32_t file_id,
                                         uint32_t kind) {
  xaios_source_index_storage_t *storage = storage_for(index_id);
  if (storage == 0) {
    return 0;
  }
  uint64_t count = 0;
  for (uint32_t i = 0; i < storage->symbol_count; ++i) {
    if (storage->symbols[i].state == XAIOS_SOURCE_INDEX_SLOT_USED &&
        storage->symbols[i].file_id == file_id &&
        storage->symbols[i].kind == kind) {
      ++count;
    }
  }
  return count;
}

uint64_t source_index_scan_count(void) {
  return g_scan_count;
}

void source_index_self_test(void) {
  source_index_runtime_init();

  xaios_source_index_manifest_t invalid;
  invalid.index_id = 0;
  invalid.cell_id = 1;
  invalid.repo_path = "repo/app/main";
  invalid.revision = "r1";
  invalid.source_arena_bytes = sizeof(xaios_source_index_storage_t);
  kassert(source_index_create(&invalid) == XAIOS_ERR_INVALID);

  invalid.repo_path = "/repo/app";
  invalid.revision = "r1";
  invalid.source_arena_bytes = sizeof(xaios_source_index_storage_t);
  kassert(source_index_create(&invalid) == XAIOS_OK);
  kassert(source_index_create(&invalid) == XAIOS_ERR_BUSY);

  kassert(source_index_add_file(0, "/repo/app/main.c", XAIOS_SOURCE_INDEX_LANG_C,
                               2048, 0x111111ULL) == XAIOS_OK);
  kassert(source_index_add_file(0, "/repo/app/main.c", XAIOS_SOURCE_INDEX_LANG_C,
                               512, 0x222222ULL) == XAIOS_ERR_BUSY);
  kassert(source_index_add_file(0, "/repo/app/xaios-agent.c", XAIOS_SOURCE_INDEX_LANG_C,
                               3072, 0x333333ULL) == XAIOS_OK);

  kassert(source_index_add_symbol(0, 0, "init", XAIOS_SOURCE_INDEX_SYMBOL_FUNCTION, 12) ==
          XAIOS_OK);
  kassert(source_index_add_symbol(0, 1, "build_weights",
                                 XAIOS_SOURCE_INDEX_SYMBOL_FUNCTION, 88) ==
          XAIOS_OK);
  kassert(source_index_add_symbol(0, 99, "oops", XAIOS_SOURCE_INDEX_SYMBOL_FUNCTION,
                                 1) == XAIOS_ERR_INVALID);

  kassert(source_index_incremental_update(0, "r2") == XAIOS_OK);
  kassert(source_index_incremental_update(0, "") == XAIOS_ERR_INVALID);

  kassert(source_index_active_count() == 1);
  kassert(source_index_total_file_records() == 2);
  kassert(source_index_total_symbol_records() == 2);
  kassert(source_index_total_updates() == 1);
  klog("source-index: fixture loaded files=%lu symbols=%lu updates=%lu\n",
       source_index_total_file_records(), source_index_total_symbol_records(),
       source_index_total_updates());

  /* C source scanner test */
  static const char c_fixture[] =
      "/* test source */\n"
      "typedef int myint;\n"
      "struct point { int x; int y; };\n"
      "static void init(void) {\n"
      "  int val = 0;\n"
      "}\n"
      "int compute(int a) {\n"
      "  return a;\n"
      "}\n";
  kassert(source_index_scan_source(0, 0, c_fixture,
                                   sizeof(c_fixture) - 1) == XAIOS_OK);
  kassert(source_index_scan_source(0, 99, c_fixture, 1) == XAIOS_ERR_INVALID);
  kassert(source_index_query_symbol_count(0, 0,
      XAIOS_SOURCE_INDEX_SYMBOL_FUNCTION) >= 2);
  kassert(source_index_query_symbol_count(0, 0,
      XAIOS_SOURCE_INDEX_SYMBOL_TYPE) >= 2);
  kassert(source_index_scan_count() == 1);
  klog("source-index: C scanner self-test passed scans=%lu symbols=%lu\n",
       source_index_scan_count(),
       (unsigned long)source_index_query_symbol_count(0, 0,
           XAIOS_SOURCE_INDEX_SYMBOL_FUNCTION));
}
