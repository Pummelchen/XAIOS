/*
 * Private interface shared by the source-index translation units after
 * source_index.c was split so no source file exceeds 500 lines.
 *
 * source_index.c keeps the index table, the arena-backed storage, the
 * create/add-file/add-symbol/update lifecycle and the four lifecycle
 * counters. The C scanner lives in source_index_scanner.c together with the
 * scan counter it drives and source_index_scan_count(); the boot fixture
 * self-test lives in source_index_self_test.c.
 *
 * Only the record and storage types the scanner and the self-test read, and
 * the two helpers they call, cross a file boundary here. The functions the
 * public <xaios/source_index.h> already declares keep their names; the two
 * new globals carry the module's source_index_ prefix.
 *
 * source_index_file_is_scannable() reports whether an index and file slot are
 * usable; it returns an int, so neither the index table nor the arena behind
 * it leaks out of source_index.c. The scan counter
 * moved with the scanner that increments it; source_index_runtime_init()
 * reaches it through source_index_scanner_stats_reset(), which performs
 * exactly the assignment the unsplit init performed inline, at the same point
 * in the same order. No counter takes a lock before or after, so no critical
 * section changes shape.
 */
#ifndef XAIOS_KERNEL_RUNTIME_SOURCE_INDEX_INTERNAL_H
#define XAIOS_KERNEL_RUNTIME_SOURCE_INDEX_INTERNAL_H

#include <xaios/source_index.h>
#include <xaios/types.h>

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

/* Defined in source_index.c. Nonzero when the index exists in the created
   state and its arena holds a used record for file_id. */
int source_index_file_is_scannable(uint32_t index_id, uint32_t file_id);

/* Defined in source_index_scanner.c. Zeroes the scan counter exactly where
   source_index_runtime_init() zeroed it inline. */
void source_index_scanner_stats_reset(void);

#endif /* XAIOS_KERNEL_RUNTIME_SOURCE_INDEX_INTERNAL_H */
