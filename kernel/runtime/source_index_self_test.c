/*
 * The source-index boot fixture self-test, moved out of source_index.c so no
 * source file exceeds 500 lines. It drives the public <xaios/source_index.h>
 * lifecycle exactly as before, including the file/symbol/update counts and the
 * two gated boot markers "source-index: fixture loaded files=2 symbols=2
 * updates=1" and "source-index: C scanner self-test passed scans=1 ...", which
 * are unchanged in wording and in the values they print. The only include it
 * needs beyond the public header is source_index_internal.h, for the
 * sizeof(xaios_source_index_storage_t) arena request.
 */

#include <xaios/assert.h>
#include <xaios/klog.h>
#include <xaios/source_index.h>

#include "source_index_internal.h"

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
