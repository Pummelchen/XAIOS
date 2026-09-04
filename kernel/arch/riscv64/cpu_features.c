#include <xaios/cpu_features.h>
#include <xaios/riscv64_fdt.h>

int riscv64_timer_has_stimecmp(void);
const void *riscv64_device_tree(void);

/* The ISA string is the device tree's, because misa is a machine-mode
   register a supervisor cannot read. "rv64imafdcv_zicsr..." -- the single
   letters follow the base, the multi-letter extensions follow underscores. */
typedef struct isa_search {
  int vector;
  int found;
} isa_search_t;

static int property_is(const char *name, const char *wanted) {
  while (*wanted != '\0' && *name == *wanted) { ++name; ++wanted; }
  return *name == '\0' && *wanted == '\0';
}

static void find_isa(const fdt_property_t *property, void *context) {
  isa_search_t *search = (isa_search_t *)context;
  if (search->found != 0 || !property_is(property->name, "riscv,isa")) return;
  const char *isa = (const char *)property->value;
  uint32_t i = 0U;
  search->found = 1;
  if (property->length < 5U) return;
  /* Skip "rv64" or "rv32", then read single-letter extensions up to the
     first underscore or the end. */
  i = 4U;
  while (i < property->length && isa[i] != '\0' && isa[i] != '_') {
    if (isa[i] == 'v') search->vector = 1;
    ++i;
  }
}

void cpu_features_query(xaios_cpu_features_t *features) {
  isa_search_t search = {0, 0};
  if (features == 0) return;
  features->neon = 0U; features->sve = 0U; features->avx2 = 0U;
  features->avx512 = 0U; features->vnni = 0U; features->amx = 0U;
  if (riscv64_device_tree() != 0) {
    fdt_walk(riscv64_device_tree(), find_isa, &search);
  }
  features->rvv = search.vector != 0 ? 1U : 0U;
  features->sstc = riscv64_timer_has_stimecmp() != 0 ? 1U : 0U;
}
