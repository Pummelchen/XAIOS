/* The lookups built on fdt_walk: memory, node, compatible and property
 * discovery.
 *
 * This was the tail of the single 613-line fdt.c, which is now the reader
 * core -- the big-endian primitives, the validity and size questions, and
 * the one structural walk in fdt_walk. Everything here answers a question by
 * walking that tree: where memory is, where a named node or a compatible
 * string lives, how many nodes declare one, the lowest address among them
 * and the interrupt it is wired to, a named property of a matched or named
 * node, and which hart owns an interrupt-controller phandle.
 *
 * The split is a size split. Every pass, guard, ordering and diagnostic is
 * the one the single file had, and the public names and signatures are
 * unchanged. The big-endian read and the string comparison cross between the
 * two files through fdt_internal.h and are defined once in fdt.c; `be64`,
 * `read_cells`, `node_name_matches` and the compatible matcher moved here
 * unchanged and stayed static, because only this side uses them. Both files
 * are compiled together by scripts/build-riscv64.sh.
 *
 * This is arch-private: the public interface stays in xaios/riscv64_fdt.h.
 */
#include <xaios/riscv64_fdt.h>

#include <stdint.h>

#include "fdt_internal.h"

/* Big-endian 64-bit read, assembled from the two 32-bit halves. Only
   read_cells below uses it. */
static uint64_t be64(const void *pointer) {
  const uint8_t *bytes = (const uint8_t *)pointer;
  return ((uint64_t)riscv64_fdt_be32(bytes) << 32) |
         (uint64_t)riscv64_fdt_be32(bytes + 4);
}

/* Whether `name` is `prefix` or `prefix@something`. Device-tree node names
   carry a unit address after an @, so a caller looking for "memory" has to
   match "memory@80000000" as well, and a caller looking for "memory" must
   not match "memory-controller". */
int riscv64_fdt_node_name_matches(const char *name, const char *prefix) {
  while (*prefix != '\0') {
    if (*name != *prefix) return 0;
    ++name;
    ++prefix;
  }
  return *name == '\0' || *name == '@';
}

uint64_t riscv64_fdt_read_cells(const uint8_t *data, uint32_t cells) {
  return cells >= 2U ? be64(data) : (uint64_t)riscv64_fdt_be32(data);
}

typedef struct memory_search {
  uint64_t base;
  uint64_t size;
  int found;
} memory_search_t;

static void find_memory(const fdt_property_t *property, void *context) {
  memory_search_t *search = (memory_search_t *)context;
  if (search->found != 0) return;
  if (!riscv64_fdt_node_name_matches(property->node_name, "memory")) return;
  if (!riscv64_fdt_string_equal(property->name, "reg")) return;
  uint32_t stride = (property->address_cells + property->size_cells) * 4U;
  if (property->length < stride) return;
  search->base = riscv64_fdt_read_cells(property->value, property->address_cells);
  search->size = riscv64_fdt_read_cells(property->value + property->address_cells * 4U,
                            property->size_cells);
  search->found = 1;
}

int fdt_find_memory(const void *blob, uint64_t *base, uint64_t *size) {
  memory_search_t search = {0U, 0U, 0};
  fdt_walk(blob, find_memory, &search);
  if (search.found == 0 || base == 0 || size == 0) return 0;
  *base = search.base;
  *size = search.size;
  return 1;
}

typedef struct node_search {
  const char *wanted_node;
  const char *wanted_property;
  uint64_t value;
  int found;
} node_search_t;

static void find_node_reg(const fdt_property_t *property, void *context) {
  node_search_t *search = (node_search_t *)context;
  if (search->found != 0) return;
  if (!riscv64_fdt_node_name_matches(property->node_name, search->wanted_node)) return;
  if (!riscv64_fdt_string_equal(property->name, search->wanted_property))
    return;
  if (property->length < property->address_cells * 4U) return;
  search->value = riscv64_fdt_read_cells(property->value, property->address_cells);
  search->found = 1;
}

int fdt_find_node_address(const void *blob, const char *node_name,
                          uint64_t *address) {
  node_search_t search = {node_name, "reg", 0U, 0};
  fdt_walk(blob, find_node_reg, &search);
  if (search.found == 0 || address == 0) return 0;
  *address = search.value;
  return 1;
}


/* Find a device by what it *is*, not by what it is called.
 *
 * Node names are a convention and not a contract. The PLIC on QEMU's virt
 * board is called `interrupt-controller@c000000`, not `plic@...` -- and
 * `interrupt-controller` on its own is a different node entirely, the hart's
 * local controller under /cpus. Looking it up by name found neither, and the
 * kernel reported "no plic in the device tree" on a board that has one.
 *
 * `compatible` is the contract. Two passes, because a node's compatible and
 * its reg arrive in whatever order the tree was written and one pass would
 * have to assume which comes first.
 */
typedef struct compatible_search {
  const char *wanted;
  const char *node_name;
  uint64_t address;
  int matched;
  int have_address;
} compatible_search_t;

/* `compatible` is a list of NUL-separated strings, so a prefix match against
   the whole value would miss every entry but the first. */
static int compatible_contains(const uint8_t *value, uint32_t length,
                               const char *wanted) {
  uint32_t offset = 0U;
  while (offset < length) {
    const char *entry = (const char *)(value + offset);
    if (riscv64_fdt_string_equal(entry, wanted)) return 1;
    while (offset < length && value[offset] != 0U) ++offset;
    ++offset;
  }
  return 0;
}

static void find_compatible_node(const fdt_property_t *property,
                                 void *context) {
  compatible_search_t *search = (compatible_search_t *)context;
  if (search->matched != 0) return;
  if (!riscv64_fdt_string_equal(property->name, "compatible")) return;
  if (!compatible_contains(property->value, property->length, search->wanted)) {
    return;
  }
  search->node_name = property->node_name;
  search->matched = 1;
}

static void find_matched_reg(const fdt_property_t *property, void *context) {
  compatible_search_t *search = (compatible_search_t *)context;
  if (search->have_address != 0) return;
  if (search->node_name == 0) return;
  if (!riscv64_fdt_string_equal(property->node_name, search->node_name)) return;
  if (!riscv64_fdt_string_equal(property->name, "reg")) return;
  if (property->length < property->address_cells * 4U) return;
  search->address = riscv64_fdt_read_cells(property->value, property->address_cells);
  search->have_address = 1;
}

int fdt_find_compatible(const void *blob, const char *compatible,
                        uint64_t *address) {
  compatible_search_t search = {compatible, 0, 0U, 0, 0};
  fdt_walk(blob, find_compatible_node, &search);
  if (search.matched == 0) return 0;
  fdt_walk(blob, find_matched_reg, &search);
  if (search.have_address == 0 || address == 0) return 0;
  *address = search.address;
  return 1;
}


typedef struct compatible_count {
  const char *wanted;
  uint32_t count;
} compatible_count_t;

static void count_compatible(const fdt_property_t *property, void *context) {
  compatible_count_t *counter = (compatible_count_t *)context;
  if (!riscv64_fdt_string_equal(property->name, "compatible")) return;
  if (compatible_contains(property->value, property->length, counter->wanted)) {
    ++counter->count;
  }
}

uint32_t fdt_count_compatible(const void *blob, const char *compatible) {
  compatible_count_t counter = {compatible, 0U};
  fdt_walk(blob, count_compatible, &counter);
  return counter.count;
}


/* The lowest address among nodes with this compatible string.
 *
 * Not the first one found, which is what fdt_find_compatible gives and what
 * is wrong for a window: this tree lists virtio_mmio@10008000 before
 * @10001000, so taking the first put the scan base at the last slot and every
 * probe after it ran off the end of the devices that exist.
 *
 * Two passes, for the reason the earlier two-pass search already gave and
 * this one initially ignored: a node's `reg` and its `compatible` arrive in
 * whatever order the tree was written, and in this tree `reg` comes first.
 * A single pass that waits to see `compatible` before accepting a `reg`
 * therefore matched nothing at all, and the window silently kept its default
 * -- which is a worse failure than not finding it, because it looks like
 * success.
 */
#define FDT_MAX_MATCHES 32U

typedef struct lowest_search {
  const char *wanted;
  const char *names[FDT_MAX_MATCHES];
  uint32_t name_count;
  uint64_t lowest;
  const char *lowest_name;
  uint32_t interrupt;
  int have_interrupt;
  int found;
} lowest_search_t;

static void collect_matching_names(const fdt_property_t *property,
                                   void *context) {
  lowest_search_t *search = (lowest_search_t *)context;
  if (!riscv64_fdt_string_equal(property->name, "compatible")) return;
  if (!compatible_contains(property->value, property->length, search->wanted)) {
    return;
  }
  if (search->name_count < FDT_MAX_MATCHES) {
    search->names[search->name_count++] = property->node_name;
  }
}

static void lowest_reg_of_matches(const fdt_property_t *property,
                                  void *context) {
  lowest_search_t *search = (lowest_search_t *)context;
  if (!riscv64_fdt_string_equal(property->name, "reg")) return;
  if (property->length < property->address_cells * 4U) return;
  for (uint32_t i = 0U; i < search->name_count; ++i) {
    if (!riscv64_fdt_string_equal(property->node_name, search->names[i]))
      continue;
    uint64_t address = riscv64_fdt_read_cells(property->value, property->address_cells);
    if (search->found == 0 || address < search->lowest) {
      search->lowest = address;
      search->lowest_name = property->node_name;
      search->found = 1;
    }
    return;
  }
}

/* The interrupt the lowest-addressed match is wired to.
 *
 * A third pass, because the node is only known after the second: `interrupts`
 * and `reg` can appear in either order, and the node with the lowest address
 * is not the first one the tree lists -- QEMU emits these in descending
 * order. */
static void interrupt_of_lowest(const fdt_property_t *property,
                                void *context) {
  lowest_search_t *search = (lowest_search_t *)context;
  if (search->have_interrupt != 0 || search->lowest_name == 0) return;
  if (!riscv64_fdt_string_equal(property->node_name, search->lowest_name))
    return;
  if (!riscv64_fdt_string_equal(property->name, "interrupts")) return;
  if (property->length < 4U) return;
  const uint8_t *value = property->value;
  search->interrupt = ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16) |
                      ((uint32_t)value[2] << 8) | (uint32_t)value[3];
  search->have_interrupt = 1;
}

int fdt_find_compatible_lowest(const void *blob, const char *compatible,
                               uint64_t *address, uint32_t *interrupt) {
  lowest_search_t search;
  search.wanted = compatible;
  search.name_count = 0U;
  search.lowest = 0U;
  search.lowest_name = 0;
  search.interrupt = 0U;
  search.have_interrupt = 0;
  search.found = 0;
  fdt_walk(blob, collect_matching_names, &search);
  if (search.name_count == 0U) return 0;
  fdt_walk(blob, lowest_reg_of_matches, &search);
  if (search.found == 0 || address == 0) return 0;
  fdt_walk(blob, interrupt_of_lowest, &search);
  *address = search.lowest;
  if (interrupt != 0) {
    *interrupt = search.have_interrupt != 0 ? search.interrupt : 0U;
  }
  return 1;
}

/* A named property of the node matching a compatible string.
 *
 * Two passes for the same reason fdt_find_compatible needs them: properties
 * arrive in the order the tree stores them, and `ranges` can precede
 * `compatible` in the very node being looked for. */
typedef struct property_search {
  const char *wanted;
  const char *property;
  const char *node_name;
  const uint8_t *value;
  uint32_t length;
  int matched;
  int found;
} property_search_t;

static void find_named_property(const fdt_property_t *property, void *context) {
  property_search_t *search = (property_search_t *)context;
  if (search->found != 0 || search->node_name == 0) return;
  if (!riscv64_fdt_string_equal(property->node_name, search->node_name)) return;
  if (!riscv64_fdt_string_equal(property->name, search->property)) return;
  search->value = property->value;
  search->length = property->length;
  search->found = 1;
}

static void find_property_node(const fdt_property_t *property, void *context) {
  property_search_t *search = (property_search_t *)context;
  if (search->matched != 0) return;
  if (!riscv64_fdt_string_equal(property->name, "compatible")) return;
  if (!compatible_contains(property->value, property->length, search->wanted)) {
    return;
  }
  search->node_name = property->node_name;
  search->matched = 1;
}

int fdt_find_compatible_property(const void *blob, const char *compatible,
                                 const char *name, const uint8_t **value,
                                 uint32_t *length) {
  property_search_t search = {compatible, name, 0, 0, 0U, 0, 0};
  fdt_walk(blob, find_property_node, &search);
  if (search.matched == 0) return 0;
  fdt_walk(blob, find_named_property, &search);
  if (search.found == 0 || value == 0 || length == 0) return 0;
  *value = search.value;
  *length = search.length;
  return 1;
}


/* Every node with a compatible string, not just the first one.
 *
 * Two passes over the tree rather than one, for the reason the searches above
 * already give and this one cannot avoid either: a node's `compatible`, its
 * `reg` and its `phandle` arrive in whatever order the tree was written, and
 * QEMU writes `phandle` first and `compatible` last. A single pass would have
 * to decide whether to believe a `reg` before it knows whose node it is.
 *
 * The count returned is how many matched, which can exceed `max`. A caller
 * that gets back more than it had room for has been told its assumption about
 * the board is wrong, which is more useful than a silent truncation.
 */
typedef struct all_search {
  const char *wanted;
  fdt_node_ref_t *matches;
  uint32_t max;
  uint32_t count;
} all_search_t;

static void collect_all_compatible(const fdt_property_t *property,
                                   void *context) {
  all_search_t *search = (all_search_t *)context;
  if (!riscv64_fdt_string_equal(property->name, "compatible")) return;
  if (!compatible_contains(property->value, property->length, search->wanted)) {
    return;
  }
  if (search->count < search->max) {
    fdt_node_ref_t *slot = &search->matches[search->count];
    slot->node_name = property->node_name;
    slot->address = 0U;
    slot->size = 0U;
    slot->phandle = 0U;
  }
  ++search->count;
}

static void fill_all_reg(const fdt_property_t *property, void *context) {
  all_search_t *search = (all_search_t *)context;
  uint32_t limit = search->count < search->max ? search->count : search->max;
  int is_reg = riscv64_fdt_string_equal(property->name, "reg");
  int is_phandle = riscv64_fdt_string_equal(property->name, "phandle");
  if (is_reg == 0 && is_phandle == 0) return;
  for (uint32_t index = 0U; index < limit; ++index) {
    fdt_node_ref_t *slot = &search->matches[index];
    if (!riscv64_fdt_string_equal(property->node_name, slot->node_name))
      continue;
    if (is_phandle != 0) {
      if (property->length >= 4U) slot->phandle = riscv64_fdt_be32(property->value);
      return;
    }
    if (property->length < property->address_cells * 4U) return;
    slot->address = riscv64_fdt_read_cells(property->value, property->address_cells);
    if (property->length >=
        (property->address_cells + property->size_cells) * 4U) {
      slot->size = riscv64_fdt_read_cells(property->value + property->address_cells * 4U,
                              property->size_cells);
    }
    return;
  }
}

uint32_t fdt_find_compatible_all(const void *blob, const char *compatible,
                                 fdt_node_ref_t *matches, uint32_t max) {
  all_search_t search;
  search.wanted = compatible;
  search.matches = matches;
  search.max = matches == 0 ? 0U : max;
  search.count = 0U;
  fdt_walk(blob, collect_all_compatible, &search);
  if (search.count != 0U && search.max != 0U) {
    fdt_walk(blob, fill_all_reg, &search);
  }
  return search.count;
}

typedef struct named_property_search {
  const char *node_name;
  const char *property;
  const uint8_t *value;
  uint32_t length;
  int found;
} named_property_search_t;

static void find_property_of_named_node(const fdt_property_t *property,
                                        void *context) {
  named_property_search_t *search = (named_property_search_t *)context;
  if (search->found != 0) return;
  if (!riscv64_fdt_string_equal(property->node_name, search->node_name)) return;
  if (!riscv64_fdt_string_equal(property->name, search->property)) return;
  search->value = property->value;
  search->length = property->length;
  search->found = 1;
}

int fdt_node_property(const void *blob, const char *node_name,
                      const char *name, const uint8_t **value,
                      uint32_t *length) {
  named_property_search_t search = {node_name, name, 0, 0U, 0};
  if (node_name == 0 || name == 0) return 0;
  fdt_walk(blob, find_property_of_named_node, &search);
  if (search.found == 0 || value == 0 || length == 0) return 0;
  *value = search.value;
  *length = search.length;
  return 1;
}
