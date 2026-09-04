#ifndef XAIOS_RISCV64_FDT_H
#define XAIOS_RISCV64_FDT_H

#include <stdint.h>

/* One property, with enough of its context to be acted on: which node it
   belongs to, and the cell widths in force there. The cell widths matter --
   a "reg" value is a list of addresses and sizes whose widths are declared
   by an ancestor, so a reader that assumes 64-bit addresses gets the right
   answer on this board and the wrong one on a machine that declares 32. */
typedef struct fdt_property {
  const char *node_name;
  const char *name;
  const uint8_t *value;
  uint32_t length;
  uint32_t address_cells;
  uint32_t size_cells;
  uint32_t depth;
} fdt_property_t;

typedef void (*fdt_visit_fn)(const fdt_property_t *property, void *context);

int fdt_valid(const void *blob);
uint64_t fdt_total_size(const void *blob);
void fdt_walk(const void *blob, fdt_visit_fn visit, void *context);

/* The first memory range the tree declares. */
int fdt_find_memory(const void *blob, uint64_t *base, uint64_t *size);

/* The first address in the `reg` of the first node whose name is `node_name`
   or `node_name@...`. */
int fdt_find_node_address(const void *blob, const char *node_name,
                          uint64_t *address);

/* The address of the first node whose `compatible` list contains this
   string. Preferred over a name lookup: names are a convention, compatible
   is the contract. */
int fdt_find_compatible(const void *blob, const char *compatible,
                        uint64_t *address);

/* How many nodes declare this compatible string. A scan that assumes a fixed
   number of slots reads past the ones that exist, and an unassigned address
   faults rather than reading as absent. */
uint32_t fdt_count_compatible(const void *blob, const char *compatible);

/* The lowest address among matching nodes -- what a window starts at. The
   tree's node order is not sorted, so the first match is not the first
   slot. */
/* A named property of the node matching a compatible string, returned as the
   raw big-endian bytes the tree holds. Used for `ranges`, whose layout the
   caller knows and this parser does not. */
int fdt_find_compatible_property(const void *blob, const char *compatible,
                                 const char *name, const uint8_t **value,
                                 uint32_t *length);

/* The lowest address among the nodes matching a compatible string, and the
   first interrupt that node declares. `interrupt` may be null; it is set to
   zero when the node declares none. */
int fdt_find_compatible_lowest(const void *blob, const char *compatible,
                               uint64_t *address, uint32_t *interrupt);

#endif
