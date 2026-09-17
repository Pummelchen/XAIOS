/* Which hart a local interrupt controller belongs to.
 *
 * This was the tail of kernel/arch/riscv64/fdt_lookup.c, itself the tail of
 * the single 613-line fdt.c. It moved when fdt_lookup.c crossed the 500-line
 * limit; the code is the one that file had, byte for byte, with the two
 * helpers it shares with the lookup module reached through fdt_internal.h.
 *
 * This is arch-private: the public interface stays in xaios/riscv64_fdt.h.
 */
#include <xaios/riscv64_fdt.h>

#include <stdint.h>

#include "fdt_internal.h"

/* Which hart a local interrupt controller belongs to.
 *
 * The tree nests it: `/cpus/cpu@N` carries the hart id in its `reg`, and its
 * child `interrupt-controller` carries the phandle everything else refers to
 * that hart by. The walk is linear and a node's properties precede its
 * children, so the last `reg` seen under a node named `cpu` belongs to the
 * hart whose intc child comes next. That is a property of how a device tree
 * is serialised rather than a guess: the FDT_PROP tokens of a node always
 * come before any FDT_BEGIN_NODE inside it.
 *
 * Why it matters at all: an IMSIC's interrupt files are selected by position
 * in its `interrupts-extended` list, not by hart id, and the two agree only
 * on a machine where firmware kept no hart for itself. This port has already
 * been bitten once by assuming hart ids have no gaps.
 */
typedef struct intc_search {
  uint32_t wanted_phandle;
  uint32_t current_hart;
  int have_current;
  uint32_t hart_id;
  int found;
} intc_search_t;

static void find_intc_hart(const fdt_property_t *property, void *context) {
  intc_search_t *search = (intc_search_t *)context;
  if (search->found != 0) return;
  if (riscv64_fdt_node_name_matches(property->node_name, "cpu") &&
      riscv64_fdt_string_equal(property->name, "reg") &&
      property->length >= 4U) {
    /* Decoded with the cells /cpus declared for its children, which is what
       fdt_walk already hands over. Assuming one cell would read the top half
       of a 64-bit id on a tree that declares two. */
    search->current_hart =
        (uint32_t)riscv64_fdt_read_cells(property->value, property->address_cells);
    search->have_current = 1;
    return;
  }
  if (!riscv64_fdt_string_equal(property->node_name, "interrupt-controller"))
    return;
  if (!riscv64_fdt_string_equal(property->name, "phandle") ||
      property->length < 4U)
    return;
  if (search->have_current == 0) return;
  if (riscv64_fdt_be32(property->value) != search->wanted_phandle) return;
  search->hart_id = search->current_hart;
  search->found = 1;
}

int fdt_hart_of_intc_phandle(const void *blob, uint32_t phandle,
                             uint32_t *hart_id) {
  intc_search_t search = {phandle, 0U, 0, 0U, 0};
  if (phandle == 0U) return 0;
  fdt_walk(blob, find_intc_hart, &search);
  if (search.found == 0 || hart_id == 0) return 0;
  *hart_id = search.hart_id;
  return 1;
}

