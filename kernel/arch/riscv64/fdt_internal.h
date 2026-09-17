/* Private interface shared by fdt.c and fdt_lookup.c.
 *
 * fdt.c is the reader: the big-endian primitives, the validity and size
 * questions, and the single structural walk in fdt_walk. fdt_lookup.c is
 * everything built on that walk -- the memory, node, compatible, property
 * and hart lookups -- which was the tail of the single 613-line fdt.c until
 * it passed the size limit. The split is a size split, so every pass, guard,
 * ordering and diagnostic in the lookups is the one the single file had, and
 * the two files are compiled together by scripts/build-riscv64.sh.
 *
 * Only the two helpers that the walk in fdt.c and the lookups in
 * fdt_lookup.c both call cross here. They were static in the single file and
 * became external with the riscv64_fdt_ prefix, as the other split arch
 * modules did; nothing else about them changed. `be64`, `read_cells`,
 * `node_name_matches` and the compatible matcher stayed private, because
 * only one side of the split uses each.
 *
 * This is arch-private. Nothing outside kernel/arch/riscv64 includes it, and
 * the public interface stays in xaios/riscv64_fdt.h.
 */
#ifndef XAIOS_ARCH_RISCV64_FDT_INTERNAL_H
#define XAIOS_ARCH_RISCV64_FDT_INTERNAL_H

#include <stdint.h>

/* Big-endian 32-bit read. Every multi-byte value in a device tree is
   big-endian regardless of the machine reading it. Defined in fdt.c and
   called from both sides. */
uint32_t riscv64_fdt_be32(const void *pointer);

/* NUL-terminated string equality without libc. Defined in fdt.c and called
   from both sides. */
int riscv64_fdt_string_equal(const char *left, const char *right);

/* Node-name prefix match and multi-cell read, defined in fdt_lookup.c and
   called from the interrupt-controller lookup in fdt_intc.c. They were static
   while both callers lived in one file. */
int riscv64_fdt_node_name_matches(const char *name, const char *prefix);
uint64_t riscv64_fdt_read_cells(const uint8_t *data, uint32_t cells);

#endif /* XAIOS_ARCH_RISCV64_FDT_INTERNAL_H */
