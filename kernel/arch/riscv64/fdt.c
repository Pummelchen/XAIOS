/* A flattened device tree reader, because RISC-V has no other way to ask.
 *
 * AArch64 gets its memory map, its UART and its PCI window from UEFI, and
 * x86-64 gets them from ACPI. RISC-V on this board gets a device tree pointer
 * in a1 and nothing else. So the choice is between parsing it and hardcoding
 * QEMU's addresses -- and hardcoding them would break the rule this whole
 * codebase is built on: firmware supplies capabilities, never identity. A
 * kernel that knows 0x10000000 is the UART is a kernel that only runs on the
 * machine somebody tested.
 *
 * Only what the boot path needs is parsed: memory, the console, and the
 * ranges a driver has to be told about. It is a reader, not a device-tree
 * library -- no overlays, no phandle resolution, no aliases.
 *
 * Every multi-byte value in a device tree is big-endian regardless of the
 * machine reading it, which on a little-endian RISC-V means every read goes
 * through a byte swap. That is not a detail to leave implicit: reading one
 * field natively yields a number that is wrong by a factor of sixteen million
 * and looks like a plausible address.
 *
 * This file is the reader core. The lookups built on fdt_walk -- memory,
 * node, compatible, property and hart discovery -- live in fdt_lookup.c,
 * which the same build compiles beside it; what the two share is exactly the
 * two helpers declared in fdt_internal.h.
 */
#include <xaios/riscv64_fdt.h>

#include "fdt_internal.h"

/* Deep enough for any tree these boards present; a deeper one is
   refused rather than read with a stale scope. */
#define FDT_MAX_DEPTH 32U

#define FDT_MAGIC UINT32_C(0xd00dfeed)
#define FDT_BEGIN_NODE UINT32_C(0x00000001)
#define FDT_END_NODE UINT32_C(0x00000002)
#define FDT_PROP UINT32_C(0x00000003)
#define FDT_NOP UINT32_C(0x00000004)
#define FDT_END UINT32_C(0x00000009)

/* Big-endian 32-bit read. External because fdt_lookup.c calls it too; the
   body is the one the static helper had. */
uint32_t riscv64_fdt_be32(const void *pointer) {
  const uint8_t *bytes = (const uint8_t *)pointer;
  return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
         ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

/* External for the same reason as riscv64_fdt_be32. */
int riscv64_fdt_string_equal(const char *left, const char *right) {
  while (*left != '\0' && *left == *right) {
    ++left;
    ++right;
  }
  return *left == *right;
}

int fdt_valid(const void *blob) {
  return blob != 0 && riscv64_fdt_be32(blob) == FDT_MAGIC;
}

uint64_t fdt_total_size(const void *blob) {
  return fdt_valid(blob)
             ? (uint64_t)riscv64_fdt_be32((const uint8_t *)blob + 4)
             : 0U;
}

/* Walk the structure block, calling `visit` for every node.
 *
 * One traversal serves every query rather than each caller writing its own,
 * because the walk is where the fiddly parts live: tokens are four-byte
 * aligned, property names are offsets into a separate strings block, and a
 * property's value is padded to alignment while its length is not. Getting
 * that wrong once is better than getting it wrong in five places.
 */
void fdt_walk(const void *blob, fdt_visit_fn visit, void *context) {
  if (!fdt_valid(blob) || visit == 0) return;
  const uint8_t *base = (const uint8_t *)blob;
  uint32_t struct_offset = riscv64_fdt_be32(base + 8);
  uint32_t strings_offset = riscv64_fdt_be32(base + 12);
  uint32_t struct_size = riscv64_fdt_be32(base + 36);
  const uint8_t *cursor = base + struct_offset;
  const uint8_t *end = cursor + struct_size;
  const char *strings = (const char *)(base + strings_offset);

  /* The node currently open, and how deep. Only the name is tracked: a
     caller that needs a path can match on depth and name, and carrying full
     paths would need allocation this has no business doing. */
  const char *node_name = "";
  uint32_t depth = 0U;
  /* #address-cells and #size-cells are scoped, and getting that wrong is not
     a subtle failure.
     A node declares them for its *children*, and they are inherited until
     another node overrides them. So a node's own `reg` is decoded with its
     parent's values, and the values a node declares must be forgotten when
     the walk leaves it.
     The first version of this tracked one pair for the whole traversal. On
     QEMU's virt board `/cpus` declares #address-cells = 1, `/cpus` is walked
     before `/memory`, and so `/memory`'s reg -- two 64-bit cells -- was
     decoded as 32-bit ones. The answer was not garbage, which is what made it
     worth writing down: it reported memory at 0x0 of size 0x80000000, a
     plausible-looking map that happens to describe a machine this is not.
     A stack indexed by depth, inheriting on entry, is the whole fix. */
  uint32_t address_cells[FDT_MAX_DEPTH];
  uint32_t size_cells[FDT_MAX_DEPTH];
  address_cells[0] = 2U;
  size_cells[0] = 1U;

  while (cursor + 4U <= end) {
    uint32_t token = riscv64_fdt_be32(cursor);
    cursor += 4U;
    if (token == FDT_BEGIN_NODE) {
      node_name = (const char *)cursor;
      uint32_t length = 0U;
      while (cursor + length < end && cursor[length] != '\0') ++length;
      cursor += (length + 4U) & ~UINT32_C(3);
      if (depth + 1U >= FDT_MAX_DEPTH) return; /* deeper than this reads */
      ++depth;
      /* Inherit, so a node that declares nothing keeps its parent's. */
      address_cells[depth] = address_cells[depth - 1U];
      size_cells[depth] = size_cells[depth - 1U];
    } else if (token == FDT_END_NODE) {
      if (depth > 0U) --depth;
      node_name = "";
    } else if (token == FDT_PROP) {
      if (cursor + 8U > end) return;
      uint32_t value_length = riscv64_fdt_be32(cursor);
      uint32_t name_offset = riscv64_fdt_be32(cursor + 4U);
      const uint8_t *value = cursor + 8U;
      const char *name = strings + name_offset;
      if (riscv64_fdt_string_equal(name, "#address-cells") &&
          value_length >= 4U) {
        address_cells[depth] = riscv64_fdt_be32(value);
      } else if (riscv64_fdt_string_equal(name, "#size-cells") &&
                 value_length >= 4U) {
        size_cells[depth] = riscv64_fdt_be32(value);
      }
      /* Decoded with the *parent's* cells, because that is whose declaration
         governs this node's reg. */
      uint32_t parent = depth > 0U ? depth - 1U : 0U;
      fdt_property_t property = {node_name, name, value, value_length,
                                 address_cells[parent], size_cells[parent],
                                 depth};
      visit(&property, context);
      cursor = value + ((value_length + 3U) & ~UINT32_C(3));
    } else if (token == FDT_END) {
      return;
    } else if (token != FDT_NOP) {
      /* An unrecognised token means the blob is not what it claims, and
         continuing would walk off into whatever follows it. */
      return;
    }
  }
}
