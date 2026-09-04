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
 */
#include <xaios/riscv64_fdt.h>

/* Deep enough for any tree these boards present; a deeper one is
   refused rather than read with a stale scope. */
#define FDT_MAX_DEPTH 32U

#define FDT_MAGIC UINT32_C(0xd00dfeed)
#define FDT_BEGIN_NODE UINT32_C(0x00000001)
#define FDT_END_NODE UINT32_C(0x00000002)
#define FDT_PROP UINT32_C(0x00000003)
#define FDT_NOP UINT32_C(0x00000004)
#define FDT_END UINT32_C(0x00000009)

static uint32_t be32(const void *pointer) {
  const uint8_t *bytes = (const uint8_t *)pointer;
  return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
         ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

static uint64_t be64(const void *pointer) {
  const uint8_t *bytes = (const uint8_t *)pointer;
  return ((uint64_t)be32(bytes) << 32) | (uint64_t)be32(bytes + 4);
}

static int string_equal(const char *left, const char *right) {
  while (*left != '\0' && *left == *right) {
    ++left;
    ++right;
  }
  return *left == *right;
}

/* Whether `name` is `prefix` or `prefix@something`. Device-tree node names
   carry a unit address after an @, so a caller looking for "memory" has to
   match "memory@80000000" as well, and a caller looking for "memory" must
   not match "memory-controller". */
static int node_name_matches(const char *name, const char *prefix) {
  while (*prefix != '\0') {
    if (*name != *prefix) return 0;
    ++name;
    ++prefix;
  }
  return *name == '\0' || *name == '@';
}

static uint64_t read_cells(const uint8_t *data, uint32_t cells) {
  return cells >= 2U ? be64(data) : (uint64_t)be32(data);
}

int fdt_valid(const void *blob) {
  return blob != 0 && be32(blob) == FDT_MAGIC;
}

uint64_t fdt_total_size(const void *blob) {
  return fdt_valid(blob) ? (uint64_t)be32((const uint8_t *)blob + 4) : 0U;
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
  uint32_t struct_offset = be32(base + 8);
  uint32_t strings_offset = be32(base + 12);
  uint32_t struct_size = be32(base + 36);
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
    uint32_t token = be32(cursor);
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
      uint32_t value_length = be32(cursor);
      uint32_t name_offset = be32(cursor + 4U);
      const uint8_t *value = cursor + 8U;
      const char *name = strings + name_offset;
      if (string_equal(name, "#address-cells") && value_length >= 4U) {
        address_cells[depth] = be32(value);
      } else if (string_equal(name, "#size-cells") && value_length >= 4U) {
        size_cells[depth] = be32(value);
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

typedef struct memory_search {
  uint64_t base;
  uint64_t size;
  int found;
} memory_search_t;

static void find_memory(const fdt_property_t *property, void *context) {
  memory_search_t *search = (memory_search_t *)context;
  if (search->found != 0) return;
  if (!node_name_matches(property->node_name, "memory")) return;
  if (!string_equal(property->name, "reg")) return;
  uint32_t stride = (property->address_cells + property->size_cells) * 4U;
  if (property->length < stride) return;
  search->base = read_cells(property->value, property->address_cells);
  search->size = read_cells(property->value + property->address_cells * 4U,
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
  if (!node_name_matches(property->node_name, search->wanted_node)) return;
  if (!string_equal(property->name, search->wanted_property)) return;
  if (property->length < property->address_cells * 4U) return;
  search->value = read_cells(property->value, property->address_cells);
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
    if (string_equal(entry, wanted)) return 1;
    while (offset < length && value[offset] != 0U) ++offset;
    ++offset;
  }
  return 0;
}

static void find_compatible_node(const fdt_property_t *property,
                                 void *context) {
  compatible_search_t *search = (compatible_search_t *)context;
  if (search->matched != 0) return;
  if (!string_equal(property->name, "compatible")) return;
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
  if (!string_equal(property->node_name, search->node_name)) return;
  if (!string_equal(property->name, "reg")) return;
  if (property->length < property->address_cells * 4U) return;
  search->address = read_cells(property->value, property->address_cells);
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
  if (!string_equal(property->name, "compatible")) return;
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
  if (!string_equal(property->name, "compatible")) return;
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
  if (!string_equal(property->name, "reg")) return;
  if (property->length < property->address_cells * 4U) return;
  for (uint32_t i = 0U; i < search->name_count; ++i) {
    if (!string_equal(property->node_name, search->names[i])) continue;
    uint64_t address = read_cells(property->value, property->address_cells);
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
  if (!string_equal(property->node_name, search->lowest_name)) return;
  if (!string_equal(property->name, "interrupts")) return;
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
  if (!string_equal(property->node_name, search->node_name)) return;
  if (!string_equal(property->name, search->property)) return;
  search->value = property->value;
  search->length = property->length;
  search->found = 1;
}

static void find_property_node(const fdt_property_t *property, void *context) {
  property_search_t *search = (property_search_t *)context;
  if (search->matched != 0) return;
  if (!string_equal(property->name, "compatible")) return;
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
