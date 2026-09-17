/* Discovery and register programming for the RISC-V Advanced Interrupt
 * Architecture: IMSIC for messages, APLIC for wires.
 *
 * This is the half of the driver that looks at the device tree and decides
 * what this machine is, then programs it. It was one file with the runtime in
 * aia.c and the delivery tests in aia_selftest.c until the driver passed 500
 * lines; the split is a size split, so the register map, the ordering of
 * every write and the text of every diagnostic are the ones the single file
 * had. What moved here is exactly the cohesive part: the FDT walk that picks
 * the supervisor IMSIC out of the machine-mode pair by the cause its
 * `interrupts-extended` names, the matching APLIC by its `msi-parent`, the
 * CSR probe that refuses to drive a controller the hardware does not have,
 * and the programming that brings both up. The geometry it found lives here
 * too and is answered to aia.c through the accessors in aia_internal.h, so
 * nothing outside this file holds a pointer into it.
 *
 * The two rules this file encodes, both of them learned elsewhere in this
 * tree: a controller belonging to firmware looks identical to this kernel's
 * and is selected by what it is attached to rather than by position, and a
 * register that will not read back what was written is treated as absent
 * rather than as configured.
 */
#include <xaios/riscv64_aia.h>
#include <xaios/riscv64_fdt.h>
#include <xaios/status.h>

#include <stdint.h>

#include "aia_internal.h"

void exception_mmio_probe_begin(void);
void exception_mmio_probe_end(void);
int exception_mmio_probe_faulted(void);

/* Controller geometry, written once by riscv64_aia_init() and read afterwards
   through the accessors below. These were the file-scope variables of the
   single aia.c; they moved with the code that writes them. */
static uint64_t g_imsic_base;
static uint64_t g_imsic_size;
static uint64_t g_imsic_stride;
static uint32_t g_identity_count;
static uint64_t g_aplic_base;
static uint32_t g_aplic_sources;
static int g_present;
static int g_wired_present;
/* Which interrupt file inside the IMSIC's window belongs to a hart. Not the
   hart id: files are selected by position in the controller's
   `interrupts-extended` list, and the two agree only on a machine where
   firmware kept no hart for itself. This port has already been bitten once by
   assuming hart ids have no gaps. */
static uint32_t g_file_of_hart[AIA_MAX_HARTS];
static uint8_t g_file_known[AIA_MAX_HARTS];

int riscv64_aia_present(void) { return g_present; }
int riscv64_aia_wired_present(void) { return g_wired_present; }

uint32_t riscv64_aia_identity_count(void) { return g_identity_count; }
uint32_t riscv64_aia_aplic_sources(void) { return g_aplic_sources; }

static uint32_t be32_at(const uint8_t *bytes) {
  return ((uint32_t)bytes[0] << 24) | ((uint32_t)bytes[1] << 16) |
         ((uint32_t)bytes[2] << 8) | (uint32_t)bytes[3];
}

/* Interrupts off across an indirect register access, and no further.
 *
 * siselect and sireg are two writes that have to stay together: a trap taken
 * between them that also used the indirection would leave the selector
 * pointing somewhere the first half of this access did not choose. Nothing in
 * the trap path uses siselect today -- dispatch reads stopei, which needs no
 * selector -- so this is a guard against a future handler rather than a fix
 * for a bug seen. It costs two CSR writes. */
static uint64_t interrupts_off(void) {
  uint64_t previous = 0U;
  __asm__ volatile("csrrc %0, sstatus, %1"
                   : "=r"(previous)
                   : "r"(SSTATUS_SIE)
                   : "memory");
  return previous & SSTATUS_SIE;
}

static void interrupts_restore(uint64_t saved) {
  if (saved != 0U) {
    __asm__ volatile("csrs sstatus, %0" : : "r"(SSTATUS_SIE) : "memory");
  }
}

static void imsic_write(uint32_t selector, uint64_t value) {
  uint64_t saved = interrupts_off();
  __asm__ volatile("csrw 0x150, %0" : : "r"((uint64_t)selector) : "memory");
  __asm__ volatile("csrw 0x151, %0" : : "r"(value) : "memory");
  interrupts_restore(saved);
}

void riscv64_aia_imsic_set_enable(uint32_t identity, int enabled) {
  uint32_t selector = IMSIC_EIE0 + 2U * (identity / 64U);
  uint32_t bit = identity % 64U;
  uint64_t saved = interrupts_off();
  __asm__ volatile("csrw 0x150, %0" : : "r"((uint64_t)selector) : "memory");
  if (enabled != 0) {
    __asm__ volatile("csrs 0x151, %0"
                     :
                     : "r"(UINT64_C(1) << bit)
                     : "memory");
  } else {
    __asm__ volatile("csrc 0x151, %0"
                     :
                     : "r"(UINT64_C(1) << bit)
                     : "memory");
  }
  interrupts_restore(saved);
}

volatile uint32_t *riscv64_aia_aplic_register(uint64_t offset) {
  return (volatile uint32_t *)(uintptr_t)(g_aplic_base + offset);
}

void riscv64_aia_device_barrier(void) {
  __asm__ volatile("fence iorw, iorw" ::: "memory");
}

/* Does this hart implement the supervisor AIA CSRs at all?
 *
 * Reading siselect on hardware without Ssaia traps as an illegal instruction,
 * and a kernel that assumed the extension because the device tree mentioned a
 * controller would take that trap during its own bring-up. The probe the MMIO
 * scanner already uses recovers from exactly this: between begin and end an
 * illegal instruction sets a flag and steps over itself instead of killing
 * the machine. Asking is the only way to find out, and the answer is the
 * difference between a working configuration and a fatal one. */
static int supervisor_aia_csrs_present(void) {
  uint64_t value = 0U;
  exception_mmio_probe_begin();
  __asm__ volatile("csrr %0, 0x150" : "=r"(value) : : "memory");
  exception_mmio_probe_end();
  (void)value;
  return exception_mmio_probe_faulted() == 0;
}

/* The supervisor-level controller among the ones the tree publishes.
 *
 * `interrupts-extended` on an IMSIC is a list of (hart-intc phandle, cause)
 * pairs, one per hart it serves. The cause says which privilege level this
 * controller raises interrupts at: 9 for supervisor, 11 for machine. Reading
 * it is how the kernel avoids programming the firmware's controller. */
static int imsic_is_supervisor(const void *blob, const char *node_name) {
  const uint8_t *value = 0;
  uint32_t length = 0U;
  if (!fdt_node_property(blob, node_name, "interrupts-extended", &value,
                         &length)) {
    return 0;
  }
  if (length < 8U) return 0;
  uint32_t cause = be32_at(value + 4U);
  return cause == CAUSE_SUPERVISOR_EXTERNAL;
}

/* Which interrupt file belongs to which hart, from the same list. Position in
   `interrupts-extended` selects the file; the phandle names the hart. */
static uint32_t map_files_to_harts(const void *blob, const char *node_name) {
  const uint8_t *value = 0;
  uint32_t length = 0U;
  uint32_t files = 0U;
  if (!fdt_node_property(blob, node_name, "interrupts-extended", &value,
                         &length)) {
    return 0U;
  }
  for (uint32_t offset = 0U; offset + 8U <= length; offset += 8U) {
    uint32_t phandle = be32_at(value + offset);
    uint32_t hart = 0U;
    uint32_t index = offset / 8U;
    if (fdt_hart_of_intc_phandle(blob, phandle, &hart) && hart < AIA_MAX_HARTS) {
      g_file_of_hart[hart] = index;
      g_file_known[hart] = 1U;
    }
    ++files;
  }
  return files;
}

static uint32_t node_u32(const void *blob, const char *node_name,
                         const char *property, uint32_t fallback) {
  const uint8_t *value = 0;
  uint32_t length = 0U;
  if (!fdt_node_property(blob, node_name, property, &value, &length) ||
      length < 4U) {
    return fallback;
  }
  return be32_at(value);
}

/* Whether a hart has an interrupt file at all. The single file asked
   `g_file_known[hart]` directly; this is the same test, kept behind a call so
   that aia.c never holds the array. */
int riscv64_aia_file_known(uint32_t hart) {
  return hart < AIA_MAX_HARTS && g_file_known[hart] != 0U;
}

/* The interrupt-file index a hart owns, answered into the caller's own local. */
int riscv64_aia_file_of_cpu(uint32_t cpu_id, uint32_t *file) {
  uint32_t hart = riscv64_hart_of_cpu(cpu_id);
  if (!riscv64_aia_file_known(hart)) return 0;
  *file = g_file_of_hart[hart];
  return 1;
}

/* The page a device writes to raise an interrupt on the hart that owns this
   file. This is the whole of MSI addressing on this architecture -- no
   translation table, no device id, no event id -- and it stays beside the
   stride it is computed from. */
uint64_t riscv64_aia_message_address(uint32_t file) {
  return g_imsic_base + (uint64_t)file * g_imsic_stride;
}

void riscv64_aia_init_hart(void) {
  if (g_present == 0) return;
  /* Delivery on, threshold zero. A threshold left at anything else is how a
     controller ends up enabled and silent, which is the PLIC lesson repeated
     with different register names: eithreshold blocks every identity at or
     above it, and zero means "block nothing". */
  imsic_write(IMSIC_EIDELIVERY, 1U);
  imsic_write(IMSIC_EITHRESHOLD, 0U);
  for (uint32_t identity = 0U; identity < g_identity_count; identity += 64U) {
    uint32_t index = 2U * (identity / 64U);
    imsic_write(IMSIC_EIE0 + index, 0U);
    imsic_write(IMSIC_EIP0 + index, 0U);
  }
  /* Anything already promised to this hart while it was still asleep is
     enabled by aia.c, which owns the vector table those promises live in. */
  riscv64_aia_enable_pending_for_hart(riscv64_hart_of_cpu(smp_cpu_id()));
}

int riscv64_aia_init(const void *blob) {
  if (blob == 0) return 0;

  fdt_node_ref_t imsics[AIA_MAX_CONTROLLERS];
  uint32_t imsic_count =
      fdt_find_compatible_all(blob, "riscv,imsics", imsics,
                              AIA_MAX_CONTROLLERS);
  const fdt_node_ref_t *supervisor = 0;
  uint32_t examined = imsic_count < AIA_MAX_CONTROLLERS ? imsic_count
                                                        : AIA_MAX_CONTROLLERS;
  for (uint32_t index = 0U; index < examined; ++index) {
    if (imsic_is_supervisor(blob, imsics[index].node_name)) {
      supervisor = &imsics[index];
      break;
    }
  }
  if (supervisor == 0) {
    /* An APLIC with no IMSIC is `aia=aplic`, where the APLIC delivers to
       harts directly through a claim register rather than by message. That is
       a third delivery path this port does not implement, and half-driving it
       would produce a controller that looks configured and delivers nothing.
       Said out loud, because a machine that silently fell back to the PLIC
       branch on a board that has no PLIC would be a boot with no external
       interrupts and no explanation. */
    if (fdt_count_compatible(blob, "riscv,aplic") != 0U) {
      klog("aia: this board has an APLIC but no IMSIC; direct delivery is "
           "not implemented here and no interrupt controller was claimed\n");
    }
    return 0;
  }

  if (!supervisor_aia_csrs_present()) {
    klog("aia: the device tree publishes a supervisor IMSIC at %lx but this "
         "hart traps on siselect; Ssaia is absent and the controller cannot "
         "be driven\n", supervisor->address);
    return 0;
  }

  uint32_t guest_index_bits =
      node_u32(blob, supervisor->node_name, "riscv,guest-index-bits", 0U);
  /* One group only. A multi-group IMSIC spreads its files across several
     `reg` entries with a shift between groups, and this reader takes the
     first entry: a machine with more than one socket would need the group
     arithmetic as well, and claiming to serve it from one base would put
     every message on the wrong socket. Refused below when the window is too
     small for the files the tree says it has, which is what that mistake
     would look like. */
  g_imsic_base = supervisor->address;
  g_imsic_size = supervisor->size;
  g_imsic_stride = UINT64_C(1) << (12U + guest_index_bits);
  g_identity_count =
      node_u32(blob, supervisor->node_name, "riscv,num-ids", 0U) + 1U;
  if (g_identity_count > AIA_MAX_IDENTITIES) {
    g_identity_count = AIA_MAX_IDENTITIES;
  }
  if (g_imsic_base == 0U || g_identity_count < 2U) {
    klog("aia: supervisor IMSIC node is present but describes no window or "
         "no identities; not claimed\n");
    g_imsic_base = 0U;
    return 0;
  }

  uint32_t files = map_files_to_harts(blob, supervisor->node_name);
  if (files == 0U ||
      (g_imsic_size != 0U && (uint64_t)files * g_imsic_stride > g_imsic_size)) {
    klog("aia: supervisor IMSIC at %lx names %u interrupt files but its "
         "window is %lu bytes; refusing rather than addressing past it\n",
         g_imsic_base, files, g_imsic_size);
    g_imsic_base = 0U;
    return 0;
  }

  g_present = 1;
  riscv64_aia_init_hart();

  /* The wired half. The supervisor APLIC is the one whose msi-parent is the
     IMSIC just claimed -- not the first APLIC in the tree, which on this
     board is machine mode's and belongs to firmware. */
  fdt_node_ref_t aplics[AIA_MAX_CONTROLLERS];
  uint32_t aplic_count =
      fdt_find_compatible_all(blob, "riscv,aplic", aplics,
                              AIA_MAX_CONTROLLERS);
  uint32_t aplics_examined =
      aplic_count < AIA_MAX_CONTROLLERS ? aplic_count : AIA_MAX_CONTROLLERS;
  for (uint32_t index = 0U; index < aplics_examined; ++index) {
    uint32_t parent = node_u32(blob, aplics[index].node_name, "msi-parent", 0U);
    if (parent == 0U || parent != supervisor->phandle) continue;
    g_aplic_base = aplics[index].address;
    g_aplic_sources =
        node_u32(blob, aplics[index].node_name, "riscv,num-sources", 0U);
    break;
  }
  if (g_aplic_base != 0U && g_aplic_sources != 0U) {
    /* Every source starts inactive. Firmware may have left the domain
       configured for its own purposes, and a source left enabled with no
       handler delivers a message nothing claims -- which is quieter and worse
       than an unhandled interrupt, exactly as it is on the PLIC. */
    for (uint32_t source = 1U; source <= g_aplic_sources; ++source) {
      *riscv64_aia_aplic_register(APLIC_SOURCECFG + (source - 1U) * 4U) =
          APLIC_SOURCECFG_INACTIVE;
    }
    *riscv64_aia_aplic_register(APLIC_DOMAINCFG) =
        APLIC_DOMAINCFG_IE | APLIC_DOMAINCFG_DM;
    riscv64_aia_device_barrier();
    uint32_t domaincfg = *riscv64_aia_aplic_register(APLIC_DOMAINCFG);
    if ((domaincfg & APLIC_DOMAINCFG_SIGNATURE) != 0U &&
        (domaincfg & APLIC_DOMAINCFG_DM) != 0U &&
        (domaincfg & APLIC_DOMAINCFG_IE) != 0U) {
      g_wired_present = 1;
    } else {
      /* Read back and disbelieved. A domaincfg that will not hold the message
         delivery bit is a controller that would silently keep trying to
         deliver directly, and a wired device routed through it would simply
         never be heard from. */
      klog("aia: supervisor APLIC at %lx would not accept message delivery "
           "(domaincfg=0x%x); wired sources stay unrouted\n", g_aplic_base,
           domaincfg);
      g_aplic_base = 0U;
      g_aplic_sources = 0U;
    }
  }
  return 1;
}

void riscv64_aia_report(void) {
  if (g_present == 0) return;
  klog("aia: supervisor imsic base=%lx stride=%lu identities=%u files=%u\n",
       g_imsic_base, g_imsic_stride, g_identity_count - 1U,
       (uint32_t)(g_imsic_stride == 0U ? 0U : g_imsic_size / g_imsic_stride));
  if (g_wired_present != 0) {
    klog("aia: supervisor aplic base=%lx sources=%u delivery=msi\n",
         g_aplic_base, g_aplic_sources);
  } else {
    klog("aia: no supervisor aplic; wired devices have no route on this "
         "machine\n");
  }
}
