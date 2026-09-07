/* The Advanced Interrupt Architecture: IMSIC for messages, APLIC for wires.
 *
 * Why this file exists at all. Until it did, RISC-V was the only architecture
 * in this tree where every device queue was serviced by polling: NVMe said
 * "no message-signalled interrupts on this machine" and virtio said "MSI-X
 * unavailable", against four MSI-X queues on AArch64 and x86-64. That was
 * recorded as a property of the board, and it was half a property of the
 * board and half a property of this kernel. QEMU's `virt` machine does offer
 * message-signalled interrupts -- `-machine virt,aia=aplic-imsic` publishes
 * an APLIC and an IMSIC at both privilege levels -- but the only interrupt
 * controller this port had a driver for was the PLIC, which carries wires and
 * not messages. Selecting the capable board therefore produced a machine that
 * booted every self-test and reported that external interrupts would not be
 * delivered: correct degradation, and not a usable configuration.
 *
 * What the two controllers are, because the names do not say it.
 *
 * The IMSIC is the message receiver, and it is remarkably plain compared to a
 * GIC ITS. Each hart owns one 4 KiB page of physical address space per
 * privilege level; a device raises an interrupt on that hart by writing a
 * small integer -- the external interrupt identity -- as one 32-bit word to
 * that page. There is no device table, no interrupt translation table, no
 * command queue and no synchronisation command. The address is the hart and
 * the data is the interrupt. Everything the shared MSI-X code needs from an
 * interrupt controller -- "give me an address and a word that will reach this
 * CPU" -- is therefore two lines of arithmetic here, where on AArch64 it is
 * six hundred lines of ITS.
 *
 * The hart's own view of its interrupt file is not memory at all: enabling an
 * identity, setting a threshold and taking the top pending interrupt are done
 * through CSRs (siselect/sireg indirection, and stopei). So the file is
 * written from outside by devices and read from inside by its own hart, and
 * neither side can do the other's job. That is why enabling an identity has
 * to happen on the hart that will receive it, and why this file records a
 * target and lets a hart pick its own up when it comes online rather than
 * pretending one hart can program another's.
 *
 * The APLIC is the wire receiver. Devices that pull a line rather than write
 * a word -- the virtio-mmio transports, the UART, the RTC -- are attached to
 * it. In this configuration it is programmed in MSI delivery mode, which
 * means it does not deliver anything to a hart directly: it forwards each
 * asserted source onward as an MSI to an IMSIC. So it is not an alternative
 * to the IMSIC, it is a translator that puts wired devices onto the same
 * delivery path as PCI ones. The PCI host bridge on this board names the
 * supervisor IMSIC as its `msi-parent` directly and does not involve the
 * APLIC at all.
 *
 * What is discovered and what is refused.
 *
 * A board with AIA publishes two of everything: an IMSIC and an APLIC for
 * machine mode, which belong to firmware, and another pair for supervisor
 * mode, which belong to this kernel. They have identical compatible strings
 * and differ only in what they are wired to, so "the first riscv,imsics node"
 * is a coin toss -- and programming firmware's controller is accepted
 * silently by QEMU and delivers nothing here. The supervisor IMSIC is the one
 * whose `interrupts-extended` names cause 9, the supervisor external
 * interrupt; the machine one names cause 11. The supervisor APLIC is the one
 * whose `msi-parent` is that IMSIC. Both are found by what they are attached
 * to, never by address and never by position.
 *
 * An APLIC with no IMSIC beside it -- `aia=aplic`, where the APLIC delivers
 * directly to harts rather than by message -- is detected and refused rather
 * than half-driven. Direct mode is a third delivery path with its own claim
 * register and its own idle-hart semantics, and nothing in this tree needs it
 * today; saying so is better than a driver that appears to configure it.
 *
 * What is not proven here. The self-test below sends this hart a message
 * through its own interrupt file and requires it to arrive, which proves the
 * receiver, the enable bit, the threshold, the trap path and the dispatch
 * loop. It does not prove that a *device* can reach the file, because the
 * write comes from the CPU rather than over the bus. The claim that a device
 * MSI is delivered is made by the NVMe interrupt self-test, which submits a
 * read with the queue unmasked and requires the completion to arrive without
 * anybody polling for it.
 */
#include <xaios/riscv64_aia.h>
#include <xaios/riscv64_fdt.h>
#include <xaios/status.h>

#include <stdint.h>

void klog(const char *fmt, ...);
uint32_t smp_cpu_id(void);
uint32_t riscv64_hart_of_cpu(uint32_t cpu_id);
void exception_mmio_probe_begin(void);
void exception_mmio_probe_end(void);
int exception_mmio_probe_faulted(void);

/* Supervisor indirect CSRs, by number rather than by name.
 *
 * `csrw siselect, x` assembles only when the assembler has been told the
 * hardware implements Ssaia, and this kernel is built with one -march string
 * for every RISC-V machine it runs on -- including the boards that have no
 * AIA at all. Numbers assemble unconditionally, and whether the hardware
 * answers is decided at run time by the probe below rather than at build time
 * by a flag.
 *
 * The asm below spells the numbers out rather than using these names, because
 * a macro cannot be pasted into an inline asm string without stringifying it
 * and the stringified form is what would then have to be kept in step. These
 * exist so that a reader meeting `0x15c` in an instruction has somewhere to
 * look it up; they are documentation, and grep will find both. */
#define CSR_SISELECT 0x150
#define CSR_SIREG 0x151
#define CSR_STOPEI 0x15c

/* Indirectly addressed interrupt-file registers, from the AIA specification.
   On RV64 the 64-bit arrays are addressed at even offsets only: eie0, eie2,
   eie4 and so on, each holding 64 identities. */
#define IMSIC_EIDELIVERY 0x70U
#define IMSIC_EITHRESHOLD 0x72U
#define IMSIC_EIP0 0x80U
#define IMSIC_EIE0 0xc0U

#define SSTATUS_SIE (UINT64_C(1) << 1)

/* APLIC register map, from the specification. */
#define APLIC_DOMAINCFG UINT64_C(0x0000)
#define APLIC_SOURCECFG UINT64_C(0x0004)
#define APLIC_SETIPNUM UINT64_C(0x1cdc)
#define APLIC_SETIPNUM_LE UINT64_C(0x2000)
#define APLIC_SETIENUM UINT64_C(0x1edc)
#define APLIC_CLRIENUM UINT64_C(0x1fdc)
#define APLIC_TARGET UINT64_C(0x3004)

/* domaincfg: interrupts enabled, delivery by message. The top byte reads back
   as 0x80 on a controller that is present and answering, which is the only
   cheap liveness check the register map offers. */
#define APLIC_DOMAINCFG_IE UINT32_C(0x0100)
#define APLIC_DOMAINCFG_DM UINT32_C(0x0004)
#define APLIC_DOMAINCFG_SIGNATURE UINT32_C(0x80000000)

/* sourcecfg source modes. Level-high is what this board's tree declares for
   every wired device on it (`interrupts = <n 4>`). */
#define APLIC_SOURCECFG_INACTIVE UINT32_C(0)
/* Detached: the controller ignores whatever the wire is doing and the source
   can only be made pending by software writing setipnum. That is what makes a
   self-test of the forwarding path possible without a device. */
#define APLIC_SOURCECFG_DETACHED UINT32_C(1)
#define APLIC_SOURCECFG_LEVEL_HIGH UINT32_C(6)

/* The supervisor external interrupt, which is what an IMSIC serving this
   privilege level is wired to raise. Machine mode's is 11, and telling the
   two apart is the entire point of looking. */
#define CAUSE_SUPERVISOR_EXTERNAL 9U
#define CAUSE_MACHINE_EXTERNAL 11U

/* Bounds. The identity space is what `riscv,num-ids` declares, capped here at
   what the handler table can hold; QEMU's virt board declares 255. The hart
   bound matches the one exception.c already uses for its per-hart state. */
#define AIA_MAX_IDENTITIES 256U
#define AIA_MAX_HARTS 64U
#define AIA_MAX_CONTROLLERS 4U

typedef struct aia_vector {
  riscv64_aia_handler_t handler;
  void *context;
  /* Which hart's file this identity was enabled on, and the wired source it
     stands for -- zero when it is a message from a device rather than a
     translated wire. A level-triggered wire has to be re-armed at the APLIC
     after its handler runs, and the identity is all the dispatch loop knows
     by then. */
  uint32_t hart;
  uint32_t wired_source;
  uint8_t enabled;
  uint8_t pending_enable;
  /* Whether a message for this identity has ever actually arrived.
   *
   * The distinction this records is the one the whole change turns on:
   * "a handler was registered" is a statement about this kernel, and "an
   * interrupt was delivered" is a statement about the machine. Every driver
   * in this tree can also poll, so a board on which no message ever arrives
   * boots and passes exactly as one where they all do. The first arrival per
   * identity is announced once, which is what makes the difference visible in
   * a log instead of only in a debugger. */
  uint8_t announced;
} aia_vector_t;

static uint64_t g_imsic_base;
static uint64_t g_imsic_size;
static uint64_t g_imsic_stride;
static uint32_t g_identity_count;
static uint32_t g_next_identity = 1U;
static uint64_t g_aplic_base;
static uint32_t g_aplic_sources;
static int g_present;
static int g_wired_present;
static uint64_t g_delivered;
static uint64_t g_spurious;
static aia_vector_t g_vectors[AIA_MAX_IDENTITIES];
/* Which interrupt file inside the IMSIC's window belongs to a hart. Not the
   hart id: files are selected by position in the controller's
   `interrupts-extended` list, and the two agree only on a machine where
   firmware kept no hart for itself. This port has already been bitten once by
   assuming hart ids have no gaps. */
static uint32_t g_file_of_hart[AIA_MAX_HARTS];
static uint8_t g_file_known[AIA_MAX_HARTS];

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

static void imsic_set_enable(uint32_t identity, int enabled) {
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

static volatile uint32_t *aplic_register(uint64_t offset) {
  return (volatile uint32_t *)(uintptr_t)(g_aplic_base + offset);
}

static void device_barrier(void) {
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

static int file_of_cpu(uint32_t cpu_id, uint32_t *file) {
  uint32_t hart = riscv64_hart_of_cpu(cpu_id);
  if (hart >= AIA_MAX_HARTS || g_file_known[hart] == 0U) return 0;
  *file = g_file_of_hart[hart];
  return 1;
}

int riscv64_aia_present(void) { return g_present; }
int riscv64_aia_wired_present(void) { return g_wired_present; }
uint64_t riscv64_aia_delivered(void) { return g_delivered; }
uint64_t riscv64_aia_spurious(void) { return g_spurious; }

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
  /* Anything already promised to this hart while it was still asleep. A
     driver that configured a queue before the secondary came online recorded
     its identity here rather than writing another hart's CSRs, which is not
     something one hart can do. */
  uint32_t hart = riscv64_hart_of_cpu(smp_cpu_id());
  for (uint32_t identity = 1U; identity < g_identity_count; ++identity) {
    aia_vector_t *vector = &g_vectors[identity];
    if (vector->hart != hart) continue;
    if (vector->pending_enable == 0U && vector->enabled == 0U) continue;
    imsic_set_enable(identity, 1);
    vector->pending_enable = 0U;
    vector->enabled = 1U;
  }
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
      *aplic_register(APLIC_SOURCECFG + (source - 1U) * 4U) =
          APLIC_SOURCECFG_INACTIVE;
    }
    *aplic_register(APLIC_DOMAINCFG) =
        APLIC_DOMAINCFG_IE | APLIC_DOMAINCFG_DM;
    device_barrier();
    uint32_t domaincfg = *aplic_register(APLIC_DOMAINCFG);
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

xaios_status_t riscv64_aia_allocate(uint32_t *identifier) {
  if (identifier == 0) return XAIOS_ERR_INVALID;
  if (g_present == 0) return XAIOS_ERR_UNSUPPORTED;
  /* Handed out once and never reissued. A free-slot search would reissue an
     identity whose owner polls and therefore never registered a handler, and
     two devices sharing one identity deliver each other's interrupts -- the
     same reasoning the GIC's LPI allocator carries, and the same failure. */
  while (g_next_identity < g_identity_count) {
    uint32_t candidate = g_next_identity++;
    if (g_vectors[candidate].handler == 0 &&
        g_vectors[candidate].enabled == 0U &&
        g_vectors[candidate].pending_enable == 0U) {
      *identifier = candidate;
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_NO_MEMORY;
}

xaios_status_t riscv64_aia_register(uint32_t identifier, uint32_t cpu_id,
                                    riscv64_aia_handler_t handler,
                                    void *context) {
  if (g_present == 0) return XAIOS_ERR_UNSUPPORTED;
  if (identifier == 0U || identifier >= g_identity_count || handler == 0) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t hart = riscv64_hart_of_cpu(cpu_id);
  if (hart >= AIA_MAX_HARTS || g_file_known[hart] == 0U) {
    return XAIOS_ERR_INVALID;
  }
  aia_vector_t *vector = &g_vectors[identifier];
  if (vector->handler != 0 && vector->handler != handler) {
    return XAIOS_ERR_BUSY;
  }
  vector->handler = handler;
  vector->context = context;
  vector->hart = hart;
  /* Enabling is a CSR write, and a CSR belongs to the hart executing it. A
     target that is not this hart is recorded and enabled by that hart when it
     brings its own file up, rather than pretended. */
  if (hart == riscv64_hart_of_cpu(smp_cpu_id())) {
    imsic_set_enable(identifier, 1);
    vector->enabled = 1U;
    vector->pending_enable = 0U;
  } else {
    vector->pending_enable = 1U;
  }
  return XAIOS_OK;
}

xaios_status_t riscv64_aia_unregister(uint32_t identifier) {
  if (g_present == 0) return XAIOS_ERR_UNSUPPORTED;
  if (identifier == 0U || identifier >= g_identity_count) {
    return XAIOS_ERR_INVALID;
  }
  aia_vector_t *vector = &g_vectors[identifier];
  if (vector->enabled != 0U &&
      vector->hart == riscv64_hart_of_cpu(smp_cpu_id())) {
    imsic_set_enable(identifier, 0);
    vector->enabled = 0U;
  }
  vector->pending_enable = 0U;
  vector->handler = 0;
  vector->context = 0;
  if (vector->wired_source != 0U) {
    (void)riscv64_aia_disable_wired(vector->wired_source);
    vector->wired_source = 0U;
  }
  return XAIOS_OK;
}

xaios_status_t riscv64_aia_message_target(uint32_t identifier, uint32_t cpu_id,
                                          uint64_t *address, uint32_t *data) {
  if (address == 0 || data == 0) return XAIOS_ERR_INVALID;
  *address = 0U;
  *data = 0U;
  if (g_present == 0) return XAIOS_ERR_UNSUPPORTED;
  if (identifier == 0U || identifier >= g_identity_count) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t file = 0U;
  if (!file_of_cpu(cpu_id, &file)) return XAIOS_ERR_INVALID;
  /* This is the whole of MSI addressing on this architecture: the page is the
     hart and the word is the interrupt. No translation table, no device id,
     no event id, and nothing to synchronise afterwards. */
  *address = g_imsic_base + (uint64_t)file * g_imsic_stride;
  *data = identifier;
  return XAIOS_OK;
}

xaios_status_t riscv64_aia_route_wired(uint32_t source, uint32_t identifier,
                                       uint32_t cpu_id) {
  if (g_wired_present == 0) return XAIOS_ERR_UNSUPPORTED;
  if (source == 0U || source > g_aplic_sources || identifier == 0U ||
      identifier >= g_identity_count) {
    return XAIOS_ERR_INVALID;
  }
  uint32_t file = 0U;
  if (!file_of_cpu(cpu_id, &file)) return XAIOS_ERR_INVALID;
  /* Level-high, because that is what every wired device on this board's tree
     declares (`interrupts = <n 4>`). In message delivery mode a level source
     sends one message when its line rises and is re-armed after the handler
     runs; the dispatch loop below does that re-arming, which is the part a
     driver written against direct delivery does not have to think about. */
  *aplic_register(APLIC_SOURCECFG + (source - 1U) * 4U) =
      APLIC_SOURCECFG_LEVEL_HIGH;
  /* target: hart index in the top bits, identity in the low ones. The hart
     index the APLIC uses to compute an IMSIC address is the interrupt file
     index, not the hart id -- the same number the message target above
     uses. */
  *aplic_register(APLIC_TARGET + (source - 1U) * 4U) =
      (file << 18U) | (identifier & UINT32_C(0x7ff));
  device_barrier();
  uint32_t sourcecfg = *aplic_register(APLIC_SOURCECFG + (source - 1U) * 4U);
  if (sourcecfg != APLIC_SOURCECFG_LEVEL_HIGH) {
    /* A source the controller refused to configure is one that will never
       fire, and a driver told "registered" would wait for it forever. */
    return XAIOS_ERR_IO;
  }
  g_vectors[identifier].wired_source = source;
  *aplic_register(APLIC_SETIENUM) = source;
  device_barrier();
  return XAIOS_OK;
}

xaios_status_t riscv64_aia_disable_wired(uint32_t source) {
  if (g_wired_present == 0) return XAIOS_ERR_UNSUPPORTED;
  if (source == 0U || source > g_aplic_sources) return XAIOS_ERR_INVALID;
  *aplic_register(APLIC_CLRIENUM) = source;
  *aplic_register(APLIC_SOURCECFG + (source - 1U) * 4U) =
      APLIC_SOURCECFG_INACTIVE;
  device_barrier();
  return XAIOS_OK;
}

uint32_t riscv64_aia_dispatch(void) {
  if (g_present == 0) return 0U;
  uint32_t handled = 0U;
  /* Bounded, because the loop can re-arm what it just took. A level-triggered
     wire whose device is still asserting is re-sent by the APLIC the moment
     it is re-armed below, so an unbounded drain would never return from the
     trap on a device whose handler did not quieten it. Leaving the rest
     pending and returning costs one more trap and keeps the hart able to do
     anything else at all. */
  while (handled < 64U) {
    uint64_t top = 0U;
    /* Read and claim in one instruction. stopei reports the highest-priority
       pending-and-enabled identity in the top half of the value, and writing
       to it clears that identity's pending bit; a plain read would loop on
       the same interrupt forever. */
    __asm__ volatile("csrrw %0, 0x15c, zero" : "=r"(top) : : "memory");
    if (top == 0U) break;
    uint32_t identity = (uint32_t)(top >> 16U);
    ++handled;
    ++g_delivered;
    if (identity < g_identity_count && g_vectors[identity].handler != 0) {
      g_vectors[identity].handler(identity, g_vectors[identity].context);
      if (g_vectors[identity].announced == 0U) {
        /* Safe from a trap: klog takes its lock with a try and drops the line
           rather than waiting, so it cannot deadlock against the code this
           interrupted. The same trylock means a line can be dropped under
           contention -- which is true of every line this kernel logs, self-
           test results included -- so the counters below, not this message,
           are the authority on how many arrived. */
        klog("aia: identity=%u first message delivered hart=%u wired_source="
             "%u\n", identity, g_vectors[identity].hart,
             g_vectors[identity].wired_source);
        g_vectors[identity].announced = 1U;
      }
      uint32_t source = g_vectors[identity].wired_source;
      if (source != 0U && g_wired_present != 0) {
        /* A level-triggered wire re-arms itself only if it is still low when
           this is written; if the device is still asserting, the APLIC sends
           another message straight away, which is what a level interrupt
           means. Without this a wired device fires exactly once per boot --
           and the boot still looks healthy, because everything in this tree
           can also poll. */
        *aplic_register(APLIC_SETIPNUM_LE) = source;
      }
    } else {
      /* An identity nobody claimed. Counted rather than ignored: this is what
         a target register programmed for the wrong hart or the wrong identity
         produces, and a silent count of zero is the only way to tell that
         apart from a device that never fired. */
      ++g_spurious;
    }
  }
  return handled;
}

static volatile uint64_t g_self_test_calls;

static void self_test_handler(uint32_t identifier, void *context) {
  (void)identifier;
  (void)context;
  ++g_self_test_calls;
}

void riscv64_aia_self_test(void) {
  if (g_present == 0) return;
  /* A message this hart sends to itself, through the same interrupt file a
     device would write.
   *
   * What this proves: the file address arithmetic, the enable bit, the
   * threshold, that the supervisor external interrupt reaches the trap
   * handler, and that dispatch finds the identity and clears it. What it does
   * not prove is that a *device* can reach the file, because this write comes
   * from the CPU and not over the bus -- the NVMe interrupt self-test is what
   * makes that claim, and it makes it by requiring a completion to arrive
   * with nobody polling.
   *
   * The identity is allocated and released around the test rather than
   * hardcoded, so it cannot collide with a driver's. */
  uint32_t identity = 0U;
  if (riscv64_aia_allocate(&identity) != XAIOS_OK) {
    klog("aia: self-test skipped, no identity free\n");
    return;
  }
  uint32_t cpu = smp_cpu_id();
  uint64_t address = 0U;
  uint32_t data = 0U;
  if (riscv64_aia_message_target(identity, cpu, &address, &data) != XAIOS_OK) {
    klog("aia: self-test FAILED: no message target for cpu=%u\n", cpu);
    return;
  }
  if (riscv64_aia_register(identity, cpu, self_test_handler, 0) != XAIOS_OK) {
    klog("aia: self-test FAILED: identity=%u would not register\n", identity);
    return;
  }
  uint64_t before = g_self_test_calls;
  uint64_t spurious_before = g_spurious;
  *(volatile uint32_t *)(uintptr_t)address = data;
  device_barrier();
  /* Bounded, and not a busy wait on a value a compiler may keep in a
     register: the counter is volatile and written by the trap handler on this
     hart. A wfi here would be wrong -- if the message has already been taken,
     nothing else is going to wake this hart. */
  for (uint32_t spin = 0U; spin < 1000000U && g_self_test_calls == before;
       ++spin) {
    __asm__ volatile("" ::: "memory");
  }
  uint64_t arrived = g_self_test_calls - before;
  (void)riscv64_aia_unregister(identity);
  if (arrived == 0U) {
    klog("aia: self-test FAILED: a message written to %lx data=%u never "
         "reached cpu=%u (delivered=%lu unclaimed=%lu)\n", address, data, cpu,
         g_delivered, g_spurious);
    return;
  }
  klog("aia: self-test passed identity=%u target=%lx data=%u handled=%lu "
       "unclaimed=%lu\n", identity, address, data, arrived,
       g_spurious - spurious_before);

  /* And the wired half, end to end, with no device involved.
   *
   * The test above wrote the interrupt file directly, which says nothing
   * about the APLIC. This one configures a source the APLIC owns, points its
   * target register at this hart's interrupt file, and asserts the source in
   * software -- so what is exercised is sourcecfg, the target register's hart
   * index and identity fields, the APLIC's own address arithmetic, the
   * message it sends, the IMSIC receiving it and the dispatch loop. The only
   * thing not exercised is a physical wire, and QEMU has no physical wires
   * either.
   *
   * The source is detached rather than level-sensitive on purpose: a level
   * source with nothing holding it would be re-armed by the dispatch loop and
   * immediately go quiet, which works but proves less clearly. Detached means
   * the only thing that can make it pending is the write below.
   *
   * The highest source the controller declares is used because nothing on
   * this board is wired that high -- QEMU's virt uses the low thirty-odd --
   * and it is checked to be inactive first, so a board that does use it gets
   * the test skipped instead of having a driver's routing overwritten. */
  if (g_wired_present == 0) {
    klog("aia: wired self-test skipped, no aplic on this machine\n");
    return;
  }
  uint32_t source = g_aplic_sources;
  if (*aplic_register(APLIC_SOURCECFG + (source - 1U) * 4U) !=
      APLIC_SOURCECFG_INACTIVE) {
    klog("aia: wired self-test skipped, source=%u is already in use\n",
         source);
    return;
  }
  uint32_t wired_identity = 0U;
  if (riscv64_aia_allocate(&wired_identity) != XAIOS_OK) {
    klog("aia: wired self-test skipped, no identity free\n");
    return;
  }
  uint32_t file = 0U;
  if (!file_of_cpu(cpu, &file) ||
      riscv64_aia_register(wired_identity, cpu, self_test_handler, 0) !=
          XAIOS_OK) {
    klog("aia: wired self-test FAILED: identity=%u would not register\n",
         wired_identity);
    return;
  }
  *aplic_register(APLIC_SOURCECFG + (source - 1U) * 4U) =
      APLIC_SOURCECFG_DETACHED;
  *aplic_register(APLIC_TARGET + (source - 1U) * 4U) =
      (file << 18U) | (wired_identity & UINT32_C(0x7ff));
  *aplic_register(APLIC_SETIENUM) = source;
  device_barrier();
  uint64_t wired_before = g_self_test_calls;
  *aplic_register(APLIC_SETIPNUM) = source;
  device_barrier();
  for (uint32_t spin = 0U;
       spin < 1000000U && g_self_test_calls == wired_before; ++spin) {
    __asm__ volatile("" ::: "memory");
  }
  uint64_t wired_arrived = g_self_test_calls - wired_before;
  *aplic_register(APLIC_CLRIENUM) = source;
  *aplic_register(APLIC_SOURCECFG + (source - 1U) * 4U) =
      APLIC_SOURCECFG_INACTIVE;
  device_barrier();
  (void)riscv64_aia_unregister(wired_identity);
  if (wired_arrived == 0U) {
    klog("aia: wired self-test FAILED: source=%u asserted at the aplic never "
         "reached identity=%u on hart file=%u\n", source, wired_identity,
         file);
    return;
  }
  klog("aia: wired self-test passed source=%u identity=%u file=%u "
       "handled=%lu\n", source, wired_identity, file, wired_arrived);
}
