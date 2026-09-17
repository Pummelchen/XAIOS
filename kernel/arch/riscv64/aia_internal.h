/* Private interface shared by aia.c, aia_init.c and aia_selftest.c.
 *
 * The AIA driver was one 833-line file. aia_init.c now owns the device-tree
 * discovery that picks the supervisor controllers out of the machine-mode
 * pair, the register programming that brings them up and the geometry they
 * were found at; aia_selftest.c owns the two proof-of-delivery tests at the
 * end; aia.c keeps the per-identity vector table and the runtime that
 * allocates, registers, routes and dispatches through it.
 *
 * What has to be agreed across those three translation units lives here: the
 * register numbers and field values from the AIA and APLIC specifications,
 * the three declarations all three files already used from the single file,
 * the register primitives that stopped being static when they crossed, and
 * the accessors that answer aia.c's questions about what aia_init.c found.
 * The accessors answer by value or into a caller-owned local, never as a
 * pointer into aia_init.c's mutable state, and every name crossing a
 * translation unit carries the riscv64_aia_ prefix.
 *
 * This is arch-private. Nothing outside kernel/arch/riscv64 includes it, and
 * the public interface stays in xaios/riscv64_aia.h.
 */
#ifndef XAIOS_ARCH_RISCV64_AIA_INTERNAL_H
#define XAIOS_ARCH_RISCV64_AIA_INTERNAL_H

#include <xaios/riscv64_aia.h>
#include <xaios/status.h>

#include <stdint.h>

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

/* Declared here rather than taken from xaios/klog.h, which carries a printf
   format attribute: these are the declarations the single aia.c has always
   used, moved so that every split file shares one copy of them. */
void klog(const char *fmt, ...);
uint32_t smp_cpu_id(void);
uint32_t riscv64_hart_of_cpu(uint32_t cpu_id);

/* Register programming, defined in aia_init.c and called by the runtime in
   aia.c. These were static helpers of the single file; only their linkage
   changed, and each keeps the exact sequence of CSR or MMIO accesses it had.
   `riscv64_aia_aplic_register` returns an APLIC MMIO address, not a pointer
   into kernel state. */
void riscv64_aia_imsic_set_enable(uint32_t identity, int enabled);
volatile uint32_t *riscv64_aia_aplic_register(uint64_t offset);
void riscv64_aia_device_barrier(void);

/* What discovery found, written once during riscv64_aia_init() and read
   afterwards by the runtime. Each answers into the caller's own local; none
   exposes aia_init.c's mutable state. */
uint32_t riscv64_aia_identity_count(void);
uint32_t riscv64_aia_aplic_sources(void);
uint64_t riscv64_aia_message_address(uint32_t file);
int riscv64_aia_file_of_cpu(uint32_t cpu_id, uint32_t *file);
int riscv64_aia_file_known(uint32_t hart);

/* The per-identity enable a hart owes itself when it brings its own interrupt
   file up. Defined in aia.c, which owns the vector table, and called from
   riscv64_aia_init_hart() in aia_init.c. */
void riscv64_aia_enable_pending_for_hart(uint32_t hart);

#endif /* XAIOS_ARCH_RISCV64_AIA_INTERNAL_H */
