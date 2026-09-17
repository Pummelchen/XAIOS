/* The OS-contract and hardware-gate reports, extracted verbatim from
 * kernel/arch/x86_64/early.c.
 *
 * This is a part of the bring-up with a boot position of its own and no
 * ordering coupling: x86_64_kmain calls
 * xaios_x86_early_validate_os_contract() and then
 * xaios_x86_early_validate_hardware_gate() at the very end of the
 * non-common-runtime path -- after the ring-3 syscall validation, the PCI and
 * VirtIO checks and the CPU placement policy, at milestones 50 and 51. Both
 * report state by reading xaios_common_runtime_probe() and printing it;
 * neither starts an AP, sends an IPI, touches the IDT or the AP trampoline,
 * programs a timer or takes an interrupt.
 *
 * The two report structs and their file-scope storage moved with the bodies.
 * The serial primitives come from early_serial.h and early_module.h, and the
 * common-runtime probe from <xaios/common_runtime.h>. The entry points cross
 * the seam under the names early_contract.h declares; the aliases at the top
 * of early.c keep its two call sites spelling them the way they did.
 *
 * Both reports exist only in the non-common-runtime configuration, which is
 * the only one whose x86_64_kmain calls them, so the definitions sit under
 * `#if !XAIOS_X86_COMMON_RUNTIME` below. That guard is load-bearing rather than
 * cosmetic: the bodies read xaios_common_runtime_probe(), and no kernel object
 * in the x86_64 link defines that symbol (kernel/core/common_runtime.c is not
 * in the build lists). The definitions were file-scope in that file, so -Os
 * removed them there and the reference never reached the link; they are
 * externally visible here, and emitting them into the common-runtime link
 * would be an undefined reference. In the non-common-runtime configuration
 * they are called, exactly as before. */

#include <xaios/common_runtime.h>
#include <xaios/types.h>

#include "early_contract.h"
#include "early_module.h"
#include "early_serial.h"

#ifndef XAIOS_X86_COMMON_RUNTIME
#define XAIOS_X86_COMMON_RUNTIME 0
#endif

#if XAIOS_X86_COMMON_RUNTIME
#define X86_BRINGUP_ONLY __attribute__((unused))
#else
#define X86_BRINGUP_ONLY
#endif

/* early.c's serial primitives, under the names early_module.h declares. */
#define serial_puts xaios_x86_early_serial_puts
#define serial_dec xaios_x86_early_serial_dec
#define serial_hex64 xaios_x86_early_serial_hex64

#if !XAIOS_X86_COMMON_RUNTIME

typedef struct x86_64_contract_state {
  uint32_t userspace_contract_ready;
  uint32_t filesystem_contract_ready;
  uint32_t networking_contract_ready;
  uint32_t ai_cell_contract_ready;
  uint32_t security_contract_ready;
  uint32_t telemetry_contract_ready;
  uint32_t full_os_contract_ready;
} x86_64_contract_state_t;

typedef struct x86_64_hardware_gate_state {
  uint32_t qemu_correctness_ready;
  uint32_t physical_hardware_required;
  uint32_t tuned_linux_bsd_baseline_required;
  uint32_t performance_claims_allowed;
  uint32_t release_candidate_ready;
} x86_64_hardware_gate_state_t;

/* The two report records. Both were file-scope in early.c and are file-scope
 * here; nothing outside these two functions read them. */
static x86_64_contract_state_t g_contract;
static x86_64_hardware_gate_state_t g_hardware_gate;

void X86_BRINGUP_ONLY xaios_x86_early_validate_os_contract(
    uint16_t serial_base) {
  uint32_t portable = xaios_common_runtime_probe();
  uint32_t storage_ready =
      (portable & (XAIOS_COMMON_RUNTIME_BLOCK | XAIOS_COMMON_RUNTIME_VFS)) ==
      (XAIOS_COMMON_RUNTIME_BLOCK | XAIOS_COMMON_RUNTIME_VFS);
  g_contract = (x86_64_contract_state_t){
      .userspace_contract_ready = 0U,
      .filesystem_contract_ready = storage_ready,
      .networking_contract_ready = 0U,
      .ai_cell_contract_ready = 0U,
      .security_contract_ready = 0U,
      .telemetry_contract_ready = 0U,
      .full_os_contract_ready = 0U,
  };

  serial_puts(serial_base, "x86_64: common kernel/runtime linked=1 probe=");
  serial_hex64(serial_base, portable);
  serial_puts(serial_base, " expected=0x000000000000000f\n");
  serial_puts(serial_base, "x86_64: OS contract userspace=");
  serial_dec(serial_base, g_contract.userspace_contract_ready);
  serial_puts(serial_base, " filesystem=");
  serial_dec(serial_base, g_contract.filesystem_contract_ready);
  serial_puts(serial_base, " networking=");
  serial_dec(serial_base, g_contract.networking_contract_ready);
  serial_puts(serial_base, " ai_cell=");
  serial_dec(serial_base, g_contract.ai_cell_contract_ready);
  serial_puts(serial_base, " security=");
  serial_dec(serial_base, g_contract.security_contract_ready);
  serial_puts(serial_base, " telemetry=");
  serial_dec(serial_base, g_contract.telemetry_contract_ready);
  serial_puts(serial_base, "\n");
  serial_puts(serial_base, "x86_64: full OS contract parity marker ready=");
  serial_dec(serial_base, g_contract.full_os_contract_ready);
  serial_puts(serial_base, "\n");
}

void X86_BRINGUP_ONLY xaios_x86_early_validate_hardware_gate(
    uint16_t serial_base) {
  g_hardware_gate = (x86_64_hardware_gate_state_t){
      .qemu_correctness_ready = 1U,
      .physical_hardware_required = 1U,
      .tuned_linux_bsd_baseline_required = 1U,
      .performance_claims_allowed = 0U,
      .release_candidate_ready = 0U,
  };

  serial_puts(serial_base, "x86_64: hardware gate qemu_correctness=");
  serial_dec(serial_base, g_hardware_gate.qemu_correctness_ready);
  serial_puts(serial_base, " physical_required=");
  serial_dec(serial_base, g_hardware_gate.physical_hardware_required);
  serial_puts(serial_base, " baseline_required=");
  serial_dec(serial_base, g_hardware_gate.tuned_linux_bsd_baseline_required);
  serial_puts(serial_base, " performance_claims_allowed=");
  serial_dec(serial_base, g_hardware_gate.performance_claims_allowed);
  serial_puts(serial_base, " release_candidate_ready=");
  serial_dec(serial_base, g_hardware_gate.release_candidate_ready);
  serial_puts(serial_base, "\n");
  serial_puts(serial_base, "x86_64: Intel Desktop hardware gate blocked platform-parity-and-physical-evidence-required\n");
}

#endif
