/* The two delivery self-tests of the RISC-V Advanced Interrupt Architecture.
 *
 * This is the tail of the single aia.c, split out once the driver passed 500
 * lines. Both tests are here because they are one subject -- proof that a
 * message actually arrived rather than that a register was written -- and
 * because neither is on any path a running system takes: the IMSIC test sends
 * this hart a message through its own interrupt file, and the APLIC test
 * asserts a detached source in software and requires it forwarded as a
 * message. The counters they read are aia.c's; the geometry they read is
 * aia_init.c's, through the accessors in aia_internal.h.
 *
 * The tests are moved verbatim, including their comments. What is asserted on
 * a real board is the log text, so nothing about the sequence, the spin
 * bound, the identity allocation or the wording changed.
 */
#include <xaios/riscv64_aia.h>
#include <xaios/status.h>

#include <stdint.h>

#include "aia_internal.h"

static volatile uint64_t g_self_test_calls;

static void self_test_handler(uint32_t identifier, void *context) {
  (void)identifier;
  (void)context;
  ++g_self_test_calls;
}

void riscv64_aia_self_test(void) {
  if (riscv64_aia_present() == 0) return;
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
  uint64_t spurious_before = riscv64_aia_spurious();
  *(volatile uint32_t *)(uintptr_t)address = data;
  riscv64_aia_device_barrier();
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
         riscv64_aia_delivered(), riscv64_aia_spurious());
    return;
  }
  klog("aia: self-test passed identity=%u target=%lx data=%u handled=%lu "
       "unclaimed=%lu\n", identity, address, data, arrived,
       riscv64_aia_spurious() - spurious_before);

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
  if (riscv64_aia_wired_present() == 0) {
    klog("aia: wired self-test skipped, no aplic on this machine\n");
    return;
  }
  uint32_t source = riscv64_aia_aplic_sources();
  if (*riscv64_aia_aplic_register(APLIC_SOURCECFG + (source - 1U) * 4U) !=
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
  if (!riscv64_aia_file_of_cpu(cpu, &file) ||
      riscv64_aia_register(wired_identity, cpu, self_test_handler, 0) !=
          XAIOS_OK) {
    klog("aia: wired self-test FAILED: identity=%u would not register\n",
         wired_identity);
    return;
  }
  *riscv64_aia_aplic_register(APLIC_SOURCECFG + (source - 1U) * 4U) =
      APLIC_SOURCECFG_DETACHED;
  *riscv64_aia_aplic_register(APLIC_TARGET + (source - 1U) * 4U) =
      (file << 18U) | (wired_identity & UINT32_C(0x7ff));
  *riscv64_aia_aplic_register(APLIC_SETIENUM) = source;
  riscv64_aia_device_barrier();
  uint64_t wired_before = g_self_test_calls;
  *riscv64_aia_aplic_register(APLIC_SETIPNUM) = source;
  riscv64_aia_device_barrier();
  for (uint32_t spin = 0U;
       spin < 1000000U && g_self_test_calls == wired_before; ++spin) {
    __asm__ volatile("" ::: "memory");
  }
  uint64_t wired_arrived = g_self_test_calls - wired_before;
  *riscv64_aia_aplic_register(APLIC_CLRIENUM) = source;
  *riscv64_aia_aplic_register(APLIC_SOURCECFG + (source - 1U) * 4U) =
      APLIC_SOURCECFG_INACTIVE;
  riscv64_aia_device_barrier();
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
