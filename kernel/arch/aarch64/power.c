#include <xaios/arch_power.h>

#define PSCI_SYSTEM_OFF 0x84000008UL
#define PSCI_SYSTEM_RESET 0x84000009UL

static void psci_call(unsigned long function) {
  register unsigned long x0 __asm__("x0") = function;
  register unsigned long x1 __asm__("x1") = 0UL;
  register unsigned long x2 __asm__("x2") = 0UL;
  register unsigned long x3 __asm__("x3") = 0UL;
  __asm__ volatile("hvc #0"
                   : "+r"(x0)
                   : "r"(x1), "r"(x2), "r"(x3)
                   : "memory");
}

void arch_power_off(void) {
  __asm__ volatile("msr daifset, #0xf" ::: "memory");
  psci_call(PSCI_SYSTEM_OFF);
  for (;;) __asm__ volatile("wfe");
}

void arch_reboot(void) {
  __asm__ volatile("msr daifset, #0xf" ::: "memory");
  psci_call(PSCI_SYSTEM_RESET);
  for (;;) __asm__ volatile("wfe");
}
