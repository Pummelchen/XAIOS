#include <xaios/arch_power.h>
#include <xaios/types.h>

static inline void outb(uint16_t port, uint8_t value) {
  __asm__ volatile("outb %0, %1" : : "a"(value), "Nd"(port) : "memory");
}

static inline void outw(uint16_t port, uint16_t value) {
  __asm__ volatile("outw %0, %1" : : "a"(value), "Nd"(port) : "memory");
}

void arch_power_off(void) {
  __asm__ volatile("cli" ::: "memory");
  outw(UINT16_C(0x604), UINT16_C(0x2000));
  for (;;) __asm__ volatile("hlt");
}

void arch_reboot(void) {
  __asm__ volatile("cli" ::: "memory");
  outb(UINT16_C(0xcf9), UINT8_C(0x06));
  outb(UINT16_C(0x64), UINT8_C(0xfe));
  for (;;) __asm__ volatile("hlt");
}
