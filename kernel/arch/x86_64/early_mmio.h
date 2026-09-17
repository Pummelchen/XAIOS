#ifndef XAIOS_X86_64_EARLY_MMIO_H
#define XAIOS_X86_64_EARLY_MMIO_H

/* The byte/word/dword/qword MMIO accessors early_pci.c uses, carved out of
 * early.c at the same time as that file's VirtIO block so no one module
 * exceeds the repository's file-size budget. `static inline`, so each
 * translation unit that includes this inlines them and no external symbol is
 * introduced. */

#include <xaios/types.h>

static inline uint8_t mmio_read8(uint64_t address) {
  return *(volatile uint8_t *)(uintptr_t)address;
}

static inline uint16_t mmio_read16(uint64_t address) {
  return *(volatile uint16_t *)(uintptr_t)address;
}

static inline uint32_t mmio_read32(uint64_t address) {
  return *(volatile uint32_t *)(uintptr_t)address;
}

static inline void mmio_write8(uint64_t address, uint8_t value) {
  *(volatile uint8_t *)(uintptr_t)address = value;
}

static inline void mmio_write16(uint64_t address, uint16_t value) {
  *(volatile uint16_t *)(uintptr_t)address = value;
}

static inline void mmio_write32(uint64_t address, uint32_t value) {
  *(volatile uint32_t *)(uintptr_t)address = value;
}

static inline void mmio_write64(uint64_t address, uint64_t value) {
  *(volatile uint64_t *)(uintptr_t)address = value;
}

#endif
