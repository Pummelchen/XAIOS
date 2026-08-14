#include <xaios/arch_random.h>

#if defined(__aarch64__)

#define XAIOS_AARCH64_ISAR0_RNDR_SHIFT UINT32_C(60)
#define XAIOS_AARCH64_PSTATE_C UINT64_C(1) << 29U

static uint64_t aarch64_isar0(void) {
  uint64_t value;
  __asm__ volatile("mrs %0, ID_AA64ISAR0_EL1" : "=r"(value));
  return value;
}

static xaios_status_t aarch64_random_word(uint64_t *word) {
  for (uint32_t attempt = 0U; attempt < 16U; ++attempt) {
    uint64_t value;
    uint64_t flags;
    __asm__ volatile("mrs %0, S3_3_C2_C4_0\n\tmrs %1, NZCV"
                     : "=r"(value), "=r"(flags));
    if ((flags & XAIOS_AARCH64_PSTATE_C) != 0U) {
      *word = value;
      return XAIOS_OK;
    }
  }
  return XAIOS_ERR_IO;
}

xaios_status_t arch_random_read(void *buffer, uint64_t size) {
  if (buffer == 0 || size == 0U) return XAIOS_ERR_INVALID;
  if (((aarch64_isar0() >> XAIOS_AARCH64_ISAR0_RNDR_SHIFT) & 0xfU) == 0U) {
    return XAIOS_ERR_UNSUPPORTED;
  }
  uint8_t *out = (uint8_t *)buffer;
  while (size != 0U) {
    uint64_t word = 0U;
    xaios_status_t status = aarch64_random_word(&word);
    if (status != XAIOS_OK) return status;
    const uint32_t bytes = size > sizeof(word) ? sizeof(word) : (uint32_t)size;
    for (uint32_t index = 0U; index < bytes; ++index) {
      out[index] = (uint8_t)(word >> (8U * index));
    }
    word = 0U;
    out += bytes;
    size -= bytes;
  }
  return XAIOS_OK;
}

#else

xaios_status_t arch_random_read(void *buffer, uint64_t size) {
  (void)buffer;
  (void)size;
  return XAIOS_ERR_UNSUPPORTED;
}

#endif
