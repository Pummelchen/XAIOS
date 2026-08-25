#include <xaios/aarch64_sve.h>
#include <xaios/vmm.h>
#include <xaios/assert.h>
#include <xaios/klog.h>

extern uint64_t aarch64_sve_vector_bytes(void);
extern uint64_t aarch64_sve2_known_answer(void);

uint64_t g_aarch64_sve_enabled;

void aarch64_sve_publish_to_memory(void) {
  vmm_clean_to_memory(&g_aarch64_sve_enabled, sizeof(g_aarch64_sve_enabled));
}

uint32_t aarch64_sve_enabled(void) {
  return g_aarch64_sve_enabled != 0U;
}

uint64_t aarch64_sve_state_size(void) {
  return g_aarch64_sve_enabled == 0U
             ? 0U
             : XAIOS_AARCH64_SVE_STATE_MAX_BYTES;
}

void aarch64_sve2_self_test(void) {
  uint64_t pfr0 = 0U;
  __asm__ volatile("mrs %0, id_aa64pfr0_el1" : "=r"(pfr0));
  if (((pfr0 >> 32U) & UINT64_C(0xf)) == 0U) {
    klog("SVE: unavailable; scalable backend remains capability-gated\n");
    return;
  }
  uint64_t zfr0 = 0U;
  __asm__ volatile("mrs %0, S3_0_C0_C4_4" : "=r"(zfr0));
  if ((zfr0 & UINT64_C(0xf)) < 1U) {
    klog("SVE2: unavailable; scalable backend remains capability-gated\n");
    return;
  }
  uint64_t cpacr = 0U;
  __asm__ volatile("mrs %0, cpacr_el1" : "=r"(cpacr));
  /* The scheduler owns per-task Z/P/FFR storage, so EL0 and EL1 may use SVE. */
  cpacr = (cpacr & ~(UINT64_C(3) << 16U)) | (UINT64_C(3) << 16U);
  __asm__ volatile("msr cpacr_el1, %0\n"
                   "msr S3_0_C1_C2_0, %1\n"
                   "isb\n"
                   :
                   : "r"(cpacr), "r"(UINT64_C(0xf))
                   : "memory");
  uint64_t vector_bytes = aarch64_sve_vector_bytes();
  kassert(vector_bytes >= 16U && vector_bytes <= 256U &&
          (vector_bytes & (vector_bytes - 1U)) == 0U);
  kassert(aarch64_sve2_known_answer() == UINT64_C(7));
  g_aarch64_sve_enabled = vector_bytes;
  klog("SVE2: QEMU arithmetic canary passed vector_bytes=%lu el0=enabled\n",
       vector_bytes);
}
