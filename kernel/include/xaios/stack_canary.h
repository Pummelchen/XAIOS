#ifndef XAIOS_STACK_CANARY_H
#define XAIOS_STACK_CANARY_H

#include <xaios/arch_cpu.h>
#include <xaios/types.h>

#define XAIOS_CANARY_MAGIC UINT64_C(0x5841494F535F4341) /* "XAIOS_CA" */

/* Global canary value, seeded in entry.S from CNTVCT_EL0 */
extern uint64_t g_stack_canary;

void stack_canary_init(void);
uint64_t stack_canary_value(void);
void stack_canary_check(uint64_t saved, const char *func);
uint64_t stack_canary_corruption_count(void);
void stack_canary_self_test(void);

/*
 * Stack protection macros for manual insertion in critical functions.
 * Usage:
 *   void critical_function(void) {
 *     uint64_t __canary_saved;
 *     XAIOS_STACK_PROTECT_BEGIN(__canary_saved);
 *     ... function body ...
 *     XAIOS_STACK_PROTECT_END(__canary_saved, "critical_function");
 *   }
 */
#define XAIOS_STACK_PROTECT_BEGIN(saved_var)                     \
  do {                                                          \
    uint64_t __sp_val;                                          \
    __sp_val = xaios_cpu_stack_pointer();                       \
    (saved_var) = g_stack_canary ^ __sp_val;                   \
  } while (0)

#define XAIOS_STACK_PROTECT_END(saved_var, func_name)            \
  do {                                                          \
    uint64_t __sp_val;                                          \
    __sp_val = xaios_cpu_stack_pointer();                       \
    uint64_t __expected = g_stack_canary ^ __sp_val;           \
    if ((saved_var) != __expected) {                            \
      stack_canary_check((saved_var), (func_name));             \
    }                                                           \
  } while (0)

#endif
