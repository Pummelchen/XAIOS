#ifndef XAIOS_X86_64_PLATFORM_H
#define XAIOS_X86_64_PLATFORM_H

#include <xaios/types.h>

struct xaios_cpu_state;

uint64_t x86_64_platform_tsc(void);
uint64_t x86_64_platform_tsc_hz(void);
void x86_64_platform_set_tsc_hz(uint64_t frequency);
uint64_t x86_64_platform_lapic_hz(void);
uint32_t x86_64_platform_cpu_count(void);
uint32_t x86_64_platform_cpu_apic_id(uint32_t ordinal);
uint32_t x86_64_platform_cpu_online(uint32_t ordinal);
uint32_t x86_64_platform_workers_ready(void);
struct xaios_cpu_state *x86_64_platform_cpu_state(uint32_t ordinal);
void x86_64_platform_set_page_tables(uint32_t ordinal, uint64_t *root,
                                      uint64_t *user_directory);
uint64_t *x86_64_platform_page_table_root(uint32_t ordinal);
uint64_t *x86_64_platform_user_page_directory(uint32_t ordinal);
uint32_t x86_64_platform_current_ordinal(void);
void x86_64_platform_wake(uint32_t ordinal);
void x86_64_platform_release_workers(void);
uint64_t x86_64_platform_bootstrap_start(void);
uint64_t x86_64_platform_bootstrap_end(void);
void x86_64_platform_timer_start(uint32_t initial_count, uint32_t periodic);
void x86_64_platform_timer_stop(void);
uint64_t x86_64_platform_timer_interrupts(void);
void x86_64_platform_eoi(void);
void x86_64_platform_invalidate_page_all(uint64_t virtual_address);
uint64_t x86_64_platform_tlb_shootdown_count(void);

void x86_64_platform_timer_irq(void);
void x86_64_platform_set_user_resume(uint64_t stack);
uint64_t x86_64_platform_user_resume(void);
void x86_64_platform_set_user_return(uint64_t value);
uint64_t x86_64_platform_user_return(void);

#endif
