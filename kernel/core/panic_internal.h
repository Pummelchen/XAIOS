/* Private interface shared by panic.c and the rendering half of it.
 *
 * panic.c keeps panic_at -- the entry point, the interrupt mask, the console
 * claim, and the register and backtrace capture -- and the cyan-screen
 * rendering moves out: the banner, the formatted message, and the CPU,
 * general-purpose-register, system-register, backtrace, recent-log and halt
 * reports.
 *
 * The panic output is parsed by tests/scripts/resolve-panic.py and matched by
 * the fault gates, so every printed field and its order is exactly what
 * panic.c printed before; the renderers moved verbatim and only their names
 * gained the `panic_render_' prefix. The capture routines stay in panic.c
 * because they run before the console is claimed and are tied to the frame it
 * captures.
 *
 * The symbols declared here carry that prefix so two modules cannot collide
 * at link time.
 */
#ifndef XAIOS_KERNEL_CORE_PANIC_INTERNAL_H
#define XAIOS_KERNEL_CORE_PANIC_INTERNAL_H

#include <stdarg.h>
#include <stdint.h>

/* The cyan banner and its clear sequence. */
void panic_render_banner(void);

/* The "ERROR:" line, its payload format and the file/line footer. */
void panic_render_message(const char *file, int line, const char *fmt,
                          va_list args);

/* CPU identity, online count and the free/total RAM lines. */
void panic_render_cpu_info(void);

/* The general-purpose register dump, by ABI name for the architecture. */
void panic_render_gp_regs(const uint64_t *r);

/* The system-register dump, under the names of the architecture that faulted. */
void panic_render_sys_regs(uint64_t elr, uint64_t esr, uint64_t far,
                           uint64_t spsr, uint64_t sp_el0,
                           uint64_t current_el);

/* The stack backtrace, its load base and the frames that fell outside. */
void panic_render_backtrace(const uint64_t *trace, uint32_t depth);

/* The tail of the kernel log, so the reason stays attached to the failure. */
void panic_render_recent_log(void);

/* The suppression counts and the final halt lines. */
void panic_render_halt(void);

#endif /* XAIOS_KERNEL_CORE_PANIC_INTERNAL_H */
