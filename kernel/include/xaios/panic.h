#ifndef XAIOS_PANIC_H
#define XAIOS_PANIC_H

/*
 * Kernel panic — cyan screen of death.
 *
 * On fatal error: dumps registers + stack trace to UART with ANSI cyan
 * background, then halts forever (no auto-reboot) so the operator can
 * read the diagnostics.
 *
 * noreturn is load-bearing beyond codegen: kassert(pointer != 0) guards
 * every dereference that follows it only if the compiler and analyzers
 * know a failed assertion never falls through.
 */

void panic_at(const char *file, int line, const char *fmt, ...)
    __attribute__((noreturn, format(printf, 3, 4)));

#define panic(...) panic_at(__FILE__, __LINE__, __VA_ARGS__)

#endif
