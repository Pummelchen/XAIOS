#include <stdio.h>
#include <stdlib.h>

typedef unsigned long long xaios_u64;

#define XAIOS_SYSCALL_EXIT 2ULL
#define XAIOS_SYSCALL_CONSOLE_READ 47ULL
#define XAIOS_SYSCALL_CONSOLE_WRITE 48ULL

#if defined(XAIOS_LIBC_MAIN_VOID)
extern int main(void);
#else
extern int main(int argc, char **argv);
#endif
extern void __libc_init_array(void);

xaios_u64 __xaios_libc_syscall3(xaios_u64 number, xaios_u64 arg0,
                                xaios_u64 arg1, xaios_u64 arg2) {
#if defined(__aarch64__)
  register xaios_u64 x0 __asm__("x0") = arg0;
  register xaios_u64 x1 __asm__("x1") = arg1;
  register xaios_u64 x2 __asm__("x2") = arg2;
  register xaios_u64 x8 __asm__("x8") = number;
  __asm__ volatile("svc #0"
                   : "+r"(x0)
                   : "r"(x1), "r"(x2), "r"(x8)
                   : "memory");
  return x0;
#elif defined(__x86_64__)
  register xaios_u64 rax __asm__("rax") = number;
  register xaios_u64 rdi __asm__("rdi") = arg0;
  register xaios_u64 rsi __asm__("rsi") = arg1;
  register xaios_u64 rdx __asm__("rdx") = arg2;
  __asm__ volatile("int $0x80"
                   : "+a"(rax)
                   : "D"(rdi), "S"(rsi), "d"(rdx)
                   : "rcx", "r11", "memory");
  return rax;
#elif defined(__riscv)
  register xaios_u64 a0 __asm__("a0") = arg0;
  register xaios_u64 a1 __asm__("a1") = arg1;
  register xaios_u64 a2 __asm__("a2") = arg2;
  register xaios_u64 a7 __asm__("a7") = number;
  __asm__ volatile("ecall"
                   : "+r"(a0)
                   : "r"(a1), "r"(a2), "r"(a7)
                   : "memory");
  return a0;
#else
#error "Unsupported XAIOS userspace architecture"
#endif
}

static int console_put(char value, FILE *stream) {
  (void)stream;
  xaios_u64 result = __xaios_libc_syscall3(
      XAIOS_SYSCALL_CONSOLE_WRITE, (xaios_u64)(unsigned long)&value, 1U, 0U);
  return result == 1U ? (unsigned char)value : _FDEV_ERR;
}

static int console_get(FILE *stream) {
  unsigned char value = 0U;
  (void)stream;
  xaios_u64 result = __xaios_libc_syscall3(
      XAIOS_SYSCALL_CONSOLE_READ, (xaios_u64)(unsigned long)&value, 1U, 0U);
  return result == 1U ? value : _FDEV_EOF;
}

static int console_flush(FILE *stream) {
  (void)stream;
  return 0;
}

static FILE xaios_stdin_file =
    FDEV_SETUP_STREAM(NULL, console_get, NULL, _FDEV_SETUP_READ);
static FILE xaios_stdout_file =
    FDEV_SETUP_STREAM(console_put, NULL, console_flush, _FDEV_SETUP_WRITE);
static FILE xaios_stderr_file =
    FDEV_SETUP_STREAM(console_put, NULL, console_flush, _FDEV_SETUP_WRITE);

FILE *const stdin = &xaios_stdin_file;
FILE *const stdout = &xaios_stdout_file;
FILE *const stderr = &xaios_stderr_file;

void _exit(int status) {
  (void)__xaios_libc_syscall3(XAIOS_SYSCALL_EXIT,
                              (xaios_u64)(unsigned int)status, 0U, 0U);
  for (;;) {
#if defined(__aarch64__)
    __asm__ volatile("wfe");
#elif defined(__x86_64__)
    __asm__ volatile("pause");
#elif defined(__riscv)
    /* Not wfi: it is privileged and would trap out of the process that ran
       it. There is no unprivileged hint to give here, so this spins. */
    __asm__ volatile("" ::: "memory");
#endif
  }
}

void xaios_libc_start(int argc, char **argv) {
#if defined(XAIOS_LIBC_MAIN_VOID)
  (void)argc;
  (void)argv;
  __libc_init_array();
  exit(main());
#else
  __libc_init_array();
  exit(main(argc, argv));
#endif
}
