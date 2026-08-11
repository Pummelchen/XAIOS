#include <assert.h>
#include <complex.h>
#include <errno.h>
#include <math.h>
#include <setjmp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <wchar.h>

#if __STDC_HOSTED__ != 1
#error "XAIOS libc applications must be hosted implementations"
#endif

#if __STDC_VERSION__ != 199901L
#error "XAIOS libc applications must select ISO C99"
#endif

static jmp_buf jump_target;
static volatile sig_atomic_t signal_seen;

extern int xaios_c99_conformance_suite(void);

static int compare_ints(const void *left, const void *right) {
  int a = *(const int *)left;
  int b = *(const int *)right;
  return (a > b) - (a < b);
}

static void on_signal(int number) {
  signal_seen = number;
}

static void on_exit_marker(void) {
  puts("C99-ATEXIT-PASS");
}

int main(int argc, char **argv) {
  char formatted[96];
  int values[] = {7, -2, 19, 0, 5};
  wchar_t wide[8];
  double complex value = 5.0;
  unsigned char *memory;
  char file_buffer[32];
  FILE *file;
  clock_t cpu_before;
  time_t wall;

  assert(argc == 0);
  assert(argv != NULL && argv[0] == NULL);
  assert(atexit(on_exit_marker) == 0);

  memory = malloc(4096U);
  assert(memory != NULL);
  memset(memory, 0x5a, 4096U);
  assert(memory[0] == 0x5a && memory[4095] == 0x5a);
  free(memory);

  qsort(values, sizeof(values) / sizeof(values[0]), sizeof(values[0]),
        compare_ints);
  assert(values[0] == -2 && values[4] == 19);
  assert(strtol("7f", NULL, 16) == 127L);
  assert(fabs(cabs(value) - 5.0) < 1e-12);

  assert(mbstowcs(wide, "C99", 8U) == 3U);
  assert(wide[0] == L'C' && wide[2] == L'9');
  assert(snprintf(formatted, sizeof(formatted), "%lld %.3Lf %ls%n",
                  9223372036854775807LL, 1.25L, wide, &values[0]) > 0);
  assert(strstr(formatted, "9223372036854775807 1.250 C99") != NULL);
  assert(values[0] > 0);

  assert(signal(SIGINT, on_signal) != SIG_ERR);
  assert(raise(SIGINT) == 0);
  assert(signal_seen == SIGINT);

  if (setjmp(jump_target) == 0) {
    longjmp(jump_target, 42);
  }

  file = fopen("/tmp/c99-runtime.txt", "w+");
  assert(file != NULL);
  assert(fwrite("portable-c99", 1U, 12U, file) == 12U);
  assert(fflush(file) == 0);
  assert(ftell(file) == 12L);
  rewind(file);
  memset(file_buffer, 0, sizeof(file_buffer));
  assert(fread(file_buffer, 1U, 12U, file) == 12U);
  assert(strcmp(file_buffer, "portable-c99") == 0);
  assert(fclose(file) == 0);
  assert(rename("/tmp/c99-runtime.txt", "/tmp/c99-runtime-renamed.txt") == 0);
  file = fopen("/tmp/c99-runtime-renamed.txt", "r");
  assert(file != NULL);
  assert(fclose(file) == 0);
  assert(remove("/tmp/c99-runtime-renamed.txt") == 0);

  file = tmpfile();
  assert(file != NULL);
  assert(fputs("temporary", file) >= 0);
  rewind(file);
  assert(fgets(file_buffer, sizeof(file_buffer), file) != NULL);
  assert(strcmp(file_buffer, "temporary") == 0);
  assert(fclose(file) == 0);

  cpu_before = clock();
  assert(cpu_before != (clock_t)-1);
  wall = time(NULL);
  assert(wall != (time_t)-1);
  assert(xaios_c99_conformance_suite() == 0);

  puts("C99-RUNTIME-PASS");
  return 0;
}
