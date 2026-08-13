#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <xaios/thread.h>

#define XAIOS_LIBC_TEST_THREADS 3U
#define XAIOS_LIBC_TEST_WRITES 64U
#define XAIOS_LIBC_TEST_STACK_BYTES 32768U

static unsigned char stacks[XAIOS_LIBC_TEST_THREADS][XAIOS_LIBC_TEST_STACK_BYTES]
    __attribute__((aligned(16)));
static FILE *shared_stream;

static uint64_t worker(void *argument) {
  uintptr_t ordinal = (uintptr_t)argument;
  char line[32];
  for (unsigned int iteration = 0U; iteration < XAIOS_LIBC_TEST_WRITES;
       ++iteration) {
    unsigned char *block = (unsigned char *)malloc(257U + ordinal);
    if (block == NULL) return UINT64_MAX;
    memset(block, (int)(ordinal + iteration), 257U + ordinal);
    if (block[0] != (unsigned char)(ordinal + iteration)) return UINT64_MAX;
    free(block);
    if (snprintf(line, sizeof(line), "T%lu:%u\n", (unsigned long)ordinal,
                 iteration) <= 0 || fputs(line, shared_stream) < 0) {
      return UINT64_MAX;
    }
    errno = 0;
    if (fopen("/tmp/xaios-libc-missing", "r") != NULL || errno != ENOENT) {
      return UINT64_MAX;
    }
  }
  return UINT64_C(0xc9900000) + ordinal;
}

int main(int argc, char **argv) {
  uint64_t ids[XAIOS_LIBC_TEST_THREADS];
  uint64_t result;
  char line[32];
  unsigned int lines = 0U;

  assert(argc == 1 && argv != NULL);
  shared_stream = tmpfile();
  assert(shared_stream != NULL);
  for (unsigned int index = 0U; index < XAIOS_LIBC_TEST_THREADS; ++index) {
    assert(xaios_thread_create(worker, (void *)(uintptr_t)index, stacks[index],
                               sizeof(stacks[index]), XAIOS_THREAD_CPU_ANY,
                               &ids[index]) == 0);
  }
  for (unsigned int index = 0U; index < XAIOS_LIBC_TEST_THREADS; ++index) {
    assert(xaios_thread_join(ids[index], UINT64_C(5000000000), &result) == 0);
    assert(result == UINT64_C(0xc9900000) + index);
  }
  assert(fflush(shared_stream) == 0);
  rewind(shared_stream);
  while (fgets(line, sizeof(line), shared_stream) != NULL) ++lines;
  assert(lines == XAIOS_LIBC_TEST_THREADS * XAIOS_LIBC_TEST_WRITES);
  assert(fclose(shared_stream) == 0);
  puts("C99-THREAD-CONTEXT-PASS");
  return 0;
}
