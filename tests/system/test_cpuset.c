#include <stdint.h>
#include <stdio.h>

#include <xaios/cpuset.h>

static int require(int condition, const char *message) {
  if (condition != 0) return 0;
  fprintf(stderr, "test-cpuset: %s\n", message);
  return 1;
}

int main(void) {
  enum { CPU_CAPACITY = 4097, WORD_COUNT = 65 };
  uint64_t lhs_storage[WORD_COUNT];
  uint64_t rhs_storage[WORD_COUNT];
  xaios_cpuset_t lhs;
  xaios_cpuset_t rhs;
  int failures = 0;

  failures += require(xaios_cpuset_words(CPU_CAPACITY) == WORD_COUNT,
                      "runtime word count is incorrect");
  xaios_cpuset_init(&lhs, lhs_storage, CPU_CAPACITY);
  xaios_cpuset_init(&rhs, rhs_storage, CPU_CAPACITY);

  xaios_cpuset_set(&lhs, 0U);
  xaios_cpuset_set(&lhs, 127U);
  xaios_cpuset_set(&lhs, 128U);
  xaios_cpuset_set(&lhs, 4096U);
  xaios_cpuset_set(&lhs, CPU_CAPACITY);
  failures += require(xaios_cpuset_count(&lhs) == 4U,
                      "set/count crossed a runtime boundary incorrectly");
  failures += require(xaios_cpuset_first(&lhs) == 0U,
                      "first CPU lookup failed");
  failures += require(xaios_cpuset_test(&lhs, 127U) != 0 &&
                          xaios_cpuset_test(&lhs, 128U) != 0 &&
                          xaios_cpuset_test(&lhs, 4096U) != 0,
                      "high CPU IDs were not represented");
  failures += require(xaios_cpuset_test(&lhs, CPU_CAPACITY) == 0,
                      "out-of-range CPU was represented");

  xaios_cpuset_set(&rhs, 128U);
  xaios_cpuset_set(&rhs, 2048U);
  xaios_cpuset_and(&lhs, &rhs);
  failures += require(xaios_cpuset_count(&lhs) == 1U &&
                          xaios_cpuset_test(&lhs, 128U) != 0,
                      "intersection failed across multiple words");
  xaios_cpuset_or(&lhs, &rhs);
  failures += require(xaios_cpuset_count(&lhs) == 2U &&
                          xaios_cpuset_test(&lhs, 2048U) != 0,
                      "union failed across multiple words");
  xaios_cpuset_clear(&lhs, 128U);
  failures += require(xaios_cpuset_first(&lhs) == 2048U,
                      "clear or first failed for a high CPU ID");
  xaios_cpuset_zero(&lhs);
  failures += require(xaios_cpuset_first(&lhs) == CPU_CAPACITY,
                      "empty set sentinel is incorrect");

  if (failures != 0) return 1;
  puts("test-cpuset: dynamic CPU sets passed capacity=4097 words=65");
  return 0;
}
