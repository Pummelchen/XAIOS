#include <assert.h>
#include <complex.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#define C99_SUM3(first, ...) ((first) + (__VA_ARGS__))
#define C99_STRINGIFY_INNER(value) #value
#define C99_STRINGIFY(value) C99_STRINGIFY_INNER(value)

struct language_record {
  int first;
  int second;
  int values[];
};

static inline int square(int value) {
  return value * value;
}

static int restricted_sum(size_t count, int *restrict output,
                          const int *restrict input) {
  int total = 0;
  for (size_t index = 0; index < count; ++index) {
    output[index] = input[index] * 2;
    total += output[index];
  }
  return total;
}

static int variable_array_sum(size_t count) {
  int values[count];
  int total = 0;
  for (size_t index = 0; index < count; ++index) {
    values[index] = (int)index + 1;
    total += values[index];
  }
  return total;
}

int xaios_c99_language_conformance(void) {
  struct language_record designated = {
      .second = 7,
      .first = 3,
  };
  int sparse[5] = {[1] = 4, [4] = 9};
  int input[] = {1, 2, 3, 4};
  int output[4] = {0};
  struct language_record *flexible =
      malloc(sizeof(*flexible) + 3U * sizeof(flexible->values[0]));
  double complex imaginary = 2.0 * I;
  _Bool truth = 1;
  int \u03b1 = 11;

  assert(designated.first == 3 && designated.second == 7);
  assert(sparse[0] == 0 && sparse[1] == 4 && sparse[4] == 9);
  assert(((struct language_record){.first = 5, .second = 6}).second == 6);
  assert(restricted_sum(4U, output, input) == 20 && output[3] == 8);
  assert(variable_array_sum(5U) == 15);
  assert(square(6) == 36);
  assert(C99_SUM3(1, 2 + 3) == 6);
  assert(sizeof(C99_STRINGIFY(C99_SUM3)) > 1U);
  assert(0x1.8p+2 == 6.0);
  assert(creal(imaginary) == 0.0 && cimag(imaginary) == 2.0);
  assert(truth && \u03b1 == 11);
  assert(flexible != NULL);
  flexible->first = 1;
  flexible->second = 2;
  flexible->values[0] = 3;
  flexible->values[1] = 4;
  flexible->values[2] = 5;
  assert(flexible->values[2] == 5);
  free(flexible);

  puts("C99-LANGUAGE-PASS");
  return 0;
}
