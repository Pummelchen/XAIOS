#include <assert.h>
#include <complex.h>
#include <ctype.h>
#include <errno.h>
#include <fenv.h>
#include <float.h>
#include <inttypes.h>
#include <limits.h>
#include <locale.h>
#include <math.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tgmath.h>
#include <time.h>
#include <wchar.h>
#include <wctype.h>

#pragma STDC FENV_ACCESS ON

typedef union maximum_alignment_probe {
  long double ld;
  void *pointer;
  long long integer;
} maximum_alignment_probe_t;

extern int xaios_c99_language_conformance(void);

static int integer_compare(const void *left, const void *right) {
  const int a = *(const int *)left;
  const int b = *(const int *)right;
  return (a > b) - (a < b);
}

static void test_types_and_macros(void) {
  maximum_alignment_probe_t probe;
  ptrdiff_t difference = (char *)&probe.pointer - (char *)&probe;
  int32_t exact = INT32_C(123);
  uintmax_t maximum = UINTMAX_C(18446744073709551615);
  assert(difference >= 0);
  assert(sizeof(int8_t) == 1U && sizeof(uint64_t) == 8U);
  assert(exact == 123 && maximum == UINTMAX_MAX);
  assert(true && !false);
  assert(CHAR_BIT == 8 && LLONG_MAX >= 9223372036854775807LL);
  assert(FLT_RADIX >= 2 && DECIMAL_DIG >= 10);
  puts("C99-TYPES-MACROS-PASS");
}

static void test_character_and_strings(void) {
  char text[64] = "alpha";
  char transformed[64];
  char overlap[] = "abcdef";
  wchar_t wide[16];
  mbstate_t state;
  const char *multibyte = "C99";
  const wchar_t *wide_source;

  assert(isalpha((unsigned char)'A') && isblank((unsigned char)' '));
  assert(isxdigit((unsigned char)'f') && toupper((unsigned char)'q') == 'Q');
  assert(strcat(text, "-beta") == text);
  assert(strcmp(text, "alpha-beta") == 0);
  assert(strstr(text, "beta") == text + 6);
  assert(memmove(overlap + 1, overlap, 5U) == overlap + 1);
  assert(memcmp(overlap, "aabcde", 6U) == 0);
  assert(strxfrm(transformed, "C99", sizeof(transformed)) <
         sizeof(transformed));
  assert(strcoll("a", "b") < 0);

  memset(&state, 0, sizeof(state));
  assert(mbrlen("A", 1U, &state) == 1U);
  memset(&state, 0, sizeof(state));
  assert(mbsrtowcs(wide, &multibyte, 16U, &state) == 3U);
  assert(wcscmp(wide, L"C99") == 0);
  assert(iswalpha(L'Z') && towlower(L'Z') == L'z');
  wide_source = wide;
  memset(&state, 0, sizeof(state));
  assert(wcsrtombs(transformed, &wide_source, sizeof(transformed), &state) ==
         3U);
  assert(strcmp(transformed, "C99") == 0);
  puts("C99-CHAR-STRING-WIDE-PASS");
}

static void test_conversion_and_allocation(void) {
  int values[] = {9, -4, 11, 2};
  int key = 9;
  char *end;
  unsigned char *block;
  div_t quotient;
  volatile size_t impossible = SIZE_MAX;
  int first_random;
  void *fragments[64];

  errno = 0;
  assert(strtoll("-7fffffffffffffff", &end, 16) ==
         -9223372036854775807LL);
  assert(*end == '\0' && errno == 0);
  assert(strtoumax("ff", &end, 16) == UINTMAX_C(255) && *end == '\0');
  assert(fabs(strtod("0x1.8p+2", &end) - 6.0) < 1e-12 && *end == '\0');
  quotient = div(17, 5);
  assert(quotient.quot == 3 && quotient.rem == 2);

  block = calloc(32U, 4U);
  assert(block != NULL && block[0] == 0U && block[127] == 0U);
  block = realloc(block, 512U);
  assert(block != NULL);
  assert(block[0] == 0U && block[127] == 0U);
  memset(block, 0xa5, 512U);
  free(block);
  errno = 0;
  assert(calloc(impossible, 2U) == NULL);

  for (size_t index = 0; index < 64U; ++index) {
    fragments[index] = malloc(17U + index * 13U);
    assert(fragments[index] != NULL);
    memset(fragments[index], (int)index, 17U + index * 13U);
  }
  for (size_t index = 0; index < 64U; index += 2U) {
    free(fragments[index]);
    fragments[index] = NULL;
  }
  for (size_t index = 0; index < 64U; index += 2U) {
    fragments[index] = calloc(1U, 23U + index * 7U);
    assert(fragments[index] != NULL);
  }
  for (size_t index = 0; index < 64U; ++index) {
    free(fragments[index]);
  }

  qsort(values, 4U, sizeof(values[0]), integer_compare);
  assert(values[0] == -4 && values[3] == 11);
  assert(*(int *)bsearch(&key, values, 4U, sizeof(values[0]),
                         integer_compare) == 9);
  srand(123U);
  first_random = rand();
  srand(123U);
  assert(rand() == first_random);
  assert(system(NULL) == 0);
  assert(system("not-an-xaios-command") == -1 && errno == ENOSYS);
  puts("C99-CONVERSION-ALLOCATION-PASS");
}

static void test_locale_and_time(void) {
  struct tm value;
  struct tm *round_trip;
  char formatted[64];
  time_t timestamp;
  struct lconv *conventions;

  assert(setlocale(LC_ALL, "C") != NULL);
  conventions = localeconv();
  assert(conventions != NULL && strcmp(conventions->decimal_point, ".") == 0);
  memset(&value, 0, sizeof(value));
  value.tm_year = 100;
  value.tm_mon = 0;
  value.tm_mday = 2;
  value.tm_hour = 3;
  value.tm_min = 4;
  value.tm_sec = 5;
  value.tm_isdst = -1;
  timestamp = mktime(&value);
  assert(timestamp != (time_t)-1);
  round_trip = gmtime(&timestamp);
  assert(round_trip != NULL && round_trip->tm_year == 100 &&
         round_trip->tm_mon == 0 && round_trip->tm_mday == 2);
  assert(strftime(formatted, sizeof(formatted), "%Y-%m-%d %H:%M:%S",
                  round_trip) == 19U);
  assert(strcmp(formatted, "2000-01-02 03:04:05") == 0);
  assert(difftime(timestamp + 3, timestamp) == 3.0);
  puts("C99-LOCALE-TIME-PASS");
}

static void test_stdio(void) {
  char buffer[128];
  char word[16];
  int integer = 0;
  double real = 0.0;
  fpos_t position;
  wchar_t wide_buffer[16];
  int written = -1;
  FILE *file = tmpfile();
  assert(file != NULL);
  assert(setvbuf(file, buffer, _IOFBF, sizeof(buffer)) == 0);
  assert(fprintf(file, "%s %d %a", "value", 42, 1.5) > 0);
  assert(fflush(file) == 0);
  assert(fgetpos(file, &position) == 0);
  rewind(file);
  assert(fscanf(file, "%15s %d %la", word, &integer, &real) == 3);
  assert(strcmp(word, "value") == 0 && integer == 42 &&
         fabs(real - 1.5) < 1e-12);
  assert(ungetc('X', file) == 'X' && fgetc(file) == 'X');
  assert(fsetpos(file, &position) == 0);
  assert(feof(file) == 0 && ferror(file) == 0);
  clearerr(file);
  assert(fclose(file) == 0);

  assert(snprintf(buffer, sizeof(buffer), "%#x %.2f %lld", 42, 1.25,
                  1234567890123LL) > 0);
  assert(strcmp(buffer, "0x2a 1.25 1234567890123") == 0);
  assert(sscanf("77 0x1.4p+1", "%d %la", &integer, &real) == 2);
  assert(integer == 77 && fabs(real - 2.5) < 1e-12);
  assert(snprintf(buffer, sizeof(buffer), "%hhd %zu %td%n", (signed char)-7,
                  (size_t)99U, (ptrdiff_t)-3, &written) > 0);
  assert(written > 0 && strcmp(buffer, "-7 99 -3") == 0);

  file = tmpfile();
  assert(file != NULL);
  assert(fwide(file, 1) > 0);
  assert(fwprintf(file, L"%ls %d", L"wide", 9) > 0);
  assert(fflush(file) == 0);
  rewind(file);
  assert(fwscanf(file, L"%15ls %d", wide_buffer, &integer) == 2);
  assert(wcscmp(wide_buffer, L"wide") == 0 && integer == 9);
  assert(fclose(file) == 0);
  puts("C99-STDIO-PASS");
}

static void test_math_complex_and_fenv(void) {
  double complex z = csqrt(-1.0);
  fenv_t environment;
  double generic = sqrt(81.0);

  assert(fabs(sin(0.5) * sin(0.5) + cos(0.5) * cos(0.5) - 1.0) <
         1e-12);
  assert(fabs(exp(log(7.0)) - 7.0) < 1e-12);
  assert(fabs(pow(2.0, 10.0) - 1024.0) < 1e-12);
  assert(fabs(tgamma(6.0) - 120.0) < 1e-10);
  assert(generic == 9.0);
  assert(fabs(cimag(z) - 1.0) < 1e-12 && fabs(creal(z)) < 1e-12);
  assert(cabs(cexp(clog(z)) - z) < 1e-11);
  assert(isnan(nan("xaios")) && isinf(HUGE_VAL));

  assert(fegetenv(&environment) == 0);
  assert(feclearexcept(FE_ALL_EXCEPT) == 0);
  assert(feraiseexcept(FE_INVALID) == 0);
  assert((fetestexcept(FE_INVALID) & FE_INVALID) != 0);
  assert(fesetround(FE_DOWNWARD) == 0 && fegetround() == FE_DOWNWARD);
  assert(fesetenv(&environment) == 0);
  puts("C99-MATH-COMPLEX-FENV-PASS");
}

int xaios_c99_conformance_suite(void) {
  assert(xaios_c99_language_conformance() == 0);
  test_types_and_macros();
  test_character_and_strings();
  test_conversion_and_allocation();
  test_locale_and_time();
  test_stdio();
  test_math_complex_and_fenv();
  puts("C99-CONFORMANCE-SUITE-PASS");
  return 0;
}
