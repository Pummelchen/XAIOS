#include <xaios_user.h>

static int text_equal(const char *lhs, const char *rhs) {
  if (lhs == 0 || rhs == 0) {
    return 0;
  }
  for (u64 i = 0;; ++i) {
    if (lhs[i] != rhs[i]) {
      return 0;
    }
    if (lhs[i] == '\0') {
      return 1;
    }
  }
}

int main(void) {
  char output[96];
  u64 out = 0;
  const unsigned char xor_input[2] = {1, 0};
  const unsigned char sum_input[4] = {1, 2, 3, 4};
  const unsigned char parity_input[3] = {1, 1, 1};

  xaios_log("/bin/mltest: validating general CPU-only ML runtime dispatcher\n");
  xaios_memzero(output, sizeof(output));
  if (xaios_ml_run(XAIOS_ML_MODEL_XOR, xor_input, sizeof(xor_input), output,
                  sizeof(output), &out) < 0 ||
      !text_equal(output, "1")) {
    xaios_log("/bin/mltest: xor model failed\n");
    return 1;
  }
  xaios_log("/bin/mltest: xor output=");
  xaios_log(output);
  xaios_log("\n");

  xaios_memzero(output, sizeof(output));
  if (xaios_ml_run(XAIOS_ML_MODEL_SUM, sum_input, sizeof(sum_input), output,
                  sizeof(output), &out) < 0 ||
      !text_equal(output, "10")) {
    xaios_log("/bin/mltest: sum model failed\n");
    return 1;
  }
  xaios_log("/bin/mltest: sum output=");
  xaios_log(output);
  xaios_log("\n");

  xaios_memzero(output, sizeof(output));
  if (xaios_ml_run(XAIOS_ML_MODEL_PARITY, parity_input, sizeof(parity_input),
                  output, sizeof(output), &out) < 0 ||
      !text_equal(output, "odd")) {
    xaios_log("/bin/mltest: parity model failed\n");
    return 1;
  }
  xaios_log("/bin/mltest: parity output=");
  xaios_log(output);
  xaios_log("\n");

  /* Q8.8 matmul test: I_2x2 * I_2x2 = I_2x2 */
  xaios_memzero(output, sizeof(output));
  {
    unsigned char mm[28];
    mm[0] = 2; mm[1] = 2; mm[2] = 2;
    for (u64 i = 3; i < 12; ++i) { mm[i] = 0; }
    /* Two Q8.8 identity matrices: 256=1.0. */
    short *ma = (short *)&mm[12];
    ma[0] = 256; ma[1] = 0; ma[2] = 0; ma[3] = 256;
    ma[4] = 256; ma[5] = 0; ma[6] = 0; ma[7] = 256;
    if (xaios_ml_run(XAIOS_ML_MODEL_MATMUL, mm, sizeof(mm), output,
                    sizeof(output), &out) < 0) {
      xaios_log("/bin/mltest: matmul model failed\n");
      return 1;
    }
    short *mr = (short *)output;
    if (mr[0] != 256 || mr[1] != 0 || mr[2] != 0 || mr[3] != 256) {
      xaios_log("/bin/mltest: matmul result mismatch\n");
      return 1;
    }
  }
  xaios_log("/bin/mltest: matmul I*I=I passed\n");

  xaios_log("/bin/mltest: multi-model CPU-only ML runtime passed\n");
  xaios_log("/bin/mltest: complete\n");
  return 0;
}
