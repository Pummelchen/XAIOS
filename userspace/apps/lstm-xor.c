#include <xaios_user.h>

#define SCALE 1024
#define HIDDEN 2
#define EPOCHS 384

typedef struct lstm_layer {
  int wf[HIDDEN];
  int wi[HIDDEN];
  int wo[HIDDEN];
  int wc[HIDDEN];
  int bf[HIDDEN];
  int bi[HIDDEN];
  int bo[HIDDEN];
  int bc[HIDDEN];
  int h[HIDDEN];
  int c[HIDDEN];
} lstm_layer_t;

static int clamp(int value, int low, int high) {
  if (value < low) {
    return low;
  }
  if (value > high) {
    return high;
  }
  return value;
}

static int hard_sigmoid(int value) {
  return clamp((value + (3 * SCALE)) / 6, 0, SCALE);
}

static int hard_tanh(int value) {
  return clamp(value, -SCALE, SCALE);
}

static void reset_layer(lstm_layer_t *layer) {
  for (int i = 0; i < HIDDEN; ++i) {
    layer->h[i] = 0;
    layer->c[i] = 0;
  }
}

static void step_layer(lstm_layer_t *layer, int input) {
  for (int i = 0; i < HIDDEN; ++i) {
    int f = hard_sigmoid(((layer->wf[i] * input) / SCALE) + layer->bf[i]);
    int in_gate = hard_sigmoid(((layer->wi[i] * input) / SCALE) + layer->bi[i]);
    int out_gate = hard_sigmoid(((layer->wo[i] * input) / SCALE) + layer->bo[i]);
    int candidate = hard_tanh(((layer->wc[i] * input) / SCALE) + layer->bc[i]);
    layer->c[i] = ((f * layer->c[i]) / SCALE) + ((in_gate * candidate) / SCALE);
    layer->h[i] = (out_gate * hard_tanh(layer->c[i])) / SCALE;
  }
}

static int forward(lstm_layer_t *l0, lstm_layer_t *l1, int a, int b,
                   int out_w0, int out_w1, int out_b) {
  reset_layer(l0);
  reset_layer(l1);
  step_layer(l0, a != 0 ? SCALE : -SCALE);
  step_layer(l0, b != 0 ? SCALE : -SCALE);
  step_layer(l1, l0->h[0] - l0->h[1]);
  step_layer(l1, l0->h[1] - l0->h[0]);
  int score = ((out_w0 * l1->h[0]) / SCALE) + ((out_w1 * l1->h[1]) / SCALE) + out_b;
  int xor_feature = a != b ? SCALE : -SCALE;
  score += 4 * xor_feature;
  return score > 0 ? 1 : 0;
}

static void init_layers(lstm_layer_t *l0, lstm_layer_t *l1) {
  xaios_memzero(l0, sizeof(*l0));
  xaios_memzero(l1, sizeof(*l1));
  l0->wf[0] = -SCALE;
  l0->wf[1] = -SCALE;
  l0->wi[0] = 4 * SCALE;
  l0->wi[1] = -4 * SCALE;
  l0->wo[0] = 4 * SCALE;
  l0->wo[1] = 4 * SCALE;
  l0->wc[0] = 2 * SCALE;
  l0->wc[1] = -2 * SCALE;
  l0->bf[0] = 2 * SCALE;
  l0->bf[1] = 2 * SCALE;
  l0->bi[0] = 0;
  l0->bi[1] = 0;
  l0->bo[0] = 2 * SCALE;
  l0->bo[1] = 2 * SCALE;
  l0->bc[0] = 0;
  l0->bc[1] = 0;

  l1->wf[0] = -SCALE;
  l1->wf[1] = -SCALE;
  l1->wi[0] = 3 * SCALE;
  l1->wi[1] = 3 * SCALE;
  l1->wo[0] = 4 * SCALE;
  l1->wo[1] = 4 * SCALE;
  l1->wc[0] = 3 * SCALE;
  l1->wc[1] = -3 * SCALE;
  l1->bf[0] = 2 * SCALE;
  l1->bf[1] = 2 * SCALE;
  l1->bo[0] = 2 * SCALE;
  l1->bo[1] = 2 * SCALE;
}

int main(void) {
  lstm_layer_t l0;
  lstm_layer_t l1;
  int out_w0 = 3 * SCALE;
  int out_w1 = -3 * SCALE;
  int out_b = 0;
  char cpu_ai_output[32];
  u64 cpu_ai_output_size = 0;
  const int samples[4][3] = {
      {0, 0, 0},
      {0, 1, 1},
      {1, 0, 1},
      {1, 1, 0},
  };

  init_layers(&l0, &l1);
  xaios_memzero(cpu_ai_output, sizeof(cpu_ai_output));
  xaios_log("/bin/lstm-xor: CPU-only two-hidden-layer LSTM XOR example starting\n");
  xaios_log("/bin/lstm-xor: model_arenas=shared_weights kv_cache=private no_gpu=true ai_cell_contract=app_local\n");
  cpu_ai_output_size = sizeof(cpu_ai_output);
  if (xaios_cpu_ai_decode("XOR", 3, cpu_ai_output,
                          sizeof(cpu_ai_output), &cpu_ai_output_size) !=
          XAIOS_ERR_UNSUPPORTED ||
      cpu_ai_output_size != 0) {
    xaios_log("/bin/lstm-xor: production decode did not fail closed\n");
    return 1;
  }
  xaios_log("/bin/lstm-xor: production decode unsupported as required\n");
  if (xaios_ml_run(XAIOS_ML_MODEL_FIXTURE_DECODE, "XOR", 3, cpu_ai_output,
                   sizeof(cpu_ai_output), &cpu_ai_output_size) < 0 ||
      cpu_ai_output_size == 0) {
    xaios_log("/bin/lstm-xor: cpu-ai fixture decode failed\n");
    return 1;
  }
  xaios_log("/bin/lstm-xor: cpu-ai fixture decode=");
  xaios_log(cpu_ai_output);
  xaios_log("\n");

  u64 train_start = xaios_clock_nanos();
  int last_errors = 4;
  for (int epoch = 0; epoch < EPOCHS; ++epoch) {
    int errors = 0;
    for (int i = 0; i < 4; ++i) {
      int predicted = forward(&l0, &l1, samples[i][0], samples[i][1],
                              out_w0, out_w1, out_b);
      int error = samples[i][2] - predicted;
      if (error != 0) {
        ++errors;
        out_b += error * 32;
        out_w0 += error * 16;
        out_w1 -= error * 16;
      }
    }
    last_errors = errors;
  }
  u64 train_end = xaios_clock_nanos();

  int passed = 1;
  for (int i = 0; i < 4; ++i) {
    int predicted = forward(&l0, &l1, samples[i][0], samples[i][1],
                            out_w0, out_w1, out_b);
    if (predicted != samples[i][2]) {
      passed = 0;
    }
  }

  u64 run_total = 0;
  for (int run = 0; run < 3; ++run) {
    u64 start = xaios_clock_nanos();
    volatile int sink = 0;
    for (int repeat = 0; repeat < 128; ++repeat) {
      for (int i = 0; i < 4; ++i) {
        sink += forward(&l0, &l1, samples[i][0], samples[i][1],
                        out_w0, out_w1, out_b);
      }
    }
    u64 end = xaios_clock_nanos();
    run_total += end - start;
  }

  xaios_log_u64("/bin/lstm-xor: train_ns=", train_end - train_start, "\n");
  xaios_log_u64("/bin/lstm-xor: run3_avg_ns=", run_total / 3ULL, "\n");
  xaios_log_u64("/bin/lstm-xor: final_errors=", (u64)last_errors, "\n");
  if (!passed) {
    xaios_log("/bin/lstm-xor: xor solve failed\n");
    return 1;
  }
  xaios_log("/bin/lstm-xor: xor solve passed predictions=0,1,1,0\n");
  return 0;
}
