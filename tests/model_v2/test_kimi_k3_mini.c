#include <xaios_engine/kimi_k3_mini.h>

#include <math.h>
#include <stdio.h>
#include <string.h>

static int close_enough(float actual, float expected) {
  return fabsf(actual - expected) <= 1.0e-5f;
}

int main(void) {
  float state[4] = {0};
  float output[2];
  const float decay[2] = {1.0f, 1.0f};
  const float q[2] = {1.0f, 0.0f};
  const float k[2] = {1.0f, 0.0f};
  const float first_value[2] = {2.0f, -1.0f};
  const float second_value[2] = {4.0f, 3.0f};
  if (xaios_k3_mini_kda_step(q, k, first_value, decay, 1.0f, 2U, 2U,
                              state, output) != XAIOS_ENGINE_OK ||
      !close_enough(output[0], 1.41421356f) ||
      !close_enough(output[1], -0.70710678f) ||
      xaios_k3_mini_kda_step(q, k, second_value, decay, 0.5f, 2U, 2U,
                              state, output) != XAIOS_ENGINE_OK ||
      !close_enough(output[0], 2.12132034f) ||
      !close_enough(output[1], 0.70710678f)) {
    return 1;
  }

  float key_cache[4] = {0};
  float value_cache[4] = {0};
  float scores[2];
  uint64_t cache_length = 0U;
  const float mla_key_a[2] = {1.0f, 0.0f};
  const float mla_key_b[2] = {0.0f, 1.0f};
  const float mla_value_a[2] = {2.0f, 4.0f};
  const float mla_value_b[2] = {6.0f, 0.0f};
  if (xaios_k3_mini_mla_step(q, mla_key_a, mla_value_a, 0.5f, 2U, 2U,
                              key_cache, value_cache, 2U, &cache_length,
                              output, scores) != XAIOS_ENGINE_OK ||
      output[0] != 1.0f || output[1] != 2.0f ||
      xaios_k3_mini_mla_step(q, mla_key_b, mla_value_b, 1.0f, 2U, 2U,
                              key_cache, value_cache, 2U, &cache_length,
                              output, scores) != XAIOS_ENGINE_OK ||
      !close_enough(output[0], 3.3209538f) ||
      !close_enough(output[1], 2.6790462f)) {
    return 1;
  }
  float invalid_key[2] = {NAN, 0.0f};
  if (xaios_k3_mini_mla_step(q, invalid_key, mla_value_b, 1.0f, 2U, 2U,
                              key_cache, value_cache, 3U, &cache_length,
                              output, scores) != XAIOS_ENGINE_ERR_INVALID ||
      cache_length != 2U) {
    return 1;
  }

  float logits[20];
  float correction[20] = {0};
  float router_scores[20];
  uint64_t expert_ids[16];
  float expert_weights[16];
  for (uint64_t expert = 0U; expert < 20U; ++expert) {
    logits[expert] = (float)expert / 10.0f;
  }
  correction[0] = 2.0f;
  if (xaios_k3_mini_route_topk(logits, correction, 20U, 16U, 1.0f,
                                expert_ids, expert_weights,
                                router_scores) != XAIOS_ENGINE_OK ||
      expert_ids[0] != 0U) {
    return 1;
  }
  float weight_sum = 0.0f;
  for (uint64_t selected = 0U; selected < 16U; ++selected) {
    weight_sum += expert_weights[selected];
    for (uint64_t prior = 0U; prior < selected; ++prior) {
      if (expert_ids[prior] == expert_ids[selected]) return 1;
    }
  }
  if (!close_enough(weight_sum, 1.0f)) return 1;

  float expert_outputs[40];
  for (uint64_t expert = 0U; expert < 20U; ++expert) {
    expert_outputs[expert * 2U] = (float)expert;
    expert_outputs[expert * 2U + 1U] = -(float)expert;
  }
  const float shared[2] = {10.0f, 20.0f};
  float expected_routed = 0.0f;
  for (uint64_t selected = 0U; selected < 16U; ++selected) {
    expected_routed += expert_weights[selected] * (float)expert_ids[selected];
  }
  if (xaios_k3_mini_reduce_experts(expert_outputs, expert_ids,
                                    expert_weights, 16U, 20U, 2U, shared,
                                    output) != XAIOS_ENGINE_OK ||
      !close_enough(output[0], 10.0f + expected_routed) ||
      !close_enough(output[1], 20.0f - expected_routed)) {
    return 1;
  }
  expert_ids[0] = 20U;
  if (xaios_k3_mini_reduce_experts(expert_outputs, expert_ids,
                                    expert_weights, 16U, 20U, 2U, shared,
                                    output) != XAIOS_ENGINE_ERR_INVALID) {
    return 1;
  }

  const float situ_gate[2] = {0.0f, 4.0f};
  const float situ_up[2] = {3.0f, 25.0f};
  if (xaios_k3_mini_situ(situ_gate, situ_up, 2U, 4.0f, 25.0f, output) !=
          XAIOS_ENGINE_OK ||
      output[0] != 0.0f || !close_enough(output[1], 56.959320f)) {
    return 1;
  }

  uint8_t packed[16];
  memset(packed, UINT8_C(0x21), sizeof(packed));
  float dequantized[32];
  if (xaios_k3_mini_mxfp4_dequantize(packed, 128U, dequantized) !=
          XAIOS_ENGINE_OK ||
      dequantized[0] != 1.0f || dequantized[1] != 2.0f ||
      xaios_k3_mini_mxfp4_dequantize(packed, UINT8_C(0xff), dequantized) !=
          XAIOS_ENGINE_ERR_INVALID) {
    return 1;
  }

  puts("Kimi K3 miniature: KDA, gated MLA, exact top-16 routing, shared-expert reduction, SiTU, and MXFP4 golden tests passed");
  return 0;
}
