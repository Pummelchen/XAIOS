#include <xaios_engine/kimi_k3_mini.h>

#include <math.h>
#include <stddef.h>
#include <string.h>

static float dot(const float *left, const float *right, uint64_t count) {
  float value = 0.0f;
  for (uint64_t i = 0U; i < count; ++i) value += left[i] * right[i];
  return value;
}

static xaios_engine_status_t normalized_copy(const float *input,
                                              uint64_t count, float *output) {
  float square_sum = dot(input, input, count);
  if (!(square_sum > 0.0f) || !isfinite(square_sum)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  float inverse_norm = 1.0f / sqrtf(square_sum);
  for (uint64_t i = 0U; i < count; ++i) output[i] = input[i] * inverse_norm;
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_k3_mini_kda_step(
    const float *query, const float *key, const float *value,
    const float *decay, float beta, uint64_t key_dimension,
    uint64_t value_dimension, float *state, float *output) {
  if (query == NULL || key == NULL || value == NULL || decay == NULL ||
      state == NULL || output == NULL || key_dimension == 0U ||
      value_dimension == 0U || key_dimension > 64U || beta < 0.0f ||
      beta > 1.0f || !isfinite(beta) ||
      value_dimension > SIZE_MAX / sizeof(*state) / key_dimension) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  float normalized_query[64];
  float normalized_key[64];
  for (uint64_t row = 0U; row < key_dimension; ++row) {
    if (!isfinite(decay[row])) return XAIOS_ENGINE_ERR_INVALID;
  }
  for (uint64_t column = 0U; column < value_dimension; ++column) {
    if (!isfinite(value[column])) return XAIOS_ENGINE_ERR_INVALID;
  }
  if (normalized_copy(query, key_dimension, normalized_query) !=
          XAIOS_ENGINE_OK ||
      normalized_copy(key, key_dimension, normalized_key) != XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  for (uint64_t row = 0U; row < key_dimension; ++row) {
    if (decay[row] < 0.0f || decay[row] > 1.0f) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
    for (uint64_t column = 0U; column < value_dimension; ++column) {
      state[row * value_dimension + column] *= decay[row];
    }
  }
  for (uint64_t column = 0U; column < value_dimension; ++column) {
    float predicted = 0.0f;
    for (uint64_t row = 0U; row < key_dimension; ++row) {
      predicted += normalized_key[row] *
                   state[row * value_dimension + column];
    }
    float delta = beta * (value[column] - predicted);
    for (uint64_t row = 0U; row < key_dimension; ++row) {
      state[row * value_dimension + column] += normalized_key[row] * delta;
    }
  }
  float scale = 1.0f / sqrtf((float)key_dimension);
  for (uint64_t column = 0U; column < value_dimension; ++column) {
    output[column] = 0.0f;
    for (uint64_t row = 0U; row < key_dimension; ++row) {
      output[column] += normalized_query[row] *
                        state[row * value_dimension + column];
    }
    output[column] *= scale;
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_k3_mini_mla_step(
    const float *query, const float *key, const float *value, float output_gate,
    uint64_t key_dimension, uint64_t value_dimension, float *key_cache,
    float *value_cache, uint64_t cache_capacity, uint64_t *cache_length,
    float *output, float *score_scratch) {
  if (query == NULL || key == NULL || value == NULL || key_cache == NULL ||
      value_cache == NULL || cache_length == NULL || output == NULL ||
      score_scratch == NULL || key_dimension == 0U || value_dimension == 0U ||
      cache_capacity == 0U || *cache_length >= cache_capacity ||
      output_gate < 0.0f || output_gate > 1.0f || !isfinite(output_gate) ||
      cache_capacity > SIZE_MAX / sizeof(*key_cache) / key_dimension ||
      cache_capacity > SIZE_MAX / sizeof(*value_cache) / value_dimension) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  uint64_t position = *cache_length;
  for (uint64_t column = 0U; column < key_dimension; ++column) {
    if (!isfinite(query[column]) || !isfinite(key[column])) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
  }
  for (uint64_t column = 0U; column < value_dimension; ++column) {
    if (!isfinite(value[column])) return XAIOS_ENGINE_ERR_INVALID;
  }
  memcpy(key_cache + position * key_dimension, key,
         (size_t)key_dimension * sizeof(*key));
  memcpy(value_cache + position * value_dimension, value,
         (size_t)value_dimension * sizeof(*value));
  *cache_length = position + 1U;

  float scale = 1.0f / sqrtf((float)key_dimension);
  float maximum = -INFINITY;
  for (uint64_t token = 0U; token < *cache_length; ++token) {
    float score = dot(query, key_cache + token * key_dimension,
                      key_dimension) * scale;
    score_scratch[token] = score;
    if (score > maximum) maximum = score;
  }
  float denominator = 0.0f;
  for (uint64_t token = 0U; token < *cache_length; ++token) {
    score_scratch[token] = expf(score_scratch[token] - maximum);
    denominator += score_scratch[token];
  }
  if (!(denominator > 0.0f) || !isfinite(denominator)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  memset(output, 0, (size_t)value_dimension * sizeof(*output));
  for (uint64_t token = 0U; token < *cache_length; ++token) {
    float probability = score_scratch[token] / denominator;
    for (uint64_t column = 0U; column < value_dimension; ++column) {
      output[column] += probability *
                        value_cache[token * value_dimension + column];
    }
  }
  for (uint64_t column = 0U; column < value_dimension; ++column) {
    output[column] *= output_gate;
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_k3_mini_route_topk(
    const float *logits, const float *correction_bias, uint64_t expert_count,
    uint64_t top_k, float routed_scaling_factor, uint64_t *expert_ids,
    float *expert_weights, float *score_scratch) {
  if (logits == NULL || correction_bias == NULL || expert_ids == NULL ||
      expert_weights == NULL || score_scratch == NULL || expert_count == 0U ||
      top_k == 0U || top_k > expert_count || routed_scaling_factor <= 0.0f ||
      !isfinite(routed_scaling_factor)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  for (uint64_t expert = 0U; expert < expert_count; ++expert) {
    if (!isfinite(logits[expert]) || !isfinite(correction_bias[expert])) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
    score_scratch[expert] = 1.0f / (1.0f + expf(-logits[expert]));
  }
  for (uint64_t selected = 0U; selected < top_k; ++selected) {
    uint64_t best = UINT64_MAX;
    float best_choice = -INFINITY;
    for (uint64_t expert = 0U; expert < expert_count; ++expert) {
      int already_selected = 0;
      for (uint64_t prior = 0U; prior < selected; ++prior) {
        if (expert_ids[prior] == expert) already_selected = 1;
      }
      float choice = score_scratch[expert] + correction_bias[expert];
      if (!already_selected &&
          (best == UINT64_MAX || choice > best_choice ||
           (choice == best_choice && expert < best))) {
        best = expert;
        best_choice = choice;
      }
    }
    if (best == UINT64_MAX) return XAIOS_ENGINE_ERR_INVALID;
    expert_ids[selected] = best;
    expert_weights[selected] = score_scratch[best];
  }
  float denominator = 0.0f;
  for (uint64_t selected = 0U; selected < top_k; ++selected) {
    denominator += expert_weights[selected];
  }
  if (!(denominator > 0.0f)) return XAIOS_ENGINE_ERR_INVALID;
  for (uint64_t selected = 0U; selected < top_k; ++selected) {
    expert_weights[selected] =
        expert_weights[selected] / denominator * routed_scaling_factor;
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_k3_mini_reduce_experts(
    const float *expert_outputs, const uint64_t *expert_ids,
    const float *expert_weights, uint64_t selected_count,
    uint64_t expert_count, uint64_t expert_stride, const float *shared_output,
    float *output) {
  if (expert_outputs == NULL || expert_ids == NULL || expert_weights == NULL ||
      selected_count == 0U || expert_count == 0U || expert_stride == 0U ||
      expert_count > SIZE_MAX / sizeof(*expert_outputs) / expert_stride ||
      shared_output == NULL || output == NULL) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  for (uint64_t expert = 0U; expert < selected_count; ++expert) {
    if (expert_ids[expert] >= expert_count ||
        !isfinite(expert_weights[expert])) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
  }
  memcpy(output, shared_output, (size_t)expert_stride * sizeof(*output));
  for (uint64_t expert = 0U; expert < selected_count; ++expert) {
    const float *partial = expert_outputs + expert_ids[expert] * expert_stride;
    for (uint64_t column = 0U; column < expert_stride; ++column) {
      output[column] += expert_weights[expert] * partial[column];
    }
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_k3_mini_situ(
    const float *gate, const float *up, uint64_t count, float beta,
    float linear_beta, float *output) {
  if (gate == NULL || up == NULL || output == NULL || count == 0U ||
      beta <= 0.0f || linear_beta <= 0.0f || !isfinite(beta) ||
      !isfinite(linear_beta)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  for (uint64_t i = 0U; i < count; ++i) {
    float situ = beta * tanhf(gate[i] / beta) /
                 (1.0f + expf(-gate[i]));
    float linear = linear_beta * tanhf(up[i] / linear_beta);
    output[i] = situ * linear;
  }
  return XAIOS_ENGINE_OK;
}

static float e2m1_value(uint8_t value) {
  static const float positive[8] = {0.0f, 0.5f, 1.0f, 1.5f,
                                    2.0f, 3.0f, 4.0f, 6.0f};
  float result = positive[value & UINT8_C(7)];
  return (value & UINT8_C(8)) != 0U ? -result : result;
}

xaios_engine_status_t xaios_k3_mini_mxfp4_dequantize(
    const uint8_t packed[XAIOS_K3_MINI_MXFP4_BLOCK_VALUES / 2U],
    uint8_t e8m0_scale,
    float output[XAIOS_K3_MINI_MXFP4_BLOCK_VALUES]) {
  if (packed == NULL || output == NULL || e8m0_scale == UINT8_C(0xff)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  float scale = ldexpf(1.0f, (int)e8m0_scale - 127);
  for (uint32_t byte = 0U; byte < XAIOS_K3_MINI_MXFP4_BLOCK_VALUES / 2U;
       ++byte) {
    output[byte * 2U] = e2m1_value(packed[byte] & UINT8_C(0x0f)) * scale;
    output[byte * 2U + 1U] = e2m1_value(packed[byte] >> 4U) * scale;
  }
  return XAIOS_ENGINE_OK;
}
