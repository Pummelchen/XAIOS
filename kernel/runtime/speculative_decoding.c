#include <xaios/assert.h>
#include <xaios/cpu_ai_runtime.h>
#include <xaios/klog.h>
#include <xaios/speculative_decoding.h>

/* Janeway — “Now, this is how I prefer the Borg: in pieces.” */

/*
 * Speculative Decoding Implementation
 *
 * Draft model generates candidates, target model verifies.
 * Achieves 2-3× speedup when acceptance rate is high (>60%).
 */

static void bytes_zero(void *buffer, uint64_t size) {
  uint8_t *bytes = (uint8_t *)buffer;
  for (uint64_t i = 0; i < size; ++i) {
    bytes[i] = 0;
  }
}

/* Extract token ID from model output buffer.
 * Reads up to 4 bytes as little-endian uint32_t, which is the
 * standard representation for BPE token IDs in the inference runtime.
 * Single-byte ASCII tokens are correctly handled (upper bytes = 0). */
static uint32_t extract_token_id(const char *output, uint64_t output_bytes) {
  uint32_t token = 0;
  uint64_t read_bytes = output_bytes < 4 ? output_bytes : 4;
  for (uint64_t i = 0; i < read_bytes; ++i) {
    token |= (uint32_t)(uint8_t)output[i] << (i * 8);
  }
  return token;
}

xaios_status_t speculative_decoding_init(xaios_speculative_state_t *state,
                                         uint32_t draft_cell_id,
                                         uint32_t target_cell_id) {
  kassert(state != 0 && draft_cell_id != target_cell_id);
  
  state->draft_cell_id = draft_cell_id;
  state->target_cell_id = target_cell_id;
  state->num_draft_tokens = 0;
  state->num_verified_tokens = 0;
  state->num_accepted_tokens = 0;
  
  state->total_speculations = 0;
  state->total_accepted = 0;
  state->total_rejected = 0;
  state->avg_acceptance_rate = 0;
  state->speedup_factor = 0;
  
  bytes_zero(state->draft_tokens, sizeof(state->draft_tokens));
  bytes_zero(state->verified_tokens, sizeof(state->verified_tokens));
  
  klog("speculative-decoding: initialized draft_cell=%u target_cell=%u\n",
       draft_cell_id, target_cell_id);
  
  return XAIOS_OK;
}

xaios_status_t speculative_generate_draft(
    xaios_speculative_state_t *state,
    const uint8_t *context,
    uint32_t context_length,
    uint32_t num_draft_tokens) {
  kassert(state != 0 && context != 0);
  kassert(num_draft_tokens > 0 && num_draft_tokens <= XAIOS_SPEC_MAX_DRAFT_TOKENS);
  
  /* Generate tokens one at a time with draft model (fast) */
  uint8_t input_buffer[256];
  char output_buffer[64];
  uint64_t output_bytes = 0;
  
  for (uint32_t i = 0; i < num_draft_tokens; ++i) {
    /* Prepare input: context + previously generated draft tokens */
    uint32_t input_size = context_length + i;
    if (input_size > sizeof(input_buffer)) {
      break; /* Context too long */
    }
    
    /* Copy context */
    for (uint32_t j = 0; j < context_length; ++j) {
      input_buffer[j] = context[j];
    }
    
    /* Append draft tokens */
    for (uint32_t j = 0; j < i; ++j) {
      input_buffer[context_length + j] = (uint8_t)state->draft_tokens[j];
    }
    
    /* Run draft model */
    xaios_status_t status = cpu_ai_runtime_run_model(
        state->draft_cell_id,
        XAIOS_ML_MODEL_FIXTURE_DECODE,
        input_buffer,
        input_size,
        output_buffer,
        sizeof(output_buffer),
        &output_bytes);
    
    if (status != XAIOS_OK || output_bytes == 0) {
      klog("speculative-decoding: draft generation failed at token %u\n", i);
      state->num_draft_tokens = i;
      return XAIOS_ERR_INVALID;
    }
    
    /* Extract full token ID from model output (supports multi-byte BPE tokens) */
    state->draft_tokens[i] = extract_token_id(output_buffer, output_bytes);
  }
  
  state->num_draft_tokens = num_draft_tokens;
  
  klog("speculative-decoding: generated %u draft tokens\n", num_draft_tokens);
  return XAIOS_OK;
}

xaios_status_t speculative_verify_tokens(
    xaios_speculative_state_t *state,
    const uint8_t *context,
    uint32_t context_length) {
  kassert(state != 0 && context != 0);
  
  if (state->num_draft_tokens == 0) {
    return XAIOS_OK; /* Nothing to verify */
  }
  
  /* Verify all draft tokens in parallel with target model */
  /* For simplicity, verify one at a time (production would batch) */
  uint8_t input_buffer[256];
  char output_buffer[64];
  uint64_t output_bytes = 0;
  uint32_t accepted = 0;
  
  for (uint32_t i = 0; i < state->num_draft_tokens; ++i) {
    /* Prepare input: context + all draft tokens up to this point */
    uint32_t input_size = context_length + i;
    if (input_size > sizeof(input_buffer)) {
      break;
    }
    
    for (uint32_t j = 0; j < context_length; ++j) {
      input_buffer[j] = context[j];
    }
    
    for (uint32_t j = 0; j < i; ++j) {
      input_buffer[context_length + j] = (uint8_t)state->draft_tokens[j];
    }
    
    /* Run target model */
    xaios_status_t status = cpu_ai_runtime_run_model(
        state->target_cell_id,
        XAIOS_ML_MODEL_FIXTURE_DECODE,
        input_buffer,
        input_size,
        output_buffer,
        sizeof(output_buffer),
        &output_bytes);
    
    if (status != XAIOS_OK || output_bytes == 0) {
      klog("speculative-decoding: target verification failed at token %u\n", i);
      break;
    }
    
    /* Extract full token ID from target model output */
    uint32_t target_token = extract_token_id(output_buffer, output_bytes);
    state->verified_tokens[i] = target_token;
    
    if (target_token == state->draft_tokens[i]) {
      accepted++;
    } else {
      klog("speculative-decoding: token %u mismatch (draft=%u, target=%u)\n",
           i, state->draft_tokens[i], target_token);
      break; /* Stop at first mismatch */
    }
  }
  
  state->num_verified_tokens = accepted;
  state->num_accepted_tokens = accepted;
  state->total_speculations += state->num_draft_tokens;
  state->total_accepted += accepted;
  state->total_rejected += (state->num_draft_tokens - accepted);
  
  /* Update acceptance rate (scaled by 100) */
  if (state->total_speculations > 0) {
    state->avg_acceptance_rate = (state->total_accepted * 100) / state->total_speculations;
  }
  
  klog("speculative-decoding: verified %u/%u tokens (%lu%% acceptance)\n",
       accepted, state->num_draft_tokens, state->avg_acceptance_rate);
  
  return XAIOS_OK;
}

xaios_status_t speculative_decode_step(
    xaios_speculative_state_t *state,
    const uint8_t *context,
    uint32_t context_length,
    uint32_t *output_tokens,
    uint32_t *num_output_tokens) {
  kassert(state != 0 && context != 0 && output_tokens != 0 && num_output_tokens != 0);
  
  /* Step 1: Generate draft tokens */
  uint32_t num_draft = XAIOS_SPEC_MAX_DRAFT_TOKENS;
  xaios_status_t status = speculative_generate_draft(state, context, context_length, num_draft);
  if (status != XAIOS_OK) {
    return status;
  }
  
  /* Step 2: Verify with target model */
  status = speculative_verify_tokens(state, context, context_length);
  if (status != XAIOS_OK) {
    return status;
  }
  
  /* Step 3: Copy accepted tokens to output */
  for (uint32_t i = 0; i < state->num_accepted_tokens; ++i) {
    output_tokens[i] = state->verified_tokens[i];
  }
  *num_output_tokens = state->num_accepted_tokens;
  
  /* Calculate speedup factor */
  if (state->num_draft_tokens > 0) {
    /* Speedup = tokens_generated / model_calls */
    uint32_t model_calls = 1 + state->num_draft_tokens; /* 1 draft + N verify */
    state->speedup_factor = (state->num_accepted_tokens * 100) / model_calls;
  }
  
  klog("speculative-decoding: step complete, output %u tokens, speedup %lu%%\n",
       *num_output_tokens, state->speedup_factor);
  
  return XAIOS_OK;
}

void speculative_decoding_get_stats(
    const xaios_speculative_state_t *state,
    uint64_t *acceptance_rate,
    uint64_t *speedup_factor,
    uint64_t *total_speculations,
    uint64_t *total_accepted) {
  kassert(state != 0);
  
  if (acceptance_rate != 0) *acceptance_rate = state->avg_acceptance_rate;
  if (speedup_factor != 0) *speedup_factor = state->speedup_factor;
  if (total_speculations != 0) *total_speculations = state->total_speculations;
  if (total_accepted != 0) *total_accepted = state->total_accepted;
}

void speculative_decoding_reset(xaios_speculative_state_t *state) {
  kassert(state != 0);
  
  state->num_draft_tokens = 0;
  state->num_verified_tokens = 0;
  state->num_accepted_tokens = 0;
  
  bytes_zero(state->draft_tokens, sizeof(state->draft_tokens));
  bytes_zero(state->verified_tokens, sizeof(state->verified_tokens));
  
  klog("speculative-decoding: reset state\n");
}
