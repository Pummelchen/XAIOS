#include <xaios_engine/inference.h>

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct file_reader_context {
  FILE *file;
} file_reader_context_t;

static xaios_engine_status_t file_read_at(void *opaque, uint64_t offset,
                                          void *destination, size_t length) {
  file_reader_context_t *context = (file_reader_context_t *)opaque;
  if (context == NULL || context->file == NULL || destination == NULL ||
      offset > (uint64_t)LONG_MAX ||
      fseek(context->file, (long)offset, SEEK_SET) != 0 ||
      fread(destination, 1U, length, context->file) != length) {
    return XAIOS_ENGINE_ERR_IO;
  }
  return XAIOS_ENGINE_OK;
}

static int test_interfaces(void) {
  const xaios_architecture_adapter_t *qwen =
      xaios_architecture_find("qwen3_5");
  const xaios_architecture_adapter_t *kimi =
      xaios_architecture_find("kimi_k3");
  if (xaios_architecture_count() != 2U || qwen == NULL || kimi == NULL ||
      qwen->status != XAIOS_ARCHITECTURE_INTERFACE_ONLY ||
      kimi->status != XAIOS_ARCHITECTURE_INTERFACE_ONLY ||
      xaios_architecture_find("Qwen3.6") != NULL) {
    return 1;
  }

  const xaios_backend_t *backend = xaios_backend_select(0);
  if (backend == NULL || backend->validate() != XAIOS_ENGINE_OK ||
      backend->probe_capabilities() != XAIOS_BACKEND_CAP_SCALAR ||
      ((xaios_backend_select(XAIOS_BACKEND_CAP_AVX2) != NULL) !=
       (xaios_packed_avx2_available() != 0)) ||
      ((xaios_backend_select(XAIOS_BACKEND_CAP_NEON) != NULL) !=
       (xaios_packed_neon_available() != 0))) {
    return 1;
  }
  const float input[2] = {2.0f, 3.0f};
  const float weights[4] = {1.0f, 2.0f, -1.0f, 1.0f};
  float output[2] = {0.0f, 0.0f};
  if (backend->dense_projection(input, weights, NULL, output, 2U, 2U) !=
          XAIOS_ENGINE_OK ||
      output[0] != 8.0f || output[1] != 1.0f) {
    return 1;
  }
  return 0;
}

static int inspect_package(const char *path) {
  FILE *file = fopen(path, "rb");
  if (file == NULL || fseek(file, 0, SEEK_END) != 0) {
    if (file != NULL) {
      fclose(file);
    }
    return 1;
  }
  long end = ftell(file);
  if (end < 0 || fseek(file, 0, SEEK_SET) != 0) {
    fclose(file);
    return 1;
  }

  file_reader_context_t context = {file};
  xaios_model_v2_reader_t reader = {&context, file_read_at, (uint64_t)end};
  xaios_model_v2_package_t package;
  xaios_engine_status_t status = xaios_model_v2_open(&reader, &package);
  if (status != XAIOS_ENGINE_OK) {
    fprintf(stderr, "model-v2 open failed: %d\n", (int)status);
    fclose(file);
    return 1;
  }

  uint8_t scratch[4096];
  for (uint64_t i = 0; i < package.header.section_count; ++i) {
    xaios_model_v2_section_t section;
    status = xaios_model_v2_read_section(&package, i, &section);
    if (status != XAIOS_ENGINE_OK ||
        xaios_model_v2_verify_section(&package, &section, scratch,
                                      sizeof(scratch)) != XAIOS_ENGINE_OK) {
      fprintf(stderr, "model-v2 section validation failed: %llu\n",
              (unsigned long long)i);
      fclose(file);
      return 1;
    }
  }
  for (uint64_t i = 0; i < package.header.tensor_count; ++i) {
    xaios_model_v2_tensor_t tensor;
    status = xaios_model_v2_read_tensor(&package, i, &tensor);
    if (status != XAIOS_ENGINE_OK) {
      fprintf(stderr, "model-v2 tensor validation failed: %d\n", (int)status);
      fclose(file);
      return 1;
    }
  }
  printf("model-v2: ok architecture=%s sections=%llu tensors=%llu\n",
         package.header.architecture_id,
         (unsigned long long)package.header.section_count,
         (unsigned long long)package.header.tensor_count);
  fclose(file);
  return 0;
}

int main(int argc, char **argv) {
  if (test_interfaces() != 0) {
    fprintf(stderr, "hosted engine interface canary failed\n");
    return 1;
  }
  if (argc == 1) {
    puts("hosted engine: scalar canary and architecture registry passed");
    return 0;
  }
  if (argc != 2) {
    fprintf(stderr, "usage: test-engine [model-v2-package]\n");
    return 2;
  }
  return inspect_package(argv[1]);
}
