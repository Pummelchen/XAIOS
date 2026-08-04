#define _POSIX_C_SOURCE 200809L

#include <xaios_engine/inference.h>

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct hosted_reader {
  int descriptor;
} hosted_reader_t;

static xaios_engine_status_t hosted_read_at(void *opaque, uint64_t offset,
                                            void *destination,
                                            size_t length) {
  hosted_reader_t *reader = (hosted_reader_t *)opaque;
  if (reader == NULL || reader->descriptor < 0 || destination == NULL ||
      offset > (uint64_t)INT64_MAX) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  uint8_t *output = (uint8_t *)destination;
  size_t completed = 0U;
  while (completed < length) {
    ssize_t result = pread(reader->descriptor, output + completed,
                           length - completed, (off_t)(offset + completed));
    if (result <= 0) return XAIOS_ENGINE_ERR_IO;
    completed += (size_t)result;
  }
  return XAIOS_ENGINE_OK;
}

static int probe(void) {
  const xaios_backend_t *scalar = xaios_backend_select(0U);
  printf("scalar=%s avx2=%u neon=%u sve=interface-only sve2=interface-only\n",
         scalar != NULL ? "ready" : "failed",
         xaios_packed_avx2_available() != 0,
         xaios_packed_neon_available() != 0);
  return scalar != NULL ? 0 : 1;
}

static int inspect_or_serve(const char *path, int serve) {
  int descriptor = open(path, O_RDONLY);
  if (descriptor < 0) {
    fprintf(stderr, "xaios-engine: open %s: %s\n", path, strerror(errno));
    return 1;
  }
  struct stat metadata;
  if (fstat(descriptor, &metadata) != 0 || metadata.st_size < 0) {
    fprintf(stderr, "xaios-engine: stat %s failed\n", path);
    close(descriptor);
    return 1;
  }
  hosted_reader_t hosted = {descriptor};
  xaios_model_v2_reader_t reader = {
      &hosted, hosted_read_at, (uint64_t)metadata.st_size};
  xaios_engine_model_slot_t models[1];
  xaios_engine_session_slot_t sessions[1];
  xaios_engine_service_t service;
  uint64_t model_id = 0U;
  xaios_engine_status_t status = xaios_engine_service_init(
      &service, models, 1U, sessions, 1U);
  if (status == XAIOS_ENGINE_OK) {
    status = xaios_engine_service_admit_model(&service, &reader, NULL, 0U,
                                              &model_id);
  }
  if (status != XAIOS_ENGINE_OK) {
    fprintf(stderr, "xaios-engine: package admission failed status=%d\n",
            (int)status);
    close(descriptor);
    return 1;
  }
  printf("model_id=%llu architecture=%s sections=%llu tensors=%llu "
         "bytes=%llu execution=%s\n",
         (unsigned long long)model_id,
         models[0].package.header.architecture_id,
         (unsigned long long)models[0].package.header.section_count,
         (unsigned long long)models[0].package.header.tensor_count,
         (unsigned long long)models[0].package.header.file_size,
         models[0].executable != 0U ? "scalar-ready" : "interface-only");
  if (serve != 0 && models[0].executable == 0U) {
    fprintf(stderr,
            "xaios-engine: inference unsupported for interface-only adapter\n");
    close(descriptor);
    return 3;
  }
  close(descriptor);
  return 0;
}

int main(int argc, char **argv) {
  if (argc == 2 && strcmp(argv[1], "probe") == 0) return probe();
  if (argc == 3 && strcmp(argv[1], "inspect") == 0) {
    return inspect_or_serve(argv[2], 0);
  }
  if (argc == 3 && strcmp(argv[1], "serve") == 0) {
    return inspect_or_serve(argv[2], 1);
  }
  fprintf(stderr, "usage: xaios-engine probe|inspect MODEL|serve MODEL\n");
  return 2;
}
