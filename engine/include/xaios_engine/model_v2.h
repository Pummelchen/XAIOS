#ifndef XAIOS_ENGINE_MODEL_V2_H
#define XAIOS_ENGINE_MODEL_V2_H

#include <stddef.h>
#include <stdint.h>

#define XAIOS_MODEL_V2_MAGIC "XAIOSM2\0"
#define XAIOS_MODEL_V2_HEADER_SIZE UINT64_C(256)
#define XAIOS_MODEL_V2_SECTION_DESCRIPTOR_SIZE UINT64_C(128)
#define XAIOS_MODEL_V2_TENSOR_DESCRIPTOR_SIZE UINT64_C(320)
#define XAIOS_MODEL_V2_IO_ALIGNMENT UINT64_C(4096)
#define XAIOS_MODEL_V2_MAX_RANK 8U
#define XAIOS_MODEL_V2_INDEX_NONE UINT64_MAX

typedef enum xaios_engine_status {
  XAIOS_ENGINE_OK = 0,
  XAIOS_ENGINE_ERR_INVALID = -1,
  XAIOS_ENGINE_ERR_IO = -2,
  XAIOS_ENGINE_ERR_UNSUPPORTED = -3,
  XAIOS_ENGINE_ERR_CHECKSUM = -4,
  XAIOS_ENGINE_ERR_OVERFLOW = -5,
  XAIOS_ENGINE_ERR_CAPABILITY = -6
} xaios_engine_status_t;

typedef enum xaios_model_v2_hash_algorithm {
  XAIOS_MODEL_V2_HASH_NONE = 0,
  XAIOS_MODEL_V2_HASH_SHA256 = 1
} xaios_model_v2_hash_algorithm_t;

typedef enum xaios_model_v2_execution_mode {
  XAIOS_MODEL_V2_EXECUTION_EXACT = 1,
  XAIOS_MODEL_V2_EXECUTION_APPROXIMATE = 2
} xaios_model_v2_execution_mode_t;

typedef enum xaios_model_v2_section_type {
  XAIOS_MODEL_V2_SECTION_ARCHITECTURE = 1,
  XAIOS_MODEL_V2_SECTION_LAYER_PLAN = 2,
  XAIOS_MODEL_V2_SECTION_TENSOR_DIRECTORY = 3,
  XAIOS_MODEL_V2_SECTION_TOKENIZER = 4,
  XAIOS_MODEL_V2_SECTION_STRING_TABLE = 5,
  XAIOS_MODEL_V2_SECTION_DENSE_WEIGHTS = 6,
  XAIOS_MODEL_V2_SECTION_EXPERT_WEIGHTS = 7,
  XAIOS_MODEL_V2_SECTION_VISION = 8,
  XAIOS_MODEL_V2_SECTION_INTEGRITY = 9
} xaios_model_v2_section_type_t;

typedef enum xaios_model_v2_storage_class {
  XAIOS_MODEL_V2_TENSOR_RESIDENT = UINT32_C(1),
  XAIOS_MODEL_V2_TENSOR_CACHEABLE = UINT32_C(1) << 1,
  XAIOS_MODEL_V2_TENSOR_STREAMABLE = UINT32_C(1) << 2
} xaios_model_v2_storage_class_t;

typedef xaios_engine_status_t (*xaios_model_v2_read_at_fn)(
    void *context, uint64_t offset, void *destination, size_t length);

typedef struct xaios_model_v2_reader {
  void *context;
  xaios_model_v2_read_at_fn read_at;
  uint64_t size;
} xaios_model_v2_reader_t;

typedef struct xaios_model_v2_header {
  uint16_t version_major;
  uint16_t version_minor;
  uint8_t endianness;
  uint8_t hash_algorithm;
  uint8_t execution_mode;
  uint8_t flags;
  uint64_t header_size;
  uint64_t section_descriptor_size;
  uint64_t tensor_descriptor_size;
  uint64_t file_size;
  uint64_t section_directory_offset;
  uint64_t section_count;
  uint64_t tensor_directory_offset;
  uint64_t tensor_count;
  uint64_t architecture_section_index;
  uint64_t tokenizer_section_index;
  uint64_t layer_plan_section_index;
  uint64_t string_table_section_index;
  uint8_t model_uuid[16];
  uint8_t source_revision[32];
  char converter_version[17];
  char architecture_id[33];
  uint8_t header_hash[32];
} xaios_model_v2_header_t;

typedef struct xaios_model_v2_package {
  xaios_model_v2_reader_t reader;
  xaios_model_v2_header_t header;
} xaios_model_v2_package_t;

typedef struct xaios_model_v2_section {
  uint32_t type;
  uint32_t flags;
  uint64_t section_id;
  uint64_t offset;
  uint64_t length;
  uint64_t alignment;
  uint64_t shard_id;
  uint32_t checksum_algorithm;
  uint8_t checksum[32];
  uint64_t name_offset;
  uint64_t name_length;
} xaios_model_v2_section_t;

typedef struct xaios_model_v2_tensor {
  uint32_t flags;
  uint32_t semantic_role;
  uint64_t tensor_id;
  uint64_t layer_id;
  uint64_t expert_id;
  uint64_t name_offset;
  uint64_t name_length;
  uint32_t rank;
  uint16_t logical_dtype;
  uint16_t stored_dtype;
  uint16_t quantization_scheme;
  uint16_t scale_dtype;
  uint32_t layout_id;
  uint64_t required_backend;
  uint64_t shard_id;
  uint64_t data_offset;
  uint64_t data_length;
  uint64_t alignment;
  uint64_t scale_offset;
  uint64_t scale_length;
  uint64_t quant_block_size;
  uint64_t quant_group_size;
  uint64_t dimensions[XAIOS_MODEL_V2_MAX_RANK];
  uint64_t strides[XAIOS_MODEL_V2_MAX_RANK];
  uint32_t checksum_algorithm;
  uint8_t checksum[32];
} xaios_model_v2_tensor_t;

xaios_engine_status_t xaios_model_v2_open(
    const xaios_model_v2_reader_t *reader, xaios_model_v2_package_t *package);
xaios_engine_status_t xaios_model_v2_read_section(
    const xaios_model_v2_package_t *package, uint64_t index,
    xaios_model_v2_section_t *section);
xaios_engine_status_t xaios_model_v2_read_tensor(
    const xaios_model_v2_package_t *package, uint64_t index,
    xaios_model_v2_tensor_t *tensor);
xaios_engine_status_t xaios_model_v2_verify_section(
    const xaios_model_v2_package_t *package,
    const xaios_model_v2_section_t *section, void *scratch,
    size_t scratch_size);

#endif
