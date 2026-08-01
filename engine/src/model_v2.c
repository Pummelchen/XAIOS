#include <xaios_engine/model_v2.h>

#include <string.h>

#include "sha256.h"

#define HEADER_HASH_OFFSET 208U
#define HEADER_HASH_LENGTH 32U

static uint16_t load_le16(const uint8_t *bytes) {
  return (uint16_t)((uint16_t)bytes[0] | ((uint16_t)bytes[1] << 8));
}

static uint32_t load_le32(const uint8_t *bytes) {
  return (uint32_t)bytes[0] | ((uint32_t)bytes[1] << 8) |
         ((uint32_t)bytes[2] << 16) | ((uint32_t)bytes[3] << 24);
}

static uint64_t load_le64(const uint8_t *bytes) {
  uint64_t value = 0;
  for (uint32_t i = 0; i < 8U; ++i) {
    value |= (uint64_t)bytes[i] << (i * 8U);
  }
  return value;
}

static int bytes_are_zero(const uint8_t *bytes, size_t length) {
  for (size_t i = 0; i < length; ++i) {
    if (bytes[i] != 0U) {
      return 0;
    }
  }
  return 1;
}

static int power_of_two(uint64_t value) {
  return value != 0U && (value & (value - 1U)) == 0U;
}

static xaios_engine_status_t checked_add(uint64_t left, uint64_t right,
                                         uint64_t *result) {
  if (result == NULL || left > UINT64_MAX - right) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  *result = left + right;
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t checked_multiply(uint64_t left, uint64_t right,
                                              uint64_t *result) {
  if (result == NULL || (left != 0U && right > UINT64_MAX / left)) {
    return XAIOS_ENGINE_ERR_OVERFLOW;
  }
  *result = left * right;
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t range_in_file(uint64_t offset, uint64_t length,
                                           uint64_t file_size) {
  if (offset > file_size || length > file_size - offset) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  return XAIOS_ENGINE_OK;
}

static xaios_engine_status_t directory_end(uint64_t offset, uint64_t count,
                                           uint64_t item_size,
                                           uint64_t file_size,
                                           uint64_t *end) {
  uint64_t length = 0;
  xaios_engine_status_t status = checked_multiply(count, item_size, &length);
  if (status != XAIOS_ENGINE_OK) {
    return status;
  }
  status = range_in_file(offset, length, file_size);
  if (status != XAIOS_ENGINE_OK) {
    return status;
  }
  return checked_add(offset, length, end);
}

static xaios_engine_status_t read_exact(
    const xaios_model_v2_reader_t *reader, uint64_t offset, void *destination,
    size_t length) {
  if (reader == NULL || reader->read_at == NULL || destination == NULL ||
      range_in_file(offset, (uint64_t)length, reader->size) !=
          XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  return reader->read_at(reader->context, offset, destination, length);
}

static void copy_fixed_string(char *destination, size_t destination_size,
                              const uint8_t *source, size_t source_size) {
  size_t count = source_size;
  if (count >= destination_size) {
    count = destination_size - 1U;
  }
  memcpy(destination, source, count);
  destination[count] = '\0';
}

static xaios_engine_status_t decode_section(
    const xaios_model_v2_package_t *package, const uint8_t raw[128],
    xaios_model_v2_section_t *section) {
  section->type = load_le32(raw);
  section->flags = load_le32(raw + 4U);
  section->section_id = load_le64(raw + 8U);
  section->offset = load_le64(raw + 16U);
  section->length = load_le64(raw + 24U);
  section->alignment = load_le64(raw + 32U);
  section->shard_id = load_le64(raw + 40U);
  section->checksum_algorithm = load_le32(raw + 48U);
  memcpy(section->checksum, raw + 56U, sizeof(section->checksum));
  section->name_offset = load_le64(raw + 88U);
  section->name_length = load_le64(raw + 96U);

  if (section->type == 0U || section->length == 0U ||
      !power_of_two(section->alignment) ||
      section->alignment < XAIOS_MODEL_V2_IO_ALIGNMENT ||
      (section->offset & (section->alignment - 1U)) != 0U ||
      range_in_file(section->offset, section->length,
                    package->header.file_size) != XAIOS_ENGINE_OK ||
      range_in_file(section->name_offset, section->name_length,
                    package->header.file_size) != XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  if (section->checksum_algorithm != XAIOS_MODEL_V2_HASH_SHA256 ||
      bytes_are_zero(section->checksum, sizeof(section->checksum))) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_model_v2_open(
    const xaios_model_v2_reader_t *reader, xaios_model_v2_package_t *package) {
  uint8_t raw[256];
  uint8_t hash_input[256];
  uint8_t calculated_hash[32];
  uint64_t section_directory_end = 0;
  uint64_t tensor_directory_end = 0;
  uint64_t metadata_end = 0;

  if (reader == NULL || package == NULL ||
      reader->size < XAIOS_MODEL_V2_HEADER_SIZE) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  xaios_engine_status_t status = read_exact(reader, 0, raw, sizeof(raw));
  if (status != XAIOS_ENGINE_OK) {
    return status;
  }
  if (memcmp(raw, XAIOS_MODEL_V2_MAGIC, 8U) != 0) {
    return XAIOS_ENGINE_ERR_INVALID;
  }

  memset(package, 0, sizeof(*package));
  package->reader = *reader;
  package->header.version_major = load_le16(raw + 8U);
  package->header.version_minor = load_le16(raw + 10U);
  package->header.endianness = raw[12U];
  package->header.hash_algorithm = raw[13U];
  package->header.execution_mode = raw[14U];
  package->header.flags = raw[15U];
  package->header.header_size = load_le64(raw + 16U);
  package->header.section_descriptor_size = load_le64(raw + 24U);
  package->header.tensor_descriptor_size = load_le64(raw + 32U);
  package->header.file_size = load_le64(raw + 40U);
  package->header.section_directory_offset = load_le64(raw + 48U);
  package->header.section_count = load_le64(raw + 56U);
  package->header.tensor_directory_offset = load_le64(raw + 64U);
  package->header.tensor_count = load_le64(raw + 72U);
  package->header.architecture_section_index = load_le64(raw + 80U);
  package->header.tokenizer_section_index = load_le64(raw + 88U);
  package->header.layer_plan_section_index = load_le64(raw + 96U);
  package->header.string_table_section_index = load_le64(raw + 104U);
  memcpy(package->header.model_uuid, raw + 112U, 16U);
  memcpy(package->header.source_revision, raw + 128U, 32U);
  copy_fixed_string(package->header.converter_version,
                    sizeof(package->header.converter_version), raw + 160U,
                    16U);
  copy_fixed_string(package->header.architecture_id,
                    sizeof(package->header.architecture_id), raw + 176U,
                    32U);
  memcpy(package->header.header_hash, raw + HEADER_HASH_OFFSET,
         HEADER_HASH_LENGTH);

  if (package->header.version_major != 2U ||
      package->header.endianness != 1U ||
      package->header.hash_algorithm != XAIOS_MODEL_V2_HASH_SHA256 ||
      (package->header.execution_mode != XAIOS_MODEL_V2_EXECUTION_EXACT &&
       package->header.execution_mode !=
           XAIOS_MODEL_V2_EXECUTION_APPROXIMATE) ||
      package->header.header_size != XAIOS_MODEL_V2_HEADER_SIZE ||
      package->header.section_descriptor_size !=
          XAIOS_MODEL_V2_SECTION_DESCRIPTOR_SIZE ||
      package->header.tensor_descriptor_size !=
          XAIOS_MODEL_V2_TENSOR_DESCRIPTOR_SIZE ||
      package->header.file_size != reader->size ||
      package->header.section_count == 0U ||
      package->header.architecture_id[0] == '\0' ||
      bytes_are_zero(package->header.model_uuid, 16U) ||
      bytes_are_zero(package->header.source_revision, 32U) ||
      !bytes_are_zero(raw + 240U, 16U)) {
    return XAIOS_ENGINE_ERR_INVALID;
  }

  memcpy(hash_input, raw, sizeof(hash_input));
  memset(hash_input + HEADER_HASH_OFFSET, 0, HEADER_HASH_LENGTH);
  xaios_sha256_context_t hash_context;
  xaios_sha256_init(&hash_context);
  xaios_sha256_update(&hash_context, hash_input, sizeof(hash_input));
  xaios_sha256_final(&hash_context, calculated_hash);
  if (memcmp(calculated_hash, package->header.header_hash,
             sizeof(calculated_hash)) != 0) {
    return XAIOS_ENGINE_ERR_CHECKSUM;
  }

  status = directory_end(package->header.section_directory_offset,
                         package->header.section_count,
                         package->header.section_descriptor_size,
                         package->header.file_size, &section_directory_end);
  if (status != XAIOS_ENGINE_OK) {
    return status;
  }
  status = directory_end(package->header.tensor_directory_offset,
                         package->header.tensor_count,
                         package->header.tensor_descriptor_size,
                         package->header.file_size, &tensor_directory_end);
  if (status != XAIOS_ENGINE_OK) {
    return status;
  }
  if (package->header.section_directory_offset <
          XAIOS_MODEL_V2_IO_ALIGNMENT ||
      package->header.tensor_directory_offset <
          XAIOS_MODEL_V2_IO_ALIGNMENT ||
      (package->header.section_directory_offset &
       (XAIOS_MODEL_V2_IO_ALIGNMENT - 1U)) != 0U ||
      (package->header.tensor_directory_offset &
       (XAIOS_MODEL_V2_IO_ALIGNMENT - 1U)) != 0U) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  if (package->header.tensor_count != 0U &&
      package->header.section_directory_offset < tensor_directory_end &&
      package->header.tensor_directory_offset < section_directory_end) {
    return XAIOS_ENGINE_ERR_INVALID;
  }

  metadata_end = section_directory_end > tensor_directory_end
                     ? section_directory_end
                     : tensor_directory_end;
  uint64_t previous_end = metadata_end;
  for (uint64_t i = 0; i < package->header.section_count; ++i) {
    xaios_model_v2_section_t section;
    status = xaios_model_v2_read_section(package, i, &section);
    if (status != XAIOS_ENGINE_OK) {
      return status;
    }
    if (section.offset < previous_end) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
    status = checked_add(section.offset, section.length, &previous_end);
    if (status != XAIOS_ENGINE_OK) {
      return status;
    }
  }

  const uint64_t indices[] = {
      package->header.architecture_section_index,
      package->header.tokenizer_section_index,
      package->header.layer_plan_section_index,
      package->header.string_table_section_index};
  const uint32_t expected_types[] = {
      XAIOS_MODEL_V2_SECTION_ARCHITECTURE,
      XAIOS_MODEL_V2_SECTION_TOKENIZER,
      XAIOS_MODEL_V2_SECTION_LAYER_PLAN,
      XAIOS_MODEL_V2_SECTION_STRING_TABLE};
  for (size_t i = 0; i < sizeof(indices) / sizeof(indices[0]); ++i) {
    if (indices[i] == XAIOS_MODEL_V2_INDEX_NONE ||
        indices[i] >= package->header.section_count) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
    xaios_model_v2_section_t section;
    status = xaios_model_v2_read_section(package, indices[i], &section);
    if (status != XAIOS_ENGINE_OK || section.type != expected_types[i]) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_model_v2_read_section(
    const xaios_model_v2_package_t *package, uint64_t index,
    xaios_model_v2_section_t *section) {
  uint8_t raw[128];
  uint64_t relative = 0;
  uint64_t offset = 0;
  if (package == NULL || section == NULL ||
      index >= package->header.section_count) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  xaios_engine_status_t status = checked_multiply(
      index, package->header.section_descriptor_size, &relative);
  if (status != XAIOS_ENGINE_OK) {
    return status;
  }
  status = checked_add(package->header.section_directory_offset, relative,
                       &offset);
  if (status != XAIOS_ENGINE_OK) {
    return status;
  }
  status = read_exact(&package->reader, offset, raw, sizeof(raw));
  if (status != XAIOS_ENGINE_OK) {
    return status;
  }
  return decode_section(package, raw, section);
}

xaios_engine_status_t xaios_model_v2_read_tensor(
    const xaios_model_v2_package_t *package, uint64_t index,
    xaios_model_v2_tensor_t *tensor) {
  uint8_t raw[320];
  uint64_t relative = 0;
  uint64_t offset = 0;
  uint64_t element_count = 1;
  if (package == NULL || tensor == NULL ||
      index >= package->header.tensor_count) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  xaios_engine_status_t status = checked_multiply(
      index, package->header.tensor_descriptor_size, &relative);
  if (status != XAIOS_ENGINE_OK) {
    return status;
  }
  status = checked_add(package->header.tensor_directory_offset, relative,
                       &offset);
  if (status != XAIOS_ENGINE_OK) {
    return status;
  }
  status = read_exact(&package->reader, offset, raw, sizeof(raw));
  if (status != XAIOS_ENGINE_OK) {
    return status;
  }

  memset(tensor, 0, sizeof(*tensor));
  tensor->flags = load_le32(raw);
  tensor->semantic_role = load_le32(raw + 4U);
  tensor->tensor_id = load_le64(raw + 8U);
  tensor->layer_id = load_le64(raw + 16U);
  tensor->expert_id = load_le64(raw + 24U);
  tensor->name_offset = load_le64(raw + 32U);
  tensor->name_length = load_le64(raw + 40U);
  tensor->rank = load_le32(raw + 48U);
  tensor->logical_dtype = load_le16(raw + 52U);
  tensor->stored_dtype = load_le16(raw + 54U);
  tensor->quantization_scheme = load_le16(raw + 56U);
  tensor->scale_dtype = load_le16(raw + 58U);
  tensor->layout_id = load_le32(raw + 60U);
  tensor->required_backend = load_le64(raw + 64U);
  tensor->shard_id = load_le64(raw + 72U);
  tensor->data_offset = load_le64(raw + 80U);
  tensor->data_length = load_le64(raw + 88U);
  tensor->alignment = load_le64(raw + 96U);
  tensor->scale_offset = load_le64(raw + 104U);
  tensor->scale_length = load_le64(raw + 112U);
  tensor->quant_block_size = load_le64(raw + 120U);
  tensor->quant_group_size = load_le64(raw + 128U);
  for (uint32_t i = 0; i < XAIOS_MODEL_V2_MAX_RANK; ++i) {
    tensor->dimensions[i] = load_le64(raw + 136U + (i * 8U));
    tensor->strides[i] = load_le64(raw + 200U + (i * 8U));
  }
  tensor->checksum_algorithm = load_le32(raw + 264U);
  memcpy(tensor->checksum, raw + 272U, sizeof(tensor->checksum));

  if (tensor->semantic_role == 0U || tensor->rank == 0U ||
      tensor->rank > XAIOS_MODEL_V2_MAX_RANK ||
      tensor->data_length == 0U || !power_of_two(tensor->alignment) ||
      tensor->alignment < XAIOS_MODEL_V2_IO_ALIGNMENT ||
      (tensor->data_offset & (tensor->alignment - 1U)) != 0U ||
      range_in_file(tensor->data_offset, tensor->data_length,
                    package->header.file_size) != XAIOS_ENGINE_OK ||
      range_in_file(tensor->name_offset, tensor->name_length,
                    package->header.file_size) != XAIOS_ENGINE_OK ||
      tensor->checksum_algorithm != XAIOS_MODEL_V2_HASH_SHA256 ||
      bytes_are_zero(tensor->checksum, sizeof(tensor->checksum))) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  if (tensor->scale_length != 0U &&
      range_in_file(tensor->scale_offset, tensor->scale_length,
                    package->header.file_size) != XAIOS_ENGINE_OK) {
    return XAIOS_ENGINE_ERR_INVALID;
  }
  for (uint32_t i = 0; i < tensor->rank; ++i) {
    if (tensor->dimensions[i] == 0U || tensor->strides[i] == 0U) {
      return XAIOS_ENGINE_ERR_INVALID;
    }
    status = checked_multiply(element_count, tensor->dimensions[i],
                              &element_count);
    if (status != XAIOS_ENGINE_OK) {
      return status;
    }
  }
  return XAIOS_ENGINE_OK;
}

xaios_engine_status_t xaios_model_v2_verify_section(
    const xaios_model_v2_package_t *package,
    const xaios_model_v2_section_t *section, void *scratch,
    size_t scratch_size) {
  if (package == NULL || section == NULL || scratch == NULL ||
      scratch_size < XAIOS_MODEL_V2_IO_ALIGNMENT ||
      section->checksum_algorithm != XAIOS_MODEL_V2_HASH_SHA256) {
    return XAIOS_ENGINE_ERR_INVALID;
  }

  xaios_sha256_context_t hash_context;
  xaios_sha256_init(&hash_context);
  uint64_t cursor = 0;
  while (cursor < section->length) {
    uint64_t remaining = section->length - cursor;
    size_t count = remaining < (uint64_t)scratch_size
                       ? (size_t)remaining
                       : scratch_size;
    xaios_engine_status_t status = read_exact(
        &package->reader, section->offset + cursor, scratch, count);
    if (status != XAIOS_ENGINE_OK) {
      return status;
    }
    xaios_sha256_update(&hash_context, scratch, count);
    cursor += (uint64_t)count;
  }
  uint8_t calculated[32];
  xaios_sha256_final(&hash_context, calculated);
  return memcmp(calculated, section->checksum, sizeof(calculated)) == 0
             ? XAIOS_ENGINE_OK
             : XAIOS_ENGINE_ERR_CHECKSUM;
}
