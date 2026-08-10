#include <xaios/inflate.h>

#define INFLATE_MAX_BITS 15U
#define INFLATE_MAX_CODES 320U

typedef struct inflate_bits {
  const uint8_t *input;
  uint64_t size;
  uint64_t cursor;
  uint32_t bits;
  uint32_t count;
} inflate_bits_t;

typedef struct inflate_huffman {
  uint16_t count[INFLATE_MAX_BITS + 1U];
  uint16_t symbol[INFLATE_MAX_CODES];
} inflate_huffman_t;

static xaios_status_t read_bits(inflate_bits_t *stream, uint32_t count,
                                uint32_t *value) {
  if (stream == 0 || value == 0 || count > 16U) return XAIOS_ERR_INVALID;
  while (stream->count < count) {
    if (stream->cursor >= stream->size) return XAIOS_ERR_INVALID;
    stream->bits |= (uint32_t)stream->input[stream->cursor++] << stream->count;
    stream->count += 8U;
  }
  *value = count == 0U ? 0U : stream->bits & ((UINT32_C(1) << count) - 1U);
  stream->bits >>= count;
  stream->count -= count;
  return XAIOS_OK;
}

static xaios_status_t construct(inflate_huffman_t *table,
                                const uint8_t *lengths, uint32_t symbols) {
  uint16_t offsets[INFLATE_MAX_BITS + 1U];
  if (table == 0 || lengths == 0 || symbols > INFLATE_MAX_CODES)
    return XAIOS_ERR_INVALID;
  for (uint32_t i = 0U; i <= INFLATE_MAX_BITS; ++i) table->count[i] = 0U;
  for (uint32_t i = 0U; i < symbols; ++i) {
    if (lengths[i] > INFLATE_MAX_BITS) return XAIOS_ERR_INVALID;
    ++table->count[lengths[i]];
  }
  if (table->count[0] == symbols) return XAIOS_ERR_INVALID;
  int32_t available = 1;
  for (uint32_t length = 1U; length <= INFLATE_MAX_BITS; ++length) {
    available = (available << 1) - table->count[length];
    if (available < 0) return XAIOS_ERR_INVALID;
  }
  offsets[1] = 0U;
  for (uint32_t length = 1U; length < INFLATE_MAX_BITS; ++length)
    offsets[length + 1U] = offsets[length] + table->count[length];
  for (uint32_t symbol = 0U; symbol < symbols; ++symbol)
    if (lengths[symbol] != 0U)
      table->symbol[offsets[lengths[symbol]]++] = (uint16_t)symbol;
  return XAIOS_OK;
}

static xaios_status_t decode(inflate_bits_t *stream,
                             const inflate_huffman_t *table,
                             uint32_t *symbol) {
  uint32_t code = 0U;
  uint32_t first = 0U;
  uint32_t index = 0U;
  for (uint32_t length = 1U; length <= INFLATE_MAX_BITS; ++length) {
    uint32_t bit = 0U;
    if (read_bits(stream, 1U, &bit) != XAIOS_OK) return XAIOS_ERR_INVALID;
    code |= bit;
    uint32_t count = table->count[length];
    if (code < first + count) {
      *symbol = table->symbol[index + code - first];
      return XAIOS_OK;
    }
    index += count;
    first = (first + count) << 1U;
    code <<= 1U;
  }
  return XAIOS_ERR_INVALID;
}

static xaios_status_t build_fixed(inflate_huffman_t *literal,
                                  inflate_huffman_t *distance) {
  uint8_t lengths[288];
  for (uint32_t i = 0U; i <= 143U; ++i) lengths[i] = 8U;
  for (uint32_t i = 144U; i <= 255U; ++i) lengths[i] = 9U;
  for (uint32_t i = 256U; i <= 279U; ++i) lengths[i] = 7U;
  for (uint32_t i = 280U; i <= 287U; ++i) lengths[i] = 8U;
  if (construct(literal, lengths, 288U) != XAIOS_OK) return XAIOS_ERR_INVALID;
  for (uint32_t i = 0U; i < 32U; ++i) lengths[i] = 5U;
  return construct(distance, lengths, 32U);
}

static xaios_status_t build_dynamic(inflate_bits_t *stream,
                                    inflate_huffman_t *literal,
                                    inflate_huffman_t *distance) {
  static const uint8_t order[19] = {16, 17, 18, 0, 8, 7, 9, 6, 10, 5,
                                    11, 4, 12, 3, 13, 2, 14, 1, 15};
  uint32_t value = 0U;
  if (read_bits(stream, 5U, &value) != XAIOS_OK) return XAIOS_ERR_INVALID;
  uint32_t literal_count = value + 257U;
  if (read_bits(stream, 5U, &value) != XAIOS_OK) return XAIOS_ERR_INVALID;
  uint32_t distance_count = value + 1U;
  if (read_bits(stream, 4U, &value) != XAIOS_OK) return XAIOS_ERR_INVALID;
  uint32_t code_count = value + 4U;
  if (literal_count > 286U || distance_count > 30U) return XAIOS_ERR_INVALID;

  uint8_t lengths[INFLATE_MAX_CODES];
  for (uint32_t i = 0U; i < INFLATE_MAX_CODES; ++i) lengths[i] = 0U;
  for (uint32_t i = 0U; i < code_count; ++i) {
    if (read_bits(stream, 3U, &value) != XAIOS_OK) return XAIOS_ERR_INVALID;
    lengths[order[i]] = (uint8_t)value;
  }
  inflate_huffman_t code_table;
  if (construct(&code_table, lengths, 19U) != XAIOS_OK)
    return XAIOS_ERR_INVALID;

  uint32_t total = literal_count + distance_count;
  uint32_t used = 0U;
  while (used < total) {
    uint32_t symbol = 0U;
    if (decode(stream, &code_table, &symbol) != XAIOS_OK)
      return XAIOS_ERR_INVALID;
    if (symbol < 16U) {
      lengths[used++] = (uint8_t)symbol;
      continue;
    }
    uint32_t repeat = 0U;
    uint8_t repeated = 0U;
    if (symbol == 16U) {
      if (used == 0U || read_bits(stream, 2U, &repeat) != XAIOS_OK)
        return XAIOS_ERR_INVALID;
      repeat += 3U;
      repeated = lengths[used - 1U];
    } else if (symbol == 17U) {
      if (read_bits(stream, 3U, &repeat) != XAIOS_OK)
        return XAIOS_ERR_INVALID;
      repeat += 3U;
    } else if (symbol == 18U) {
      if (read_bits(stream, 7U, &repeat) != XAIOS_OK)
        return XAIOS_ERR_INVALID;
      repeat += 11U;
    } else {
      return XAIOS_ERR_INVALID;
    }
    if (repeat > total - used) return XAIOS_ERR_INVALID;
    while (repeat-- != 0U) lengths[used++] = repeated;
  }
  if (lengths[256U] == 0U ||
      construct(literal, lengths, literal_count) != XAIOS_OK ||
      construct(distance, lengths + literal_count, distance_count) != XAIOS_OK)
    return XAIOS_ERR_INVALID;
  return XAIOS_OK;
}

static xaios_status_t decode_codes(inflate_bits_t *stream,
                                   const inflate_huffman_t *literal,
                                   const inflate_huffman_t *distance,
                                   uint8_t *output, uint64_t capacity,
                                   uint64_t *used) {
  static const uint16_t length_base[29] = {
      3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27,
      31, 35, 43, 51, 59, 67, 83, 99, 115, 131, 163, 195, 227, 258};
  static const uint8_t length_extra[29] = {
      0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2,
      2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0};
  static const uint16_t distance_base[30] = {
      1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129,
      193, 257, 385, 513, 769, 1025, 1537, 2049, 3073, 4097,
      6145, 8193, 12289, 16385, 24577};
  static const uint8_t distance_extra[30] = {
      0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6,
      6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13, 13};
  for (;;) {
    uint32_t symbol = 0U;
    if (decode(stream, literal, &symbol) != XAIOS_OK)
      return XAIOS_ERR_INVALID;
    if (symbol < 256U) {
      if (*used >= capacity) return XAIOS_ERR_NO_MEMORY;
      output[(*used)++] = (uint8_t)symbol;
      continue;
    }
    if (symbol == 256U) return XAIOS_OK;
    if (symbol < 257U || symbol > 285U) return XAIOS_ERR_INVALID;
    uint32_t length_index = symbol - 257U;
    uint32_t extra = 0U;
    if (read_bits(stream, length_extra[length_index], &extra) != XAIOS_OK)
      return XAIOS_ERR_INVALID;
    uint32_t length = length_base[length_index] + extra;
    if (decode(stream, distance, &symbol) != XAIOS_OK || symbol >= 30U ||
        read_bits(stream, distance_extra[symbol], &extra) != XAIOS_OK)
      return XAIOS_ERR_INVALID;
    uint32_t back = distance_base[symbol] + extra;
    if (back > *used || length > capacity - *used) return XAIOS_ERR_INVALID;
    for (uint32_t i = 0U; i < length; ++i) {
      output[*used] = output[*used - back];
      ++(*used);
    }
  }
}

xaios_status_t xaios_inflate_raw(const uint8_t *input, uint64_t input_size,
                                 uint8_t *output, uint64_t output_capacity,
                                 uint64_t *output_size) {
  if (input == 0 || output == 0 || output_size == 0) return XAIOS_ERR_INVALID;
  inflate_bits_t stream = {input, input_size, 0U, 0U, 0U};
  uint64_t used = 0U;
  uint32_t final = 0U;
  do {
    uint32_t type = 0U;
    if (read_bits(&stream, 1U, &final) != XAIOS_OK ||
        read_bits(&stream, 2U, &type) != XAIOS_OK)
      return XAIOS_ERR_INVALID;
    if (type == 0U) {
      stream.bits = 0U;
      stream.count = 0U;
      if (stream.cursor + 4U > stream.size) return XAIOS_ERR_INVALID;
      uint32_t length = (uint32_t)stream.input[stream.cursor] |
                        ((uint32_t)stream.input[stream.cursor + 1U] << 8U);
      uint32_t inverse = (uint32_t)stream.input[stream.cursor + 2U] |
                         ((uint32_t)stream.input[stream.cursor + 3U] << 8U);
      stream.cursor += 4U;
      if ((length ^ UINT32_C(0xffff)) != inverse ||
          length > stream.size - stream.cursor || length > output_capacity - used)
        return XAIOS_ERR_INVALID;
      for (uint32_t i = 0U; i < length; ++i)
        output[used++] = stream.input[stream.cursor++];
    } else if (type == 1U || type == 2U) {
      inflate_huffman_t literal;
      inflate_huffman_t distance;
      xaios_status_t status = type == 1U ? build_fixed(&literal, &distance)
                                         : build_dynamic(&stream, &literal,
                                                         &distance);
      if (status != XAIOS_OK ||
          decode_codes(&stream, &literal, &distance, output, output_capacity,
                       &used) != XAIOS_OK)
        return XAIOS_ERR_INVALID;
    } else {
      return XAIOS_ERR_INVALID;
    }
  } while (final == 0U);
  *output_size = used;
  return XAIOS_OK;
}
