#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <zlib.h>

#include <xaios/inflate.h>

static void check_level(const uint8_t *input, size_t input_size, int level) {
  uint8_t compressed[8192];
  uint8_t decoded[8192];
  z_stream stream;
  memset(&stream, 0, sizeof(stream));
  assert(deflateInit2(&stream, level, Z_DEFLATED, -15, 8,
                      Z_DEFAULT_STRATEGY) == Z_OK);
  stream.next_in = (Bytef *)input;
  stream.avail_in = (uInt)input_size;
  stream.next_out = compressed;
  stream.avail_out = sizeof(compressed);
  assert(deflate(&stream, Z_FINISH) == Z_STREAM_END);
  size_t compressed_size = sizeof(compressed) - stream.avail_out;
  assert(deflateEnd(&stream) == Z_OK);

  uint64_t decoded_size = 0U;
  assert(xaios_inflate_raw(compressed, compressed_size, decoded,
                           sizeof(decoded), &decoded_size) == XAIOS_OK);
  assert(decoded_size == input_size);
  assert(memcmp(decoded, input, input_size) == 0);
  assert(xaios_inflate_raw(compressed, compressed_size - 1U, decoded,
                           sizeof(decoded), &decoded_size) != XAIOS_OK);
}

int main(void) {
  uint8_t input[4096];
  uint32_t state = UINT32_C(0x12345678);
  for (size_t i = 0U; i < sizeof(input); ++i) {
    state = state * UINT32_C(1664525) + UINT32_C(1013904223);
    input[i] = (uint8_t)(' ' + state % 95U);
  }
  check_level(input, sizeof(input), 0);
  check_level(input, sizeof(input), 1);
  check_level(input, sizeof(input), 6);
  puts("inflate: stored, fixed/dynamic and truncation tests passed");
  return 0;
}
