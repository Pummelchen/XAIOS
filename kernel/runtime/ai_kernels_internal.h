/* Private interface shared by the split modules of the AI kernel file.
 *
 * ai_kernels.c was split so no source file exceeds 500 lines. The packed
 * INT4/INT6 word decode helpers and the accumulator narrowing helper stay in
 * ai_kernels.c, beside the attention, RoPE and self-test kernels; the matrix
 * kernels, the quantization dispatcher and the work-unit entrypoints move to
 * ai_kernels_matmul.c; the FP16 conversion, the quantise/dequantise entry
 * points and the self-test fixture packers move to ai_kernels_quant.c.
 *
 * Everything that crosses a file boundary is declared here under an
 * ai_kernels_ prefix, because generic names such as unpack_int4 and bytes_zero
 * already exist as file-local symbols elsewhere in the kernel and a bare
 * exported name would collide at link time.
 */
#ifndef XAIOS_RUNTIME_AI_KERNELS_INTERNAL_H
#define XAIOS_RUNTIME_AI_KERNELS_INTERNAL_H

#include <xaios/ai_kernels.h>
#include <xaios/types.h>

/* Packed word decode, defined once in ai_kernels.c. Values are unpacked only
 * while resident in the inner dot product; complete matrices are never
 * expanded into temporary buffers. */
int8_t ai_kernels_unpack_int4(const uint8_t *packed, uint64_t index);
int8_t ai_kernels_unpack_int6(const uint8_t *packed, uint64_t index);
int32_t ai_kernels_narrow_accumulator(int64_t value);

/* FP16 bit conversion, defined once in ai_kernels_quant.c. */
float ai_kernels_fp16_from_bits(uint16_t bits);
uint16_t ai_kernels_fp16_to_bits(float value);

/* Self-test fixture packers, defined once in ai_kernels_quant.c. */
void ai_kernels_pack_int4_fixture(const int8_t *values, uint32_t count,
                                  uint8_t *packed);
void ai_kernels_pack_int6_fixture(const int8_t *values, uint32_t count,
                                  uint8_t *packed);

#endif /* XAIOS_RUNTIME_AI_KERNELS_INTERNAL_H */
