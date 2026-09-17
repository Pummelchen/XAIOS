/*
 * Private interface between gpt.c and gpt_write.c: the on-disk header
 * constants both directions sign, and the four byte and geometry primitives
 * the reader and the writer share.
 *
 * Split out of a 625-line gpt.c. gpt.c keeps the GUID text API, the table
 * reader, its CRC and geometry validation, and -- defined once and nowhere
 * else -- the primitives declared below; the write path moves to gpt_write.c.
 * Nothing here owns state the module did not already own: no file-scope
 * object crosses the split, and the write order is unchanged.
 */

#ifndef XAIOS_KERNEL_STORAGE_GPT_INTERNAL_H
#define XAIOS_KERNEL_STORAGE_GPT_INTERNAL_H

#include <xaios/gpt.h>

/* The header layout both the reader and the writer agree on. */
#define GPT_HEADER_SIZE 92U
#define GPT_REVISION UINT32_C(0x00010000)
#define GPT_SIGNATURE "EFI PART"

/* Defined once, in gpt.c. */
void gpt_bytes_zero(void *buffer, uint64_t length);
void gpt_bytes_copy(void *destination, const void *source, uint64_t length);
void gpt_write_u32(uint8_t *bytes, uint32_t value);
int gpt_valid_geometry(const xaios_block_device_info_t *info);

#endif
