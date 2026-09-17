/*
 * Declarations shared between the screen framework's translation units.
 *
 * The grid model, the painter and the presenter stay in xaios_screen.c; the
 * key decoder moved to xaios_screen_input.c. The UTF-8 lead-byte length both
 * halves need is defined once, in xaios_screen.c, and named here rather than
 * in the public header, which is for callers outside this directory.
 */

#ifndef XAIOS_USERSPACE_LIB_XAIOS_SCREEN_INTERNAL_H
#define XAIOS_USERSPACE_LIB_XAIOS_SCREEN_INTERNAL_H

#include <xaios_screen.h>

/* Bytes in the UTF-8 sequence a lead byte starts: 1, 2, 3 or 4. */
uint32_t xaios_screen_utf8_length(uint8_t lead);

#endif
