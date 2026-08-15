#ifndef XAIOS_INPUT_H
#define XAIOS_INPUT_H

#include <xaios/types.h>

/* Console input is intentionally byte-oriented so serial and USB HID share it. */
void input_init(void);
int input_read_char(uint8_t *value);
uint32_t input_keyboard_available(void);
void input_self_test(void);

#endif
