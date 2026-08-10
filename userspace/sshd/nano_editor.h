#ifndef XAIOS_NANO_EDITOR_H
#define XAIOS_NANO_EDITOR_H

#include <xaios/types.h>

#define NANO_EDITOR_PATH_MAX 256U
#define NANO_EDITOR_BUFFER_SIZE 32768U
#define NANO_EDITOR_STATUS_SIZE 96U

typedef struct nano_editor {
  uint32_t active;
  uint32_t dirty;
  uint32_t confirm_exit;
  uint32_t escape_state;
  uint32_t ignore_lf;
  uint32_t columns;
  uint32_t rows;
  uint32_t cursor;
  uint32_t length;
  uint32_t viewport_line;
  uint32_t viewport_column;
  char path[NANO_EDITOR_PATH_MAX];
  char status[NANO_EDITOR_STATUS_SIZE];
  uint8_t data[NANO_EDITOR_BUFFER_SIZE];
} nano_editor_t;

int nano_editor_open(nano_editor_t *editor, const char *argument,
                     const char *cwd, uint32_t columns, uint32_t rows);
int nano_editor_render(nano_editor_t *editor, char *output,
                       uint32_t output_capacity, uint32_t *output_size);
int nano_editor_input(nano_editor_t *editor, const uint8_t *input,
                      uint32_t input_size, uint32_t *should_exit);
void nano_editor_resize(nano_editor_t *editor, uint32_t columns,
                        uint32_t rows);

#endif
