#ifndef XAIOS_LESS_PAGER_H
#define XAIOS_LESS_PAGER_H

#include <xaios/types.h>

#define LESS_PAGER_PATH_MAX 256U
#define LESS_PAGER_QUERY_MAX 64U

typedef struct less_pager {
  uint32_t active;
  uint32_t number_lines;
  uint32_t columns;
  uint32_t rows;
  uint32_t top_line;
  uint32_t total_lines;
  uint32_t search_mode;
  uint32_t query_length;
  uint32_t escape_state;
  int fd;
  uint64_t size;
  char path[LESS_PAGER_PATH_MAX];
  char query[LESS_PAGER_QUERY_MAX];
} less_pager_t;

int less_pager_open(less_pager_t *pager, const char *command, const char *cwd,
                    uint32_t columns, uint32_t rows);
int less_pager_render(less_pager_t *pager, char *output,
                      uint32_t output_capacity, uint32_t *output_size);
int less_pager_input(less_pager_t *pager, const uint8_t *input,
                     uint32_t input_size, uint32_t *should_exit);
void less_pager_resize(less_pager_t *pager, uint32_t columns, uint32_t rows);
void less_pager_close(less_pager_t *pager);

#endif
