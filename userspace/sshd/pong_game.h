#ifndef XAIOS_PONG_GAME_H
#define XAIOS_PONG_GAME_H

#include <xaios/types.h>

#define PONG_MIN_COLUMNS 40U
#define PONG_MAX_COLUMNS 240U
#define PONG_MIN_ROWS 12U
#define PONG_MAX_ROWS 100U
#define PONG_FRAME_BYTES 32768U
#define PONG_MAX_FPS 60U

typedef struct pong_game {
  uint32_t active;
  uint32_t paused;
  uint32_t columns;
  uint32_t rows;
  uint32_t play_width;
  uint32_t play_height;
  uint32_t speed_basis_points;
  int32_t ball_x;
  int32_t ball_y;
  int32_t human_y;
  int32_t computer_y;
  int32_t computer_target_y;
  int32_t direction_x;
  int32_t direction_y;
  uint64_t human_wins;
  uint64_t computer_wins;
  uint64_t last_update_ns;
  uint64_t next_frame_ns;
  uint64_t next_computer_decision_ns;
  uint64_t serve_until_ns;
  uint32_t random_state;
} pong_game_t;

void pong_game_start(pong_game_t *game, uint32_t columns, uint32_t rows,
                     uint64_t now_ns);
void pong_game_resize(pong_game_t *game, uint32_t columns, uint32_t rows);
int pong_game_tick(pong_game_t *game, uint64_t now_ns);
int pong_game_input(pong_game_t *game, const uint8_t *input,
                    uint32_t input_size, uint32_t *should_exit,
                    uint64_t now_ns);
int pong_game_render(const pong_game_t *game, char *output,
                     uint32_t output_capacity, uint32_t *output_size,
                     uint64_t now_ns);

#endif
