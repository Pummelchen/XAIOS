#include "pong_game.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#define Q (1 << 10)

int main(void) {
  pong_game_t game;
  char frame[PONG_FRAME_BYTES];
  uint32_t frame_size = 0U;
  uint32_t should_exit = 0U;
  uint64_t now = UINT64_C(1000000000);

  pong_game_start(&game, 80U, 24U, now);
  assert(game.active == 1U);
  assert(game.speed_basis_points == 10000U);
  assert(game.play_width == 78U && game.play_height == 20U);
  assert(pong_game_tick(&game, now) == 1);
  assert(game.next_frame_ns - now == UINT64_C(16666667));
  assert(pong_game_tick(&game, now + UINT64_C(16666666)) == 0);
  assert(pong_game_tick(&game, now + UINT64_C(16666667)) == 1);

  int32_t original_human = game.human_y;
  assert(pong_game_input(&game, (const uint8_t *)"w", 1U, &should_exit,
                         now) == 0);
  assert(game.human_y < original_human && should_exit == 0U);
  assert(pong_game_input(&game, (const uint8_t *)"s", 1U, &should_exit,
                         now) == 0);
  assert(game.human_y == original_human);

  game.serve_until_ns = 0U;
  game.ball_x = 2 * Q + Q / 2;
  game.ball_y = game.human_y;
  game.direction_x = -1;
  game.direction_y = 1;
  assert(pong_game_tick(&game, now + UINT64_C(66666667)) == 1);
  assert(game.direction_x == 1);

  game.serve_until_ns = 0U;
  game.ball_x = (int32_t)game.play_width * Q + Q;
  game.direction_x = 1;
  assert(pong_game_tick(&game, now + UINT64_C(100000000)) == 1);
  assert(game.human_wins == 1U);
  assert(game.speed_basis_points == 10100U);

  now += UINT64_C(1100000000);
  game.serve_until_ns = 0U;
  game.ball_x = -Q - 1;
  game.direction_x = -1;
  assert(pong_game_tick(&game, now) == 1);
  assert(game.computer_wins == 1U);
  assert(game.speed_basis_points == 9999U);

  assert(pong_game_render(&game, frame, sizeof(frame), &frame_size, now) == 0);
  assert(frame_size != 0U && frame_size < sizeof(frame));
  frame[frame_size] = '\0';
  assert(strstr(frame, "PONG  Human wins: 1  Computer wins: 1") != NULL);
  assert(strstr(frame, "Speed: 99.99%") != NULL);
  assert(strstr(frame, "W/S move") != NULL);

  for (uint32_t i = 0U; i < 240U; ++i) {
    game.serve_until_ns = 0U;
    game.ball_x = (int32_t)game.play_width * Q + Q;
    game.direction_x = 1;
    assert(pong_game_tick(&game, ++now) >= 0);
  }
  assert(game.speed_basis_points == 30000U);
  for (uint32_t i = 0U; i < 240U; ++i) {
    game.serve_until_ns = 0U;
    game.ball_x = -Q - 1;
    game.direction_x = -1;
    assert(pong_game_tick(&game, ++now) >= 0);
  }
  assert(game.speed_basis_points == 4000U);
  game.human_wins = UINT64_MAX;
  game.serve_until_ns = 0U;
  game.ball_x = (int32_t)game.play_width * Q + Q;
  game.direction_x = 1;
  assert(pong_game_tick(&game, ++now) >= 0);
  assert(game.human_wins == UINT64_MAX);

  assert(pong_game_input(&game, (const uint8_t *)"r", 1U, &should_exit,
                         now) == 0);
  assert(game.human_wins == 0U && game.computer_wins == 0U);
  assert(game.speed_basis_points == 10000U);

  pong_game_resize(&game, 20U, 8U);
  assert(game.columns == PONG_MIN_COLUMNS && game.rows == PONG_MIN_ROWS);
  assert(pong_game_input(&game, (const uint8_t *)"q", 1U, &should_exit,
                         now) == 0);
  assert(should_exit == 1U && game.active == 0U);

  puts("pong-game: physics, adaptive scoring, controls and rendering passed");
  return 0;
}
