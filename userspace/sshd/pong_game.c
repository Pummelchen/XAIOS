#include "pong_game.h"

#define PONG_FIXED_SHIFT 10U
#define PONG_FIXED_ONE (INT32_C(1) << PONG_FIXED_SHIFT)
#define PONG_PADDLE_HALF 2
#define PONG_FRAME_NS UINT64_C(33333334)
#define PONG_MAX_STEP_NS UINT64_C(50000000)
#define PONG_SERVE_DELAY_NS UINT64_C(700000000)
#define PONG_COMPUTER_DECISION_NS UINT64_C(160000000)
#define PONG_SPEED_INITIAL 10000U
#define PONG_SPEED_MIN 4000U
#define PONG_SPEED_MAX 30000U

typedef struct pong_output {
  char *data;
  uint32_t capacity;
  uint32_t used;
  int failed;
} pong_output_t;

static uint32_t pong_clamp_dimension(uint32_t value, uint32_t minimum,
                                     uint32_t maximum) {
  if (value < minimum) return minimum;
  if (value > maximum) return maximum;
  return value;
}

static int32_t pong_clamp_position(int32_t value, int32_t minimum,
                                   int32_t maximum) {
  if (value < minimum) return minimum;
  if (value > maximum) return maximum;
  return value;
}

static uint32_t pong_random(pong_game_t *game) {
  uint32_t value = game->random_state;
  value ^= value << 13U;
  value ^= value >> 17U;
  value ^= value << 5U;
  game->random_state = value == 0U ? UINT32_C(0x9e3779b9) : value;
  return game->random_state;
}

static void pong_append_bytes(pong_output_t *output, const char *data,
                              uint32_t length) {
  if (output->failed != 0 || length > output->capacity - output->used) {
    output->failed = 1;
    return;
  }
  for (uint32_t i = 0U; i < length; ++i)
    output->data[output->used++] = data[i];
}

static void pong_append_text(pong_output_t *output, const char *text) {
  uint32_t length = 0U;
  while (text[length] != '\0') ++length;
  pong_append_bytes(output, text, length);
}

static void pong_append_u64(pong_output_t *output, uint64_t value) {
  char digits[20];
  uint32_t count = 0U;
  do {
    digits[count++] = (char)('0' + value % 10U);
    value /= 10U;
  } while (value != 0U);
  while (count != 0U) {
    --count;
    pong_append_bytes(output, digits + count, 1U);
  }
}

static void pong_append_cursor(pong_output_t *output, uint32_t row) {
  pong_append_text(output, "\033[");
  pong_append_u64(output, row);
  pong_append_text(output, ";1H");
}

static uint32_t pong_line_text(char *line, uint32_t capacity, uint32_t used,
                               const char *text) {
  while (*text != '\0' && used < capacity) line[used++] = *text++;
  return used;
}

static uint32_t pong_line_u64(char *line, uint32_t capacity, uint32_t used,
                              uint64_t value) {
  char digits[20];
  uint32_t count = 0U;
  do {
    digits[count++] = (char)('0' + value % 10U);
    value /= 10U;
  } while (value != 0U);
  while (count != 0U && used < capacity) line[used++] = digits[--count];
  return used;
}

static void pong_append_line(pong_output_t *output, uint32_t row,
                             const char *line, uint32_t length,
                             uint32_t columns, const char *color) {
  pong_append_cursor(output, row);
  pong_append_text(output, color);
  if (length > columns) length = columns;
  pong_append_bytes(output, line, length);
  for (uint32_t i = length; i < columns; ++i)
    pong_append_bytes(output, " ", 1U);
  pong_append_text(output, "\033[0m");
}

static int32_t pong_horizontal_speed(const pong_game_t *game) {
  uint64_t base = (uint64_t)game->play_width * PONG_FIXED_ONE / 6U;
  uint64_t scaled = base * game->speed_basis_points / PONG_SPEED_INITIAL;
  if (scaled < 8U * PONG_FIXED_ONE) scaled = 8U * PONG_FIXED_ONE;
  return (int32_t)scaled;
}

static int32_t pong_vertical_speed(const pong_game_t *game) {
  uint64_t base = (uint64_t)game->play_height * PONG_FIXED_ONE / 5U;
  uint64_t scaled = base * game->speed_basis_points / PONG_SPEED_INITIAL;
  if (scaled < 4U * PONG_FIXED_ONE) scaled = 4U * PONG_FIXED_ONE;
  return (int32_t)scaled;
}

static int32_t pong_reflect_y(int64_t value, int32_t maximum) {
  int64_t period = (int64_t)maximum * 2;
  if (maximum <= 0) return 0;
  value %= period;
  if (value < 0) value += period;
  if (value > maximum) value = period - value;
  return (int32_t)value;
}

static void pong_reset_ball(pong_game_t *game, int human_scored,
                            uint64_t now_ns) {
  game->ball_x = (int32_t)(game->play_width - 1U) * PONG_FIXED_ONE / 2;
  game->ball_y = (int32_t)(game->play_height - 1U) * PONG_FIXED_ONE / 2;
  if (game->play_height > 8U) {
    int32_t variation = (int32_t)(pong_random(game) % 5U) - 2;
    game->ball_y += variation * PONG_FIXED_ONE;
  }
  game->ball_y = pong_clamp_position(
      game->ball_y, 0,
      (int32_t)(game->play_height - 1U) * PONG_FIXED_ONE);
  game->direction_x = human_scored != 0 ? 1 : -1;
  game->direction_y = (pong_random(game) & 1U) != 0U ? 1 : -1;
  game->serve_until_ns = now_ns > UINT64_MAX - PONG_SERVE_DELAY_NS
                             ? UINT64_MAX
                             : now_ns + PONG_SERVE_DELAY_NS;
}

static void pong_reset_match(pong_game_t *game, uint64_t now_ns) {
  game->human_wins = 0U;
  game->computer_wins = 0U;
  game->speed_basis_points = PONG_SPEED_INITIAL;
  game->human_y = (int32_t)(game->play_height - 1U) * PONG_FIXED_ONE / 2;
  game->computer_y = game->human_y;
  game->computer_target_y = game->computer_y;
  pong_reset_ball(game, 0, now_ns);
}

void pong_game_start(pong_game_t *game, uint32_t columns, uint32_t rows,
                     uint64_t now_ns) {
  uint8_t *bytes = (uint8_t *)game;
  for (uint32_t i = 0U; i < sizeof(*game); ++i) bytes[i] = 0U;
  game->active = 1U;
  game->columns = pong_clamp_dimension(columns, PONG_MIN_COLUMNS,
                                       PONG_MAX_COLUMNS);
  game->rows = pong_clamp_dimension(rows, PONG_MIN_ROWS, PONG_MAX_ROWS);
  game->play_width = game->columns - 2U;
  game->play_height = game->rows - 4U;
  game->random_state = (uint32_t)now_ns ^ UINT32_C(0x5841494f);
  if (game->random_state == 0U) game->random_state = UINT32_C(0x9e3779b9);
  game->last_update_ns = now_ns;
  game->next_frame_ns = now_ns;
  game->next_computer_decision_ns = now_ns;
  pong_reset_match(game, now_ns);
}

void pong_game_resize(pong_game_t *game, uint32_t columns, uint32_t rows) {
  if (game == 0 || game->active == 0U) return;
  uint32_t old_width = game->play_width;
  uint32_t old_height = game->play_height;
  game->columns = pong_clamp_dimension(columns, PONG_MIN_COLUMNS,
                                       PONG_MAX_COLUMNS);
  game->rows = pong_clamp_dimension(rows, PONG_MIN_ROWS, PONG_MAX_ROWS);
  game->play_width = game->columns - 2U;
  game->play_height = game->rows - 4U;
  if (old_width != 0U) {
    game->ball_x = (int32_t)((int64_t)game->ball_x * game->play_width /
                             old_width);
  }
  if (old_height != 0U) {
    game->ball_y = (int32_t)((int64_t)game->ball_y * game->play_height /
                             old_height);
    game->human_y = (int32_t)((int64_t)game->human_y * game->play_height /
                              old_height);
    game->computer_y =
        (int32_t)((int64_t)game->computer_y * game->play_height / old_height);
  }
  int32_t maximum_y = (int32_t)(game->play_height - 1U) * PONG_FIXED_ONE;
  game->ball_x = pong_clamp_position(
      game->ball_x, 0,
      (int32_t)(game->play_width - 1U) * PONG_FIXED_ONE);
  game->ball_y = pong_clamp_position(game->ball_y, 0, maximum_y);
  game->human_y = pong_clamp_position(game->human_y,
                                      PONG_PADDLE_HALF * PONG_FIXED_ONE,
                                      maximum_y -
                                          PONG_PADDLE_HALF * PONG_FIXED_ONE);
  game->computer_y = pong_clamp_position(
      game->computer_y, PONG_PADDLE_HALF * PONG_FIXED_ONE,
      maximum_y - PONG_PADDLE_HALF * PONG_FIXED_ONE);
  game->next_frame_ns = 0U;
}

static void pong_computer_decide(pong_game_t *game, uint64_t now_ns) {
  if (now_ns < game->next_computer_decision_ns) return;
  int32_t maximum_y = (int32_t)(game->play_height - 1U) * PONG_FIXED_ONE;
  int32_t target = maximum_y / 2;
  if (game->direction_x > 0) {
    int32_t distance =
        (int32_t)(game->play_width - 3U) * PONG_FIXED_ONE - game->ball_x;
    if (distance < 0) distance = 0;
    int32_t horizontal = pong_horizontal_speed(game);
    int32_t vertical = pong_vertical_speed(game) * game->direction_y;
    int64_t projected = game->ball_y;
    if (horizontal != 0)
      projected += (int64_t)vertical * distance / horizontal;
    target = pong_reflect_y(projected, maximum_y);
    target += ((int32_t)(pong_random(game) % 9U) - 4) * PONG_FIXED_ONE;
  }
  game->computer_target_y = pong_clamp_position(
      target, PONG_PADDLE_HALF * PONG_FIXED_ONE,
      maximum_y - PONG_PADDLE_HALF * PONG_FIXED_ONE);
  game->next_computer_decision_ns =
      now_ns > UINT64_MAX - PONG_COMPUTER_DECISION_NS
          ? UINT64_MAX
          : now_ns + PONG_COMPUTER_DECISION_NS;
}

static void pong_move_computer(pong_game_t *game, uint64_t elapsed_ns) {
  int32_t difference = game->computer_target_y - game->computer_y;
  int64_t speed = (int64_t)game->play_height * PONG_FIXED_ONE * 2 / 7;
  int32_t step = (int32_t)(speed * (int64_t)elapsed_ns / INT64_C(1000000000));
  if (step < 1) step = 1;
  if (difference > step) game->computer_y += step;
  else if (difference < -step) game->computer_y -= step;
  else game->computer_y = game->computer_target_y;
}

static int pong_paddle_hit(int32_t ball_y, int32_t paddle_y) {
  int32_t reach = (PONG_PADDLE_HALF + 1) * PONG_FIXED_ONE;
  int32_t difference = ball_y - paddle_y;
  return difference >= -reach && difference <= reach;
}

static void pong_record_score(pong_game_t *game, int human_scored,
                              uint64_t now_ns) {
  if (human_scored != 0) {
    if (game->human_wins != UINT64_MAX) ++game->human_wins;
    uint64_t adjusted =
        ((uint64_t)game->speed_basis_points * 101U + 50U) / 100U;
    game->speed_basis_points = adjusted > PONG_SPEED_MAX
                                   ? PONG_SPEED_MAX
                                   : (uint32_t)adjusted;
  } else {
    if (game->computer_wins != UINT64_MAX) ++game->computer_wins;
    uint64_t adjusted =
        ((uint64_t)game->speed_basis_points * 99U + 50U) / 100U;
    game->speed_basis_points = adjusted < PONG_SPEED_MIN
                                   ? PONG_SPEED_MIN
                                   : (uint32_t)adjusted;
  }
  pong_reset_ball(game, human_scored, now_ns);
}

int pong_game_tick(pong_game_t *game, uint64_t now_ns) {
  if (game == 0 || game->active == 0U) return 0;
  if (now_ns < game->last_update_ns) game->last_update_ns = now_ns;
  uint64_t elapsed_ns = now_ns - game->last_update_ns;
  game->last_update_ns = now_ns;
  if (elapsed_ns > PONG_MAX_STEP_NS) elapsed_ns = PONG_MAX_STEP_NS;
  pong_computer_decide(game, now_ns);
  pong_move_computer(game, elapsed_ns);
  if (game->paused == 0U && now_ns >= game->serve_until_ns && elapsed_ns != 0U) {
    int32_t previous_x = game->ball_x;
    int32_t horizontal = pong_horizontal_speed(game) * game->direction_x;
    int32_t vertical = pong_vertical_speed(game) * game->direction_y;
    game->ball_x += (int32_t)((int64_t)horizontal * (int64_t)elapsed_ns /
                              INT64_C(1000000000));
    game->ball_y += (int32_t)((int64_t)vertical * (int64_t)elapsed_ns /
                              INT64_C(1000000000));
    int32_t maximum_y = (int32_t)(game->play_height - 1U) * PONG_FIXED_ONE;
    if (game->ball_y < 0) {
      game->ball_y = -game->ball_y;
      game->direction_y = 1;
    } else if (game->ball_y > maximum_y) {
      game->ball_y = maximum_y - (game->ball_y - maximum_y);
      game->direction_y = -1;
    }
    int32_t left_plane = 2 * PONG_FIXED_ONE;
    int32_t right_plane =
        (int32_t)(game->play_width - 3U) * PONG_FIXED_ONE;
    if (game->direction_x < 0 && previous_x >= left_plane &&
        game->ball_x <= left_plane &&
        pong_paddle_hit(game->ball_y, game->human_y)) {
      game->ball_x = left_plane + (left_plane - game->ball_x);
      game->direction_x = 1;
      game->direction_y = game->ball_y < game->human_y ? -1 : 1;
    } else if (game->direction_x > 0 && previous_x <= right_plane &&
               game->ball_x >= right_plane &&
               pong_paddle_hit(game->ball_y, game->computer_y)) {
      game->ball_x = right_plane - (game->ball_x - right_plane);
      game->direction_x = -1;
      game->direction_y = game->ball_y < game->computer_y ? -1 : 1;
    }
    if (game->ball_x < -PONG_FIXED_ONE) {
      pong_record_score(game, 0, now_ns);
    } else if (game->ball_x >
               (int32_t)game->play_width * PONG_FIXED_ONE) {
      pong_record_score(game, 1, now_ns);
    }
  }
  if (now_ns < game->next_frame_ns) return 0;
  game->next_frame_ns = now_ns > UINT64_MAX - PONG_FRAME_NS
                            ? UINT64_MAX
                            : now_ns + PONG_FRAME_NS;
  return 1;
}

int pong_game_input(pong_game_t *game, const uint8_t *input,
                    uint32_t input_size, uint32_t *should_exit,
                    uint64_t now_ns) {
  if (game == 0 || input == 0 || should_exit == 0 || game->active == 0U)
    return -1;
  *should_exit = 0U;
  int32_t maximum_y = (int32_t)(game->play_height - 1U) * PONG_FIXED_ONE;
  for (uint32_t i = 0U; i < input_size; ++i) {
    uint8_t key = input[i];
    if (key == 'q' || key == 'Q' || key == 3U) {
      *should_exit = 1U;
      game->active = 0U;
      return 0;
    }
    if (key == 'w' || key == 'W') {
      game->human_y -= 2 * PONG_FIXED_ONE;
    } else if (key == 's' || key == 'S') {
      game->human_y += 2 * PONG_FIXED_ONE;
    } else if (key == 'p' || key == 'P' || key == ' ') {
      game->paused ^= 1U;
      game->last_update_ns = now_ns;
    } else if (key == 'r' || key == 'R') {
      pong_reset_match(game, now_ns);
    }
  }
  game->human_y = pong_clamp_position(
      game->human_y, PONG_PADDLE_HALF * PONG_FIXED_ONE,
      maximum_y - PONG_PADDLE_HALF * PONG_FIXED_ONE);
  game->next_frame_ns = 0U;
  return 0;
}

int pong_game_render(const pong_game_t *game, char *output,
                     uint32_t output_capacity, uint32_t *output_size,
                     uint64_t now_ns) {
  if (game == 0 || output == 0 || output_size == 0 || game->active == 0U ||
      output_capacity < 64U) return -1;
  pong_output_t writer = {output, output_capacity, 0U, 0};
  char line[PONG_MAX_COLUMNS];
  uint32_t used = 0U;
  pong_append_text(&writer, "\033[2J\033[H\033[?25l");
  used = pong_line_text(line, game->columns, used, " PONG  Human wins: ");
  used = pong_line_u64(line, game->columns, used, game->human_wins);
  used = pong_line_text(line, game->columns, used, "  Computer wins: ");
  used = pong_line_u64(line, game->columns, used, game->computer_wins);
  pong_append_line(&writer, 1U, line, used, game->columns, "\033[44;97m");

  used = 0U;
  used = pong_line_text(line, game->columns, used, " Speed: ");
  used = pong_line_u64(line, game->columns, used,
                       game->speed_basis_points / 100U);
  if (used < game->columns) line[used++] = '.';
  uint32_t fraction = game->speed_basis_points % 100U;
  if (used < game->columns) line[used++] = (char)('0' + fraction / 10U);
  if (used < game->columns) line[used++] = (char)('0' + fraction % 10U);
  used = pong_line_text(line, game->columns, used,
                        "%  W/S move  P pause  R reset  Q quit");
  if (game->paused != 0U) {
    used = pong_line_text(line, game->columns, used, "  [PAUSED]");
  } else if (now_ns < game->serve_until_ns) {
    used = pong_line_text(line, game->columns, used, "  [SERVE]");
  }
  pong_append_line(&writer, 2U, line, used, game->columns, "\033[30;106m");

  line[0] = '+';
  for (uint32_t x = 1U; x + 1U < game->columns; ++x) line[x] = '-';
  line[game->columns - 1U] = '+';
  pong_append_line(&writer, 3U, line, game->columns, game->columns,
                   "\033[36m");

  uint32_t ball_x = (uint32_t)(game->ball_x < 0 ? 0 : game->ball_x) /
                    PONG_FIXED_ONE;
  uint32_t ball_y = (uint32_t)(game->ball_y < 0 ? 0 : game->ball_y) /
                    PONG_FIXED_ONE;
  uint32_t human_y = (uint32_t)game->human_y / PONG_FIXED_ONE;
  uint32_t computer_y = (uint32_t)game->computer_y / PONG_FIXED_ONE;
  for (uint32_t y = 0U; y < game->play_height; ++y) {
    line[0] = '|';
    for (uint32_t x = 0U; x < game->play_width; ++x) {
      char value = ' ';
      if (x == 1U && y + PONG_PADDLE_HALF >= human_y &&
          y <= human_y + PONG_PADDLE_HALF) {
        value = '#';
      } else if (x + 2U == game->play_width &&
                 y + PONG_PADDLE_HALF >= computer_y &&
                 y <= computer_y + PONG_PADDLE_HALF) {
        value = '#';
      } else if (x == ball_x && y == ball_y) {
        value = 'O';
      } else if (x == game->play_width / 2U && (y & 1U) == 0U) {
        value = ':';
      }
      line[x + 1U] = value;
    }
    line[game->columns - 1U] = '|';
    pong_append_line(&writer, y + 4U, line, game->columns, game->columns,
                     "\033[37m");
  }
  line[0] = '+';
  for (uint32_t x = 1U; x + 1U < game->columns; ++x) line[x] = '-';
  line[game->columns - 1U] = '+';
  pong_append_line(&writer, game->rows, line, game->columns, game->columns,
                   "\033[36m");
  pong_append_text(&writer, "\033[0m\033[?25l");
  if (writer.failed != 0) return -1;
  *output_size = writer.used;
  return 0;
}
