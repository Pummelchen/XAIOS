#include <xaios_user.h>

static int text_equal(const char *lhs, const char *rhs) {
  if (lhs == 0 || rhs == 0) return 0;
  while (*lhs != '\0' && *lhs == *rhs) {
    ++lhs;
    ++rhs;
  }
  return *lhs == *rhs;
}

int main(int argc, char **argv) {
  static const char usage[] =
      "pong: interactive terminal required; start pong from a local or SSH "
      "shell\ncontrols: W/S move, P pauses, R resets, Q quits; capped at 60 "
      "frames per second\n";
  const char *args = argc == 2 ? argv[1] : "";
  (void)xaios_console_write(usage, sizeof(usage) - 1U);
  return text_equal(args, "--help") ? 0 : 1;
}
