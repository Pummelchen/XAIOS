#include <xaios_user.h>

static void print(const char *text) {
  (void)xaios_console_write(text, xaios_strlen(text));
}

int main(int argc, char **argv) {
  print("xapt-test-app");
  for (int index = 1; index < argc; ++index) {
    print(" ");
    print(argv[index]);
  }
  print("\n");
  return 0;
}
