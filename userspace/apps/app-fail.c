#include <xaios_user.h>

int main(void) {
  xaios_log("/bin/app-fail: intentional exit status 42\n");
  return 42;
}
