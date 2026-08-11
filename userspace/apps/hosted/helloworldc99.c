#include <stdio.h>

#if __STDC_HOSTED__ != 1
#error "helloworldc99 requires the XAIOS hosted libc"
#endif

#if __STDC_VERSION__ != 199901L
#error "helloworldc99 must be compiled as ISO C99"
#endif

int main(void) {
  if (printf("/bin/helloworldc99: Hello, World!\n") < 0) return 1;
  if (printf("/bin/helloworldc99: hosted ISO C99 libc application\n") < 0) {
    return 1;
  }
  return fflush(stdout) == 0 ? 0 : 1;
}
