#include <xaios_user.h>

int main(void) {
  volatile u64 *unmapped = (volatile u64 *)0x1000ULL;
  xaios_log("/bin/app-crash: triggering intentional user page fault\n");
  return (int)*unmapped;
}
