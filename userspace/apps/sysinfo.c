#include <xaios_user.h>

int main(void) {
  xaios_log("/bin/sysinfo: legacy utility; use xaiosctl status and xaiosctl "
            "hardware for measured state\n");
  xaios_log_u64("/bin/sysinfo: monotonic_nanos=", xaios_clock_nanos(), "\n");
  xaios_log("/bin/sysinfo: complete\n");
  return 0;
}
