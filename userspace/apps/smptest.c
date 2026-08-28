#include <xaios_user.h>

#define USER_THREAD_COUNT 3ULL
#define USER_THREAD_STACK_BYTES 16384ULL

static unsigned char g_thread_stacks[USER_THREAD_COUNT][USER_THREAD_STACK_BYTES]
    __attribute__((aligned(16)));

static u64 user_thread_worker(void *opaque) {
  u64 ordinal = (u64)opaque;
  u64 value = (ordinal + 1ULL) * 0x100000001b3ULL;
  for (u64 i = 0; i < 4096ULL; ++i) {
    value ^= i + (ordinal << 12ULL);
    value *= 0x9e3779b185ebca87ULL;
  }
  return value;
}

int main(void) {
  u64 workers = 0;
  u64 checksum = 0;
  u64 threads = 0;
  u64 thread_checksum = 0;
  u64 user_thread_ids[USER_THREAD_COUNT];
  xaios_log("/bin/smptest: validating SMP-visible scheduler state\n");
  if (xaios_smp_run(4, 128, &workers, &checksum) < 0 || workers == 0 ||
      checksum == 0) {
    xaios_log("/bin/smptest: smp worker syscall failed\n");
    return 1;
  }
  if (xaios_thread_group_run(6, 256, &threads, &thread_checksum) < 0 ||
      threads != 6 || thread_checksum == 0) {
    xaios_log("/bin/smptest: user thread group syscall failed\n");
    return 1;
  }
  if (workers > 1ULL) {
    for (u64 i = 0; i < USER_THREAD_COUNT; ++i) {
      if (xaios_thread_create(user_thread_worker, (void *)i,
                              g_thread_stacks[i], USER_THREAD_STACK_BYTES,
                              XAIOS_THREAD_CPU_ANY, &user_thread_ids[i]) < 0) {
        xaios_log("/bin/smptest: EL0 thread create failed\n");
        return 1;
      }
    }
    for (u64 i = 0; i < USER_THREAD_COUNT; ++i) {
      u64 result = 0;
      /* Report which of the three things went wrong, because they mean
         different things and one message for all of them made a sighting
         unclassifiable. A join that returns an error under a saturated host is
         most likely the five-second timeout expiring -- the kernel logs
         "threads: user join timeout" when it does -- and says nothing about
         thread correctness. A join that succeeds and hands back the wrong
         value is a real defect. B-02 is one sighting that could have been
         either, and the log did not distinguish them. */
      int status = xaios_thread_join(user_thread_ids[i], 5000000000ULL,
                                     &result);
      if (status < 0) {
        xaios_log_u64("/bin/smptest: EL0 thread join failed thread=", i, "");
        xaios_log_u64(" status=", (u64)(long)status, "");
        xaios_log(" (a timeout here is host slowness, not a thread defect)\n");
        return 1;
      }
      u64 expected = user_thread_worker((void *)i);
      if (result != expected) {
        xaios_log_u64("/bin/smptest: EL0 thread result wrong thread=", i, "");
        xaios_log_u64(" expected=", expected, "");
        xaios_log_u64(" got=", result, "\n");
        return 1;
      }
    }
  } else {
    if (xaios_thread_create(user_thread_worker, 0, g_thread_stacks[0],
                            USER_THREAD_STACK_BYTES, XAIOS_THREAD_CPU_ANY,
                            &user_thread_ids[0]) >= 0) {
      xaios_log("/bin/smptest: uniprocessor thread rejection failed\n");
      return 1;
    }
    xaios_log("/bin/smptest: uniprocessor thread fallback passed\n");
  }
  u64 invalid_thread_id = 0;
  if (xaios_thread_create(user_thread_worker, 0, g_thread_stacks[0], 2048,
                          XAIOS_THREAD_CPU_ANY, &invalid_thread_id) >= 0 ||
      (workers > 1ULL &&
       xaios_thread_join(user_thread_ids[USER_THREAD_COUNT - 1ULL],
                         1000000ULL, &invalid_thread_id) >= 0)) {
    xaios_log("/bin/smptest: EL0 thread validation failed\n");
    return 1;
  }
  (void)xaios_osctl("osctl ps");
  xaios_log_u64("/bin/smptest: workers=", workers, "\n");
  xaios_log_u64("/bin/smptest: checksum=", checksum, "\n");
  xaios_log_u64("/bin/smptest: user_threads=", threads, "\n");
  xaios_log_u64("/bin/smptest: thread_checksum=", thread_checksum, "\n");
  xaios_log("/bin/smptest: app-requested SMP worker set passed\n");
  xaios_log("/bin/smptest: concurrent kernel-dispatched worker group passed\n");
  if (workers > 1ULL) {
    xaios_log("/bin/smptest: general EL0 create/join threads passed\n");
  }
  xaios_log("/bin/smptest: EL0 thread validation passed\n");
  xaios_log("/bin/smptest: complete\n");
  return 0;
}
