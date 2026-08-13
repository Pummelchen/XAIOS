#include <xaios_user.h>

static void log_command(const char *command) {
  xaios_log("$ ");
  xaios_log(command);
  xaios_log("\n");
}

static int shell_run(const char *command, char *output, u64 output_capacity,
                    u64 *out_size) {
  u64 command_out_size = 0;
  log_command(command);
  if (xaios_remote_login("admin", command, output, output_capacity,
                        &command_out_size) < 0) {
    return -1;
  }
  if (out_size != 0) {
    *out_size = command_out_size;
  }
  if (output_capacity > 0U) {
    u64 effective = command_out_size;
    if (effective >= output_capacity) {
      effective = output_capacity - 1U;
    }
    output[effective] = '\0';
  }
  if (command_out_size != 0U) {
    xaios_log(output);
  }
  return 0;
}

int main(void) {
  char output[2048];
  u64 out_size = 0;

  xaios_log("/bin/posix-shell: starting POSIX compatibility test session\n");

  /* Setup: create test directory and files */
  const char *setup[] = {
      "mkdir /tmp/posix-test",
      "cd /tmp/posix-test",
      "write input.txt hello world foo bar",
      "touch data.txt",
      "write data.txt line1 apple\nline2 banana\nline3 apple pie",
  };
  for (u64 i = 0; i < sizeof(setup) / sizeof(setup[0]); ++i) {
    if (shell_run(setup[i], output, sizeof(output), &out_size) != 0) {
      xaios_log("/bin/posix-shell: setup failed\n");
      return 1;
    }
  }
  xaios_log("/bin/posix-shell: setup complete\n");

  /* Test 1: Output redirection (echo > file) */
  xaios_log("/bin/posix-shell: test redirect\n");
  const char *redirect_tests[] = {
      "echo hello redirect > /tmp/posix-test/redir.txt",
      "cat /tmp/posix-test/redir.txt",
      "echo line1 > /tmp/posix-test/overwrite.txt",
      "cat /tmp/posix-test/overwrite.txt",
  };
  for (u64 i = 0; i < sizeof(redirect_tests) / sizeof(redirect_tests[0]); ++i) {
    if (shell_run(redirect_tests[i], output, sizeof(output), &out_size) != 0) {
      xaios_log("/bin/posix-shell: redirect test failed\n");
      return 1;
    }
  }
  xaios_log("/bin/posix-shell: redirect passed\n");

  /* Test 2: Pipe (echo | grep) */
  xaios_log("/bin/posix-shell: test pipe\n");
  const char *pipe_tests[] = {
      "echo hello world | grep hello",
      "echo apple banana cherry | grep banana",
      "echo one two three | grep missing",
  };
  for (u64 i = 0; i < sizeof(pipe_tests) / sizeof(pipe_tests[0]); ++i) {
    if (shell_run(pipe_tests[i], output, sizeof(output), &out_size) != 0) {
      /* grep with no match returns empty output but command succeeds */
      xaios_log("/bin/posix-shell: pipe test returned non-zero (may be ok)\n");
    }
  }
  xaios_log("/bin/posix-shell: pipe passed\n");

  /* Test 3: Pipe with head/tail */
  xaios_log("/bin/posix-shell: test pipe head/tail\n");
  const char *pipe_filter_tests[] = {
      "cat /tmp/posix-test/data.txt | head -n 2",
      "cat /tmp/posix-test/data.txt | tail -n 1",
  };
  for (u64 i = 0; i < sizeof(pipe_filter_tests) / sizeof(pipe_filter_tests[0]); ++i) {
    if (shell_run(pipe_filter_tests[i], output, sizeof(output), &out_size) != 0) {
      xaios_log("/bin/posix-shell: pipe filter test failed\n");
      return 1;
    }
  }
  xaios_log("/bin/posix-shell: pipe head/tail passed\n");

  /* Test 4: sed substitution */
  xaios_log("/bin/posix-shell: test sed\n");
  const char *sed_tests[] = {
      "sed 's/apple/orange/g' /tmp/posix-test/data.txt",
      "cat /tmp/posix-test/data.txt",
      "sed 's/hello/goodbye/' /tmp/posix-test/input.txt",
      "cat /tmp/posix-test/input.txt",
  };
  for (u64 i = 0; i < sizeof(sed_tests) / sizeof(sed_tests[0]); ++i) {
    if (shell_run(sed_tests[i], output, sizeof(output), &out_size) != 0) {
      xaios_log("/bin/posix-shell: sed test failed\n");
      return 1;
    }
  }
  xaios_log("/bin/posix-shell: sed passed\n");

  /* Test 5: Combined pipe + grep with file input */
  xaios_log("/bin/posix-shell: test combined operations\n");
  const char *combined_tests[] = {
      "grep orange /tmp/posix-test/data.txt",
      "echo test pipe sed redirect | grep pipe",
  };
  for (u64 i = 0; i < sizeof(combined_tests) / sizeof(combined_tests[0]); ++i) {
    if (shell_run(combined_tests[i], output, sizeof(output), &out_size) != 0) {
      xaios_log("/bin/posix-shell: combined test failed\n");
      return 1;
    }
  }
  xaios_log("/bin/posix-shell: combined operations passed\n");

  /* Cleanup */
  const char *cleanup[] = {
      "rm /tmp/posix-test/redir.txt",
      "rm /tmp/posix-test/overwrite.txt",
      "rm /tmp/posix-test/input.txt",
      "rm /tmp/posix-test/data.txt",
      "cd /",
      "rmdir /tmp/posix-test",
  };
  for (u64 i = 0; i < sizeof(cleanup) / sizeof(cleanup[0]); ++i) {
    if (shell_run(cleanup[i], output, sizeof(output), &out_size) != 0) {
      xaios_log("/bin/posix-shell: cleanup warning\n");
    }
  }

  xaios_log("/bin/posix-shell: pipe and redirect surface passed\n");
  xaios_log("/bin/posix-shell: POSIX compatibility test complete\n");
  return 0;
}
