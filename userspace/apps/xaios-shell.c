#include <xaios_user.h>

static void log_command(const char *command) {
  xaios_log("$ ");
  xaios_log(command);
  xaios_log("\n");
}

static int text_contains(const char *text, const char *needle) {
  if (text == 0 || needle == 0 || needle[0] == '\0') {
    return 0;
  }
  for (u64 i = 0; text[i] != '\0'; ++i) {
    u64 j = 0;
    while (needle[j] != '\0' && text[i + j] == needle[j]) {
      ++j;
    }
    if (needle[j] == '\0') {
      return 1;
    }
  }
  return 0;
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

static int shell_run_core(const char *command, char *output,
                          u64 output_capacity, u64 *out_size) {
  char internal[512];
  const char *prefix = 0;
  u64 used = 0U;
  u64 skip = 0U;
  if (command[0] == 'n' && command[1] == 'a' && command[2] == 'n' &&
      command[3] == 'o' && (command[4] == '\0' || command[4] == ' ')) {
    prefix = "__xaios_nano_core";
    skip = 4U;
  } else if (command[0] == 'h' && command[1] == 't' && command[2] == 'o' &&
             command[3] == 'p' &&
             (command[4] == '\0' || command[4] == ' ')) {
    prefix = "__xaios_htop_core";
    skip = 4U;
  }
  if (prefix == 0) return shell_run(command, output, output_capacity, out_size);
  while (prefix[used] != '\0' && used + 1U < sizeof(internal)) {
    internal[used] = prefix[used];
    ++used;
  }
  for (u64 index = skip; command[index] != '\0' &&
                           used + 1U < sizeof(internal); ++index) {
    internal[used++] = command[index];
  }
  internal[used] = '\0';
  return shell_run(internal, output, output_capacity, out_size);
}

static int remote_login_check(const char *command, char *output, u64 output_capacity,
                             u64 *out_size) {
  return shell_run_core(command, output, output_capacity, out_size);
}

int main(void) {
  char output[2048];
  u64 out_size = 0;

  const char *commands[] = {
      "help",
      "pwd",
      "ls /",
      "ls -a /",
      "ls -l /",
      "ls -la /",
      "ls -al /",
      "ls -a -l /",
      "l /",
      "ll /",
      "la /",
      "mkdir /state/remote-shell-test",
      "cd /state/remote-shell-test",
      "touch readme.txt",
      "write readme.txt hello world",
      "cat readme.txt",
      "cp readme.txt readme.copy",
      "grep hello readme.txt",
      "find . -name *.txt",
      "head readme.copy",
      "head -n 1 readme.copy",
      "tail readme.copy",
      "tail -n 1 readme.copy",
      "stat readme.copy",
      "echo shell command surface check",
      "cpio -o -O backup.cpio readme.txt readme.copy",
      "tar -cf backup.tar readme.txt readme.copy",
      "tar -tf backup.tar",
      "mv readme.copy readme.renamed.txt",
      "rm readme.renamed.txt",
      "nano editor.txt --write alpha\\nbeta",
      "nano editor.txt --insert 2 inserted",
      "nano editor.txt --replace 1 first",
      "nano editor.txt --delete 3",
      "nano editor.txt --append tail",
      "cpio -i -I backup.cpio",
      "tar -xf backup.tar -C /state/remote-shell-test",
      "rm readme.txt",
      "rm readme.copy",
      "rm backup.cpio",
      "rm backup.tar",
      "exit",
      "cd /",
  };

  xaios_log("/bin/xaios-shell: starting scripted remote-login surface session\n");
  for (u64 i = 0; i < sizeof(commands) / sizeof(commands[0]); ++i) {
    if (remote_login_check(commands[i], output, sizeof(output), &out_size) != 0) {
      xaios_log("/bin/xaios-shell: command failed\n");
      return 1;
    }
  }

  if (shell_run_core("nano /state/remote-shell-test/editor.txt --number", output,
                sizeof(output), &out_size) != 0 ||
      text_contains(output, "1  first\n2  inserted\n3  tail\n") == 0) {
    xaios_log("/bin/xaios-shell: nano edit verification failed\n");
    return 1;
  }
  if (shell_run_core("htop", output,
                sizeof(output), &out_size) != 0 ||
      text_contains(output, "XAIOS htop sample_ms=250") == 0 ||
      text_contains(output, "CPU CPU% BUSY_MS IDLE_MS ACTIVE ROLE") == 0 ||
      text_contains(output, "0 100.0%") != 0 ||
      text_contains(output, "MEM managed=") == 0 ||
      text_contains(output, "physical_pages=") == 0 ||
      text_contains(output, "cpu_shown=") == 0 ||
      text_contains(
          output,
          "PID PPID S CPU% MEM% TIME_MS RES_KIB CPU SYSCALLS COMMAND") == 0 ||
      text_contains(output, "/init") == 0 ||
      text_contains(output, "/bin/xaios-shell") == 0) {
    xaios_log("/bin/xaios-shell: htop process verification failed\n");
    return 1;
  }
  xaios_log("/bin/xaios-shell: htop idle sample returned to userspace\n");
  if (shell_run_core("htop --active --sample-ms 1 --no-cpus", output,
                sizeof(output), &out_size) != 0 ||
      text_contains(output, "/bin/xaios-shell") == 0 ||
      text_contains(output, "/init") != 0) {
    xaios_log("/bin/xaios-shell: htop active-view override failed\n");
    return 1;
  }
  if (shell_run_core("htop --all --sample-ms 10 --cpu-count 2 --sort mem "
                "--reverse --filter xaios-shell --process-start 0",
                output, sizeof(output), &out_size) != 0 ||
      text_contains(output, "sort=mem reverse=1 filter=xaios-shell") == 0 ||
      text_contains(output, "/bin/xaios-shell") == 0 ||
      text_contains(output, "process_start=0") == 0) {
    xaios_log("/bin/xaios-shell: htop sort/filter verification failed\n");
    return 1;
  }
  if (shell_run_core("htop --all --sample-ms 10 --cpu-count 2 --color "
                "--interactive --sort syscalls --columns 40 --rows 12",
                output, sizeof(output), &out_size) != 0 ||
      text_contains(output, "\033[2J\033[H") == 0 ||
      text_contains(output, "\033[?25l") == 0 ||
      text_contains(output, "\033[42;30m") == 0 ||
      text_contains(output, "Tasks:") == 0 ||
      text_contains(output, "Load:") == 0 ||
      text_contains(output, "Uptime:") == 0 ||
      text_contains(output, "\033[36mMem\033[32m[") == 0 ||
      text_contains(output, "\033[36mSwp\033[32m[") == 0 ||
      text_contains(output, "View: ") == 0 ||
      text_contains(output, "Sort: ") == 0 ||
      text_contains(output, "syscalls") == 0 ||
      text_contains(output, "[Main]") == 0 ||
      text_contains(output, " PID S   CPU%   MEM% COMMAND") == 0 ||
      text_contains(output, "CPU page:") == 0 ||
      text_contains(output, "F10") == 0 ||
      text_contains(output, "Quit") == 0) {
    xaios_log("/bin/xaios-shell: htop ANSI dashboard verification failed\n");
    return 1;
  }
  if (shell_run_core("htop --all --sample-ms 10 --no-cpus --color --tree "
                "--columns 120 --rows 20",
                output, sizeof(output), &out_size) != 0 ||
      text_contains(output, "Sort: \033[32mparent") == 0 ||
      text_contains(output, "|- /bin/xaios-worker") == 0) {
    xaios_log("/bin/xaios-shell: htop tree verification failed\n");
    return 1;
  }
  if (shell_run_core("htop --sort invalid", output, sizeof(output), &out_size) == 0 ||
      text_contains(output, "htop: invalid --sort key") == 0) {
    xaios_log("/bin/xaios-shell: htop option validation failed\n");
    return 1;
  }
  if (shell_run("rm /state/remote-shell-test/editor.txt", output,
                sizeof(output), &out_size) != 0) {
    xaios_log("/bin/xaios-shell: nano cleanup failed\n");
    return 1;
  }
  if (shell_run("rmdir /state/remote-shell-test", output, sizeof(output),
                &out_size) != 0) {
    xaios_log("/bin/xaios-shell: nano test directory cleanup failed\n");
    return 1;
  }
  xaios_log("/bin/xaios-shell: nano and htop utilities passed\n");
  xaios_log(
      "/bin/xaios-shell: command surface passed 1..15 + ls variants + tar/cpio archive "
      "commands\n");
  xaios_log("/bin/xaios-shell: command engine ready for QEMU remote-login surface\n");
  return 0;
}
