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

static int remote_login_check(const char *command, char *output, u64 output_capacity,
                             u64 *out_size) {
  return shell_run(command, output, output_capacity, out_size);
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

  if (shell_run("nano /state/remote-shell-test/editor.txt --number", output,
                sizeof(output), &out_size) != 0 ||
      text_contains(output, "1  first\n2  inserted\n3  tail\n") == 0) {
    xaios_log("/bin/xaios-shell: nano edit verification failed\n");
    return 1;
  }
  if (shell_run("htop --all", output, sizeof(output), &out_size) != 0 ||
      text_contains(
          output,
          "PID PPID STATE TICKS SYSCALLS REJECTS PAGES COMMAND") == 0 ||
      text_contains(output, "/bin/xaios-shell") == 0) {
    xaios_log("/bin/xaios-shell: htop process verification failed\n");
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
