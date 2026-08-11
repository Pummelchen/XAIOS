# Applications

This page inventories executable images and dedicated interactive applications
shipped with XAIOS. Standalone programs are started through the kernel loader
with explicit capabilities; arbitrary host binaries and FreeBSD/Linux binaries
do not execute in XAIOS.

Shell built-in commands such as `ls`, `ssh`, and `scp` are documented separately
in [[Commands|Commands]].

## Boot and service applications

| Path | Purpose | Normal startup |
|---|---|---|
| `/init` | First userspace process. Establishes the initial service lifecycle and returns status to the kernel. | Started once during boot. |
| `/bin/service-manager` | Exercises and owns the bounded service-manager protocol used for managed workers. | Started during boot. |
| `/bin/xaios-worker` | Joinable worker process used for scheduler, CPU-assignment, and service-lifecycle work. | Started by the service manager; count follows the boot profile. |
| `/bin/sshd` | Persistent SSH/SFTP server, authenticated PTY shell, command engine, outbound SSH/SCP client host, and interactive terminal utilities. | Started only after networking and the configured external IPv4/DNS readiness check succeeds. |

## Administrative applications

| Path | Purpose |
|---|---|
| `/bin/xaiosctl` | Test client for the versioned `xaios.control.v1` administrative protocol. Exercises status, health, hardware, metrics, logs, configuration, identity, audit, storage, and ModelFS rendering/authorization paths. The interactive shell exposes the same bounded command family. |
| `/bin/xaios-shell` | Scripted acceptance application for the remote-login command engine. It validates filesystem commands, archives, `nano`, and `htop`; it is not the persistent interactive shell process. |

## Interactive terminal applications

These are applications rather than shell commands. Their current implementation
is packaged as dedicated state, input, and rendering modules inside `/bin/sshd`
so the local console and SSH PTYs execute the same code. They do not yet have
independent `/bin/*` ELF images.

| Application | Runtime host | Purpose |
|---|---|---|
| `nano` | `/bin/sshd` | Full-screen editor with cursor movement, insertion/deletion, save, search, and exit. The editing buffer is limited to 32 KiB. |
| `htop` | `/bin/sshd` | Full-screen sampled process monitor with color, alternate-screen in-place refresh, runtime-sized CPU meters, sorting, filtering, tree view, keyboard navigation, and a 60 FPS rendering cap. |
| `pong` | `/bin/sshd` | 60 FPS terminal Pong. `W`/`S` control the left paddle, the computer controls the right, and session win/loss counts adjust ball speed by one percent per round. |

## Diagnostic applications

These executables are not started on a normal boot. An authenticated exact-name
remote command can launch an allowlisted diagnostic as a transient process;
the kernel reports its exit status and reclaims it. The dedicated
`XAIOS_BOOT_TEST_APPS=1` image profile may run them during deterministic QEMU
acceptance.

| Path | Purpose |
|---|---|
| `/bin/hello` | Minimal userspace toolchain, ELF loader, logging, and exit integration check. |
| `/bin/sysinfo` | Legacy compatibility diagnostic that directs administrators to `xaiosctl status` and `xaiosctl hardware`. |
| `/bin/systest` | Syscall, descriptor-width validation, and MutableFS create/read/stat/list/rename/delete suite. |
| `/bin/smptest` | SMP scheduler visibility, worker groups, and EL0 thread create/join/validation test. |
| `/bin/nettest` | App-callable UDP/TCP, external session, and asynchronous DNS/cache telemetry test. |
| `/bin/lstm-xor` | Deterministic CPU-only LSTM/XOR fixture. It also verifies that production model decode fails closed; it is not real-model inference. |
| `/bin/sshtest` | Scripted SSH-compatible command, filesystem, archive, process, and error-surface acceptance suite. |
| `/bin/mltest` | Deterministic CPU ML dispatcher test for XOR, sum, parity, and fixed-point matrix multiplication fixtures. |
| `/bin/posix-shell` | Scripted FreeBSD/POSIX-like shell-subset compatibility suite for redirects, pipelines, filters, and filesystem operations. |
| `/bin/agenttest` | Bounded agent protocol dispatch test for ping, source-index, Git status, build, denial, and validation cases. |

`/bin/app-fail` exists only in the explicit failure-fixture image. It exits with
status 42 so lifecycle and error reporting can be tested; it is not shipped in
the normal image.

## Execution boundaries

- Diagnostic names are exact allowlist entries; paths, arguments, and arbitrary
  executable launch are rejected by the remote application dispatcher.
- Built-in shell commands run inside the persistent SSH/local command subsystem.
- Interactive terminal applications have dedicated lifecycle and UI modules,
  but currently share the `/bin/sshd` host process rather than separate ELF
  images.
- A crashed or nonzero application reports a friendly command error and exit
  status; it does not remain as an active process.
- Normal boot does not pre-run `hello`, `sysinfo`, `lstm-xor`, or the other
  diagnostics.

For command syntax see [[Commands|Commands]]. For lifecycle verification see
[[Testing XAIOS|Testing-XAIOS]].
