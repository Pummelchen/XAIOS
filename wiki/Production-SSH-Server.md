# SSH and Remote Login Status

This page name is retained for incoming links. XAIOS does not currently have a
physically deployed, audited, production-supported Internet SSH service.

## Current Evidence

| Path | Status | Boundary |
|---|---|---|
| Kernel remote-login contract | QEMU fixture | Exercises allowlisted commands, capability checks, password-login rejection, and deterministic telemetry. |
| Host OpenSSH-compatible bridge | Development tool | `scripts/xaios-ssh-bridge.py` listens on localhost and exposes the QEMU command contract through Paramiko. |
| Freestanding userspace SSH/SFTP service | Experimental | FreeBSD 15.1, native macOS and Debian 13 OpenSSH clients authenticate to QEMU guests. FreeBSD covers the Unix-reference key/SFTP/PTY/UDP subset; macOS and Debian cover the broader parallel administration, saturation, recovery and direct-TCP suite. Physical-network deployment and security acceptance are not established. |
| Phase 2 `xaiosctl` administration | QEMU-tested | Forty-nine typed operations cover measured queries, strict config transactions, role-mapped key lifecycle/revocation, host-key rotation, payload-redacted audit, GPT/ModelFS lifecycle, dynamic staging, scrub and trim. Role, replay, rollback, persistence and secret-exposure checks pass through OpenSSH gates. Cluster control is not implemented. |

The bridge is useful for local integration testing with commands such as
`ssh -p 2222 admin@localhost`. It must not be represented as proof that the
freestanding userspace server is safe for direct Internet exposure.

The guest service is also reachable locally with QEMU TCP forwarding. It has no
built-in password: Ed25519 authorized keys and strict PBKDF2 password records
are packaged explicitly. VirtIO RNG entropy is mandatory, the persistent
Ed25519 host key is flushed and stable across reboot, and OpenSSH-forced rekey
passes. Default-disabled and malformed credentials fail closed. It currently
admits four active SSH connections and two channels per connection, deliberate
fixed userspace-memory bounds. Shared exec/SFTP channels, overlapping SFTP,
wrong-key/password rejection, 40 combined reconnects, and post-load recovery
pass from macOS and Debian 13 against one guest. UDP userspace delivery and
asynchronous DNS, malformed/reset/reordered/retransmitted TCP, and out-of-order
IPv4/IPv6 fragment reassembly are in
[`docs/NETWORK-SSH-STATUS.md`](https://github.com/Pummelchen/XAIOS/blob/main/docs/NETWORK-SSH-STATUS.md).

Both AArch64 and x86_64 QEMU launchers forward host TCP port `7788` to guest
SSH port `22` by default. Connect with `ssh -p 7788 admin@127.0.0.1`, or with
`ssh ssh://admin@127.0.0.1:7788` on OpenSSH versions that support SSH URIs.
The bare form `ssh admin@127.0.0.1:7788` is not valid OpenSSH syntax. Set
`XAIOS_QEMU_HOSTFWD_PORT` to override the host-side port.

On normal boot, the service first requires an external IPv4 A-record response.
It does not open TCP port 22 until that check and all SSH initialization stages
succeed. The final serial screen prints the configured guest IPv4 and a verified
listener state. Failure reports a stage-specific numeric error without
advertising SSH readiness. Password-enabled development images then require the
same PBKDF2 admin credentials at `xaios login:` before exposing a local shell.
Default, key-only and release images keep serial login locked and require SSH
public-key authentication; there is no built-in console password.

The server currently negotiates classical `curve25519-sha256` only; it does not
yet implement an OpenSSH hybrid post-quantum KEX such as
`mlkem768x25519-sha256`. OpenSSH 10 therefore warns on a direct connection.
For local QEMU development, `scripts/ssh-xaios-qemu.sh` uses a persistent
project-local known-hosts file and suppresses that client notice for this scoped
connection. This convenience does not add post-quantum protection or relax the
production security gate.

The guest validates SSH PTY and resize dimensions. Running `htop` on a PTY
selects a native XAIOS-generated live ANSI monitor with sampled CPU/memory
meters, process selection and paging, CPU paging, sorting, filtering, help and
resize-aware rerendering. Bare `htop` shows all process slots and detected CPUs
with a 250 ms refresh; `--active`, `--all`, `--sample-ms`, and CPU-range options
remain available. Each SSH channel has independent monitor state and
bounded refresh/backpressure behavior with a hard monotonic 60-frame-per-second
render cap. The PTY uses the terminal alternate-screen buffer and restores the
original screen on exit, preventing live frames from accumulating in normal
scrollback. CPU sampling uses a complete interrupt-backed timer wait that is
excluded from process runtime, so htop does not create a permanent 100% CPU 0
reading. CPU, memory and swap meter brackets share one dynamically sized label
column. Up to eight CPU meters remain in the left half beside Tasks, scheduler
1/5/15-minute Load average, and Uptime. For 9-16 visible CPUs, the second group
uses the right half and those three status rows move below the CPU grid; larger
pages progress through 4, 8, and 16 column-major CPU columns when terminal width
permits. Narrow terminals reduce column density, and ordinal pages preserve
access to every runtime CPU instead of collapsing systems above 128 CPUs to one
aggregate meter. Memory and swap remain beneath the left CPU group, capacity
values are right-aligned there when width permits, and footer keys use
htop-style color segments.
Non-PTY calls remain one-shot plain
snapshots for automation. Process kill and priority controls are not offered
until XAIOS has a safe generic process-control ABI.

Running `pong` on an SSH PTY starts a session-local, fixed-point terminal game.
`W`/`S` control the human paddle and a predictive rate-limited controller owns
the right paddle. Human and computer win counters continue without a match
limit. Human points multiply ball speed by 1.01; computer points multiply it by
0.99, bounded to 40%-300% for indefinite play. `P` pauses, `R` resets, and `Q`
or Control-C restores the alternate screen and shell prompt. Window-change
requests rescale the live court. The authenticated serial console uses the same
engine with independent state.

A bare SSH PTY starts a stateful line-edited shell rather than a one-command
facade. Its cwd and colored `admin@xaios:<cwd>$` prompt are isolated per
connection, unknown commands produce a Unix-style diagnostic and nonzero exit
status, and `exit`/`logout` close the channel cleanly. Basic file and directory
commands include recursive tree rename/removal, portable process/storage views,
standard ustar/ZIP exchange, and an alternate-screen `less` pager. `nano PATH`
provides an alternate-screen editor with cursor movement, scrolling,
insertion/deletion, save and dirty-exit confirmation. MutableFS v4 permits
128 KiB state files; interactive nano remains intentionally bounded to 32 KiB.

The PTY shell also owns a bounded outbound SSHv2 client. `ssh [-p PORT]
user@host [command]` provides an interactive shell or remote exec, while
`scp [-r] [-P PORT]` transfers files and directory trees through SFTP v3.
Host Ed25519 signatures are verified and a persistent TOFU known-host entry is
required after first contact; changed keys fail closed. Current client
authentication is password-only, and active opens are IPv4/DNS-A only. Client
public-key authentication, IPv6 active open, forwarding, agents and jump hosts
remain unsupported.

Normal images start only `/init`, `/bin/service-manager`, and persistent
`/bin/sshd`. They do not pre-run `hello`, `sysinfo`, `lstm-xor`, or the other
diagnostics. Administrators may invoke `hello`, `sysinfo`, `systest`, `smptest`,
`nettest`, `lstm-xor`, `mltest`, `posix-shell`, and `agenttest` by exact command
name. Each command receives a fixed least-privilege capability mask, runs in a
separate transient address space, and is reaped after exit. Arbitrary paths and
arguments remain rejected. `make qemu-smoke` uses the separate deterministic
boot-diagnostic profile instead.

Ed25519 principals are assigned observer, operator or administrator roles.
Administrative audit entries and operational remote-login records omit command
payloads and authentication material.
Configuration, keys/revocations and audit metadata persist across reboot;
mutations require replay-protected operation IDs. Private host-key and control
state paths are denied through shell and SFTP. Password support is disabled by
default, requires an explicit development-image opt-in and is forbidden in
release builds.

## Required Production Gates

- Physical NIC and full network-stack execution outside QEMU fixtures.
- Fleet identity integration, durable external audit export and production
  secret-storage/replay-retention policy beyond the bounded Phase 2 stores.
- Extended rate-limit, timeout, repeated-loss, and long concurrent-session soak.
- Independent cryptographic and security review.
- Reviewed hybrid post-quantum SSH KEX, interoperability and downgrade-policy
  validation.
- Long-run physical-hardware soak, recovery, logging, and update validation.

## Validation Commands

```sh
make qemu-network-suite
make qemu-freebsd-network-suite
make qemu-docker-network-suite
make qemu-parallel-network-load
make qemu-local-console-gate
make qemu-model-sftp-gate
make qemu-ssh-smoke
make xaios-ssh-bridge
```

These commands provide development and QEMU correctness evidence only.

The guest SSH server admits its bounded shell commands, exact `xaiosctl` prefix,
and fixed diagnostic registry. It does not provide arbitrary executable launch.
See the [xaiosctl reference](https://github.com/Pummelchen/XAIOS/blob/main/docs/XAIOSCTL.md)
and [control protocol](https://github.com/Pummelchen/XAIOS/blob/main/docs/CONTROL-PROTOCOL.md).

## Relevant Source

- `kernel/runtime/remote_login.c`
- `userspace/sshd/`
- `scripts/xaios-ssh-bridge.py`
- `scripts/qemu-ssh-smoke.py`
- `scripts/qemu-docker-network-suite.py`
- `scripts/qemu-freebsd-network-suite.py`
- `scripts/qemu-parallel-network-load.py`
- `scripts/qemu-model-sftp-gate.py`
- `tests/network/`

See the [repository README](https://github.com/Pummelchen/XAIOS/blob/main/README.md)
and [hardware-readiness contract](https://github.com/Pummelchen/XAIOS/blob/main/HARDWARE-READINESS.md)
for current support boundaries.
