# Security Model

XAIOS is experimental. Security behavior is exercised under QEMU, but the
project is not ready for untrusted production deployment or physical-hardware
security claims.

## Current model

- Processes receive explicit capability masks. Every syscall is mapped to a
  required capability.
- Syscall request structures, nested pointers, ranges, permissions, transfer
  sizes, and narrowing conversions are validated before use.
- VFS descriptors and network sockets are process-owned and reclaimed with the
  owning process.
- Mutable user payloads are copied into bounded kernel-owned snapshots before
  policy checks or asynchronous subsystem use.
- Filesystem, workspace, sandbox, administrative role, replay, rollback, and
  development update-signature policies have focused self-tests.
- Administrative keys, revocations, configuration transactions, host-key
  rotation, and audit records use typed operations with explicit role and
  capability checks.
- Credential-like material is rejected from protected logging and persistence
  paths.
- Active ModelFS packages are immutable; publication uses verified,
  crash-consistent state transitions.

## Sensitive source areas

- `kernel/user/syscall.c`
- `kernel/include/xaios/syscall.h`
- `kernel/runtime/security.c`
- `kernel/runtime/admin_control.c`
- `kernel/runtime/control_protocol.c`
- `kernel/runtime/update.c`
- `kernel/runtime/persistence.c`
- `kernel/runtime/sandbox.c`
- `kernel/fs/`
- `kernel/net/`
- `userspace/sshd/`

Changes in these areas require focused review for ownership, bounds, failure
atomicity, replay, cleanup, and secret exposure.

## SSH administration

Release images do not contain a built-in password or authorized key. Key
material is packaged explicitly for a deployment or disposable test image.
Password authentication is disabled by default and release mode rejects a
password-enabled build. The QEMU acceptance suite checks valid and invalid
keys, valid and invalid passwords in development mode, malformed credential
files, entropy failure, host identity persistence and rotation, revocation,
rekey, session limits, reconnects, SFTP isolation, and secret redaction.
The local serial console follows the same policy: it authenticates against the
PBKDF2 database only in an explicitly password-enabled development image.
Key-only, default and release images remain locally locked and direct operators
to SSH public-key authentication. Password input is not echoed, failed login
does not create a shell session, and logout requires authentication again.

These tests do not replace an independent cryptographic implementation audit,
hostile-network review, side-channel analysis, or production key-management
design.

## Updates and persistence

The current signed-update format uses a QEMU development key identifier and
monotonic generation counter to exercise parser, authorization, replay,
fallback, and rollback behavior. It is not a production trust root. Production
signing, key custody, rotation, recovery, and compromise response remain open.

System-slot metadata and ModelFS use redundant or copy-on-write publication
where implemented. QEMU crash gates test selected interruption points, not all
physical power-loss, controller-cache, firmware, or storage-device behavior.

## Required validation

Security-sensitive changes must run at least:

```sh
make compile-check
make qemu-security-gate
make qemu-smoke
```

Update, storage, SSH, administration, or network changes also require their
focused gates and the external interoperability suites described in
[[Testing and Benchmarking|Testing-and-Benchmarking]].

## Secret handling

Never commit credentials, access tokens, API keys, private keys, SSH keys,
passwords, production signing material, or benchmark artifacts containing
secrets. Revoke and rotate an exposed credential before continuing work.

## Non-claims

- QEMU validation is not a security certification.
- The x86_64 QEMU image integrates the common security, process, SSH,
  filesystem, networking, AI Cell and telemetry services, but this is not an
  independent security review or approval for physical Internet exposure.
- Development keys and fixture credentials are not production trust roots.
- Physical DMA isolation, firmware trust, side channels, thermal/fault behavior,
  and supply-chain controls require separate validation.

See [[Current Limitations|Current-Limitations]] and [[Project Tracker|Project-Tracker]].
