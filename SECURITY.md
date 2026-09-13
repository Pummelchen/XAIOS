# Security Policy

XAIOS is an experimental operating system. Its security behavior is exercised
under QEMU, but it is not ready for untrusted production deployment or physical
hardware use.

## Reporting

Production vulnerability reporting is not active because there is no production
release. Report security design concerns through repository issues or pull
requests without including live secrets or exploit data that would expose a
third party.

## Secret Handling

Never commit credentials, GitHub tokens, API keys, private keys, SSH keys, passwords, or benchmark data that contains secrets.

If a secret is exposed, revoke and rotate it immediately before continuing development.

## Verified QEMU Boundary

Current source and QEMU gates verify:

- every syscall is mapped to a required process capability;
- syscall request structures and nested user pointers are range/permission
  checked before dereference;
- filesystem descriptors and network sockets are process-owned;
- sockets are reclaimed when a process address space is reclaimed;
- log, filesystem-write, positional-write and network-send payloads are copied
  into bounded kernel-owned snapshots before policy checks or subsystem use;
- filesystem calls reject high-bit values before narrowing descriptors to 32
  bits, and per-call filesystem/network transfer sizes are bounded;
- credential-like material is rejected from protected logs and writes;
- filesystem, workspace, sandbox, administrative-role, replay, rollback and
  development update-signature policies have focused self-tests.

The primary implementation surfaces are `kernel/user/syscall.c`,
`kernel/runtime/security.c`, `kernel/runtime/admin_control.c`,
`kernel/runtime/update.c`, `kernel/runtime/sandbox.c`, and `userspace/sshd/`.

## Explicit Non-Claims

- QEMU validation is not a production security certification.
- The x86_64 image runs the same process-owned security, SSH/control,
  filesystem, networking, AI Cell and telemetry service stack as AArch64.
  `wiki/Current-Limitations` and `wiki/Architecture` state that, and
  `check-core-os-status.py` requires them to state it; this bullet said the
  opposite for five weeks after the parity landed, which is the kind of claim
  `tests/repository/check-doc-freshness.py` now reads this file for. What
  remains open on x86_64 is not the stack but the *evidence for the hardware it
  runs on*, which is the physical item below.
- Development update keys and QEMU fixtures are not production trust roots.
- Physical DMA isolation, firmware trust, side-channel resistance and hardware
  fault behavior require separate physical-platform validation.

Security-sensitive changes must run at least `make compile-check`,
`make qemu-security-gate`, and `make qemu-smoke`. Update, storage, SSH or network
changes also require their focused gates.
