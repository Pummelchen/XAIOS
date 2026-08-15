# Boot and Console

## Startup sequence

The UEFI loader validates and loads the kernel, then XAIOS initializes memory,
interrupts, devices, storage, filesystems, security, networking, processes,
runtime services, and telemetry in dependency order.

A normal boot displays `XAI OS`, with `XAI` in purple and `OS` in cyan, an
in-place 0-100% progress bar, the component that completed, the component
currently loading, and the remaining count. At completion it prints the
configured IPv4 address and one of these outcomes:

- `SSH server: up and running` only after the listener is operational;
- a numeric startup error when networking, IPv4 reachability, entropy,
  credentials, crypto,
  or listener initialization fails.

SSH is not opened until networking is active and a bounded IPv4 TCP connection
to `1.1.1.1:443` succeeds. This checks configured external reachability without
making SSH startup depend on public DNS. Failure leaves the listener closed.

## Local console policy

The default development image presents:

```text
xaios login:
```

Its public development account is `admin` with password `xaios`. It is for
isolated QEMU/Fusion development only; use `XAIOS_SSH_PASSWORD_AUTH=0` to make
a development build key-only. Release images keep the local serial console
locked and never package a password database.

After successful authentication the prompt is:

```text
admin@xaios:/$
```

The serial console supports independent working-directory state, line editing,
`Backspace`, `Ctrl-C`, `Ctrl-L`, logout, filesystem commands, `nano`, `less`,
`htop`, and `pong`. Password input is not echoed. Failed authentication does
not create a shell session.

## Verbose diagnostics

Normal boot avoids scrolling logs. For failure analysis:

```sh
XAIOS_BOOT_VERBOSE=1 make qemu
```

The explicit QEMU fixture image may also start diagnostic applications during
boot to emit deterministic test markers:

```sh
make image-qemu-test
```

That profile is for validation only. Normal images start diagnostics on demand
and reclaim them after exit.

On VMware Fusion, the graphics window displays the compact 8x16 post-UEFI
status screen, including the 100% completion state and the current local login
prompt with a blinking cursor. It mirrors the PL011 serial-console state but
does not yet receive graphical keyboard input. Interactive local login uses
PL011; use SSH for an interactive network terminal.

See [[Networking and SSH|Networking-and-SSH]], [[Security Model|Security-Model]],
and [[Applications|Applications]].
