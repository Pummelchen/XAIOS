# Boot and Console

## Startup sequence

The UEFI loader validates and loads the kernel, then XAIOS initializes memory,
interrupts, devices, storage, filesystems, security, networking, processes,
runtime services, and telemetry in dependency order.

A normal boot displays `XAI OS`, with `XAI` in purple and `OS` in cyan, an
in-place 0-100% progress bar, the component that completed, the component
currently loading, and the remaining count. At completion it prints the
configured IPv4 address without padding between address components. If a
checksum-valid Router Advertisement supplies an autonomous global-unicast
`/64` prefix, it also prints the resulting `PUBLIC IPV6` SLAAC address.
Link-local and unique-local IPv6 addresses are not shown as public addresses.
It then reports one of these outcomes:

- `SSH server: up and running` only after the listener is operational;
- a numeric startup error when networking, IPv4 reachability, entropy,
  credentials, crypto,
  or listener initialization fails.

Once networking is active and before any service starts, the kernel sets the
wall clock from NTP. The default server is a bare address, so this needs no
DNS. It is bounded and non-fatal: a network that filters UDP/123 costs a pause
of at most six seconds and boot continues on the RTC reading. Without this the
clock is whatever the RTC reports, and QEMU's PL031 commonly reports epoch
zero, which leaves anything checking a certificate validity window seeing every
certificate as not yet valid. Confirm the result with `date` and `ntp status`.

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

The same prompt also accepts a six-digit console PIN, `012345` by default.
Entering six digits authenticates directly, without a password prompt; any
other entry is treated as a user name. Digits are masked as they are typed.

The PIN is a local console credential only. It is never accepted over SSH,
because a six-digit space is far too small to expose to a network attacker,
and it is packaged only when password authentication is already enabled, so a
key-only image stays key-only. Five consecutive console authentication
failures lock the prompt for 60 seconds, which applies to password and PIN
attempts alike. Override the record with `XAIOS_CONSOLE_PIN_FILE`; release
builds refuse to package one at all.

After successful authentication the prompt is:

```text
admin@xaios:/$
```

The serial console supports independent working-directory state, line editing,
`Backspace`, `Ctrl-C`, `Ctrl-L`, logout, filesystem commands, `nano`, `less`,
`htop`, and `pong`. Password input is not echoed. Failed authentication does
not create a shell session. The same byte-oriented console interface accepts
USB HID boot-keyboard input from the default xHCI device on both QEMU ARM64 and
QEMU x86_64; PL011 serial remains available when no USB keyboard is attached.

## Diagnosing a boot failure

A panic prints registers, a backtrace, and the tail of the kernel log. That
last section matters because a normal boot redraws the progress display over
the serial console, so the message explaining a failure is cleared from the
screen moments before the panic replaces it. Capture starts at the very
beginning of boot and does not depend on storage, so it is available even for
failures that happen before any filesystem is mounted.

Boot-time reads of the boot image retry a bounded number of times before
failing. A read that only succeeded on a retry is logged, so a marginal device
stays visible rather than being silently absorbed.

## Rebuilding over an existing persistent disk

The active administration configuration lives in persistent storage, and a
stored record takes precedence over the compiled default. `build/xaios-persistent.img`
is not recreated by a rebuild, so an image rebuilt over a disk written by an
earlier key-only build inherits `password=disabled` from that disk and comes up
with the console locked, whatever the new build was configured for. The boot
log names it:

```text
admin-control: initialized schema=1 generation=1 password=disabled
```

Discard the stale state to get the development credentials the build intended:

```sh
make clean-persistent
make image
```

This deletes persistent state, so use it on development images rather than on a
disk holding anything worth keeping.

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
prompt with a blinking cursor. The bundle exposes an xHCI controller to the
common USB HID input driver; the interactive Fusion window path is documented
as a separate qualification scope. PL011 remains the headless console and SSH
remains the network terminal.

See [[Networking and SSH|Networking-and-SSH]], [[Security Model|Security-Model]],
and [[Applications|Applications]].
