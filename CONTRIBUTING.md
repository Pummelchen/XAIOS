# Contributing to XAIOS

XAIOS is an experimental freestanding operating system and portable inference
engine. Keep changes focused, reviewable, and tied to the current project
tracker.

## The rule that outranks the others

**XAIOS behaves the same everywhere it boots.** Firmware supplies capabilities,
never identity, and never behaviour.

A hypervisor may lack a framebuffer, a serial port, an interrupt translation
service or an entropy protocol. XAIOS may not notice *which* hypervisor it is,
and may never behave differently because of the answer. What the boot display,
the prompts, the shell and the SSH server say is XAIOS's, and reads identically
on every target that can run them. Where a capability is absent, the system
degrades the same way everywhere.

This is not style. The loader once advertised a hard-coded QEMU serial port to
every machine it booted, so on a platform with no serial hardware the kernel's
first log write went to a device that was not there. That was recorded as
"XAIOS does not boot" for a long time; the port was fine and the assumption was
not.

`make platform-neutrality-check` enforces it and runs inside `make docs-check`.
Two things fail review: a platform-branded constant used as the initial value
of something discovery fills in, and a user-visible string naming a hypervisor.
The test to apply is whether the sentence could name a vendor -- "this machine
has no framebuffer" is a capability, "this is Fusion, so draw differently" is
identity. Read
[`docs/PLATFORM-NEUTRALITY.md`](./docs/PLATFORM-NEUTRALITY.md) before touching
`kernel/`, `boot/` or `userspace/`.

Harnesses in `tools/`, run scripts in `scripts/`, gates in `tests/` and
firmware profiles in `contracts/` are exempt: driving or asserting one specific
platform is their purpose.

## Where things live

| Directory | Holds |
|---|---|
| `boot/` | UEFI loader |
| `kernel/` | the kernel, with `arch/<architecture>/` for anything architecture-specific |
| `userspace/` | init, the shell, applications, the C library, sshd |
| `engine/` | the inference engine |
| `platform/<environment>/` | one directory per supported hypervisor: its assets and its launchers, nothing else |
| `tests/` | gates in `tests/scripts/`, fixtures in `tests/fixtures/`, network harnesses in `tests/network/` |
| `contracts/` | versioned machine-readable contracts, `<name>-v<n>.json` |
| `docs/` | versioned specifications and formats |
| `wiki/` | the published Wiki: what XAIOS does, not how it was built |
| `scripts/` | build and release automation the build system invokes |
| `tools/` | standalone utilities a person runs by hand |
| `config/` | build cross-files, development credentials, deployment configuration |

`scripts/` and `tools/` are not interchangeable. If the build calls it, it is a
script; if you call it, it is a tool. `check-test-layout.py` enforces the
contents of `scripts/` and the shape of `platform/`, so a new file in either
needs a deliberate decision rather than a convenient one.

Anything that exists to drive or assert one specific hypervisor belongs under
`platform/` or `tests/`, never in the kernel. See the rule above.

## Getting Started

See [Getting Started](docs/GETTING-STARTED.md) for toolchain setup, building,
running, and userspace application development. The
[testing guide](https://github.com/Pummelchen/XAIOS/wiki/Testing-XAIOS)
documents validation tiers and external interoperability suites.

## Documentation

- [XAIOS Wiki](https://github.com/Pummelchen/XAIOS/wiki) - human-facing project documentation
- [API](docs/API.md) - userspace syscall and capability reference
- [Architecture](docs/ARCHITECTURE.md) - detailed system architecture and boot flow
- [Getting Started](docs/GETTING-STARTED.md) - prerequisites, builds, and app development
- [Current Limitations](https://github.com/Pummelchen/XAIOS/wiki/Current-Limitations) - verified gaps and non-claims

## Development Environment

| Platform | Toolchain |
|----------|-----------|
| macOS | `brew install llvm lld qemu mtools python3` |
| Linux | `apt install clang lld qemu-system-arm qemu-efi-aarch64 mtools python3` |

Build and smoke test:

```sh
make image && make qemu-smoke
```

The smoke test boots the AArch64 QEMU image, runs its self-tests and userspace
fixtures, and verifies JSON telemetry. Broader changes require the focused gates
listed in the Wiki testing guide.

## Code Style

All C code is freestanding C99 compiled with `-Wall -Wextra -Werror`:

- **No libc.** Kernel code uses `kernel/include/xaios/`; userspace uses
  `userspace/include/xaios_user.h`.
- **Naming.** Use `snake_case` for functions and types and `UPPER_SNAKE` for
  constants and macros.
- **Prefixes.** Kernel APIs use a module prefix such as `pmm_`, `vmm_`, or
  `smmu_`; userspace wrappers use `xaios_`.
- **Types.** Use the fixed-width types already established in the surrounding
  kernel or userspace module.
- **Error handling.** Return `xaios_status_t` for recoverable failures and use
  `kassert()` only for invariants that cannot be recovered safely.
- **Userspace allocation.** The freestanding userspace runtime has no general
  `malloc`; use bounded buffers or an existing owned arena.
- **Self-tests.** New kernel modules require focused `*_self_test()` coverage
  and correct initialization order in `kernel/core/kmain.c`.

## Contribution Rules

- Use one task per commit or pull request.
- Keep firmware out of XAIOS's behaviour. See the rule above; `make platform-neutrality-check` will reject the obvious violations, but it cannot see a new code path that quietly does something different on one platform.
- Run the relevant tests, build checks, or QEMU boot command before submitting.
- Keep boot logs and benchmark outputs when they support the change.
- Update the Wiki under `wiki/` when code changes alter architecture, build steps, APIs, or benchmark methodology. Edit it there rather than on GitHub: `make docs-check` gates its page set and links, and CI publishes it to the GitHub Wiki on merge to `main`, so an edit made on the published pages is overwritten by the next merge.
- Do not make benchmark claims without measured data and a documented baseline.
- Do not commit credentials, GitHub tokens, private keys, SSH keys, passwords, or secret benchmark data.

## Adding a Userspace App

1. Create `userspace/apps/myapp.c` using `#include <xaios_user.h>`.
2. Add the app to `USER_APPS` in `scripts/build-image.sh`.
3. Register its launch and capability mask in `kernel/core/kmain.c`.
4. Add a functional smoke marker when the app participates in boot validation.
5. Verify with `make image && make qemu-smoke`.

See [docs/GETTING-STARTED.md](docs/GETTING-STARTED.md) for a complete example.

## Adding a Kernel Module

1. Add the header and source under the established subsystem directories.
2. Add focused `module_self_test()` coverage.
3. Add the object to the relevant architecture build list.
4. Register initialization and self-test calls in `kernel/core/kmain.c`,
   respecting dependency order.
5. Run `make compile-check` followed by the focused QEMU gate and
   `make qemu-smoke`.
