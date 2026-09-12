# Hosted ISO C99 Library

**Status: project conformance gates complete.** XAIOS provides a statically
linked hosted implementation of ISO/IEC 9899:1999 with Technical Corrigenda
1-3 for AArch64, x86_64 and RISC-V. The machine-readable inventory contains all 24
mandatory headers and 464 mandatory library functions. The strict compile,
link, namespace, runtime, termination and QEMU execution gates pass.

This means 100% of the repository's mandatory C99 inventory is accounted for
and green. It is not a claim of third-party ISO certification, exhaustive
testing of every possible input, POSIX compatibility, or physical-hardware
performance. The requirement source is the
[WG14 N1256 public draft](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1256.pdf).

## Non-negotiable rules

1. Application headers expose hosted ISO C99, not a POSIX, Linux, or BSD API.
2. Capabilities, threads, sockets, services, NUMA, model mappings and AI
   execution remain explicit XAIOS-native interfaces.
3. Libc adds no syscall identifier. The ABI is 55 identifiers, all of them
   XAIOS-native; `tests/libc/c99-requirements.json` pins the count and
   `make libc-check` fails when it moves, so a syscall added for anything else
   has to say so in the same change.
4. Standard functions execute in userspace and cross into the kernel only for
   console, file, clock, or termination state.
5. AI hot paths do not use stdio or the general libc heap for tensors, model
   weights, KV state, DMA, huge pages, or NUMA placement.
6. Kernel, boot code and low-level applications remain freestanding. Normal
   images include only the hosted `helloworldc99` demonstration; additional
   hosted applications remain an explicit build choice.

## Architecture

```text
hosted C99 application
  -> XAIOS C99 sysroot + Picolibc static archives
  -> private XAIOS console/file/time/exit adapter
  -> existing capability-checked XAIOS ABI

AI application
  -> C99 for portable control code
  -> libxaios and portable inference engine for threads, memory and compute
  -> shared mappings/rings and batched native operations
```

The pinned baseline is Picolibc 1.8.12 commit
`2ae376c6cdf4fef90ca2388ecf7a07457fa63cff`. Required compiler ABI helpers are
copied from LLVM compiler-rt release `llvmorg-22.1.8`, commit
`ca7933e47d3a3451d81e72ac174dcb5aa28b59d1`. Both upstream license notices are
retained. Generated wrapper headers hide non-C99 extension declarations while
reserved private headers remain available to the library implementation.

## Implemented boundary

| Area | Implementation |
|---|---|
| Language | Clang strict hosted C99 with VLAs, `restrict`, designated initializers, compound literals, flexible arrays, variadic macros, complex arithmetic and hexadecimal floating point tested. |
| Allocation | Userspace Picolibc allocator over a bounded 256 KiB application heap. AI-scale allocation remains native XAIOS runtime work. |
| Stdio | Narrow/wide formatting, scanning and buffering in userspace; private descriptors map streams to existing xaibootFS operations. |
| Time | `time()` uses UTC realtime and `clock()` uses process runtime through selectors on existing syscall 20. |
| Signals | ISO `signal()` and `raise()` use process-local handling. No POSIX signal delivery API is exposed. |
| Termination | Return from both standard `main` forms, `atexit`, `exit`, `_Exit`, and `abort` are exercised as separate processes. |
| Math | `float`, `double`, architecture-native `long double`, complex math and fenv operations link and execute on all three targets. |
| Locale | The required `C` locale and single-byte multibyte behavior are supported. |
| Linking | Static ELF executables with page-separated RX, R and RW load segments. Dynamic linking is outside this profile. |
| Threads | ISO C99 itself has no thread API. XAIOS exposes an explicitly non-ISO `<xaios/thread.h>` extension; each created XAIOS thread gets a stack-bound libc context with isolated `errno`, allocator locking and stream locking. |

## Build and test

```sh
make libc
make libc-check
make qemu-libc-gate
```

Build an application after `make libc`:

```sh
scripts/build-c99-app.sh --arch aarch64 --main args app.c build/app.elf
scripts/build-c99-app.sh --arch x86_64 --main void app.c build/app-x86.elf
scripts/build-c99-app.sh --arch riscv64 --main args app.c build/app-riscv.elf
```

`--main args` selects `int main(int, char **)`; `--main void` selects
`int main(void)`. Applications compile with `-std=c99 -fhosted
-pedantic-errors` against the generated architecture sysroot.

Every standard image packages `/bin/helloworldc99` from
`userspace/apps/hosted/helloworldc99.c`. Run `helloworldc99` from an
authenticated local or SSH shell to verify hosted `stdio`, process loading and
clean exit. Its bounded standard output is returned to the invoking terminal
while the same bytes remain visible on the serial console.

`make qemu-libc-gate` runs the contract audit, builds an image per
architecture, and then executes the runtime and termination probes on every
architecture that carries the library -- all three, since the runner stopped
saying "both architectures" as though two were all of them.

It builds every image it boots, and that is worth stating because for a long
time it did not: the make dependency built AArch64 and x86-64 while the gate
iterated three, so the RISC-V leg booted whatever `build/` happened to hold and
passed as convincingly as a leg testing the right artefact (`B-31`). The list
of architectures built and the list booted are now literally the same table.
RISC-V needs three build steps rather than two -- kernel, image, and the signed
A/B system volume the runner copies into its boot state -- and the third was
missing from every libc target, including the one documented here as building
its own image.

The conformance report at `build/libc/c99-conformance-report.json` is generated
from the contract's `architecture_gates`, which names AArch64 and x86_64, so
the report says two architectures and means it. CI uploads that report, the
manifests, the linked ELFs and the QEMU logs. `make qemu-riscv64-libc-gate` is
the same gate with `--arch riscv64`, and its result is not part of that
report.

## Implementation-defined choices

| Choice | XAIOS definition |
|---|---|
| Data model | LP64, little-endian, 8-bit bytes on all three targets. |
| Plain `char` | Unsigned on AArch64 and RISC-V; signed on x86_64. |
| `long double` | IEEE binary128 on AArch64 and RISC-V; x87 extended precision in 16-byte storage on x86_64. |
| Execution character set | ASCII-compatible execution set; the required `C` locale is always available. |
| Text and binary streams | Identical byte representation; no newline translation. |
| Temporary files | Created in `/tmp/` through xaibootFS and removed on close where required by the library. |
| Command processor | None. `system(NULL)` returns zero; a non-null command returns `-1` with `ENOSYS`. |
| Environment | No predefined environment variables are promised. |
| Clock epoch | `time_t` is signed 64-bit seconds from the Unix epoch; realtime comes from the XAIOS wall clock. |
| `errno` | Isolated per XAIOS native thread through Picolibc's reserved errno hook. The ISO C99 headers remain unchanged and POSIX-free. |

Optional IEC 60559 and ISO 10646 annex macros are not advertised merely
because a compiler or CPU provides related behavior.

## Execution plan and outcome

| Phase | Result | Evidence |
|---:|---|---|
| 1. Freeze standard and architecture rules | `DONE` | Machine-readable standard, syscall and non-POSIX contract. |
| 2. Pin and audit upstream sources | `DONE` | Picolibc submodule and compiler-rt source identity plus licenses. |
| 3. Build strict architecture sysroots | `DONE` | 24 headers, exact public function namespace, no forbidden headers. |
| 4. Add startup, runtime and native adapters | `DONE` | Both `main` forms, standard streams, filesystem, clocks and exit path. |
| 5. Complete mandatory surface | `DONE` | 464/464 functions declare and force-link on both targets. |
| 6. Exercise semantics and edge cases | `DONE` | Language, allocation, strings, conversion, locale, wide text, stdio, math, complex, fenv, setjmp and signals. |
| 7. Preserve XAIOS design invariants | `DONE` | Zero new syscall IDs; no public POSIX kernel API; AI-native boundary documented. |
| 8. Run every target architecture | `DONE` | AArch64, x86_64 and RISC-V QEMU marker sets pass without panic. |
| 9. Generate auditable evidence | `DONE` | Deterministic 14-gate report with SHA-256 artifact identities. |

## Separate follow-on work

The following are useful native extensions but are not part of ISO C99 and do
not block the hosted C99 status:

- native-thread context regression coverage exercises concurrent allocation,
  shared-stream writes and isolated failing I/O paths on AArch64, x86_64 and RISC-V
  QEMU;
- runtime-selected NEON/SVE and AVX2/AVX-512 memory primitives after scalar
  differential and physical-hardware tests;
- larger or dynamically supplied general heaps for ordinary hosted programs;
- third-party commercial conformance certification, if the project later
  requires a legally certified result.

QEMU proves the named semantics and ABI behavior, not physical throughput or
AI performance.
