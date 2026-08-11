# Hosted ISO C99 Library

**Status: project conformance gates complete.** XAIOS provides a statically
linked hosted implementation of ISO/IEC 9899:1999 with Technical Corrigenda
1-3 for AArch64 and x86_64. The machine-readable inventory contains all 24
mandatory headers and 464 mandatory library functions. The strict compile,
link, namespace, runtime, termination and dual-architecture QEMU gates pass.

This means 100% of the repository's mandatory C99 inventory is accounted for
and green. It is not a claim of third-party ISO certification, exhaustive
testing of every possible input, POSIX compatibility, or physical-hardware
performance. The requirement source is the
[WG14 N1256 public draft](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n1256.pdf).

## Non-negotiable rules

1. Application headers expose hosted ISO C99, not a POSIX, Linux, or BSD API.
2. Capabilities, threads, sockets, services, NUMA, model mappings and AI
   execution remain explicit XAIOS-native interfaces.
3. Libc adds no syscall identifier. The ABI remains at 50 identifiers.
4. Standard functions execute in userspace and cross into the kernel only for
   console, file, clock, or termination state.
5. AI hot paths do not use stdio or the general libc heap for tensors, model
   weights, KV state, DMA, huge pages, or NUMA placement.
6. Kernel, boot code and existing low-level applications remain freestanding;
   the hosted sysroot is opt-in.

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
| Stdio | Narrow/wide formatting, scanning and buffering in userspace; private descriptors map streams to existing MutableFS operations. |
| Time | `time()` uses UTC realtime and `clock()` uses process runtime through selectors on existing syscall 20. |
| Signals | ISO `signal()` and `raise()` use process-local handling. No POSIX signal delivery API is exposed. |
| Termination | Return from both standard `main` forms, `atexit`, `exit`, `_Exit`, and `abort` are exercised as separate processes. |
| Math | `float`, `double`, architecture-native `long double`, complex math and fenv operations link and execute on both targets. |
| Locale | The required `C` locale and single-byte multibyte behavior are supported. |
| Linking | Static ELF executables with page-separated RX, R and RW load segments. Dynamic linking is outside this profile. |
| Threads | ISO C99 itself has no thread API. The current libc profile has process-global state; thread-safe native-libc contexts are a separate extension gate. |

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
```

`--main args` selects `int main(int, char **)`; `--main void` selects
`int main(void)`. Applications compile with `-std=c99 -fhosted
-pedantic-errors` against the generated architecture sysroot.

`make qemu-libc-gate` runs the contract audit, builds both images, executes the
runtime and termination probes under AArch64 and x86_64 QEMU, and writes the
ignored evidence artifact `build/libc/c99-conformance-report.json`. CI uploads
the report, manifests, linked ELFs and QEMU logs.

## Implementation-defined choices

| Choice | XAIOS definition |
|---|---|
| Data model | LP64, little-endian, 8-bit bytes on both targets. |
| Plain `char` | Unsigned on AArch64; signed on x86_64. |
| `long double` | IEEE binary128 on AArch64; x87 extended precision in 16-byte storage on x86_64. |
| Execution character set | ASCII-compatible execution set; the required `C` locale is always available. |
| Text and binary streams | Identical byte representation; no newline translation. |
| Temporary files | Created in `/tmp/` through MutableFS and removed on close where required by the library. |
| Command processor | None. `system(NULL)` returns zero; a non-null command returns `-1` with `ENOSYS`. |
| Environment | No predefined environment variables are promised. |
| Clock epoch | `time_t` is signed 64-bit seconds from the Unix epoch; realtime comes from the XAIOS wall clock. |
| `errno` | Process-global in the ISO-only profile. Per-thread state belongs to the future native thread-context extension. |

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
| 8. Run both target architectures | `DONE` | AArch64 and x86_64 QEMU marker sets pass without panic. |
| 9. Generate auditable evidence | `DONE` | Deterministic 13-gate report with SHA-256 artifact identities. |

## Separate follow-on work

The following are useful native extensions but are not part of ISO C99 and do
not block the hosted C99 status:

- per-thread libc context, `errno`, allocator and stream locking for programs
  that opt into XAIOS native threads;
- runtime-selected NEON/SVE and AVX2/AVX-512 memory primitives after scalar
  differential and physical-hardware tests;
- larger or dynamically supplied general heaps for ordinary hosted programs;
- third-party commercial conformance certification, if the project later
  requires a legally certified result.

QEMU proves the named semantics and ABI behavior, not physical throughput or
AI performance.
