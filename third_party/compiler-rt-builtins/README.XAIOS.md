# XAIOS compiler-rt builtins slice

This directory contains the quad-precision helper sources required by the
AArch64 hosted C99 `long double` formatting path. The files are copied without
functional changes from LLVM compiler-rt release `llvmorg-22.1.8`, resolved to
commit `ca7933e47d3a3451d81e72ac174dcb5aa28b59d1`.

Only the source and private headers needed to close the complete mandatory C99
`long double` and complex-math symbol graph are retained. This includes IEEE
binary128 helpers on AArch64, x87 conversion helpers on x86_64, complex
multiplication helpers on both architectures, and the AArch64 floating-point
mode adapter.
The upstream license is in `LICENSE.TXT`. This is compiler ABI support, not a
public XAIOS API and not a POSIX compatibility layer.
