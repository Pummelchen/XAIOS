//===----- lib/riscv/fp_mode.c - Floating-point mode utilities ----*- C -*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM
// Exceptions. See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
//
// Written for XAIOS rather than copied from upstream, unlike the rest of this
// directory, and marked as such: the quad-precision builtins call these two
// functions on every rounding decision, and without them the riscv64 hosted
// C99 library does not link at all.
//
// RISC-V keeps both halves of the floating-point environment in fcsr: the
// rounding mode in frm, and the accrued exception flags in fflags. Both have
// their own CSR aliases, which is what the accessors below use.
//
//===----------------------------------------------------------------------===//

#include <stdint.h>

#include "../fp_mode.h"

#define RISCV_RNE 0x0 // to nearest, ties to even
#define RISCV_RTZ 0x1 // toward zero
#define RISCV_RDN 0x2 // down, toward negative infinity
#define RISCV_RUP 0x3 // up, toward positive infinity
#define RISCV_RMM 0x4 // to nearest, ties to max magnitude

#define RISCV_INEXACT 0x1 // fflags.NX

#ifndef __riscv_flen
// A soft-float target has no fcsr to read, so the rounding mode is whatever
// this weak symbol says. Weak so a program that needs a different mode can
// override it, which is how the AArch64 adapter handles the same case.
CRT_FE_ROUND_MODE __attribute__((weak)) __riscv_fe_default_rmode =
    CRT_FE_TONEAREST;
#endif

CRT_FE_ROUND_MODE __fe_getround(void) {
#ifdef __riscv_flen
  uint64_t frm;
  __asm__ __volatile__("frrm %0" : "=r"(frm));
  switch (frm) {
  case RISCV_RUP:
    return CRT_FE_UPWARD;
  case RISCV_RDN:
    return CRT_FE_DOWNWARD;
  case RISCV_RTZ:
    return CRT_FE_TOWARDZERO;
  // RMM is round-to-nearest with a different tie rule, and this interface has
  // no way to say that. Reported as to-nearest, which is what it is except on
  // exact ties -- claiming to-zero or a directed mode would be further from
  // the truth than the tie rule is.
  case RISCV_RMM:
  case RISCV_RNE:
  default:
    return CRT_FE_TONEAREST;
  }
#else
  return __riscv_fe_default_rmode;
#endif
}

int __fe_raise_inexact(void) {
#ifdef __riscv_flen
  // Set rather than written: fflags is accrued, so replacing it would clear
  // every other exception the program had already raised.
  __asm__ __volatile__("csrsi fflags, %0" : : "i"(RISCV_INEXACT));
  return 0;
#else
  return 0;
#endif
}
