#!/usr/bin/env python3
"""Fail-closed entry point for the retired model-v1 GGUF converter.

The previous implementation emitted packages that disagreed with the kernel
fixture reader on header offsets, quantization identifiers, tokenizer layout,
and checksums. Keeping that behavior available would produce files that look
like inference models but cannot preserve any source model's semantics.
"""

import sys


def main() -> int:
    print(
        "error: GGUF conversion is not implemented for xaios.model.v2; "
        "the incompatible v1 converter has been retired",
        file=sys.stderr,
    )
    print(
        "use tools/create_xaios_v1_fixture.py only for deterministic QEMU "
        "contract fixtures, or tools/xaios_model_v2.py for model-v2 "
        "metadata/package tests",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
