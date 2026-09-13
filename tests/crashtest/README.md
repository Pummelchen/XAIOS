# Deterministic hardening tests

This directory contains executable, deterministic tests for untrusted input
boundaries. It intentionally does not assign passing results to packet cases
that were not delivered to XAIOS.

`make crash-test` performs the hosted parser corpus under AddressSanitizer and
UndefinedBehaviorSanitizer. The corpus covers DNS compression and response
parsing, SFTP packet parsing, the control command parser, model packages and
storage metadata. QEMU exception, network, persistence and recovery paths are
covered by their dedicated gates -- `make qemu-fault-injection`,
`make qemu-network-suite`, `make qemu-storage-crash-test` and
`make qemu-persistence-reboot` -- and `make qemu-core-os-rc` runs the first
three of those among its steps. This paragraph named
`make qemu-production-gate`, which has never existed in the Makefile;
`check-test-layout.py` validates script paths and not target names, which is
why nothing caught it.

Every generated test case uses a fixed seed. A failure therefore has a stable
case ordinal that can be replayed from the same checkout. Generated reports are
written under `build/` and are not source artifacts.
