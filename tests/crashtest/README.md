# Deterministic hardening tests

This directory contains executable, deterministic tests for untrusted input
boundaries. It intentionally does not assign passing results to packet cases
that were not delivered to XAIOS.

`make crash-test` performs the hosted parser corpus under AddressSanitizer and
UndefinedBehaviorSanitizer. The corpus covers DNS compression and response
parsing, SFTP packet parsing, the control command parser, model packages and
storage metadata. QEMU exception, network, persistence and recovery paths are
covered by their dedicated gates and by `make qemu-production-gate`.

Every generated test case uses a fixed seed. A failure therefore has a stable
case ordinal that can be replayed from the same checkout. Generated reports are
written under `build/` and are not source artifacts.
