# Portable engine service

The service boundary is `engine/include/xaios_engine/service.h`. It is portable
C99 and uses caller-owned storage so the same ownership rules work in a hosted
process and in a future XAIOS service without depending on libc allocation.
Its cross-platform progress is tracked only in
[`wiki/Project-Tracker.md`](../wiki/Project-Tracker.md).

## Implemented contract

- Model and session identities are 64-bit.
- Admission opens `xaios.model.v2` through an immutable positional reader and
  retains that reader; it does not copy the package payload.
- Backends and architecture adapters are selected by capability and official
  architecture ID.
- Asynchronous range I/O writes directly into the final caller buffer and has
  completion and cancellation callbacks. Alignment and transfer limits are
  validated for the package offset, destination address and length before
  submission.
- Session metadata supports append, fork, commit, rollback, snapshot and safe
  destruction. A parent with live children and a model with live sessions
  cannot be destroyed.
- Unsupported architecture execution returns `XAIOS_ENGINE_ERR_UNSUPPORTED`.

`make engine-cli` builds `build/hosted/xaios-engine` on macOS or Linux:

```sh
build/hosted/xaios-engine probe
build/hosted/xaios-engine inspect package.xaiosmodel
build/hosted/xaios-engine serve package.xaiosmodel
```

`serve` is intentionally fail-closed while the selected adapter is
interface-only.

## Not complete

The session transaction currently owns production-width lifecycle metadata,
not architecture-specific tensors. Qwen work must add typed KV, recurrent and
convolution state with copy-on-write page ownership. Continuous batching must
execute ragged multi-sequence operators rather than looping over sessions.
Exact speculation must branch state and preserve target-model authority. No
current interface result is evidence of model support or performance.
