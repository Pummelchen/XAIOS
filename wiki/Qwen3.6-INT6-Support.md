# Qwen CPU Inference Status

This page name is retained for incoming links. Earlier revisions described
Qwen inference, conversion, INT6 optimization, and performance as complete.
Those claims are not supported by current source or immutable physical-hardware
artifacts and must not be treated as implementation facts.

## Delivery Dependency

Qwen 3.6 27B is workstream 2. It is the first real-model target, but
implementation starts only after the XAIOS platform milestone is complete. Its
current GitHub Project status is `Blocked`, not `In Progress`.

## Current Status

| Target | Status | Evidence boundary |
|---|---|---|
| Qwen 3.6 27B | Interface only | Model-v2 and architecture/backend interfaces exist; official tokenizer, layer/logit and deterministic decode parity are incomplete. |

The model-v1 QEMU path is a deterministic fixture and does not execute a
transformer. The retired GGUF converter is fail-closed because its package
contract did not match the runtime reader. No production Qwen checkpoint can
currently be converted, loaded, and decoded through XAIOS.

## Required Acceptance Gates

1. Complete the XAIOS platform milestone.
2. Pin immutable official model, configuration, tokenizer, and tensor-index
   revisions.
3. Stream a real checkpoint into `xaios.model.v2` with bounded memory.
4. Match official tokenizer IDs, embeddings, one complete layer, and prefill
   logits within documented tolerances.
5. Match at least 32 deterministic decode steps and session reload behavior.
6. Differential-test optimized kernels against the scalar backend.
7. Produce physical Apple and Intel artifacts under the benchmark contract
   before publishing performance claims.

## Plans

- [[Project Tracker|Project-Tracker]]
- [Model-v2 specification](https://github.com/Pummelchen/XAIOS/blob/main/docs/MODEL-V2-SPECIFICATION.md)
- [Benchmark contract](https://github.com/Pummelchen/XAIOS/blob/main/docs/BENCHMARK-CONTRACT.md)
- [Qwen tracker](https://github.com/Pummelchen/XAIOS/issues/17)

Status labels such as `Interface only` and `Roadmap only` are not support
claims. This page should expand only when corresponding correctness gates
produce reproducible evidence.
