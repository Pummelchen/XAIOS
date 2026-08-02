# Model Support Roadmap

Last updated: 2026-08-02.

This page mirrors the repository roadmap. The authoritative status and delivery
sequence source is
[`docs/MODEL-SUPPORT.json`](https://github.com/Pummelchen/XAIOS/blob/main/docs/MODEL-SUPPORT.json).
Current source code takes precedence if any Wiki page disagrees.

## Delivery Sequence

| Order | Workstream | Project status | Entry gate |
|---|---|---|---|
| 1 | XAIOS | In Progress | Finish the core OS, portable engine, model-v2 integration, platform services, hardware readiness, and release gates. |
| 2 | Qwen 3.6 27B Support | Blocked | Starts only after the XAIOS completion gate. |
| Later | Kimi K3 Support | Backlog | Queued behind XAIOS and Qwen unless explicitly reprioritized. |
| Later | DeepSeek V4 Flash 0731 Support | Blocked | Also blocked on authoritative release and source verification. |
| Later | GLM 5.2 Support | Backlog | Queued behind XAIOS and Qwen unless explicitly reprioritized. |

## Support Status

| Model or path | Status | Current boundary |
|---|---|---|
| Deterministic QEMU model-v1 path | Fixture only | Validates OS/runtime contracts. It is not transformer inference or a hardware benchmark. |
| xaios.model.v2 tooling | Interface only | Package parser/writer and interface tests exist; no production model executes from it. |
| Qwen 3.6 27B | Interface only | Next model target after XAIOS; tokenizer, logits and deterministic decode parity remain incomplete. |
| Kimi K3 text | Interface only | Queued behind Qwen; KDA, Gated MLA, exact top-16 MoE, shared experts and MXFP4 remain unimplemented. |
| Kimi K3 multimodal | Roadmap only | Vision preprocessing, tower, projection and multimodal parity are a separate later gate. |
| DeepSeek V4 Flash 0731 | Roadmap only | Exact official release, configuration and tokenizer sources must be verified first. |
| GLM 5.2 | Roadmap only | Importer, tokenizer, operators, state and parity work have not started. |

`Fixture only`, `Interface only`, and `Roadmap only` are not support claims. A
model becomes supported only after official tokenizer, tensor import,
operator/state, logits, deterministic decode, session continuity, and
physical-hardware gates pass.

## Workstream Boundaries

### XAIOS

Complete the portable service boundary, production-width memory/NUMA/storage
paths, worker dispatch, session state, x86_64 common runtime, release/security
gates, and physical-hardware entry evidence before model implementation begins.

### Qwen 3.6 27B

Qwen is workstream 2 and the first real-model target. It remains blocked until
XAIOS completes. The implementation then proceeds through a smaller compatible
Qwen-family checkpoint before 27B tokenizer/logits/decode and hardware gates.

### Later Model Workstreams

Kimi K3, DeepSeek V4 Flash 0731, and GLM 5.2 remain queued behind XAIOS and
Qwen unless explicitly reprioritized. Kimi text and multimodal acceptance are
separate. DeepSeek also remains blocked on authoritative source identity.

## Detailed Plans

- [Repository implementation roadmap](https://github.com/Pummelchen/XAIOS/blob/main/docs/QWEN-K3-IMPLEMENTATION-ROADMAP.md)
- [Model-v2 specification](https://github.com/Pummelchen/XAIOS/blob/main/docs/MODEL-V2-SPECIFICATION.md)
- [Benchmark contract](https://github.com/Pummelchen/XAIOS/blob/main/docs/BENCHMARK-CONTRACT.md)
- [GitHub Project](https://github.com/users/Pummelchen/projects/5)
