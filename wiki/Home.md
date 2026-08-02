# XAIOS Wiki

This directory mirrors selected pages from the live GitHub Wiki. Current source,
build/test configuration, and `docs/MODEL-SUPPORT.json` take precedence over
older Wiki revisions.

XAIOS is an experimental operating system and portable inference-engine
foundation. Its current QEMU paths validate deterministic OS/runtime contracts;
they do not prove real-model inference or physical-hardware performance.

## Delivery Sequence

Only the XAIOS platform workstream is active. Qwen is next, but remains blocked
until XAIOS reaches its completion gate. Later model workstreams are not active
unless the maintainer explicitly reprioritizes them.

| Order | Workstream | Project status | Entry gate |
|---|---|---|---|
| 1 | XAIOS | In Progress | Finish the core OS, portable engine, model-v2 integration, platform services, hardware readiness, and release gates. |
| 2 | Qwen 3.6 27B Support | Blocked | Starts only after the XAIOS completion gate. |
| Later | Kimi K3 Support | Backlog | Queued behind XAIOS and Qwen unless explicitly reprioritized. |
| Later | DeepSeek V4 Flash 0731 Support | Blocked | Also blocked on authoritative release and source verification. |
| Later | GLM 5.2 Support | Backlog | Queued behind XAIOS and Qwen unless explicitly reprioritized. |

## Current Boundaries

- The model-v1 QEMU path is a deterministic fixture, not a transformer.
- `xaios.model.v2` and portable adapter/backend APIs are interface foundations.
- No listed real model has passed tokenizer, logits, deterministic decode, and
  physical-hardware acceptance gates.
- QEMU is correctness and ABI evidence only.
- Performance claims require immutable artifacts under the benchmark contract.

## Start Here

- [[Model Support Roadmap|Model-Support-Roadmap]]
- [[Qwen CPU Inference Status|Qwen3.6-INT6-Support]]
- [[SSH Status|Production-SSH-Server]]
- [Repository README](https://github.com/Pummelchen/XAIOS/blob/main/README.md)
- [Implementation roadmap](https://github.com/Pummelchen/XAIOS/blob/main/docs/QWEN-K3-IMPLEMENTATION-ROADMAP.md)
- [Benchmark contract](https://github.com/Pummelchen/XAIOS/blob/main/docs/BENCHMARK-CONTRACT.md)
- [GitHub Project](https://github.com/users/Pummelchen/projects/5)
