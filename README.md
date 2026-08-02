<img width="1122" height="1402" alt="image" src="https://github.com/user-attachments/assets/e305c7bb-40f2-4454-87f8-f58c9082d808" />


# XAIOS

XAIOS is an experimental operating system and portable inference-engine
foundation for model-extensible AI serving. The current OS boots under QEMU and
exercises deterministic kernel/runtime contracts. Real-model inference is
under development and is not production supported.

AI coding agents should read [`AI_INDEX.md`](./AI_INDEX.md),
[`AGENTS.md`](./AGENTS.md), and [`.ai/START_HERE.md`](./.ai/START_HERE.md), then
verify their claims against current source.

## Model support status

[`docs/MODEL-SUPPORT.json`](./docs/MODEL-SUPPORT.json) is the authoritative
status and delivery-sequence source. CI checks the README, project tracker,
implementation roadmap, hardware-readiness document, and selected Wiki mirrors
against it.

| Model or path | Status | Current evidence and boundary |
|---|---|---|
| Deterministic QEMU model-v1 path | Fixture only | Validates model admission, private state, ABI and deterministic dispatch. It is not transformer inference or a hardware benchmark. |
| xaios.model.v2 tooling | Interface only | Streaming Python writer, Python reader and C parser pass round-trip, checksum, overflow and sparse-file tests. No production importer or executing model uses it yet. |
| Qwen 3.6 27B | Interface only | Next real-model bring-up target after XAIOS platform completion. Transformer execution, official tokenizer parity, logits parity and physical-hardware validation remain incomplete. |
| Kimi K3 text | Interface only | Queued behind XAIOS and Qwen for KDA, Gated MLA, AttnRes, exact top-16 routing, shared experts and native MXFP4. Text inference is not available. |
| Kimi K3 multimodal | Roadmap only | Vision preprocessing, MoonViT-V2, projection, multimodal positions and golden image cases are a separate milestone. |
| DeepSeek V4 Flash 0731 | Roadmap only | Planned architecture-adapter target. The exact official release, configuration and tokenizer sources must be verified and pinned before implementation. |
| GLM 5.2 | Roadmap only | Planned architecture-adapter target. Import, tokenizer, operator, state, logits and physical-hardware parity work has not started. |

## Delivery sequence

This order is authoritative for current execution planning. Only XAIOS is
active. Qwen is the next workstream, but remains blocked until the XAIOS
platform milestone is complete. No relative order is assigned to the later
model workstreams unless the maintainer explicitly reprioritizes them.

| Order | Workstream | Project status | Entry gate |
|---|---|---|---|
| 1 | XAIOS | In Progress | Finish the core OS, portable engine, model-v2 integration, platform services, hardware readiness, and release gates. |
| 2 | Qwen 3.6 27B Support | Blocked | Starts only after the XAIOS completion gate. |
| Later | Kimi K3 Support | Backlog | Queued behind XAIOS and Qwen unless explicitly reprioritized. |
| Later | DeepSeek V4 Flash 0731 Support | Blocked | Also blocked on authoritative release and source verification. |
| Later | GLM 5.2 Support | Backlog | Queued behind XAIOS and Qwen unless explicitly reprioritized. |

XAIOS is designed for multiple official architecture identifiers rather than a
hard-coded Qwen graph. Qwen 3.6 27B remains the first real-model target after
the platform completion gate. Kimi K3 text and multimodal support are separate
later milestones. DeepSeek V4 Flash 0731 and GLM 5.2 are additional roadmap
targets, each requiring its own verified architecture adapter and parity gates.
Approximate routing or execution modes, if added, will be named, reported and
opt-in; exact target-model semantics are the default.

## Current implementation

- AArch64 UEFI/QEMU boot, freestanding kernel, EL0 userspace, VirtIO devices,
  filesystem, network, capability, AI Cell and telemetry fixtures.
- An experimental freestanding SSH/SFTP service reachable through QEMU host
  forwarding, plus guest userspace UDP receive/echo and IPv6/TCP receive/send
  paths. An official Debian 13 Docker client on macOS verifies password
  acceptance/rejection, SFTP transfer and stat, two overlapping SFTP sessions,
  four simultaneous SSH sessions, 20 reconnects, UDP echo, and direct IPv6/TCP.
  These QEMU checks do not approve Internet exposure or production use.
- A deterministic 80-byte model-v1 fixture path used only by QEMU correctness
  gates. The production decode syscall returns an explicit unsupported error.
- A hosted C99 engine boundary under `engine/` with on-demand model-v2 parsing,
  exact architecture registry IDs, backend capability selection and a scalar
  dense-projection known-answer canary.
- A streaming model-v2 writer under `tools/xaios_model_v2.py` that does not keep
  weight payloads proportional to package size in memory.

The retired GGUF converter emitted packages incompatible with the model-v1
reader and has been made fail-closed. `tools/create_xaios_v1_fixture.py` exists
only for deterministic fixture generation. SafeTensors/config/tokenizer and
GGUF importers for model-v2 remain to be implemented.

## Architecture direction

The XAIOS kernel owns topology, cpusets, isolation, NUMA/large-page allocation,
immutable mappings, asynchronous device queues, shared rings, timekeeping,
telemetry and AI Cell admission. The portable engine owns package parsing,
tokenizers/templates, architecture adapters, execution plans, sampling,
session state, batching, expert residency, speculation and backend selection.

The same engine is intended to run as an XAIOS service and as native macOS and
Linux processes. Planned backends are scalar reference, Apple CPU/NEON,
optional Metal, Intel AVX2, and Xeon AVX-512/VNNI/AMX with NUMA-aware expert
placement. None of those optimized hosted backends is implemented today.

## Build and validation

Host prerequisites are Clang, LLD, Python 3, mtools, QEMU and AAVMF/UEFI
firmware. See [`docs/GETTING-STARTED.md`](./docs/GETTING-STARTED.md).

```sh
make bootstrap
make compile-check
make hosted-test
make qemu-abi-contract
make image
make qemu-smoke
make qemu-docker-network-suite
```

`make hosted-test` is the foundational model-v2/engine gate. QEMU gates validate
OS correctness and ABI behavior only. They do not establish model parity,
physical-hardware readiness, tokens per second, bandwidth, power, or production
support.

## Documentation

- [Model implementation roadmap](./docs/QWEN-K3-IMPLEMENTATION-ROADMAP.md)
- [xaios.model.v2 specification](./docs/MODEL-V2-SPECIFICATION.md)
- [Architecture adapters](./docs/ARCHITECTURE-ADAPTERS.md)
- [Hardware backends](./docs/HARDWARE-BACKENDS.md)
- [Benchmark evidence contract](./docs/BENCHMARK-CONTRACT.md)
- [OS architecture](./docs/ARCHITECTURE.md)
- [API](./docs/API.md)
- [Network and SSH status](./docs/NETWORK-SSH-STATUS.md)
- [Hardware readiness](./HARDWARE-READINESS.md)
- [Project tracker](./PROJECT-TRACKER.md)
- [Live GitHub Wiki](https://github.com/Pummelchen/XAIOS/wiki)
- [Live model support roadmap](https://github.com/Pummelchen/XAIOS/wiki/Model-Support-Roadmap)

Official compatibility sources used for the current design audit:

- [Qwen3.5-0.8B configuration](https://huggingface.co/Qwen/Qwen3.5-0.8B/blob/main/config.json)
- [Qwen3.6-27B configuration](https://huggingface.co/Qwen/Qwen3.6-27B/blob/main/config.json)
- [Qwen3.6 repository](https://github.com/QwenLM/Qwen3.6)
- [Kimi K3 configuration](https://huggingface.co/moonshotai/Kimi-K3/blob/main/config.json)
- [Kimi K3 repository and report](https://github.com/MoonshotAI/Kimi-K3)
- [GLM 5.2 model repository](https://huggingface.co/zai-org/GLM-5.2)

An immutable official source has not yet been pinned for the exact roadmap
label DeepSeek V4 Flash 0731. Its name in this document is a planning target,
not evidence of compatibility or implementation.

## Performance evidence

No physical Apple or Xeon benchmark artifact currently exists in this
repository. Performance numbers without immutable artifacts meeting
[`docs/BENCHMARK-CONTRACT.md`](./docs/BENCHMARK-CONTRACT.md) are targets, not
results. Microbenchmark improvements may not be multiplied into end-to-end
claims.

## License

XAIOS is source-available under the
[PolyForm Noncommercial License 1.0.0](./LICENSE). The license permits private,
personal, educational and noncommercial research use, including use by
universities and public research organizations. It does not grant commercial
use.

Commercial use requires a separate written commercial license obtained before
use. See [`COMMERCIAL-LICENSE.md`](./COMMERCIAL-LICENSE.md) for the licensing
route. XAIOS is not MIT-licensed because the MIT License permits unrestricted
commercial use.
