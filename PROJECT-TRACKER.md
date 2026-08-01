# XAIOS project tracker

Last updated: 2026-08-01. Status labels are checked against
[`docs/MODEL-SUPPORT.json`](./docs/MODEL-SUPPORT.json). A checked interface is
not equivalent to executing-model support.

## Support status

| Model or path | Status | Exit criterion |
|---|---|---|
| Deterministic QEMU model-v1 path | Fixture only | Remains limited to OS/runtime correctness and ABI gates. |
| xaios.model.v2 tooling | Interface only | Production importer, tokenizer schema and executing engine integration still required. |
| Qwen 3.6 27B | Interface only | Official tokenizer, layer/logit parity, 32-step decode parity and physical execution. |
| Kimi K3 text | Interface only | KDA/MLA/MoE/MXFP4 parity, target-token parity and physical execution. |
| Kimi K3 multimodal | Roadmap only | Vision preprocessing/tower/projection/position and golden multimodal parity. |
| DeepSeek V4 Flash 0731 | Roadmap only | Verify and pin the exact official release before defining its adapter and correctness gates. |
| GLM 5.2 | Roadmap only | Pin official sources, implement a separate adapter, and pass tokenizer/operator/logit parity. |

## Completed foundation

- [x] AArch64 UEFI/QEMU OS bring-up and deterministic system fixtures.
- [x] Architecture-correct compile checks for AArch64 and x86_64 source.
- [x] Independent CI jobs so ABI, hosted engine, docs, smoke and regression
  results are visible even when another job fails.
- [x] Frozen QEMU contract synchronized through syscall 34 and current initfs
  capacity/paths.
- [x] Production decode fails with an unsupported error; deterministic decode
  is explicitly selected as `XAIOS_ML_MODEL_FIXTURE_DECODE`.
- [x] Stable model-v2 header/section/tensor binary layout and SHA-256 rules.
- [x] Streaming Python writer and on-demand C reader with >4 GiB sparse-file,
  corruption, malformed-range and overflow tests.
- [x] Portable architecture/backend interfaces and scalar projection canary.
- [x] Benchmark evidence contract and removal of unevidenced throughput claims.

## Active: Qwen correctness MVP

- [ ] Pin immutable Qwen3.5-0.8B config, tokenizer and SafeTensors fixtures.
- [ ] Implement streaming SafeTensors/config/tokenizer importer.
- [ ] Implement package-owned tokenizer and trusted ID corpus.
- [ ] Build `qwen3_5` ordered hybrid layer plan from official fields.
- [ ] Implement scalar embedding, RMSNorm and first projection parity.
- [ ] Implement configured linear/full attention, convolution/recurrent state,
  GQA, masking, mRoPE, feed-forward, residual and output head.
- [ ] Pass embedding, complete-layer, prefill-logit, 32-step decode and session
  reload golden gates.

## Next: packed hardware backends and sessions

- [ ] Replace full-matrix INT4/INT6 expansion with fused packed kernels.
- [ ] Add scalar differential and randomized tail tests before SIMD enablement.
- [ ] Add native macOS process with Apple CPU and optional Metal backends.
- [ ] Add AVX2, AVX-512/VNNI and AMX capability canaries.
- [ ] Add persistent NUMA-aware worker gangs and bandwidth-knee autotuning.
- [ ] Replace prototype state/batching/speculation with typed state, prefix COW,
  branch/commit/rollback, ragged batching and exact target verification.

## Kimi K3 text

- [ ] Implement the separate `kimi_k3` architecture adapter.
- [ ] Preserve exact top-16 routing; predictive routing may affect prefetch only.
- [ ] Implement KDA, Gated MLA, AttnRes, shared experts, SiTU and native MXFP4.
- [ ] Add independently addressable expert extents and asynchronous expert
  residency/cache policy.
- [ ] Pass a miniature K3 metadata/operator/router/expert/reduction fixture.
- [ ] Pass real checkpoint tokenizer and target-token parity on physical hardware.

## Kimi K3 multimodal

- [ ] Implement MoonViT-V2 preprocessing and vision tower.
- [ ] Implement vision-language projection and multimodal positions.
- [ ] Match official special-token and chat-template behavior.
- [ ] Pass separate golden image/text cases before advertising full K3 support.

## Additional model architecture targets

- [ ] Pin immutable official source, configuration, tokenizer and tensor-index
  revisions for DeepSeek V4 Flash 0731 and GLM 5.2.
- [ ] Probe official architecture identifiers and reject unknown configuration
  fields before building execution plans.
- [ ] Implement each family as a separate architecture adapter rather than
  adding model-name conditionals to Qwen or Kimi code.
- [ ] Define per-model tokenizer, layer/operator, state, logits, deterministic
  decode and physical-hardware acceptance gates.

## OS and scale-out dependencies

- [ ] Link the common kernel/runtime into the x86_64 image.
- [ ] Replace fixed-size physical/virtual/model allocators with sparse,
  multi-terabyte-capable structures and large pages.
- [ ] Parse x86 MADT/SRAT/SLIT/HMAT and track local/remote bytes.
- [ ] Add asynchronous NVMe multiqueue and direct final-buffer reads.
- [ ] Dispatch real inference work to secondary CPUs and AI Cell leases.
- [ ] Add NUMA/machine expert ownership, stable reduction and failure handling.

## Evidence gates

- `make compile-check`
- `make hosted-test`
- `make docs-check`
- `make qemu-abi-contract`
- `make qemu-smoke`
- `make qemu-regression-suite`

QEMU gates are correctness evidence only. Physical performance claims require
immutable artifacts satisfying
[`docs/BENCHMARK-CONTRACT.md`](./docs/BENCHMARK-CONTRACT.md).

Detailed dependency order and official source links are in
[`docs/QWEN-K3-IMPLEMENTATION-ROADMAP.md`](./docs/QWEN-K3-IMPLEMENTATION-ROADMAP.md).
