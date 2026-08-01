# Architecture adapters

Architecture adapters are the model-specific boundary above `xaios.model.v2`.
They parse official configuration and tensor metadata, map tensors to semantic
roles, construct ordered prefill/decode/verification plans, define typed
session state, and validate backend capabilities.

The portable interface is `engine/include/xaios_engine/architecture.h`.
Registry lookup is exact and currently recognizes official configuration IDs
`qwen3_5` and `kimi_k3`. Both entries are **Interface only**: validation and
plan construction return `XAIOS_ENGINE_ERR_UNSUPPORTED` until operator and
golden-parity work exists.

An adapter must provide:

- strict config probing with unknown-field handling;
- tensor-name-to-semantic-role mapping checked against shapes and dtypes;
- ordered prefill, one-token decode, and multi-position verification plans;
- KV, recurrent, convolution, KDA, MLA, RoPE/mRoPE and position-state schemas;
- scratch and persistent-state requirements;
- exact/approximate mode validation and backend capability checks.

Qwen3.6 cannot be implemented as an assumed dense transformer. Its official
27B configuration identifies as `qwen3_5`, mixes linear-attention and
full-attention layers, and includes convolution/recurrent state and mRoPE
fields. The small Qwen3.5-0.8B bring-up model has the same hybrid family and is
the first practical correctness checkpoint.

Kimi K3 is a separate adapter. Its official configuration identifies as
`kimi_k3` with a `kimi_linear` text component, 93 layers, KDA and Gated MLA,
exact top-16 routing across 896 routed experts, two shared experts, AttnRes,
SiTU activation, long-context state, and MXFP4 metadata. Text and multimodal
acceptance remain separate milestones.

Official compatibility sources are linked from
`docs/QWEN-K3-IMPLEMENTATION-ROADMAP.md` and must be rechecked at an immutable
revision before implementing an adapter.
