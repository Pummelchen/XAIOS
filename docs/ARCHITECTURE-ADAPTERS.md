# Architecture adapters

Architecture adapters are the model-specific boundary above `xaios.model.v2`.
They parse official configuration and tensor metadata, map tensors to semantic
roles, construct ordered prefill/decode/verification plans, define typed
session state, and validate backend capabilities.

The portable interface is `engine/include/xaios_engine/architecture.h`.
Registry lookup is exact and currently recognizes `xaios_fixture` synthetic
test metadata and the configuration ID `kimi_k3`. Both entries are **Interface
only**: validation and plan construction return
`XAIOS_ENGINE_ERR_UNSUPPORTED` until operator and golden-parity work exists.
`xaios_fixture` must not be presented as model support.

An adapter must provide:

- strict config probing with unknown-field handling;
- tensor-name-to-semantic-role mapping checked against shapes and dtypes;
- ordered prefill, one-token decode, and multi-position verification plans;
- KV, recurrent, convolution, KDA, MLA, RoPE/mRoPE and position-state schemas;
- scratch and persistent-state requirements;
- exact/approximate mode validation and backend capability checks.

Qwen 3.8 27B cannot be implemented from a marketing name or an assumed generic
transformer. Implementation starts only after an immutable official
configuration, tokenizer, tensor manifest, and parity corpus are pinned. The
adapter must follow every operator and state requirement in that configuration.

Kimi K3 is a separate adapter. Its official configuration identifies as
`kimi_k3` with a `kimi_linear` text component, 93 layers, KDA and Gated MLA,
exact top-16 routing across 896 routed experts, two shared experts, AttnRes,
SiTU activation, long-context state, and MXFP4 metadata. Text and multimodal
acceptance remain separate milestones.

An immutable source revision must be recorded in the model package and its
acceptance evidence before implementing or claiming an adapter.
