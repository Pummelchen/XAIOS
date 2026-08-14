# Architecture adapters

Architecture adapters are the model-specific boundary above `xaios.model.v2`.
They parse official configuration and tensor metadata, map tensors to semantic
roles, construct ordered prefill/decode/verification plans, define typed
session state, and validate backend capabilities.

The portable interface is `engine/include/xaios_engine/architecture.h`.
Registry lookup is exact and currently recognizes `xaios_fixture` synthetic
test metadata and the configuration ID `kimi_k3`. Both production entries are
**Interface only**: validation and plan construction return
`XAIOS_ENGINE_ERR_UNSUPPORTED` until operator and golden-parity work exists.
`xaios_fixture` must not be presented as model support.

The portable service in `engine/include/xaios_engine/service.h` owns fixture
package admission and unload, explicit resident/evicted state, reference-counted
pins, deterministic least-recently-used eviction, async package-range reads,
and branchable session metadata. Pinned models and models with active sessions
cannot be evicted or unloaded. These lifecycle controls operate on immutable
package readers and do not copy model payloads. They are fixture-backed service
correctness, not real-model execution support.

An adapter must provide:

- strict config probing with unknown-field handling;
- tensor-name-to-semantic-role mapping checked against shapes and dtypes;
- ordered prefill, one-token decode, and multi-position verification plans;
- KV, recurrent, convolution, KDA, MLA, RoPE/mRoPE and position-state schemas;
- scratch and persistent-state requirements;
- exact/approximate mode validation and backend capability checks.

Qwen 3.8 cannot be implemented from a marketing name or an assumed generic
transformer. Implementation starts only after an immutable official
configuration, tokenizer, tensor manifest, and parity corpus are pinned. The
adapter must follow every operator and state requirement in that configuration.

Kimi K3 is a separate adapter. Its official configuration identifies as
`kimi_k3` with a `kimi_linear` text component, 93 layers, KDA and Gated MLA,
exact top-16 routing across 896 routed experts, two shared experts, AttnRes,
SiTU activation, long-context state, and MXFP4 metadata. Text and multimodal
acceptance remain separate milestones.

The isolated `kimi_k3_mini` scalar reference and model-v2 fixture cover a
four-layer reduced shape and exact top-16 selection across 20 experts. They are
kept outside the production adapter so a passing miniature golden test cannot
turn `kimi_k3` backend validation into a support claim. The reference was
checked against official revision
`9f62e4e9fffbd0a83ddd60e1c209d828994b3569`; real dimensions, tokenizer,
AttnRes composition and checkpoint parity remain mandatory.

An immutable source revision must be recorded in the model package and its
acceptance evidence before implementing or claiming an adapter.
