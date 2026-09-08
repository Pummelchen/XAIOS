# Host tools

Programs that run on the development machine rather than inside XAIOS. They
build the artefacts a guest boots from, inspect those artefacts without booting
anything, and stand in for hardware the emulator does not provide.

Most are invoked by `scripts/` or by a gate in `tests/scripts/`; two are run by
hand and are listed as such, because a tool nothing calls is a tool nobody
finds.

## Building and inspecting guest artefacts

| Tool | What it does |
|---|---|
| `xaios_system_volume.py` | Builds and inspects the signed A/B system volume a machine boots from, and reads back which slot is active. `scripts/build-*-boot-media.sh` calls it; run it directly to see what a volume actually contains. |
| `xaios_write_gpt.py` | Writes a GUID partition table onto a disk image. |
| `xaios_xai_fs.py` | A host implementation of the xaiFS volume format, crash-consistent in the same way the kernel's is. Gates use it to build a volume and to check what the guest wrote. |
| `xaios_model_v2.py` | Streaming writer and inspector for `xaios.model.v2` packages. |
| `xaios_xapt_repo.py` | Builds and verifies signed application repositories for `xapt`, including the per-architecture catalogues. |
| `create_xaios_v1_fixture.py` | Creates the deterministic model-v1 fixture the QEMU correctness gates read. Deterministic on purpose: a fixture that changed between runs would make every gate that reads it untrustworthy. |

## Standing in for hardware

| Tool | What it does |
|---|---|
| `xaios_write_log.py` | A block device that acknowledges writes and then loses the unflushed ones, replayed from QEMU's `blklogwrites` journal. This is what makes `make qemu-power-loss-gate` a real power-loss test rather than a constructed one — no emulator option loses an acknowledged write on its own. |

## Guarding the build

| Tool | What it does |
|---|---|
| `check_user_elf_base.py` | Refuses to pack a user binary linked where the kernel will not map it. Both image builders call it. A stale binary here does not fail the build without it — it panics the kernel a full boot later, which is how it was found. |

## Run by hand

Neither of these is called by a script or a gate. They exist for a maintainer
doing a specific job, and both are listed here so that job is findable.

| Tool | When to run it |
|---|---|
| `gen_xapt_trust_anchors.py` | When the trust anchors `xapt` validates the update chain against need regenerating — a certificate rotation at the origin, or a change of origin. It writes the BearSSL anchor table the updater compiles in. Changing what the updater trusts is a security decision: see [Security Model](../wiki/Security-Model.md) and [xapt Package Updates](../wiki/Xapt-Package-Updates.md). |
| `xaios_engine_cli.c` | A host build of the inference engine's command surface, for exercising the engine without a guest. Built by the `engine-cli` target. |

## Retired, deliberately

`convert_gguf_to_xaios.py` no longer converts anything. It prints an error and
exits non-zero.

It is kept rather than deleted because the implementation it replaced emitted
packages that disagreed with the kernel's fixture reader about header offsets,
quantisation identifiers, tokenizer layout and checksums — files that looked
like models and could not preserve any source model's semantics. A tool that
fails loudly is safer than a path that silently produces such a file, and
safer than a missing file that invites someone to write the converter again
without knowing why the first one was withdrawn.
