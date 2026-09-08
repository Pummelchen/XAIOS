# XAIOS technical reference

This directory is the technical reference: file formats, wire protocols, API
surfaces, contracts, and measurement methodology. It is the half of the
documentation that the code and the repository checks depend on, so a change
here is a change to something another part of the tree reads.

`wiki/` is the other half. It is published to the GitHub Wiki and is the
reader-facing documentation: what XAIOS is, how to run it, how to operate it.

## Which side a document belongs on

| If the document is | It lives in |
|---|---|
| A format, a protocol, an ABI or a syscall surface | `docs/` |
| A contract a gate or check validates against | `docs/` |
| Measurement methodology and the evidence rules for a claim | `docs/` |
| Orientation: what the system is and what it is not | `wiki/` |
| Operation: installing, running, administering, recovering | `wiki/` |
| Status of a platform, a gate, or a piece of work | `wiki/` |

The test is who reads it. A specification is read by someone implementing
against it or by a check enforcing it; those must not move without the code
moving too. Everything else is read by someone trying to use XAIOS, and that
belongs where it is published.

`CONTRIBUTING.md` states the same division for the whole repository; this page
is where it is applied.

## Four topics that used to exist twice

Architecture, getting started, Unix compatibility and VMware Fusion each had a
full treatment on both sides. They had already drifted: the two Fusion
documents disagreed about whether multi-vCPU and VMXNET3 worked, and the two
getting-started documents disagreed about what SSH waits for before it binds
port 22. A reader had no way to tell which was current.

Each is now single-sourced in `wiki/`, and the file here is a pointer. The
files remain rather than being deleted because `README.md`, `CONTRIBUTING.md`
and the published Wiki link to these paths, and a pointer keeps those links
resolving.

The developer material that was only in `GETTING-STARTED.md` — how to register
an application, where its execution path is declared, and what capability mask
it is given — is a contract against the kernel rather than orientation, so it
stayed on this side as
[Application development](./APPLICATION-DEVELOPMENT.md).

## Contents

| Document | Covers |
|---|---|
| [API](./API.md) | Syscall table, capability bits, and userspace data types |
| [Application development](./APPLICATION-DEVELOPMENT.md) | Registering an application, its execution path and its capability mask |
| [Architecture adapters](./ARCHITECTURE-ADAPTERS.md) | The model-specific boundary above `xaios.model.v2` |
| [Benchmark contract](./BENCHMARK-CONTRACT.md) | What a performance claim must record to be valid |
| [Benchmark methodology](./BENCHMARK-METHODOLOGY.md) | What the QEMU benchmarks measure, and what they cannot |
| [Block device API](./BLOCK-DEVICE-API.md) | The generic block interface drivers register against |
| [Cluster protocol](./CLUSTER-PROTOCOL.md) | Authenticated peer frames and deterministic expert placement |
| [Control protocol](./CONTROL-PROTOCOL.md) | The `xaios.control.v1` request/response ABI |
| [Engine service](./ENGINE-SERVICE.md) | The portable model and session service boundary |
| [Firmware platform profiles](./FIRMWARE-PLATFORM-PROFILES.md) | The three-profile evidence contract and its report format |
| [GPT partitions](./GPT-PARTITIONS.md) | Partition-map parsing and the bounded partition device |
| [Hardware backends](./HARDWARE-BACKENDS.md) | The compute-backend registry and its capability descriptions |
| [Hardware portability](./HARDWARE-PORTABILITY.md) | The rule that keeps drivers capability-selected, and the qualification layers |
| [Large-model upload](./LARGE-MODEL-UPLOAD.md) | Staging a package larger than memory over SFTP |
| [Model-v2 specification](./MODEL-V2-SPECIFICATION.md) | The `xaios.model.v2` package format |
| [xaiFS format](./MODELFS-FORMAT.md) | The on-disk model filesystem |
| [xaiFS recovery](./MODELFS-RECOVERY.md) | fsck, scrub, quarantine and repair semantics |
| [Network and SSH status](./NETWORK-SSH-STATUS.md) | Implemented protocol surface and its boundaries |
| [Physical qualification readiness](./PHYSICAL-QUALIFICATION-READINESS.md) | The pre-physical evidence gate and what it cannot supply |
| [Platform neutrality](./PLATFORM-NEUTRALITY.md) | Why the kernel discovers capabilities and never identifies a platform |
| [Storage architecture](./STORAGE-ARCHITECTURE.md) | Layering from syscall to block device, and its current limits |
| [Storage benchmarking](./STORAGE-BENCHMARKING.md) | Required identity and metrics for a storage result |
| [Storage security](./STORAGE-SECURITY.md) | Trust model, destructive-operation policy, and open review items |
| [Storage tools](./STORAGE-TOOLS.md) | The hosted xaiFS CLI and the guest lifecycle commands |
| [xaiFS](./XAI-FS.md) | The portable reader and its ownership rules |
| [`xaiosctl`](./XAIOSCTL.md) | Command surface, output shapes and exit codes |

`ARCHITECTURE.md`, `GETTING-STARTED.md`, `UNIX-COMPATIBILITY.md` and
`VMWARE-FUSION.md` are the four pointers described above. They are kept so
existing links resolve, and each one says where its subject went.

`MODEL-SUPPORT.json` and `PLATFORM-SUPPORT.json` are machine-readable
registries; `tests/repository/check-model-support.py` and
`check-platform-support.py` read them, and the project tracker is the prose
that must agree with them.
