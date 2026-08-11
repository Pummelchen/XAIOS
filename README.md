<img width="1122" height="1402" alt="image" src="https://github.com/user-attachments/assets/e305c7bb-40f2-4454-87f8-f58c9082d808" />

# XAIOS

XAIOS is an experimental freestanding Unix-like operating system and portable
inference-engine foundation being developed as an SSH-administered distributed
CPU AI model server. The current OS boots under QEMU and exercises deterministic
kernel/runtime contracts. Real-model inference and the dedicated inference
network service are under development and are not production supported.

Human-facing project documentation is maintained in the
[XAIOS Wiki](https://github.com/Pummelchen/XAIOS/wiki). The repository keeps
the complete curated Wiki page set under [`wiki/`](./wiki/) so operating,
architecture, testing, security, and status claims can be checked with source.

## Unix compatibility boundary

FreeBSD is the primary external behavioral reference for portable command,
SSH/SFTP and network interoperability work. XAIOS is not FreeBSD-derived and
does not provide a FreeBSD or Linux binary ABI: guest programs use native XAIOS
syscalls, and passing host-client tests proves wire behavior only. The official
FreeBSD 15.1 AArch64 QEMU gate covers public-key acceptance/rejection,
`xaiosctl`, SFTP, PTY ANSI `htop`, and UDP echo. The Debian 13 client remains an
independent Linux/OpenSSH cross-family gate with broader administration and
load coverage. See [Unix compatibility](./wiki/Unix-Compatibility.md).

## Model support status

The deterministic QEMU model-v1 path is **Fixture only**, and model-v2 is a
format/interface foundation; neither executes a transformer. Qwen 3.6 27B is
the next real-model correctness target. Kimi K3 text, Kimi K3 multimodal,
DeepSeek V4 Flash 0731, and GLM 5.2 remain later targets, and no listed model is
production supported. K3 text and multimodal support are separate milestones.

XAIOS is designed around official architecture adapters rather than a
hard-coded Qwen graph. Exact target-model semantics are the default;
approximate modes, if introduced, will be explicit and opt-in. The single
authoritative delivery order, progress code, support boundary, acceptance gate,
open-decision list, risk register, and official compatibility sources are in the
[Project Tracker](./wiki/Project-Tracker.md). The machine-readable model catalog
at [`docs/MODEL-SUPPORT.json`](./docs/MODEL-SUPPORT.json) contains identifiers,
not an independent status mirror.

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
