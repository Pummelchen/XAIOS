# Release and build rules — XAIOS

The release and build standard for this repository.

**This file belongs to this repository.** Edit it here and nowhere else. It was once
deployed from a master document kept in another repository; that arrangement is gone.
Nothing outside this repository governs these rules or can overwrite this file, and an
agent working here never needs to leave the repository to find the standard.

**Part 1 is the rule set** and **Part 2 is this repository's own section**; where the
two appear to disagree, Part 2 wins.

---

# Part 1 — Generic rules

## 1.1 Scope

These apply to any repository that produces a **runnable artifact**: a binary, a
library, an image, a package. Repositories that only hold documents, data or
configuration are out of scope, and should say so in their Part 2 section rather
than adopting a release process they cannot use.

## 1.2 Non-negotiable

1. **Apple Silicon only.** Build native `arm64`. This covers M1–M6. Never
   `--arch x86_64`, never `ARCHS=arm64 x86_64`, and never `lipo -create` — that
   is how a universal binary gets made, and there is no x86_64 build.
2. **Assert it, do not assume it.** After building, check the artifact:
   `lipo -archs <binary>` must be exactly `arm64`. A build that silently produced
   a fat binary is a release defect, not a build option.
3. **Every release carries the artifacts.** A tag alone is not a release. If the
   Release page has no binaries attached, the release did not happen.
4. **No hardcoded build-toolchain triple in a path.** `.build/release` is the
   stable spelling. `.build/arm64-apple-macosx/release` points at nothing on a
   newer toolchain and at a stale binary on this one. The one exception is a build
   that explicitly passes `--arch arm64`: then the triple directory really is
   where SwiftPM writes, and that build must also assert the arch (§1.2.2).
5. **One checksummed artifact per target, or one checksum file covering all of
   them.** Never publish a binary without a digest beside it.
6. **Dry run by default; publish only on an explicit flag.**
7. **Never fetch a model, dataset or dependency to make a gate pass.** A check
   that cannot run is reported *not checked* — and the release notes must name it.
   "Not checked, no input" and "checked and identical" are different sentences.

## 1.3 Identity

The version or build number is **single-sourced and enforced**, not maintained by
hope.

- **One authoritative value.** A file at the repository root — `VERSION` for a
  semantic version, `BUILD_NUMBER` for a build number. Anywhere else it appears
  is a **mirror**, and the build or CI must fail when a mirror disagrees.
- **Pick one scheme and state it.** Semantic versions (`vX.Y.Z`) or build numbers
  (`b1`, `b2`). Do not mix them, and do not "helpfully" introduce versions into a
  project that uses build numbers.
- **The build refuses a malformed or inconsistent identity.** Fail at configure
  or compile time, not at release time.
- **Identity is observable.** A user must be able to say what they are running
  from the artifact alone: the archive filename, or the program's own answer, or
  both.
- **Bump once, propagate mechanically.** Provide a command that writes the mirrors
  from the authoritative value. A release is one edit plus one command.
- **A second declaration in a test is a defect.** Derive the expected value from
  the source of truth; a literal in a test means every bump fails a test that is
  not about the version, and the tempting fix — editing the test — is how a wrong
  version ships.
- **Multi-library projects version in lockstep.** Libraries that ship together and
  interoperate carry the **same** version, because a caller pairing them has no
  other way to know the pair is compatible. A library with no code change is
  recompiled and republished at the new number rather than left behind.
  Lockstep applies to the **library version only** — an ABI version, protocol
  draft, or schema version is a separate axis and must not be dragged along.

## 1.4 Preconditions

Before starting, confirm and record: the OS floor and toolchain floor are met
(`sw_vers`, `swift --version`); there is disk for a clean scratch build plus the
staged archive; `memory_pressure -Q` is acceptable; **no competing build or model
process is running**; `gh auth status` is the repository owner's account; the tree
is clean; and `HEAD` **is** the tag.

**Never terminate a process you did not start.** If one is blocking, name it with
its parent and age, and stop.

## 1.5 Gates

Run these in order, and make each one **able to fail**:

1. **Lint** — the project's own lint gates.
2. **Full test suite**, serially, and it must report the count that passed.
3. **Parity or golden checks** — real inference, real rendering, real protocol
   frames; whatever "the output is unchanged" means for this project.
4. **A clean scratch build** with the log scanned for warnings.

Two traps, both of which have shipped broken gates in this organisation:

- **A gate that cannot fail is not a gate.** A guard that looks for a file the
  build never produces passes for every input. A warning scan over an *incremental*
  build compiles nothing and passes vacuously — always use a fresh scratch path.
  Before trusting a new gate, break its input and watch it fail.
- **Guard the plan, not the byproduct.** Ask the build system what it resolved
  (`swift package describe --type json`, `cmake --build ... -t help`) rather than
  checking for artifacts after the fact.

## 1.6 Packaging

The archive contains, at minimum:

- the **executables or libraries**, built for arm64;
- **resource bundles** — a Swift binary without its `.bundle` cannot load its
  Metal kernels, and this fails at runtime rather than at build time;
- `LICENSE`, and `NOTICE` / `THIRD_PARTY_NOTICES.md` where third-party code is
  redistributed;
- a **`README-binaries.txt`** stating the platform floor, that the build is
  Apple-Silicon-only, and that the binaries are **not code-signed or notarized** —
  with the quarantine command (`xattr -dr com.apple.quarantine <path>`) so a user
  who verified the checksum can run them. Do not imply a notarized build.

Name the archive `<project>[-<library>]-<version>-macos-arm64.tar.gz`; the
library segment is required only for a multi-library project, and exists so two
artifacts of the same release are distinguishable.

## 1.7 Publishing

```bash
gh release create "$TAG" "$ARCHIVE" "$ARCHIVE.sha256" \
  --repo <owner>/<repo> --title "<Project> $VERSION" \
  --notes-file "$NOTES" --latest
```

**Pin `--repo` on every `gh` call.** In a fork `gh` defaults to the *parent*
repository, so `gh release list` shows another project's releases and
`gh release create` fails with a misleading "tag has not been pushed".

## 1.8 Release notes

- Full notes in `docs/release-notes-vX.Y.md` (or the repository's equivalent),
  one section per user-visible change, each naming the check that backs it.
- End with a checksum block carrying `SHA256_PENDING` and
  `ARCHIVE_BYTES_PENDING`, substituted at publish time. **Never copy a size out
  of a dry run** — publish rebuilds, and the archive differs.
- `--publish` must **refuse** unless the notes carry the placeholder or quote the
  real value. A release quoting the wrong digest is worse than one quoting none.
- Name **every** check that did not run, and why.
- The README gets **no release callout**. It changes only when a fact it states
  changes. The changelog is the announcement.

## 1.9 After publishing

Verify the Release: the notes quote the digest in the `.sha256` beside it, the
assets are the archive and its checksum, and the changelog points at the same tag.
Leave previous releases' notes and performance tables alone.

## 1.10 Rules, agents and other repositories

- **These rules live in this repository and are edited only here.** They are not
  deployed from anywhere and nothing outside this repository can overwrite them. A
  rule an agent cannot find is a rule that will be broken, so a rule about this
  repository belongs in this file or in `AGENTS.md` — not in a shell-script comment,
  and not in another repository.
- **Work happens in this repository only.** Never commit, push, open a pull request
  against, or otherwise modify another repository. A change that appears to belong
  elsewhere is reported to the owner with the exact edit and the reason, not applied.
  Touching another repository requires an instruction that names it, and "the fix
  lives there" is not one. **The one write that is part of this repository's own
  workflow is the published Wiki:** `wiki/` is the source of truth, and the
  `publish-wiki` CI job copies `wiki/*.md` over `XAIOS.wiki.git` after the
  documentation contract passes and then reads it back with
  `make wiki-parity-check`. Agents edit `wiki/` in this repository; publishing it by
  hand is a maintainer action, and an edit made on the published pages is overwritten
  by the next publish.
- **`AGENTS.md` is the one instruction file, and every harness must reach it.** This
  account works with Codex, Claude Code, DeepSeek Harness, OpenCode, Qwen Code,
  Qoder and Zed. Six read `AGENTS.md` directly; **Claude Code does not** — its
  documentation is explicit that it reads `CLAUDE.md`, not `AGENTS.md` — so this
  repository also carries a committed `CLAUDE.md` whose entire content is the
  `@AGENTS.md` import. Commit it: a symlink made on one machine is invisible to a
  fresh clone, to CI and to every other checkout, and on Windows it needs
  Administrator rights. Qwen Code reads `AGENTS.md` alongside its own `QWEN.md`, so
  there is nothing to duplicate for it.
- **Never add a file that shadows `AGENTS.md`.** Zed takes the *first match* from
  `.rules`, `.cursorrules`, `.windsurfrules`, `.clinerules`,
  `.github/copilot-instructions.md`, `AGENT.md`, and only then `AGENTS.md` — so any
  of those six silently replaces this file for every Zed user. Check for them whenever
  the instruction file changes.
- **An archived repository is read-only.** Nothing can be committed to it, so no
  release step may depend on one. Name the exclusion rather than leaving a gap.
- **A check that has never been seen to fail is not yet trusted.**

# Part 2 — This repository

## XAIOS — C, **build numbers**, 8 releases

*An operating system, not an application. Two rules that apply elsewhere do not
apply here.*

- **Identity is a build number, not a version.** Tags are `b1`, `b2`, … `bN`, and
  the Release title is "XAIOS Build N". **Do not introduce semantic versions.**
  Single-sourced from the `BUILD_NUMBER` file at the root, which must be a whole
  number — the build refuses to proceed otherwise — and which the running system
  reports on its first boot line and from `xaiosctl version`, so a support case,
  an advisory and a file on disk cannot disagree about what is running.
- **The multi-architecture release is intentional and stays as it is.** XAIOS
  publishes guest images for `aarch64`, `riscv64` **and** `x86_64`. Those are
  **guest** architectures, not host binaries: the Apple-Silicon-only rule (§1.2.1)
  governs host binaries a contributor builds for their own Mac, and does not
  restrict which architectures the OS ships images for. Do not "standardise" this
  list, and do not apply a host `lipo` assertion to a guest image.
- **Artifacts** are committed under `release/` (`xaios_bN-<arch>.iso.zip`) beside a
  per-build notes file `release/xaios_bN.md`, and the same files are attached to
  the Release. This is the one project that keeps built artifacts in-tree; that is
  a deliberate choice, not an oversight, and the reason is that a released image
  must remain fetchable at the tag it names.
- **Builders** `scripts/build-arch-image.sh` per architecture, `Makefile` at the
  root, `platform/*/build-*.sh` per hypervisor target.
- **Gates** `BUILD_NUMBER` validation, which `make docs-check` cross-checks against
  the `## Build <n>` section in `CHANGELOG.md` — bump both together or the gate
  fails. Then `make compile-check` (which runs `make wt-upstream-compile` beside it),
  `make hosted-test`, `make xapt-test`, the WebTransport gates
  (`make wt-vectors-check`, `make wt-host-test`, `make wt-host-sanitize`,
  `make wt-interop-test`, `make qemu-quic-handshake-gate`) and the other QEMU boot
  gates. **`release-check` is local-only**: no CI job runs it, and `local-gates` must
  be recorded against HEAD on a clean tree, because any later commit costs another
  run.
