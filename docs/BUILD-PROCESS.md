# How an XAIOS build is produced

This is the reference for building XAIOS and for cutting a numbered release: what
each step makes, what order the steps go in, and — the part that matters most —
what each check in the sequence is there to catch. Almost every rule below exists
because something got past its absence once, and the incident is named rather
than summarised, because a rule whose reason has been lost is a rule someone
removes.

`wiki/Getting-Started.md` is the other document about building: it is for
someone who wants a booted machine. This one is for someone who wants to
understand the pipeline or to publish from it.

## The shape of it

```
 sources ──► per-architecture payload ──► image ──► release package ──► kits
                (build-image.sh)    (build-arch-   (build-release.sh)   (build-vm-packages.sh
                                     image.sh)                           build-boot-media.sh)
```

Everything downstream of the payload is per architecture, and has been since
build 6. Before that a release was a single ISO carrying an AArch64, an x86-64
and a RISC-V loader, kernel and initial filesystem. UEFI makes that work —
firmware picks its own loader from the removable-media path and never sees the
others — and it was genuinely one deliverable. What it was not was easy to
reason about: a boot that went wrong had three kernels, three initial
filesystems and three loaders on the medium to be wrong about; the file was
220 MB of which about thirty was payload; and an architecture whose build had
quietly not happened produced an image that still booted on the machine that
built it and not on the machine it was carried to.

## Before anything

    make bootstrap

`scripts/macos-bootstrap.sh` checks for and installs what the build needs:
`clang`, `lld`, `llvm-objcopy`, `llvm-readelf`, `qemu`, `python3`. The image
builders additionally need `xorriso`, `mtools` (`mformat`, `mmd`, `mcopy`,
`mdir`, `minfo`) and `zip`; the Virtualization.framework kit needs `swiftc`, and
the network-boot server script needs `dnsmasq` on whoever runs it, not on
whoever builds it.

On a Mac the toolchain is not on the default `PATH`. Builds and gates want:

    export PATH=/opt/homebrew/opt/llvm/bin:/opt/homebrew/bin:$HOME/.docker/bin:/usr/bin:/bin:/usr/sbin

`/usr/sbin` is in that list for `lsof`, which several network gates use, and
Homebrew's `llvm` must precede Apple's `clang` or the freestanding builds pick
up the wrong linker.

## `BUILD_NUMBER`

One integer in a file at the repository root, and the single source of the
build's identity. The kernel prints it on its first boot line, `xaiosctl
version` reports the same string, and every released file is named for it — so a
support case, an advisory and a file on disk cannot disagree about what is
running.

There is no `MAJOR.MINOR.PATCH`. There was, and it was invented rather than
earned: nothing had shipped, so the three numbers recorded no history and
implied compatibility rules nobody had agreed to.

Bumping it makes `make docs-check` fail until `CHANGELOG.md` has a matching
`## Build <n>` section, which is deliberate: a build nobody has described is one
nobody can find out what changed in.

**Never renumber a published build.** Build 5 shipped as a single unified image;
when the per-architecture split landed, the tree began producing a completely
different set of files under the same number. The correct move was to bump to 6
and leave build 5 exactly as published — its note, its README table and its
GitHub assets are the historical record of what people actually downloaded.

## Building one architecture

    make image                                    # AArch64, release configuration
    XAIOS_TARGET_ARCH=x86_64 ./scripts/build-image.sh
    ./scripts/build-riscv64.sh                    # RISC-V has its own builder

`build-image.sh` produces the payload: the UEFI loader, the kernel ELF, and the
initial filesystem holding userspace. RISC-V is built by `build-riscv64.sh` and
`build-riscv64-image.sh` rather than by the shared script.

Two environment variables select a *configuration*, not an architecture, and
confusing them has cost real time:

| Variable | Effect |
|---|---|
| `XAIOS_BOOT_TEST_APPS=1` | the boot-test configuration: launches applications as processes so gates can assert the command surface |
| `XAIOS_BOOT_VERBOSE=1` | verbose boot console |
| `XAIOS_STRESS_TEST=1` | a *build* flag; without it `/bin/smpstress` is not compiled in at all |
| `XAIOS_FAULT_TEST=page\|ro\|nx` | a kernel that faults on purpose. See the warning below |

## Building an image

    make release-image-aarch64
    make release-image-x86_64
    make release-image-riscv64
    make release-images          # all three, serially

Each target builds that architecture's payload and then wraps it with
`scripts/build-arch-image.sh`, which writes `build/xaios_b<n>-<arch>.iso` and the
EFI System Partition it was made from, `build/esp-<arch>.img`.

The output is a hybrid: an ISO 9660 filesystem that is simultaneously a
GPT-partitioned disk carrying an EFI System Partition. One file, three ways in —
firmware that boots optical media reads the El Torito entry, firmware that boots
disks finds the ESP in the GPT, and anything that just wants to read it mounts
the ISO.

**Serial, never parallel.** Every builder writes the same `build/` directory. See
*Two builders at once* below.

### Things in the image builder that are not free to change

**The kernel's filename on AArch64 is `kernel.elf` and nothing else.** VMware
Fusion boots an image whose kernel has that name, and boots nothing at all, with
no output, from an otherwise identical image where the only change is that name.
Measured by renaming that one file in a working image and watching it stop
booting. Why its firmware cares is not understood. The other two loaders ask for
their qualified name first and fall back to `kernel.elf`.

**The AArch64 removable-media path holds GRUB, not the XAIOS loader.** Fusion's
firmware will not launch the XAIOS loader from optical media; it will launch
GRUB, whose only job is to find `XAIOS.EFI` and hand over. The other three
environments launch GRUB perfectly well. This is why `make vmware-fusion-image`
has to have been run before a release image is built, and why a clean of
`build/` silently breaks the AArch64 image until it is.

**The EFI System Partition must be FAT16.** Fusion boots FAT16 from the El Torito
path and boots nothing, silently, from FAT32 — no output, no error, a VM that
runs and does nothing. QEMU and Virtualization.framework read either, so this
shows up on one platform and only on the optical path, which is the worst way for
a constraint to be enforced. `mformat` picks the type from the size, so the size
is what has to be right; the builder asks `minfo` what it actually got rather
than assuming the size still implies it. A 4 MiB partition comes out FAT12 and is
refused.

**ESP sizes are per architecture and not arbitrary.** The partition appears twice
in the finished ISO — once as the El Torito boot image, once as the appended GPT
partition — so every megabyte costs two in the output.

| Architecture | ESP | Image | Why |
|---|---|---|---|
| AArch64 | 96 MiB | ~219 MB | the size every image Fusion has ever booted was built at; shrinking it is a Fusion re-qualification, not an edit |
| x86-64 | 32 MiB | ~78 MB | payload is about 10 MB |
| RISC-V | 32 MiB | ~84 MB | payload is about 17 MB |

`XAIOS_ARCH_IMAGE_ESP_MIB` overrides it, and the FAT16 check still applies.

## Building the release package

    make release-package          # release-images, then scripts/build-release.sh

This copies each `build/xaios_b<n>-<arch>.iso` into `release/` and writes a zip
beside it. Both files of a pair are written together and both checksums printed:
a zip made separately from the image it contains drifts from it silently — one
did, within an hour of the image being rebuilt, and the only way anyone noticed
was checksumming what was inside it.

The AArch64 image is over GitHub's 100 MB file limit, which is why the zips
exist. The other two are under it and are zipped anyway, because a release whose
three files are fetched three different ways is a release people get wrong.

`build-release.sh` refuses to proceed when:

- an architecture it was asked for has no image (`XAIOS_RELEASE_ARCHS` selects
  the set; the default is all three);
- an image exists but the ESP it was built from does not, so what is inside it
  cannot be checked;
- the ESP is *newer* than the image, meaning the partition being checked is not
  the one inside the image;
- an image's ESP has no loader at the removable-media path firmware looks for —
  `BOOTAA64.EFI`, `BOOTX64.EFI`, `BOOTRISCV64.EFI`;
- the VMware Fusion chainloader is absent or under 1 MB. The size is the test,
  not the existence: a placeholder file at that path passes any check that only
  asks whether it exists, and one did.

## Building the kits

    ./scripts/build-vm-packages.sh
    ./scripts/build-boot-media.sh

Both read `release/xaios_b<n>-<arch>.iso`, so they run *after* `build-release.sh`.
Eleven kits:

| Kit | AArch64 | x86-64 | RISC-V |
|---|---|---|---|
| `-qemu.zip` — the image and its launcher | yes | yes | yes |
| `-usb.zip` — the image and `write-usb.sh` | yes | yes | yes |
| `-netboot.zip` — one self-contained binary and `serve-netboot.sh` | yes | yes | yes |
| `-vmware-fusion.zip` — the image and a `.vmx` | yes | — | — |
| `-virtualization-framework.zip` — the image and a Swift harness | yes | — | — |

Fusion and Virtualization.framework are AArch64 only because both run guests on
the host Mac's own cores. An x86-64 or RISC-V guest there would be emulation,
which is what the QEMU kits are for.

A network-boot binary is not the image. Firmware that boots from the network
fetches exactly one file and then has nowhere to go back to, so the kernel, the
initial filesystem and an entropy seed are appended to the loader as PE sections
rather than sitting beside it as files. It also carries a plain copy of the
loader, because a running PE cannot be copied back out — firmware maps its
sections at their virtual addresses, so what is in memory is not the file that
was fetched — and a netbooted machine installing to a disk has to write one.

Each architecture's `serve-netboot.sh` answers one DHCP option 93 client
architecture value: `0x000b` (ARM64 EFI), `0x0007`/`0x0009` (x86-64 EFI),
`0x001b` (RISC-V 64-bit UEFI, given to dnsmasq as the number 27 because it has
no name in dnsmasq's table). Serving one file to all comers is the common mistake
and produces a machine that fetches successfully and then faults on a binary for
another architecture.

### Two traps in the kit builders

**`platform/vmware-fusion/XAIOS.vmx.in` has placeholders**, and a kit shipping an
unsubstituted one is a VM Fusion refuses to power on — `vmrun start` says only
"Communication with the virtual machine might have been interrupted", no serial
log is created, and nothing else reports a problem. `@@XAIOS_FUSION_NIC@@` bit
once; `@@XAIOS_FUSION_MEMSIZE@@` had been unsubstituted since the commit that
introduced it and made the Fusion kit unbuildable. The builder now fails on any
leftover `@@`.

**A checksum fallback must not be attached to a pipeline.** `shasum ... | cut ||
sha256sum ...` never fires the fallback, because `cut` succeeds on empty input —
so on a host without `shasum` the kit would ship a `SHA256SUMS` of blank
checksums that verifies nothing.

## Gating it

Cheapest first.

    make docs-check          # twelve repository checks, no build, seconds
    make compile-check       # every freestanding source compiles clean
    make hosted-test         # unit tests that run on the host
    make release-image-gate  # each image on all five environments
    make boot-media-gate     # each kit's files, and each netboot binary booted
    make vm-package-gate     # each VM kit booted out of its own archive
    make local-gates         # the two hypervisors, recorded against HEAD
    make release-check       # refuses to pass unless the above happened

`release-image-gate` is the one that says the file a release ships boots. It
boots each `.iso` on QEMU AArch64, QEMU x86-64, QEMU RISC-V,
Virtualization.framework and VMware Fusion, and requires each guest to print
*this build's* number and `system-slot: unavailable`.

That second marker is not decoration. The loader prefers a verified A/B system
slot over the kernel on the medium, so a guest booted with a system volume
attached runs the kernel from the volume and not the one in the file under test —
which looks exactly like the image booting and is not. The Virtualization.
framework row did precisely that and reported success, while the guest printed
`XAIOS Build 5 kernel starting` during a test of build 6's image. It went
unnoticed because the marker was `XAIOS Build \d+ kernel starting`: any build
satisfied it.

`boot-media-gate` boots each shipped network-boot binary from an EFI System
Partition. It cannot test the fetch — that needs firmware on a real network — but
everything after the fetch is the same code path, and before this existed the
shipped binaries had never been started at all, because the binary
`qemu-netboot-gate` boots is deliberately a different one.

`local-gates` records `build/local-gates.json` naming the commit it checked.
`check-local-gate-record.py` requires that record to name **HEAD exactly** and to
have been taken against a clean tree. Not an ancestor: a change that looks
harmless in a diff is precisely the kind that has broken a hypervisor here
before. In practice this means `local-gates` is the last thing you run before
tagging, and any commit after it — a typo fix in a README included — costs
another run.

## Publishing

1. `release/xaios_b<n>.md` — the release note. It publishes a SHA-256 for every
   file and states what was *not* tested as plainly as what was.
2. `## Build <n>` in `CHANGELOG.md`, written for someone *running* XAIOS rather
   than someone reading the diff.
3. The build number in `README.md`, `wiki/Home.md`, `wiki/Getting-Started.md`.
   The download tables are per architecture and nothing checks them against the
   release note, so they are the thing most likely to be left describing the
   build before.
4. `make release-check`.
5. `git tag b<n>` and push it.
6. `gh release create b<n>` with the three `.iso.zip` files and the eleven kits.
   The raw `.iso` files are not uploaded; the AArch64 one is over the limit and
   the other two follow it for consistency.

Only `release/xaios_b<n>*.iso.zip` and `release/xaios_b<n>.md` are tracked in
git; kits and raw ISOs are ignored. Three zips is about 34 MB per build.

`check-release-package.py` reads the note and requires that every image it names
has an archive, that each archive contains exactly its image, that the checksums
match on disk *and inside the archive*, and — the half that stops the rule being
circular — that nothing in `release/` for this build goes undescribed. It is
note-driven rather than hard-coded to three architectures, because build 5's note
describes one image and is not wrong about build 5.

## Two builders at once

Do not run two things that write `build/` at the same time. This is not caution,
it is an incident report.

`make qemu-fault-matrix` compiles three kernels that halt on purpose — the
`XAIOS_FAULT_TEST` builds — each into the same `build/kernel*/kernel.elf` that
every packaging script reads, and restores a normal image when it finishes. That
restoration is a courtesy, not a guarantee: interrupt it, crash it, or run a
packaging script beside it, and the tree holds a kernel that halts on purpose
under the name that means "the kernel". A netboot binary was built exactly that
way. It looked like a release binary in every respect a person can check, and the
only thing that caught it was `boot-media-gate` booting it and watching it stop
at `exceptions: triggering controlled NX execute fault`.

Since then such a kernel writes a marker into its own bytes, and
`build-arch-image.sh` and `build-netboot-image.sh` both refuse a kernel carrying
it, without booting anything. `tests/repository/check-fault-test-marker.py` keeps
the kernel's copy of that string and the two scripts' copies in step, because a
grep that can no longer match is a check that cannot fail.

The same rule applies to gates: editing a source file while `local-gates` runs
produces a record describing a tree that never existed, because several of its
legs rebuild. That has happened here too, and the honest response is to discard
the record rather than keep a result that cannot be attributed.

## Cleaning

`make clean` removes `build/`. Two things do not come back by themselves:

- the VMware Fusion chainloader, which needs `make vmware-fusion-image` and
  Docker;
- `build/xaios-persistent.img`, the durable volume most ad-hoc runs share.
  `make clean-persistent` removes it, and occasionally should: a volume tens of
  boots deep accumulates enough fragmentation to be interesting, and gates that
  boot it unisolated will report the machine's history as a defect in the guest.
