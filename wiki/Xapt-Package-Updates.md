# xapt Package Updates

`xapt` is XAIOS's native, deliberately small package updater. It distributes
complete XAIOS application ELFs rather than source packages or Linux/FreeBSD
binaries. Applications can be installed, upgraded, removed, or rolled back
without replacing the OS. A system update is streamed into the inactive A/B
slot and takes effect only after reboot.

## Operator commands

```sh
xapt update
xapt list
xapt list --upgradable
xapt search APP
xapt show APP
xapt install APP
xapt upgrade APP
xapt rollback APP
xapt remove APP
xapt os-upgrade
```

`APP` is a package name returned by the signed catalog. The current production
catalog contains no optional applications; a newly published application is
offered by `xapt list` without requiring an OS-image update.

`xapt update` fetches and activates the catalog only after signature,
architecture, and monotonic-generation validation. Install and upgrade are
explicit confirmation actions; there is no dependency resolver and no
automatic background update. A newly installed application is available by
name immediately and is not started automatically.

## Compatibility and integrity

Each application manifest binds:

- application name and semantic version;
- target architecture;
- minimum XAIOS version and ABI version;
- exact capability mask;
- payload size and SHA-256 digest;
- Ed25519 signer identity and signature.

Catalogs are signed separately, architecture-specific, and generation
monotonic. XAIOS rejects incompatible, downgraded, malformed, oversized, or
corrupted content before activation. Current and previous versions are stored
separately so `xapt rollback NAME` is one-step and atomic. Failed staging does
not change the active application.

System records bind version, architecture, monotonic system generation, byte
size, SHA-256, signed update metadata, and image path. `xapt os-upgrade` rejects
the current or an older version, streams the image in bounded chunks, verifies
it in the inactive slot, and marks that slot pending. The boot lifecycle retains
the existing verified fallback behavior. A pending slot becomes active only
after mandatory boot services have initialized; optional diagnostic fixtures do
not determine OS-slot health.

## Storage layout

```text
/etc/xapt.conf              image default
/state/xapt/config          administrator override
/state/xapt/catalog         last verified catalog
/update/xapt/               non-authoritative staging
/apps/NAME/current.elf      active application
/apps/NAME/current.manifest active signed metadata
/apps/NAME/previous.*       one rollback version
```

The default development origin is `91.99.176.243:8443`. Configuration is plain
text, but transport security is mandatory:

```text
host=91.99.176.243
port=8443
base=/
tls=required
tls_rsa_modulus=OPERATOR_RSA_MODULUS_HEX
```

`xapt` uses TLS 1.2 with an exact operator-managed RSA public-key pin and
fail-closed entropy. Signed catalogs/manifests and payload hashes remain the
content authenticity layer. The client requires HTTP/1.1 with
`Content-Length`; transfer encoding, compression, mirrors, proxies, deltas,
dependencies, and unattended upgrades are not supported.

The signing trust chain is independent of the TLS identity. Monotonic signed
trust records rotate the active Ed25519 release key and revoke the previous
key. A separately pinned offline recovery key can publish a later recovery
record. XAIOS retains the previous verified trust/catalog pair and restores it
after an interrupted activation; replayed generations, revoked signers, and
mismatched trust/catalog generations fail closed.

## Build and publish a development repository

```sh
make xapt-repository
./scripts/publish-xapt-repository.sh
```

The first command creates and verifies both architecture trees under
`build/xapt/repository`. The publisher re-verifies locally, synchronizes to
`/var/xaios_updater`, validates the repository Caddy configuration, and reloads
Caddy on TLS port 8443. Override the destination with `XAIOS_UPDATE_HOST` and
`XAIOS_UPDATE_ROOT`.

Publishing requires `XAIOS_XAPT_TLS_CERT` and `XAIOS_XAPT_TLS_KEY`; the script
refuses to publish without an operator-managed identity. The public fixture may
be selected only for disposable tests with `XAIOS_ALLOW_TEST_TLS_FIXTURE=1`.
The configured `tls_rsa_modulus` must match the deployed certificate key.
Caddy exposes only the TLS listener on port 8443.

The repository shape is:

```text
catalog-aarch64.txt
catalog-x86_64.txt
apps/ARCH/NAME/VERSION/{NAME.elf,manifest.txt,record.json}
os/ARCH/VERSION/{kernel.elf,record.json}
```

Use `tools/xaios_xapt_repo.py` for focused package, system, catalog, and verify
operations. Publishing a newer catalog requires a strictly higher generation.

## Security boundary

The checked-in Ed25519 signing keys and TLS certificate/key are deterministic
test fixtures and their private material is public. They exist so builds and
QEMU tests are reproducible. The implementation covers signing-root rotation,
revocation, offline recovery, interrupted-activation rollback, TLS pin
rejection, and payload corruption. Production use remains blocked until
maintainers provision private operator keys and define custody, authorization,
recovery, and release-audit procedures.

The app loader remains capability-based and does not add a package-manager
syscall. `xapt` uses the existing filesystem, network, clock, and control
protocol surface. Eight new administrative control operations fit inside the
existing control syscall, so the XAIOS syscall count remains 50.

## Evidence

```sh
make xapt-test
make qemu-xapt-gate
```

The dual-architecture QEMU gate proves pinned TLS transport, signed catalog
refresh, signing-root rotation/revocation/recovery, interrupted activation
recovery, independent app install and argv execution, upgrade, one-step
rollback, tamper rejection, streamed A/B OS delivery, reboot persistence, and
removal. QEMU does not prove physical-device durability, Internet-scale
availability, or production key security.

See [[Applications|Applications]], [[Administration|Administration]],
[[Testing XAIOS|Testing-XAIOS]], and [[Security Model|Security-Model]].
