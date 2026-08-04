# Storage Security

Status: parsing, integrity, namespace isolation, destructive-operation
confirmations, and capability-gated online storage administration are
implemented. Production trust-root management and physical-device validation
remain incomplete.

## Trust model

- Block devices and disk metadata are untrusted input. All lengths, offsets,
  additions, multiplications, alignments, counts, and reserved fields are
  validated before allocation or I/O.
- GPT CRC protects structural integrity, not authenticity.
- ModelFS SHA-256 protects metadata and chunk integrity. Ed25519 authenticates
  the signed package identity. Signature verification occurs before package
  admission; touched chunks are hashed before bytes are delivered.
- Package content is immutable after activation. Corruption quarantines or
  rejects the package instead of returning unverified model bytes.
- VFS mount and owner-generation checks prevent handle reuse across owners or
  remounts. Cross-filesystem rename is unsupported.

## Destructive operations

Host format, removal, grow, repair, scrub mutation, recovery cleanup, and trim
require operation-specific exact path/package/volume confirmation. Dry-run or
read-only inspection is separate. There is no generic force flag.

The host CLI cannot independently prove that a path is the boot,
rollback, mounted, or serving device. Its safe operating contract therefore
requires an offline target selected by the administrator. Guest `xaiosctl`
mutations re-read stable device identity, enforce operation-specific capability,
administrator role and replay protection, and audit operation ID, principal,
target identity, result and range counts without logging model bytes or keys.

## Secrets and remote access

Existing SSH/SFTP policy denies private host keys, password databases,
authorized-key sources, and `/state/control`. Model package data is not a
credential, but signer private keys must never be stored in ModelFS images or
passed through guest SFTP. Only public verification keys and signatures are in
the format.

SFTP canonicalizes absolute paths before prefix policy checks and rejects
empty, repeated, trailing, `.` and `..` components. It permits writes only to
signed `/models/.staging/<package-id>` files created by administrator-only
registration. Registration carries the expected package ID and signature,
allocates checked extents and cannot modify active data. Active package
replacement is impossible: active files are immutable and activation rejects a
duplicate active model UUID. Registration, cleanup and activation require an
authenticated administrator, replay-protected operation ID and a durable
copy-on-write ModelFS generation; activation additionally requires complete
package verification.

## Remaining review requirements

- Pin a production trust-root and key rotation/revocation design.
- Security-review the shared Ed25519 implementation currently linked by both
  SSH and the kernel ModelFS verifier.
- Fuzz the portable ModelFS and SFTP packet parsers continuously.
- Add fleet-scale tenant quota, package-expiry and trust-root rotation policy
  before accepting arbitrary untrusted tenants.
- Validate discard, failure recovery, and DMA/IOMMU behavior on physical
  hardware before deployment.
