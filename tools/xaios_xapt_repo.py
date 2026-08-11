#!/usr/bin/env python3
"""Build and verify deterministic signed XAIOS application repositories."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


TEST_SEED = bytes.fromhex(
    "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
)
PUBLIC_KEY = bytes.fromhex(
    "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
)
PRIVATE = Ed25519PrivateKey.from_private_bytes(TEST_SEED)
ARCHES = {"aarch64", "x86_64"}
SYSTEM_SLOT_BYTES = 16 * 1024 * 1024


def valid_token(value: str, limit: int) -> bool:
    return 0 < len(value) < limit and all(
        ch.islower() or ch.isdigit() or ch in "-_" for ch in value
    )


def semver(value: str) -> tuple[int, int, int]:
    parts = value.split(".")
    if len(parts) != 3 or any(not part.isdigit() for part in parts):
        raise ValueError(f"invalid three-part version: {value}")
    parsed = tuple(int(part) for part in parts)
    if any(part > 0xFFFFFFFF for part in parsed):
        raise ValueError(f"version component out of range: {value}")
    return parsed  # type: ignore[return-value]


def sign_document(unsigned: bytes) -> bytes:
    return unsigned + b"signature=" + PRIVATE.sign(unsigned).hex().encode("ascii") + b"\n"


def verify_document(data: bytes, prefix: bytes) -> bytes:
    if not data.startswith(prefix) or not data.endswith(b"\n"):
        raise ValueError("invalid signed document framing")
    marker = b"signature="
    offset = data.rfind(marker)
    if offset < 0 or data[offset - len(b"key=" + PUBLIC_KEY.hex().encode() + b"\n") : offset] != (
        b"key=" + PUBLIC_KEY.hex().encode() + b"\n"
    ):
        raise ValueError("missing trusted key immediately before signature")
    signature_hex = data[offset + len(marker) : -1]
    if len(signature_hex) != 128:
        raise ValueError("invalid Ed25519 signature width")
    PRIVATE.public_key().verify(bytes.fromhex(signature_hex.decode("ascii")), data[:offset])
    return data[:offset]


def package(args: argparse.Namespace) -> None:
    if not valid_token(args.name, 32):
        raise ValueError("invalid application name")
    semver(args.version)
    semver(args.minimum_os)
    if args.arch not in ARCHES:
        raise ValueError("unsupported architecture")
    binary = args.elf.read_bytes()
    if not binary.startswith(b"\x7fELF") or not binary or len(binary) > 131072:
        raise ValueError("application must be a non-empty ELF no larger than 128 KiB")
    target = args.repository / "apps" / args.arch / args.name / args.version
    target.mkdir(parents=True, exist_ok=True)
    binary_name = f"{args.name}.elf"
    shutil.copyfile(args.elf, target / binary_name)
    unsigned = (
        "XAIOS-APP-V1\n"
        f"name={args.name}\n"
        f"version={args.version}\n"
        f"arch={args.arch}\n"
        f"min_os={args.minimum_os}\n"
        f"min_abi={args.minimum_abi}\n"
        f"capabilities={args.capabilities}\n"
        f"size={len(binary)}\n"
        f"sha256={hashlib.sha256(binary).hexdigest()}\n"
        f"key={PUBLIC_KEY.hex()}\n"
    ).encode("ascii")
    manifest = sign_document(unsigned)
    (target / "manifest.txt").write_bytes(manifest)
    (target / "record.json").write_text(
        json.dumps(
            {
                "name": args.name,
                "version": args.version,
                "arch": args.arch,
                "minimum_os": args.minimum_os,
                "description": args.description,
                "manifest": f"/apps/{args.arch}/{args.name}/{args.version}/manifest.txt",
                "binary": f"/apps/{args.arch}/{args.name}/{args.version}/{binary_name}",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    verify_document(manifest, b"XAIOS-APP-V1\n")
    print(f"xapt-repo: packaged {args.name} {args.version} {args.arch} bytes={len(binary)}")


def system(args: argparse.Namespace) -> None:
    semver(args.version)
    if args.arch not in ARCHES:
        raise ValueError("unsupported architecture")
    if args.generation <= 0 or args.generation > 0xFFFFFFFF:
        raise ValueError("system generation must be between 1 and 4294967295")
    image = args.image.read_bytes()
    if not image or len(image) > SYSTEM_SLOT_BYTES:
        raise ValueError("system image must fit the 16 MiB inactive slot")
    digest = hashlib.sha256(image).hexdigest()
    unsigned = (
        f"xaios-update:v2:gen={args.generation}:sha256={digest}:"
        f"key={PUBLIC_KEY.hex()}"
    ).encode("ascii")
    signature = unsigned.decode("ascii") + ":sig=" + PRIVATE.sign(unsigned).hex()
    target = args.repository / "os" / args.arch / args.version
    target.mkdir(parents=True, exist_ok=True)
    image_name = "kernel.elf"
    shutil.copyfile(args.image, target / image_name)
    record = {
        "version": args.version,
        "generation": args.generation,
        "arch": args.arch,
        "size": len(image),
        "sha256": digest,
        "signature": signature,
        "image": f"/os/{args.arch}/{args.version}/{image_name}",
    }
    record_path = target / "record.json"
    record_path.write_text(json.dumps(record, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"xapt-repo: system {args.version} generation={args.generation} "
        f"{args.arch} bytes={len(image)} record={record_path}"
    )


def catalog(args: argparse.Namespace) -> None:
    records: dict[str, dict[str, object]] = {}
    root = args.repository / "apps" / args.arch
    for record_path in sorted(root.glob("*/*/record.json")):
        record = json.loads(record_path.read_text(encoding="utf-8"))
        name = str(record["name"])
        current = records.get(name)
        if current is None or semver(str(record["version"])) > semver(str(current["version"])):
            records[name] = record
    if args.generation <= 0 or args.generation > 0xFFFFFFFF:
        raise ValueError("catalog generation must be between 1 and 4294967295")
    lines = [
        "XAIOS-CATALOG-V1",
        f"generation={args.generation}",
        f"generated={args.generated}",
        f"arch={args.arch}",
    ]
    if args.os_record:
        os_record = json.loads(args.os_record.read_text(encoding="utf-8"))
        if os_record["arch"] != args.arch:
            raise ValueError("OS record architecture mismatch")
        lines.append(
            "os=" + "|".join(
                str(os_record[key])
                for key in ("version", "generation", "arch", "size", "sha256", "signature", "image")
            )
        )
    for name in sorted(records):
        record = records[name]
        values = [
            str(record[key])
            for key in ("name", "version", "arch", "minimum_os", "manifest", "binary", "description")
        ]
        if any("|" in value or "\n" in value for value in values):
            raise ValueError("catalog fields may not contain separators")
        lines.append("app=" + "|".join(values))
    lines.append(f"key={PUBLIC_KEY.hex()}")
    data = sign_document(("\n".join(lines) + "\n").encode("ascii"))
    output = args.repository / f"catalog-{args.arch}.txt"
    output.write_bytes(data)
    verify_document(data, b"XAIOS-CATALOG-V1\n")
    print(f"xapt-repo: catalog {args.arch} apps={len(records)} bytes={len(data)}")


def verify(args: argparse.Namespace) -> None:
    catalogs = sorted(args.repository.glob("catalog-*.txt"))
    if not catalogs:
        raise ValueError("repository has no catalogs")
    package_count = 0
    system_count = 0
    for catalog_path in catalogs:
        unsigned = verify_document(catalog_path.read_bytes(), b"XAIOS-CATALOG-V1\n")
        fields = dict(
            line.split("=", 1)
            for line in unsigned.decode("ascii").splitlines()[1:4]
        )
        expected_arch = catalog_path.stem.removeprefix("catalog-")
        generation = int(fields.get("generation", "0"))
        if generation <= 0 or generation > 0xFFFFFFFF:
            raise ValueError(f"invalid catalog generation: {catalog_path}")
        if fields.get("arch") != expected_arch:
            raise ValueError(f"catalog architecture mismatch: {catalog_path}")
    for manifest_path in sorted(args.repository.glob("apps/*/*/*/manifest.txt")):
        unsigned = verify_document(manifest_path.read_bytes(), b"XAIOS-APP-V1\n")
        fields = dict(
            line.split("=", 1)
            for line in unsigned.decode("ascii").splitlines()[1:]
        )
        binary = manifest_path.parent / f"{fields['name']}.elf"
        payload = binary.read_bytes()
        if int(fields["size"]) != len(payload) or fields["sha256"] != hashlib.sha256(payload).hexdigest():
            raise ValueError(f"package payload mismatch: {manifest_path}")
        package_count += 1
    for record_path in sorted(args.repository.glob("os/*/*/record.json")):
        record = json.loads(record_path.read_text(encoding="utf-8"))
        arch = str(record["arch"])
        version = str(record["version"])
        generation = int(record["generation"])
        if arch not in ARCHES or record_path.parts[-3:-1] != (arch, version):
            raise ValueError(f"system record path mismatch: {record_path}")
        semver(version)
        image = record_path.parent / "kernel.elf"
        payload = image.read_bytes()
        digest = hashlib.sha256(payload).hexdigest()
        if int(record["size"]) != len(payload) or str(record["sha256"]) != digest:
            raise ValueError(f"system payload mismatch: {record_path}")
        signed, signature_hex = str(record["signature"]).rsplit(":sig=", 1)
        expected = (
            f"xaios-update:v2:gen={generation}:sha256={digest}:"
            f"key={PUBLIC_KEY.hex()}"
        )
        if signed != expected:
            raise ValueError(f"system signature metadata mismatch: {record_path}")
        PRIVATE.public_key().verify(bytes.fromhex(signature_hex), signed.encode("ascii"))
        system_count += 1
    print(
        f"xapt-repo: verified catalogs={len(catalogs)} "
        f"packages={package_count} systems={system_count}"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    package_parser = commands.add_parser("package")
    package_parser.add_argument("--repository", type=Path, required=True)
    package_parser.add_argument("--elf", type=Path, required=True)
    package_parser.add_argument("--name", required=True)
    package_parser.add_argument("--version", required=True)
    package_parser.add_argument("--arch", required=True)
    package_parser.add_argument("--minimum-os", default="0.1.0")
    package_parser.add_argument("--minimum-abi", type=int, default=1)
    package_parser.add_argument("--capabilities", type=int, required=True)
    package_parser.add_argument("--description", required=True)
    package_parser.set_defaults(function=package)
    system_parser = commands.add_parser("system")
    system_parser.add_argument("--repository", type=Path, required=True)
    system_parser.add_argument("--image", type=Path, required=True)
    system_parser.add_argument("--version", required=True)
    system_parser.add_argument("--generation", type=int, required=True)
    system_parser.add_argument("--arch", required=True)
    system_parser.set_defaults(function=system)
    catalog_parser = commands.add_parser("catalog")
    catalog_parser.add_argument("--repository", type=Path, required=True)
    catalog_parser.add_argument("--arch", required=True, choices=sorted(ARCHES))
    catalog_parser.add_argument("--generated", default="deterministic")
    catalog_parser.add_argument("--generation", type=int, default=1)
    catalog_parser.add_argument("--os-record", type=Path)
    catalog_parser.set_defaults(function=catalog)
    verify_parser = commands.add_parser("verify")
    verify_parser.add_argument("--repository", type=Path, required=True)
    verify_parser.set_defaults(function=verify)
    args = parser.parse_args()
    args.function(args)


if __name__ == "__main__":
    main()
