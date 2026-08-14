#!/usr/bin/env python3
"""Generate a bounded signed DNSSEC test chain for the hosted C verifier."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa, utils


def wire_name(name: str) -> bytes:
    if not name:
        return b"\0"
    return b"".join(bytes((len(label),)) + label.lower().encode("ascii")
                    for label in name.split(".")) + b"\0"


def key_tag(rdata: bytes) -> int:
    total = sum(value if index & 1 else value << 8
                for index, value in enumerate(rdata))
    total += (total >> 16) & 0xFFFF
    return total & 0xFFFF


def rsa_dnskey(private_key: rsa.RSAPrivateKey) -> bytes:
    public = private_key.public_key().public_numbers()
    exponent = public.e.to_bytes((public.e.bit_length() + 7) // 8, "big")
    exponent_wire = (bytes((len(exponent),)) + exponent if len(exponent) < 256
                     else b"\0" + len(exponent).to_bytes(2, "big") + exponent)
    modulus = public.n.to_bytes((public.n.bit_length() + 7) // 8, "big")
    return b"\x01\x01\x03\x08" + exponent_wire + modulus


def sign_rrsig(private_key: object, algorithm: int, signed: bytes) -> bytes:
    if algorithm == 8:
        return private_key.sign(signed, padding.PKCS1v15(), hashes.SHA256())
    if algorithm == 13:
        encoded = private_key.sign(signed, ec.ECDSA(hashes.SHA256()))
        r, s = utils.decode_dss_signature(encoded)
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    if algorithm == 14:
        encoded = private_key.sign(signed, ec.ECDSA(hashes.SHA384()))
        r, s = utils.decode_dss_signature(encoded)
        return r.to_bytes(48, "big") + s.to_bytes(48, "big")
    if algorithm == 15:
        return private_key.sign(signed)
    raise ValueError(f"unsupported test algorithm: {algorithm}")


def rrsig(owner: str, record_type: int, ttl: int, rdata: bytes,
          signer: str, private_key: object, algorithm: int,
          signer_key: bytes) -> bytes:
    fixed = (record_type.to_bytes(2, "big") + bytes((algorithm,)) +
             bytes((0 if not owner else len(owner.split(".")),)) +
             ttl.to_bytes(4, "big") + (2524608000).to_bytes(4, "big") +
             (1577836800).to_bytes(4, "big") +
             key_tag(signer_key).to_bytes(2, "big"))
    signed = (fixed + wire_name(signer) + wire_name(owner) +
              record_type.to_bytes(2, "big") + b"\0\x01" +
              ttl.to_bytes(4, "big") + len(rdata).to_bytes(2, "big") + rdata)
    return fixed + wire_name(signer) + sign_rrsig(private_key, algorithm, signed)


def ecdsa_dnskey(private_key: ec.EllipticCurvePrivateKey, algorithm: int) -> bytes:
    size = 32 if algorithm == 13 else 48
    public = private_key.public_key().public_numbers()
    return (b"\x01\x01\x03" + bytes((algorithm,)) +
            public.x.to_bytes(size, "big") + public.y.to_bytes(size, "big"))


def ed25519_dnskey(private_key: ed25519.Ed25519PrivateKey) -> bytes:
    public = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return b"\x01\x01\x03\x0f" + public


def signed_address_fixture(private_key: object, algorithm: int, key: bytes) -> tuple[bytes, bytes]:
    address = b"\x05\x06\x07\x08"
    message_bytes = message("test", 1, [
        ("test", 1, 60, address),
        ("test", 46, 60, rrsig("test", 1, 60, address, "test", private_key,
                               algorithm, key)),
    ])
    return key, message_bytes


def message(question_name: str, question_type: int,
            records: list[tuple[str, int, int, bytes]]) -> bytes:
    question = wire_name(question_name) + question_type.to_bytes(2, "big") + b"\0\x01"
    result = b"\0\0\x81\x80\0\x01" + len(records).to_bytes(2, "big") + b"\0\0\0\0" + question
    for owner, record_type, ttl, rdata in records:
        result += (wire_name(owner) + record_type.to_bytes(2, "big") + b"\0\x01" +
                   ttl.to_bytes(4, "big") + len(rdata).to_bytes(2, "big") + rdata)
    return result


def c_array(name: str, value: bytes) -> str:
    rows = [", ".join(f"0x{item:02x}U" for item in value[index:index + 12])
            for index in range(0, len(value), 12)]
    return f"static const uint8_t {name}[] = {{\n" + "\n".join(f"  {row}," for row in rows) + "\n};\n"


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    args = parser.parse_args()

    root = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    child = rsa.generate_private_key(public_exponent=65537, key_size=1024)
    root_key, child_key = rsa_dnskey(root), rsa_dnskey(child)
    child_ds = (key_tag(child_key).to_bytes(2, "big") + b"\x08\x02" +
                hashlib.sha256(wire_name("test") + child_key).digest())
    root_message = message("", 48, [
        ("", 48, 3600, root_key),
        ("", 46, 3600, rrsig("", 48, 3600, root_key, "", root, 8, root_key)),
    ])
    ds_message = message("test", 43, [
        ("test", 43, 3600, child_ds),
        ("test", 46, 3600, rrsig("test", 43, 3600, child_ds, "", root, 8, root_key)),
    ])
    child_message = message("test", 48, [
        ("test", 48, 3600, child_key),
        ("test", 46, 3600, rrsig("test", 48, 3600, child_key, "test", child, 8, child_key)),
    ])
    address = b"\x01\x02\x03\x04"
    address_message = message("test", 1, [
        ("test", 1, 60, address),
        ("test", 46, 60, rrsig("test", 1, 60, address, "test", child, 8, child_key)),
    ])
    nsec = wire_name("zz.test") + bytes((0, 1, 0x40))
    nsec_message = message("missing.test", 28, [
        ("missing.test", 47, 60, nsec),
        ("missing.test", 46, 60, rrsig("missing.test", 47, 60, nsec, "test", child, 8, child_key)),
    ])
    p256 = ec.generate_private_key(ec.SECP256R1())
    p256_key, p256_message = signed_address_fixture(p256, 13,
                                                     ecdsa_dnskey(p256, 13))
    p384 = ec.generate_private_key(ec.SECP384R1())
    p384_key, p384_message = signed_address_fixture(p384, 14,
                                                     ecdsa_dnskey(p384, 14))
    ed = ed25519.Ed25519PrivateKey.generate()
    ed_key, ed_message = signed_address_fixture(ed, 15, ed25519_dnskey(ed))
    source = "#ifndef XAIOS_DNSSEC_FIXTURE_H\n#define XAIOS_DNSSEC_FIXTURE_H\n"
    for name, value in (("k_root_dnskey_message", root_message),
                        ("k_test_ds_message", ds_message),
                        ("k_test_dnskey_message", child_message),
                        ("k_test_a_message", address_message),
                        ("k_test_nsec_message", nsec_message),
                        ("k_p256_key", p256_key),
                        ("k_p256_message", p256_message),
                        ("k_p384_key", p384_key),
                        ("k_p384_message", p384_message),
                        ("k_ed25519_key", ed_key),
                        ("k_ed25519_message", ed_message),
                        ("k_test_anchor_digest", hashlib.sha256(wire_name("") + root_key).digest())):
        source += c_array(name, value)
    source += f"#define DNSSEC_TEST_ROOT_TAG {key_tag(root_key)}U\n#endif\n"
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(source, encoding="ascii")


if __name__ == "__main__":
    main()
