#!/usr/bin/env python3
from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TOOL = ROOT / "tools" / "xaios_xapt_repo.py"


class XaptRepositoryTests(unittest.TestCase):
    def run_tool(self, *arguments: str, ok: bool = True) -> subprocess.CompletedProcess[str]:
        result = subprocess.run(
            ["python3", str(TOOL), *arguments],
            cwd=ROOT,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            check=False,
        )
        self.assertEqual(result.returncode == 0, ok, result.stdout)
        return result

    def test_package_catalog_and_corruption_detection(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xaios-xapt-test.") as temporary:
            root = Path(temporary)
            elf = root / "calculator.elf"
            elf.write_bytes(b"\x7fELF" + bytes(range(64)))
            common = (
                "package",
                "--repository", str(root / "repo"),
                "--elf", str(elf),
                "--name", "calculator",
                "--version", "1.2.3",
                "--arch", "aarch64",
                "--capabilities", "1073741826",
                "--description", "Integer calculator",
            )
            self.run_tool(*common)
            self.run_tool(
                "catalog", "--repository", str(root / "repo"),
                "--arch", "aarch64", "--generation", "7",
                "--generated", "fixture",
            )
            verified = self.run_tool("verify", "--repository", str(root / "repo"))
            self.assertIn("packages=1", verified.stdout)

            payload = root / "repo/apps/aarch64/calculator/1.2.3/calculator.elf"
            payload.write_bytes(payload.read_bytes() + b"corrupt")
            failed = self.run_tool(
                "verify", "--repository", str(root / "repo"), ok=False
            )
            self.assertIn("package payload mismatch", failed.stdout)

    def test_rejects_invalid_name_and_oversized_payload(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xaios-xapt-test.") as temporary:
            root = Path(temporary)
            elf = root / "app.elf"
            elf.write_bytes(b"\x7fELF" + b"x" * 131069)
            result = self.run_tool(
                "package", "--repository", str(root / "repo"),
                "--elf", str(elf), "--name", "../bad", "--version", "1.0.0",
                "--arch", "aarch64", "--capabilities", "2",
                "--description", "bad", ok=False,
            )
            self.assertIn("invalid application name", result.stdout)
            result = self.run_tool(
                "package", "--repository", str(root / "repo"),
                "--elf", str(elf), "--name", "large", "--version", "1.0.0",
                "--arch", "aarch64", "--capabilities", "2",
                "--description", "large", ok=False,
            )
            self.assertIn("no larger than 128 KiB", result.stdout)

    def test_rejects_invalid_catalog_generation(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xaios-xapt-test.") as temporary:
            root = Path(temporary)
            result = self.run_tool(
                "catalog", "--repository", str(root / "repo"),
                "--arch", "aarch64", "--generation", "0", ok=False,
            )
            self.assertIn("catalog generation must be", result.stdout)

    def test_system_record_catalog_and_corruption_detection(self) -> None:
        with tempfile.TemporaryDirectory(prefix="xaios-xapt-test.") as temporary:
            root = Path(temporary)
            image = root / "kernel.elf"
            image.write_bytes(b"\x7fELFsystem-fixture")
            repository = root / "repo"
            self.run_tool(
                "system", "--repository", str(repository), "--image", str(image),
                "--version", "0.2.0", "--generation", "100",
                "--arch", "x86_64",
            )
            record = repository / "os/x86_64/0.2.0/record.json"
            self.run_tool(
                "catalog", "--repository", str(repository), "--arch", "x86_64",
                "--generation", "8", "--os-record", str(record),
            )
            verified = self.run_tool("verify", "--repository", str(repository))
            self.assertIn("systems=1", verified.stdout)
            payload = repository / "os/x86_64/0.2.0/kernel.elf"
            payload.write_bytes(payload.read_bytes() + b"corrupt")
            failed = self.run_tool("verify", "--repository", str(repository), ok=False)
            self.assertIn("system payload mismatch", failed.stdout)


if __name__ == "__main__":
    unittest.main()
