# Repository-level checks and the cleanup targets.

crash-test: hosted-sanitizer-test
	python3 -m compileall -q scripts tools tests

model-v2-test: hosted-test

# XAIOS behaves the same everywhere it boots; firmware supplies capabilities,
# never identity. See docs/PLATFORM-NEUTRALITY.md.
platform-neutrality-check:
	python3 tests/repository/check-platform-neutrality.py

# Prose cannot be enforced by shape, so this checks the claims that expire:
# evidence commits that have fallen behind, and review dates that predate the
# page's own last edit.
doc-freshness-check:
	python3 tests/repository/check-doc-freshness.py

# risk R-012 names a post-push byte comparison against the published Wiki as a
# mitigation. This is that comparison, and it is deliberately not in docs-check:
# that target runs inside qemu-core-os-rc under a 120-second budget and has to
# work with no network, and CI runs it after publish-wiki has pushed.
wiki-parity-check:
	python3 tests/repository/check-wiki-parity.py

docs-check:
	python3 tests/repository/check-platform-neutrality.py
	python3 tests/repository/check-doc-freshness.py
	python3 tests/repository/check-test-layout.py
	python3 tests/repository/check-firmware-platform-profiles.py
	python3 tests/repository/check-code-scanning-contract.py
	python3 tests/repository/check-wiki-layout.py
	python3 tests/repository/check-user-docs.py
	python3 tests/repository/check-model-support.py
	python3 tests/repository/check-platform-support.py
	python3 tests/repository/check-core-os-status.py
	python3 tests/repository/check-ssh-wire-bound.py
	python3 tests/repository/check-fault-test-marker.py
	python3 tests/repository/check-portable-dd.py
	python3 tests/repository/check-syscall-abi.py
	python3 tests/repository/check-riscv-firmware-paths.py
	python3 tests/repository/check-aggregate-budgets.py
	python3 tests/repository/check-xai-fs-chunk-bounds.py
	python3 tests/repository/check-panic-registers.py
	python3 tests/repository/check-webtransport-vendor.py
	python3 tests/repository/check-file-size-budget.py

code-scanning-contract:
	python3 tests/repository/check-code-scanning-contract.py

production-source-audit:
	python3 tests/repository/check-production-source.py

qemu-baseline: image
	python3 ./tests/scripts/benchmark-baseline.py

clean:
	rm -rf build out dist

clean-persistent:
	rm -f build/xaios-persistent.img
