# Host unit tests and the freestanding compile sweep.

# Every freestanding source compiles clean -- in every configuration, on every
# architecture the project ships.
#
# The userspace legs are aarch64, x86_64 and riscv64. The third was missing for
# reasons that compounded: `scripts/build-libc.sh` built two sysroots while the
# kernel legs covered three, so there was no `build/libc/riscv64/sysroot` for a
# userspace leg to point at, and `userspace/wt/` was therefore compiled for
# RISC-V by nothing at all (B-91). Both halves are addressed together, because
# a leg without a sysroot cannot exist and a sysroot nobody points a leg at is
# not coverage.
#
# Every freestanding source compiles clean -- in every configuration.
#
# The kernel legs run twice over the same aarch64 file set, once as the default
# configuration and once with `-DXAIOS_BOOT_TEST_APPS=1`, which is what the
# gated images are built with. They have to: the files default that macro with
# `#ifndef`, so compiling only the default arm leaves the arm that ships
# unchecked, and `remote_login.c` alone switches nine regions on it. A format
# string reachable only from the shipped configuration got past this target and
# past a local sweep of it before the second pass existed (B-95).
#
# That failure mode is the one this repository names elsewhere as worse than
# having no check: a check that compiles a configuration nobody boots, and
# reports the tree clean. The comment is here rather than inside the recipe
# because the recipe is one shell command joined by backslashes -- a `#` or a
# `@#` line inside it is not a comment to the shell, it is the next command.
# userspace/wt/xaios is the hosted WebTransport port: it is built against the
# vendored tree's headers and the hosted libc sysroot, not freestanding against
# the target include path, so the userspace sweep below excludes it. It is
# checked instead by `make wt-upstream-compile` (every architecture, the real
# flags), `make wt-host-test` and `make wt-interop-test`, all of which CI runs;
# leaving it in this sweep would only prove it cannot be built the way nothing
# builds it.
compile-check: libc
	@mkdir -p build/compile-check/x86-kernel build/compile-check/x86-userspace \
	  build/compile-check/riscv-userspace
	@failed=0; \
	for f in $$(find kernel -name '*.c' ! -path '*/x86_64/*' ! -path '*/riscv64/*'); do \
	  clang --target=aarch64-none-elf -std=c99 -ffreestanding \
	    -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
	    -Wall -Wextra -Werror -Ikernel/include -Iengine/include \
	    -Iengine/src -Iuserspace/include -Iuserspace/sshd -Ithird_party/bearssl/inc \
	    -fsyntax-only "$$f" \
	    || failed=$$((failed + 1)); \
	done; \
	for f in $$(find kernel -name '*.c' ! -path '*/x86_64/*' ! -path '*/riscv64/*'); do \
	  clang --target=aarch64-none-elf -std=c99 -ffreestanding \
	    -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
	    -Wall -Wextra -Werror -DXAIOS_BOOT_TEST_APPS=1 \
	    -DXAIOS_BUILD_NUMBER=$$(cat BUILD_NUMBER) \
	    -Ikernel/include -Iengine/include \
	    -Iengine/src -Iuserspace/include -Iuserspace/sshd -Ithird_party/bearssl/inc \
	    -fsyntax-only "$$f" \
	    || failed=$$((failed + 1)); \
	done; \
	for f in $$(find kernel/arch/riscv64 -name '*.c'); do \
	  clang --target=riscv64-unknown-elf -std=c99 -ffreestanding \
	    -fno-stack-protector -mno-relax -march=rv64gc -mabi=lp64d \
	    -mcmodel=medany \
	    -Wall -Wextra -Werror -pedantic -Ikernel/include -Iengine/include \
	    -fsyntax-only "$$f" \
	    || failed=$$((failed + 1)); \
	done; \
	for f in $$(find kernel/arch/x86_64 -name '*.c'); do \
	  clang --target=x86_64-none-elf -std=c99 -ffreestanding \
	    -fno-stack-protector -fno-builtin -fno-pic -fno-pie -mno-red-zone \
	    -Wall -Wextra -Werror -DXAIOS_X86_COMMON_RUNTIME=1 -Ikernel/include -Iengine/include \
	    -fsyntax-only "$$f" \
	    || failed=$$((failed + 1)); \
	done; \
	for f in $$(find kernel -name '*.c' ! -path '*/arch/aarch64/*' \
	    ! -path '*/arch/x86_64/*' ! -path '*/arch/riscv64/*'); do \
	  object=build/compile-check/x86-kernel/$$(printf '%s' "$$f" | tr / _).o; \
	  clang --target=x86_64-none-elf -std=c99 -ffreestanding \
	    -fno-stack-protector -fno-builtin -fno-pic -fno-pie -mno-red-zone \
	    -Wall -Wextra -Werror -DXAIOS_X86_COMMON_RUNTIME=1 \
	    -Ikernel/include -Iengine/include -Ithird_party/bearssl/inc \
	    -Iengine/src -Iuserspace/include -Iuserspace/sshd \
	    -c "$$f" -o "$$object" \
	    || failed=$$((failed + 1)); \
	done; \
	for f in $$(find userspace -name '*.c' ! -path 'userspace/libc/*' \
	    ! -path 'userspace/apps/hosted/*' \
	    ! -path 'userspace/wt/xaios/*'); do \
	  clang --target=aarch64-none-elf -std=c99 -ffreestanding \
	    -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
	    -Wall -Wextra -Werror -Iuserspace/include -Iuserspace/sshd \
	    -Iuserspace/wt/include \
	    -Iengine/include \
	    -Iuserspace/apps/terminal -Ithird_party/mlkem-native/mlkem \
	    -Ithird_party/openbsd-compat -Ithird_party/bearssl/inc \
	    -Ithird_party/bearssl/src -Itests \
	    -isystem build/libc/aarch64/sysroot/include \
	    -DMLK_CONFIG_FILE='"mlkem_xaios_config.h"' -fsyntax-only "$$f" \
	    || failed=$$((failed + 1)); \
	done; \
	for f in $$(find userspace -name '*.c' ! -path 'userspace/libc/*' \
	    ! -path 'userspace/apps/hosted/*' \
	    ! -path 'userspace/wt/xaios/*'); do \
	  object=build/compile-check/x86-userspace/$$(printf '%s' "$$f" | tr / _).o; \
	  clang --target=x86_64-none-elf -std=c99 -ffreestanding \
	    -fno-stack-protector -fno-builtin -fno-pic -fno-pie -mno-red-zone \
	    -Wall -Wextra -Werror -Iuserspace/include -Iuserspace/sshd \
	    -Iuserspace/wt/include \
	    -Iengine/include \
	    -Iuserspace/apps/terminal -Ithird_party/mlkem-native/mlkem \
	    -Ithird_party/openbsd-compat -Ithird_party/bearssl/inc \
	    -Ithird_party/bearssl/src -Itests \
	    -isystem build/libc/x86_64/sysroot/include \
	    -DMLK_CONFIG_FILE='"mlkem_xaios_config.h"' \
	    -c "$$f" -o "$$object" \
	    || failed=$$((failed + 1)); \
	done; \
	for f in $$(find userspace -name '*.c' ! -path 'userspace/libc/*' \
	    ! -path 'userspace/apps/hosted/*' \
	    ! -path 'userspace/wt/xaios/*'); do \
	  object=build/compile-check/riscv-userspace/$$(printf '%s' "$$f" | tr / _).o; \
	  clang --target=riscv64-unknown-elf -std=c99 -ffreestanding \
	    -fno-stack-protector -fno-builtin -fno-pic -fno-pie \
	    -march=rv64gc -mabi=lp64d -mcmodel=medany \
	    -Wall -Wextra -Werror -Iuserspace/include -Iuserspace/sshd \
	    -Iuserspace/wt/include \
	    -Iengine/include \
	    -Iuserspace/apps/terminal -Ithird_party/mlkem-native/mlkem \
	    -Ithird_party/openbsd-compat -Ithird_party/bearssl/inc \
	    -Ithird_party/bearssl/src -Itests \
	    -isystem build/libc/riscv64/sysroot/include \
	    -DMLK_CONFIG_FILE='"mlkem_xaios_config.h"' \
	    -c "$$f" -o "$$object" \
	    || failed=$$((failed + 1)); \
	done; \
	if [ "$$failed" -ne 0 ]; then \
	  printf '%s\n' "$$failed file(s) failed compilation" >&2; \
	  exit 1; \
	fi; \
	printf '%s\n' "All freestanding C files compiled clean; hosted libc uses make libc-check"

hosted-test: engine-cli
	@mkdir -p build/hosted
	./build/hosted/xaios-engine probe
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include tests/system/test_cpuset.c \
	  -o build/hosted/test-cpuset
	./build/hosted/test-cpuset
	$(HOST_CC) $(HOST_CFLAGS) -Ikernel/include \
	  kernel/arch/x86_64/acpi.c tests/system/test_x86_acpi.c \
	  -o build/hosted/test-x86-acpi
	./build/hosted/test-x86-acpi
	$(HOST_CC) $(HOST_CFLAGS) -Ikernel/include \
	  kernel/arch/aarch64/acpi.c tests/system/test_aarch64_acpi.c \
	  -o build/hosted/test-aarch64-acpi
	./build/hosted/test-aarch64-acpi
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Iengine/include engine/src/model_v2.c engine/src/sha256.c \
	  engine/src/architecture.c engine/src/service.c engine/src/backend_scalar.c \
	  engine/src/backend_neon.c engine/src/backend_avx2.c engine/src/packed.c \
	  tests/model_v2/test_engine.c -o build/hosted/test-engine
	./build/hosted/test-engine
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Iengine/include -Iengine/src engine/src/cluster.c engine/src/sha256.c \
	  tests/model_v2/test_cluster.c -o build/hosted/test-cluster
	./build/hosted/test-cluster
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Iengine/include engine/src/kimi_k3_mini.c \
	  tests/model_v2/test_kimi_k3_mini.c -lm -o build/hosted/test-kimi-k3-mini
	./build/hosted/test-kimi-k3-mini
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Iengine/include engine/src/backend_scalar.c engine/src/backend_neon.c \
	  engine/src/backend_avx2.c engine/src/packed.c \
	  tests/model_v2/test_packed.c \
	  -o build/hosted/test-packed
	./build/hosted/test-packed
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Iuserspace/include userspace/lib/xaios_control_client.c \
	  userspace/lib/control_render_primitives.c \
	  userspace/lib/control_render_system.c \
	  userspace/lib/control_render_storage.c \
	  userspace/lib/control_render_ops.c \
	  userspace/lib/control_render_config.c \
	  userspace/lib/control_request.c userspace/lib/control_parse_flags.c userspace/lib/control_parse_validate.c userspace/lib/control_dispatch.c \
	  tests/control/test_control_client_support.c \
	  tests/control/test_control_client_server.c \
	  tests/control/test_control_client.c -o build/hosted/test-control-client
	./build/hosted/test-control-client
	$(HOST_CC) $(HOST_CFLAGS) \
	  userspace/sshd/ssh_known_hosts.c \
	  tests/system/test_known_hosts.c -o build/hosted/test-known-hosts
	./build/hosted/test-known-hosts
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Iuserspace/include -Ikernel/include userspace/lib/xaios_screen.c \
	  tests/system/test_screen.c -o build/hosted/test-screen
	./build/hosted/test-screen
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/dev/block_device.c \
	  tests/storage/test_block_device.c -o build/hosted/test-block-device
	./build/hosted/test-block-device
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/dev/block_device.c kernel/lib/crc32.c \
	  kernel/storage/gpt.c kernel/storage/gpt_write.c kernel/storage/partition_device.c \
	  tests/storage/test_gpt.c -o build/hosted/test-gpt
	./build/hosted/test-gpt
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/dev/block_device.c kernel/lib/crc32.c \
	  kernel/storage/gpt.c kernel/storage/gpt_write.c kernel/storage/partition_device.c \
	  kernel/storage/storage_admin.c kernel/storage/storage_admin_table.c kernel/storage/storage_admin_self_test.c kernel/fs/fat.c kernel/fs/fat_dir.c kernel/fs/fat_file_io.c kernel/fs/fat_codec.c \
	  tests/storage/test_storage_admin.c \
	  -o build/hosted/test-storage-admin
	./build/hosted/test-storage-admin
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/dev/block_device.c kernel/fs/fat.c kernel/fs/fat_dir.c kernel/fs/fat_file_io.c kernel/fs/fat_codec.c \
	  tests/storage/test_fat.c -o build/hosted/test-fat
	./build/hosted/test-fat build/hosted/fat-long-names.img
	@# The reciprocal check: an implementation that is not this one, reading
	@# what this one wrote. mtools has long-name support and firmware does
	@# too, so a volume whose long names only this code can see would be a
	@# volume no machine can boot from.
	@for name in BOOTRISCV64.EFI TOOLONGNAME.EFI NAME.TOOLONG TWO.DOTS.X; do \
	  mdir -i build/hosted/fat-long-names.img -/ ::/EFI/BOOT \
	    | grep -q "$$name" \
	    || { echo "fat: mtools cannot see $$name on the volume XAIOS wrote"; \
	         exit 1; }; \
	done
	@echo "fat: mtools reads every long name XAIOS wrote"
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include -Iengine/include -Iengine/src -Iuserspace/include \
	  -Iuserspace/sshd kernel/dev/block_device.c kernel/lib/crc32.c \
	  kernel/storage/gpt.c kernel/storage/gpt_write.c kernel/storage/partition_device.c \
	  kernel/storage/storage_admin.c kernel/storage/storage_admin_table.c kernel/storage/storage_admin_self_test.c kernel/fs/fat.c kernel/fs/fat_dir.c kernel/fs/fat_file_io.c kernel/fs/fat_codec.c \
	  kernel/fs/xai_fs_admin.c kernel/fs/xai_fs_admin_support.c \
	  engine/src/xai_fs.c engine/src/xai_fs_codec.c engine/src/xai_fs_read.c engine/src/xai_fs_writer.c engine/src/xai_fs_writer_staging.c engine/src/xai_fs_writer_rewrite.c engine/src/xai_fs_writer_util.c \
	  engine/src/sha256.c userspace/sshd/ssh_crypto.c userspace/sshd/ssh_crypto_symmetric.c userspace/sshd/ssh_crypto_curve25519.c \
	  userspace/sshd/tweetnacl_subset.c \
	  tests/storage/test_xai_fs_admin.c \
	  -o build/hosted/test-xaifs-admin
	./build/hosted/test-xaifs-admin
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/fs/vfs.c kernel/fs/vfs_namespace.c kernel/fs/vfs_handle.c tests/storage/test_vfs.c \
	  -o build/hosted/test-vfs
	./build/hosted/test-vfs
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/fs/xaiboot_fs.c kernel/fs/xbfs_state.c kernel/fs/xbfs_node_codec.c kernel/fs/xbfs_util.c kernel/fs/xbfs_record.c kernel/fs/xbfs_metadata.c kernel/fs/xbfs_dir.c kernel/fs/xbfs_alloc.c kernel/fs/xbfs_file_io.c kernel/fs/xbfs_fd.c kernel/fs/xbfs_mount.c kernel/fs/xbfs_snapshot.c kernel/fs/xbfs_format.c kernel/fs/xbfs_selfcheck.c kernel/dev/block_device.c \
	  tests/storage/test_xaiboot_fs_mirror.c \
	  -o build/hosted/test-mutable-fs-mirror
	./build/hosted/test-mutable-fs-mirror
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/fs/xaiboot_fs.c kernel/fs/xbfs_state.c kernel/fs/xbfs_node_codec.c kernel/fs/xbfs_util.c kernel/fs/xbfs_record.c kernel/fs/xbfs_metadata.c kernel/fs/xbfs_dir.c kernel/fs/xbfs_alloc.c kernel/fs/xbfs_file_io.c kernel/fs/xbfs_fd.c kernel/fs/xbfs_mount.c kernel/fs/xbfs_snapshot.c kernel/fs/xbfs_format.c kernel/fs/xbfs_selfcheck.c kernel/dev/block_device.c \
	  tests/storage/test_xaiboot_fs_v6.c \
	  -o build/hosted/test-xaiboot-fs-v6
	./build/hosted/test-xaiboot-fs-v6
	@# B-48: the metadata commit's cost, counted at the block device, so the
	@# figure is what the disk saw rather than a claim about what it should be.
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/fs/xaiboot_fs.c kernel/fs/xbfs_state.c kernel/fs/xbfs_node_codec.c kernel/fs/xbfs_util.c kernel/fs/xbfs_record.c kernel/fs/xbfs_metadata.c kernel/fs/xbfs_dir.c kernel/fs/xbfs_alloc.c kernel/fs/xbfs_file_io.c kernel/fs/xbfs_fd.c kernel/fs/xbfs_mount.c kernel/fs/xbfs_snapshot.c kernel/fs/xbfs_format.c kernel/fs/xbfs_selfcheck.c kernel/dev/block_device.c \
	  tests/storage/test_xaiboot_fs_write_cost.c \
	  -o build/hosted/test-xaiboot-fs-write-cost
	./build/hosted/test-xaiboot-fs-write-cost
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/fs/xaiboot_fs.c kernel/fs/xbfs_state.c kernel/fs/xbfs_node_codec.c kernel/fs/xbfs_util.c kernel/fs/xbfs_record.c kernel/fs/xbfs_metadata.c kernel/fs/xbfs_dir.c kernel/fs/xbfs_alloc.c kernel/fs/xbfs_file_io.c kernel/fs/xbfs_fd.c kernel/fs/xbfs_mount.c kernel/fs/xbfs_snapshot.c kernel/fs/xbfs_format.c kernel/fs/xbfs_selfcheck.c kernel/dev/block_device.c \
	  tests/storage/test_xaiboot_fs_fragmentation.c \
	  -o build/hosted/test-xaiboot-fs-fragmentation
	./build/hosted/test-xaiboot-fs-fragmentation
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/fs/xaiboot_fs.c kernel/fs/xbfs_state.c kernel/fs/xbfs_node_codec.c kernel/fs/xbfs_util.c kernel/fs/xbfs_record.c kernel/fs/xbfs_metadata.c kernel/fs/xbfs_dir.c kernel/fs/xbfs_alloc.c kernel/fs/xbfs_file_io.c kernel/fs/xbfs_fd.c kernel/fs/xbfs_mount.c kernel/fs/xbfs_snapshot.c kernel/fs/xbfs_format.c kernel/fs/xbfs_selfcheck.c kernel/dev/block_device.c \
	  tests/storage/test_xaiboot_fs_extent_depth.c \
	  -o build/hosted/test-xaiboot-fs-extent-depth
	./build/hosted/test-xaiboot-fs-extent-depth
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/fs/xaiboot_fs.c kernel/fs/xbfs_state.c kernel/fs/xbfs_node_codec.c kernel/fs/xbfs_util.c kernel/fs/xbfs_record.c kernel/fs/xbfs_metadata.c kernel/fs/xbfs_dir.c kernel/fs/xbfs_alloc.c kernel/fs/xbfs_file_io.c kernel/fs/xbfs_fd.c kernel/fs/xbfs_mount.c kernel/fs/xbfs_snapshot.c kernel/fs/xbfs_format.c kernel/fs/xbfs_selfcheck.c kernel/dev/block_device.c \
	  tests/storage/test_xaiboot_fs_large_volume.c \
	  -o build/hosted/test-xaiboot-fs-large-volume
	./build/hosted/test-xaiboot-fs-large-volume
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Iuserspace/include -Iuserspace/sshd -Iuserspace/apps/terminal \
	  -Ikernel/include \
	  userspace/sshd/sftp_server.c userspace/sshd/sftp_server_file.c userspace/sshd/sftp_server_dir.c tests/storage/test_sftp_large.c \
	  -o build/hosted/test-sftp-large
	./build/hosted/test-sftp-large
	python3 tests/scripts/generate-dnssec-fixture.py build/hosted/dnssec_fixture.h
	$(HOST_CC) $(HOST_CFLAGS) -D_DEFAULT_SOURCE \
	  -Ikernel/include -Iuserspace/include -Iuserspace/sshd -Ithird_party/bearssl/inc \
	  -Ithird_party/bearssl/src -Ibuild/hosted \
	  kernel/net/dns.c kernel/net/dns_resolver.c kernel/net/dns_selftest.c kernel/net/dnssec.c kernel/net/ipv4.c \
	  userspace/sshd/ssh_crypto.c userspace/sshd/ssh_crypto_symmetric.c userspace/sshd/ssh_crypto_curve25519.c userspace/sshd/tweetnacl_subset.c \
	  $$(find third_party/bearssl/src -name '*.c' | LC_ALL=C sort) \
	  tests/crashtest/test_dns.c -o build/hosted/test-dns
	./build/hosted/test-dns
	$(HOST_CC) $(HOST_CFLAGS) \
	  -DMLK_CONFIG_FILE='"mlkem_xaios_config.h"' \
	  -Iuserspace/sshd -Ithird_party/mlkem-native/mlkem \
	  third_party/mlkem-native/mlkem/mlkem_native.c \
	  tests/security/test_mlkem.c -o build/hosted/test-mlkem
	./build/hosted/test-mlkem
	rm -f build/hosted/id-ed25519 build/hosted/id-ed25519.pub \
	  build/hosted/id-ed25519-encrypted build/hosted/id-ed25519-encrypted.pub
	ssh-keygen -q -t ed25519 -N '' -f build/hosted/id-ed25519
	ssh-keygen -q -t ed25519 -N xaios-test-passphrase \
	  -f build/hosted/id-ed25519-encrypted
	$(HOST_CC) $(HOST_CFLAGS) -DXAIOS_IDENTITY_HOSTED=1 -Wno-unknown-attributes \
	  -Iuserspace/include -Iuserspace/sshd -Ithird_party/openbsd-compat \
	  userspace/sshd/ssh_identity.c userspace/sshd/ssh_crypto.c userspace/sshd/ssh_crypto_symmetric.c userspace/sshd/ssh_crypto_curve25519.c \
	  userspace/sshd/tweetnacl_subset.c \
	  third_party/openbsd-compat/blowfish.c \
	  third_party/openbsd-compat/bcrypt_pbkdf.c \
	  tests/security/test_ssh_identity.c -o build/hosted/test-ssh-identity
	./build/hosted/test-ssh-identity build/hosted/id-ed25519 \
	  build/hosted/id-ed25519-encrypted
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Ikernel/include kernel/net/ipv4.c kernel/net/ipv6.c kernel/net/ipv6_ext.c \
	  tests/network/test_ip_fragments.c -o build/hosted/test-ip-fragments
	./build/hosted/test-ip-fragments
	$(HOST_CC) $(HOST_CFLAGS) -Ikernel/include \
	  kernel/lib/inflate.c tests/system/test_inflate.c -lz \
	  -o build/hosted/test-inflate
	./build/hosted/test-inflate
	$(HOST_CC) $(HOST_CFLAGS) -Iuserspace/include -Iuserspace/sshd \
	  -Iuserspace/apps/terminal \
	  userspace/apps/terminal/pong_game.c tests/system/test_pong_game.c \
	  -o build/hosted/test-pong-game
	./build/hosted/test-pong-game
	PYTHONPATH=. python3 -m unittest discover -s tests/system -p 'test_*.py'
	PYTHONPATH=tools python3 -m unittest discover -s tests/model_v2 -p 'test_*.py'
	PYTHONPATH=tools python3 -m unittest discover -s tests/xai_fs -p 'test_*.py'
	PYTHONPATH=tools python3 tests/xai_fs/create_c_fixture.py \
	  build/hosted/xaifs-c-fixture.img
	PYTHONPATH=tools python3 tests/xai_fs/create_c_sparse_fixture.py \
	  build/hosted/xaifs-c-sparse.img
	$(HOST_CC) $(HOST_CFLAGS) \
	  -Iengine/include -Iengine/src -Iuserspace/include -Iuserspace/sshd \
	  -Iuserspace/apps/terminal \
	  -Ikernel/include engine/src/xai_fs.c engine/src/xai_fs_codec.c engine/src/xai_fs_read.c \
	  engine/src/xai_fs_writer.c engine/src/xai_fs_writer_staging.c engine/src/xai_fs_writer_rewrite.c engine/src/xai_fs_writer_util.c engine/src/model_file.c \
	  engine/src/sha256.c \
	  userspace/sshd/ssh_crypto.c userspace/sshd/ssh_crypto_symmetric.c userspace/sshd/ssh_crypto_curve25519.c userspace/sshd/tweetnacl_subset.c \
	  tests/xai_fs/test_xai_fs_reader.c \
  tests/xai_fs/test_xai_fs_reader_format.c \
  tests/xai_fs/test_xai_fs_reader_staging.c \
	  -o build/hosted/test-xaifs-reader
	./build/hosted/test-xaifs-reader \
	  build/hosted/xaifs-c-fixture.img \
	  build/hosted/xaifs-c-sparse.img
	$(HOST_CC) $(HOST_CFLAGS) -Iengine/src \
	  tests/engine/test_sha256_accel.c \
	  engine/src/sha256.c engine/src/sha256_accel.c \
	  -o build/hosted/test-sha256-accel
	./build/hosted/test-sha256-accel

hosted-sanitizer-test:
	ASAN_OPTIONS=detect_leaks=1:halt_on_error=1 \
	UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1 \
	$(MAKE) hosted-test \
	  HOST_CFLAGS='-std=c99 -Wall -Wextra -Werror -pedantic -O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined'
