# Application development

This is the contract for adding a userspace program to XAIOS: what it may
call, how it is built into an image, how it is allowed to run, and what it is
permitted to do once it does. [Getting
Started](https://github.com/Pummelchen/XAIOS/wiki/Getting-Started) covers
installing a toolchain and building an image; this page starts after that.

Two things make this a contract rather than a tutorial. An application is
launched with a capability mask and the kernel rejects every syscall the mask
does not name, so the mask is part of the program's definition. And a normal
image runs nothing on its own — a program that is built into the image but has
no declared execution path is present and unreachable.

## The freestanding path

The default userspace SDK is `userspace/include/xaios_user.h`. It is
freestanding C99: no `malloc`, no POSIX headers, no standard library. Use
stack buffers or fixed-size arrays, return from `main`, and let the runtime
call `xaios_exit()`.

Create `userspace/apps/myapp.c`:

```c
#include <xaios_user.h>

int main(void) {
    xaios_log("myapp: starting\n");

    u64 now = xaios_clock_nanos();
    xaios_log_u64("myapp: clock_nanos = ", now, "\n");

    xaios_fs_mkdir("/state/myapp");
    xaios_write_file("/state/myapp/data.txt", "hello from myapp");

    char buf[256];
    int n = xaios_read_file("/state/myapp/data.txt", buf, sizeof(buf) - 1);
    if (n > 0) {
        buf[n] = '\0';
        xaios_log("myapp: read back: ");
        xaios_log(buf);
        xaios_log("\n");
    }

    xaios_log("myapp: done\n");
    return 0;
}
```

An application is a single process. `xaios_thread_group_run()` gives it
parallelism within its own CPU; `xaios_smp_run()` dispatches to secondary
cores. Neither is a general thread API — see [API](./API.md) for what each
one accepts.

## Building it into an image

Add the name to the `USER_APPS` list in `scripts/build-image.sh`. There are
three such lists and they mean different things: `USER_APPS` is a dedicated
application binary, `UTILITY_APPS` is one of the small file and text tools that
share `userspace/apps/xutils.c`, and `HOSTED_USER_APPS` is built against the
hosted C99 sysroot instead of the freestanding SDK.
`tests/repository/check-user-docs.py` reads all three and requires every entry
to appear in `wiki/Applications.md`, so a new application is documented in the
same change that builds it or `make docs-check` fails.

## Giving it an execution path

A normal image starts `/init`, the service manager and `sshd`, and nothing
else. To make an application reachable, add it to `g_remote_apps` in
`kernel/runtime/remote_login.c`. Each entry names the exact command an
authenticated session may type, the initramfs path to load, and the capability
mask the process is launched with, followed by three flags: whether the command
receives its raw argument string, whether the session's working directory is
passed to it, and whether its completion is reported back to the session.

Matching is by exact name — there is no search path — and the kernel reclaims
the process's pages and process-table slot after it exits.

Give the least privilege that works. `XAIOS_CAP_LOG | XAIOS_CAP_EXIT` is
enough for a program that only prints; a program that reads files needs
`XAIOS_CAP_FS_READ` as well, and so on. The complete list of bits is in
`kernel/include/xaios/syscall.h` and is documented with the syscalls each one
authorizes in [API](./API.md). A mask assembled by copying an existing entry
usually grants more than the new program needs.

For a deterministic boot fixture instead of an on-demand command, add a
`run_user_app` call inside the `XAIOS_BOOT_TEST_APPS` block in
`kernel/core/kmain.c`, with a PID that no other fixture application in that
block already uses:

```c
run_user_app("/bin/myapp", 25, app_caps);
```

That block exists so QEMU gates have stable markers, and it runs only in the
fixture profile that `make image-qemu-test` builds. It is not how an
application reaches a normal image.

## Proving it runs

If the application emits a line the smoke gate should require, add that exact
line to `TARGETS` in `tests/scripts/qemu-smoke.py`:

```python
"myapp: done",
```

Then:

```sh
make image-qemu-test
make qemu-smoke
```

A marker in `TARGETS` is a requirement: the gate fails if the line is absent.
That is the point, and it is also the trap — a marker that a passing boot
prints for some other reason is not evidence about this application. Make the
string specific enough that only this program can produce it.

## The hosted C99 path

An application may instead be built against the static XAIOS C99 libc. This is
an explicit build choice, not a default, and it does not change the kernel ABI
or introduce POSIX: the sysroot exposes ISO C99 and nothing more.

```sh
make libc
scripts/build-c99-app.sh --arch aarch64 --main args app.c build/app.elf
scripts/build-c99-app.sh --arch x86_64  --main void app.c build/app-x86.elf
scripts/build-c99-app.sh --arch riscv64 --main args app.c build/app-rv.elf
make qemu-libc-gate
```

`--main` selects which form of `main` the source defines. Registering the
resulting ELF in an image and assigning its capability mask are the same two
steps as above; being hosted grants a program nothing.

See [C99 Libc](https://github.com/Pummelchen/XAIOS/wiki/C99-Libc) for what the
sysroot implements.
