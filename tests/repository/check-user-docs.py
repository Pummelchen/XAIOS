#!/usr/bin/env python3
"""Keep the Wiki application and built-in command catalogs source-complete."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INTERACTIVE_APPLICATIONS = {"xtop", "nano", "pong"}
ADMIN_APPLICATIONS = {"xaiosctl", "xapt"}


def main() -> int:
    failures: list[str] = []
    build = (ROOT / "scripts/build-image.sh").read_text(encoding="utf-8")
    apps_doc = (ROOT / "wiki/Applications.md").read_text(encoding="utf-8")
    commands_doc = (ROOT / "wiki/Commands.md").read_text(encoding="utf-8")
    user_apps: set[str] = set()
    utility_apps: set[str] = set()
    for variable in ("USER_APPS", "UTILITY_APPS", "HOSTED_USER_APPS"):
        match = re.search(rf'^{variable}="([^"]+)"', build, re.MULTILINE)
        if match is None:
            failures.append(f"cannot locate {variable} in build-image.sh")
        else:
            names = set(match.group(1).split())
            user_apps.update(names)
            if variable == "UTILITY_APPS":
                utility_apps = names
    all_apps = user_apps | {
        "init",
        "service-manager",
        "xaios-worker",
        "sshd",
        "app-fail",
        "app-crash",
    }
    missing_binaries = INTERACTIVE_APPLICATIONS - user_apps
    if missing_binaries:
        failures.append(
            "interactive applications are not dedicated USER_APPS: "
            + ", ".join(sorted(missing_binaries))
        )
    for app in sorted(INTERACTIVE_APPLICATIONS):
        if not (ROOT / "userspace" / "apps" / f"{app}.c").is_file():
            failures.append(f"interactive application source missing: {app}.c")
    for app in sorted(INTERACTIVE_APPLICATIONS | ADMIN_APPLICATIONS):
        source_path = ROOT / "userspace" / "apps" / f"{app}.c"
        if not source_path.is_file() or "main(" not in source_path.read_text(
            encoding="utf-8"
        ):
            failures.append(f"application is not a standalone ELF source: {app}")
    utility_source = ROOT / "userspace" / "apps" / "xutils.c"
    if not utility_source.is_file() or "main(" not in utility_source.read_text(
        encoding="utf-8"
    ):
        failures.append("utility applications do not have a standalone ELF source")
    for app in sorted(all_apps):
        rendered = f"`/init`" if app == "init" else f"`/bin/{app}`"
        if rendered not in apps_doc:
            failures.append(f"Applications.md missing {rendered}")

    source = (ROOT / "kernel/runtime/remote_login.c").read_text(encoding="utf-8")
    for forbidden in (
        "__xaios_nano_core",
        "__xaios_xtop_core",
        "__xaios_pong_core",
        "handle_nano(",
        "handle_xtop(",
    ):
        if forbidden in source:
            failures.append(f"kernel retains private application logic: {forbidden}")
    if (ROOT / "userspace/apps/terminal_app_bridge.h").exists():
        failures.append("terminal applications still use the private kernel bridge")
    start = source.find('"XAIOS shell: ')
    end = source.find('quit logout help\\n"', start)
    if start < 0 or end < 0:
        failures.append("cannot locate shell help catalog")
        shell_commands: set[str] = set()
    else:
        region = source[start : end + len('quit logout help\\n"')]
        help_text = "".join(re.findall(r'"([^"\\]*(?:\\.[^"\\]*)*)"', region))
        help_text = help_text.replace("XAIOS shell: ", "").replace("\\n", "")
        shell_commands = set(help_text.split())

    app_commands = user_apps - {"xaios-shell", "sshtest"}
    built_in_commands = shell_commands - app_commands - INTERACTIVE_APPLICATIONS
    for command in sorted(built_in_commands):
        if f"`{command}" not in commands_doc and f" `{command}`" not in commands_doc:
            failures.append(f"Commands.md missing built-in {command}")
    for app in sorted(INTERACTIVE_APPLICATIONS):
        if f"| `/bin/{app}` |" not in apps_doc:
            failures.append(f"Applications.md missing dedicated /bin/{app}")
        if re.search(rf"^\| `{re.escape(app)}(?:[ `])", commands_doc, re.MULTILINE):
            failures.append(f"Commands.md lists interactive application {app}")
    for app in sorted(utility_apps):
        if f"| `/bin/{app}` |" not in apps_doc:
            failures.append(f"Applications.md missing utility /bin/{app}")
        if re.search(rf"^\| `{re.escape(app)}(?:[ `])", commands_doc, re.MULTILINE):
            failures.append(f"Commands.md lists utility application {app}")
    if "[[Commands|Commands]]" not in apps_doc or "[[Applications|Applications]]" not in commands_doc:
        failures.append("Applications and Commands pages are not cross-referenced")
    for marker in ("user-mode fault", "exit status 128"):
        if marker not in apps_doc:
            failures.append(f"Applications.md missing isolation evidence: {marker}")
    for marker in ("Current owner", "asynchronous child-channel IPC", "`cd`"):
        if marker not in commands_doc:
            failures.append(f"Commands.md missing ownership audit: {marker}")

    if failures:
        print("user-docs: failed")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(
        f"user-docs: documented {len(all_apps)} executable images and "
        f"{len(INTERACTIVE_APPLICATIONS)} interactive applications, "
        f"{len(utility_apps)} utility applications, and "
        f"{len(built_in_commands)} built-in commands"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
