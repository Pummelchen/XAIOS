#!/usr/bin/env python3
"""Keep the Wiki application and built-in command catalogs source-complete."""

from __future__ import annotations

import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
INTERACTIVE_APPLICATIONS = {"htop", "nano", "pong"}


def main() -> int:
    failures: list[str] = []
    build = (ROOT / "scripts/build-image.sh").read_text(encoding="utf-8")
    apps_doc = (ROOT / "wiki/Applications.md").read_text(encoding="utf-8")
    commands_doc = (ROOT / "wiki/Commands.md").read_text(encoding="utf-8")
    user_apps: set[str] = set()
    for variable in ("USER_APPS", "HOSTED_USER_APPS"):
        match = re.search(rf'^{variable}="([^"]+)"', build, re.MULTILINE)
        if match is None:
            failures.append(f"cannot locate {variable} in build-image.sh")
        else:
            user_apps.update(match.group(1).split())
    all_apps = user_apps | {"init", "service-manager", "xaios-worker", "sshd", "app-fail"}
    missing_binaries = INTERACTIVE_APPLICATIONS - user_apps
    if missing_binaries:
        failures.append(
            "interactive applications are not dedicated USER_APPS: "
            + ", ".join(sorted(missing_binaries))
        )
    for app in sorted(INTERACTIVE_APPLICATIONS):
        if not (ROOT / "userspace" / "apps" / f"{app}.c").is_file():
            failures.append(f"interactive application source missing: {app}.c")
    for app in sorted(all_apps):
        rendered = f"`/init`" if app == "init" else f"`/bin/{app}`"
        if rendered not in apps_doc:
            failures.append(f"Applications.md missing {rendered}")

    source = (ROOT / "kernel/runtime/remote_login.c").read_text(encoding="utf-8")
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
    if "[[Commands|Commands]]" not in apps_doc or "[[Applications|Applications]]" not in commands_doc:
        failures.append("Applications and Commands pages are not cross-referenced")

    if failures:
        print("user-docs: failed")
        for failure in failures:
            print(f"  - {failure}")
        return 1
    print(
        f"user-docs: documented {len(all_apps)} executable images and "
        f"{len(INTERACTIVE_APPLICATIONS)} interactive applications and "
        f"{len(built_in_commands)} built-in commands"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
