#!/usr/bin/env python3
"""The FreeBSD guest's cloud-init payload for the network suite.

Moved verbatim out of `qemu-freebsd-network-suite.py`. This half is the shell
program the FreeBSD end runs on first boot -- driving XAIOS's SSH, SFTP, PTY
xtop and UDP endpoints -- together with the cloud-config document that carries
it. Nothing here touches the host, so the suite keeps the orchestration and
this module keeps the text. The two markers it announces itself with are owned
by `qemu_freebsd_network_env.py`.
"""

from __future__ import annotations

import base64

from qemu_freebsd_network_env import FREEBSD_FAIL_MARKER, FREEBSD_PASS_MARKER


def freebsd_client_script(
    private_key: str,
    unauthorized_key: str,
    ssh_port: int,
    udp_port: int,
    architecture: str,
) -> str:
    # Keystrokes into a full-screen program are paced for the machine that has
    # to draw between them.
    #
    # This drives xtop by typing and waiting, which is the only way to drive it
    # from inside a shell script piping into ssh. Two tenths of a second is
    # long enough for a guest running natively and is not long enough for one
    # being interpreted instruction by instruction: on RISC-V the help key
    # arrived before the program had finished starting, and the check for the
    # help screen failed on a guest that would have drawn it. Scaled, not
    # lengthened for everyone, because a suite that waits four times as long
    # on every machine to accommodate the slowest is a suite people stop
    # running.
    xtop_settle = 8 if architecture == "riscv64" else 2
    xtop_step = "0.5" if architecture == "riscv64" else "0.1"
    return f"""#!/bin/sh
exec >/dev/console 2>&1
set -eu

fail() {{
    echo "{FREEBSD_FAIL_MARKER}: $*"
    poweroff
    exit 1
}}

key=/tmp/xaios-authorized
bad_key=/tmp/xaios-unauthorized
cat >"$key" <<'XAIOS_AUTHORIZED_KEY'
{private_key.rstrip()}
XAIOS_AUTHORIZED_KEY
cat >"$bad_key" <<'XAIOS_UNAUTHORIZED_KEY'
{unauthorized_key.rstrip()}
XAIOS_UNAUTHORIZED_KEY
chmod 600 "$key" "$bad_key"

host=10.0.2.2
port={ssh_port}
ssh_base="-i $key -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no -o ConnectTimeout=5 -p $port"

echo "XAIOS_FREEBSD_INTEROP: client $(uname -K) $(uname -m) OpenSSH_$(ssh -V 2>&1 | sed -n 's/^OpenSSH_\\([^,]*\\).*/\\1/p')"
ready=0
attempt=0
while [ "$attempt" -lt 90 ]; do
    if ssh $ssh_base admin@$host 'echo freebsd-ssh-ok' >/tmp/ssh-ready.out 2>/tmp/ssh-ready.err; then
        ready=1
        break
    fi
    attempt=$((attempt + 1))
    sleep 2
done
[ "$ready" -eq 1 ] || fail "SSH did not become ready"
[ "$(cat /tmp/ssh-ready.out)" = "freebsd-ssh-ok" ] || fail "SSH command output mismatch"
echo "XAIOS_FREEBSD_INTEROP: SSH public-key command PASS"

if ssh -i "$bad_key" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no -o BatchMode=yes -o ConnectTimeout=5 -p "$port" admin@$host 'echo rejected-key-ran' >/tmp/bad-key.out 2>/tmp/bad-key.err; then
    fail "unauthorized key was accepted"
fi
[ ! -s /tmp/bad-key.out ] || fail "unauthorized key command reached XAIOS"
echo "XAIOS_FREEBSD_INTEROP: unauthorized key rejection PASS"

ssh $ssh_base admin@$host 'xaiosctl version --json' >/tmp/version.json || fail "xaiosctl version failed"
grep -q '"status":"ok"' /tmp/version.json || fail "xaiosctl response was not successful"
grep -q '"architecture":"{architecture}"' /tmp/version.json || fail "xaiosctl did not report {architecture}"
echo "XAIOS_FREEBSD_INTEROP: xaiosctl PASS"

printf 'freebsd-sftp-roundtrip\\nsecond-line\\n' >/tmp/sftp-source
cat >/tmp/sftp.batch <<'XAIOS_SFTP_BATCH'
put /tmp/sftp-source /tmp/freebsd-sftp
ls -l /tmp/freebsd-sftp
get /tmp/freebsd-sftp /tmp/sftp-result
rename /tmp/freebsd-sftp /tmp/freebsd-sftp-renamed
get /tmp/freebsd-sftp-renamed /tmp/sftp-renamed-result
rm /tmp/freebsd-sftp-renamed
quit
XAIOS_SFTP_BATCH
sftp -b /tmp/sftp.batch -i "$key" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no -o ConnectTimeout=5 -P "$port" admin@$host >/tmp/sftp.log 2>&1 || {{ cat /tmp/sftp.log; fail "SFTP batch failed"; }}
cmp /tmp/sftp-source /tmp/sftp-result || fail "SFTP round trip differed"
cmp /tmp/sftp-source /tmp/sftp-renamed-result || fail "SFTP rename round trip differed"
grep -q '/tmp/freebsd-sftp' /tmp/sftp.log || fail "SFTP stat/list output missing"
echo "XAIOS_FREEBSD_INTEROP: SFTP read/write/stat/rename/remove PASS"

{{ sleep {xtop_settle}; printf 'M'; sleep {xtop_step}; printf '/sshd\n'; sleep {xtop_step}; printf 'h'; sleep {xtop_step}; printf 'h'; sleep {xtop_step}; printf 'q'; }} | TERM=xterm ssh -tt $ssh_base admin@$host 'xtop' >/tmp/xtop.ansi 2>/tmp/xtop.err || fail "PTY xtop failed"
printf '\\033[2J\\033[H' >/tmp/clear-sequence
printf '\\033[?1049h' >/tmp/alternate-enter
printf '\\033[?1049l' >/tmp/alternate-leave
grep -F -f /tmp/alternate-enter /tmp/xtop.ansi >/dev/null || fail "PTY xtop did not enter alternate screen"
grep -F -f /tmp/clear-sequence /tmp/xtop.ansi >/dev/null || fail "PTY xtop lacked ANSI clear sequence"
grep -q 'Tasks:' /tmp/xtop.ansi || fail "PTY xtop lacked task meter"
grep -q 'Filter:' /tmp/xtop.ansi || fail "PTY xtop lacked interactive filter"
# The help screen, by three of its lines rather than by its title.
#
# The title is on the screen -- a person pressing h sees "XAIOS xtop help" in
# the top rule -- but it is not in the byte stream as one run. The screen
# framework sends only the cells that changed, and the rule's leading corner
# and dashes match the frame underneath, so the title arrives split around
# cursor moves. Body lines differ from the frame beneath them along their
# whole width and arrive whole, which is what a grep over a stream can check.
# This is the same correction B-26 made to the Docker suite; this suite kept
# the old assertion because nothing had run it since.
grep -q 'Up/Down, j/k   select process' /tmp/xtop.ansi \
    || fail "PTY xtop lacked the help screen's process-selection line"
grep -q 'Press F1, h, Escape or q to return.' /tmp/xtop.ansi \
    || fail "PTY xtop lacked the help screen's return line"
grep -q '60 frames/s' /tmp/xtop.ansi || fail "PTY xtop lacked frame-cap status"
grep -F -f /tmp/alternate-leave /tmp/xtop.ansi >/dev/null || fail "PTY xtop did not leave alternate screen"
echo "XAIOS_FREEBSD_INTEROP: SSH PTY interactive xtop PASS"

payload='freebsd-udp-echo'
reply="$(printf '%s' "$payload" | nc -u -w 5 "$host" {udp_port})" || fail "UDP echo failed"
[ "$reply" = "$payload" ] || fail "UDP echo payload mismatch"
echo "XAIOS_FREEBSD_INTEROP: UDP PASS"

echo "{FREEBSD_PASS_MARKER}"
poweroff
"""


def freebsd_user_data(
    private_key: str,
    unauthorized_key: str,
    ssh_port: int,
    udp_port: int,
    architecture: str,
) -> str:
    client = freebsd_client_script(
        private_key, unauthorized_key, ssh_port, udp_port, architecture
    )
    encoded = base64.b64encode(client.encode("ascii")).decode("ascii")
    return (
        "#cloud-config\n"
        "package_update: false\n"
        "package_upgrade: false\n"
        "write_files:\n"
        "  - path: /etc/rc.conf.d/firstboot_freebsd_update\n"
        "    permissions: '0644'\n"
        "    owner: root:wheel\n"
        "    content: 'firstboot_freebsd_update_enable=\"NO\"'\n"
        "  - path: /etc/rc.conf.d/firstboot_pkg_upgrade\n"
        "    permissions: '0644'\n"
        "    owner: root:wheel\n"
        "    content: 'firstboot_pkg_upgrade_enable=\"NO\"'\n"
        "  - path: /root/xaios-freebsd-client.sh\n"
        "    permissions: '0700'\n"
        "    owner: root:wheel\n"
        "    encoding: b64\n"
        f"    content: {encoded}\n"
        "runcmd:\n"
        "  - /bin/sh /root/xaios-freebsd-client.sh\n"
    )

