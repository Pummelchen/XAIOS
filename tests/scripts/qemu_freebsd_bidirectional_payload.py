#!/usr/bin/env python3
"""The FreeBSD guest's cloud-init payload for the bidirectional suite.

Moved verbatim out of `qemu-freebsd-bidirectional-suite.py`. This half is the
shell program the FreeBSD end runs on first boot -- provisioning its user,
authorized keys and sshd, then driving XAIOS in the outbound direction over
SSH, SFTP, SCP and UDP -- together with the cloud-config document that carries
it. Nothing here touches the host, so the suite keeps the orchestration and
this module keeps the text.
"""

from __future__ import annotations

import base64

from qemu_freebsd_bidirectional_env import CLIENT_FAIL, CLIENT_PASS, SERVER_READY


def freebsd_script(
    private_key: str,
    unauthorized_key: str,
    outbound_public_key: str,
    server_password: str,
    expected_architecture: str,
) -> str:
    return f"""#!/bin/sh
# amd64 cloud images keep the framebuffer as /dev/console even with QEMU's
# headless mode.  ttyu0 is the serial console consumed by the gate on both
# supported architectures.
if [ -c /dev/ttyu0 ]; then
    exec >/dev/ttyu0 2>&1
else
    exec >/dev/console 2>&1
fi
set -eu

fail() {{
    echo "{CLIENT_FAIL}: $*"
    exit 1
}}

printf '%s\n' '{server_password}' | pw useradd xaios -m -s /bin/sh -h 0 \
    || fail "could not create server user"
mkdir -p /home/xaios/fixture/nested
printf 'freebsd-to-xaios-scp\n' >/home/xaios/fixture/nested/source.txt
mkdir -p /home/xaios/.ssh
cat >/home/xaios/.ssh/authorized_keys <<'XAIOS_OUTBOUND_AUTHORIZED_KEY'
{outbound_public_key.rstrip()}
XAIOS_OUTBOUND_AUTHORIZED_KEY
chmod 700 /home/xaios/.ssh
chmod 600 /home/xaios/.ssh/authorized_keys
chown -R xaios:xaios /home/xaios
cat >>/etc/ssh/sshd_config <<'XAIOS_SSHD_CONFIG'
PasswordAuthentication yes
KbdInteractiveAuthentication no
PermitRootLogin no
LogLevel DEBUG3
XAIOS_SSHD_CONFIG
sysrc sshd_enable=YES >/dev/null
/usr/bin/ssh-keygen -A || fail "could not generate FreeBSD SSH host keys"
service sshd restart || fail "could not start FreeBSD sshd"
tail -F /var/log/auth.log >/dev/ttyu0 2>&1 &
sockstat -4 -l | grep -q ':22' || fail "FreeBSD sshd is not listening"
echo "{SERVER_READY}"
sleep 10

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
port=2223
ssh_base="-i $key -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no -o ConnectTimeout=5 -p $port"
ready=0
attempt=0
while [ "$attempt" -lt 120 ]; do
    if ssh -vv $ssh_base admin@$host 'echo freebsd-client-ssh-ok' >/tmp/ssh-ready.out 2>/tmp/ssh-ready.err; then
        ready=1
        break
    fi
    attempt=$((attempt + 1))
    sleep 2
done
[ "$ready" -eq 1 ] || fail "XAIOS SSH did not become reachable"
[ "$(cat /tmp/ssh-ready.out)" = "freebsd-client-ssh-ok" ] || fail "SSH output mismatch"
grep -q 'kex: algorithm: mlkem768x25519-sha256' /tmp/ssh-ready.err \
    || {{ cat /tmp/ssh-ready.err; fail "hybrid ML-KEM KEX was not negotiated"; }}

printf 'echo freebsd-pty-ok\nexit\n' | ssh -tt $ssh_base admin@$host \
    >/tmp/pty.out 2>/tmp/pty.err || {{ cat /tmp/pty.err; fail "PTY shell failed"; }}
[ "$(grep -c 'freebsd-pty-ok' /tmp/pty.out)" -ge 2 ] \
    || fail "PTY shell output mismatch"

if ssh -i "$bad_key" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no -o BatchMode=yes -o ConnectTimeout=5 -p "$port" admin@$host true >/tmp/bad.out 2>/tmp/bad.err; then
    fail "unauthorized key was accepted"
fi

ssh $ssh_base admin@$host 'xaiosctl version --json' >/tmp/version.json \
    || fail "xaiosctl failed"
grep -q '"status":"ok"' /tmp/version.json || fail "xaiosctl status mismatch"
grep -q '"architecture":"{expected_architecture}"' /tmp/version.json \
    || fail "xaiosctl architecture mismatch"

printf 'freebsd-sftp-roundtrip\nsecond-line\n' >/tmp/sftp-source
cat >/tmp/sftp.batch <<'XAIOS_SFTP_BATCH'
put /tmp/sftp-source /tmp/freebsd-sftp
ls -l /tmp/freebsd-sftp
get /tmp/freebsd-sftp /tmp/sftp-result
rename /tmp/freebsd-sftp /tmp/freebsd-sftp-renamed
get /tmp/freebsd-sftp-renamed /tmp/sftp-renamed-result
rm /tmp/freebsd-sftp-renamed
quit
XAIOS_SFTP_BATCH
sftp -b /tmp/sftp.batch -i "$key" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no -o ConnectTimeout=5 -P "$port" admin@$host >/tmp/sftp.log 2>&1 \
    || {{ cat /tmp/sftp.log; fail "SFTP batch failed"; }}
cmp /tmp/sftp-source /tmp/sftp-result || fail "SFTP content differed"
cmp /tmp/sftp-source /tmp/sftp-renamed-result || fail "SFTP renamed content differed"

scp -vvv -i "$key" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no -P "$port" /tmp/sftp-source admin@$host:/tmp/freebsd-scp >/tmp/scp-upload.log 2>&1 \
    || {{ cat /tmp/scp-upload.log; fail "FreeBSD scp upload failed"; }}
scp -vvv -i "$key" -o IdentitiesOnly=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o PasswordAuthentication=no -P "$port" admin@$host:/tmp/freebsd-scp /tmp/scp-result >/tmp/scp-download.log 2>&1 \
    || {{ cat /tmp/scp-download.log; fail "FreeBSD scp download failed"; }}
cmp /tmp/sftp-source /tmp/scp-result || fail "SCP content differed"

payload='freebsd-udp-echo'
reply=''
attempt=0
while [ "$attempt" -lt 5 ]; do
    reply="$(printf '%s' "$payload" | nc -u -w 5 "$host" 2224)" || true
    [ "$reply" = "$payload" ] && break
    attempt=$((attempt + 1))
    sleep 1
done
[ "$reply" = "$payload" ] || fail "UDP payload mismatch after 5 attempts"

echo "{CLIENT_PASS}"
"""


def user_data(
    private_key: str,
    unauthorized_key: str,
    outbound_public_key: str,
    server_password: str,
    architecture: str,
) -> str:
    script = freebsd_script(
        private_key, unauthorized_key, outbound_public_key, server_password,
        architecture
    )
    encoded = base64.b64encode(script.encode("ascii")).decode("ascii")
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
        "  - path: /root/xaios-freebsd-suite.sh\n"
        "    permissions: '0700'\n"
        "    owner: root:wheel\n"
        "    encoding: b64\n"
        f"    content: {encoded}\n"
        "runcmd:\n"
        "  - /bin/sh /root/xaios-freebsd-suite.sh\n"
    )
