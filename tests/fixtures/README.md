# Test fixtures

Everything here is disposable and exists so a gate has something to run
against. None of it is a secret, and none of it may become one.

## `xapt-tls-key.pem`, `xapt-tls-cert.pem`

A throwaway RSA key and self-signed certificate. `qemu-xapt-gate.py` serves the
package repository over TLS with them so the updater's transport path can be
exercised end to end.

**This private key is public.** It is in a public repository and has been since
it was committed, so treat it as compromised by definition. It is here because
a TLS test needs *a* key, not because this one is protected.

It must never be used to sign anything, must never appear in a release image,
and must never be presented by a service anyone connects to expecting privacy.
Production key custody and rotation are separate open gates, tracked in
[the project tracker](../../wiki/Project-Tracker.md).

Regenerate it whenever you like; nothing depends on its identity:

```sh
openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
  -keyout tests/fixtures/xapt-tls-key.pem \
  -out tests/fixtures/xapt-tls-cert.pem \
  -subj "/CN=xapt.test"
```

## `xapt-test-app.c`

A minimal application the packaging gates build, sign with a development key
and install, to prove `xapt` can carry a payload without rebooting.

## Adding a fixture

Fixtures carry no real credentials, no customer data and no financial data. If
a test needs something that would be sensitive in production, it needs a
generated stand-in, not a copy of the real thing with the risky parts removed.
