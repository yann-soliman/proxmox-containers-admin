# Testing and acceptance

## Reproducible local/CI checks

All Python dependencies stay in the project venv. Python >=3.11 and OpenSSL are
required for the local HTTPS integration certificate. No PVE, real Gotify, DNS,
Traefik, SSH production, password vault or service configuration is contacted.

    python3 -m venv .venv
    .venv/bin/python -m pip install setuptools==84.0.0 wheel==0.48.0
    .venv/bin/python -m pip install --no-build-isolation -c requirements.lock -e '.[test]'
    bash -n scripts/proxmox-guest-wrapper.sh scripts/install-host-access.sh scripts/uninstall-host-access.sh
    .venv/bin/shellcheck scripts/install-host-access.sh scripts/uninstall-host-access.sh
    .venv/bin/shellcheck -e SC2086,SC2295 scripts/proxmox-guest-wrapper.sh
    .venv/bin/python -m ruff check host_access tests
    .venv/bin/python -m pytest -q --junitxml=.venv/test-results.xml
    .venv/bin/python -m build --wheel --no-isolation

If ensurepip is unavailable, ask the operator for venv support or use the pip
bootstrap exclusively inside `.venv` (do not install globally). Build artifacts,
venv, credentials, certificate keys and runtime state are ignored by Git.

The two ShellCheck exclusions apply only to the unchanged upstream guest parser
and reproduce its existing SC2086/SC2295 baseline (splitting/pattern expansion).
The new installer/uninstaller scripts are checked without exclusions.

Tests exercise real lease state/files, salted Argon2id hashes, real Unix sockets
with SO_PEERCRED, actual local supervised process groups (explicit test injection),
real HTTPS with a temporary certificate and verified TLS trust, and a local HTTP
Gotify-compatible receiver. Credentials are random/ephemeral and not intentionally
printed; test fixtures redact their representation. HTTP/S redirects, CSRF, Host,
Origin, Secure cookies, malicious reason escaping, session-only approval rejection,
nonce replay/expiry, rate budgets, peer rejection, immutable mapping, permission
checks, race/revocation/expiry, stdin/stdout/stderr/exit status, binary output,
output overflow, directory bounds, closed safe catalogue and native local dispatch
are covered. Guest regression tests run the real Bash parser with only absolute
pct/qm paths replaced by explicitly declared fixture executables, not real guests.
Installer tests stage and remove real files without installing an OS account or
starting services. A separate umask-077 test exercises the live installer code
against temporary paths with account/chown/systemd/pip calls intercepted: it
creates a real venv, copies locally installed dependency distributions without
network access, checks actual directory/file modes and requested root ownership,
and imports Flask/Argon2/Waitress/the web module from that venv. This is not a
distinct-UID web import or proof of actual root chown/systemd installation.
Client reception tests use live subprocess pipes, binary EOF and regular-file
input, missing/revoked/expired leases, an absolute timeout despite incoming chunks,
oversize without EOF, cross-process nonblocking flock contention/cleanup and
untrusted runtime/lock paths. They use the real local peer-authenticated broker,
with explicit test-only UID/config injection, not production sudo/root accounts.
Optional diagnostic dependencies are reported unavailable,
never replaced with invented successful diagnostic output.

These tests DO NOT prove production systemd cgroup behavior. LocalTestBackend is
constructor injection only: no config/CLI fallback, no production auto-selection.
They DO NOT prove independent UID ownership boundaries in a same-UID unprivileged
test fixture. Production socket UID/modes are explicit and peer rejection is tested;
verify them on the destination before permitting agents to request access.

## Disposable Linux/systemd acceptance (operator opt-in)

Only on a disposable root/systemd environment with this package installed:

    sudo env PHA_SYSTEMD_ACCEPTANCE=1 .venv/bin/python -m pytest tests/test_systemd_live.py -q

The ordinary suite skips this test. It runs a benign transient printf service and
a benign sleep/descendant deadline test. It does not create a persistent production
service or test hostile root escape. Separately validate production services,
root/nonroot sockets, broker restart/cleanup and process revocation under that
host's actual systemd/PVE versions. Root execution can escape supervision: see
security.md. A denied transient-unit creation is a blocker, not a passing result.

## Real PVE/mobile acceptance — later, with explicit deployment approval

1. Audit permanent agent sudo/guest privileges, binds/devices, proxy and vault trust.
2. Install and inspect actual owner/mode on code/config/state/sockets/password hash;
   verify web nonroot UID differs from installed agent UID.
3. Validate HTTPS Host/origin and backend source filtering; reject forged forwarding.
4. Without lease, refuse host-safe/full/script. Existing guest commands still work.
5. Request SAFE; attest actual Gotify receipt on the phone. Opening the push alone
   cannot approve. Authenticate once, review immutable mode/duration, click approve
   without a second password entry.
6. Read actual status via agent socket/SSH, run benign host-summary/cpu-memory.
7. Deny, ignore beyond pending TTL, replay approval, try wrong login password,
   expired/missing session, wrong CSRF and mismatched nonce: no grant.
   SAFE cannot execute FULL shell/script.
8. With separate explicit FULL approval, run hostname; test stdin/exitcode and
   revoke a benign sleep while it runs. Read state and verify descendants stopped.
9. Verify expiry and restart/reboot invalidation; no silent extension/renewal.
10. On Firefox Android 12, manually attest responsive UI, password-manager autofill,
    approval and revoke. Operator stores password personally; agent never handles it.
11. Verify optional diagnostics against real PVE native versions, installed tools
    and reviewed local targets; review journal secrecy before enabling log actions.
12. Test reversible removal without altering the guest wrapper/SSH, retain emergency
    operator access and preserve evidence. Publication/deployment remain separate.

No successful API response substitutes for phone receipt, live readback, real
systemd execution or human UX validation. Current local results should be reported
with the exact command, measured counts and explicit skipped/live blockers.
