# Security boundary

This is a password-only approval mechanism, not MFA, WebAuthn or a root sandbox.
A compromised password, browser, approval web service, TLS reverse proxy or
operator password vault can allow approval. Keep the operator vault private and
outside every permanent agent credential/guest capability. The deployment chain
including DNS, TLS termination and its host/configuration must be independent of
agent-administered guests, or explicitly accept that trust failure.

The agent permanently controls allowed guests, not the approval authority. Audit
privileged containers, bind mounts, host/device/socket access and reusable
infrastructure credentials: the legacy guest wrapper does not provide absolute
host isolation. A guest with host escape capabilities defeats this entire model.
The SSH account itself must not have additional sudo rules. Root-owned wrapper,
launcher, code, configuration and Unix socket directories must not be writable
through any guest/agent path. Numeric sudo identity and SO_PEERCRED, not a client
username, establish the fixed single-agent mapping.

Reading a notification, a request ID or the whole request page does not grant a
lease. Password verification at login is local to the privileged broker. Approval
uses the authenticated 15-minute session with one-use request-specific
confirmation, CSRF and strict web boundaries; there is no second password prompt. Registration,
password changes and recovery are operator-local via getpass; no secret URLs,
CLI arguments or public reset endpoints. The global authentication budget is
six attempts in a rolling minute. An attacker can temporarily deny password
verification, but cannot create a permanent lockout. Sessions/challenges are
memory-only and die on broker restart. Theft of an active session cookie can
allow an attacker to fetch a confirmation nonce and approve. Protect the browser
and operator session; explicit logout invalidates the session at the broker.

Expiration is monotonic, grants begin only after approval, and immutable requests
have single terminal decisions. Exclusive file locking plus broker locking avoid
multiple authorities and check-then-exec races. A lease is rechecked after
supervised startup. RuntimeMaxSec, watchdog, revocation and broker cleanup bound
tracked units. Input/output/concurrency/history/protocol limits bound resources.
Root state corruption or persistence failures do not recover an active lease.
Network/password failure never falls back to authorization.

FULL intentionally grants arbitrary host root execution. Root can escape its
cgroup, create other services/persistence, alter the broker, steal the credential
hash, stop supervision or reboot. Supervision kills only tracked cgroups; this
feature cannot guarantee removal of everything root has launched. Revoke/expiry
do not reverse mutations. Uninterruptible kernel I/O can delay termination.
Run adversarial root escape testing only on disposable infrastructure, never PVE
production. Broker service restrictions must not be mistaken for root confinement.

SAFE is a closed diagnostic dispatcher, not arbitrary argv with a prefix check.
It intentionally avoids host writes, activation, mounts, shell, credential files,
raw unit definitions, process argv/environ, secret serial numbers, arbitrary
network probes and task log contents. Local storage status reports configured
local paths only: remote storage health is deliberately unavailable. The directory
scanner pins file descriptors, rejects symlink and mount crossings (including
same-device bind mounts via mount IDs), caps depth/entries/time and does not read
file contents. Counts are partial apparent regular-file sizes, not `du` allocated
space or an unbounded tree walk. Systemd provides the outer limit if kernel calls
block. Filesystem names, addresses, process names, ZFS/LVM/device reports and guest
names can still disclose operational information. Native tools may update caches,
locks or diagnostic logs; no absolute zero-write guarantee is made.

`service-logs` is disabled per service by default and can expose secrets if enabled.
Review each service first. The extension's optional `audit_enabled` metadata-only
JSONL audit is also disabled by default, root-only, best-effort, rotated at 1 MiB
with one prior file. It omits reason, password, tokens, command/script/stdin/stdout,
stderr and process argv/environment. It is not tamper-proof or a durable security
ledger against root. Systemd/web unit stdout/stderr logging is disabled to avoid
payload/exception capture. Host wrapper actions bypass the legacy command logger.
Legacy guest actions retain their previous logging behavior and may log guest
command content; do not transmit guest secrets in command text. Application and
reverse-proxy logs must never log request bodies/authorization headers/passwords.
Gotify messages contain reason: never put a credential into the request reason.

Deployment review must verify real file ownership, group membership, sudoers,
service account, proxy source filtering and guest isolation, then exercise the
real phone/browser/password flow. Unit tests and a local HTTPS server do not attest
receipt of a real Gotify push or mobile compatibility.
