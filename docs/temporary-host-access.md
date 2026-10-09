# Optional temporary host access

This extension is disabled when its fixed launcher/configuration/services are absent.
It is independent of any agent framework or private infrastructure. It adds one
single-node, single-agent authority, not a general identity platform.

## Protocol and policy

SSH commands (one per connection):

* `host-access-request safe|full [seconds] -- reason`
* `host-access-status [request-id]`
* `host-access-revoke request-id`
* `host-safe action [key=value ...]`
* `host-exec -- command` (FULL only, no input payload)
* `host-exec --stdin -- command` (FULL only, buffered input until EOF)
* `host-script-stdin` (FULL only; disabled by default)

A request ID is a random 32-character hexadecimal lookup identifier, NOT a
capability. No SSH approval command exists. The server derives agent and target
from root-owned configuration. The root wrapper launcher additionally checks the
sudo-generated numeric `SUDO_UID` against the installed mapping. Supplying a
username, UID, mode override, duration override or an approval field cannot alter
an existing request.

Defaults: 900 seconds requested access, maximum 1800 seconds, pending request TTL
300 seconds. A lease starts on approval, uses monotonic time and cannot be renewed
silently. FULL includes SAFE; SAFE cannot execute shell commands/scripts. One
pending request OR active lease, one running execution, one request per minute.
A request is immutable. States: pending → active/denied/expired/revoked; active →
expired/revoked. Terminal decisions are single-use. Request history is capped at
100 records. Active/pending state is invalidated on broker restart or reboot.
A state persistence failure closes in-memory authority. Broker state is protected
by an exclusive OS file lock.

Two Unix sockets use Linux `SO_PEERCRED`: root-only agent socket and web UID-only
authority socket. No `getpeername` identity inference, client-provided actor or
network broker port. Each message is one newline-framed JSON object, at most
128 KiB. Each socket admits at most 16 handler threads with a 5-second input timeout.
Password verification and authorization transitions are serialized. Authenticated
sessions live in broker memory for 15 minutes, max 32. Each approval requires an
authenticated session and a one-use, 120-second confirmation nonce tied to the
immutable request ID, but no second password entry. Login has a global
six-attempt-per-minute budget (including successful attempts), expiring
automatically rather than permanently locking out. A stolen active operator
session can authorize requests: protect the browser and log out when finished.

The UI uses same-origin POST, CSRF, Secure/HttpOnly/SameSite=Strict cookies, no-store,
CSP, HSTS, escaping and exact configured Host/HTTPS origin. GET never grants or
revokes host access. It can create a presentation nonce, not an authorization.
No signup/reset/registration endpoint exists. Login redirects accept only a
validated request ID; arbitrary `next` URLs are ignored.

## Installation (operator on the destination PVE; not run by an agent)

Prerequisites: Python >=3.11 with venv/pip support, Linux systemd with transient
service support, a dedicated existing SSH agent account, and an independent HTTPS
reverse proxy. Install any missing OS prerequisites manually as operator. The
installer does not use apt or modify the system Python, SSH, firewall, DNS or proxy.
Use a reviewed trusted checkout, not an agent-writable directory, for root installation.

1. `sudo bash scripts/install-host-access.sh`
   Creates the nonroot `proxmox-host-access` service account, a dedicated venv at
   `/opt/proxmox-host-access/venv`, root-owned modules and the fixed root launcher.
   Installation/venv directories are explicitly 0755 even under umask 077;
   dependency files are 0644 (0755 for executables), root-owned and never
   group/world-writable. Extension module files remain root:web-group 0640.
   Config/hash/state/secret protections are not relaxed.
   Services are installed but NOT enabled or started. No real config/credential is
   auto-created. The existing guest wrapper is not overwritten.
2. Manually install the reviewed updated `scripts/proxmox-guest-wrapper.sh` using
   the existing README procedure, retaining the old wrapper for rollback.
3. Copy `/etc/proxmox-host-access/config.toml.example` to `config.toml` and edit as
   operator. Set exact external HTTPS origin, target label, numeric agent UID
   (`id -u proxmox-agent`) and web UID (`id -u proxmox-host-access`). Config must be
   root:proxmox-host-access 0640, directory root:proxmox-host-access 0750. No private
   domains or credentials belong in the repository. Agent/web UIDs must differ.
4. Configure reviewed local diagnostic resources by short alias, not client paths.
   Leave `log_services=[]`, `audit_enabled=false` and `enable_script=false` initially.
5. Optional Gotify: supply an HTTPS base URL and a root-only 0600 token file via
   `gotify_token_file`. Create/edit this token file using the operator's secure
   editor/secret tooling, never a CLI argument, URL, shell-history command or agent
   chat. The sender uses `X-Gotify-Key` and refuses redirects. Empty URL disables
   notifications. Failed delivery never grants access; `notified` reports transport
   acceptance only, not delivery to a phone. Request/decision/closure notifications
   are best-effort, without retry storms.
6. Run `sudo /opt/proxmox-host-access/venv/bin/python -I -m host_access.operator bootstrap`.
   This stops both authority services, prompts twice using `getpass`, writes only
   an Argon2id hash (64 MiB, time cost 3, parallelism 4) to a 0600 root-only file.
   Store the password personally in a nonshared password vault; no agent access.
7. Configure HTTPS proxy separately. Default backend is loopback:8787, trusted proxy
   127.0.0.1. A remote proxy requires an explicit backend bind IP and EXACT proxy
   IP in `trusted_proxy`, plus host firewall source restriction. Preserve original
   Host and set X-Forwarded-Proto from the trusted TLS endpoint. Never trust
   forwarded identity or arbitrary forwarded Host. HTTP between remote proxy and
   host exposes the operator password to that network: require a protected network
   or a local TLS tunnel. Do not disable TLS verification for a TLS backend.
8. Explicitly start: `sudo systemctl start proxmox-host-access-broker.service proxmox-host-access-web.service`.
   Enable on boot only after live acceptance: `sudo systemctl enable proxmox-host-access-broker.service proxmox-host-access-web.service`.

No live deployment is implicit in tests or staging. For offline layout validation:
`bash scripts/install-host-access.sh --stage /absolute/empty/staging-directory`.
This renders services, launcher and example only, without an account, dependencies
or services. It is NOT a working installed runtime or deployment acceptance.

## Use

Agent requests SAFE/FULL with a concrete reason, reads request state and waits.
Gotify opens `/request/<id>`. The human logs in once, reviews target/agent/mode/duration
and explicitly clicks approve without re-entering the password. An active session
plus the request-specific confirmation can authorize; reading a notification
alone cannot. The authenticated `/` console shows current and recent requests.
Refuse or revoke via authenticated UI. The agent can
revoke its own request too. No automatic renewal or escalation.

Examples:

    ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-access-request safe -- inspect node pressure'
    ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-access-status'
    ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-safe cpu-memory'
    ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-safe service-status service=pveproxy.service'

For FULL, after separate explicit approval:

    ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec -- hostname'
    printf 'benign input' | ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec --stdin -- cat'

No interactive terminal protocol: input and output are buffered and bounded.
Before reading stdin, the client requires an active FULL lease from the broker.
One pre-admission stdin receiver is allowed across root clients, using a
nonblocking exclusive flock on `socket_dir/stdin.lock` (default
`/run/proxmox-host-access/stdin.lock`), root-owned 0600 in the protected runtime
directory. Contenders fail immediately; clients cannot choose the path or limits.
Reception has a 10-second absolute monotonic deadline (`stdin_timeout`, operator
configuration only, integer 1..30 seconds), including authorization polling;
incoming chunks never renew it. The selected immutable lease ID is checked every
0.2 seconds and again at EOF; each status RPC has a total 1-second deadline,
capped by remaining reception time. Missing, SAFE, revoked or expired leases fail
closed. Pipes held open are not allowed to wait forever. Binary input is preserved.
The lock is released on every exit and retained on disk to avoid inode races.
The broker independently reauthorizes execution; the reception lock is not an
execution grant or hostile-root confinement.
Default input limit 64 KiB (command+payload together); default stdout+stderr limit
1 MiB. Binary outputs are preserved using base64 on the internal protocol and
written as bytes by the client. Overflow kills the supervised command and sets
`truncated=true`; SSH receives the failed/signal-derived exit code, or 125 if
truncation coincides with an otherwise successful exit. Default command
runtime 300 seconds and always at most remaining lease time. Commands and script
contents are transported to a fixed worker by stdin/memfd, not argv/environment.
Execution units have KillMode=control-group, RuntimeMaxSec, stop timeout and SIGKILL.
Admission, approval and revocation share a lock. A watchdog continuously checks
leases; revocation kills tracked units. Broker shutdown/restart also cleans only
its `pha-exec-*.service` units. There is no production non-systemd fallback.

## Closed SAFE catalogue

All 22 identifiers have dispatch implementations. Optional tools/targets return
`available=false` when absent/unconfigured/failing; nothing is auto-installed.
Native diagnostics have a ten-second timeout and 256 KiB combined I/O cap; outer
supervision adds the lease/runtime/output bounds. SAFE still requires a valid lease.

| Action | Implementation / arguments |
| --- | --- |
| host-summary | hostname, kernel, OS release, uptime, optional pveversion |
| cpu-memory | lscpu JSON, /proc load/memory/pressure |
| process-summary | PID/UID/short comm/CPU/RAM; no argv or environ |
| disk-usage | statvfs of configured `filesystems` local aliases |
| disk-layout | lsblk NAME/TYPE/SIZE/MOUNTPOINTS; no serial, blkid/FSTYPE probing requested |
| directory-usage | `root=alias`, `depth=1..3`; apparent regular-file sizes per level, 10000 entries, 5 seconds, no file contents; pinned dirfds, no symlinks, device/mount-ID boundaries, hardlink dedup |
| journal-usage | journalctl --disk-usage; no vacuum |
| pve-storage-status | statvfs of configured local `storage_paths` ONLY, no pvesm status or remote activation/mount/probe; not a claim of remote storage health |
| zfs-health | zpool status -p plus selected name/size/alloc/free/cap/health list fields; no import/scrub |
| lvm-summary | readonly selected PV/VG/LV/thin-pool reports; no activation |
| disk-health | `device=alias`, canonical block device, smartctl -H -A; no test/settings |
| hardware-temperatures | existing hwmon temperature and fan-RPM inputs only; no sensors-detect/probing |
| service-status | `service=allowed.service`, systemctl show selected Id/Active/Sub/Result fields |
| failed-units | selected name/load/active/sub fields only; no descriptions/definitions |
| service-logs | default unavailable; `service=reviewed.service`, `lines=1..200`, `minutes=1..60`; logs may contain secrets |
| network-summary | ip address/route JSON with counters; no probes/captures |
| listening-ports | ss listening address/port/protocol and selected short process names; no outbound connections/argv/environ |
| time-status | timedatectl selected time/timezone/NTP fields |
| pve-node-health | selected cluster node/quorum status fields, read-only pvesh |
| guest-summary | selected resource VMID/name/type/status/node fields, read-only pvesh |
| task-summary | `limit=1..50`, selected recent task metadata, never task log contents |
| backup-schedule-summary | selected job ID/schedule/enabled/VMID/node/all/exclude fields; no triggering |

Local filesystem types are explicitly limited. Unsupported filesystem types,
noncanonical paths and remote/automount ancestors are refused before opening or
statvfs. Mountinfo path escapes are decoded; known directory mount crossings are
skipped before opening them, with descriptor mount-ID checks as an additional guard.
All unknown parameters/actions
are rejected; there are no free paths, units, executable choices, options or argv.
Diagnostic output may contain operationally sensitive names. Read-only intent is
not a promise of zero cache/log/device metadata side effects.

## Recovery and removal

Keep a separate operator emergency SSH/console access. Credential loss/change:
`sudo /opt/proxmox-host-access/venv/bin/python -I -m host_access.operator change-password`.
It stops services and invalidates existing sessions/leases; restart explicitly.
There is no public password reset. On state corruption, keep services stopped,
review/retain the protected state for diagnosis, remove only the corrupted state
as operator, then restart for a new closed authority. Do not manually mark a lease
active in the file: startup invalidates it and monotonic deadlines are memory-only.

## Fresh-install checklist (generic, operator-controlled)

- Python >=3.11, venv/pip, systemd, dedicated SSH agent account, independent HTTPS proxy.
- `sudo bash scripts/install-host-access.sh` (staging: `--stage /abs/dir`).
- Update legacy wrapper manually (`scripts/proxmox-guest-wrapper.sh`); retain old for rollback.
- Edit `config.toml`: `agent_uid`/`web_uid` (distinct, non-root), exact HTTPS `origin`, `bind`/`trusted_proxy`.
- Root-only 0600 token file for optional Gotify (`gotify_token_file`); never CLI/URL.
- `umask 077`; config `0640`, dir `0750`, state `0700`; module files `0640` (root:web).
- Bootstrap: stops both broker+web, `getpass` twice, writes Argon2id (`password.hash`, 0600 root-only).
- No agent web access; agent uses SSH wrapper + `SUDO_UID` check only.
- UI: `/` dashboard (authenticated) with 15-min broker session; one login password; approval uses request nonce/CSRF + session; no second password.
- Default loopback `bind=127.0.0.1`/`port=8787`; remote proxy needs exact IP + firewall.
- Services installed but NOT auto-enabled/started; start explicitly: `systemctl start ...`; enable only after live acceptance.
- Guest commands unchanged when extension absent; install optional — no regression.
- Update/rollback: `uninstall` preserves wrapper/SSH/account/config/hash/state; reinstall requires uninstall first.

## Version / update considerations

- Dependency updates use locked `requirements.lock`; install uses `--no-build-isolation` with `setuptools==84.0.0 wheel==0.48.0`. Offline: pre-build wheels.
- Password bootstrap stops both services; restart explicitly after change.
- No agent auth via web; agent access remains SSH-only with numeric sudo identity.
- Web requires `web_uid`; broker requires root; sockets use `SO_PEERCRED`.
- CSRF, exact `Origin`, `Secure/HttpOnly/SameSite=Strict`, `no-store`, CSP/HSTS enforced; `GET` never grants/revokes.

`sudo bash scripts/uninstall-host-access.sh` stops/disables authority services,
cleans tracked transient units and removes installed extension files/venv. It
preserves the guest wrapper, SSH configuration, service account, config, hash and
state so rollback/reinstall does not destroy credentials. Purge retained protected
data manually after review. Reinstallation requires uninstall first. A failed
installation may leave partial files/account; uninstall or inspect/remove the
partial fixed installation paths before retrying. Never recursively delete an
operator-configured arbitrary state/config path.

See [security](security.md) and [testing](testing.md) for the threat boundary and
what remains to validate on a disposable systemd host and real PVE/mobile setup.
