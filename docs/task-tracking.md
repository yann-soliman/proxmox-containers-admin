# Follow a Proxmox task without submitting it twice

Some `pvesh create/set/delete` API operations return an asynchronous task ID
(`UPID:...`). A successful submission is not a completed operation. CLI commands
such as `pct create` or `qm clone` may wait synchronously instead: check their
exit status and resource state; do not invent a UPID from arbitrary output.
Read `pvesh usage <path> -v` through approved host access for the installed schema.

## Access boundary

The local standard-library helper `scripts/proxmox-task-wait.py` only reads task
status. Each poll uses the existing SSH destination and exactly one wrapper action:
`host-exec -- pvesh get /nodes/<node>/tasks/<upid>/status --output-format json`.
The broker must already have an active, human-approved **FULL** lease covering the
operation and its verification. SAFE does not expose arbitrary `pvesh`.

No token, new sudo rule, wrapper action or host deployment is needed. SSH uses
existing keys/config and normal host-key verification, with noninteractive auth.
The helper neither requests nor renews access. If access expires or is refused,
stop; do not bypass approval. An existing task may continue after access expires.

## Local use

Save the exact UPID immediately after submission, together with its intended
node, VMID and operation, in private local task notes (not committed). The helper
extracts the node from the UPID, validates the identifier and retains it in its
JSON output. It accepts standard PVE UPIDs with simple task/resource identifiers;
it fails closed on unsupported identifiers rather than rewriting them.

```bash
# Run on the agent machine from the repository root, not on PVE.
# Existing environment: PROXMOX_SSH_USER and PROXMOX_HOST.
python3 scripts/proxmox-task-wait.py "$UPID" --timeout 600 --interval 3
```

Exit codes:
- `0`: stopped with `exitstatus=OK`.
- `1`: stopped with a non-OK exit status (task failure).
- `2`: polling/inspection timed out; task outcome is unknown, NOT cancelled.
  CLI usage errors also use argparse's conventional exit code 2, on stderr
  without a JSON task result.
- `3`: invalid identifier/destination, malformed status, access refusal or
  transport error; task outcome is unknown. Raw stderr/payloads are not echoed.

Each SSH read is bounded to at most 15 seconds and the remaining overall timeout.
A slow read may therefore end polling before the overall timeout. Inspect again
using the **same UPID** when access/connectivity permits. Do not resubmit the
original write after a timeout or connection failure: it may still be running or
may already have succeeded. If the original submission lost its response before
returning a UPID, inspect task inventory and the target resource before deciding
whether to retry. Never automatically cancel, delete or roll back.

## Completion means resource readback

After a successful task, read the exact target configuration/status. For a new
LXC/VM, verify disks, network, identity and actual guest access as described in
[guest provisioning](guest-provisioning.md). `exitstatus=OK` does not prove the
application works. Read only scoped failure diagnostics if needed; task logs and
guest output can contain secrets, so do not dump them wholesale.

## Validation

`python -m pytest tests/test_task_wait.py -q` exercises success, task failure,
timeout, malformed data/identifiers, SSH construction and transport refusal
without contacting Proxmox. These are local automated tests, not a live-PVE
acceptance claim. The helper has no write, resubmit, cancellation or approval path.
