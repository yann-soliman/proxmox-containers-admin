---
name: proxmox-containers-admin
description: Administer a Proxmox homelab through a restricted SSH wrapper that exposes guest inventory, status, configuration inspection, guest shell execution, LXC file transfer, and optional power actions without exposing a free Proxmox host shell. Use when operating or documenting day-to-day homelab administration through the wrapper commands, especially to inspect guests, run shell commands inside them, transfer files to or from LXC guests, or understand which wrapped action maps to which underlying Proxmox command.
---

# Proxmox homelab administration via SSH wrapper

Use the wrapper commands, not raw `pct`/`qm` commands.

## Goal

Use this skill to operate the homelab through the wrapper:
- list guests
- inspect status
- read guest configuration
- run shell commands inside a guest
- transfer files to or from an LXC guest
- use power actions only when explicitly requested

## How to work

Prefer this sequence:
1. identify the guest
2. inspect status
3. inspect configuration if needed
4. run read-only guest commands first
5. transfer files only when shell output is not enough
6. use power actions only on explicit request

## Wrapped commands

### Inventory
- `list-lxc`
  - purpose: list available LXC guests
  - underlying command: `pct list`

- `list-vm`
  - purpose: list available VM guests
  - underlying command: `qm list`

### Status
- `lxc-status <vmid>`
  - purpose: check whether an LXC is running and get its state
  - underlying command: `pct status <vmid>`

- `vm-status <vmid>`
  - purpose: check whether a VM is running and get its state
  - underlying command: `qm status <vmid>`

### Configuration inspection
- `lxc-config <vmid>`
  - purpose: inspect an LXC definition, mount points, network config, and limits
  - underlying command: `pct config <vmid>`

- `vm-config <vmid>`
  - purpose: inspect a VM definition, disks, network config, and options
  - underlying command: `qm config <vmid>`

### Run shell commands inside a guest
- `lxc-shell <vmid> -- <command>`
  - purpose: run a shell command inside an LXC for diagnosis or administration
  - underlying command: `pct exec <vmid> -- sh -c "<command>"`

- `vm-shell <vmid> -- <command>`
  - purpose: run a shell command inside a VM when guest-agent execution is available
  - underlying command: `qm guest exec <vmid> -- sh -c "<command>"`

- `lxc-shell-stdin <vmid>`
  - purpose: run a multi-line shell script inside an LXC through SSH stdin
  - underlying command: `pct exec <vmid> -- sh -s`

- `vm-shell-stdin <vmid>`
  - purpose: run a multi-line shell script inside a VM through SSH stdin when guest-agent execution is available
  - underlying command: `qm guest exec <vmid> -- sh -s`

### Transfer files with an LXC
- `lxc-pull <vmid> <guest-path>`
  - purpose: retrieve a file from an LXC through SSH stdout
  - underlying command: `pct pull <vmid> <guest-path> <temporary-host-file>`

- `lxc-push <vmid> <guest-path>`
  - purpose: send a file to an LXC through SSH stdin
  - underlying command: `pct push <vmid> <temporary-host-file> <guest-path>`

### Power actions
Use only when explicitly requested.

- `lxc-power <vmid> <start|stop|shutdown|reboot>`
  - purpose: control LXC power state
  - underlying command: `pct <verb> <vmid>`

- `vm-power <vmid> <start|stop|shutdown|reboot|reset>`
  - purpose: control VM power state
  - underlying command: `qm <verb> <vmid>`

- `vm-agent-ping <vmid>`
  - purpose: verify that the VM guest agent is responding
  - underlying command: `qm agent <vmid> ping`

## Typical usage patterns

### Start with inventory
Use when the target VMID is unknown.
- `ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "list-lxc"`
- `ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "list-vm"`

### Check guest health
Use when a guest may be down or misbehaving.
- `ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-status 117"`
- `ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "vm-status 201"`

### Inspect guest definition
Use when the issue may come from network, mounts, CPU, RAM, disks, or boot options.
- `ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-config 117"`
- `ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "vm-config 201"`

### Diagnose from inside the guest
Use when the guest is reachable and you need system-level inspection.
- `ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-shell 117 -- hostname"`
- `ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-shell 117 -- systemctl status patchmon-agent --no-pager"`
- `ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-shell 117 -- journalctl -u patchmon-agent -n 200 --no-pager | tail -20"`
- `ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "vm-shell 201 -- uname -a"`

For multi-line inspection scripts:

```bash
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-shell-stdin 117" <<'EOF'
set -eu
hostname
df -h
EOF
```

### Transfer a file with an LXC
Use when a file is too large or too structured to handle comfortably through shell output.
- `ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-pull 117 /etc/app/config.yaml" > config.yaml`
- `ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-push 117 /etc/app/config.yaml" < config.yaml`
- `ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-pull 117 /etc/app/My Config/config.yaml" > config.yaml`
- `ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-push 117 /etc/app/My Config/config.yaml" < config.yaml`

## Operational guardrails

Keep these rules in mind when using the wrapper:
- use one SSH call per wrapper action
- do not chain multiple wrapper actions in the same SSH command
- keep `lxc-shell` and `vm-shell` for simple commands
- prefer `lxc-shell-stdin` and `vm-shell-stdin` for long or multi-step operations
- keep a temporary guest-side script as a fallback when stdin alone is not enough
- do not use `ssh -n` when sending file content to `lxc-push`, or stdin will be empty

## Practical rule

For homelab administration, think in terms of:
- inventory
- status
- config inspection
- guest shell execution
- LXC file transfer when needed
- power action only on request

Read `README.md` only when you need the installation or variable configuration details.
