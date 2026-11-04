# Guest provisioning recipes

A guest is a VM or LXC container; the host is the Proxmox node. These are
parameterized procedures, not an unattended universal installer. Replace every
placeholder with discovered, validated values before executing. Commands below
DO mutate state when executed: reading this document does not authorize them.

## Access and common preflight

The permanent wrapper has no creation/configuration-write actions. Run raw
`pvesh`, `qm` and `pct` only **inside `host-exec` with an active, human-approved
FULL lease** covering discovery, creation and verification. Never use root SSH,
add credentials/permissions or renew access automatically to make a recipe work.
See [host access](temporary-host-access.md). Commands use one wrapper action per
SSH call; `host-exec` parses argv, not shell pipelines/redirections.

Start with ordinary `list-lxc` and `list-vm`, then approved discovery:

```bash
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec -- pvesh get /nodes --output-format json'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec -- pvesh get /cluster/resources --output-format json'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec -- pvesh get /nodes/<NODE>/status --output-format json'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec -- pvesh get /nodes/<NODE>/storage --output-format json'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec -- pvesh get /nodes/<NODE>/network --output-format json'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec -- pvesh get /nodes/<NODE>/storage/<TEMPLATE_STORAGE>/content --content vztmpl --output-format json'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec -- pvesh get /cluster/nextid --output-format json'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec -- pvesh usage /nodes/<NODE>/lxc -v'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec -- pvesh usage /nodes/<NODE>/qemu -v'
```

- Check free RAM, guest commitments and storage space; thin allocation is not
  guaranteed physical capacity. Select enabled storage supporting the needed
  content (`rootdir` for LXC, `images` for VM disks).
- Choose the bridge/VLAN and DHCP/static plan; do not reconfigure host networking.
- `nextid` is not a reservation. Recheck inventory immediately before creation;
  let PVE reject a concurrent allocation. Never delete/reuse an occupied ID.
- Identify template architecture/version and new resource names. Do not silently
  change an existing template, storage content types, guest or mount slot.
- Size per workload. Examples below are starting points, not fleet policy.
  No privileged LXC, nesting, Docker features or onboot autostart by default.
- No passwords in argv/logs. Public-key file paths below refer to files already
  staged on PVE through an approved method, not paths on the agent machine.
- Preserve UPIDs from asynchronous submissions and use [task tracking](task-tracking.md).
  Synchronous CLI commands may block without returning a UPID: check their exit
  code and read back the resource. Never resubmit blindly after a lost response.

## 1. Small Debian LXC

Select an existing Debian template from the listing; separate template storage
from rootfs storage. This creates a stopped, unprivileged container:

```bash
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec -- pct create <NEW_VMID> <TEMPLATE_STORAGE>:vztmpl/<EXACT_TEMPLATE> --hostname <NAME> --ostype debian --memory 512 --swap 512 --cores 1 --rootfs <ROOTFS_STORAGE>:8 --net0 name=eth0,bridge=<BRIDGE>,ip=dhcp --unprivileged 1 --onboot 0 --start 0 --ssh-public-keys <HOST_PUBLIC_KEY_PATH>'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'lxc-config <NEW_VMID>'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'lxc-status <NEW_VMID>'
```

Check disk location, resource limits, network and `unprivileged: 1`. Omission of
features leaves nesting disabled. SSH policy depends on the template: injecting
a root public key is not a guarantee that root SSH is enabled or disabled.
For static addressing, replace `ip=dhcp` with a validated address/prefix and
gateway; do not invent a free IP.

Start only when the user's creation request includes bringing the service up
(or after explicit agreement). Then verify inside the guest:

```bash
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'lxc-power <NEW_VMID> start'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'lxc-shell <NEW_VMID> -- hostname'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'lxc-shell <NEW_VMID> -- ip addr'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'lxc-shell <NEW_VMID> -- ip route'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'lxc-shell <NEW_VMID> -- getent hosts <REQUIRED_SERVICE_HOST>'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'lxc-shell <NEW_VMID> -- df -h'
```

Validate required application connectivity separately; DNS alone is not an E2E
check. Check whether backup jobs and monitoring include the new ID; report any
gap and do not silently change their configuration.

## 2. VM from a cloud-init template

### Prefer a suitable existing template

Inspect `vm-config <TEMPLATE_VMID>` and confirm it is actually a template, with a
cloud-init drive, supported boot disk, correct architecture and known provenance.
Do not boot or edit a shared template. Clone into a fresh VMID, then configure the
**clone**, not the source (`qm clone` does not accept `qm set` options):

```bash
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec -- qm clone <TEMPLATE_VMID> <NEW_VMID> --name <NAME> --full 1 --storage <VM_STORAGE>'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec -- qm set <NEW_VMID> --memory 2048 --cores 2 --net0 virtio,bridge=<BRIDGE> --ipconfig0 ip=dhcp --ciuser <LOGIN_USER> --sshkeys <HOST_PUBLIC_KEY_PATH> --agent enabled=1 --onboot 0'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'vm-config <NEW_VMID>'
```

Inspect inherited extra NICs, disks, cloud-init overrides and credentials before
starting; replacing `net0` does not remove other NICs. Do not boot an unsuitable
clone or delete resources automatically as cleanup.

### If a template must be prepared

Treat template preparation as an explicitly scoped creation task. Download an
architecture-matching cloud image from the vendor's HTTPS release location and
obtain its SHA-256 through a trusted vendor manifest (verify signatures when
available). Stage in a **new private disk-backed directory**, not a RAM-backed
temporary directory or an existing ISO path. Check space first. For example,
`mktemp -d /var/lib/vz/cloud-image.XXXXXX` through host-exec returns a unique path;
confirm the local path is appropriate for that node before using it.

```bash
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec -- curl --fail --location --proto =https --proto-redir =https --output <NEW_PRIVATE_DIR>/image.qcow2 <VENDOR_HTTPS_URL>'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec -- sha256sum <NEW_PRIVATE_DIR>/image.qcow2'
```

Compare the entire digest exactly to the trusted manifest; mismatch means STOP,
not import anyway. Download format/name must match the actual image, not its
extension alone. Check installed schema/help for release-specific options.
Create the VM definition **before importing its disk**:

```bash
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec -- qm create <NEW_TEMPLATE_VMID> --name <TEMPLATE_NAME> --memory 2048 --cores 2 --scsihw virtio-scsi-pci --net0 virtio,bridge=<BRIDGE> --serial0 socket --onboot 0'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec -- qm importdisk <NEW_TEMPLATE_VMID> <NEW_PRIVATE_DIR>/image.qcow2 <VM_STORAGE>'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'vm-config <NEW_TEMPLATE_VMID>'
```

Read the actual `unusedN` imported volume identifier from configuration; never
assume its disk name. Attach that exact new disk:

```bash
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec -- qm set <NEW_TEMPLATE_VMID> --scsi0 <EXACT_IMPORTED_VOLUME> --ide2 <VM_STORAGE>:cloudinit --boot order=scsi0 --agent enabled=1'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'vm-config <NEW_TEMPLATE_VMID>'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec -- qm template <NEW_TEMPLATE_VMID>'
```

The `scsi0` boot example is for images supporting this hardware/firmware; adapt
from vendor requirements, not trial writes on an existing VM. Keep the template
unbooted to avoid baked-in identities. Enabling the agent in PVE does not install
`qemu-guest-agent` inside the image. Prefer an already prepared image/template;
otherwise install and enable it inside the new clone after authorized SSH access.
Clean only the specifically created staging directory after verification, never
wildcard paths. Preserve failed new resources for diagnosis unless cleanup is approved.

### Boot and verify the clone

When startup is within the request, use `vm-power <NEW_VMID> start`. Discover its
address from DHCP or the guest agent, not an assumed IP. From the agent machine,
verify actual SSH using existing credentials and a verified guest host key:

```bash
ssh -o BatchMode=yes <LOGIN_USER>@<GUEST_IP> 'cloud-init status --wait'
ssh -o BatchMode=yes <LOGIN_USER>@<GUEST_IP> 'hostname; ip addr; ip route; df -h'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'vm-agent-ping <NEW_VMID>'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'vm-shell <NEW_VMID> -- hostname'
```

Bound waits locally, check cloud-init exit status, required DNS/connectivity and
service health. If SSH cannot reach the guest from here, state the missing
verification; agent ping is not proof of SSH access. Check backup/monitoring
coverage as for LXC. Do not enable onboot implicitly.

## 3. LXC shared-media variant

Use an existing host media path, verified mounted and containing expected data.
Never create an empty replacement when its underlying share is missing. Inspect
host ownership/mount options and guest service UID plus supplementary groups.
For an unprivileged container, read its actual UID/GID mappings: host UID 1000 is
not automatically guest UID 1000. Do not add custom mappings casually, change
shared ownership or make the container privileged to bypass access failures.

Choose a free mount slot on the **new target container**, while stopped:

```bash
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'lxc-config <NEW_VMID>'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'host-exec -- pct set <NEW_VMID> --mp<FREE_SLOT> <EXISTING_HOST_MEDIA_PATH>,mp=<GUEST_MEDIA_PATH>,ro=1,backup=0'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'lxc-config <NEW_VMID>'
```

Read-only is explicit (`ro=1`), not inferred from Unix permission checks. After
approved startup, use guest tools available on that OS to test as the service
user (Debian example; replace the sample path before execution):

```bash
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" 'lxc-shell <NEW_VMID> -- id <SERVICE_USER>'
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-shell <NEW_VMID> -- runuser -u <SERVICE_USER> -- ls -ld '<GUEST_MEDIA_PATH>'"
ssh "$PROXMOX_SSH_USER@$PROXMOX_HOST" "lxc-shell <NEW_VMID> -- runuser -u <SERVICE_USER> -- test -r '<GUEST_MEDIA_PATH>/<KNOWN_FILE>'"
```

Verify mount flags and actual application access, not root's `test -r` alone.
No `chmod 777`, recursive chown or unapproved write probe. Grant write access only
for a concrete approved need, with appropriate identity and share-side rights.
Bind-mounted host data is **not included in container backups**; identify its
separate protection rather than treating `backup=0` as sufficient protection.
