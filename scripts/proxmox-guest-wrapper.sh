#!/usr/bin/env bash
set -euo pipefail
umask 077

LOG_TAG="proxmox-guest-wrapper"

log() {
  logger -t "$LOG_TAG" -- "$*"
}

fail() {
  echo "ERROR: $*" >&2
  log "deny: $* | cmd=${SSH_ORIGINAL_COMMAND:-<empty>}"
  exit 1
}

require_vmid() {
  [[ "${1:-}" =~ ^[0-9]+$ ]] || fail "invalid vmid"
}

parse_vmid_only() {
  local prefix="$1"
  local usage="$2"
  local rest
  rest=${cmd#${prefix} }
  [[ "$rest" != "$cmd" ]] || fail "$usage"
  [[ "$rest" =~ ^[0-9]+$ ]] || fail "$usage"
  require_vmid "$rest"
  PARSED_VMID="$rest"
}

parse_vmid_and_double_dash_tail() {
  local prefix="$1"
  local rest vmid tail
  rest=${cmd#${prefix} }
  [[ "$rest" != "$cmd" ]] || fail "usage: ${prefix} <vmid> -- <guest shell command>"
  vmid=${rest%% *}
  tail=${rest#* }
  [[ -n "$vmid" && "$tail" != "$rest" ]] || fail "usage: ${prefix} <vmid> -- <guest shell command>"
  require_vmid "$vmid"
  [[ "$tail" == --\ * ]] || fail "usage: ${prefix} <vmid> -- <guest shell command>"
  PARSED_VMID="$vmid"
  PARSED_TAIL=${tail#-- }
  [[ -n "$PARSED_TAIL" ]] || fail "usage: ${prefix} <vmid> -- <guest shell command>"
}

parse_vmid_and_path() {
  local prefix="$1"
  local usage="$2"
  local rest vmid tail
  rest=${cmd#${prefix} }
  [[ "$rest" != "$cmd" ]] || fail "$usage"
  vmid=${rest%% *}
  tail=${rest#* }
  [[ -n "$vmid" && "$tail" != "$rest" ]] || fail "$usage"
  require_vmid "$vmid"
  [[ -n "$tail" ]] || fail "$usage"
  PARSED_VMID="$vmid"
  PARSED_TAIL="$tail"
}

cmd="${SSH_ORIGINAL_COMMAND:-}"
[[ -n "$cmd" ]] || fail "empty command"

tmpfile=""
cleanup() {
  if [[ -n "$tmpfile" && -f "$tmpfile" ]]; then
    rm -f -- "$tmpfile"
  fi
}
trap cleanup EXIT

# Keep large transfer copies off RAM-backed /tmp and inside root-only storage.
transfer_temp() {
  local base="/var/lib/proxmox-guest-wrapper" directory
  for directory in "$base" "$base/tmp"; do
    [[ ! -L "$directory" ]] || fail "unsafe transfer directory"
    if [[ ! -e "$directory" ]]; then
      mkdir -m 700 -- "$directory"
    fi
    [[ -d "$directory" && "$(stat -c '%u:%a' -- "$directory")" == "0:700" ]] || fail "transfer directory must be private and root-owned"
  done
  case "$(stat -f -c '%T' -- "$base/tmp")" in
    tmpfs|ramfs) fail "transfer staging must be disk-backed" ;;
  esac
  mktemp "$base/tmp/proxmox-guest-wrapper.$1.XXXXXX"
}

run_transfer() {
  local output status
  # PVE may print transfer errors but still return zero. These commands are
  # silent on success; fail closed on diagnostics instead of returning bad data.
  if output=$(/usr/sbin/pct "$@" 2>&1); then
    if [[ -n "$output" ]]; then
      printf '%s\n' "$output" >&2
      return 1
    fi
  else
    status=$?
    [[ -z "$output" ]] || printf '%s\n' "$output" >&2
    return "$status"
  fi
}

run_qm_guest_exec() {
  local output qm_exitcode guest_exitcode

  if output=$(/usr/sbin/qm guest exec "$@"); then
    qm_exitcode=0
  else
    qm_exitcode=$?
  fi

  printf '%s\n' "$output"
  (( qm_exitcode == 0 )) || return "$qm_exitcode"

  if [[ "$output" =~ \"exitcode\"[[:space:]]*:[[:space:]]*([0-9]+) ]]; then
    guest_exitcode=${BASH_REMATCH[1]}
    (( guest_exitcode <= 255 )) || fail "guest exit code out of range: $guest_exitcode"
    return "$guest_exitcode"
  fi

  fail "qm guest exec response did not contain an exit code"
}

# Host commands never pass through the legacy command logger: scripts may
# contain secrets. Optional extension is a fixed, root-installed launcher.
case "$cmd" in
  host-*)
    if [[ -x /usr/local/libexec/proxmox-host-access-agent ]]; then
      exec /usr/local/libexec/proxmox-host-access-agent
    fi
    printf '%s\n' 'ERROR: host access extension unavailable' >&2
    exit 1
    ;;
esac

case "$cmd" in
  list-lxc)
    log "allow: $cmd"
    exec /usr/sbin/pct list
    ;;

  list-vm)
    log "allow: $cmd"
    exec /usr/sbin/qm list
    ;;

  lxc-status\ *)
    set -- $cmd
    [[ $# -eq 2 ]] || fail "usage: lxc-status <vmid>"
    require_vmid "$2"
    log "allow: $cmd"
    exec /usr/sbin/pct status "$2"
    ;;

  vm-status\ *)
    set -- $cmd
    [[ $# -eq 2 ]] || fail "usage: vm-status <vmid>"
    require_vmid "$2"
    log "allow: $cmd"
    exec /usr/sbin/qm status "$2"
    ;;

  lxc-config\ *)
    set -- $cmd
    [[ $# -eq 2 ]] || fail "usage: lxc-config <vmid>"
    require_vmid "$2"
    log "allow: $cmd"
    exec /usr/sbin/pct config "$2"
    ;;

  vm-config\ *)
    set -- $cmd
    [[ $# -eq 2 ]] || fail "usage: vm-config <vmid>"
    require_vmid "$2"
    log "allow: $cmd"
    exec /usr/sbin/qm config "$2"
    ;;

  lxc-shell\ *)
    parse_vmid_and_double_dash_tail "lxc-shell"
    log "allow: $cmd"
    exec /usr/sbin/pct exec "$PARSED_VMID" -- sh -c "$PARSED_TAIL"
    ;;

  vm-shell\ *)
    parse_vmid_and_double_dash_tail "vm-shell"
    log "allow: $cmd"
    run_qm_guest_exec "$PARSED_VMID" -- sh -c "$PARSED_TAIL"
    ;;

  lxc-shell-stdin\ *)
    parse_vmid_only "lxc-shell-stdin" "usage: lxc-shell-stdin <vmid>"
    log "allow: $cmd"
    exec /usr/sbin/pct exec "$PARSED_VMID" -- sh -s
    ;;

  vm-shell-stdin\ *)
    parse_vmid_only "vm-shell-stdin" "usage: vm-shell-stdin <vmid>"
    log "allow: $cmd"
    run_qm_guest_exec "$PARSED_VMID" --pass-stdin 1 -- sh -s
    ;;

  lxc-pull\ *)
    parse_vmid_and_path "lxc-pull" "usage: lxc-pull <vmid> <guest-path>"
    tmpfile=$(transfer_temp pull)
    log "allow: $cmd"
    run_transfer pull "$PARSED_VMID" "$PARSED_TAIL" "$tmpfile"
    cat -- "$tmpfile"
    ;;

  lxc-push\ *)
    parse_vmid_and_path "lxc-push" "usage: lxc-push <vmid> <guest-path>"
    tmpfile=$(transfer_temp push)
    cat > "$tmpfile"
    log "allow: $cmd"
    run_transfer push "$PARSED_VMID" "$tmpfile" "$PARSED_TAIL"
    ;;

  vm-agent-ping\ *)
    set -- $cmd
    [[ $# -eq 2 ]] || fail "usage: vm-agent-ping <vmid>"
    require_vmid "$2"
    log "allow: $cmd"
    exec /usr/sbin/qm agent "$2" ping
    ;;

  lxc-power\ *)
    set -- $cmd
    [[ $# -eq 3 ]] || fail "usage: lxc-power <vmid> <start|stop|shutdown|reboot>"
    require_vmid "$2"
    case "$3" in start|stop|shutdown|reboot) ;; *) fail "invalid lxc power verb" ;; esac
    log "allow: $cmd"
    exec /usr/sbin/pct "$3" "$2"
    ;;

  vm-power\ *)
    set -- $cmd
    [[ $# -eq 3 ]] || fail "usage: vm-power <vmid> <start|stop|shutdown|reboot|reset>"
    require_vmid "$2"
    case "$3" in start|stop|shutdown|reboot|reset) ;; *) fail "invalid vm power verb" ;; esac
    log "allow: $cmd"
    exec /usr/sbin/qm "$3" "$2"
    ;;

  *)
    fail "unknown action"
    ;;
esac
