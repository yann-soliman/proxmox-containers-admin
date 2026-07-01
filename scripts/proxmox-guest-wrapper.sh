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
    exec /usr/sbin/pct exec "$PARSED_VMID" -- sh -lc "$PARSED_TAIL"
    ;;

  vm-shell\ *)
    parse_vmid_and_double_dash_tail "vm-shell"
    log "allow: $cmd"
    exec /usr/sbin/qm guest exec "$PARSED_VMID" -- sh -lc "$PARSED_TAIL"
    ;;

  lxc-pull\ *)
    parse_vmid_and_path "lxc-pull" "usage: lxc-pull <vmid> <guest-path>"
    tmpfile=$(mktemp /tmp/proxmox-guest-wrapper.pull.XXXXXX)
    log "allow: $cmd"
    /usr/sbin/pct pull "$PARSED_VMID" "$PARSED_TAIL" "$tmpfile" >/dev/null
    exec cat -- "$tmpfile"
    ;;

  lxc-push\ *)
    parse_vmid_and_path "lxc-push" "usage: lxc-push <vmid> <guest-path>"
    tmpfile=$(mktemp /tmp/proxmox-guest-wrapper.push.XXXXXX)
    cat > "$tmpfile"
    log "allow: $cmd"
    exec /usr/sbin/pct push "$PARSED_VMID" "$tmpfile" "$PARSED_TAIL"
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
