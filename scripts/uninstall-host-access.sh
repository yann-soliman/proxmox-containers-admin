#!/usr/bin/env bash
set -euo pipefail
umask 077
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
exec /usr/bin/python3 -I "$root/host_access/install.py" uninstall "$@"
