#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "ERROR: command failed at line %s (exit %s): %s\n" "$LINENO" "$status" "$BASH_COMMAND" >&2; exit "$status"' ERR

usage() {
    cat <<'EOF'
Usage: cleanup.sh [--mininet-global-cleanup]

Without an option, report that no project experiment runtime is implemented
yet and make no changes. --mininet-global-cleanup runs `mn -c`, which removes
Mininet state for the entire host, including state created by other projects.
EOF
}

if (($# == 0)); then
    printf 'No project runtime manager is implemented yet; no state was changed.\n'
    printf 'Use --mininet-global-cleanup only if you intend host-wide Mininet cleanup.\n'
    exit 0
fi

if (($# != 1)) || [[ "$1" != --mininet-global-cleanup ]]; then
    usage >&2
    exit 2
fi

if ! command -v mn >/dev/null 2>&1; then
    printf 'ERROR: mn is not installed or not on PATH.\n' >&2
    exit 1
fi

printf 'WARNING: this runs host-wide `mn -c` and may disrupt other Mininet labs.\n'
if ((EUID == 0)); then
    mn -c
elif command -v sudo >/dev/null 2>&1; then
    sudo mn -c
else
    printf 'ERROR: root privileges are required and sudo is unavailable.\n' >&2
    exit 1
fi

printf 'Host-wide Mininet cleanup completed.\n'