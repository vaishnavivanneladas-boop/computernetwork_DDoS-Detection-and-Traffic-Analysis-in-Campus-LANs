#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "ERROR: command failed at line %s (exit %s): %s\n" "$LINENO" "$status" "$BASH_COMMAND" >&2; exit "$status"' ERR

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_dir=$(cd -- "$script_dir/.." && pwd)
fail_count=0

printf 'DDoS Campus Lab host health check\n'
if "$script_dir/check_environment.sh"; then
    printf '\n[ OK ] Required host tools are present\n'
else
    printf '\n[WARN] One or more host prerequisites are missing\n'
    ((fail_count += 1))
fi

for data_dir in captures logs results; do
    if [[ -d "$project_dir/$data_dir" && -w "$project_dir/$data_dir" ]]; then
        printf '[ OK ] %s/ exists and is writable\n' "$data_dir"
    else
        printf '[FAIL] %s/ is missing or not writable\n' "$data_dir"
        ((fail_count += 1))
    fi
done

if command -v ovs-vsctl >/dev/null 2>&1; then
    if ovs-vsctl show >/dev/null 2>&1; then
        printf '[ OK ] Open vSwitch responds to ovs-vsctl\n'
    elif ((EUID != 0)) && command -v sudo >/dev/null 2>&1 && \
        sudo -n ovs-vsctl show >/dev/null 2>&1; then
        printf '[ OK ] Open vSwitch responds with non-interactive sudo\n'
    else
        printf '[FAIL] Open vSwitch is not responding or access is denied\n'
        ((fail_count += 1))
    fi
else
    printf '[FAIL] ovs-vsctl is not installed or not on PATH\n'
    ((fail_count += 1))
fi

if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet openvswitch-switch; then
    printf '[ OK ] openvswitch-switch service is active\n'
elif command -v systemctl >/dev/null 2>&1; then
    printf '[WARN] openvswitch-switch service is not active (or systemd is unavailable)\n'
    ((fail_count += 1))
else
    printf '[WARN] systemctl unavailable; service state was not checked\n'
    ((fail_count += 1))
fi

printf '\n'
if ((fail_count > 0)); then
    printf 'Health check found %s issue(s). No topology was started.\n' "$fail_count"
    exit 1
fi

printf 'Host checks passed. This does not verify that a Mininet topology is running.\n'