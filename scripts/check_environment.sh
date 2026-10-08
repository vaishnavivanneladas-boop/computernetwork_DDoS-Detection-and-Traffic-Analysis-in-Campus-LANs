#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "ERROR: environment check failed at line %s (exit %s): %s\n" "$LINENO" "$status" "$BASH_COMMAND" >&2; exit "$status"' ERR

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
failure_count=0
warning_count=0
python_bin=$(command -v python3 || true)

pass() {
    printf '[PASS] %s\n' "$1"
}

warn() {
    printf '[WARN] %s\n' "$1"
    ((warning_count += 1))
}

fail() {
    printf '[FAIL] %s\n' "$1"
    ((failure_count += 1))
}

check_optional_command() {
    local label=$1
    local command_name=$2
    if command -v "$command_name" >/dev/null 2>&1; then
        pass "$label is available ($(command -v "$command_name"))"
    else
        warn "$label is unavailable (optional)"
    fi
}

printf 'Checking readiness for the isolated Mininet experiment...\n\n'

if [[ -r /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    IFS=. read -r os_major os_minor _ <<< "${VERSION_ID:-}"
    if [[ "${ID:-}" == ubuntu && "${os_major:-}" =~ ^[0-9]+$ && "${os_minor:-}" =~ ^[0-9]+$ ]] && \
        ((os_major > 22 || (os_major == 22 && os_minor >= 4))); then
        pass "Operating system: ${PRETTY_NAME:-Ubuntu ${VERSION_ID}}"
    else
        fail "Operating system: Ubuntu 22.04 or later required (detected ${PRETTY_NAME:-unknown})"
    fi
else
    fail 'Operating system: cannot read /etc/os-release'
fi

if command -v uname >/dev/null 2>&1 && [[ "$(uname -s)" == Linux ]]; then
    pass "Linux kernel: $(uname -r)"
else
    fail 'Linux kernel: Linux is required'
fi

if [[ -x "$project_root/.venv/bin/python" ]]; then
    python_bin="$project_root/.venv/bin/python"
fi
if [[ -n "$python_bin" ]] && "$python_bin" -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)' 2>/dev/null; then
    pass "Python 3: $($python_bin --version 2>&1) via $python_bin"
    if "$python_bin" -c 'import venv' >/dev/null 2>&1; then
        pass 'Python venv module is available'
    else
        warn 'Python venv module is unavailable'
    fi
else
    python_bin=
    fail 'Python 3.10 or newer is unavailable'
fi

if command -v mn >/dev/null 2>&1 && [[ -n "$python_bin" ]] && "$python_bin" -c 'import mininet' >/dev/null 2>&1; then
    pass "Mininet is available ($(command -v mn); Python package imports)"
else
    fail 'Mininet is unavailable (requires mn and its Python package)'
fi

if command -v ovs-vsctl >/dev/null 2>&1; then
    pass "Open vSwitch is installed ($(command -v ovs-vsctl))"
    if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet openvswitch-switch; then
        pass 'Open vSwitch service is running'
    else
        fail 'Open vSwitch is installed but not running.'
        printf '       Start it with: sudo systemctl start openvswitch-switch\n'
    fi
    if command -v timeout >/dev/null 2>&1 && timeout 5s ovs-vsctl show >/dev/null 2>&1; then
        pass 'ovs-vsctl responds to the local OVS database'
    elif ! command -v timeout >/dev/null 2>&1 && ovs-vsctl show >/dev/null 2>&1; then
        pass 'ovs-vsctl responds to the local OVS database'
    else
        fail 'ovs-vsctl is installed but did not respond to the local OVS database'
    fi
else
    fail 'Open vSwitch is unavailable (ovs-vsctl is not installed)'
    fail 'OVS service status cannot be checked because Open vSwitch is not installed'
    fail 'ovs-vsctl responsiveness cannot be checked because ovs-vsctl is unavailable'
fi

for required_command in hping3 curl ip iptables; do
    if command -v "$required_command" >/dev/null 2>&1; then
        pass "$required_command is available ($(command -v "$required_command"))"
    else
        fail "$required_command is unavailable"
    fi
done

check_optional_command 'Wireshark GUI' wireshark
check_optional_command 'tshark' tshark
check_optional_command 'sar' sar
check_optional_command 'mpstat' mpstat
check_optional_command 'tcpdump' tcpdump

python_modules=(
    'flask:Flask'
    'yaml:PyYAML'
    'matplotlib:matplotlib'
    'pandas:pandas'
    'psutil:psutil'
    'scapy:scapy'
)
for module_entry in "${python_modules[@]}"; do
    module_name=${module_entry%%:*}
    package_name=${module_entry#*:}
    if [[ -n "$python_bin" ]] && "$python_bin" -c "import ${module_name}" >/dev/null 2>&1; then
        pass "Required Python module ${package_name} imports using $python_bin"
    else
        fail "Required Python module ${package_name} is unavailable"
    fi
done

printf '\n'
if ((failure_count > 0)); then
    printf 'ENVIRONMENT STATUS: NOT READY\n'
    printf '%s mandatory check(s) failed; %s optional check(s) warned.\n' "$failure_count" "$warning_count"
    exit 1
fi
printf 'ENVIRONMENT STATUS: READY\n'
printf 'All mandatory checks passed; %s optional check(s) warned.\n' "$warning_count"