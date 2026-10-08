#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "ERROR: command failed at line %s (exit %s): %s\n" "$LINENO" "$status" "$BASH_COMMAND" >&2; exit "$status"' ERR

pass_count=0
fail_count=0

pass() {
    printf '[ OK ] %s\n' "$1"
    ((pass_count += 1))
}
    fail_count=0
    warning_count=0
    python_available=false
    ovs_installed=false

    pass() {
        printf '[PASS] %s\n' "$1"
    }

    warn() {
        printf '[WARN] %s\n' "$1"
        ((warning_count += 1))
    }

    fail() {
        printf '[FAIL] %s\n' "$1"
        ((fail_count += 1))
    }

    check_optional_command() {
        local label=$1
        local command_name=$2

        if command -v "$command_name" >/dev/null 2>&1; then
            pass "$label is available ($(command -v "$command_name"))"
        else
            warn "$label is not installed or not on PATH (optional)"
        fi
    }

    printf 'Checking readiness for the isolated Mininet experiment...\n\n'

    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        source /etc/os-release
        if [[ "${ID:-}" == ubuntu ]]; then
            IFS=. read -r os_major os_minor _ <<< "${VERSION_ID:-}"
            if [[ "${os_major:-}" =~ ^[0-9]+$ && "${os_minor:-}" =~ ^[0-9]+$ ]] && \
                ((os_major > 22 || (os_major == 22 && os_minor >= 4))); then
                pass "Operating system: ${PRETTY_NAME:-Ubuntu ${VERSION_ID}}"
            else
                fail "Operating system: Ubuntu 22.04 or later is required (detected ${PRETTY_NAME:-unknown})"
            fi
        else
            fail "Operating system: Ubuntu 22.04 or later is required (detected ${PRETTY_NAME:-unknown})"
        fi
    else
        fail 'Operating system: cannot read /etc/os-release'
    fi

    if command -v uname >/dev/null 2>&1 && [[ "$(uname -s)" == Linux ]]; then
        pass "Linux kernel: $(uname -r)"
    else
        fail 'Linux kernel: this experiment requires a Linux kernel'
    fi

    if command -v python3 >/dev/null 2>&1; then
        if python3 -c 'import sys; raise SystemExit(0 if sys.version_info >= (3, 10) else 1)'; then
            python_available=true
            pass "Python 3: $(python3 --version 2>&1)"
        else
            fail 'Python 3: version 3.10 or later is required'
        fi
    else
        fail 'Python 3: python3 is not installed or not on PATH'
    fi

    if [[ "$python_available" == true ]]; then
        if python3 -c 'import venv' >/dev/null 2>&1; then
            pass 'Python venv module is available'
        else
            warn 'Python venv module is unavailable (optional for running system Python)'
        fi
    else
        warn 'Python venv module cannot be checked without Python 3'
    fi

    if command -v mn >/dev/null 2>&1 && [[ "$python_available" == true ]] && \
        python3 -c 'import mininet' >/dev/null 2>&1; then
        pass "Mininet is available ($(command -v mn); Python package imports)"
    else
        fail 'Mininet is unavailable (requires the mn command and importable Python package)'
    fi

    if command -v ovs-vsctl >/dev/null 2>&1; then
        ovs_installed=true
        pass "Open vSwitch is installed ($(command -v ovs-vsctl))"
    else
        fail 'Open vSwitch is not installed or ovs-vsctl is not on PATH'
    fi

    if [[ "$ovs_installed" == true ]]; then
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
        fail 'OVS service status cannot be checked because Open vSwitch is not installed'
        fail 'ovs-vsctl responsiveness cannot be checked because ovs-vsctl is unavailable'
    fi

    if command -v hping3 >/dev/null 2>&1; then
        pass "hping3 is available ($(command -v hping3))"
    else
        fail 'hping3 is not installed or not on PATH'
    fi

    check_optional_command 'Wireshark GUI' wireshark
    check_optional_command 'tshark' tshark

    if command -v curl >/dev/null 2>&1; then
        pass "curl is available ($(command -v curl))"
    else
        fail 'curl is not installed or not on PATH'
    fi

    if command -v ip >/dev/null 2>&1; then
        pass "iproute2 is available ($(command -v ip))"
    else
        fail 'iproute2 is unavailable (the ip command is not on PATH)'
    fi

    if command -v iptables >/dev/null 2>&1; then
        pass "iptables is available ($(command -v iptables))"
    else
        fail 'iptables is not installed or not on PATH'
    fi

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
        if [[ "$python_available" == true ]] && \
            python3 -c "import ${module_name}" >/dev/null 2>&1; then
            pass "Required Python module ${package_name} imports successfully"
        else
            fail "Required Python module ${package_name} is unavailable"
        fi
    done

    printf '\n'
    if ((fail_count > 0)); then
        printf 'ENVIRONMENT STATUS: NOT READY\n'
        printf '%s mandatory check(s) failed; %s optional check(s) warned.\n' "$fail_count" "$warning_count"
        exit 1
    fi

    printf 'ENVIRONMENT STATUS: READY\n'
    printf 'All mandatory checks passed; %s optional check(s) warned.\n' "$warning_count"