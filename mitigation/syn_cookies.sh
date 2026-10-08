#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "ERROR: SYN-cookie operation failed at line %s (exit %s): %s\n" "$LINENO" "$status" "$BASH_COMMAND" >&2; exit "$status"' ERR

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
config_path="$project_root/config/config.yaml"
experiment_id=
results_root="$project_root/results"
previous_value=
state_file=
log_file=
change_started=false
keep_enabled=false

rollback_partial_change() {
    exit_status=$?
    trap - EXIT INT TERM HUP
    set +e
    if [[ "$change_started" == true && "$keep_enabled" != true && "$previous_value" =~ ^[01]$ ]]; then
        rollback_value=$(sysctl -w "net.ipv4.tcp_syncookies=$previous_value" 2>&1)
        rollback_status=$?
        if [[ -n "$log_file" ]]; then
            printf 'rollback_attempted=true\nrollback_status=%s\nrollback_output=%s\n' \
                "$rollback_status" "$rollback_value" >>"$log_file"
        fi
        if ((rollback_status == 0)) && [[ -n "$state_file" && -f "$state_file" ]]; then
            python3 - "$state_file" "$previous_value" <<'PY'
import json
import os
import sys
import tempfile
from pathlib import Path
path = Path(sys.argv[1])
state = json.loads(path.read_text(encoding="utf-8"))
state["applied"] = False
state["restored_value"] = int(sys.argv[2])
fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".syn-cookie-rollback-")
try:
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(state, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
        fi
    fi
    exit "$exit_status"
}
trap rollback_partial_change EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

usage() {
    printf '%s\n' 'Usage: syn_cookies.sh --enable --experiment-id ID [--results-root PATH]'
}

while (($#)); do
    case "$1" in
        --enable) enable_requested=true; shift ;;
        --experiment-id) (($# >= 2)) || { usage >&2; exit 2; }; experiment_id=$2; shift 2 ;;
        --results-root) (($# >= 2)) || { usage >&2; exit 2; }; results_root=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'ERROR: unknown option %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ "${enable_requested:-false}" == true ]] || { usage >&2; exit 2; }
[[ "$experiment_id" =~ ^EXP_[0-9]{8}_[0-9]{6}(_[0-9]{2,})?$ ]] || { printf 'ERROR: valid experiment ID required.\n' >&2; exit 2; }
if ((EUID != 0)); then
    printf 'ERROR: SYN Cookies must be changed as root inside the Mininet DMZ server host.\n' >&2
    exit 1
fi
if [[ ! -r /proc/self/ns/net || ! -r /proc/1/ns/net ]] || \
    [[ "$(stat -Lc '%i' /proc/self/ns/net)" == "$(stat -Lc '%i' /proc/1/ns/net)" ]]; then
    printf 'ERROR: refusing to modify SYN Cookies outside a Mininet network namespace.\n' >&2
    exit 1
fi

readarray -t server_settings < <(python3 - "$config_path" "$experiment_id" "$results_root" <<'PY'
import json
import sys
from pathlib import Path
import yaml
config_path, experiment_id, results_root = sys.argv[1:]
root = Path(results_root).resolve()
experiment_dir = root / experiment_id
with Path(config_path).open(encoding="utf-8") as stream:
    config = yaml.safe_load(stream)
topology = config["topology"]
hosts = topology["hosts"]
web = topology["hosts"]["web_server"]
with (experiment_dir / "logs" / "experiment.json").open(encoding="utf-8") as stream:
    manifest = json.load(stream)
if manifest.get("experiment_id") != experiment_id:
    raise SystemExit("experiment manifest does not match")
print(web["node"])
print(web["ip"])
print(topology["vlans"][int(web["vlan"])]["subnet"])
print(manifest["scenario"])
print(topology["nodes"]["core_switch"])
print(int(web["vlan"]))
print(",".join([host["node"] + "-eth0" for host in hosts.values()] + [topology["nodes"]["campus_router"] + "-eth0"]))
PY
) || { printf 'ERROR: cannot verify the configured DMZ host and experiment manifest.\n' >&2; exit 1; }
if ((${#server_settings[@]} != 7)); then
    printf 'ERROR: incomplete DMZ configuration.\n' >&2
    exit 1
fi
server_host=${server_settings[0]}
server_ip=${server_settings[1]}
server_network=${server_settings[2]}
scenario=${server_settings[3]}
core_bridge=${server_settings[4]}
server_vlan=${server_settings[5]}
expected_bridge_ports=${server_settings[6]}
if [[ "$server_ip" != "10.10.10.100" || "$server_network" != "10.10.10.0/24" ]]; then
    printf 'ERROR: configured DMZ endpoint is not the approved Mininet server.\n' >&2
    exit 1
fi
if ! ip -o -4 address show | awk -v ip="$server_ip/24" -v prefix="$server_host-eth" '$4 == ip && index($2, prefix) == 1 { found++ } END { exit(found == 1 ? 0 : 1) }'; then
    printf 'ERROR: this namespace is not the configured Mininet DMZ server (%s).\n' "$server_ip" >&2
    exit 1
fi
command -v ovs-vsctl >/dev/null 2>&1 || { printf 'ERROR: ovs-vsctl is required to verify the Mininet DMZ host.\n' >&2; exit 1; }
bridge_ports=$(ovs-vsctl --timeout=3 list-ports "$core_bridge") || { printf 'ERROR: cannot inspect Mininet OVS core.\n' >&2; exit 1; }
if ! python3 - "$bridge_ports" "$expected_bridge_ports" "$core_bridge" <<'PY'
import sys
actual = set(sys.argv[1].splitlines()) - {sys.argv[3]}
expected = set(sys.argv[2].split(","))
if actual != expected:
    print(f"unexpected={sorted(actual - expected)} missing={sorted(expected - actual)}", file=sys.stderr)
    raise SystemExit(1)
PY
then
    printf 'ERROR: OVS bridge ports do not match the configured Mininet topology.\n' >&2
    exit 1
fi
server_port="$server_host-eth0"
server_port_vlan=$(ovs-vsctl --timeout=3 get Port "$server_port" tag | tr -d '[]"[:space:]')
if [[ "$server_port_vlan" != "$server_vlan" ]]; then
    printf 'ERROR: DMZ OVS port VLAN %s does not match configured VLAN %s.\n' "$server_port_vlan" "$server_vlan" >&2
    exit 1
fi

experiment_dir=$(realpath -m -- "$results_root/$experiment_id")
results_root=$(realpath -m -- "$results_root")
if [[ "$(dirname -- "$experiment_dir")" != "$results_root" || ! -d "$experiment_dir/logs" ]]; then
    printf 'ERROR: experiment result directory is missing or outside results root.\n' >&2
    exit 1
fi
state_file="$experiment_dir/logs/syn_cookies_state.json"
if [[ -e "$state_file" ]]; then
    printf 'ERROR: SYN Cookie state already exists for this experiment; refusing to overwrite.\n' >&2
    exit 1
fi
previous_value=$(sysctl -n net.ipv4.tcp_syncookies)
if [[ "$previous_value" != 0 && "$previous_value" != 1 ]]; then
    printf 'ERROR: unexpected current SYN Cookie value: %s\n' "$previous_value" >&2
    exit 1
fi
backlog_values=()
for setting in net.ipv4.tcp_max_syn_backlog net.ipv4.tcp_synack_retries net.ipv4.tcp_syn_retries net.core.somaxconn; do
    value=$(sysctl -n "$setting" 2>/dev/null || printf 'unavailable')
    backlog_values+=("$setting=$value")
done
current_timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
log_file="$experiment_dir/logs/syn_cookies_${current_timestamp//:/-}.log"
printf 'timestamp=%s\nexperiment_id=%s\nscenario=%s\ntarget_host=%s\ntarget_ip=%s\nsetting=net.ipv4.tcp_syncookies\nprevious_value=%s\nrequested_value=1\n' \
    "$current_timestamp" "$experiment_id" "$scenario" "$server_host" "$server_ip" "$previous_value" > "$log_file"
printf 'observed_tcp_settings=%s\n' "${backlog_values[*]}" >>"$log_file"
python3 - "$state_file" "$experiment_id" "$scenario" "$server_host" "$server_ip" "$previous_value" <<'PY'
import json
import sys
from pathlib import Path
path, experiment_id, scenario, host, address, previous = sys.argv[1:]
state = {
    "experiment_id": experiment_id,
    "scenario": scenario,
    "target_host": host,
    "target_ip": address,
    "setting": "net.ipv4.tcp_syncookies",
    "previous_value": int(previous),
    "new_value": 1,
    "applied": False,
}
with Path(path).open("x", encoding="utf-8") as stream:
    json.dump(state, stream, indent=2, sort_keys=True)
    stream.write("\n")
PY

printf '[MITIGATION] %s current=%s new=1 on %s (%s)\n' net.ipv4.tcp_syncookies "$previous_value" "$server_host" "$server_ip"
printf '[OBSERVE] TCP backlog/retry settings (unchanged): %s\n' "${backlog_values[*]}"
change_started=true
if ! sysctl -w net.ipv4.tcp_syncookies=1 >>"$log_file" 2>&1; then
    printf 'ERROR: failed to enable SYN Cookies; previous value %s remains recorded for rollback.\n' "$previous_value" >&2
    exit 1
fi
new_value=$(sysctl -n net.ipv4.tcp_syncookies)
if [[ "$new_value" != 1 ]]; then
    sysctl -w "net.ipv4.tcp_syncookies=$previous_value" >>"$log_file" 2>&1 || true
    printf 'ERROR: SYN Cookie verification failed (observed %s); attempted rollback.\n' "$new_value" >&2
    exit 1
fi
python3 - "$state_file" <<'PY'
import json
import os
import sys
import tempfile
from pathlib import Path
path = Path(sys.argv[1])
state = json.loads(path.read_text(encoding="utf-8"))
state["applied"] = True
state["applied_at"] = __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()
fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".syn-cookies-")
try:
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(state, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
finally:
    if os.path.exists(temporary):
        os.unlink(temporary)
PY
printf 'new_value=%s\nverified=true\n' "$new_value" >>"$log_file"
keep_enabled=true
printf '[PASS] SYN Cookies enabled and verified: previous=%s new=%s; state=%s\n' "$previous_value" "$new_value" "$state_file"
