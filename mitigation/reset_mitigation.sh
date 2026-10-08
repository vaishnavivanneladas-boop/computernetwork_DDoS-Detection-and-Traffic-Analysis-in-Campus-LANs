#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "ERROR: mitigation reset failed at line %s (exit %s): %s\n" "$LINENO" "$status" "$BASH_COMMAND" >&2; exit "$status"' ERR

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
config_path="$project_root/config/config.yaml"
experiment_id=
results_root="$project_root/results"

usage() {
    printf '%s\n' 'Usage: reset_mitigation.sh --experiment-id ID [--results-root PATH]'
}

while (($#)); do
    case "$1" in
        --experiment-id) (($# >= 2)) || { usage >&2; exit 2; }; experiment_id=$2; shift 2 ;;
        --results-root) (($# >= 2)) || { usage >&2; exit 2; }; results_root=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'ERROR: unknown option %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done
[[ "$experiment_id" =~ ^EXP_[0-9]{8}_[0-9]{6}(_[0-9]{2,})?$ ]] || { printf 'ERROR: valid experiment ID required.\n' >&2; exit 2; }
if ((EUID != 0)); then
    printf 'ERROR: mitigation reset requires root inside the Mininet DMZ server host.\n' >&2
    exit 1
fi
current_namespace=$(stat -Lc '%i' /proc/self/ns/net) || { printf 'ERROR: cannot inspect network namespace.\n' >&2; exit 1; }
host_namespace=$(stat -Lc '%i' /proc/1/ns/net) || { printf 'ERROR: cannot inspect host network namespace.\n' >&2; exit 1; }
if [[ "$current_namespace" == "$host_namespace" ]]; then
    printf 'ERROR: refusing to modify SYN Cookies on the physical host.\n' >&2
    exit 1
fi

experiment_dir=$(realpath -m -- "$results_root/$experiment_id")
results_root=$(realpath -m -- "$results_root")
if [[ "$(dirname -- "$experiment_dir")" != "$results_root" || ! -f "$experiment_dir/logs/syn_cookies_state.json" ]]; then
    printf 'ERROR: saved SYN Cookie state is missing; cannot safely restore.\n' >&2
    exit 1
fi
state_file="$experiment_dir/logs/syn_cookies_state.json"
readarray -t state_values < <(python3 - "$state_file" "$experiment_id" "$config_path" <<'PY'
import json
import sys
from pathlib import Path
import yaml
state_path, experiment_id, config_path = sys.argv[1:]
state = json.loads(Path(state_path).read_text(encoding="utf-8"))
config = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
web = config["topology"]["hosts"]["web_server"]
if state.get("experiment_id") != experiment_id or state.get("target_ip") != web["ip"] or state.get("target_host") != web["node"]:
    raise SystemExit("saved state does not target the configured Mininet DMZ host")
print(state["target_host"])
print(state["target_ip"])
print(state["previous_value"])
print(state["new_value"])
print(state.get("scenario", "unknown"))
print(topology["nodes"]["core_switch"])
print(int(web["vlan"]))
print(",".join([host["node"] + "-eth0" for host in topology["hosts"].values()] + [topology["nodes"]["campus_router"] + "-eth0"]))
PY
) || { printf 'ERROR: saved mitigation state is invalid or belongs to another host.\n' >&2; exit 1; }
if ((${#state_values[@]} != 8)); then
    printf 'ERROR: incomplete saved mitigation state.\n' >&2
    exit 1
fi
server_host=${state_values[0]}
server_ip=${state_values[1]}
previous_value=${state_values[2]}
new_value=${state_values[3]}
scenario=${state_values[4]}
core_bridge=${state_values[5]}
server_vlan=${state_values[6]}
expected_bridge_ports=${state_values[7]}
if [[ "$previous_value" != 0 && "$previous_value" != 1 ]] || [[ "$new_value" != 1 ]]; then
    printf 'ERROR: saved SYN Cookie values are invalid.\n' >&2
    exit 1
fi
if ! ip -o -4 address show | awk -v ip="$server_ip/24" -v prefix="$server_host-eth" '$4 == ip && index($2, prefix) == 1 { found++ } END { exit(found == 1 ? 0 : 1) }'; then
    printf 'ERROR: configured Mininet DMZ host %s is not running in this namespace.\n' "$server_ip" >&2
    exit 1
fi
command -v ovs-vsctl >/dev/null 2>&1 || { printf 'ERROR: ovs-vsctl unavailable; Mininet server cannot be verified.\n' >&2; exit 1; }
bridge_ports=$(ovs-vsctl --timeout=3 list-ports "$core_bridge") || { printf 'ERROR: configured Mininet OVS core is not running.\n' >&2; exit 1; }
if ! python3 - "$bridge_ports" "$expected_bridge_ports" "$core_bridge" <<'PY'
import sys
actual = set(sys.argv[1].splitlines()) - {sys.argv[3]}
expected = set(sys.argv[2].split(","))
if actual != expected:
    raise SystemExit(1)
PY
then
    printf 'ERROR: OVS core ports no longer match the configured Mininet topology.\n' >&2
    exit 1
fi
server_port_vlan=$(ovs-vsctl --timeout=3 get Port "$server_host-eth0" tag | tr -d '[]"[:space:]')
if [[ "$server_port_vlan" != "$server_vlan" ]]; then
    printf 'ERROR: configured Mininet DMZ port VLAN changed; refusing reset.\n' >&2
    exit 1
fi
current_value=$(sysctl -n net.ipv4.tcp_syncookies)
if [[ "$current_value" != "$new_value" && "$current_value" != "$previous_value" ]]; then
    printf 'ERROR: current SYN Cookie value %s differs from both recorded values; refusing to overwrite external changes.\n' "$current_value" >&2
    exit 1
fi
log_file="$experiment_dir/logs/syn_cookies_reset_$(date -u +%Y%m%dT%H%M%S.%NZ).log"
printf 'timestamp=%s\nexperiment_id=%s\nscenario=%s\ntarget_host=%s\ntarget_ip=%s\nsetting=net.ipv4.tcp_syncookies\ncurrent_value=%s\nrestore_value=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)" "$experiment_id" "$scenario" "$server_host" "$server_ip" "$current_value" "$previous_value" >"$log_file"
if [[ "$current_value" != "$previous_value" ]]; then
    sysctl -w "net.ipv4.tcp_syncookies=$previous_value" >>"$log_file" 2>&1
fi
verified_value=$(sysctl -n net.ipv4.tcp_syncookies)
if [[ "$verified_value" != "$previous_value" ]]; then
    printf 'ERROR: rollback verification failed; current value is %s.\n' "$verified_value" >&2
    exit 1
fi
printf 'new_value=%s\nverified=true\n' "$verified_value" >>"$log_file"
python3 - "$state_file" "$verified_value" <<'PY'
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
path = Path(sys.argv[1])
state = json.loads(path.read_text(encoding="utf-8"))
state["restored_value"] = int(sys.argv[2])
state["restored_at"] = datetime.now(timezone.utc).isoformat()
state["applied"] = False
fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".syn-cookies-reset-")
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
printf '[PASS] SYN Cookie configuration restored: previous=%s current=%s; log=%s\n' "$previous_value" "$verified_value" "$log_file"
