#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "ERROR: capture failed at line %s (exit %s): %s\n" "$LINENO" "$status" "$BASH_COMMAND" >&2; exit "$status"' ERR

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_root=$(cd -- "$script_dir/.." && pwd)
config_path="$project_root/config/config.yaml"
experiment_id=
scenario=
duration=3600
results_root="$project_root/results"
python_bin=python3
output_path=
log_path=

usage() {
    printf '%s\n' 'Usage: capture_packets.sh --experiment-id ID --scenario NAME [--duration SECONDS] [--results-root PATH] [--python PATH] [--output PCAP] [--log-file PATH]'
}

while (($#)); do
    case "$1" in
        --experiment-id) (($# >= 2)) || { usage >&2; exit 2; }; experiment_id=$2; shift 2 ;;
        --scenario) (($# >= 2)) || { usage >&2; exit 2; }; scenario=$2; shift 2 ;;
        --duration) (($# >= 2)) || { usage >&2; exit 2; }; duration=$2; shift 2 ;;
        --results-root) (($# >= 2)) || { usage >&2; exit 2; }; results_root=$2; shift 2 ;;
        --python) (($# >= 2)) || { usage >&2; exit 2; }; python_bin=$2; shift 2 ;;
        --output) (($# >= 2)) || { usage >&2; exit 2; }; output_path=$2; shift 2 ;;
        --log-file) (($# >= 2)) || { usage >&2; exit 2; }; log_path=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'ERROR: unknown option %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ "$experiment_id" =~ ^EXP_[0-9]{8}_[0-9]{6}(_[0-9]{2,})?$ ]] || { printf 'ERROR: valid --experiment-id required.\n' >&2; exit 2; }
[[ "$scenario" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$ ]] || { printf 'ERROR: valid --scenario required.\n' >&2; exit 2; }
if ! "$python_bin" - "$duration" <<'PY'
import math
import sys
try:
    seconds = float(sys.argv[1])
except ValueError:
    raise SystemExit(1)
raise SystemExit(0 if math.isfinite(seconds) and 0 < seconds <= 3600 else 1)
PY
then
    printf 'ERROR: duration must be finite, positive, and no more than 3600 seconds.\n' >&2
    exit 2
fi

if ((EUID != 0)) || ! command -v tcpdump >/dev/null 2>&1 || ! command -v ip >/dev/null 2>&1 || ! command -v ovs-vsctl >/dev/null 2>&1; then
    printf 'ERROR: root, tcpdump, iproute2, and ovs-vsctl are required inside the Mininet server host.\n' >&2
    exit 1
fi
if ! command -v "$python_bin" >/dev/null 2>&1; then
    printf 'ERROR: configured Python interpreter %s is unavailable.\n' "$python_bin" >&2
    exit 1
fi
current_namespace=$(stat -Lc '%i' /proc/self/ns/net) || { printf 'ERROR: cannot inspect network namespace.\n' >&2; exit 1; }
host_namespace=$(stat -Lc '%i' /proc/1/ns/net) || { printf 'ERROR: cannot inspect host network namespace.\n' >&2; exit 1; }
if [[ "$current_namespace" == "$host_namespace" ]]; then
    printf 'ERROR: refusing to capture on the physical host network.\n' >&2
    exit 1
fi

experiment_dir=$(realpath -m -- "$results_root/$experiment_id")
results_root=$(realpath -m -- "$results_root")
if [[ "$(dirname -- "$experiment_dir")" != "$results_root" || ! -d "$experiment_dir/pcap" || ! -d "$experiment_dir/logs" ]]; then
    printf 'ERROR: experiment directory is missing or outside the results root.\n' >&2
    exit 1
fi
topology_json=$("$python_bin" - "$config_path" "$experiment_dir/logs/experiment.json" "$experiment_id" "$scenario" <<'PY'
import json
import sys
import yaml
config_path, manifest_path, experiment_id, scenario = sys.argv[1:]
with open(config_path, encoding="utf-8") as config_file:
    config = yaml.safe_load(config_file)
with open(manifest_path, encoding="utf-8") as manifest_file:
    manifest = json.load(manifest_file)
if manifest.get("experiment_id") != experiment_id or manifest.get("scenario") != scenario:
    raise SystemExit("experiment manifest ID/scenario mismatch")
topology = config["topology"]
web = topology["hosts"]["web_server"]
vlan = topology["vlans"][int(web["vlan"])]
if web["ip"] != "10.10.10.100" or vlan["subnet"] != "10.10.10.0/24" or int(topology["http"]["port"]) != 80:
    raise SystemExit("DMZ server is outside the configured isolated topology")
print(json.dumps({"node": web["node"], "ip": web["ip"], "network": vlan["subnet"], "port": 80,
                  "bridge": topology["nodes"]["core_switch"], "vlan": int(web["vlan"]),
                  "expected_ports": [host["node"] + "-eth0" for host in topology["hosts"].values()] +
                                    [topology["nodes"]["campus_router"] + "-eth0"]}))
PY
) || { printf 'ERROR: cannot validate experiment and configured DMZ server.\n' >&2; exit 1; }
server_ip=$("$python_bin" -c 'import json,sys; print(json.loads(sys.stdin.read())["ip"])' <<<"$topology_json")
server_node=$("$python_bin" -c 'import json,sys; print(json.loads(sys.stdin.read())["node"])' <<<"$topology_json")
server_network=$("$python_bin" -c 'import json,sys; print(json.loads(sys.stdin.read())["network"])' <<<"$topology_json")
core_bridge=$("$python_bin" -c 'import json,sys; print(json.loads(sys.stdin.read())["bridge"])' <<<"$topology_json")
server_vlan=$("$python_bin" -c 'import json,sys; print(json.loads(sys.stdin.read())["vlan"])' <<<"$topology_json")

interface=$(ip -j -4 address show | "$python_bin" -c '
import ipaddress, json, sys
target = ipaddress.ip_address(sys.argv[1])
matches = [link["ifname"] for link in json.load(sys.stdin)
           if any(address.get("family") == "inet" and
                  ipaddress.ip_interface(address["local"]).ip == target
                  for address in link.get("addr_info", []))]
if len(matches) != 1:
    raise SystemExit(f"expected one interface with {target}; found {len(matches)}")
print(matches[0])
' "$server_ip") || { printf 'ERROR: cannot uniquely discover the DMZ server interface.\n' >&2; exit 1; }
if [[ "$interface" != "$server_node-eth"* ]]; then
    printf 'ERROR: interface %s does not belong to Mininet host %s.\n' "$interface" "$server_node" >&2
    exit 1
fi
mapfile -t non_loopback_interfaces < <(ip -j link show | "$python_bin" -c '
import json, sys
for link in json.load(sys.stdin):
    if link.get("ifname") != "lo":
        print(link["ifname"])
')
if ((${#non_loopback_interfaces[@]} != 1)) || [[ "${non_loopback_interfaces[0]}" != "$interface" ]]; then
    printf 'ERROR: unexpected non-loopback interfaces in DMZ host namespace; refusing capture.\n' >&2
    exit 1
fi

bridge_ports=$(ovs-vsctl --timeout=3 list-ports "$core_bridge") || { printf 'ERROR: cannot inspect configured OVS core.\n' >&2; exit 1; }
if ! "$python_bin" - "$topology_json" "$bridge_ports" <<'PY'
import json
import sys

topology = json.loads(sys.argv[1])
expected = set(topology["expected_ports"])
actual = set(sys.argv[2].splitlines()) - {topology["bridge"]}
if actual != expected:
    print(f"unexpected={sorted(actual - expected)} missing={sorted(expected - actual)}", file=sys.stderr)
    raise SystemExit(1)
PY
then
    printf 'ERROR: OVS core contains ports outside the configured Mininet topology.\n' >&2
    exit 1
fi
if ! grep -Fxq "$interface" <<<"$bridge_ports"; then
    printf 'ERROR: server-facing interface %s is not attached to OVS bridge %s.\n' "$interface" "$core_bridge" >&2
    exit 1
fi
port_vlan=$(ovs-vsctl --timeout=3 get Port "$interface" tag | tr -d '[]"[:space:]')
if [[ "$port_vlan" != "$server_vlan" ]]; then
    printf 'ERROR: server-facing OVS port VLAN %s does not match configured VLAN %s.\n' "$port_vlan" "$server_vlan" >&2
    exit 1
fi

utc_id=$(date -u +%Y%m%dT%H%M%S.%NZ)
[[ -n "$output_path" ]] || output_path="$experiment_dir/pcap/server_capture_${utc_id}.pcap"
[[ -n "$log_path" ]] || log_path="$experiment_dir/logs/server_capture_${utc_id}.log"
if [[ "$(realpath -m -- "$(dirname -- "$output_path")")" != "$experiment_dir/pcap" || \
      "$(realpath -m -- "$(dirname -- "$log_path")")" != "$experiment_dir/logs" ]]; then
    printf 'ERROR: capture outputs must stay inside this experiment pcap/ and logs/ directories.\n' >&2
    exit 1
fi
if [[ -e "$output_path" || -e "$log_path" ]]; then
    printf 'ERROR: refusing to overwrite an existing PCAP or capture log.\n' >&2
    exit 1
fi

umask 077
set -o noclobber
: > "$log_path"
set +o noclobber
exec 3>>"$log_path"
capture_filter="host $server_ip and tcp port 80"
start_time=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
start_monotonic=$("$python_bin" -c 'import time; print(time.monotonic_ns())')
capture_pid=
timer_pid=
tcpdump_status=not_started
printf 'start_time=%s\nexperiment_id=%s\nscenario=%s\nserver_host=%s\ninterface=%s\nserver_ip=%s\nserver_network=%s\nvlan=%s\nfilter=%s\n' \
    "$start_time" "$experiment_id" "$scenario" "$server_node" "$interface" "$server_ip" "$server_network" "$server_vlan" "$capture_filter" >&3

cleanup() {
    script_status=$?
    trap - EXIT INT TERM HUP
    set +e
    if [[ -n "$timer_pid" ]] && kill -0 "$timer_pid" 2>/dev/null; then
        kill "$timer_pid" 2>/dev/null
        wait "$timer_pid" 2>/dev/null
    fi
    if [[ -n "$capture_pid" ]]; then
        if kill -0 "$capture_pid" 2>/dev/null; then
            kill -INT "$capture_pid" 2>/dev/null
        fi
        wait "$capture_pid" 2>/dev/null
        tcpdump_status=$?
    fi
    end_time=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
    end_monotonic=$("$python_bin" -c 'import time; print(time.monotonic_ns())')
    elapsed=$("$python_bin" - "$start_monotonic" "$end_monotonic" <<'PY'
import sys
print(f"{(int(sys.argv[2]) - int(sys.argv[1])) / 1_000_000_000:.6f}")
PY
)
    printf 'end_time=%s\ncapture_elapsed_seconds=%s\ntcpdump_exit_status=%s\nscript_exit_status=%s\npcap_file=%s\n' \
        "$end_time" "$elapsed" "$tcpdump_status" "$script_status" "$output_path" >&3
    exec 3>&-
    printf '[CAPTURE] stopped; elapsed=%ss; tcpdump_status=%s; pcap=%s\n' "$elapsed" "$tcpdump_status" "$output_path"
    exit "$script_status"
}
trap cleanup EXIT
trap 'exit 0' INT TERM HUP

printf '[CAPTURE] %s on %s; BPF filter: %s; maximum duration: %ss\n' "$start_time" "$interface" "$capture_filter" "$duration"
tcpdump -nn -s 0 -U -i "$interface" -w "$output_path" "$capture_filter" >&3 2>&3 &
capture_pid=$!
(sleep "$duration"; kill -TERM "$$" 2>/dev/null) &
timer_pid=$!
set +e
wait "$capture_pid"
tcpdump_status=$?
capture_pid=
set -e
if ((tcpdump_status != 0)); then
    printf 'ERROR: tcpdump exited with status %s.\n' "$tcpdump_status" >&2
    exit 1
fi
