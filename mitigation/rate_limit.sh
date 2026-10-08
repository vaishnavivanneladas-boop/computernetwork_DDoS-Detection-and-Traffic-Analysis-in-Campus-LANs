#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "ERROR: rate-limit operation failed at line %s (exit %s): %s\n" "$LINENO" "$status" "$BASH_COMMAND" >&2; exit "$status"' ERR

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
config_path="$project_root/config/config.yaml"
action=
experiment_id=
legitimate_pid=
rate_override=
burst_override=
results_root="$project_root/results"
allow_installed=false
drop_installed=false
keep_rules=false
allow_rule=()
drop_rule=()
state_file=
log_file=

rollback_partial_rules() {
    exit_status=$?
    trap - EXIT INT TERM HUP
    set +e
    if [[ "$action" == apply && "$keep_rules" != true ]]; then
        if ((${#drop_rule[@]})) && iptables -w 3 -C FORWARD "${drop_rule[@]}" 2>/dev/null; then
            iptables -w 3 -D FORWARD "${drop_rule[@]}"
            printf 'rollback=removed_drop_rule\n' >>"$log_file"
        fi
        if ((${#allow_rule[@]})) && iptables -w 3 -C FORWARD "${allow_rule[@]}" 2>/dev/null; then
            iptables -w 3 -D FORWARD "${allow_rule[@]}"
            printf 'rollback=removed_allow_rule\n' >>"$log_file"
        fi
        if [[ -f "$state_file" ]]; then
            python3 - "$state_file" <<'PY'
import json
from pathlib import Path
path = Path(__import__("sys").argv[1])
state = json.loads(path.read_text(encoding="utf-8"))
state["applied"] = False
path.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n", encoding="utf-8")
PY
        fi
    fi
    exit "$exit_status"
}
trap rollback_partial_rules EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP

usage() {
    printf '%s\n' 'Usage: rate_limit.sh --apply --experiment-id ID --legitimate-pid PID [--rate N/second] [--burst N] [--results-root PATH]'
    printf '%s\n' '       rate_limit.sh --remove --experiment-id ID [--results-root PATH]'
}

while (($#)); do
    case "$1" in
        --apply) action=apply; shift ;;
        --remove|--reset) action=remove; shift ;;
        --experiment-id) (($# >= 2)) || { usage >&2; exit 2; }; experiment_id=$2; shift 2 ;;
        --legitimate-pid) (($# >= 2)) || { usage >&2; exit 2; }; legitimate_pid=$2; shift 2 ;;
        --rate) (($# >= 2)) || { usage >&2; exit 2; }; rate_override=$2; shift 2 ;;
        --burst) (($# >= 2)) || { usage >&2; exit 2; }; burst_override=$2; shift 2 ;;
        --results-root) (($# >= 2)) || { usage >&2; exit 2; }; results_root=$2; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'ERROR: unknown option %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done
[[ "$action" == apply || "$action" == remove ]] || { usage >&2; exit 2; }
[[ "$experiment_id" =~ ^EXP_[0-9]{8}_[0-9]{6}(_[0-9]{2,})?$ ]] || { printf 'ERROR: valid experiment ID required.\n' >&2; exit 2; }
if [[ "$action" == apply && ! "$legitimate_pid" =~ ^[1-9][0-9]*$ ]]; then
    printf 'ERROR: --legitimate-pid is required for apply so HTTP can be verified from dclLegit.\n' >&2
    exit 2
fi
if ((EUID != 0)); then
    printf 'ERROR: rate limiting must run as root inside the Mininet campus-router namespace.\n' >&2
    exit 1
fi
if [[ ! -r /proc/self/ns/net || ! -r /proc/1/ns/net ]] || \
    [[ "$(stat -Lc '%i' /proc/self/ns/net)" == "$(stat -Lc '%i' /proc/1/ns/net)" ]]; then
    printf 'ERROR: refusing to modify the physical host firewall.\n' >&2
    exit 1
fi
for command_name in ip iptables nsenter; do
    command -v "$command_name" >/dev/null 2>&1 || { printf 'ERROR: %s is required.\n' "$command_name" >&2; exit 1; }
done

experiment_dir=$(realpath -m -- "$results_root/$experiment_id")
results_root=$(realpath -m -- "$results_root")
if [[ "$(dirname -- "$experiment_dir")" != "$results_root" || ! -d "$experiment_dir/logs" ]]; then
    printf 'ERROR: experiment directory is missing or outside the configured results root.\n' >&2
    exit 1
fi
state_file="$experiment_dir/logs/rate_limit_state.json"

if [[ "$action" == apply ]]; then
    readarray -t settings < <(python3 - "$config_path" "$experiment_dir/logs/experiment.json" "$experiment_id" <<'PY'
import json
import re
import sys
from pathlib import Path
import yaml
config_path, manifest_path, experiment_id = sys.argv[1:]
config = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
if manifest.get("experiment_id") != experiment_id:
    raise SystemExit("experiment manifest mismatch")
rule = config["rate_limit"]
if rule.get("enabled") is not True or rule.get("experimental_parameter") is not True:
    raise SystemExit("rate limit must be explicitly enabled and marked experimental in config.yaml")
topology = config["topology"]
web = topology["hosts"]["web_server"]
legit = topology["hosts"]["legitimate_client"]
student_vlan = topology["vlans"][int(legit["vlan"])]
dmz_vlan = topology["vlans"][int(web["vlan"])]
router = topology["nodes"]["campus_router"]
if web["ip"] != "10.10.10.100" or int(rule["destination_port"]) != 80:
    raise SystemExit("rate-limit destination must be the configured DMZ server TCP/80")
if int(legit["vlan"]) != 30 or int(web["vlan"]) != 10:
    raise SystemExit("rate limit requires configured VLAN 30 source and VLAN 10 DMZ")
rate = str(rule["syn_rate"])
burst = int(rule["burst"])
if not re.fullmatch(r"[1-9][0-9]*/second", rate) or not 1 <= burst <= 1000:
    raise SystemExit("configured SYN rate/burst is outside supported experimental syntax/range")
values = [router, web["ip"], dmz_vlan["subnet"], str(rule["destination_port"]),
          rate, str(burst), student_vlan["subnet"], legit["ip"], legit["node"],
          dmz_vlan["gateway"], student_vlan["gateway"], manifest["scenario"]]
for value in values:
    print(value)
PY
) || { printf 'ERROR: cannot validate rate-limit experiment configuration.\n' >&2; exit 1; }
    if ((${#settings[@]} != 12)); then
        printf 'ERROR: incomplete rate-limit configuration.\n' >&2
        exit 1
    fi
    router_name=${settings[0]}
    server_ip=${settings[1]}
    server_network=${settings[2]}
    destination_port=${settings[3]}
    syn_rate=${rate_override:-${settings[4]}}
    burst=${burst_override:-${settings[5]}}
    legitimate_network=${settings[6]}
    legitimate_ip=${settings[7]}
    legitimate_host=${settings[8]}
    dmz_gateway=${settings[9]}
    student_gateway=${settings[10]}
    scenario=${settings[11]}
    [[ "$syn_rate" =~ ^[1-9][0-9]*/second$ ]] || { printf 'ERROR: --rate must use a positive N/second value.\n' >&2; exit 2; }
    [[ "$burst" =~ ^[1-9][0-9]{0,3}$ ]] || { printf 'ERROR: --burst must be an integer from 1 to 1000.\n' >&2; exit 2; }
    ((burst <= 1000)) || { printf 'ERROR: --burst may not exceed 1000.\n' >&2; exit 2; }
    [[ ! -e "$state_file" ]] || { printf 'ERROR: rate-limit state already exists; refusing to overwrite.\n' >&2; exit 1; }

    interface_json=$(ip -j -4 address show)
    readarray -t interfaces < <(python3 - "$interface_json" "$student_gateway" "$dmz_gateway" <<'PY'
import json
import ipaddress
import sys
links = json.loads(sys.argv[1])
wanted = {sys.argv[2], sys.argv[3]}
found = {}
for link in links:
    for info in link.get("addr_info", []):
        if info.get("family") == "inet" and info.get("local") in wanted:
            found[info["local"]] = link["ifname"]
if set(found) != wanted or found[sys.argv[2]] == found[sys.argv[3]]:
    raise SystemExit("router namespace does not own both configured VLAN gateway interfaces")
print(found[sys.argv[2]])
print(found[sys.argv[3]])
PY
) || { printf 'ERROR: current namespace is not the configured Mininet router.\n' >&2; exit 1; }
    ingress_interface=${interfaces[0]}
    egress_interface=${interfaces[1]}
    if [[ "$ingress_interface" != "$router_name-eth"* || "$egress_interface" != "$router_name-eth"* ]]; then
        printf 'ERROR: gateway interfaces do not belong to configured router %s.\n' "$router_name" >&2
        exit 1
    fi
    route=$(ip -4 route get "$server_ip")
    [[ "$route" == *"dev $egress_interface"* ]] || { printf 'ERROR: DMZ route does not use the discovered DMZ interface.\n' >&2; exit 1; }

    legitimate_netns=$(stat -Lc '%i' "/proc/$legitimate_pid/ns/net") || { printf 'ERROR: legitimate client PID is not running.\n' >&2; exit 1; }
    [[ "$legitimate_netns" != "$host_namespace" && "$legitimate_netns" != "$(stat -Lc '%i' /proc/self/ns/net)" ]] || {
        printf 'ERROR: legitimate client PID does not identify a separate Mininet host namespace.\n' >&2
        exit 1
    }
    if ! nsenter --target "$legitimate_pid" --net -- ip -o -4 address show | \
        awk -v ip="$legitimate_ip/24" -v prefix="$legitimate_host-eth" '$4 == ip && index($2, prefix) == 1 { found++ } END { exit(found == 1 ? 0 : 1) }'; then
        printf 'ERROR: legitimate PID is not the configured Mininet client.\n' >&2
        exit 1
    fi
    legit_route=$(nsenter --target "$legitimate_pid" --net -- ip -4 route get "$server_ip")
    [[ "$legit_route" == *"src $legitimate_ip"* && "$legit_route" == *"via $student_gateway"* ]] || {
        printf 'ERROR: legitimate client route is not the configured Mininet VLAN 30 path.\n' >&2
        exit 1
    }
    if ! nsenter --target "$legitimate_pid" --net -- curl --noproxy '*' --fail --silent --show-error --connect-timeout 2 --max-time 3 "http://$server_ip/health" >/dev/null; then
        printf 'ERROR: legitimate HTTP health check failed before rate limiting.\n' >&2
        exit 1
    fi

    comment="dclab_${experiment_id}"
    allow_rule=(-i "$ingress_interface" -o "$egress_interface" -s "$legitimate_network" -d "$server_ip" -p tcp --dport "$destination_port" --syn -m limit --limit "$syn_rate" --limit-burst "$burst" -m comment --comment "${comment}_allow" -j ACCEPT)
    drop_rule=(-i "$ingress_interface" -o "$egress_interface" -s "$legitimate_network" -d "$server_ip" -p tcp --dport "$destination_port" --syn -m comment --comment "${comment}_drop" -j DROP)
    if iptables -w 3 -C FORWARD "${allow_rule[@]}" 2>/dev/null || iptables -w 3 -C FORWARD "${drop_rule[@]}" 2>/dev/null; then
        printf 'ERROR: a rule for this experiment is already active.\n' >&2
        exit 1
    fi

    timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
    log_file="$experiment_dir/logs/rate_limit_${timestamp//:/-}.log"
    state_json=$(python3 - "$experiment_id" "$scenario" "$router_name" "$server_ip" "$destination_port" "$syn_rate" "$burst" "$ingress_interface" "$egress_interface" "$legitimate_ip" <<'PY'
import json
import sys
(exp, scenario, router, server, port, rate, burst, ingress, egress, legit) = sys.argv[1:]
comment = f"dclab_{exp}"
base = ["-i", ingress, "-o", egress, "-s", "10.10.30.0/24", "-d", server, "-p", "tcp", "--dport", port, "--syn"]
allow = base + ["-m", "limit", "--limit", rate, "--limit-burst", burst,
                "-m", "comment", "--comment", comment + "_allow", "-j", "ACCEPT"]
drop = base + ["-m", "comment", "--comment", comment + "_drop", "-j", "DROP"]
print(json.dumps({"experiment_id": exp, "scenario": scenario, "router": router,
                  "server": server, "port": int(port), "rate": rate, "burst": int(burst),
                  "ingress": ingress, "egress": egress, "legitimate_ip": legit,
                  "allow_rule": allow, "drop_rule": drop, "applied": False}, sort_keys=True))
PY
)
    python3 - "$state_file" "$state_json" <<'PY'
import sys
from pathlib import Path
with Path(sys.argv[1]).open("x", encoding="utf-8") as stream:
    stream.write(sys.argv[2] + "\n")
PY
    printf 'timestamp=%s\nexperiment_id=%s\nscenario=%s\nexperimental_parameter=true\nrate=%s\nburst=%s\n' \
        "$timestamp" "$experiment_id" "$scenario" "$syn_rate" "$burst" >"$log_file"
    printf 'rule=iptables -w 3 -I FORWARD 1' >>"$log_file"
    printf ' %q' "${allow_rule[@]}" >>"$log_file"
    printf '\nrule=iptables -w 3 -I FORWARD 2' >>"$log_file"
    printf ' %q' "${drop_rule[@]}" >>"$log_file"
    printf '\n' >>"$log_file"

    if ! iptables -w 3 -I FORWARD 1 "${allow_rule[@]}"; then
        printf 'ERROR: failed to install rate-limited ACCEPT rule.\n' >&2
        exit 1
    fi
    allow_installed=true
    if ! iptables -w 3 -I FORWARD 2 "${drop_rule[@]}"; then
        iptables -w 3 -D FORWARD "${allow_rule[@]}" || true
        allow_installed=false
        printf 'ERROR: failed to install SYN drop-over-limit rule; removed partial rule.\n' >&2
        exit 1
    fi
    drop_installed=true
    if ! iptables -w 3 -C FORWARD "${allow_rule[@]}" || ! iptables -w 3 -C FORWARD "${drop_rule[@]}"; then
        iptables -w 3 -D FORWARD "${drop_rule[@]}" || true
        iptables -w 3 -D FORWARD "${allow_rule[@]}" || true
        printf 'ERROR: rate-limit verification failed; partial rules removed.\n' >&2
        exit 1
    fi
    if ! nsenter --target "$legitimate_pid" --net -- curl --noproxy '*' --fail --silent --show-error --connect-timeout 2 --max-time 3 "http://$server_ip/health" >/dev/null; then
        iptables -w 3 -D FORWARD "${drop_rule[@]}" || true
        iptables -w 3 -D FORWARD "${allow_rule[@]}" || true
        printf 'ERROR: legitimate HTTP health check failed after applying limit; rules were removed.\n' >&2
        exit 1
    fi
    printf '%s\n' 'change=installed' 'verified=true' 'legitimate_http=ok' >>"$log_file"
    python3 - "$state_file" <<'PY'
import json
import os
import sys
import tempfile
from pathlib import Path
path = Path(sys.argv[1])
state = json.loads(path.read_text(encoding="utf-8"))
state["applied"] = True
fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".rate-limit-")
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
    printf '[PASS] Installed only on Mininet router %s for %s TCP/%s at experimental rate %s burst %s.\n' \
        "$router_name" "$server_ip" "$destination_port" "$syn_rate" "$burst"
    iptables -w 3 -L FORWARD -nvx --line-numbers | tee -a "$log_file"
    printf '[RULE] '; iptables -w 3 -S FORWARD | grep -F "$comment" | tee -a "$log_file"
    keep_rules=true
    printf '[LOG] %s\n' "$log_file"
else
    [[ -f "$state_file" ]] || { printf 'ERROR: saved rate-limit rules are missing; cannot reset safely.\n' >&2; exit 1; }
    readarray -t router_identity < <(python3 - "$config_path" "$experiment_dir/logs/experiment.json" "$state_file" "$experiment_id" <<'PY'
import json
import sys
from pathlib import Path
import yaml
config = yaml.safe_load(Path(sys.argv[1]).read_text(encoding="utf-8"))
manifest = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
state = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
if manifest.get("experiment_id") != sys.argv[4] or state.get("experiment_id") != sys.argv[4]:
    raise SystemExit("experiment ID mismatch")
topology = config["topology"]
router = topology["nodes"]["campus_router"]
if state.get("router") != router:
    raise SystemExit("saved firewall rules belong to another router")
print(router)
print(topology["vlans"][30]["gateway"])
print(topology["vlans"][10]["gateway"])
PY
) || { printf 'ERROR: cannot validate saved Mininet router identity.\n' >&2; exit 1; }
    if ((${#router_identity[@]} != 3)); then
        printf 'ERROR: incomplete Mininet router identity.\n' >&2
        exit 1
    fi
    router_name=${router_identity[0]}
    for gateway in "${router_identity[1]}" "${router_identity[2]}"; do
        if ! ip -o -4 address show | awk -v ip="$gateway/24" -v prefix="$router_name-eth" '$4 == ip && index($2, prefix) == 1 { found++ } END { exit(found == 1 ? 0 : 1) }'; then
            printf 'ERROR: configured router gateway %s is not active here; refusing firewall reset.\n' "$gateway" >&2
            exit 1
        fi
    done
    mapfile -d '' -t allow_rule < <(python3 - "$state_file" "$experiment_id" <<'PY'
import json
import sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if state.get("experiment_id") != sys.argv[2]:
    raise SystemExit("state belongs to a different experiment")
for rule in state["allow_rule"]:
    sys.stdout.buffer.write(rule.encode() + b"\0")
PY
)
    mapfile -d '' -t drop_rule < <(python3 - "$state_file" "$experiment_id" <<'PY'
import json
import sys
from pathlib import Path
state = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
if state.get("experiment_id") != sys.argv[2]:
    raise SystemExit("state belongs to a different experiment")
for rule in state["drop_rule"]:
    sys.stdout.buffer.write(rule.encode() + b"\0")
PY
)
    ((${#allow_rule[@]} > 0 && ${#drop_rule[@]} > 0)) || { printf 'ERROR: saved rate-limit state is invalid.\n' >&2; exit 1; }
    timestamp=$(date -u +%Y-%m-%dT%H:%M:%S.%NZ)
    log_file="$experiment_dir/logs/rate_limit_reset_${timestamp//:/-}.log"
    printf 'timestamp=%s\nexperiment_id=%s\nrouter_namespace=current Mininet router only\n' "$timestamp" "$experiment_id" >"$log_file"
    if iptables -w 3 -C FORWARD "${drop_rule[@]}" 2>/dev/null; then
        iptables -w 3 -D FORWARD "${drop_rule[@]}"
        printf 'change=removed_drop_rule\n' >>"$log_file"
    fi
    if iptables -w 3 -C FORWARD "${allow_rule[@]}" 2>/dev/null; then
        iptables -w 3 -D FORWARD "${allow_rule[@]}"
        printf 'change=removed_allow_rule\n' >>"$log_file"
    fi
    if iptables -w 3 -C FORWARD "${drop_rule[@]}" 2>/dev/null || iptables -w 3 -C FORWARD "${allow_rule[@]}" 2>/dev/null; then
        printf 'ERROR: rate-limit rules remain active after reset.\n' >&2
        exit 1
    fi
    python3 - "$state_file" <<'PY'
import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path
path = Path(sys.argv[1])
state = json.loads(path.read_text(encoding="utf-8"))
state["applied"] = False
state["removed_at"] = datetime.now(timezone.utc).isoformat()
fd, temporary = tempfile.mkstemp(dir=path.parent, prefix=".rate-limit-reset-")
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
    printf 'verified=true\n' >>"$log_file"
    keep_rules=false
    iptables -w 3 -L FORWARD -nvx --line-numbers | tee -a "$log_file"
    printf '[PASS] Project rate-limit rules removed from this Mininet router namespace.\n'
fi
