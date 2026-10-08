#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "ERROR: scenario launcher failed at line %s (exit %s): %s\n" "$LINENO" "$status" "$BASH_COMMAND" >&2; exit "$status"' ERR

project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
if (($# < 1)); then
    printf 'Usage: run_scenario.sh SCENARIO [--results-root PATH]\n' >&2
    exit 2
fi
scenario=$1
shift
case "$scenario" in
    baseline|syn_flood_no_defense|syn_cookies|syn_cookies_rate_limit) ;;
    *) printf 'ERROR: unsupported scenario: %s\n' "$scenario" >&2; exit 2 ;;
esac
results_root="$project_root/results"
while (($#)); do
    case "$1" in
        --results-root) (($# >= 2)) || { printf 'Missing results-root value.\n' >&2; exit 2; }; results_root=$2; shift 2 ;;
        *) printf 'ERROR: unknown option %s\n' "$1" >&2; exit 2 ;;
    esac
done
mkdir -p "$project_root/logs"
log_timestamp=$(date -u +%Y%m%dT%H%M%S.%NZ)
orchestration_log="$project_root/logs/orchestration_${scenario}_${log_timestamp}.log"

printf '[STEP 1/17] Checking environment.\n' | tee "$orchestration_log"
if ! "$project_root/scripts/check_environment.sh" 2>&1 | tee -a "$orchestration_log"; then
    printf 'ERROR: environment is not ready; scenario %s was not started.\n' "$scenario" | tee -a "$orchestration_log" >&2
    exit 1
fi

python_bin=${LAB_PYTHON:-$project_root/.venv/bin/python}
if [[ ! -x "$python_bin" ]]; then
    printf 'ERROR: project Python interpreter is unavailable: %s\n' "$python_bin" | tee -a "$orchestration_log" >&2
    exit 1
fi
printf '[STEP 2/17] Topology startup will perform project-scoped stale Mininet cleanup.\n' | tee -a "$orchestration_log"
printf '[STEP 3-16/17] Starting fresh topology and scenario %s.\n' "$scenario" | tee -a "$orchestration_log"
command=("$python_bin" "$project_root/topology/campus_topology.py" --run-scenario --scenario "$scenario" --results-root "$results_root")
if ((EUID == 0)); then
    "${command[@]}" 2>&1 | tee -a "$orchestration_log"
else
    command -v sudo >/dev/null 2>&1 || { printf 'ERROR: sudo is required to create Mininet namespaces.\n' >&2; exit 1; }
    sudo -- "${command[@]}" 2>&1 | tee -a "$orchestration_log"
fi
printf '[STEP 17/17] Topology runner returned; verify its status and cleanup logs.\n' | tee -a "$orchestration_log"
printf 'Scenario %s completed. Orchestration log: %s\n' "$scenario" "$orchestration_log"
