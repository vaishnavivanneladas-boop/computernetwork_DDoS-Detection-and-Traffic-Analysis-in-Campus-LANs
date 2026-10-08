#!/usr/bin/env bash
set -Eeuo pipefail
trap 'status=$?; printf "ERROR: run_all stopped after failure at line %s (exit %s). Earlier scenario data and logs are preserved.\n" "$LINENO" "$status" >&2; exit "$status"' ERR

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
project_root=$(cd -- "$script_dir/.." && pwd)
results_root="$project_root/results"
if (($# == 2)) && [[ "$1" == --results-root ]]; then
    results_root=$2
elif (($# != 0)); then
    printf 'Usage: run_all.sh [--results-root PATH]\n' >&2
    exit 2
fi

for runner in run_baseline.sh run_attack.sh run_syn_cookies.sh run_combined.sh; do
    printf '\n=== Running %s ===\n' "$runner"
    "$script_dir/$runner" --results-root "$results_root"
done

project_python=${LAB_PYTHON:-$project_root/.venv/bin/python}
if [[ ! -x "$project_python" ]]; then
    printf 'ERROR: project Python interpreter is unavailable: %s\n' "$project_python" >&2
    exit 1
fi
if ((EUID == 0)); then
    "$project_python" "$project_root/analysis/generate_results.py" --results-root "$results_root"
else
    sudo -- "$project_python" "$project_root/analysis/generate_results.py" --results-root "$results_root"
fi
