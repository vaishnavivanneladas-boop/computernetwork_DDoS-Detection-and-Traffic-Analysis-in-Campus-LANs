#!/usr/bin/env python3
"""Experiment directory management and measured server-process monitoring."""

from __future__ import annotations

import argparse
import csv
import fcntl
import json
import math
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS_ROOT = PROJECT_ROOT / "results"
EXPERIMENT_ID_PATTERN = re.compile(r"^EXP_\d{8}_\d{6}(?:_\d{2,})?$")
SCENARIO_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
METRIC_FIELDS = (
    "timestamp",
    "experiment_id",
    "scenario",
    "metric_name",
    "value",
    "unit",
    "status",
    "request_id",
)


class MonitorError(RuntimeError):
    """Invalid experiment metadata or monitor execution failure."""


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def validate_experiment_id(experiment_id: str) -> str:
    if not EXPERIMENT_ID_PATTERN.fullmatch(experiment_id):
        raise MonitorError("Experiment ID must match EXP_YYYYMMDD_HHMMSS with an optional numeric collision suffix.")
    return experiment_id


def validate_scenario(scenario: str) -> str:
    if not SCENARIO_PATTERN.fullmatch(scenario):
        raise MonitorError("Scenario must be 1-64 letters, digits, dots, underscores, or hyphens.")
    return scenario


def experiment_directory(
    experiment_id: str,
    results_root: Path = DEFAULT_RESULTS_ROOT,
) -> Path:
    validate_experiment_id(experiment_id)
    root = results_root.resolve()
    directory = (root / experiment_id).resolve()
    if directory.parent != root:
        raise MonitorError("Experiment directory must be directly inside the results root.")
    return directory


def create_experiment(
    scenario: str,
    experiment_id: str | None = None,
    results_root: Path = DEFAULT_RESULTS_ROOT,
) -> tuple[str, Path]:
    validate_scenario(scenario)
    results_root = results_root.resolve()
    try:
        results_root.mkdir(parents=True, exist_ok=True)
    except OSError as error:
        raise MonitorError(f"Cannot create results root {results_root}: {error}") from error

    if experiment_id is not None:
        validate_experiment_id(experiment_id)
        candidates = [experiment_id]
    else:
        base_id = datetime.now(timezone.utc).strftime("EXP_%Y%m%d_%H%M%S")
        candidates = [base_id, *(f"{base_id}_{suffix:02d}" for suffix in range(1, 10_000))]

    for candidate in candidates:
        directory = experiment_directory(candidate, results_root)
        try:
            directory.mkdir(exist_ok=False)
        except FileExistsError:
            if experiment_id is not None:
                raise MonitorError(f"Experiment already exists; refusing to overwrite {directory}.")
            continue
        except OSError as error:
            raise MonitorError(f"Cannot create experiment directory {directory}: {error}") from error

        try:
            for subdirectory in ("raw", "processed", "logs", "pcap"):
                (directory / subdirectory).mkdir()
            manifest = {
                "experiment_id": candidate,
                "scenario": scenario,
                "created_at": utc_timestamp(),
            }
            with (directory / "logs" / "experiment.json").open("x", encoding="utf-8") as manifest_file:
                json.dump(manifest, manifest_file, indent=2, sort_keys=True)
                manifest_file.write("\n")
            return candidate, directory
        except OSError as error:
            for child in directory.iterdir():
                if child.is_dir():
                    child.rmdir()
                else:
                    child.unlink()
            directory.rmdir()
            raise MonitorError(f"Cannot initialize experiment directory {directory}: {error}") from error

    raise MonitorError("Could not allocate a unique experiment ID.")


def make_metric_record(
    experiment_id: str,
    scenario: str,
    metric_name: str,
    value: Any,
    unit: str,
    *,
    timestamp: str | None = None,
    status: str | None = None,
    request_id: str = "",
) -> dict[str, Any]:
    validate_experiment_id(experiment_id)
    validate_scenario(scenario)
    if not metric_name or not isinstance(metric_name, str):
        raise MonitorError("Metric name must be non-empty text.")
    if not isinstance(unit, str) or not unit:
        raise MonitorError("Metric unit must be non-empty text.")
    if value is None:
        status = "unavailable"
    elif status is None:
        status = "measured"
    if status not in ("measured", "unavailable"):
        raise MonitorError("Metric status must be 'measured' or 'unavailable'.")
    if status == "unavailable" and value is not None:
        raise MonitorError("Unavailable metrics must have a null value.")
    return {
        "timestamp": timestamp or utc_timestamp(),
        "experiment_id": experiment_id,
        "scenario": scenario,
        "metric_name": metric_name,
        "value": value,
        "unit": unit,
        "status": status,
        "request_id": request_id,
    }


def append_metric_records(
    experiment_id: str,
    scenario: str,
    records: Iterable[dict[str, Any]],
    *,
    results_root: Path = DEFAULT_RESULTS_ROOT,
    stage: str = "raw",
) -> Path:
    validate_experiment_id(experiment_id)
    validate_scenario(scenario)
    if stage not in ("raw", "processed"):
        raise MonitorError("Metric output stage must be raw or processed.")
    directory = experiment_directory(experiment_id, results_root)
    if not directory.is_dir():
        raise MonitorError(f"Experiment directory does not exist: {directory}")

    output_path = directory / stage / "metrics.csv"
    normalized_rows: list[dict[str, str]] = []
    for record in records:
        if record.get("experiment_id") != experiment_id or record.get("scenario") != scenario:
            raise MonitorError("Every metric record must match the requested experiment ID and scenario.")
        normalized = make_metric_record(
            experiment_id,
            scenario,
            record.get("metric_name"),
            record.get("value"),
            record.get("unit"),
            timestamp=record.get("timestamp"),
            status=record.get("status"),
            request_id=record.get("request_id", ""),
        )
        row: dict[str, str] = {}
        for field in METRIC_FIELDS:
            value = normalized[field]
            if value is None:
                row[field] = "null"
            elif isinstance(value, bool):
                row[field] = "true" if value else "false"
            else:
                row[field] = str(value)
        normalized_rows.append(row)

    if not normalized_rows:
        return output_path

    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("a+", newline="", encoding="utf-8") as output_file:
            fcntl.flock(output_file.fileno(), fcntl.LOCK_EX)
            output_file.seek(0)
            first_row = next(csv.reader(output_file), None)
            if first_row is not None and tuple(first_row) != METRIC_FIELDS:
                raise MonitorError(f"Unexpected metric CSV header in {output_path}.")
            output_file.seek(0, os.SEEK_END)
            writer = csv.DictWriter(output_file, fieldnames=METRIC_FIELDS, extrasaction="raise")
            if first_row is None:
                writer.writeheader()
            writer.writerows(normalized_rows)
            output_file.flush()
            fcntl.flock(output_file.fileno(), fcntl.LOCK_UN)
    except OSError as error:
        raise MonitorError(f"Cannot append measurements to {output_path}: {error}") from error
    return output_path


def unavailable_process_records(
    experiment_id: str,
    scenario: str,
    timestamp: str,
) -> list[dict[str, Any]]:
    return [
        make_metric_record(experiment_id, scenario, "server_cpu_utilization", None, "%", timestamp=timestamp),
        make_metric_record(experiment_id, scenario, "server_memory_utilization", None, "%", timestamp=timestamp),
        make_metric_record(experiment_id, scenario, "server_process_status", None, "state", timestamp=timestamp),
    ]


def monitor_process(
    experiment_id: str,
    scenario: str,
    pid: int,
    duration: float,
    interval: float,
    results_root: Path = DEFAULT_RESULTS_ROOT,
) -> int:
    validate_experiment_id(experiment_id)
    validate_scenario(scenario)
    if pid <= 0:
        raise MonitorError("Process ID must be a positive integer.")
    if not math.isfinite(duration) or not 0 < duration <= 3600:
        raise MonitorError("System monitor duration must be positive and at most 3600 seconds.")
    if not math.isfinite(interval) or not 0.1 <= interval <= 60:
        raise MonitorError("Sample interval must be between 0.1 and 60 seconds.")
    if not experiment_directory(experiment_id, results_root).is_dir():
        raise MonitorError(f"Create experiment {experiment_id} before starting monitors.")

    try:
        import psutil
    except ImportError as error:
        raise MonitorError("psutil is required for process measurements; install project requirements.") from error

    try:
        process = psutil.Process(pid)
        process.cpu_percent(None)
    except (psutil.NoSuchProcess, psutil.AccessDenied) as error:
        timestamp = utc_timestamp()
        append_metric_records(
            experiment_id,
            scenario,
            unavailable_process_records(experiment_id, scenario, timestamp),
            results_root=results_root,
        )
        raise MonitorError(f"Cannot monitor server process {pid}: {error}.") from error

    start = time.monotonic()
    deadline = start + duration
    samples = 0
    print(f"Monitoring server process {pid} for up to {duration:g}s at {interval:g}s intervals.", flush=True)
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            time.sleep(min(interval, remaining))
            timestamp = utc_timestamp()
            try:
                with process.oneshot():
                    cpu_percent = process.cpu_percent(None)
                    memory_percent = process.memory_percent()
                    process_state = process.status()
                records = [
                    make_metric_record(experiment_id, scenario, "server_cpu_utilization", cpu_percent, "%", timestamp=timestamp),
                    make_metric_record(experiment_id, scenario, "server_memory_utilization", memory_percent, "%", timestamp=timestamp),
                    make_metric_record(experiment_id, scenario, "server_process_status", process_state, "state", timestamp=timestamp),
                ]
            except psutil.NoSuchProcess:
                records = unavailable_process_records(experiment_id, scenario, timestamp)
                records[-1] = make_metric_record(
                    experiment_id, scenario, "server_process_status", "stopped", "state", timestamp=timestamp
                )
                append_metric_records(experiment_id, scenario, records, results_root=results_root)
                print(f"[WARN] Server process {pid} stopped during monitoring; later resource metrics are unavailable.", flush=True)
                return 1
            except psutil.AccessDenied:
                records = unavailable_process_records(experiment_id, scenario, timestamp)

            append_metric_records(experiment_id, scenario, records, results_root=results_root)
            samples += 1
            print(f"[SAMPLE] {timestamp} process={pid} state={records[-1]['value']}", flush=True)
    except KeyboardInterrupt:
        print("\nSystem monitoring interrupted; recorded samples are preserved.", flush=True)
    print(f"System monitoring complete: {samples} sample(s).", flush=True)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    create_parser = commands.add_parser("create", help="create a unique experiment result directory")
    create_parser.add_argument("--scenario", required=True)
    create_parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)

    sample_parser = commands.add_parser("sample", help="measure server process CPU, memory, and state")
    sample_parser.add_argument("--experiment-id", required=True)
    sample_parser.add_argument("--scenario", required=True)
    sample_parser.add_argument("--pid", required=True, type=int, help="Mininet DMZ server process PID")
    sample_parser.add_argument("--duration", type=float, default=30.0)
    sample_parser.add_argument("--interval", type=float, default=1.0)
    sample_parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "create":
            experiment_id, directory = create_experiment(args.scenario, results_root=args.results_root)
            print(json.dumps({"experiment_id": experiment_id, "scenario": args.scenario, "directory": str(directory)}))
            return 0
        return monitor_process(
            args.experiment_id,
            args.scenario,
            args.pid,
            args.duration,
            args.interval,
            args.results_root,
        )
    except (MonitorError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())