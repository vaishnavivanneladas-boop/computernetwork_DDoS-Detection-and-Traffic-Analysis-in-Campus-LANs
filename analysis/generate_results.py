#!/usr/bin/env python3
"""Generate comparisons only from completed, measured local experiment artifacts."""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from datetime import datetime
from pathlib import Path
from statistics import mean
from typing import Any

try:
    from system_monitor import DEFAULT_RESULTS_ROOT, METRIC_FIELDS, MonitorError, validate_experiment_id
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitoring"))
    from system_monitor import DEFAULT_RESULTS_ROOT, METRIC_FIELDS, MonitorError, validate_experiment_id


SCENARIOS = (
    ("baseline", "Baseline"),
    ("syn_flood_no_defense", "SYN Flood No Defense"),
    ("syn_cookies", "SYN Cookies"),
    ("syn_cookies_rate_limit", "SYN Cookies + Rate Limit"),
)
TABLE_COLUMNS = (
    ("Scenario", "scenario"),
    ("Duration", "duration_seconds"),
    ("Total Packets", "total_packets"),
    ("SYN Packets", "syn_packets"),
    ("SYN-ACK Packets", "syn_ack_packets"),
    ("ACK Packets", "ack_packets"),
    ("SYN/ACK Ratio", "syn_ack_ratio"),
    ("Packet Rate", "packet_rate"),
    ("Throughput", "throughput"),
    ("CPU", "cpu_percent"),
    ("Memory", "memory_percent"),
    ("Drops", "drops"),
    ("HTTP Successful", "http_successful"),
    ("HTTP Failed", "http_failed"),
    ("HTTP Completion %", "http_completion_percent"),
)
OUTPUT_NAMES = (
    "summary.csv",
    "summary.json",
    "report.md",
    "final_comparison.csv",
    "final_comparison.json",
    "final_report.md",
)


class ResultsError(RuntimeError):
    """Invalid or incomplete experiment artifacts."""


def parse_numeric(value: str | None) -> int | float | None:
    if value is None or value.strip().lower() in ("", "null", "n/a", "na"):
        return None
    try:
        number = float(value)
    except ValueError:
        return None
    if not math.isfinite(number):
        return None
    return int(number) if number.is_integer() else number


def read_metric_rows(path: Path, experiment_id: str, scenario: str) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    try:
        with path.open(newline="", encoding="utf-8") as metrics_file:
            reader = csv.DictReader(metrics_file)
            if tuple(reader.fieldnames or ()) != METRIC_FIELDS:
                raise ResultsError(f"Unexpected metric CSV schema in {path}.")
            rows = list(reader)
    except OSError as error:
        raise ResultsError(f"Cannot read metric file {path}: {error}") from error
    for row in rows:
        if row["experiment_id"] != experiment_id or row["scenario"] != scenario:
            raise ResultsError(f"Metric row in {path} belongs to another experiment or scenario.")
    return rows


def latest_metric(rows: list[dict[str, str]], name: str) -> int | float | None:
    candidates = [row for row in rows if row["metric_name"] == name]
    if not candidates:
        return None
    candidates.sort(key=lambda row: row["timestamp"])
    latest = candidates[-1]
    if latest["status"] != "measured":
        return None
    return parse_numeric(latest["value"])


def average_metric(rows: list[dict[str, str]], name: str) -> float | None:
    values = [
        value
        for row in rows
        if row["metric_name"] == name and row["status"] == "measured"
        if (value := parse_numeric(row["value"])) is not None
    ]
    return round(mean(values), 3) if values else None


def read_legitimate_client(path: Path) -> tuple[int | None, int | None, float | None, float | None]:
    if not path.is_file():
        return None, None, None, None
    try:
        with path.open(newline="", encoding="utf-8") as result_file:
            reader = csv.DictReader(result_file)
            required = {"request_number", "timestamp_utc", "http_status", "response_time_ms", "success"}
            if not required.issubset(reader.fieldnames or ()):
                raise ResultsError(f"Unexpected legitimate-client CSV schema in {path}.")
            rows = list(reader)
    except OSError as error:
        raise ResultsError(f"Cannot read legitimate-client CSV {path}: {error}") from error
    if not rows:
        return 0, 0, 0.0, None
    successful = 0
    response_times = []
    for row in rows:
        if row["success"].strip().lower() not in ("true", "false"):
            raise ResultsError(f"Invalid success value in {path}.")
        successful += int(row["success"].strip().lower() == "true")
        response_time = parse_numeric(row["response_time_ms"])
        if response_time is not None:
            response_times.append(float(response_time))
    total = len(rows)
    completion = successful * 100 / total if total else None
    average_response = mean(response_times) if response_times else None
    return total, successful, round(completion, 3) if completion is not None else None, round(average_response, 3) if average_response is not None else None


def experiment_duration(status_path: Path) -> float | None:
    if not status_path.is_file():
        return None
    try:
        status = json.loads(status_path.read_text(encoding="utf-8"))
        start = datetime.fromisoformat(status["start_time"].replace("Z", "+00:00"))
        end = datetime.fromisoformat(status["end_time"].replace("Z", "+00:00"))
    except (OSError, KeyError, ValueError, json.JSONDecodeError, TypeError):
        return None
    seconds = (end - start).total_seconds()
    return round(seconds, 3) if seconds >= 0 else None


def select_experiments(results_root: Path) -> dict[str, tuple[str, Path]]:
    selected: dict[str, tuple[str, Path]] = {}
    if not results_root.is_dir():
        return selected
    for directory in results_root.iterdir():
        if not directory.is_dir():
            continue
        manifest_path = directory / "logs" / "experiment.json"
        if not manifest_path.is_file():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            experiment_id = validate_experiment_id(manifest["experiment_id"])
            scenario = manifest["scenario"]
            created = manifest["created_at"]
            datetime.fromisoformat(created.replace("Z", "+00:00"))
        except (OSError, KeyError, ValueError, json.JSONDecodeError, TypeError, MonitorError) as error:
            raise ResultsError(f"Invalid experiment manifest {manifest_path}: {error}") from error
        if scenario not in {key for key, _label in SCENARIOS}:
            continue
        current = selected.get(scenario)
        if current is None:
            selected[scenario] = (experiment_id, directory)
        else:
            current_manifest = json.loads((current[1] / "logs" / "experiment.json").read_text(encoding="utf-8"))
            if created > current_manifest["created_at"]:
                selected[scenario] = (experiment_id, directory)
    return selected


def collect_scenario(label: str, scenario: str, experiment: tuple[str, Path] | None) -> dict[str, Any]:
    row: dict[str, Any] = {"scenario": label, "experiment_id": None}
    for _heading, key in TABLE_COLUMNS[1:]:
        row[key] = None
    row["average_response_time_ms"] = None
    row["capture_duration_seconds"] = None
    row["status"] = "unavailable"
    if experiment is None:
        return row

    experiment_id, directory = experiment
    manifest = json.loads((directory / "logs" / "experiment.json").read_text(encoding="utf-8"))
    if manifest.get("scenario") != scenario:
        raise ResultsError(f"Scenario manifest mismatch in {directory}.")
    status_path = directory / "logs" / "scenario_status.json"
    status = json.loads(status_path.read_text(encoding="utf-8")) if status_path.is_file() else {}
    raw_rows = read_metric_rows(directory / "raw" / "metrics.csv", experiment_id, scenario)
    processed_rows = read_metric_rows(directory / "processed" / "metrics.csv", experiment_id, scenario)
    all_rows = [*raw_rows, *processed_rows]

    row.update({
        "experiment_id": experiment_id,
        "duration_seconds": experiment_duration(status_path),
        "total_packets": latest_metric(all_rows, "network_total_packets"),
        "syn_packets": latest_metric(all_rows, "network_syn_packets"),
        "syn_ack_packets": latest_metric(all_rows, "network_syn_ack_packets"),
        "ack_packets": latest_metric(all_rows, "network_ack_packets"),
        "packet_rate": latest_metric(all_rows, "network_packet_rate"),
        "throughput": latest_metric(all_rows, "network_throughput"),
        "drops": latest_metric(all_rows, "network_dropped_packets"),
        "cpu_percent": average_metric(raw_rows, "server_cpu_utilization"),
        "memory_percent": average_metric(raw_rows, "server_memory_utilization"),
        "capture_duration_seconds": latest_metric(all_rows, "network_capture_duration_seconds"),
        "status": status.get("status", "unknown"),
    })
    syn = row["syn_packets"]
    syn_ack = row["syn_ack_packets"]
    row["syn_ack_ratio"] = syn / syn_ack if syn is not None and syn_ack not in (None, 0) else None

    total, successful, completion, response_time = read_legitimate_client(directory / "raw" / "legitimate_http.csv")
    if total is None:
        total = latest_metric(processed_rows, "http_total_requests")
        successful = latest_metric(processed_rows, "http_successful_requests")
        if total is not None and successful is not None:
            total = int(total)
            successful = int(successful)
            completion = successful * 100 / total if total else None
            completion = round(completion, 3) if completion is not None else None
        response_time = latest_metric(processed_rows, "http_average_response_time_ms")
    row["http_successful"] = successful
    row["http_failed"] = total - successful if total is not None and successful is not None else None
    row["http_completion_percent"] = completion
    row["average_response_time_ms"] = response_time
    return row


def format_value(value: Any, precision: int = 3) -> str:
    if value is None or value == "":
        return "N/A"
    if isinstance(value, float):
        return f"{value:.{precision}f}"
    return str(value)


def build_report(rows: list[dict[str, Any]]) -> str:
    try:
        import yaml
        config = yaml.safe_load((PROJECT_ROOT / "config" / "config.yaml").read_text(encoding="utf-8"))
    except (ImportError, OSError, ValueError) as error:
        raise ResultsError(f"Cannot read experimental configuration for report: {error}") from error
    topology = config.get("topology", {})
    traffic = config.get("traffic", {})
    rate_limit = config.get("rate_limit", {})
    detection = config.get("detection", {})
    headers = [header for header, _key in TABLE_COLUMNS]
    lines = [
        "# DDoS Campus LAN Experiment Comparison",
        "",
        "Results are measured from the local Mininet experiment artifacts. No research-paper values or synthetic results are inserted.",
        "",
        "## Experimental Configuration",
        "",
        f"- Legitimate request rate/duration/timeout: {format_value(traffic.get('legitimate_rate_requests_per_second'))} req/s / {format_value(traffic.get('legitimate_duration_seconds'))} s / {format_value(traffic.get('legitimate_timeout_seconds'))} s.",
        f"- Bounded SYN workload configuration: {format_value(traffic.get('syn_packet_count'))} packets, {format_value(traffic.get('syn_rate_packets_per_second'))} packets/s, {format_value(traffic.get('syn_duration_seconds'))} s, {format_value(traffic.get('syn_packet_size_bytes'))} bytes.",
        f"- Experimental router rate-limit parameter: {rate_limit.get('syn_rate', 'N/A')} with burst {format_value(rate_limit.get('burst'))}; this is not claimed to be optimal.",
        "- SYN Cookies and rate limits were applied only inside the configured Mininet namespaces.",
        "",
        "## Topology",
        "",
        f"- OVS core: {topology.get('nodes', {}).get('core_switch', 'N/A')}; internal router: {topology.get('nodes', {}).get('campus_router', 'N/A')}.",
        "- Student/Lab VLAN 30 -> routed core -> DMZ VLAN 10 web server at 10.10.10.100:80.",
        "- The edge /30 is internal to Mininet; no NAT or external forwarding is enabled.",
        "",
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    for row in rows:
        lines.append("| " + " | ".join(format_value(row[key]) for _heading, key in TABLE_COLUMNS) + " |")
    by_scenario = {row["scenario_key"]: row for row in rows}
    lines.extend(["", "## Scenario Results", ""])
    for key, heading in SCENARIOS:
        result = by_scenario.get(key, {})
        lines.extend([
            f"### {heading}",
            "",
            f"- Experiment ID: {format_value(result.get('experiment_id'))}",
            f"- Status: {format_value(result.get('status'))}",
            f"- Total/SYN/SYN-ACK/ACK packets: {format_value(result.get('total_packets'))} / {format_value(result.get('syn_packets'))} / {format_value(result.get('syn_ack_packets'))} / {format_value(result.get('ack_packets'))}.",
            f"- HTTP successful/failed/completion: {format_value(result.get('http_successful'))} / {format_value(result.get('http_failed'))} / {format_value(result.get('http_completion_percent'))}%.",
            "",
        ])

    lines.extend([
        "## Packet Analysis",
        "",
        "Packet counts, TCP flags, rates, and approximate throughput are derived from the saved server-facing PCAP. Missing capture data is N/A.",
        "",
        "## CPU Analysis",
        "",
        "CPU utilization is the arithmetic mean of measured psutil process samples for the DMZ HTTP server.",
        "",
        "## Memory Analysis",
        "",
        "Memory utilization is the arithmetic mean of measured psutil process memory percentages.",
        "",
        "## HTTP Availability",
        "",
        "HTTP completion percentage = successful legitimate HTTP responses / total legitimate HTTP requests * 100. Requests without an actual response are failures; absent request logs are N/A.",
        "",
        "## SYN/ACK Comparison",
        "",
        "SYN/ACK ratio = initial SYN packets / SYN-ACK packets. This ratio is only a handshake imbalance indicator; it is not a percentage of failed connections.",
        "",
    ])
    attack = by_scenario.get("syn_flood_no_defense", {})
    lines.extend(["## Mitigation Comparison", ""])
    for key, label in (("syn_cookies", "SYN Cookies"), ("syn_cookies_rate_limit", "SYN Cookies + Rate Limit")):
        mitigation = by_scenario.get(key, {})
        cpu_attack = attack.get("cpu_percent")
        cpu_mitigation = mitigation.get("cpu_percent")
        if cpu_attack is None or cpu_mitigation is None or cpu_attack == 0:
            cpu_reduction = "N/A"
        else:
            cpu_reduction = f"{(cpu_attack - cpu_mitigation) / cpu_attack * 100:.3f}%"
        http_attack = attack.get("http_completion_percent")
        http_mitigation = mitigation.get("http_completion_percent")
        http_recovery = "N/A" if http_attack is None or http_mitigation is None else f"{http_mitigation - http_attack:.3f} percentage points"
        lines.append(f"- {label}: CPU reduction versus SYN Flood No Defense = {cpu_reduction}; HTTP completion recovery versus SYN Flood No Defense = {http_recovery}.")
    lines.extend([
        "",
        "## Limitations",
        "",
        "Results depend on the local Ubuntu kernel, Mininet/OVS versions, host resources, and configured experimental parameters. Sender-reported SYN transmissions do not prove delivery. Tcpdump drops are reported only when the capture process supplies them. A missing metric is not estimated.",
        "",
        "## Reproducibility",
        "",
        "Each row references an experiment ID with raw/, processed/, logs/, and pcap/ artifacts. Scenario settings are recorded in each experiment manifest and orchestration log. Re-running with an existing ID or summary output is refused; use a new experiment ID and preserve earlier artifacts.",
        "",
        "Missing measurements are shown as N/A. CPU reduction uses measured mean CPU versus the no-defense SYN Flood scenario. HTTP recovery is the completion-rate percentage-point difference from that same attack baseline.",
        "",
    ])
    return "\n".join(lines)


def generate(results_root: Path) -> list[dict[str, Any]]:
    results_root = results_root.resolve()
    selected = select_experiments(results_root)
    rows = []
    for scenario_key, label in SCENARIOS:
        row = collect_scenario(label, scenario_key, selected.get(scenario_key))
        row["scenario_key"] = scenario_key
        rows.append(row)

    output_csv = results_root / "summary.csv"
    output_json = results_root / "summary.json"
    report_md = results_root / "report.md"
    final_csv = results_root / "final_comparison.csv"
    final_json = results_root / "final_comparison.json"
    final_md = results_root / "final_report.md"
    outputs = (output_csv, output_json, report_md, final_csv, final_json, final_md)
    existing = [str(path) for path in outputs if path.exists()]
    if existing:
        raise ResultsError("Refusing to overwrite existing comparison output(s): " + ", ".join(existing))
    results_root.mkdir(parents=True, exist_ok=True)

    public_rows = [{key: value for key, value in row.items() if key != "scenario_key"} for row in rows]
    headers = [key for _heading, key in TABLE_COLUMNS] + ["experiment_id", "average_response_time_ms", "status"]
    with output_csv.open("x", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=headers, extrasaction="ignore")
        writer.writeheader()
        for row in public_rows:
            writer.writerow({key: "N/A" if row.get(key) is None else row[key] for key in headers})
    json_text = json.dumps({"generated_at": datetime.now().astimezone().isoformat(), "scenarios": public_rows}, indent=2, sort_keys=True) + "\n"
    report_text = build_report(rows)
    for path, content in (
        (output_json, json_text),
        (report_md, report_text),
        (final_csv, output_csv.read_text(encoding="utf-8")),
        (final_json, json_text),
        (final_md, report_text),
    ):
        with path.open("x", encoding="utf-8") as output_file:
            output_file.write(content)
    return public_rows


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    args = parser.parse_args()
    try:
        rows = generate(args.results_root)
        print(f"Generated measured summaries for {sum(row['experiment_id'] is not None for row in rows)}/4 scenarios in {args.results_root}.")
        return 0
    except (ResultsError, MonitorError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
