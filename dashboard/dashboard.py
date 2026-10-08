#!/usr/bin/env python3
"""Local-only dashboard for measured Mininet experiment artifacts."""

from __future__ import annotations

import argparse
import csv
import html
import json
import os
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_RESULTS_ROOT = PROJECT_ROOT / "results"
SCENARIO_LABELS = {
    "baseline": "Baseline",
    "syn_flood_no_defense": "SYN Flood No Defense",
    "syn_cookies": "SYN Cookies",
    "syn_cookies_rate_limit": "SYN Cookies + Rate Limit",
}
METRIC_LABELS = {
    "network_total_packets": "Total packets",
    "network_syn_rate": "SYN rate",
    "security_syn_ack_ratio": "SYN/ACK ratio",
    "server_cpu_utilization": "CPU utilization",
    "server_memory_utilization": "Memory utilization",
    "network_throughput": "Packet throughput",
    "network_dropped_packets": "Packet drops",
    "http_completion_percentage": "HTTP success rate",
    "http_average_response_time_ms": "Average response time",
}


class DashboardError(RuntimeError):
    """Invalid local dashboard data or configuration."""


def parse_value(value: str | None) -> float | None:
    if value is None or value.strip().lower() in ("", "null", "n/a", "na"):
        return None
    try:
        number = float(value)
    except ValueError:
        return None
    return number if number == number and abs(number) != float("inf") else None


def read_metric_rows(path: Path, experiment_id: str, scenario: str) -> list[dict[str, str]]:
    if not path.is_file():
        return []
    try:
        with path.open(newline="", encoding="utf-8") as metric_file:
            reader = csv.DictReader(metric_file)
            required = {"timestamp", "experiment_id", "scenario", "metric_name", "value", "unit", "status"}
            if not required.issubset(reader.fieldnames or ()):
                return []
            return [
                row for row in reader
                if row.get("experiment_id") == experiment_id and row.get("scenario") == scenario
            ]
    except OSError:
        return []


def process_is_running(pid: Any) -> bool:
    try:
        process_id = int(pid)
        if process_id <= 0:
            return False
        cmdline = Path(f"/proc/{process_id}/cmdline").read_bytes().replace(b"\0", b" ").decode(errors="replace")
        return "topology/campus_topology.py" in cmdline and "--run-scenario" in cmdline
    except (OSError, TypeError, ValueError):
        return False


def load_experiments(results_root: Path) -> list[dict[str, Any]]:
    if not results_root.is_dir():
        return []
    experiments = []
    for directory in results_root.iterdir():
        manifest_path = directory / "logs" / "experiment.json"
        if not directory.is_dir() or not manifest_path.is_file():
            continue
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        experiment_id = manifest.get("experiment_id")
        scenario = manifest.get("scenario")
        if not isinstance(experiment_id, str) or not isinstance(scenario, str):
            continue
        raw_rows = read_metric_rows(directory / "raw" / "metrics.csv", experiment_id, scenario)
        processed_rows = read_metric_rows(directory / "processed" / "metrics.csv", experiment_id, scenario)
        http_rows = read_metric_rows(directory / "raw" / "http_requests.csv", experiment_id, scenario)
        status_path = directory / "logs" / "scenario_status.json"
        try:
            scenario_status = json.loads(status_path.read_text(encoding="utf-8")) if status_path.is_file() else {}
        except (OSError, json.JSONDecodeError):
            scenario_status = {}
        is_live = scenario_status.get("status") == "running" and process_is_running(scenario_status.get("runner_pid"))
        experiments.append({
            "experiment_id": experiment_id,
            "scenario": scenario,
            "scenario_label": SCENARIO_LABELS.get(scenario, scenario),
            "created_at": manifest.get("created_at", ""),
            "status": scenario_status.get("status", "artifacts only"),
            "live": is_live,
            "raw_rows": raw_rows,
            "processed_rows": processed_rows,
            "http_rows": http_rows,
            "directory": directory,
        })
    return sorted(experiments, key=lambda item: item["created_at"], reverse=True)


def latest_value(experiment: dict[str, Any], metric_name: str) -> tuple[float | None, str]:
    rows = [*experiment["raw_rows"], *experiment["processed_rows"]]
    rows = [row for row in rows if row["metric_name"] == metric_name]
    if not rows:
        return None, ""
    rows.sort(key=lambda row: row.get("timestamp", ""))
    row = rows[-1]
    if row.get("status") != "measured":
        return None, row.get("unit", "")
    return parse_value(row.get("value")), row.get("unit", "")


def average_value(experiment: dict[str, Any], metric_name: str) -> tuple[float | None, str]:
    values = [
        parsed
        for row in experiment["raw_rows"]
        if row["metric_name"] == metric_name and row.get("status") == "measured"
        if (parsed := parse_value(row.get("value"))) is not None
    ]
    rows = [row for row in experiment["raw_rows"] if row["metric_name"] == metric_name]
    return (sum(values) / len(values) if values else None, rows[-1].get("unit", "") if rows else "")


def http_completion(experiment: dict[str, Any]) -> tuple[float | None, float | None, int | None, int | None]:
    records: dict[str, dict[str, str]] = {}
    for row in experiment["http_rows"]:
        if row["metric_name"] == "http_request_total":
            records[row.get("request_id", "")] = {"timestamp": row.get("timestamp", "")}
        elif row["metric_name"] in ("http_request_success", "http_response_time_ms"):
            records.setdefault(row.get("request_id", ""), {})[row["metric_name"]] = row.get("value", "")
    if records:
        successful = sum(record.get("http_request_success") == "1" for record in records.values())
        total = len(records)
        elapsed = [parse_value(record.get("http_response_time_ms")) for record in records.values()]
        response_times = [value for value in elapsed if value is not None]
        return (
            successful * 100 / total if total else None,
            sum(response_times) / len(response_times) if response_times else None,
            successful,
            total - successful,
        )
    value, _unit = latest_value(experiment, "http_completion_percentage")
    avg, _unit = latest_value(experiment, "http_average_response_time_ms")
    success, _unit = latest_value(experiment, "http_successful_requests")
    failed, _unit = latest_value(experiment, "http_failed_requests")
    return value, avg, int(success) if success is not None else None, int(failed) if failed is not None else None


def mitigation_status(experiment: dict[str, Any]) -> str:
    logs = experiment["directory"] / "logs"
    states = []
    cookies = logs / "syn_cookies_state.json"
    if cookies.is_file():
        try:
            state = json.loads(cookies.read_text(encoding="utf-8"))
            states.append(f"SYN Cookies {'enabled' if state.get('applied') else 'restored'}")
        except (OSError, json.JSONDecodeError):
            states.append("SYN Cookie state unavailable")
    rate_limit = logs / "rate_limit_state.json"
    if rate_limit.is_file():
        try:
            state = json.loads(rate_limit.read_text(encoding="utf-8"))
            states.append(f"Rate limit {'active' if state.get('applied') else 'removed'}")
        except (OSError, json.JSONDecodeError):
            states.append("Rate-limit state unavailable")
    return ", ".join(states) if states else "None recorded"


def graph_points(experiment: dict[str, Any], metric_name: str) -> list[tuple[str, float]]:
    points = []
    for row in [*experiment["raw_rows"], *experiment["processed_rows"]]:
        if row["metric_name"] != metric_name or row.get("status") != "measured":
            continue
        value = parse_value(row.get("value"))
        if value is not None:
            points.append((row.get("timestamp", ""), value))
    points.sort(key=lambda point: point[0])
    if metric_name in ("http_completion_percentage", "http_average_response_time_ms"):
        request_points = []
        grouped: dict[str, dict[str, str]] = {}
        for row in experiment["http_rows"]:
            request_id = row.get("request_id", "")
            grouped.setdefault(request_id, {"timestamp": row.get("timestamp", "")})
            if row["metric_name"] == "http_request_success":
                grouped[request_id]["success"] = row["value"]
            elif row["metric_name"] == "http_response_time_ms":
                grouped[request_id]["response_time"] = row["value"]
        successes = 0
        count = 0
        for request_id, record in sorted(grouped.items(), key=lambda item: item[1].get("timestamp", "")):
            if "success" not in record:
                continue
            count += 1
            successes += int(record["success"] == "1")
            if metric_name == "http_completion_percentage":
                request_points.append((record["timestamp"], successes * 100 / count))
            else:
                response_time = parse_value(record.get("response_time"))
                if response_time is not None:
                    request_points.append((record["timestamp"], response_time))
        if request_points:
            return request_points
    return points


def svg_chart(title: str, points: list[tuple[str, float]], color: str) -> str:
    escaped_title = html.escape(title)
    if not points:
        return f'<section class="chart"><h3>{escaped_title}</h3><p class="empty">No measurements available.</p></section>'
    values = [value for _timestamp, value in points]
    minimum = min(values)
    maximum = max(values)
    span = maximum - minimum or 1.0
    coordinates = []
    for index, value in enumerate(values):
        x = 24 + index * 592 / max(1, len(values) - 1)
        y = 135 - (value - minimum) * 110 / span
        coordinates.append(f"{x:.1f},{y:.1f}")
    polyline = " ".join(coordinates)
    return (
        f'<section class="chart"><h3>{escaped_title}</h3>'
        f'<svg viewBox="0 0 640 170" role="img" aria-label="{escaped_title} over time">'
        f'<path d="M24 135H616" stroke="#cbd5e1" stroke-width="1" />'
        f'<polyline fill="none" stroke="{color}" stroke-width="3" points="{polyline}" />'
        f'<text x="24" y="158">{minimum:.3g}</text><text x="566" y="158">{maximum:.3g}</text>'
        "</svg></section>"
    )


def render_dashboard(results_root: Path) -> str:
    experiments = load_experiments(results_root)
    live = next((experiment for experiment in experiments if experiment["live"]), None)
    historical = next((experiment for experiment in experiments if not experiment["live"]), None)
    selected = live or historical
    if selected is None:
        return """<!doctype html><html lang="en"><meta charset="utf-8"><title>Campus Lab Dashboard</title>
<style>body{font:16px system-ui;background:#f4f7f8;color:#142c3a;margin:0;padding:4rem}main{max-width:800px;margin:auto;border-top:5px solid #0f766e;padding:2rem;background:white}h1{font-size:2rem}.tag{color:#64748b}</style>
<main><p class="tag">DDoS CAMPUS LAB / LOCAL</p><h1>Experiment Dashboard</h1><p>No experiment data available.</p></main></html>"""

    experiment_id = html.escape(selected["experiment_id"])
    scenario = html.escape(selected["scenario_label"])
    live_label = "LIVE MEASUREMENT" if live else "HISTORICAL EXPERIMENT"
    status = html.escape(str(selected["status"]).upper())
    total_packets, total_unit = latest_value(selected, "network_total_packets")
    syn_rate, syn_unit = latest_value(selected, "security_syn_rate")
    ratio, _ = latest_value(selected, "security_syn_ack_ratio")
    cpu, _ = average_value(selected, "server_cpu_utilization")
    memory, _ = average_value(selected, "server_memory_utilization")
    throughput, throughput_unit = latest_value(selected, "network_throughput")
    drops, _ = latest_value(selected, "network_dropped_packets")
    http_rate, _response_time, http_successful, http_failed = http_completion(selected)
    response_time, _ = http_completion(selected)[:2]
    mitigation = html.escape(mitigation_status(selected))

    metric_values = [
        ("Total packets", total_packets, total_unit or "packets"),
        ("SYN rate", syn_rate, syn_unit or "packets/s"),
        ("SYN/ACK ratio", ratio, "ratio"),
        ("CPU utilization", cpu, "%"),
        ("Memory utilization", memory, "%"),
        ("Packet throughput", throughput, throughput_unit or "bit/s"),
        ("Packet drops", drops, "packets"),
        ("HTTP success rate", http_rate, "%"),
        ("Average response time", response_time, "ms"),
        ("HTTP requests", http_successful, "successful"),
        ("HTTP failures", http_failed, "failed"),
        ("Mitigation status", mitigation, ""),
    ]
    cards = "".join(
        f'<article class="metric"><span>{html.escape(label)}</span><strong>{html.escape(format_metric(value))}</strong><small>{html.escape(unit)}</small></article>'
        for label, value, unit in metric_values
    )
    chart_specs = (
        ("Packets over time", "network_total_packets", "#0f766e"),
        ("SYN packets over time", "network_syn_packets", "#d97706"),
        ("SYN/ACK ratio over time", "security_syn_ack_ratio", "#be123c"),
        ("CPU utilization over time", "server_cpu_utilization", "#2563eb"),
        ("Memory utilization over time", "server_memory_utilization", "#7c3aed"),
        ("HTTP completion over time", "http_completion_percentage", "#0891b2"),
        ("Throughput over time", "network_throughput", "#4d7c0f"),
    )
    charts = "".join(svg_chart(title, graph_points(selected, metric), color) for title, metric, color in chart_specs)

    comparison_rows = []
    for experiment in experiments:
        completion, _avg, successes, failures = http_completion(experiment)
        total, _unit = latest_value(experiment, "network_total_packets")
        ratio_value, _unit = latest_value(experiment, "security_syn_ack_ratio")
        comparison_rows.append(
            "<tr>"
            f"<td>{html.escape(experiment['scenario_label'])}</td>"
            f"<td>{html.escape(experiment['experiment_id'])}</td>"
            f"<td>{html.escape(format_metric(total))}</td>"
            f"<td>{html.escape(format_metric(ratio_value))}</td>"
            f"<td>{html.escape(format_metric(completion))}%</td>"
            f"<td>{html.escape(format_metric(successes))}</td>"
            f"<td>{html.escape(format_metric(failures))}</td></tr>"
        )
    comparison = "".join(comparison_rows) or '<tr><td colspan="7">No experiment data available.</td></tr>'
    refresh = '<meta http-equiv="refresh" content="5">' if live else ""
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">{refresh}
<meta name="viewport" content="width=device-width, initial-scale=1"><title>Campus Lab Dashboard</title>
<style>
:root{{--ink:#142c3a;--muted:#60717b;--paper:#f4f7f8;--teal:#0f766e;--line:#dbe4e8;--white:#fff}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:15px/1.45 system-ui,sans-serif}}
header{{background:#102a34;color:#fff;padding:1.4rem max(1.4rem,calc((100vw - 1320px)/2));display:flex;justify-content:space-between;align-items:center;gap:1rem}}
header small{{display:block;color:#b9c9cc;letter-spacing:.08em}}h1{{font-size:1.35rem;margin:.25rem 0 0}}main{{max-width:1320px;margin:1.5rem auto;padding:0 1.2rem}}
.statusbar{{display:flex;flex-wrap:wrap;gap:.7rem 1.5rem;align-items:center;padding:1rem 0;border-bottom:1px solid var(--line)}}
.badge{{font-size:.75rem;font-weight:700;padding:.35rem .6rem;background:#dff5ef;color:#075e56;border-radius:3px}}
.badge.history{{background:#e8eef2;color:#44545d}}.muted{{color:var(--muted)}}h2{{font-size:1.05rem;margin:1.8rem 0 .8rem}}
.metrics{{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));border-top:1px solid var(--line);border-left:1px solid var(--line);background:white}}
.metric{{min-height:100px;padding:1rem;border-right:1px solid var(--line);border-bottom:1px solid var(--line);display:flex;flex-direction:column;gap:.25rem}}
.metric span,.metric small{{color:var(--muted);font-size:.82rem}}.metric strong{{font-size:1.35rem;overflow-wrap:anywhere}}
.charts{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem}}.chart{{background:white;border:1px solid var(--line);padding:.85rem;min-width:0}}
.chart h3{{font-size:.9rem;margin:0 0 .5rem}}svg{{width:100%;height:auto;max-height:190px}}svg text{{fill:var(--muted);font-size:11px}}.empty{{color:var(--muted);min-height:80px}}
.tablewrap{{overflow-x:auto;background:white;border:1px solid var(--line)}}table{{width:100%;border-collapse:collapse;min-width:750px}}th,td{{text-align:left;padding:.7rem;border-bottom:1px solid var(--line)}}th{{font-size:.8rem;color:var(--muted);background:#f8fafb}}
@media(max-width:800px){{.metrics{{grid-template-columns:repeat(2,minmax(0,1fr))}}.charts{{grid-template-columns:1fr}}header{{align-items:flex-start;flex-direction:column}}}}
</style></head><body><header><div><small>DDOS CAMPUS LAB / LOCAL TELEMETRY</small><h1>Experiment Dashboard</h1></div><span class="badge {'history' if not live else ''}">{live_label}</span></header>
<main><div class="statusbar"><strong>{scenario}</strong><span class="muted">{experiment_id}</span><span class="muted">Status: {status}</span><span class="muted">Mitigation: {mitigation}</span></div>
<h2>Current measurements</h2><section class="metrics">{cards}</section><h2>Measurement history</h2><section class="charts">{charts}</section>
<h2>Scenario comparison</h2><div class="tablewrap"><table><thead><tr><th>Scenario</th><th>Experiment</th><th>Packets</th><th>SYN/ACK</th><th>HTTP completion</th><th>HTTP success</th><th>HTTP failed</th></tr></thead><tbody>{comparison}</tbody></table></div>
<p class="muted">Displayed values are read from local experiment artifacts. Missing measurements are N/A; no values are estimated.</p></main></body></html>"""


def format_metric(value: Any) -> str:
    if value is None:
        return "N/A"
    if isinstance(value, float):
        return f"{value:.3f}"
    return str(value)


def create_app(results_root: Path = DEFAULT_RESULTS_ROOT) -> Any:
    try:
        from flask import Flask, Response
    except ImportError as error:
        raise DashboardError("Flask is required; install the project requirements.") from error
    app = Flask(__name__)

    @app.get("/")
    def index() -> Response:
        return Response(render_dashboard(results_root), mimetype="text/html")

    return app


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--port", type=int, default=5050)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("--port must be between 1 and 65535")
    try:
        app = create_app(args.results_root.resolve())
    except DashboardError as error:
        print(f"ERROR: {error}", file=sys.stderr)
        return 1
    print(f"Dashboard available locally at http://127.0.0.1:{args.port}/", flush=True)
    app.run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
