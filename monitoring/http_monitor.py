#!/usr/bin/env python3
"""Isolated DMZ HTTP service and request-log summarizer."""

from __future__ import annotations

import argparse
import csv
import json
import math
import os
import signal
import sys
import time
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener

try:
    from system_monitor import (
        DEFAULT_RESULTS_ROOT,
        METRIC_FIELDS,
        MonitorError as ExperimentMonitorError,
        append_metric_records,
        experiment_directory,
        make_metric_record,
        validate_experiment_id,
        validate_experiment_metadata,
        validate_scenario,
    )
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    from system_monitor import (
        DEFAULT_RESULTS_ROOT,
        METRIC_FIELDS,
        MonitorError as ExperimentMonitorError,
        append_metric_records,
        experiment_directory,
        make_metric_record,
        validate_experiment_id,
        validate_experiment_metadata,
        validate_scenario,
    )


DMZ_SERVER_IP = "10.10.10.100"
HTTP_PORT = 80
DEFAULT_ROOT_RESPONSE = "Campus Mininet web server is online."
FLUSH_EVERY_REQUESTS = 32


class MonitorError(ExperimentMonitorError):
    """Invalid monitor input or an HTTP health-check failure."""


class RequestCounters:
    def __init__(self) -> None:
        self.total_requests = 0
        self.successful_requests = 0
        self.response_time_total_ms = 0.0

    def record(self, successful: bool, response_time_ms: float) -> None:
        self.total_requests += 1
        self.response_time_total_ms += response_time_ms
        if successful:
            self.successful_requests += 1

    def snapshot(self) -> dict[str, int | float | None]:
        total = self.total_requests
        successful = self.successful_requests
        return {
            "total_requests": total,
            "successful_requests": successful,
            "failed_requests": total - successful,
            "http_completion_percentage": round(successful * 100 / total, 3) if total else None,
            "average_response_time_ms": round(self.response_time_total_ms / total, 3) if total else None,
        }


class CsvRequestLog:
    """Buffer per-request metric rows using the shared experiment CSV schema."""

    def __init__(self, path: Path, experiment_id: str, scenario: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.stream = path.open("x", newline="", encoding="utf-8", buffering=65536)
        self.writer = csv.DictWriter(self.stream, fieldnames=METRIC_FIELDS, extrasaction="raise")
        self.writer.writeheader()
        self.stream.flush()
        self.experiment_id = experiment_id
        self.scenario = scenario
        self.pending = 0

    def write_request(self, timestamp: str, request_id: str, metrics: list[tuple[str, Any, str]]) -> None:
        rows = []
        for metric_name, value, unit in metrics:
            record = make_metric_record(
                self.experiment_id,
                self.scenario,
                metric_name,
                value,
                unit,
                timestamp=timestamp,
                request_id=request_id,
            )
            rows.append({
                field: "null" if record[field] is None else
                "true" if record[field] is True else
                "false" if record[field] is False else str(record[field])
                for field in METRIC_FIELDS
            })
        self.writer.writerows(rows)
        self.pending += 1
        if self.pending >= FLUSH_EVERY_REQUESTS:
            self.flush()

    def flush(self) -> None:
        self.stream.flush()
        self.pending = 0

    def close(self) -> None:
        self.flush()
        self.stream.close()


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


class CampusRequestHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"
    server_version = "CampusLabHTTP/1.0"
    sys_version = ""

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def __getattr__(self, name: str) -> Any:
        if name.startswith("do_"):
            return self._method_not_allowed
        raise AttributeError(name)

    def do_GET(self) -> None:
        self._handle_request(send_body=True, method_allowed=True)

    def do_HEAD(self) -> None:
        self._handle_request(send_body=False, method_allowed=True)

    def _method_not_allowed(self) -> None:
        self._handle_request(send_body=self.command != "HEAD", method_allowed=False)

    def _handle_request(self, send_body: bool, method_allowed: bool) -> None:
        start_ns = time.perf_counter_ns()
        timestamp = utc_timestamp()
        request_path = urlsplit(self.path).path
        status, content_type, body = self._response(request_path, method_allowed)
        completed = False
        error_name: str | None = None

        try:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            if send_body:
                self.wfile.write(body)
            self.wfile.flush()
            completed = True
        except OSError as error:
            error_name = type(error).__name__
        finally:
            response_time_ms = round((time.perf_counter_ns() - start_ns) / 1_000_000, 3)
            successful = completed and 200 <= status < 300
            record: dict[str, Any] = {
                "timestamp": timestamp,
                "method": self.command,
                "path": self.path,
                "client_ip": self.client_address[0],
                "status": status,
                "response_time_ms": response_time_ms,
                "completed": completed,
                "successful": successful,
            }
            if error_name is not None:
                record["write_error"] = error_name
            self.server.request_counters.record(successful, response_time_ms)
            counters = self.server.request_counters.snapshot()
            request_id = f"{os.getpid()}-{counters['total_requests']}"
            self.server.request_log.write_request(
                timestamp,
                request_id,
                [
                    ("http_request_total", 1, "request"),
                    ("http_status_code", status, "HTTP status"),
                    ("http_response_time_ms", response_time_ms, "ms"),
                    ("http_request_success", int(successful), "boolean"),
                    ("http_total_requests", counters["total_requests"], "requests"),
                    ("http_successful_requests", counters["successful_requests"], "requests"),
                    ("http_failed_requests", counters["failed_requests"], "requests"),
                    ("http_completion_percentage", counters["http_completion_percentage"], "%"),
                    ("http_average_response_time_ms", counters["average_response_time_ms"], "ms"),
                ],
            )
            self.close_connection = True

    def _response(self, path: str, method_allowed: bool) -> tuple[int, str, bytes]:
        if not method_allowed:
            return 405, "text/plain; charset=utf-8", b"Method not allowed.\n"
        if path == "/":
            return 200, "text/plain; charset=utf-8", (self.server.root_response + "\n").encode("utf-8")
        if path == "/health":
            body = json.dumps(
                {
                    "status": "ok",
                    "successful_requests_before_this_request": self.server.request_counters.successful_requests,
                },
                separators=(",", ":"),
            ).encode("utf-8")
            return 200, "application/json; charset=utf-8", body
        if path == "/metrics":
            body = json.dumps(
                self.server.request_counters.snapshot(),
                separators=(",", ":"),
            ).encode("utf-8")
            return 200, "application/json; charset=utf-8", body
        return 404, "text/plain; charset=utf-8", b"Not found.\n"


def validate_health_url(url: str) -> None:
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise MonitorError(f"Invalid health-check URL: {error}") from error
    if (
        parsed.scheme != "http"
        or parsed.hostname != DMZ_SERVER_IP
        or port not in (None, HTTP_PORT)
        or parsed.path != "/health"
        or parsed.query
        or parsed.fragment
    ):
        raise MonitorError(f"Health checks are restricted to http://{DMZ_SERVER_IP}/health inside Mininet.")


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def check_health(url: str, timeout: float = 2.0) -> dict[str, Any]:
    validate_health_url(url)
    if not math.isfinite(timeout) or timeout <= 0:
        raise MonitorError("Health-check timeout must be a positive finite number.")

    request = Request(url, headers={"Connection": "close", "User-Agent": "CampusLabHealthCheck/1.0"})
    try:
        with build_opener(NoRedirectHandler()).open(request, timeout=timeout) as response:
            status = response.status
            payload = response.read(4096)
    except HTTPError as error:
        raise MonitorError(f"DMZ HTTP health check returned HTTP {error.code}.") from error
    except (URLError, TimeoutError, OSError) as error:
        raise MonitorError(f"DMZ HTTP health check could not reach {url}: {error}") from error

    if status != 200:
        raise MonitorError(f"DMZ HTTP health check expected HTTP 200, received HTTP {status}.")
    try:
        health_data = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise MonitorError("DMZ /health returned HTTP 200 but its JSON response was invalid.") from error
    if not isinstance(health_data, dict) or health_data.get("status") != "ok":
        raise MonitorError(f"DMZ /health reported an unhealthy response: {health_data!r}.")
    return {"status": "ok", "http_status": status, "url": url}


def summarize_log(
    path: Path,
    experiment_id: str,
    scenario: str,
    results_root: Path = DEFAULT_RESULTS_ROOT,
) -> dict[str, int | float | None]:
    validate_experiment_id(experiment_id)
    validate_scenario(scenario)
    try:
        with path.open(encoding="utf-8") as request_log:
            reader = csv.DictReader(request_log)
            if tuple(reader.fieldnames or ()) != METRIC_FIELDS:
                raise MonitorError(f"Unexpected HTTP raw CSV header in {path}.")
            requests: dict[str, dict[str, Any]] = {}
            for line_number, row in enumerate(reader, start=2):
                if row["experiment_id"] != experiment_id or row["scenario"] != scenario:
                    raise MonitorError(f"HTTP raw CSV row {line_number} belongs to another experiment or scenario.")
                request_id = row["request_id"]
                if not request_id:
                    raise MonitorError(f"HTTP raw CSV row {line_number} has no request ID.")
                try:
                    timestamp = datetime.fromisoformat(row["timestamp"].replace("Z", "+00:00"))
                except ValueError as error:
                    raise MonitorError(f"HTTP raw CSV row {line_number} has an invalid timestamp.") from error
                if timestamp.tzinfo is None:
                    raise MonitorError(f"HTTP raw CSV row {line_number} has a timezone-free timestamp.")

                request = requests.setdefault(request_id, {"seen": set()})
                metric_name = row["metric_name"]
                if metric_name in request["seen"]:
                    raise MonitorError(f"HTTP raw CSV row {line_number} duplicates metric {metric_name}.")
                request["seen"].add(metric_name)
                value = row["value"]
                if metric_name in ("http_request_total", "http_request_success"):
                    if value not in ("0", "1"):
                        raise MonitorError(f"HTTP raw CSV row {line_number} has an invalid request flag.")
                    request[metric_name] = int(value)
                elif metric_name == "http_status_code":
                    try:
                        status = int(value)
                    except ValueError as error:
                        raise MonitorError(f"HTTP raw CSV row {line_number} has an invalid HTTP status.") from error
                    if not 100 <= status <= 599:
                        raise MonitorError(f"HTTP raw CSV row {line_number} has an invalid HTTP status.")
                    request["status"] = status
                elif metric_name == "http_response_time_ms":
                    try:
                        response_time = float(value)
                    except ValueError as error:
                        raise MonitorError(f"HTTP raw CSV row {line_number} has an invalid response time.") from error
                    if not math.isfinite(response_time) or response_time < 0:
                        raise MonitorError(f"HTTP raw CSV row {line_number} has an invalid response time.")
                    request["response_time_ms"] = response_time

            successful = 0
            response_time_total = 0.0
            measured_response_times = 0
            for request_id, request in requests.items():
                required_metrics = {
                    "http_request_total",
                    "http_request_success",
                    "http_status_code",
                    "http_response_time_ms",
                }
                missing_metrics = required_metrics - request["seen"]
                if missing_metrics:
                    raise MonitorError(
                        f"HTTP request {request_id} is missing metric(s): {', '.join(sorted(missing_metrics))}."
                    )
                if request.get("http_request_total") != 1:
                    raise MonitorError(f"HTTP request {request_id} has no valid total-request measurement.")
                is_successful = request.get("http_request_success") == 1
                status = request.get("status")
                if status is None or (is_successful and not 200 <= status < 300):
                    raise MonitorError(f"HTTP request {request_id} has no actual or consistent HTTP status.")
                if is_successful != (200 <= status < 300 and request.get("http_request_success") == 1):
                    raise MonitorError(f"HTTP request {request_id} success flag conflicts with its HTTP status.")
                successful += int(is_successful)
                response_time = request.get("response_time_ms")
                if response_time is not None:
                    response_time_total += response_time
                    measured_response_times += 1

            total = len(requests)
            summary = {
                "total_requests": total,
                "successful_requests": successful,
                "failed_requests": total - successful,
                "http_completion_percentage": round(successful * 100 / total, 3) if total else None,
                "average_response_time_ms": round(response_time_total / measured_response_times, 3)
                if measured_response_times
                else None,
            }
            timestamp = utc_timestamp()
            records = [
                make_metric_record(experiment_id, scenario, "http_total_requests", total, "requests", timestamp=timestamp),
                make_metric_record(experiment_id, scenario, "http_successful_requests", successful, "requests", timestamp=timestamp),
                make_metric_record(experiment_id, scenario, "http_failed_requests", total - successful, "requests", timestamp=timestamp),
                make_metric_record(experiment_id, scenario, "http_completion_percentage", summary["http_completion_percentage"], "%", timestamp=timestamp),
                make_metric_record(experiment_id, scenario, "http_average_response_time_ms", summary["average_response_time_ms"], "ms", timestamp=timestamp),
            ]
            append_metric_records(experiment_id, scenario, records, results_root=results_root, stage="processed")
            return summary
    except OSError as error:
        raise MonitorError(f"Cannot read HTTP request log {path}: {error}") from error


def serve(
    experiment_id: str,
    scenario: str,
    results_root: Path,
    host_netns_inode: int,
    bind: str,
    port: int,
    root_response: str,
) -> None:
    if bind != DMZ_SERVER_IP or port != HTTP_PORT:
        raise MonitorError(f"The service may bind only to {DMZ_SERVER_IP}:{HTTP_PORT} inside Mininet.")
    validate_experiment_id(experiment_id)
    validate_scenario(scenario)
    directory = experiment_directory(experiment_id, results_root)
    validate_experiment_metadata(directory, experiment_id, scenario)
    request_log_path = directory / "raw" / "http_requests.csv"
    try:
        current_netns_inode = os.stat("/proc/self/ns/net").st_ino
        actual_host_netns_inode = os.stat("/proc/1/ns/net").st_ino
    except OSError as error:
        raise MonitorError(f"Cannot verify DMZ network namespace identity: {error}") from error
    if current_netns_inode == actual_host_netns_inode or current_netns_inode == host_netns_inode:
        raise MonitorError("Refusing to expose the DMZ service in the host network namespace.")

    request_log = CsvRequestLog(request_log_path, experiment_id, scenario)
    try:
        server = HTTPServer((bind, port), CampusRequestHandler)
    except OSError as error:
        request_log.close()
        raise MonitorError(f"Cannot bind DMZ HTTP service to {bind}:{port}: {error}") from error
    server.timeout = 0.5
    server.root_response = root_response
    server.request_log = request_log
    server.request_counters = RequestCounters()
    stop_requested = False

    def request_stop(_signum: int, _frame: Any) -> None:
        nonlocal stop_requested
        stop_requested = True

    previous_sigterm = signal.signal(signal.SIGTERM, request_stop)
    previous_sigint = signal.signal(signal.SIGINT, request_stop)
    print(f"HTTP service listening on {bind}:{port}; request log: {request_log_path}", flush=True)
    try:
        while not stop_requested:
            server.handle_request()
    finally:
        server.server_close()
        request_log.close()
        signal.signal(signal.SIGTERM, previous_sigterm)
        signal.signal(signal.SIGINT, previous_sigint)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)

    serve_parser = commands.add_parser("serve", help="run the isolated DMZ HTTP service")
    serve_parser.add_argument("--experiment-id", required=True)
    serve_parser.add_argument("--scenario", required=True)
    serve_parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    serve_parser.add_argument("--host-netns-inode", required=True, type=int)
    serve_parser.add_argument("--bind", default=DMZ_SERVER_IP)
    serve_parser.add_argument("--port", default=HTTP_PORT, type=int)
    serve_parser.add_argument("--root-response", default=DEFAULT_ROOT_RESPONSE)

    health_parser = commands.add_parser("health", help="verify the Mininet DMZ /health endpoint")
    health_parser.add_argument("--url", default=f"http://{DMZ_SERVER_IP}/health")
    health_parser.add_argument("--timeout", default=2.0, type=float)

    summary_parser = commands.add_parser("summarize", help="calculate HTTP metrics from the raw request CSV")
    summary_parser.add_argument("--experiment-id", required=True)
    summary_parser.add_argument("--scenario", required=True)
    summary_parser.add_argument("--input", required=True, type=Path)
    summary_parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "serve":
            serve(
                args.experiment_id,
                args.scenario,
                args.results_root,
                args.host_netns_inode,
                args.bind,
                args.port,
                args.root_response,
            )
        elif args.command == "health":
            result = check_health(args.url, args.timeout)
            print(f"HTTP health check passed: {result['url']} returned HTTP {result['http_status']}.")
        else:
            print(
                json.dumps(
                    summarize_log(args.input, args.experiment_id, args.scenario, args.results_root),
                    indent=2,
                    sort_keys=True,
                )
            )
        return 0
    except (MonitorError, ExperimentMonitorError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())