#!/usr/bin/env python3
"""Isolated DMZ HTTP service and request-log summarizer."""

from __future__ import annotations

import argparse
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


DMZ_SERVER_IP = "10.10.10.100"
HTTP_PORT = 80
DEFAULT_ROOT_RESPONSE = "Campus Mininet web server is online."
FLUSH_EVERY_REQUESTS = 32


class MonitorError(RuntimeError):
    """Invalid monitor input or an HTTP health-check failure."""


class RequestCounters:
    def __init__(self) -> None:
        self.total_requests = 0
        self.successful_requests = 0

    def record(self, successful: bool) -> None:
        self.total_requests += 1
        if successful:
            self.successful_requests += 1

    def snapshot(self) -> dict[str, int | float]:
        total = self.total_requests
        successful = self.successful_requests
        return {
            "total_requests": total,
            "successful_requests": successful,
            "failed_requests": total - successful,
            "http_completion_percentage": round(successful * 100 / total, 3) if total else 0.0,
        }


class JsonlRequestLog:
    """Buffer compact raw records and flush periodically to limit measurement overhead."""

    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.stream = path.open("a", encoding="utf-8", buffering=65536)
        self.pending = 0

    def write(self, record: dict[str, Any]) -> None:
        self.stream.write(json.dumps(record, separators=(",", ":"), ensure_ascii=True) + "\n")
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
            self.server.request_counters.record(successful)
            self.server.request_log.write(record)
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


def summarize_records(lines: Iterable[str]) -> dict[str, int | float | None]:
    total = 0
    successful = 0
    response_time_total = 0.0

    for line_number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as error:
            raise MonitorError(f"Invalid JSON in request log line {line_number}: {error.msg}.") from error
        if not isinstance(record, dict):
            raise MonitorError(f"Request log line {line_number} must contain a JSON object.")

        timestamp = record.get("timestamp")
        status = record.get("status")
        response_time_ms = record.get("response_time_ms")
        completed = record.get("completed")
        if not isinstance(timestamp, str):
            raise MonitorError(f"Request log line {line_number} has no timestamp.")
        try:
            parsed_timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        except ValueError as error:
            raise MonitorError(f"Request log line {line_number} has an invalid timestamp.") from error
        if parsed_timestamp.tzinfo is None:
            raise MonitorError(f"Request log line {line_number} timestamp is missing its timezone.")
        if isinstance(status, bool) or not isinstance(status, int) or not 100 <= status <= 599:
            raise MonitorError(f"Request log line {line_number} has an invalid HTTP status.")
        if isinstance(response_time_ms, bool) or not isinstance(response_time_ms, (int, float)):
            raise MonitorError(f"Request log line {line_number} has an invalid response time.")
        if not math.isfinite(response_time_ms) or response_time_ms < 0:
            raise MonitorError(f"Request log line {line_number} has a non-finite or negative response time.")
        if not isinstance(completed, bool):
            raise MonitorError(f"Request log line {line_number} has no completion flag.")

        request_successful = completed and 200 <= status < 300
        if "successful" in record and record["successful"] is not request_successful:
            raise MonitorError(f"Request log line {line_number} has an inconsistent success flag.")
        total += 1
        successful += int(request_successful)
        response_time_total += response_time_ms

    failed = total - successful
    return {
        "total_requests": total,
        "successful_requests": successful,
        "failed_requests": failed,
        "http_completion_percentage": round(successful * 100 / total, 3) if total else None,
        "average_response_time_ms": round(response_time_total / total, 3) if total else None,
    }


def summarize_log(path: Path) -> dict[str, int | float | None]:
    try:
        with path.open(encoding="utf-8") as request_log:
            return summarize_records(request_log)
    except OSError as error:
        raise MonitorError(f"Cannot read HTTP request log {path}: {error}") from error


def serve(log_path: Path, host_netns_inode: int, bind: str, port: int, root_response: str) -> None:
    if bind != DMZ_SERVER_IP or port != HTTP_PORT:
        raise MonitorError(f"The service may bind only to {DMZ_SERVER_IP}:{HTTP_PORT} inside Mininet.")
    current_netns_inode = os.stat("/proc/self/ns/net").st_ino
    if current_netns_inode == host_netns_inode:
        raise MonitorError("Refusing to expose the DMZ service in the host network namespace.")

    request_log = JsonlRequestLog(log_path)
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
    print(f"HTTP service listening on {bind}:{port}; request log: {log_path}", flush=True)
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
    serve_parser.add_argument("--log-file", required=True, type=Path)
    serve_parser.add_argument("--host-netns-inode", required=True, type=int)
    serve_parser.add_argument("--bind", default=DMZ_SERVER_IP)
    serve_parser.add_argument("--port", default=HTTP_PORT, type=int)
    serve_parser.add_argument("--root-response", default=DEFAULT_ROOT_RESPONSE)

    health_parser = commands.add_parser("health", help="verify the Mininet DMZ /health endpoint")
    health_parser.add_argument("--url", default=f"http://{DMZ_SERVER_IP}/health")
    health_parser.add_argument("--timeout", default=2.0, type=float)

    summary_parser = commands.add_parser("summarize", help="calculate metrics from a raw JSONL request log")
    summary_parser.add_argument("--input", required=True, type=Path)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        if args.command == "serve":
            serve(args.log_file, args.host_netns_inode, args.bind, args.port, args.root_response)
        elif args.command == "health":
            result = check_health(args.url, args.timeout)
            print(f"HTTP health check passed: {result['url']} returned HTTP {result['http_status']}.")
        else:
            print(json.dumps(summarize_log(args.input), indent=2, sort_keys=True))
        return 0
    except (MonitorError, OSError) as error:
        print(f"ERROR: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())