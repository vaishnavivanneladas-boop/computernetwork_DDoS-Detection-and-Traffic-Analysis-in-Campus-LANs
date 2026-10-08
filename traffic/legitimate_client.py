#!/usr/bin/env python3
"""Generate a paced HTTP workload from the configured Mininet legitimate client."""

from __future__ import annotations

import argparse
import csv
import http.client
import ipaddress
import math
import os
import signal
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


TARGET_IP = ipaddress.ip_address("10.10.10.100")
LEGITIMATE_CLIENT_IP = ipaddress.ip_address("10.10.30.20")
LEGITIMATE_GATEWAY_IP = ipaddress.ip_address("10.10.30.1")
DEFAULT_TARGET = "http://10.10.10.100/"
DEFAULT_RATE = 30.0
DEFAULT_DURATION = 30.0
DEFAULT_TIMEOUT = 3.0
MAX_REQUEST_RATE = 100.0
MAX_DURATION_SECONDS = 3600.0
MAX_TIMEOUT_SECONDS = 60.0
MAX_RESPONSE_BYTES = 1_048_576
CSV_FIELDS = (
    "request_number",
    "timestamp_utc",
    "target",
    "http_status",
    "response_time_ms",
    "success",
    "failure_type",
    "failure_detail",
)


class WorkloadError(RuntimeError):
    """Invalid options, unsafe execution context, or output errors."""


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def validate_target(target: str) -> str:
    try:
        parsed = urlsplit(target)
        port = parsed.port
        target_ip = ipaddress.ip_address(parsed.hostname or "")
    except ValueError as error:
        raise WorkloadError(f"Invalid target URL: {error}") from error

    if (
        parsed.scheme != "http"
        or target_ip != TARGET_IP
        or port not in (None, 80)
        or parsed.path != "/"
        or parsed.query
        or parsed.fragment
        or parsed.username is not None
        or parsed.password is not None
    ):
        raise WorkloadError(
            f"Requests are restricted to the Mininet DMZ origin {DEFAULT_TARGET} "
            "(HTTP port 80, root path only)."
        )
    return DEFAULT_TARGET


def _run_ip_command(arguments: list[str]) -> str:
    try:
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise WorkloadError(f"Cannot verify Mininet network state with {' '.join(arguments)}: {error}") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or f"exit status {result.returncode}"
        raise WorkloadError(f"Cannot verify Mininet network state with {' '.join(arguments)}: {detail}")
    return result.stdout


def validate_mininet_context() -> str:
    try:
        current_namespace = os.stat("/proc/self/ns/net").st_ino
        host_namespace = os.stat("/proc/1/ns/net").st_ino
    except OSError as error:
        raise WorkloadError(f"Cannot identify the current and host network namespaces: {error}") from error

    if current_namespace == host_namespace:
        raise WorkloadError("Refusing to send workload from the host network namespace; run inside Mininet dclLegit.")

    addresses = _run_ip_command(["ip", "-o", "-4", "address", "show"])
    client_interfaces: set[str] = set()
    for line in addresses.splitlines():
        fields = line.split()
        if len(fields) >= 4 and fields[2] == "inet":
            try:
                assigned_ip = ipaddress.ip_interface(fields[3]).ip
            except ValueError:
                continue
            if assigned_ip == LEGITIMATE_CLIENT_IP:
                client_interfaces.add(fields[1].split("@", maxsplit=1)[0])

    if len(client_interfaces) != 1:
        raise WorkloadError(
            f"Refusing to send workload: Mininet legitimate-client IP {LEGITIMATE_CLIENT_IP} "
            f"must be assigned to exactly one interface (found {len(client_interfaces)})."
        )
    client_interface = next(iter(client_interfaces))

    route_output = _run_ip_command(["ip", "-4", "route", "get", str(TARGET_IP)])
    route_fields = route_output.split()
    try:
        route_interface = route_fields[route_fields.index("dev") + 1]
        route_source = ipaddress.ip_address(route_fields[route_fields.index("src") + 1])
        route_gateway = ipaddress.ip_address(route_fields[route_fields.index("via") + 1])
    except (ValueError, IndexError) as error:
        raise WorkloadError(
            f"Refusing to send workload: DMZ route must use source {LEGITIMATE_CLIENT_IP} "
            f"via {LEGITIMATE_GATEWAY_IP}; observed {route_output.strip()!r}."
        ) from error

    if (
        route_interface != client_interface
        or route_source != LEGITIMATE_CLIENT_IP
        or route_gateway != LEGITIMATE_GATEWAY_IP
    ):
        raise WorkloadError(
            "Refusing to send workload: DMZ route is outside the expected Mininet path "
            f"(expected src {LEGITIMATE_CLIENT_IP} via {LEGITIMATE_GATEWAY_IP} dev {client_interface}; "
            f"observed {route_output.strip()!r})."
        )
    return client_interface


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def perform_request(opener: Any, target: str, timeout: float) -> dict[str, Any]:
    timestamp = utc_timestamp()
    start = time.perf_counter_ns()
    status: int | None = None
    failure_type = ""
    failure_detail = ""
    response = None

    request = Request(target, headers={"Connection": "close", "User-Agent": "CampusLabLegitimateClient/1.0"})
    try:
        response = opener.open(request, timeout=timeout)
        status = response.status
    except HTTPError as error:
        response = error
        status = error.code
    except (URLError, TimeoutError, socket.timeout, OSError, http.client.HTTPException) as error:
        failure_type = "network_error"
        failure_detail = str(getattr(error, "reason", error))

    if response is not None:
        try:
            response_body = response.read(MAX_RESPONSE_BYTES + 1)
            if len(response_body) > MAX_RESPONSE_BYTES:
                failure_type = "response_too_large"
                failure_detail = f"Response exceeded {MAX_RESPONSE_BYTES} bytes."
        except (OSError, URLError, TimeoutError, socket.timeout, http.client.HTTPException) as error:
            failure_type = "response_read_error"
            failure_detail = str(getattr(error, "reason", error))
        finally:
            response.close()

    elapsed_ms = round((time.perf_counter_ns() - start) / 1_000_000, 3)
    successful = status is not None and 200 <= status < 300 and not failure_type
    if status is not None and not successful and not failure_type:
        failure_type = "http_status"
        failure_detail = f"Received HTTP {status}."

    return {
        "timestamp_utc": timestamp,
        "http_status": status if status is not None else "",
        "response_time_ms": elapsed_ms,
        "success": successful,
        "failure_type": failure_type,
        "failure_detail": failure_detail,
    }


def validate_options(rate: float, duration: float, timeout: float) -> None:
    if not math.isfinite(rate) or not 0 < rate <= MAX_REQUEST_RATE:
        raise WorkloadError(f"--rate must be greater than 0 and no more than {MAX_REQUEST_RATE:g} requests/sec.")
    if not math.isfinite(duration) or not 0 < duration <= MAX_DURATION_SECONDS:
        raise WorkloadError(f"--duration must be greater than 0 and no more than {MAX_DURATION_SECONDS:g} seconds.")
    if not math.isfinite(timeout) or not 0 < timeout <= MAX_TIMEOUT_SECONDS:
        raise WorkloadError(f"--timeout must be greater than 0 and no more than {MAX_TIMEOUT_SECONDS:g} seconds.")


def run_workload(target: str, rate: float, duration: float, timeout: float, output: Path) -> int:
    target = validate_target(target)
    validate_options(rate, duration, timeout)
    interface = validate_mininet_context()
    opener = build_opener(ProxyHandler({}), NoRedirectHandler())

    try:
        output.parent.mkdir(parents=True, exist_ok=True)
        result_file = output.open("x", newline="", encoding="utf-8")
    except FileExistsError as error:
        raise WorkloadError(f"Refusing to overwrite existing results file: {output}") from error
    except (OSError, csv.Error) as error:
        raise WorkloadError(f"Cannot create results file {output}: {error}") from error

    stop_event = threading.Event()
    previous_handlers: dict[int, Any] = {}

    def request_stop(signum: int, _frame: Any) -> None:
        print(f"\nReceived signal {signum}; stopping after the current request.", flush=True)
        stop_event.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.signal(signum, request_stop)

    writer = csv.DictWriter(result_file, fieldnames=CSV_FIELDS, extrasaction="raise")
    completed_requests = 0
    successful_requests = 0
    interval = 1.0 / rate
    start_time = time.monotonic()
    deadline = start_time + duration
    next_start = start_time
    print(
        f"Starting legitimate HTTP workload: target={target}, rate={rate:g} req/s, "
        f"duration={duration:g}s, timeout={timeout:g}s, source={LEGITIMATE_CLIENT_IP} "
        f"via {LEGITIMATE_GATEWAY_IP} on {interface}",
        flush=True,
    )

    try:
        writer.writeheader()
        result_file.flush()
        while not stop_event.is_set():
            now = time.monotonic()
            if now >= deadline:
                break
            if now < next_start:
                stop_event.wait(min(next_start - now, deadline - now))
                continue
            if stop_event.is_set() or time.monotonic() >= deadline:
                break

            completed_requests += 1
            result = perform_request(opener, target, timeout)
            result["request_number"] = completed_requests
            result["target"] = target
            writer.writerow(result)
            result_file.flush()
            successful_requests += int(result["success"])
            outcome = f"HTTP {result['http_status']}" if result["http_status"] != "" else "NO HTTP RESPONSE"
            if result["failure_type"]:
                outcome += f" ({result['failure_type']})"
            print(
                f"[{result['timestamp_utc']}] request {completed_requests}: {outcome}, "
                f"{result['response_time_ms']:.3f} ms",
                flush=True,
            )
            next_start = max(next_start + interval, time.monotonic())
    except KeyboardInterrupt:
        stop_event.set()
        print("\nInterrupted; results collected so far will be preserved.", flush=True)
    except OSError as error:
        raise WorkloadError(f"Cannot write workload results to {output}: {error}") from error
    finally:
        result_file.flush()
        result_file.close()
        for signum, previous_handler in previous_handlers.items():
            signal.signal(signum, previous_handler)

    elapsed = time.monotonic() - start_time
    print(
        f"Workload stopped: {completed_requests} requests, {successful_requests} successful, "
        f"{completed_requests - successful_requests} failed; actual elapsed {elapsed:.3f}s "
        f"(request-start window {duration:g}s); output={output}",
        flush=True,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--target", default=DEFAULT_TARGET, help=f"Mininet DMZ URL (default: {DEFAULT_TARGET})")
    parser.add_argument(
        "--rate",
        type=float,
        default=DEFAULT_RATE,
        help="maximum paced request rate in requests/sec, default 30 (within the 25-40 baseline range; max 100)",
    )
    parser.add_argument("--duration", type=float, default=DEFAULT_DURATION, help="workload duration in seconds (default: 30)")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="per-request timeout in seconds (default: 3)")
    parser.add_argument("--output", type=Path, default=Path("results/legitimate_http.csv"), help="new CSV output file")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return run_workload(args.target, args.rate, args.duration, args.timeout, args.output)
    except (WorkloadError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())