#!/usr/bin/env python3
"""Scenario traffic and mitigation orchestration for the isolated Mininet topology."""

from __future__ import annotations

import json
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
LEGITIMATE_CLIENT = PROJECT_ROOT / "traffic" / "legitimate_client.py"
SYN_TEST = PROJECT_ROOT / "traffic" / "syn_flood.py"
SYN_COOKIES = PROJECT_ROOT / "mitigation" / "syn_cookies.sh"
RATE_LIMIT = PROJECT_ROOT / "mitigation" / "rate_limit.sh"

SCENARIOS = {
    "baseline",
    "syn_flood_no_defense",
    "syn_cookies",
    "syn_cookies_rate_limit",
}


class ScenarioError(RuntimeError):
    """Scenario component failed or did not terminate safely."""


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def event_log(directory: Path, event: str, **details: Any) -> None:
    record = {"timestamp": utc_timestamp(), "event": event, **details}
    with (directory / "logs" / "orchestration.jsonl").open("a", encoding="utf-8") as log_file:
        log_file.write(json.dumps(record, sort_keys=True) + "\n")
        log_file.flush()


def write_status(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def run_node_command(node: Any, arguments: list[str], description: str) -> str:
    stdout, stderr, return_code = node.pexec(*arguments)
    if return_code != 0:
        detail = (stderr or stdout).strip() or "no command output"
        raise ScenarioError(f"{description} failed on {node.name} (exit {return_code}): {detail}")
    return stdout.strip()


def launch_logged(node: Any, arguments: list[str], log_path: Path, description: str) -> Any:
    try:
        with log_path.open("x", encoding="utf-8") as output_log:
            process = node.popen(
                arguments,
                stdin=subprocess.DEVNULL,
                stdout=output_log,
                stderr=subprocess.STDOUT,
            )
    except (OSError, FileExistsError) as error:
        raise ScenarioError(f"Cannot start {description}: {error}") from error
    if process.poll() is not None:
        tail = log_path.read_text(encoding="utf-8", errors="replace")[-2000:]
        raise ScenarioError(f"{description} exited during startup (status {process.returncode}): {tail}")
    return process


def wait_for_process(process: Any, timeout: float, label: str, log_path: Path) -> None:
    try:
        return_code = process.wait(timeout=timeout)
    except subprocess.TimeoutExpired as error:
        process.send_signal(2)
        try:
            return_code = process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
            raise ScenarioError(f"{label} exceeded its bounded run time and required SIGKILL.") from error
    except KeyboardInterrupt:
        process.send_signal(2)
        try:
            process.wait(timeout=8)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        raise
    if return_code != 0:
        tail = log_path.read_text(encoding="utf-8", errors="replace")[-3000:]
        raise ScenarioError(f"{label} exited with status {return_code}: {tail}")


def apply_mitigation(
    scenario: str,
    net: Any,
    experiment_id: str,
    results_root: Path,
    settings: dict[str, Any],
) -> tuple[bool, bool]:
    cookies_applied = False
    rate_limit_applied = False
    if scenario in ("syn_cookies", "syn_cookies_rate_limit"):
        server = net.get(settings["hosts"]["web_server"]["node"])
        run_node_command(
            server,
            ["bash", str(SYN_COOKIES), "--enable", "--experiment-id", experiment_id,
             "--results-root", str(results_root)],
            "Enable Mininet DMZ SYN Cookies",
        )
        cookies_applied = True
        print("[MITIGATION] SYN Cookies enabled and verified on dclWeb.", flush=True)
    if scenario == "syn_cookies_rate_limit":
        router = net.get(settings["nodes"]["campus_router"])
        legitimate = net.get(settings["hosts"]["legitimate_client"]["node"])
        run_node_command(
            router,
            ["bash", str(RATE_LIMIT), "--apply", "--experiment-id", experiment_id,
             "--legitimate-pid", str(legitimate.pid), "--results-root", str(results_root)],
            "Apply Mininet router SYN rate limit",
        )
        rate_limit_applied = True
        print("[MITIGATION] OVS/router-boundary SYN rate limit active and legitimate HTTP verified.", flush=True)
    return cookies_applied, rate_limit_applied


def reset_mitigations(
    net: Any,
    experiment_id: str,
    results_root: Path,
    settings: dict[str, Any],
    cookies_applied: bool,
    rate_limit_applied: bool,
) -> list[str]:
    errors = []
    if rate_limit_applied:
        try:
            run_node_command(
                net.get(settings["nodes"]["campus_router"]),
                ["bash", str(RATE_LIMIT), "--remove", "--experiment-id", experiment_id,
                 "--results-root", str(results_root)],
                "Remove Mininet router SYN rate limit",
            )
        except Exception as error:
            errors.append(str(error))
    if cookies_applied:
        try:
            run_node_command(
                net.get(settings["hosts"]["web_server"]["node"]),
                ["bash", str(SYN_COOKIES), "--reset", "--experiment-id", experiment_id,
                 "--results-root", str(results_root)],
                "Restore Mininet DMZ SYN Cookie setting",
            )
        except Exception as error:
            errors.append(str(error))
    return errors


def run_scenario(
    net: Any,
    settings: dict[str, Any],
    experiment_id: str,
    scenario: str,
    results_root: Path,
) -> None:
    if scenario not in SCENARIOS:
        raise ScenarioError(f"Unsupported scenario {scenario!r}; expected one of {', '.join(sorted(SCENARIOS))}.")

    try:
        import yaml
        config = yaml.safe_load((PROJECT_ROOT / "config" / "config.yaml").read_text(encoding="utf-8"))
        workload = config["traffic"]
        legitimate_rate = float(workload["legitimate_rate_requests_per_second"])
        legitimate_duration = float(workload["legitimate_duration_seconds"])
        request_timeout = float(workload["legitimate_timeout_seconds"])
        syn_count = int(workload["syn_packet_count"])
        syn_rate = float(workload["syn_rate_packets_per_second"])
        syn_duration = float(workload["syn_duration_seconds"])
        syn_packet_size = int(workload["syn_packet_size_bytes"])
    except (ImportError, KeyError, OSError, TypeError, ValueError) as error:
        raise ScenarioError(f"Invalid scenario traffic configuration: {error}") from error

    directory = results_root / experiment_id
    status_path = directory / "logs" / "scenario_status.json"
    status: dict[str, Any] = {
        "experiment_id": experiment_id,
        "scenario": scenario,
        "status": "running",
        "start_time": utc_timestamp(),
        "end_time": None,
        "runner_pid": __import__("os").getpid(),
        "error": None,
    }
    write_status(status_path, status)
    event_log(directory, "scenario_started", config=workload)
    print(f"[STEP] Starting scenario {scenario} for experiment {experiment_id}.", flush=True)

    cookies_applied = False
    rate_limit_applied = False
    client_process = None
    attack_process = None
    failure: Exception | None = None
    client_log = directory / "logs" / "legitimate_client.log"
    attack_log = directory / "logs" / "syn_flood.log"
    try:
        cookies_applied, rate_limit_applied = apply_mitigation(
            scenario, net, experiment_id, results_root, settings
        )
        if cookies_applied or rate_limit_applied:
            event_log(directory, "mitigation_enabled", syn_cookies=cookies_applied, rate_limit=rate_limit_applied)

        legitimate = net.get(settings["hosts"]["legitimate_client"]["node"])
        client_csv = directory / "raw" / "legitimate_http.csv"
        client_process = launch_logged(
            legitimate,
            [
                sys.executable,
                str(LEGITIMATE_CLIENT),
                "--target",
                f"http://{settings['hosts']['web_server']['ip']}/",
                "--rate",
                str(legitimate_rate),
                "--duration",
                str(legitimate_duration),
                "--timeout",
                str(request_timeout),
                "--output",
                str(client_csv),
            ],
            client_log,
            "legitimate HTTP workload",
        )
        event_log(directory, "legitimate_traffic_started", rate=legitimate_rate, duration=legitimate_duration)

        if scenario != "baseline":
            attack = net.get(settings["hosts"]["attack"]["node"])
            attack_json = directory / "logs" / "syn_flood.json"
            attack_process = launch_logged(
                attack,
                [
                    sys.executable,
                    str(SYN_TEST),
                    "--lab-only",
                    "--target",
                    settings["hosts"]["web_server"]["ip"],
                    "--count",
                    str(syn_count),
                    "--duration",
                    str(syn_duration),
                    "--rate",
                    str(syn_rate),
                    "--packet-size",
                    str(syn_packet_size),
                    "--output",
                    str(attack_json),
                ],
                attack_log,
                "bounded Mininet SYN test",
            )
            event_log(directory, "syn_test_started", requested_count=syn_count, rate=syn_rate, duration=syn_duration)
            print("[STEP] Controlled SYN test started inside dclAttack.", flush=True)

        if attack_process is not None:
            wait_for_process(attack_process, syn_duration + 15, "SYN test", attack_log)
            event_log(directory, "syn_test_stopped")
        wait_for_process(client_process, legitimate_duration + request_timeout + 10, "Legitimate HTTP workload", client_log)
        event_log(directory, "legitimate_traffic_stopped")
    except Exception as error:
        failure = error
        status["error"] = str(error)
        event_log(directory, "scenario_failed", error=str(error))
        for process, label in ((attack_process, "SYN test"), (client_process, "legitimate workload")):
            if process is not None and process.poll() is None:
                try:
                    process.send_signal(2)
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
                except Exception as stop_error:
                    event_log(directory, "traffic_stop_failed", process=label, error=str(stop_error))
    except KeyboardInterrupt:
        failure = ScenarioError("Scenario interrupted by user.")
        status["error"] = str(failure)
        event_log(directory, "scenario_interrupted")
        for process in (attack_process, client_process):
            if process is not None and process.poll() is None:
                process.send_signal(2)
                try:
                    process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
    finally:
        reset_errors = reset_mitigations(net, experiment_id, results_root, settings, cookies_applied, rate_limit_applied)
        if reset_errors:
            status["mitigation_reset_errors"] = reset_errors
            event_log(directory, "mitigation_reset_failed", errors=reset_errors)
            failure = failure or ScenarioError("One or more mitigations failed to reset: " + "; ".join(reset_errors))
        else:
            event_log(directory, "mitigations_reset")
        status["end_time"] = utc_timestamp()
        status["status"] = "failed" if failure else "completed"
        write_status(status_path, status)

    if failure is not None:
        raise ScenarioError(str(failure)) from failure
    print(f"[PASS] Scenario {scenario} completed; raw traffic and logs are in {directory}.", flush=True)
