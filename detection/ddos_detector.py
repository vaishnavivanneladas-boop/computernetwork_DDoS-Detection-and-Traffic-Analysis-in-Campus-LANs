#!/usr/bin/env python3
"""Explainable, sustained rule-based DDoS indicator scoring for local experiment data."""

from __future__ import annotations

import argparse
import csv
import json
import math
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

try:
    from system_monitor import (
        DEFAULT_RESULTS_ROOT,
        MonitorError,
        append_metric_records,
        experiment_directory,
        make_metric_record,
        validate_experiment_id,
        validate_experiment_metadata,
        validate_scenario,
    )
except ImportError:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "monitoring"))
    from system_monitor import (
        DEFAULT_RESULTS_ROOT,
        MonitorError,
        append_metric_records,
        experiment_directory,
        make_metric_record,
        validate_experiment_id,
        validate_experiment_metadata,
        validate_scenario,
    )


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_ROOT / "config" / "config.yaml"


class DetectorError(RuntimeError):
    """Invalid detector settings or experiment metric input."""


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def load_config() -> dict[str, Any]:
    try:
        import yaml
        data = yaml.safe_load(CONFIG_PATH.read_text(encoding="utf-8"))
        settings = data["detection"]
        required = {
            "sustained_window_seconds",
            "sampling_interval_seconds",
            "required_consecutive_samples",
            "thresholds",
            "weights",
            "risk_levels",
        }
        if not required.issubset(settings):
            raise DetectorError("Detection configuration is missing required keys.")
        window = float(settings["sustained_window_seconds"])
        interval = float(settings["sampling_interval_seconds"])
        samples = int(settings["required_consecutive_samples"])
        if not math.isfinite(window) or window <= 0 or not math.isfinite(interval) or interval <= 0 or samples < 2:
            raise DetectorError("Detection window/interval must be positive and at least two samples are required.")
        if interval > window:
            raise DetectorError("Detection sample interval may not exceed its sustained window.")
        for level in ("suspicious_minimum", "high_minimum", "critical_minimum"):
            if int(settings["risk_levels"][level]) < 1:
                raise DetectorError(f"Risk score for {level} must be positive.")
        levels = settings["risk_levels"]
        if not int(levels["suspicious_minimum"]) < int(levels["high_minimum"]) < int(levels["critical_minimum"]):
            raise DetectorError("Risk-level score thresholds must be strictly increasing.")
        if any(int(weight) <= 0 for weight in settings["weights"].values()):
            raise DetectorError("Every configured detector weight must be positive.")
        if any(not math.isfinite(float(value)) or float(value) < 0 for value in settings["thresholds"].values()):
            raise DetectorError("Detector thresholds must be finite and non-negative.")
        return settings
    except ImportError as error:
        raise DetectorError("PyYAML is required to load detector settings.") from error
    except (OSError, KeyError, TypeError, ValueError) as error:
        raise DetectorError(f"Cannot load detector configuration: {error}") from error


def parse_metric_value(row: dict[str, str]) -> float | None:
    if row.get("status") != "measured" or row.get("value", "").strip().lower() in ("", "null"):
        return None
    try:
        value = float(row["value"])
    except (KeyError, ValueError):
        return None
    return value if math.isfinite(value) else None


def add_record(series: dict[str, list[tuple[datetime, float]]], name: str, timestamp: str, value: float | None) -> None:
    if value is None:
        return
    try:
        parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        return
    if parsed.tzinfo is None:
        return
    series[name].append((parsed, value))


def load_metric_series(directory: Path, experiment_id: str, scenario: str) -> dict[str, list[tuple[datetime, float]]]:
    series: dict[str, list[tuple[datetime, float]]] = defaultdict(list)
    for path in (directory / "raw" / "metrics.csv", directory / "processed" / "metrics.csv"):
        if not path.is_file():
            continue
        try:
            with path.open(newline="", encoding="utf-8") as metric_file:
                reader = csv.DictReader(metric_file)
                for row in reader:
                    if row.get("experiment_id") != experiment_id or row.get("scenario") != scenario:
                        continue
                    add_record(series, row.get("metric_name", ""), row.get("timestamp", ""), parse_metric_value(row))
        except OSError as error:
            raise DetectorError(f"Cannot read metric series {path}: {error}") from error

    http_path = directory / "raw" / "http_requests.csv"
    if http_path.is_file():
        try:
            with http_path.open(newline="", encoding="utf-8") as http_file:
                reader = csv.DictReader(http_file)
                requests: dict[str, dict[str, str]] = {}
                for row in reader:
                    if row.get("experiment_id") != experiment_id or row.get("scenario") != scenario:
                        continue
                    request_id = row.get("request_id", "")
                    if not request_id:
                        continue
                    request = requests.setdefault(request_id, {"timestamp": row.get("timestamp", "")})
                    metric = row.get("metric_name")
                    if metric in ("http_completion_percentage", "http_average_response_time_ms"):
                        request[metric] = row.get("value", "")
                for request in requests.values():
                    for metric in ("http_completion_percentage", "http_average_response_time_ms"):
                        try:
                            value = float(request.get(metric, ""))
                        except ValueError:
                            continue
                        if math.isfinite(value):
                            add_record(series, metric, request["timestamp"], value)
        except OSError as error:
            raise DetectorError(f"Cannot read HTTP request series {http_path}: {error}") from error

    for points in series.values():
        points.sort(key=lambda point: point[0])
    return series


def evaluate_sustained(
    points: list[tuple[datetime, float]],
    threshold: float,
    direction: str,
    window_seconds: float,
    interval_seconds: float,
    required_samples: int,
) -> dict[str, Any]:
    if not points:
        return {"active": False, "status": "unavailable", "value": None, "reason": "No measured samples are available."}
    end = points[-1][0]
    cutoff = end.timestamp() - window_seconds
    window = [(timestamp, value) for timestamp, value in points if timestamp.timestamp() >= cutoff]
    latest_value = points[-1][1]
    if len(window) < required_samples:
        return {"active": False, "status": "insufficient_persistence", "value": latest_value,
                "reason": f"Only {len(window)} measured sample(s); {required_samples} sustained samples are required."}
    span = (window[-1][0] - window[0][0]).total_seconds()
    required_span = max(0.0, window_seconds - interval_seconds * 1.5)
    if span < required_span:
        return {"active": False, "status": "insufficient_persistence", "value": latest_value,
                "reason": f"Abnormal window spans {span:.3f}s, less than the configured sustained window."}
    max_gap = max((later[0] - earlier[0]).total_seconds() for earlier, later in zip(window, window[1:]))
    if max_gap > interval_seconds * 2.5:
        return {"active": False, "status": "insufficient_persistence", "value": latest_value,
                "reason": f"Sample gap {max_gap:.3f}s breaks sustained observation."}
    comparator = (lambda value: value > threshold) if direction == "above" else (lambda value: value < threshold)
    abnormal_count = sum(comparator(value) for _timestamp, value in window)
    active = abnormal_count == len(window)
    if active:
        reason = (
            f"Measured {latest_value:g} remained {direction} configured threshold {threshold:g} "
            f"for {span:.1f}s ({len(window)} samples)."
        )
    else:
        reason = f"The configured threshold was not exceeded for the full sustained window ({abnormal_count}/{len(window)} samples)."
    return {"active": active, "status": "measured", "value": latest_value, "reason": reason, "samples": len(window), "duration_seconds": span}


def detect(
    series: dict[str, list[tuple[datetime, float]]],
    settings: dict[str, Any],
    timestamp: str | None = None,
) -> dict[str, Any]:
    thresholds = settings["thresholds"]
    weights = settings["weights"]
    window = float(settings["sustained_window_seconds"])
    interval = float(settings["sampling_interval_seconds"])
    required = int(settings["required_consecutive_samples"])
    http_completion_threshold = 100 - float(thresholds["http_failure_percent"])
    definitions = (
        ("syn_rate_high", "security_syn_rate", float(thresholds["syn_rate_packets_per_second"]), "above", "SYN rate exceeded configured experimental threshold"),
        ("handshake_imbalance", "security_syn_ack_ratio", float(thresholds["syn_ack_ratio"]), "above", "SYN/ACK imbalance persisted over the configured window"),
        ("cpu_high", "server_cpu_utilization", float(thresholds["cpu_utilization_percent"]), "above", "CPU utilization exceeded the configured experimental threshold"),
        ("memory_high", "server_memory_utilization", float(thresholds["memory_utilization_percent"]), "above", "Memory usage exceeded the configured experimental threshold"),
        ("drops_high", "network_dropped_packets", float(thresholds["dropped_packets"]), "above", "Measured packet drops exceeded the configured experimental threshold"),
        ("http_failure_high", "http_completion_percentage", http_completion_threshold, "below", "HTTP completion fell below the configured experimental threshold"),
        ("response_time_high", "http_average_response_time_ms", float(thresholds["http_response_time_ms"]), "above", "HTTP response time exceeded the configured experimental threshold"),
    )
    indicators = []
    reasons = []
    score = 0
    measured_indicator_count = 0
    for indicator_name, metric_name, threshold, direction, reason_prefix in definitions:
        result = evaluate_sustained(series.get(metric_name, []), threshold, direction, window, interval, required)
        active = bool(result["active"])
        if result["status"] != "unavailable":
            measured_indicator_count += 1
        weight = int(weights[indicator_name])
        if active:
            score += weight
            reasons.append(f"{reason_prefix}: {result['reason']}")
        indicators.append({
            "name": indicator_name,
            "metric_name": metric_name,
            "threshold": threshold,
            "weight": weight,
            **result,
        })

    levels = settings["risk_levels"]
    if measured_indicator_count == 0:
        risk_score: int | None = None
        risk_level: str | None = None
        reasons.append("Risk is unavailable because no sustained metric series were measured.")
    else:
        risk_score = score
        if score >= int(levels["critical_minimum"]):
            risk_level = "CRITICAL"
        elif score >= int(levels["high_minimum"]):
            risk_level = "HIGH"
        elif score >= int(levels["suspicious_minimum"]):
            risk_level = "SUSPICIOUS"
        else:
            risk_level = "NORMAL"
        if not reasons:
            reasons.append("No configured indicator remained abnormal for the full sustained observation window.")

    return {
        "timestamp": timestamp or utc_timestamp(),
        "detection_method": "explainable rule-based scoring; not machine learning",
        "risk_score": risk_score,
        "risk_level": risk_level,
        "indicators": indicators,
        "reasons": reasons,
        "automatic_mitigation": False,
    }


def run_detector(experiment_id: str, scenario: str, results_root: Path) -> dict[str, Any]:
    validate_experiment_id(experiment_id)
    validate_scenario(scenario)
    directory = experiment_directory(experiment_id, results_root)
    if not directory.is_dir():
        raise DetectorError(f"Experiment directory does not exist: {directory}")
    validate_experiment_metadata(directory, experiment_id, scenario)
    settings = load_config()
    series = load_metric_series(directory, experiment_id, scenario)
    result = detect(series, settings)
    result.update({"experiment_id": experiment_id, "scenario": scenario})
    timestamp_slug = result["timestamp"].replace(":", "-")
    output_path = directory / "logs" / f"ddos_detection_{timestamp_slug}.json"
    try:
        with output_path.open("x", encoding="utf-8") as result_file:
            json.dump(result, result_file, indent=2, sort_keys=True)
            result_file.write("\n")
    except OSError as error:
        raise DetectorError(f"Cannot save detector output {output_path}: {error}") from error

    record = make_metric_record(experiment_id, scenario, "security_risk_score", result["risk_score"], "weighted score", timestamp=result["timestamp"])
    append_metric_records(experiment_id, scenario, [record], results_root=results_root, stage="processed")
    print(f"Risk level: {result['risk_level'] or 'UNAVAILABLE'}; score: {result['risk_score'] if result['risk_score'] is not None else 'N/A'}")
    for reason in result["reasons"]:
        print(f"- {reason}")
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    args = parser.parse_args()
    try:
        run_detector(args.experiment_id, args.scenario, args.results_root)
        return 0
    except (DetectorError, MonitorError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
