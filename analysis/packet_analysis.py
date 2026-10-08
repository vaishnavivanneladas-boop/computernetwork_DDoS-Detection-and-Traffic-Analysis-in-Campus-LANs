#!/usr/bin/env python3
"""Analyze a Mininet DMZ PCAP and write measured metrics plus an interpretation report."""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
from collections import Counter
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
EXPECTED_SERVER_IP = "10.10.10.100"
EXPECTED_NETWORK = "10.10.10.0/24"
EXPECTED_PORT = 80
DEFAULT_SYN_ACK_THRESHOLD = 3.0
CAPTURED_FLAG_BITS = (
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
)


class AnalysisError(RuntimeError):
    """Invalid capture metadata or packet analysis failure."""


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def read_capture_metadata(path: Path) -> dict[str, str]:
    try:
        values: dict[str, str] = {}
        with path.open(encoding="utf-8") as capture_log:
            for line in capture_log:
                key, separator, value = line.rstrip("\n").partition("=")
                if separator:
                    values[key] = value
    except OSError as error:
        raise AnalysisError(f"Cannot read capture log {path}: {error}") from error

    required = {
        "experiment_id",
        "scenario",
        "server_host",
        "interface",
        "server_ip",
        "server_network",
        "vlan",
        "filter",
        "capture_elapsed_seconds",
        "tcpdump_exit_status",
    }
    missing = required - values.keys()
    if missing:
        raise AnalysisError(f"Capture log is missing fields: {', '.join(sorted(missing))}.")
    return values


def validate_capture_paths(
    experiment_id: str,
    scenario: str,
    pcap_path: Path,
    capture_log_path: Path,
    results_root: Path,
) -> tuple[Path, Path, dict[str, str]]:
    validate_experiment_id(experiment_id)
    validate_scenario(scenario)
    directory = experiment_directory(experiment_id, results_root)
    if not directory.is_dir():
        raise AnalysisError(f"Experiment directory does not exist: {directory}")
    validate_experiment_metadata(directory, experiment_id, scenario)
    try:
        pcap_path = pcap_path.resolve(strict=True)
        capture_log_path = capture_log_path.resolve(strict=True)
    except OSError as error:
        raise AnalysisError(f"PCAP or capture log does not exist: {error}") from error
    if pcap_path.parent != (directory / "pcap").resolve():
        raise AnalysisError("PCAP must be located directly inside this experiment's pcap/ directory.")
    if capture_log_path.parent != (directory / "logs").resolve():
        raise AnalysisError("Capture log must be located directly inside this experiment's logs/ directory.")

    capture = read_capture_metadata(capture_log_path)
    if capture["experiment_id"] != experiment_id or capture["scenario"] != scenario:
        raise AnalysisError("Capture log experiment ID/scenario does not match the requested experiment.")
    if (
        capture["server_host"] != "dclWeb"
        or capture["server_ip"] != EXPECTED_SERVER_IP
        or capture["server_network"] != EXPECTED_NETWORK
        or capture["vlan"] != "10"
    ):
        raise AnalysisError("Capture log is not for the configured Mininet DMZ server/network.")
    if capture["interface"] != f"{capture['server_host']}-eth0" and not capture["interface"].startswith(
        f"{capture['server_host']}-eth"
    ):
        raise AnalysisError("Capture log interface does not belong to its configured Mininet server host.")
    if capture["filter"] != f"host {EXPECTED_SERVER_IP} and tcp port {EXPECTED_PORT}":
        raise AnalysisError("Capture log filter is not restricted to the configured DMZ HTTP flow.")
    try:
        duration = float(capture["capture_elapsed_seconds"])
        tcpdump_status = int(capture["tcpdump_exit_status"])
    except ValueError as error:
        raise AnalysisError("Capture log has invalid duration or tcpdump exit status.") from error
    if not math.isfinite(duration) or duration <= 0:
        raise AnalysisError("Capture duration must be a positive measured value.")
    if tcpdump_status != 0:
        raise AnalysisError(f"tcpdump exited with status {tcpdump_status}; capture is incomplete.")
    return pcap_path, capture_log_path, capture


def analyze_capture(pcap_path: Path, capture_duration: float) -> dict[str, Any]:
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.layers.inet6 import IPv6
        from scapy.utils import PcapReader
    except ImportError as error:
        raise AnalysisError("Scapy is required to analyze PCAP files; install project requirements.") from error

    total_packets = 0
    total_bytes = 0
    syn_packets = 0
    syn_ack_packets = 0
    ack_packets = 0
    tcp_flag_distribution: Counter[str] = Counter()
    source_ip_distribution: Counter[str] = Counter()
    destination_ip_distribution: Counter[str] = Counter()
    first_packet_time: float | None = None
    last_packet_time: float | None = None

    try:
        with PcapReader(str(pcap_path)) as reader:
            for packet in reader:
                total_packets += 1
                packet_time = float(packet.time)
                first_packet_time = packet_time if first_packet_time is None else min(first_packet_time, packet_time)
                last_packet_time = packet_time if last_packet_time is None else max(last_packet_time, packet_time)
                wire_length = getattr(packet, "wirelen", None)
                total_bytes += int(wire_length) if wire_length is not None else len(bytes(packet))

                if IP in packet:
                    source_ip_distribution[str(packet[IP].src)] += 1
                    destination_ip_distribution[str(packet[IP].dst)] += 1
                elif IPv6 in packet:
                    source_ip_distribution[str(packet[IPv6].src)] += 1
                    destination_ip_distribution[str(packet[IPv6].dst)] += 1

                if TCP not in packet:
                    continue
                flags = int(packet[TCP].flags)
                active_flags = [name for bit, name in CAPTURED_FLAG_BITS if flags & bit]
                tcp_flag_distribution["|".join(active_flags) if active_flags else "NONE"] += 1
                syn = bool(flags & 0x02)
                ack = bool(flags & 0x10)
                if syn and ack:
                    syn_ack_packets += 1
                elif syn:
                    syn_packets += 1
                elif ack:
                    ack_packets += 1
    except (OSError, ValueError, TypeError) as error:
        raise AnalysisError(f"Cannot decode PCAP {pcap_path}: {error}") from error

    ratio = syn_packets / syn_ack_packets if syn_ack_packets else None
    return {
        "total_packets": total_packets,
        "syn_packets": syn_packets,
        "syn_ack_packets": syn_ack_packets,
        "ack_packets": ack_packets,
        "syn_ack_ratio": ratio,
        "packets_per_second": total_packets / capture_duration,
        "approximate_throughput_bps": total_bytes * 8 / capture_duration,
        "captured_bytes": total_bytes,
        "dropped_packets": parse_tcpdump_drops(capture_log_path=None),
        "tcp_flag_distribution": dict(sorted(tcp_flag_distribution.items())),
        "source_ip_distribution": dict(sorted(source_ip_distribution.items())),
        "destination_ip_distribution": dict(sorted(destination_ip_distribution.items())),
        "first_packet_timestamp_epoch": first_packet_time,
        "last_packet_timestamp_epoch": last_packet_time,
    }


def parse_tcpdump_drops(capture_log_path: Path | None, capture_text: str = "") -> int | None:
    if capture_log_path is not None:
        try:
            capture_text = capture_log_path.read_text(encoding="utf-8")
        except OSError:
            return None
    match = re.search(r"^(\d+)\s+packets dropped by kernel\b", capture_text, re.MULTILINE)
    return int(match.group(1)) if match else None


def build_metric_records(
    experiment_id: str,
    scenario: str,
    metrics: dict[str, Any],
    timestamp: str,
    dropped_packets: int | None,
    syn_ack_threshold: float,
) -> list[dict[str, Any]]:
    ratio = metrics["syn_ack_ratio"]
    abnormal = ratio > syn_ack_threshold if ratio is not None else None
    values = [
        ("network_total_packets", metrics["total_packets"], "packets"),
        ("network_syn_packets", metrics["syn_packets"], "packets"),
        ("network_syn_ack_packets", metrics["syn_ack_packets"], "packets"),
        ("network_ack_packets", metrics["ack_packets"], "packets"),
        ("network_packet_rate", metrics["packets_per_second"], "packets/s"),
        ("network_throughput", metrics["approximate_throughput_bps"], "bit/s (approximate)"),
        ("network_dropped_packets", dropped_packets, "packets"),
        ("network_captured_bytes", metrics["captured_bytes"], "bytes"),
        ("network_tcp_flag_distribution", json.dumps(metrics["tcp_flag_distribution"], sort_keys=True), "JSON packet counts"),
        ("network_source_ip_distribution", json.dumps(metrics["source_ip_distribution"], sort_keys=True), "JSON packet counts"),
        ("network_destination_ip_distribution", json.dumps(metrics["destination_ip_distribution"], sort_keys=True), "JSON packet counts"),
        ("security_syn_ack_ratio", ratio, "SYN/SYN-ACK ratio"),
        ("security_syn_rate", metrics["syn_packets"] / metrics["capture_duration_seconds"], "packets/s"),
        ("security_abnormal_handshake", abnormal, "boolean"),
    ]
    return [
        make_metric_record(experiment_id, scenario, name, value, unit, timestamp=timestamp)
        for name, value, unit in values
    ]


def write_report(path: Path, content: str) -> None:
    try:
        with path.open("x", encoding="utf-8") as report_file:
            report_file.write(content)
            report_file.flush()
    except FileExistsError as error:
        raise AnalysisError(f"Refusing to overwrite existing analysis report: {path}") from error
    except OSError as error:
        raise AnalysisError(f"Cannot write analysis report {path}: {error}") from error


def analyze_experiment(
    experiment_id: str,
    scenario: str,
    pcap_path: Path,
    capture_log_path: Path,
    results_root: Path = DEFAULT_RESULTS_ROOT,
    syn_ack_threshold: float = DEFAULT_SYN_ACK_THRESHOLD,
) -> dict[str, Any]:
    validate_experiment_id(experiment_id)
    validate_scenario(scenario)
    if not math.isfinite(syn_ack_threshold) or syn_ack_threshold <= 0:
        raise AnalysisError("SYN/ACK threshold must be a positive finite value.")
    pcap_path, capture_log_path, capture = validate_capture_paths(
        experiment_id,
        scenario,
        pcap_path,
        capture_log_path,
        results_root,
    )
    capture_duration = float(capture["capture_elapsed_seconds"])
    metrics = analyze_capture(pcap_path, capture_duration)
    metrics["capture_duration_seconds"] = capture_duration
    dropped_packets = parse_tcpdump_drops(capture_log_path)
    timestamp = utc_timestamp()
    directory = experiment_directory(experiment_id, results_root)
    json_report = directory / "processed" / "packet_analysis.json"
    text_report = directory / "processed" / "packet_analysis.md"
    if json_report.exists() or text_report.exists():
        raise AnalysisError("Packet analysis report already exists; refusing to overwrite experiment results.")

    ratio = metrics["syn_ack_ratio"]
    abnormal = ratio > syn_ack_threshold if ratio is not None else None
    metrics["dropped_packets"] = dropped_packets
    metrics["abnormal_handshake_indicator"] = abnormal
    report_data = {
        "timestamp": timestamp,
        "experiment_id": experiment_id,
        "scenario": scenario,
        "capture": {
            "pcap": str(pcap_path),
            "interface": capture["interface"],
            "filter": capture["filter"],
            "duration_seconds": capture_duration,
            "server_ip": capture["server_ip"],
            "server_port": EXPECTED_PORT,
        },
        "metrics": metrics,
        "interpretation": "The SYN/ACK ratio is only a handshake imbalance indicator; it is not a percentage of failed connections.",
        "initial_syn_filter": "tcp.flags.syn == 1 && tcp.flags.ack == 0",
        "throughput_note": "Approximate captured frame bytes multiplied by 8 and divided by measured capture duration.",
    }
    records = build_metric_records(experiment_id, scenario, metrics, timestamp, dropped_packets, syn_ack_threshold)
    append_metric_records(experiment_id, scenario, records, results_root=results_root, stage="processed")

    text = [
        f"# Packet Analysis: {experiment_id}",
        "",
        f"- Scenario: `{scenario}`",
        f"- Capture interface: `{capture['interface']}` (Mininet DMZ server host)",
        f"- Capture filter: `{capture['filter']}`",
        f"- Measured capture duration: {capture_duration:.6f} seconds",
        f"- PCAP: `{pcap_path}`",
        "",
        "## Packet Metrics",
        "",
        f"- Total packets: {metrics['total_packets']}",
        f"- SYN packets (SYN=1, ACK=0): {metrics['syn_packets']}",
        f"- SYN-ACK packets (SYN=1, ACK=1): {metrics['syn_ack_packets']}",
        f"- ACK packets (ACK=1, SYN=0): {metrics['ack_packets']}",
        f"- SYN/ACK ratio: {ratio if ratio is not None else 'unavailable (no SYN-ACK packets)'}",
        f"- Packets/sec: {metrics['packets_per_second']:.6f}",
        f"- Approximate throughput: {metrics['approximate_throughput_bps']:.3f} bit/s",
        f"- Dropped packets reported by tcpdump: {dropped_packets if dropped_packets is not None else 'unavailable'}",
        f"- TCP flag distribution: `{json.dumps(metrics['tcp_flag_distribution'], sort_keys=True)}`",
        f"- Source IP distribution: `{json.dumps(metrics['source_ip_distribution'], sort_keys=True)}`",
        f"- Destination IP distribution: `{json.dumps(metrics['destination_ip_distribution'], sort_keys=True)}`",
        "",
        "## Interpretation",
        "",
        report_data["interpretation"],
        "",
        f"Initial SYN packets are conceptually filtered with `{report_data['initial_syn_filter']}`.",
        report_data["throughput_note"],
        "",
    ]
    write_report(json_report, json.dumps(report_data, indent=2, sort_keys=True) + "\n")
    write_report(text_report, "\n".join(text))
    return report_data


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--pcap", required=True, type=Path)
    parser.add_argument("--capture-log", required=True, type=Path)
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--syn-ack-threshold", type=float, default=DEFAULT_SYN_ACK_THRESHOLD)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        report = analyze_experiment(
            args.experiment_id,
            args.scenario,
            args.pcap,
            args.capture_log,
            args.results_root,
            args.syn_ack_threshold,
        )
        print(
            f"Packet analysis completed: {report['metrics']['total_packets']} packets; "
            f"ratio={report['metrics']['syn_ack_ratio']}; report="
            f"{experiment_directory(args.experiment_id, args.results_root) / 'processed' / 'packet_analysis.md'}",
            flush=True,
        )
        return 0
    except (AnalysisError, MonitorError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
