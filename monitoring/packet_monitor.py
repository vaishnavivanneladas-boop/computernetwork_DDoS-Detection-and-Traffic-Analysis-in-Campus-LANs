#!/usr/bin/env python3
"""Capture packets only on the configured Mininet DMZ server-facing interface."""

from __future__ import annotations

import argparse
import ipaddress
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
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
    sys.path.insert(0, str(Path(__file__).resolve().parent))
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
MAX_CAPTURE_SECONDS = 3600.0
MAX_SNAPLEN = 65_535
DEFAULT_SYN_ACK_THRESHOLD = 3.0


class PacketMonitorError(RuntimeError):
    """Invalid topology/capture parameters or capture failure."""


def utc_timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def run_command(arguments: list[str], description: str, timeout: float = 5.0) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PacketMonitorError(f"{description} failed: {error}") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or f"exit status {result.returncode}"
        raise PacketMonitorError(f"{description} failed: {detail}")
    return result


def load_lab_config() -> dict[str, Any]:
    try:
        import yaml
    except ImportError as error:
        raise PacketMonitorError("PyYAML is required to verify the Mininet topology.") from error
    try:
        with CONFIG_PATH.open(encoding="utf-8") as config_file:
            raw_config = yaml.safe_load(config_file)
        topology = raw_config["topology"]
        hosts = topology["hosts"]
        attack = hosts["attack"]
        web = hosts["web_server"]
        attack_vlan = int(attack["vlan"])
        web_vlan = int(web["vlan"])
        settings = {
            "attack_name": attack["node"],
            "attack_ip": ipaddress.ip_address(attack["ip"]),
            "attack_network": ipaddress.ip_network(topology["vlans"][attack_vlan]["subnet"], strict=True),
            "attack_gateway": ipaddress.ip_address(topology["vlans"][attack_vlan]["gateway"]),
            "attack_vlan": attack_vlan,
            "web_name": web["node"],
            "target_ip": ipaddress.ip_address(web["ip"]),
            "web_network": ipaddress.ip_network(topology["vlans"][web_vlan]["subnet"], strict=True),
            "web_vlan": web_vlan,
            "target_port": int(topology["http"]["port"]),
            "core_bridge": topology["nodes"]["core_switch"],
            "router_name": topology["nodes"]["campus_router"],
            "configured_host_names": tuple(host["node"] for host in hosts.values()),
            "interface_prefix": topology["interface_prefix"],
        }
    except (KeyError, TypeError, ValueError) as error:
        raise PacketMonitorError(f"Cannot load packet-monitor topology settings: {error}") from error

    if (
        settings["attack_vlan"] != 30
        or settings["web_vlan"] != 10
        or settings["attack_ip"] != ipaddress.ip_address("10.10.30.30")
        or settings["target_ip"] != ipaddress.ip_address("10.10.10.100")
        or settings["attack_network"] != ipaddress.ip_network("10.10.30.0/24")
        or settings["web_network"] != ipaddress.ip_network("10.10.10.0/24")
        or settings["attack_gateway"] != ipaddress.ip_address("10.10.30.1")
        or settings["target_port"] != 80
    ):
        raise PacketMonitorError("Configured packet-monitor endpoints no longer match the isolated campus topology.")
    return settings


def parse_interface_addresses(output: str) -> dict[str, set[ipaddress.IPv4Address]]:
    addresses: dict[str, set[ipaddress.IPv4Address]] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[2] != "inet":
            continue
        interface = fields[1].split("@", maxsplit=1)[0]
        try:
            address = ipaddress.ip_interface(fields[3]).ip
        except ValueError:
            continue
        if isinstance(address, ipaddress.IPv4Address):
            addresses.setdefault(interface, set()).add(address)
    return addresses


def verify_capture_path(settings: dict[str, Any]) -> str:
    if os.geteuid() != 0:
        raise PacketMonitorError("Packet capture requires root inside Mininet; invoke this from dclWeb.")
    try:
        if os.stat("/proc/self/ns/net").st_ino == os.stat("/proc/1/ns/net").st_ino:
            raise PacketMonitorError("Refusing to capture on the host network namespace; invoke from dclWeb.")
    except OSError as error:
        raise PacketMonitorError(f"Cannot verify Mininet network namespace: {error}") from error

    address_result = run_command(["ip", "-o", "-4", "address", "show"], "Inspect Mininet capture-host addresses")
    addresses = parse_interface_addresses(address_result.stdout)
    interfaces = [name for name, ips in addresses.items() if settings["target_ip"] in ips]
    if len(interfaces) != 1:
        raise PacketMonitorError(
            f"Mininet DMZ server address {settings['target_ip']} must be assigned to exactly one interface; found {len(interfaces)}."
        )
    interface = interfaces[0]
    if not interface.startswith(f"{settings['web_name']}-eth"):
        raise PacketMonitorError(f"Capture interface {interface} does not belong to {settings['web_name']}.")

    link_result = run_command(["ip", "-o", "link", "show"], "Inspect Mininet capture-host links")
    link_names = set()
    for line in link_result.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 2:
            link_names.add(fields[1].rstrip(":").split("@", maxsplit=1)[0])
    unexpected = link_names - {"lo", interface}
    if unexpected:
        raise PacketMonitorError(f"Unexpected interfaces on DMZ server host: {', '.join(sorted(unexpected))}.")

    bridge_ports = {
        port.strip()
        for port in run_command(
            ["ovs-vsctl", "--timeout=3", "list-ports", settings["core_bridge"]],
            f"Inspect OVS core {settings['core_bridge']}",
        ).stdout.splitlines()
        if port.strip() and port.strip() != settings["core_bridge"]
    }
    expected_nodes = [*settings["configured_host_names"], settings["router_name"]]
    expected_ports: set[str] = set()
    for node_name in expected_nodes:
        matching_ports = [port for port in bridge_ports if port.startswith(f"{node_name}-eth")]
        if len(matching_ports) != 1:
            raise PacketMonitorError(f"Expected one OVS core port for Mininet node {node_name}; found {len(matching_ports)}.")
        expected_ports.add(matching_ports[0])
    extra_ports = bridge_ports - expected_ports
    missing_ports = expected_ports - bridge_ports
    if extra_ports or missing_ports:
        raise PacketMonitorError(
            "OVS core port inventory is not isolated to configured Mininet nodes "
            f"(unexpected={sorted(extra_ports)}, missing={sorted(missing_ports)})."
        )

    port_name = next(port for port in expected_ports if port.startswith(f"{settings['web_name']}-eth"))
    if port_name != interface:
        raise PacketMonitorError(f"Discovered server interface {interface} differs from OVS port {port_name}.")
    vlan = run_command(
        ["ovs-vsctl", "--timeout=3", "get", "Port", port_name, "tag"],
        f"Verify DMZ OVS VLAN for {port_name}",
    ).stdout.strip().strip("[]")
    if vlan != str(settings["web_vlan"]):
        raise PacketMonitorError(f"Server OVS port {port_name} has VLAN {vlan}, expected VLAN {settings['web_vlan']}.")
    return interface


def parse_tcpdump_stats(output: str) -> tuple[int | None, int | None, int | None]:
    captured_match = re.search(r"^(\d+)\s+packets captured\b", output, re.MULTILINE)
    received_match = re.search(r"^(\d+)\s+packets received by filter\b", output, re.MULTILINE)
    dropped_match = re.search(r"^(\d+)\s+packets dropped by kernel\b", output, re.MULTILINE)
    return (
        int(captured_match.group(1)) if captured_match else None,
        int(received_match.group(1)) if received_match else None,
        int(dropped_match.group(1)) if dropped_match else None,
    )


def capture_packets(
    experiment_id: str,
    scenario: str,
    interface: str,
    target: ipaddress.IPv4Address,
    target_port: int,
    duration: float,
    output_path: Path,
) -> tuple[str, float, int, str]:
    if not math.isfinite(duration) or not 0 < duration <= MAX_CAPTURE_SECONDS:
        raise PacketMonitorError(f"Capture duration must be positive and at most {MAX_CAPTURE_SECONDS:g} seconds.")
    tcpdump = shutil.which("tcpdump")
    if not tcpdump:
        raise PacketMonitorError("tcpdump is unavailable; refusing to start a capture.")
    if output_path.exists():
        raise PacketMonitorError(f"Refusing to overwrite existing packet capture {output_path}.")

    capture_filter = f"host {target} and tcp port {target_port}"
    command = [tcpdump, "-nn", "-s", str(MAX_SNAPLEN), "-U", "-i", interface, "-w", str(output_path), capture_filter]
    started_at = utc_timestamp()
    start_monotonic = time.monotonic()
    print(f"Starting packet capture on {interface} for {duration:g}s: {capture_filter}", flush=True)

    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            start_new_session=True,
            close_fds=True,
        )
    except OSError as error:
        raise PacketMonitorError(f"Cannot start tcpdump: {error}") from error

    interrupted = threading.Event()
    previous_handlers: dict[int, Any] = {}

    def request_stop(_signum: int, _frame: Any) -> None:
        interrupted.set()

    for signum in (signal.SIGINT, signal.SIGTERM):
        previous_handlers[signum] = signal.signal(signum, request_stop)

    try:
        deadline = start_monotonic + duration
        while process.poll() is None and not interrupted.is_set():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            interrupted.wait(min(remaining, 0.2))
        if process.poll() is None:
            process.send_signal(signal.SIGINT)
        try:
            stderr_bytes = process.communicate(timeout=5)[1] or b""
        except subprocess.TimeoutExpired:
            process.kill()
            stderr_bytes = process.communicate(timeout=3)[1] or b""
    finally:
        for signum, previous_handler in previous_handlers.items():
            signal.signal(signum, previous_handler)

    finished_at = utc_timestamp()
    elapsed = time.monotonic() - start_monotonic
    stderr = stderr_bytes.decode("utf-8", errors="replace")
    if process.returncode not in (0, -signal.SIGINT):
        raise PacketMonitorError(f"tcpdump exited with status {process.returncode}: {stderr.strip() or 'no output'}")
    if not output_path.is_file():
        raise PacketMonitorError("tcpdump stopped without creating its packet capture file.")
    return finished_at, elapsed, process.returncode, stderr


def analyze_pcap(path: Path, elapsed_seconds: float) -> dict[str, int | float | None]:
    try:
        from scapy.layers.inet import IP, TCP
        from scapy.utils import PcapReader
    except ImportError as error:
        raise PacketMonitorError("Scapy is required to analyze the captured PCAP; install project requirements.") from error
    if not path.is_file():
        raise PacketMonitorError(f"Packet capture does not exist: {path}")
    if elapsed_seconds <= 0 or not math.isfinite(elapsed_seconds):
        raise PacketMonitorError("Capture elapsed time is unavailable; packet rates cannot be calculated.")

    total_packets = 0
    syn_packets = 0
    syn_ack_packets = 0
    ack_packets = 0
    total_ip_bytes = 0
    try:
        with PcapReader(str(path)) as reader:
            for packet in reader:
                if IP not in packet or TCP not in packet:
                    continue
                total_packets += 1
                ip_length = int(packet[IP].len) if packet[IP].len else len(bytes(packet[IP]))
                total_ip_bytes += ip_length
                flags = int(packet[TCP].flags)
                syn = bool(flags & 0x02)
                ack = bool(flags & 0x10)
                if syn and ack:
                    syn_ack_packets += 1
                elif syn:
                    syn_packets += 1
                if ack and not syn:
                    ack_packets += 1
    except (OSError, ValueError) as error:
        raise PacketMonitorError(f"Cannot analyze packet capture {path}: {error}") from error

    return {
        "network_total_packets": total_packets,
        "network_syn_packets": syn_packets,
        "network_syn_ack_packets": syn_ack_packets,
        "network_ack_packets": ack_packets,
        "network_packet_rate": total_packets / elapsed_seconds,
        "network_throughput": total_ip_bytes * 8 / elapsed_seconds,
        "security_syn_rate": syn_packets / elapsed_seconds,
        "security_syn_ack_ratio": syn_packets / syn_ack_packets if syn_ack_packets else None,
        "security_abnormal_handshake": (syn_packets / syn_ack_packets) > DEFAULT_SYN_ACK_THRESHOLD
        if syn_ack_packets
        else None,
        "network_dropped_packets": None,
        "network_bytes_captured": total_ip_bytes,
    }


def metric_records(
    experiment_id: str,
    scenario: str,
    metrics: dict[str, int | float | bool | None],
    timestamp: str,
    dropped_packets: int | None,
) -> list[dict[str, Any]]:
    units = {
        "network_total_packets": "packets",
        "network_syn_packets": "packets",
        "network_syn_ack_packets": "packets",
        "network_ack_packets": "packets",
        "network_packet_rate": "packets/s",
        "network_throughput": "bit/s",
        "security_syn_rate": "packets/s",
        "security_syn_ack_ratio": "ratio",
        "security_abnormal_handshake": "boolean",
        "network_dropped_packets": "packets",
        "network_bytes_captured": "bytes",
    }
    records = [
        make_metric_record(
            experiment_id,
            scenario,
            name,
            dropped_packets if name == "network_dropped_packets" else value,
            units[name],
            timestamp=timestamp,
        )
        for name, value in metrics.items()
    ]
    if "network_dropped_packets" not in metrics:
        records.append(
            make_metric_record(experiment_id, scenario, "network_dropped_packets", dropped_packets, "packets", timestamp=timestamp)
        )
    return records


def capture_and_measure(
    experiment_id: str,
    scenario: str,
    duration: float,
    results_root: Path = DEFAULT_RESULTS_ROOT,
    syn_ack_threshold: float = DEFAULT_SYN_ACK_THRESHOLD,
) -> int:
    validate_experiment_id(experiment_id)
    validate_scenario(scenario)
    if not math.isfinite(syn_ack_threshold) or syn_ack_threshold <= 0:
        raise PacketMonitorError("SYN/ACK abnormality threshold must be a positive finite number.")
    directory = experiment_directory(experiment_id, results_root)
    if not directory.is_dir():
        raise PacketMonitorError(f"Experiment directory does not exist: {directory}")
    validate_experiment_metadata(directory, experiment_id, scenario)
    settings = load_lab_config()
    interface = verify_capture_path(settings)
    capture_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
    pcap_path = directory / "pcap" / f"server_capture_{capture_id}.pcap"
    finished, elapsed, exit_code, tcpdump_output = capture_packets(
        experiment_id,
        scenario,
        interface,
        settings["target_ip"],
        settings["target_port"],
        duration,
        pcap_path,
    )

    capture_stats = parse_tcpdump_stats(tcpdump_output)
    try:
        metrics = analyze_pcap(pcap_path, elapsed)
    except PacketMonitorError as error:
        unavailable_metrics: dict[str, int | float | bool | None] = {
            "network_total_packets": None,
            "network_syn_packets": None,
            "network_syn_ack_packets": None,
            "network_ack_packets": None,
            "network_packet_rate": None,
            "network_throughput": None,
            "security_syn_rate": None,
            "security_syn_ack_ratio": None,
            "security_abnormal_handshake": None,
            "network_dropped_packets": capture_stats[2],
            "network_bytes_captured": None,
        }
        append_metric_records(
            experiment_id,
            scenario,
            metric_records(experiment_id, scenario, unavailable_metrics, finished, capture_stats[2]),
            results_root=results_root,
            stage="processed",
        )
        write_capture_log(directory, experiment_id, scenario, finished, elapsed, exit_code, tcpdump_output, error, capture_id)
        raise

    metrics["security_abnormal_handshake"] = (
        metrics["security_syn_ack_ratio"] > syn_ack_threshold
        if metrics["security_syn_ack_ratio"] is not None
        else None
    )
    records = metric_records(experiment_id, scenario, metrics, finished, capture_stats[2])
    append_metric_records(experiment_id, scenario, records, results_root=results_root, stage="processed")
    write_capture_log(directory, experiment_id, scenario, finished, elapsed, exit_code, tcpdump_output, None, capture_id)
    print(
        f"Capture complete: {metrics['network_total_packets']} packets, "
        f"{metrics['network_syn_packets']} SYN, {metrics['network_syn_ack_packets']} SYN-ACK, "
        f"{metrics['network_ack_packets']} ACK; pcap={pcap_path}",
        flush=True,
    )
    return 0


def write_capture_log(
    experiment_directory_path: Path,
    experiment_id: str,
    scenario: str,
    ended_at: str,
    elapsed: float,
    exit_code: int,
    tcpdump_output: str,
    analysis_error: Exception | None,
    capture_id: str,
) -> None:
    path = experiment_directory_path / "logs" / f"packet_capture_{capture_id}.log"
    try:
        with path.open("x", encoding="utf-8") as log_file:
            log_file.write(f"experiment_id={experiment_id}\nscenario={scenario}\nend_time={ended_at}\n")
            log_file.write(f"capture_elapsed_seconds={elapsed:.6f}\ntcpdump_exit_status={exit_code}\n")
            log_file.write(f"tcpdump_summary={tcpdump_output.strip()}\n")
            if analysis_error is not None:
                log_file.write(f"analysis_error={analysis_error}\n")
    except FileExistsError:
        raise PacketMonitorError(f"Refusing to overwrite packet capture log {path}.")
    except OSError as error:
        raise PacketMonitorError(f"Cannot save packet capture log {path}: {error}") from error


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--duration", type=float, default=30.0)
    parser.add_argument("--results-root", type=Path, default=DEFAULT_RESULTS_ROOT)
    parser.add_argument("--syn-ack-threshold", type=float, default=DEFAULT_SYN_ACK_THRESHOLD)
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        return capture_and_measure(
            args.experiment_id,
            args.scenario,
            args.duration,
            args.results_root,
            args.syn_ack_threshold,
        )
    except (PacketMonitorError, MonitorError, OSError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())