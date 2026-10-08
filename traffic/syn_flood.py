#!/usr/bin/env python3
"""Generate a bounded TCP SYN workload only from the configured Mininet attack host."""

from __future__ import annotations

import argparse
import ipaddress
import json
import math
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_ROOT / "config" / "config.yaml"
DEFAULT_TARGET = "10.10.10.100"
DEFAULT_PACKET_COUNT = 50
DEFAULT_DURATION_SECONDS = 10.0
DEFAULT_PACKET_RATE = 5.0
DEFAULT_PACKET_SIZE = 64
MAX_PACKET_COUNT = 500
MAX_DURATION_SECONDS = 60.0
MAX_PACKET_RATE = 20.0
MAX_PACKET_SIZE = 1200
MIN_PACKET_SIZE = 40
MAX_OUTPUT_BYTES = 256_000


class SafetyError(RuntimeError):
    """Invalid lab configuration, unsafe execution context, or failed preflight."""


class NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def timestamp_utc() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def run_command(arguments: list[str], description: str, timeout: float = 5.0) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SafetyError(f"{description} failed: {error}") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip() or f"exit status {result.returncode}"
        raise SafetyError(f"{description} failed: {detail}")
    return result


def load_lab_config() -> dict[str, Any]:
    try:
        import yaml
    except ImportError as error:
        raise SafetyError("PyYAML is required; install the project requirements before running lab traffic.") from error

    try:
        with CONFIG_PATH.open(encoding="utf-8") as config_file:
            config = yaml.safe_load(config_file)
    except (OSError, yaml.YAMLError) as error:
        raise SafetyError(f"Cannot load lab configuration {CONFIG_PATH}: {error}") from error

    try:
        topology = config["topology"]
        hosts = topology["hosts"]
        attack = hosts["attack"]
        web_server = hosts["web_server"]
        vlans = topology["vlans"]
        attack_vlan = int(attack["vlan"])
        web_vlan = int(web_server["vlan"])
        attack_network = ipaddress.ip_network(vlans[attack_vlan]["subnet"], strict=True)
        web_network = ipaddress.ip_network(vlans[web_vlan]["subnet"], strict=True)
        attack_gateway = ipaddress.ip_address(vlans[attack_vlan]["gateway"])
        attack_ip = ipaddress.ip_address(attack["ip"])
        target_ip = ipaddress.ip_address(web_server["ip"])
        target_port = int(topology["http"]["port"])
        core_bridge = topology["nodes"]["core_switch"]
        attack_name = attack["node"]
        web_name = web_server["node"]
        router_name = topology["nodes"]["campus_router"]
        configured_host_names = tuple(host["node"] for host in hosts.values())
        interface_prefix = topology["interface_prefix"]
    except (KeyError, TypeError, ValueError) as error:
        raise SafetyError(f"Lab configuration is missing valid attack/DMZ topology details: {error}") from error

    if not isinstance(target_ip, ipaddress.IPv4Address) or not target_ip.is_private or target_ip.is_loopback:
        raise SafetyError(f"Configured DMZ target {target_ip} is not a private IPv4 lab address.")
    if target_port != 80:
        raise SafetyError(f"Configured DMZ target must use TCP port 80, not {target_port}.")
    if not isinstance(attack_gateway, ipaddress.IPv4Address) or attack_gateway not in attack_network:
        raise SafetyError("Configured attack-host gateway is not a valid address in its VLAN subnet.")
    if not isinstance(attack_network, ipaddress.IPv4Network) or not isinstance(web_network, ipaddress.IPv4Network):
        raise SafetyError("Attack and DMZ networks must be IPv4 subnets.")
    if (
        not isinstance(attack_ip, ipaddress.IPv4Address)
        or not attack_ip.is_private
        or attack_ip not in attack_network
        or attack_ip == attack_gateway
    ):
        raise SafetyError("Configured attack-host address must be a usable private address in its VLAN subnet.")
    if target_ip not in web_network:
        raise SafetyError(f"Configured DMZ server {target_ip} is outside its configured subnet {web_network}.")
    if attack_vlan != 30 or web_vlan != 10:
        raise SafetyError("SYN test source must be configured in VLAN 30 and target in DMZ VLAN 10.")
    if attack_network != ipaddress.ip_network("10.10.30.0/24"):
        raise SafetyError("The Mininet attack host must remain in VLAN 30 subnet 10.10.30.0/24.")
    if web_network != ipaddress.ip_network("10.10.10.0/24"):
        raise SafetyError("The Mininet DMZ server must remain in VLAN 10 subnet 10.10.10.0/24.")
    if attack_gateway != ipaddress.ip_address("10.10.30.1"):
        raise SafetyError("The Mininet attack-host gateway must remain 10.10.30.1.")
    if attack_ip != ipaddress.ip_address("10.10.30.30") or target_ip != ipaddress.ip_address(DEFAULT_TARGET):
        raise SafetyError("Attack and DMZ host IPs must match the project's configured isolated topology.")
    if not isinstance(core_bridge, str) or not isinstance(attack_name, str) or not isinstance(web_name, str):
        raise SafetyError("Configured Mininet bridge and host names must be strings.")
    if (
        not isinstance(interface_prefix, str)
        or not attack_name.startswith(interface_prefix)
        or not web_name.startswith(interface_prefix)
        or not core_bridge.startswith(interface_prefix)
    ):
        raise SafetyError("Configured Mininet hosts must use the project's interface prefix.")

    return {
        "target_ip": target_ip,
        "target_port": target_port,
        "attack_ip": attack_ip,
        "attack_gateway": attack_gateway,
        "attack_network": attack_network,
        "web_network": web_network,
        "attack_vlan": attack_vlan,
        "web_vlan": web_vlan,
        "attack_name": attack_name,
        "web_name": web_name,
        "router_name": router_name,
        "configured_host_names": configured_host_names,
        "core_bridge": core_bridge,
    }


def validate_target(target: str, configured_target: ipaddress.IPv4Address) -> ipaddress.IPv4Address:
    try:
        address = ipaddress.ip_address(target)
    except ValueError as error:
        raise SafetyError(f"Target must be a literal configured Mininet IPv4 address: {error}") from error
    if not isinstance(address, ipaddress.IPv4Address):
        raise SafetyError("IPv6 targets are not permitted.")
    if address.is_loopback or not address.is_private:
        raise SafetyError(f"Target {address} is not a private Mininet lab address.")
    if address != configured_target:
        raise SafetyError(
            f"Target {address} is not the configured Mininet DMZ web server ({configured_target}); refusing to run."
        )
    return address


def validate_parameters(count: int, duration: float, rate: float, packet_size: int) -> None:
    if not 1 <= count <= MAX_PACKET_COUNT:
        raise SafetyError(f"Packet count must be between 1 and {MAX_PACKET_COUNT}.")
    if not math.isfinite(duration) or not 0 < duration <= MAX_DURATION_SECONDS:
        raise SafetyError(f"Duration must be positive and no more than {MAX_DURATION_SECONDS:g} seconds.")
    if not math.isfinite(rate) or not 0 < rate <= MAX_PACKET_RATE:
        raise SafetyError(f"Rate must be positive and no more than {MAX_PACKET_RATE:g} packets/sec.")
    if not MIN_PACKET_SIZE <= packet_size <= MAX_PACKET_SIZE:
        raise SafetyError(f"Packet size must be between {MIN_PACKET_SIZE} and {MAX_PACKET_SIZE} bytes.")


def require_root() -> None:
    if os.geteuid() != 0:
        raise SafetyError("Mininet packet generation requires root in the Mininet host. Run this command from dclAttack.")


def verify_not_host_namespace() -> None:
    try:
        current_netns = os.stat("/proc/self/ns/net").st_ino
        host_netns = os.stat("/proc/1/ns/net").st_ino
    except OSError as error:
        raise SafetyError(f"Cannot verify network namespace identity: {error}") from error
    if current_netns == host_netns:
        raise SafetyError("Refusing to run hping3 in the host network namespace; run inside Mininet dclAttack.")


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


def verify_target_not_on_host(target: ipaddress.IPv4Address) -> None:
    if not shutil.which("nsenter"):
        raise SafetyError("Cannot verify host physical interfaces: nsenter is unavailable; refusing to run.")
    result = run_command(
        ["nsenter", "--target", "1", "--net", "ip", "-o", "-4", "address", "show"],
        "Inspect host network interfaces",
    )
    host_addresses = parse_interface_addresses(result.stdout)
    interfaces_with_target = [name for name, addresses in host_addresses.items() if target in addresses]
    if interfaces_with_target:
        raise SafetyError(
            f"Refusing to run: target {target} is assigned to host interface(s) "
            f"{', '.join(interfaces_with_target)}."
        )


def verify_ovs_access_port(host_name: str, expected_vlan: int, core_bridge: str) -> str:
    if not shutil.which("ovs-vsctl"):
        raise SafetyError("ovs-vsctl is unavailable; cannot verify the Mininet topology.")
    port_output = run_command(
        ["ovs-vsctl", "--timeout=3", "list-ports", core_bridge],
        f"Inspect OVS core bridge {core_bridge}",
    )
    port_prefix = f"{host_name}-eth"
    candidates = [line.strip() for line in port_output.stdout.splitlines() if line.strip().startswith(port_prefix)]
    if len(candidates) != 1:
        raise SafetyError(
            f"Mininet topology check failed: expected one OVS port for {host_name} on {core_bridge}, "
            f"found {len(candidates)}."
        )
    port_name = candidates[0]
    tag = run_command(
        ["ovs-vsctl", "--timeout=3", "get", "Port", port_name, "tag"],
        f"Inspect VLAN tag for OVS port {port_name}",
    ).stdout.strip().strip("[]")
    if tag != str(expected_vlan):
        raise SafetyError(
            f"Mininet topology check failed: OVS port {port_name} is on VLAN {tag}, expected VLAN {expected_vlan}."
        )
    link_state = run_command(
        ["ovs-vsctl", "--timeout=3", "get", "Interface", port_name, "link_state"],
        f"Inspect link state for OVS interface {port_name}",
    ).stdout.strip().strip('"')
    if link_state != "up":
        raise SafetyError(f"Mininet topology check failed: OVS interface {port_name} is not up (state={link_state}).")
    return port_name


def verify_ovs_bridge_inventory(settings: dict[str, Any]) -> None:
    bridge_ports = {
        port.strip()
        for port in run_command(
            ["ovs-vsctl", "--timeout=3", "list-ports", settings["core_bridge"]],
            f"Inspect OVS core bridge {settings['core_bridge']}",
        ).stdout.splitlines()
        if port.strip() and port.strip() != settings["core_bridge"]
    }
    expected_ports = {f"{host_name}-eth0" for host_name in settings["configured_host_names"]}
    expected_ports.add(f"{settings['router_name']}-eth0")
    if bridge_ports != expected_ports:
        raise SafetyError(
            "Refusing to run: OVS core ports differ from the isolated Mininet topology "
            f"(unexpected={sorted(bridge_ports - expected_ports)}, missing={sorted(expected_ports - bridge_ports)})."
        )


def verify_attack_route(settings: dict[str, Any]) -> str:
    address_output = run_command(["ip", "-o", "-4", "address", "show"], "Inspect attack-host addresses")
    addresses = parse_interface_addresses(address_output.stdout)
    source = settings["attack_ip"]
    source_interfaces = [name for name, ips in addresses.items() if source in ips]
    if len(source_interfaces) != 1:
        raise SafetyError(
            f"Mininet source validation failed: {source} must be assigned to exactly one attack-host interface "
            f"(found {len(source_interfaces)})."
        )
    source_interface = source_interfaces[0]

    interface_output = run_command(["ip", "-o", "link", "show"], "Inspect attack-host interfaces").stdout
    current_interfaces = set()
    for line in interface_output.splitlines():
        fields = line.split()
        if len(fields) >= 2:
            current_interfaces.add(fields[1].rstrip(":").split("@", maxsplit=1)[0])
    unexpected_interfaces = current_interfaces - {"lo", source_interface}
    if unexpected_interfaces:
        raise SafetyError(
            "Refusing to run: attack host has unexpected interfaces outside its single Mininet link: "
            f"{', '.join(sorted(unexpected_interfaces))}."
        )

    route_output = run_command(
        ["ip", "-4", "route", "get", str(settings["target_ip"])],
        "Inspect route to configured DMZ server",
    ).stdout
    fields = route_output.split()
    try:
        route_interface = fields[fields.index("dev") + 1]
        route_source = ipaddress.ip_address(fields[fields.index("src") + 1])
        route_gateway = ipaddress.ip_address(fields[fields.index("via") + 1])
    except (ValueError, IndexError) as error:
        raise SafetyError(f"No verified internal Mininet route to {settings['target_ip']}: {route_output.strip()!r}.") from error

    if (
        route_interface != source_interface
        or route_source != source
        or route_gateway != settings["attack_gateway"]
    ):
        raise SafetyError(
            "Refusing to run: target route does not use the configured Mininet attack interface and gateway "
            f"(expected src {source} via {settings['attack_gateway']} dev {source_interface}; "
            f"observed {route_output.strip()!r})."
        )

    if not source_interface.startswith(f"{settings['attack_name']}-eth"):
        raise SafetyError(
            f"Refusing to run: route interface {source_interface} is not attached to Mininet host "
            f"{settings['attack_name']}."
        )
    return source_interface


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def verify_dmz_http(target: ipaddress.IPv4Address, port: int) -> None:
    url = f"http://{target}:{port}/health"
    opener = build_opener(ProxyHandler({}), NoRedirect())
    request = Request(url, headers={"Connection": "close", "User-Agent": "CampusLabSynPreflight/1.0"})
    try:
        with opener.open(request, timeout=2.0) as response:
            status = response.status
            payload = response.read(4096)
    except HTTPError as error:
        raise SafetyError(f"Configured Mininet DMZ server health check returned HTTP {error.code}.") from error
    except (URLError, TimeoutError, OSError) as error:
        raise SafetyError(f"Configured Mininet DMZ server did not respond at {url}: {error}.") from error
    if status != 200 or b'"status":"ok"' not in payload:
        raise SafetyError(f"Configured Mininet DMZ server returned an invalid health response (HTTP {status}).")


def validate_lab_path(target: ipaddress.IPv4Address, settings: dict[str, Any]) -> str:
    require_root()
    verify_not_host_namespace()
    verify_target_not_on_host(target)
    source_interface = verify_attack_route(settings)
    verify_ovs_bridge_inventory(settings)
    attack_port = verify_ovs_access_port(settings["attack_name"], settings["attack_vlan"], settings["core_bridge"])
    if source_interface != attack_port:
        raise SafetyError(
            f"Source route uses {source_interface}, but the configured Mininet OVS attack port is {attack_port}."
        )
    verify_ovs_access_port(settings["web_name"], settings["web_vlan"], settings["core_bridge"])
    verify_dmz_http(target, settings["target_port"])
    return source_interface


def build_hping_command(
    binary: str,
    source_interface: str,
    target: ipaddress.IPv4Address,
    port: int,
    count: int,
    rate: float,
    packet_size: int,
) -> list[str]:
    interval_microseconds = max(1, math.ceil(1_000_000 / rate))
    tcp_ipv4_header_bytes = 40
    payload_size = packet_size - tcp_ipv4_header_bytes
    return [
        binary,
        "-S",
        "-p",
        str(port),
        "-c",
        str(count),
        "-i",
        f"u{interval_microseconds}",
        "-d",
        str(payload_size),
        "-I",
        source_interface,
        str(target),
    ]


def parse_hping_statistics(output: str) -> tuple[int | None, int | None]:
    match = re.search(r"^\s*(\d+)\s+packets transmitted,\s*(\d+)\s+packets received\b", output, re.MULTILINE)
    if not match:
        return None, None
    return int(match.group(1)), int(match.group(2))


def stop_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    try:
        os.killpg(process.pid, signal.SIGINT)
        process.wait(timeout=2)
    except (ProcessLookupError, subprocess.TimeoutExpired):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=2)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                if process.poll() is None:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=2)


def run_hping(
    command: list[str],
    duration: float,
) -> tuple[int, str, bool, bool]:
    with tempfile.TemporaryFile() as output_file:
        try:
            process = subprocess.Popen(
                command,
                stdin=subprocess.DEVNULL,
                stdout=output_file,
                stderr=subprocess.STDOUT,
                start_new_session=True,
                close_fds=True,
            )
        except OSError as error:
            raise SafetyError(f"Cannot start hping3: {error}") from error

        duration_elapsed = False
        interrupted = False
        try:
            process.wait(timeout=duration)
        except subprocess.TimeoutExpired:
            duration_elapsed = True
            stop_process(process)
        except KeyboardInterrupt:
            interrupted = True
            stop_process(process)
        finally:
            if process.poll() is None:
                stop_process(process)

        output_file.seek(0)
        output = output_file.read(MAX_OUTPUT_BYTES + 1)
        if len(output) > MAX_OUTPUT_BYTES:
            output = output[:MAX_OUTPUT_BYTES] + b"\n[output truncated]\n"
        return process.returncode, output.decode("utf-8", errors="replace"), duration_elapsed, interrupted


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--lab-only", action="store_true", required=True,
                        help="explicitly confirm this run is confined to the authorized Mininet lab")
    parser.add_argument("--target", default=DEFAULT_TARGET, help="configured Mininet DMZ server IPv4 address")
    parser.add_argument("--count", type=int, default=DEFAULT_PACKET_COUNT,
                        help=f"maximum SYN packets requested (default: {DEFAULT_PACKET_COUNT}; max: {MAX_PACKET_COUNT})")
    parser.add_argument("--duration", type=float, default=DEFAULT_DURATION_SECONDS,
                        help=f"maximum run time in seconds (default: {DEFAULT_DURATION_SECONDS:g}; max: {MAX_DURATION_SECONDS:g})")
    parser.add_argument("--rate", type=float, default=DEFAULT_PACKET_RATE,
                        help=f"maximum packet rate per second (default: {DEFAULT_PACKET_RATE:g}; max: {MAX_PACKET_RATE:g})")
    parser.add_argument("--packet-size", type=int, default=DEFAULT_PACKET_SIZE,
                        help=f"IPv4 packet size in bytes (default: {DEFAULT_PACKET_SIZE}; range: {MIN_PACKET_SIZE}-{MAX_PACKET_SIZE})")
    parser.add_argument("--output", type=Path, help="new JSON run log (default: timestamped file under logs/)")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    record: dict[str, Any] = {
        "start_time": timestamp_utc(),
        "end_time": None,
        "source_host": "dclAttack",
        "target": args.target,
        "target_port": 80,
        "packet_count_requested": args.count,
        "packets_generated_reported_by_hping3": None,
        "responses_received_by_hping3": None,
        "configuration": {
            "duration_seconds": args.duration,
            "rate_packets_per_second": args.rate,
            "packet_size_bytes": args.packet_size,
            "lab_only_confirmed": args.lab_only,
        },
        "process_exit_status": None,
        "duration_limit_reached": False,
        "execution_started": False,
        "error": None,
    }

    output_path = args.output
    if output_path is None:
        run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
        output_path = PROJECT_ROOT / "logs" / f"syn_flood_{run_id}.json"

    log_file = None
    try:
        validate_parameters(args.count, args.duration, args.rate, args.packet_size)

        output_path.parent.mkdir(parents=True, exist_ok=True)
        try:
            log_file = output_path.open("x", encoding="utf-8")
        except FileExistsError as error:
            raise SafetyError(f"Refusing to overwrite existing run log: {output_path}") from error

        settings = load_lab_config()
        target = validate_target(args.target, settings["target_ip"])
        record["target"] = str(target)
        record["target_port"] = settings["target_port"]
        record["source_host"] = settings["attack_name"]
        record["configuration"].update({
            "source_ip": str(settings["attack_ip"]),
            "source_vlan": settings["attack_vlan"],
            "target_vlan": settings["web_vlan"],
            "packet_rate_packets_per_second": args.rate,
            "ipv4_packet_size_bytes": args.packet_size,
            "tcp_payload_size_bytes": args.packet_size - 40,
            "ovs_core_bridge": settings["core_bridge"],
        })

        validated_target = validate_target(args.target, settings["target_ip"])
        source_interface = validate_lab_path(validated_target, settings)
        record["configuration"]["verified_source_interface"] = source_interface
        binary = shutil.which("hping3")
        if binary is None:
            raise SafetyError("hping3 is not installed or not on PATH; no packets were sent.")

        command = build_hping_command(
            binary,
            source_interface,
            validated_target,
            settings["target_port"],
            args.count,
            args.rate,
            args.packet_size,
        )
        record["configuration"]["hping3_command"] = command
        record["start_time"] = timestamp_utc()
        record["execution_started"] = True
        print(
            f"Starting lab-only SYN test: {settings['attack_name']} -> {validated_target}:{settings['target_port']}, "
            f"max {args.count} packets, {args.rate:g} packets/sec, {args.duration:g}s, "
            f"IPv4 packet size {args.packet_size} bytes.",
            flush=True,
        )
        print("[PASS] Target, namespace, OVS VLANs, route, and DMZ HTTP health validated before hping3.", flush=True)

        exit_status, hping_output, duration_elapsed, interrupted = run_hping(command, args.duration)
        record["process_exit_status"] = exit_status
        record["duration_limit_reached"] = duration_elapsed
        record["interrupted"] = interrupted
        record["hping3_output"] = hping_output
        transmitted, received = parse_hping_statistics(hping_output)
        record["packets_generated_reported_by_hping3"] = transmitted
        record["responses_received_by_hping3"] = received
        if transmitted is None:
            record["packet_count_measurement_note"] = (
                "hping3 did not print a parseable transmit summary; actual packet count is unavailable."
            )
        record["delivery_claim"] = "None; hping3 sender statistics do not prove target delivery."
        print(
            f"hping3 exited with status {exit_status}; packets transmitted reported by hping3: "
            f"{transmitted if transmitted is not None else 'unavailable'}. No delivery is inferred.",
            flush=True,
        )
        if interrupted:
            record["error"] = "Interrupted by user; hping3 was stopped cleanly."
            return 130
        return 0 if exit_status == 0 else 1
    except (SafetyError, OSError, ValueError) as error:
        record["error"] = str(error)
        print(f"ERROR: {error}", file=sys.stderr, flush=True)
        return 1
    except KeyboardInterrupt:
        record["error"] = "Interrupted by user; hping3 was stopped cleanly."
        print("\nInterrupted; stopping hping3 and preserving the run log.", file=sys.stderr, flush=True)
        return 130
    finally:
        record["end_time"] = timestamp_utc()
        if log_file is not None:
            try:
                json.dump(record, log_file, indent=2, sort_keys=True)
                log_file.write("\n")
                log_file.flush()
                log_file.close()
                print(f"Run log saved: {output_path.relative_to(PROJECT_ROOT) if output_path.is_relative_to(PROJECT_ROOT) else output_path}", flush=True)
            except OSError as error:
                print(f"ERROR: Cannot save run log {output_path}: {error}", file=sys.stderr, flush=True)
                if log_file and not log_file.closed:
                    log_file.close()


if __name__ == "__main__":
    raise SystemExit(main())