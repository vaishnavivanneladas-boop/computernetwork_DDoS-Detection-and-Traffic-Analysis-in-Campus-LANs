#!/usr/bin/env python3
"""Build and validate the isolated Mininet campus LAN topology."""

from __future__ import annotations

import argparse
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_ROOT = Path(__file__).resolve().parents[1]
CONFIG_PATH = PROJECT_ROOT / "config" / "config.yaml"
HTTP_MONITOR_PATH = PROJECT_ROOT / "monitoring" / "http_monitor.py"


class TopologyError(RuntimeError):
    """A configuration, startup, or topology health-check failure."""


def load_config() -> dict[str, Any]:
    try:
        import yaml
    except ImportError as error:
        raise TopologyError(
            "PyYAML is required. Install project dependencies with "
            "python3 -m pip install -r requirements.txt."
        ) from error

    try:
        with CONFIG_PATH.open(encoding="utf-8") as config_file:
            config = yaml.safe_load(config_file)
    except (OSError, yaml.YAMLError) as error:
        raise TopologyError(f"Cannot load {CONFIG_PATH}: {error}") from error

    if not isinstance(config, dict) or not isinstance(config.get("topology"), dict):
        raise TopologyError("Configuration must contain a topology mapping.")
    return config


def validate_config(config: dict[str, Any]) -> dict[str, Any]:
    topology = config["topology"]
    nodes = topology.get("nodes")
    vlans = topology.get("vlans")
    hosts = topology.get("hosts")
    edge = topology.get("edge_transit")
    http = topology.get("http")
    prefix = topology.get("interface_prefix")

    if not all(isinstance(value, dict) for value in (nodes, vlans, hosts, edge, http)):
        raise TopologyError("Topology nodes, VLANs, hosts, edge_transit, and http must be mappings.")
    if not isinstance(prefix, str) or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9]*", prefix):
        raise TopologyError("topology.interface_prefix must be a short alphanumeric prefix.")

    required_nodes = {"core_switch", "campus_router", "edge"}
    required_hosts = {"student", "faculty", "legitimate_client", "attack", "web_server"}
    if set(nodes) != required_nodes or set(hosts) != required_hosts:
        raise TopologyError("Topology configuration must contain exactly the required node and host roles.")

    names = [nodes[key] for key in required_nodes]
    names.extend(hosts[key].get("node") for key in required_hosts if isinstance(hosts[key], dict))
    if any(not isinstance(name, str) or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9]*", name) for name in names):
        raise TopologyError("All Mininet node names must be alphanumeric identifiers.")
    if len(set(names)) != len(names):
        raise TopologyError("Mininet node names must be unique.")
    if any(not name.startswith(prefix) for name in names):
        raise TopologyError("Every node name must start with topology.interface_prefix for scoped cleanup.")
    if any(len(f"{name}-eth0") > 15 for name in names):
        raise TopologyError("Node names are too long for Linux Mininet interface names (maximum 15 characters).")

    vlan_networks: dict[int, ipaddress.IPv4Network] = {}
    assigned_ips: dict[str, str] = {}
    required_gateways = {10: "10.10.10.1", 20: "10.10.20.1", 30: "10.10.30.1"}
    for raw_vlan, settings in vlans.items():
        try:
            vlan_id = int(raw_vlan)
            subnet = ipaddress.ip_network(settings["subnet"], strict=True)
            gateway = ipaddress.ip_address(settings["gateway"])
        except (KeyError, TypeError, ValueError) as error:
            raise TopologyError(f"Invalid VLAN definition {raw_vlan!r}: {error}") from error
        if not isinstance(subnet, ipaddress.IPv4Network) or not 1 <= vlan_id <= 4094:
            raise TopologyError(f"VLAN {raw_vlan!r} must use an IPv4 subnet and VLAN ID 1..4094.")
        if not isinstance(gateway, ipaddress.IPv4Address):
            raise TopologyError(f"VLAN {vlan_id} gateway must be IPv4.")
        if vlan_id not in required_gateways or str(gateway) != required_gateways[vlan_id]:
            raise TopologyError(f"VLAN {vlan_id} gateway must be {required_gateways.get(vlan_id, 'configured')}.")
        if gateway not in subnet or gateway in (subnet.network_address, subnet.broadcast_address):
            raise TopologyError(f"Gateway {gateway} is not a usable address in {subnet}.")
        if str(gateway) in assigned_ips:
            raise TopologyError(f"Duplicate IP assignment: {gateway}.")
        assigned_ips[str(gateway)] = f"VLAN {vlan_id} gateway"
        vlan_networks[vlan_id] = subnet

    if set(vlan_networks) != {10, 20, 30}:
        raise TopologyError("The campus topology must define VLANs 10, 20, and 30.")

    for role, settings in hosts.items():
        if role not in required_hosts:
            continue
        try:
            address = ipaddress.ip_address(settings["ip"])
            vlan_id = int(settings["vlan"])
            subnet = vlan_networks[vlan_id]
        except (KeyError, TypeError, ValueError) as error:
            raise TopologyError(f"Invalid IP/VLAN assignment for host {role}: {error}") from error
        if not isinstance(address, ipaddress.IPv4Address):
            raise TopologyError(f"Host {role} must use an IPv4 address.")
        if address not in subnet or address in (subnet.network_address, subnet.broadcast_address):
            raise TopologyError(f"Host {role} address {address} is not usable in VLAN {vlan_id} ({subnet}).")
        if str(address) in assigned_ips:
            raise TopologyError(f"Duplicate IP assignment: {address} for {role} and {assigned_ips[str(address)]}.")
        assigned_ips[str(address)] = role

    try:
        transit_subnet = ipaddress.ip_network(edge["subnet"], strict=True)
        router_ip = ipaddress.ip_address(edge["router_ip"])
        edge_ip = ipaddress.ip_address(edge["edge_ip"])
        port = int(http["port"])
        response = http["response"]
    except (KeyError, TypeError, ValueError) as error:
        raise TopologyError(f"Invalid edge or HTTP configuration: {error}") from error

    if not isinstance(transit_subnet, ipaddress.IPv4Network) or transit_subnet.prefixlen != 30:
        raise TopologyError("The isolated edge transit must be an IPv4 /30 network.")
    if str(transit_subnet) != "172.16.1.0/30":
        raise TopologyError("The isolated edge transit must use 172.16.1.0/30.")
    for label, address in (("router", router_ip), ("edge", edge_ip)):
        if not isinstance(address, ipaddress.IPv4Address):
            raise TopologyError(f"Edge {label} address must be IPv4.")
        if address not in transit_subnet or address in (
            transit_subnet.network_address,
            transit_subnet.broadcast_address,
        ):
            raise TopologyError(f"Edge {label} address {address} is not usable in {transit_subnet}.")
        if str(address) in assigned_ips:
            raise TopologyError(f"Duplicate IP assignment: {address}.")
        assigned_ips[str(address)] = f"edge {label}"
    if router_ip == edge_ip:
        raise TopologyError("The edge router and edge host must have different addresses.")
    if str(router_ip) != "172.16.1.1" or str(edge_ip) != "172.16.1.2":
        raise TopologyError("Edge transit endpoints must be router 172.16.1.1 and edge 172.16.1.2.")
    if port != 80 or not isinstance(response, str) or not response:
        raise TopologyError("The DMZ HTTP service must use TCP port 80 and a non-empty root response.")

    web_settings = hosts["web_server"]
    dmz_subnet = vlan_networks[int(web_settings["vlan"])]
    if int(web_settings["vlan"]) != 10 or web_settings["ip"] != "10.10.10.100":
        raise TopologyError("The DMZ web server must use 10.10.10.100 on VLAN 10.")
    if str(vlan_networks[30]) != "10.10.30.0/24" or str(vlan_networks[20]) != "10.10.20.0/24":
        raise TopologyError("VLAN 20 and VLAN 30 subnets must match the specified campus architecture.")
    if str(dmz_subnet) != "10.10.10.0/24":
        raise TopologyError("VLAN 10 must use the specified 10.10.10.0/24 DMZ subnet.")

    return {
        "topology": topology,
        "nodes": nodes,
        "vlans": vlan_networks,
        "hosts": hosts,
        "edge_network": transit_subnet,
        "edge_router_ip": router_ip,
        "edge_ip": edge_ip,
        "http_port": port,
        "http_response": response,
        "interface_prefix": prefix,
    }


def run_host_command(arguments: list[str], description: str, timeout: int = 5) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(arguments, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise TopologyError(f"{description} failed: {error}") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        raise TopologyError(f"{description} failed (exit {result.returncode}): {detail or 'no command output'}")
    return result


def require_root(mode: str = "--start") -> None:
    if os.geteuid() != 0:
        raise TopologyError(
            "Mininet requires root privileges to create namespaces and virtual links. "
            f"Run: sudo .venv/bin/python topology/campus_topology.py {mode}"
        )


def check_ovs_ready() -> None:
    if not shutil.which("ovs-vsctl"):
        raise TopologyError("Open vSwitch is not installed (ovs-vsctl is unavailable).")
    if not shutil.which("systemctl") or subprocess.run(
        ["systemctl", "is-active", "--quiet", "openvswitch-switch"], check=False
    ).returncode != 0:
        raise TopologyError(
            "Open vSwitch is installed but not running. "
            "Start it with: sudo systemctl start openvswitch-switch"
        )
    run_host_command(["ovs-vsctl", "--timeout=3", "show"], "Open vSwitch database check")


def cleanup_owned_resources(settings: dict[str, Any], remove_bridge: bool) -> None:
    """Remove only this project's OVS bridge and its uniquely prefixed veths."""
    bridge = settings["nodes"]["core_switch"]
    prefix = settings["interface_prefix"]
    bridge_list = run_host_command(["ovs-vsctl", "list-br"], "List OVS bridges")
    bridges = set(bridge_list.stdout.splitlines())
    if bridge in bridges:
        if not remove_bridge:
            raise TopologyError(
                f"Project bridge {bridge} already exists; it may belong to a running topology. "
                "Stop that run, then explicitly use --cleanup if it is stale."
            )
        run_host_command(["ovs-vsctl", "--if-exists", "del-br", bridge], f"Remove project OVS bridge {bridge}")
        print(f"[CLEANUP] Removed project OVS bridge {bridge}.", flush=True)

    links = run_host_command(["ip", "-o", "link", "show"], "Discover host network interfaces")
    for line in links.stdout.splitlines():
        fields = line.split(":", maxsplit=2)
        if len(fields) < 2:
            continue
        interface = fields[1].strip().split("@", maxsplit=1)[0]
        if not interface.startswith(prefix) or "-eth" not in interface:
            continue
        details = run_host_command(["ip", "-d", "-o", "link", "show", "dev", interface],
                                   f"Inspect project interface {interface}")
        if "veth" not in details.stdout.lower():
            continue
        run_host_command(["ip", "link", "delete", "dev", interface], f"Remove stale project veth {interface}")
        print(f"[CLEANUP] Removed stale project veth {interface}.", flush=True)


def link_between(net: Any, first_name: str, second_name: str) -> Any:
    expected = {first_name, second_name}
    for link in net.links:
        actual = {link.intf1.node.name, link.intf2.node.name}
        if actual == expected:
            return link
    raise TopologyError(f"Expected Mininet link {first_name} <-> {second_name} was not created.")


def interface_on_link(link: Any, node_name: str) -> Any:
    for interface in (link.intf1, link.intf2):
        if interface.node.name == node_name:
            return interface
    raise TopologyError(f"Link does not have an interface belonging to {node_name}.")


def run_node_command(node: Any, arguments: list[str], description: str) -> str:
    stdout, stderr, return_code = node.pexec(*arguments)
    if return_code != 0:
        detail = (stderr or stdout).strip()
        raise TopologyError(f"{description} failed on {node.name} (exit {return_code}): {detail or 'no command output'}")
    return stdout.strip()


def configure_topology(net: Any, settings: dict[str, Any]) -> dict[str, Any]:
    nodes = settings["nodes"]
    hosts = settings["hosts"]
    core_name = nodes["core_switch"]
    router_name = nodes["campus_router"]
    core = net.get(core_name)
    router = net.get(router_name)

    access_links: dict[str, Any] = {}
    for role, host_settings in hosts.items():
        host_name = host_settings["node"]
        link = link_between(net, host_name, core_name)
        access_links[role] = link
        switch_interface = interface_on_link(link, core_name)
        vlan_id = int(host_settings["vlan"])
        run_host_command(
            ["ovs-vsctl", "set", "port", switch_interface.name, f"tag={vlan_id}"],
            f"Set access VLAN {vlan_id} on {switch_interface.name}",
        )

    trunk_link = link_between(net, router_name, core_name)
    trunk_interface = interface_on_link(trunk_link, router_name)
    switch_trunk_interface = interface_on_link(trunk_link, core_name)
    vlan_list = ",".join(str(vlan_id) for vlan_id in sorted(settings["vlans"]))
    run_host_command(
        ["ovs-vsctl", "set", "port", switch_trunk_interface.name, f"trunks={vlan_list}"],
        f"Configure OVS trunk {switch_trunk_interface.name}",
    )

    expected_addresses: dict[str, list[str]] = {}
    for role, host_settings in hosts.items():
        host_name = host_settings["node"]
        host = net.get(host_name)
        host_interface = interface_on_link(access_links[role], host_name)
        vlan_id = int(host_settings["vlan"])
        subnet = settings["vlans"][vlan_id]
        gateway = settings["topology"]["vlans"][vlan_id]["gateway"]
        address = ipaddress.ip_address(host_settings["ip"])
        host.setIP(str(address), prefixLen=subnet.prefixlen, intf=host_interface)
        host.setDefaultRoute(f"via {gateway}")
        expected_addresses.setdefault(host_name, []).append(f"{address}/{subnet.prefixlen}")

    router_addresses: list[str] = []
    for vlan_id in sorted(settings["vlans"]):
        subnet = settings["vlans"][vlan_id]
        gateway = ipaddress.ip_address(settings["topology"]["vlans"][vlan_id]["gateway"])
        vlan_interface = f"{trunk_interface.name}.{vlan_id}"
        if len(vlan_interface) > 15:
            raise TopologyError(f"VLAN interface name {vlan_interface} exceeds Linux's 15-character limit.")
        run_node_command(router, ["ip", "link", "add", "link", trunk_interface.name,
                                  "name", vlan_interface, "type", "vlan", "id", str(vlan_id)],
                         f"Create router VLAN {vlan_id} interface")
        run_node_command(router, ["ip", "address", "add", f"{gateway}/{subnet.prefixlen}",
                                  "dev", vlan_interface], f"Assign VLAN {vlan_id} gateway")
        run_node_command(router, ["ip", "link", "set", "dev", vlan_interface, "up"],
                         f"Bring up router VLAN {vlan_id} interface")
        router_addresses.append(f"{gateway}/{subnet.prefixlen}")

    run_node_command(router, ["ip", "link", "set", "dev", trunk_interface.name, "up"],
                     "Bring up campus router trunk")
    run_node_command(router, ["sysctl", "-w", "net.ipv4.ip_forward=1"],
                     "Enable IPv4 routing inside the Mininet campus router")
    expected_addresses[router_name] = router_addresses

    edge_name = nodes["edge"]
    edge_link = link_between(net, router_name, edge_name)
    router_edge_interface = interface_on_link(edge_link, router_name)
    edge_interface = interface_on_link(edge_link, edge_name)
    transit_prefix = settings["edge_network"].prefixlen
    router_ip = settings["edge_router_ip"]
    edge_ip = settings["edge_ip"]
    run_node_command(router, ["ip", "address", "add", f"{router_ip}/{transit_prefix}",
                              "dev", router_edge_interface.name], "Assign router edge-transit address")
    run_node_command(router, ["ip", "link", "set", "dev", router_edge_interface.name, "up"],
                     "Bring up router edge-transit interface")
    edge_host = net.get(edge_name)
    edge_host.setIP(str(edge_ip), prefixLen=transit_prefix, intf=edge_interface)
    run_node_command(edge_host, ["sysctl", "-w", "net.ipv4.ip_forward=0"],
                     "Keep edge-host forwarding disabled")
    expected_addresses[router_name].append(f"{router_ip}/{transit_prefix}")
    expected_addresses[edge_name] = [f"{edge_ip}/{transit_prefix}"]

    validate_ip_assignments(net, expected_addresses)
    return {
        "access_links": access_links,
        "trunk_interface": trunk_interface,
        "router_edge_interface": router_edge_interface,
        "edge_interface": edge_interface,
        "expected_pairs": expected_link_pairs(settings),
    }


def expected_link_pairs(settings: dict[str, Any]) -> set[frozenset[str]]:
    nodes = settings["nodes"]
    core = nodes["core_switch"]
    pairs = {frozenset((host["node"], core)) for host in settings["hosts"].values()}
    pairs.add(frozenset((nodes["campus_router"], core)))
    pairs.add(frozenset((nodes["campus_router"], nodes["edge"])))
    return pairs


def parse_ipv4_addresses(output: str) -> dict[str, set[str]]:
    addresses: dict[str, set[str]] = {}
    for line in output.splitlines():
        fields = line.split()
        if len(fields) < 4 or fields[2] != "inet":
            continue
        interface = fields[1].split("@", maxsplit=1)[0]
        if interface == "lo":
            continue
        addresses.setdefault(interface, set()).add(fields[3])
    return addresses


def validate_ip_assignments(net: Any, expected: dict[str, list[str]]) -> None:
    seen: dict[str, str] = {}
    for node_name, addresses in expected.items():
        for address in addresses:
            ip = str(ipaddress.ip_interface(address).ip)
            if ip in seen:
                raise TopologyError(f"Duplicate configured IP {ip} on {seen[ip]} and {node_name}.")
            seen[ip] = node_name

        node = net.get(node_name)
        actual = parse_ipv4_addresses(node.cmd("ip -o -4 address show"))
        actual_addresses = {address for values in actual.values() for address in values}
        for address in addresses:
            if address not in actual_addresses:
                raise TopologyError(f"IP validation failed: {node_name} is missing {address}.")
        unexpected = actual_addresses - set(addresses)
        if unexpected:
            raise TopologyError(
                f"IP validation failed: {node_name} has unexpected non-loopback IPv4 address(es): "
                f"{', '.join(sorted(unexpected))}."
            )
    print("[PASS] All configured IPv4 assignments are unique and match their interfaces.", flush=True)


def print_topology(net: Any) -> None:
    print("\nMininet hosts, interfaces, and IPv4 addresses:", flush=True)
    switch_names = {switch.name for switch in net.switches}
    for node in sorted([*net.hosts, *net.switches], key=lambda item: item.name):
        print(f"  {node.name}:", flush=True)
        for interface in node.intfList():
            if node.name in switch_names:
                output = node.cmd(f"ip -o -4 address show dev {interface.name}") or ""
            else:
                output = node.cmd("ip -o -4 address show") or ""
            addresses = parse_ipv4_addresses(output)
            interface_addresses = ", ".join(sorted(addresses.get(interface.name, set())))
            print(f"    {interface.name}: {interface_addresses or '<no IPv4 address>'}", flush=True)
        if node.name not in switch_names:
            output = node.cmd("ip -o -4 address show") or ""
            addresses = parse_ipv4_addresses(output)
            listed_interfaces = {interface.name for interface in node.intfList()}
            for interface_name, interface_addresses in sorted(addresses.items()):
                if interface_name not in listed_interfaces:
                    print(f"    {interface_name}: {', '.join(sorted(interface_addresses))}", flush=True)


def start_http_service(net: Any, settings: dict[str, Any]) -> tuple[Any, Path]:
    web_settings = settings["hosts"]["web_server"]
    web_host = net.get(web_settings["node"])
    log_dir = PROJECT_ROOT / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    request_log = log_dir / f"http_requests_{run_id}.jsonl"
    process = web_host.popen(
        [
            sys.executable,
            str(HTTP_MONITOR_PATH),
            "serve",
            "--log-file",
            str(request_log),
            "--host-netns-inode",
            str(os.stat("/proc/self/ns/net").st_ino),
            "--bind",
            web_settings["ip"],
            "--port",
            str(settings["http_port"]),
            "--root-response",
            settings["http_response"],
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    print(f"[HTTP] Request log: {request_log.relative_to(PROJECT_ROOT)}", flush=True)
    return process, request_log


def ping_or_fail(source: Any, destination: str, label: str) -> None:
    stdout, stderr, return_code = source.pexec("ping", "-c", "1", "-W", "2", destination)
    if return_code != 0:
        detail = (stderr or stdout).strip()
        raise TopologyError(
            f"Health check failed: {label} cannot reach {destination} by ICMP "
            f"(exit {return_code}): {detail or 'no ping response'}."
        )
    print(f"[PASS] {label} can reach {destination}.", flush=True)


def validate_attack_path(net: Any, settings: dict[str, Any], topology_links: dict[str, Any]) -> None:
    nodes = settings["nodes"]
    hosts = settings["hosts"]
    attack_name = hosts["attack"]["node"]
    attack = net.get(attack_name)
    web_ip = hosts["web_server"]["ip"]

    actual_pairs = {
        frozenset((link.intf1.node.name, link.intf2.node.name)) for link in net.links
    }
    if actual_pairs != topology_links["expected_pairs"]:
        unexpected = actual_pairs - topology_links["expected_pairs"]
        missing = topology_links["expected_pairs"] - actual_pairs
        raise TopologyError(
            f"Health check failed: Mininet link inventory differs from the isolated design "
            f"(unexpected={sorted(map(sorted, unexpected))}, missing={sorted(map(sorted, missing))})."
        )

    attack_link = topology_links["access_links"]["attack"]
    attack_interface = interface_on_link(attack_link, attack_name)
    if interface_on_link(attack_link, nodes["core_switch"]).node.name != nodes["core_switch"]:
        raise TopologyError("Health check failed: attack host is not connected to the OVS core.")

    stdout, stderr, return_code = attack.pexec("ip", "-4", "route", "get", web_ip)
    if return_code != 0:
        detail = (stderr or stdout).strip()
        raise TopologyError(f"Health check failed: cannot inspect attack-host route to DMZ ({detail}).")
    route_fields = stdout.split()
    if "dev" not in route_fields or route_fields[route_fields.index("dev") + 1] != attack_interface.name:
        raise TopologyError(
            f"Health check failed: attack-host route to {web_ip} does not use its Mininet core link "
            f"{attack_interface.name}: {stdout.strip()}"
        )
    expected_gateway = settings["topology"]["vlans"][int(hosts["attack"]["vlan"])]["gateway"]
    if "via" not in route_fields or route_fields[route_fields.index("via") + 1] != expected_gateway:
        raise TopologyError(
            f"Health check failed: attack-host route to {web_ip} does not use internal gateway "
            f"{expected_gateway}: {stdout.strip()}"
        )

    for node_name in (nodes["campus_router"], nodes["edge"]):
        node = net.get(node_name)
        route_output, route_error, route_code = node.pexec("ip", "-4", "route", "show", "default")
        if route_code != 0:
            detail = (route_error or route_output).strip()
            raise TopologyError(f"Health check failed: cannot inspect {node_name} default route ({detail}).")
        if route_output.strip():
            raise TopologyError(
                f"Health check failed: {node_name} has an external-capable default route: "
                f"{route_output.strip()}"
            )

    edge_neighbors = {
        neighbor
        for pair in actual_pairs
        if nodes["edge"] in pair
        for neighbor in pair
        if neighbor != nodes["edge"]
    }
    if edge_neighbors != {nodes["campus_router"]}:
        raise TopologyError("Health check failed: edge host has a link outside the Mininet campus router.")
    print(
        "[PASS] Attack-host route to the DMZ uses only its Mininet OVS-core link; "
        "no external interface or upstream route is present.",
        flush=True,
    )


def run_health_checks(net: Any, settings: dict[str, Any], topology_links: dict[str, Any], server_process: Any) -> None:
    print("\nRunning topology health checks...", flush=True)
    student = net.get(settings["hosts"]["student"]["node"])
    web_settings = settings["hosts"]["web_server"]
    ping_or_fail(student, web_settings["ip"], "Student/Lab host")

    legitimate = net.get(settings["hosts"]["legitimate_client"]["node"])
    health_url = f"http://{web_settings['ip']}/health"
    last_detail = "HTTP health endpoint did not become available"
    for _attempt in range(20):
        if server_process.poll() is not None:
            server_error = server_process.stderr.read().decode("utf-8", errors="replace").strip()
            detail = f" {server_error}" if server_error else ""
            raise TopologyError(f"Health check failed: Mininet web server exited before serving requests.{detail}")
        stdout, stderr, return_code = legitimate.pexec(
            sys.executable, str(HTTP_MONITOR_PATH), "health", "--url", health_url, "--timeout", "2",
        )
        if return_code == 0:
            print(f"[PASS] DMZ health endpoint responded: {health_url}", flush=True)
            break
        last_detail = (stderr or stdout).strip() or f"curl exited with status {return_code}"
        time.sleep(0.25)
    else:
        raise TopologyError(f"Health check failed: DMZ HTTP health endpoint {health_url}: {last_detail}.")

    root_url = f"http://{web_settings['ip']}/"
    stdout, stderr, return_code = legitimate.pexec(
        "curl", "--fail", "--silent", "--show-error", "--connect-timeout", "2", "--max-time", "3", root_url,
    )
    if return_code != 0:
        detail = (stderr or stdout).strip() or f"curl exited with status {return_code}"
        raise TopologyError(f"Health check failed: legitimate HTTP request to {root_url}: {detail}.")
    if settings["http_response"] not in stdout:
        raise TopologyError(
            f"Health check failed: HTTP request to {root_url} returned an unexpected response: {stdout.strip()!r}."
        )
    print(f"[PASS] Legitimate HTTP request succeeded: {root_url}", flush=True)

    ping_or_fail(net.get(settings["hosts"]["attack"]["node"]), web_settings["ip"], "Attack/test host")
    validate_attack_path(net, settings, topology_links)


def build_mininet(settings: dict[str, Any]) -> Any:
    try:
        from mininet.net import Mininet
        from mininet.node import OVSBridge
        from mininet.topo import Topo
    except ImportError as error:
        raise TopologyError(
            "Mininet's Python package is unavailable. Install the Ubuntu mininet package "
            "and run this script with the system Python."
        ) from error

    class CampusTopo(Topo):
        def build(self) -> None:
            core_name = settings["nodes"]["core_switch"]
            self.addSwitch(core_name, cls=OVSBridge, dpid="0000000000000001")
            for host_settings in settings["hosts"].values():
                host_name = host_settings["node"]
                self.addHost(host_name, ip=None)
                self.addLink(host_name, core_name)
            router_name = settings["nodes"]["campus_router"]
            edge_name = settings["nodes"]["edge"]
            self.addHost(router_name, ip=None)
            self.addHost(edge_name, ip=None)
            self.addLink(router_name, core_name)
            self.addLink(router_name, edge_name)

    return Mininet(topo=CampusTopo(), controller=None, autoSetMacs=True, build=False)


def execute_topology(settings: dict[str, Any], enter_cli: bool) -> None:
    require_root("--start" if enter_cli else "--check")
    check_ovs_ready()
    cleanup_owned_resources(settings, remove_bridge=False)

    required_commands = ("mnexec", "ip", "ping", "curl", "sysctl")
    missing_commands = [command for command in required_commands if not shutil.which(command)]
    if missing_commands:
        raise TopologyError(f"Required host command(s) unavailable: {', '.join(missing_commands)}.")

    net = None
    server_process = None
    request_log = None
    operation_error: Exception | None = None
    cleanup_errors: list[str] = []
    try:
        print("Starting isolated campus topology...", flush=True)
        print(
            "Path: Student/Lab -> OVS Core/Distribution (VLAN 30) -> "
            "Campus Router -> OVS Core/Distribution (VLAN 10) -> DMZ Web Server",
            flush=True,
        )
        net = build_mininet(settings)
        net.build()
        net.start()
        print("[PASS] OVS core and Mininet links are up.", flush=True)
        topology_links = configure_topology(net, settings)
        print_topology(net)
        server_process, request_log = start_http_service(net, settings)
        run_health_checks(net, settings, topology_links, server_process)
        print("\nTopology is healthy and isolated.", flush=True)

        if enter_cli:
            from mininet.cli import CLI

            print("Starting Mininet CLI. Exit with 'exit' or Ctrl-D to shut down cleanly.", flush=True)
            CLI(net)
    except Exception as error:
        operation_error = error
    finally:
        if server_process is not None:
            try:
                if server_process.poll() is None:
                    server_process.terminate()
                    try:
                        server_process.wait(timeout=3)
                    except subprocess.TimeoutExpired:
                        server_process.kill()
                        server_process.wait(timeout=3)
            except Exception as error:
                cleanup_errors.append(f"HTTP service shutdown failed: {error}")
            if server_process.poll() is not None and server_process.stderr is not None:
                server_error = server_process.stderr.read().decode("utf-8", errors="replace").strip()
                if server_error:
                    print(f"[HTTP] Server diagnostic: {server_error}", file=sys.stderr, flush=True)
        if net is not None:
            try:
                net.stop()
            except Exception as error:
                cleanup_errors.append(f"Mininet shutdown failed: {error}")
        try:
            cleanup_owned_resources(settings, remove_bridge=True)
        except Exception as error:
            cleanup_errors.append(f"Project resource cleanup failed: {error}")
    if operation_error is not None:
        if cleanup_errors:
            raise TopologyError(f"{operation_error}; additionally, {'; '.join(cleanup_errors)}") from operation_error
        if isinstance(operation_error, TopologyError):
            raise operation_error
        raise TopologyError(f"Topology execution failed: {operation_error}") from operation_error
    if cleanup_errors:
        raise TopologyError("; ".join(cleanup_errors))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group(required=True)
    modes.add_argument("--start", action="store_true", help="start the topology and open the Mininet CLI")
    modes.add_argument("--check", action="store_true", help="start, health-check, and cleanly stop the topology")
    modes.add_argument("--cleanup", action="store_true", help="remove only this project's stale OVS bridge and veths")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    try:
        settings = validate_config(load_config())
        if args.cleanup:
            require_root("--cleanup")
            check_ovs_ready()
            cleanup_owned_resources(settings, remove_bridge=True)
            print("[PASS] Project-scoped cleanup completed.", flush=True)
            return 0
        execute_topology(settings, enter_cli=args.start)
        return 0
    except KeyboardInterrupt:
        print("\nERROR: Topology interrupted by user; cleanup was requested.", file=sys.stderr, flush=True)
        return 130
    except TopologyError as error:
        print(f"ERROR: {error}", file=sys.stderr, flush=True)
        return 1
    except Exception as error:
        print(f"ERROR: Unexpected topology failure: {error}", file=sys.stderr, flush=True)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())