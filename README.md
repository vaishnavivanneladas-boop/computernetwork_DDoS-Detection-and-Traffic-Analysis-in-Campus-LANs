# DDoS Detection and Traffic Analysis in Campus LANs

An isolated Mininet/Open vSwitch laboratory for empirical traffic analysis and
mitigation experiments on Ubuntu 22.04 or newer. The campus VLAN topology, DMZ
HTTP service, and host-readiness utilities are implemented; traffic generation,
other monitoring, mitigation, analysis, and dashboard modules remain future
stages. No experimental results are included or claimed.

## Safety boundary

- The intended experiment network is created inside Mininet and uses the
  VLAN and address plan in `config/config.yaml`.
- The legitimate HTTP workload refuses to run from the host network namespace
  or unless its source address and route match the Mininet legitimate client.
- The edge segment is a Mininet-only point-to-point link. It has no upstream
  interface, NAT, or default route. IPv4 forwarding is enabled only in the
  Mininet campus-router namespace to route between the three internal VLANs.
- Future traffic-generation code must resolve its destination to a Mininet host
  in the active topology before sending any packets. It must never target a
  physical interface, the Internet, or an address outside that topology.
- `hping3` is a required host utility for a later stage; this stage does not run
  it.
- The cleanup option `scripts/cleanup.sh --mininet-global-cleanup` invokes
  `mn -c`, which removes Mininet state host-wide, not just state from this
  project. Use it only when no other Mininet lab needs to remain running.
- Run experiments only in an authorized, isolated environment. No real-network
  traffic or measurements are part of this project.

## Ubuntu setup

Install the system tools used by the lab:

```bash
sudo apt update
sudo apt install mininet openvswitch-switch hping3 tcpdump iproute2 iptables iputils-ping curl python3 python3-pip python3-venv
```

From the project root, check system prerequisites and the OVS service:

```bash
./scripts/check_environment.sh
./scripts/health_check.sh
```

Start the topology and open the Mininet CLI, or run the checks and shut down:

```bash
sudo .venv/bin/python topology/campus_topology.py --start
sudo .venv/bin/python topology/campus_topology.py --check
```

The script prints the discovered topology interfaces and addresses, validates
all configured IP assignments, and tests student-to-DMZ reachability, a
legitimate HTTP request, attack-host reachability, and the attack host's
Mininet-only route. Shutdown is scoped to this topology. To remove stale
resources from this project after an interrupted run, use
`sudo .venv/bin/python topology/campus_topology.py --cleanup`; it does not run the
host-wide `mn -c` cleanup.

Topology startup launches the standard-library HTTP service inside the DMZ
host, bound to `10.10.10.100:80`. It serves `/`, `/health`, and `/metrics`, and
appends timestamped per-request status/completion/response-time records to a
new `logs/http_requests_<run-id>.jsonl` file. Summarize an actual run with:

```bash
python3 monitoring/http_monitor.py summarize --input logs/http_requests_<run-id>.jsonl
python3 monitoring/http_monitor.py health
```

An empty raw log reports no percentage or average rather than inventing values.
The service is synchronous and uses buffered JSONL writes to keep monitoring
overhead low; summary calculations run separately after the experiment.

Python dependencies for the planned monitoring, analysis, and dashboard modules
can be installed in a virtual environment:

```bash
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

Mininet operations that create namespaces, virtual links, or OVS state require
root privileges. The readiness scripts do not use `sudo` unless explicitly
needed for a read-only OVS query. Future experiment entry points will request
privilege only for the operations that require it and will clean up their own
runtime state.

## Project layout

```text
config/       Shared lab configuration
topology/     Mininet topology definition (next stage)
traffic/      Mininet-scoped legitimate HTTP workload; test traffic (later)
monitoring/   HTTP service and summaries; other monitors (later stage)
mitigation/   Host/network mitigation controls (later stage)
experiments/  Reproducible experiment entry points (later stage)
analysis/     Raw-data analysis and result generation (later stage)
dashboard/    Results dashboard (later stage)
captures/     Packet captures
logs/         Timestamped run logs
results/      Derived outputs, kept separate from raw measurements
scripts/      Environment, cleanup, and health utilities
```

## Current stage and next stages

The current deliverables are `config/config.yaml`, this README,
`requirements.txt`, the scripts under `scripts/`, and
`topology/campus_topology.py`. The topology CLI starts the isolated network,
validates its connectivity, and provides project-scoped cleanup. The scripts
check host and OVS readiness; they do not assert that a Mininet topology is
running.

The legitimate HTTP client must be invoked from the `dclLegit` Mininet host. For
example, at the Mininet CLI:

```text
mininet> dclLegit python3 traffic/legitimate_client.py --target http://10.10.10.100/ --rate 30 --duration 30 --timeout 3 --output results/baseline_http.csv
```

This writes real response statuses and timings to a new CSV, and refuses to
overwrite an existing output file.

The bounded SYN test must be invoked from the `dclAttack` Mininet host and
requires explicit lab confirmation. Its defaults are capped at 50 packets,
5 packets/sec, 10 seconds, and a 64-byte IPv4 packet:

```text
mininet> dclAttack python3 traffic/syn_flood.py --lab-only --target 10.10.10.100 --count 50 --duration 10 --rate 5 --packet-size 64
```

It verifies the target's configured DMZ identity, host namespace, physical
interface assignments, attack route, OVS VLAN membership, and DMZ HTTP health
before starting `hping3`. Its JSON run log distinguishes sender-reported
transmissions from delivery, which it does not infer. Next, add timestamped raw
monitors and experiment runners that use `try/finally` cleanup.
Mitigation controls and analysis/dashboard modules follow after raw capture
formats and the supplied paper's actual experimental parameters are agreed.
The paper was not included with this request, so no paper-specific values or
results are assumed here.

Every future experiment must save timestamped raw observations before deriving
summaries. Results must be generated only from files produced by an actual run.