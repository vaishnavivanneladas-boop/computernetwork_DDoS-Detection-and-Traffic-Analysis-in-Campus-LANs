# DDoS Detection and Traffic Analysis in Campus LANs

A reproducible, isolated Mininet/Open vSwitch laboratory for measuring TCP SYN traffic, HTTP availability, server resource use, and mitigation behavior. All packet generation and capture are constrained to configured Mininet hosts and the internal DMZ web server. Packet Tracer may be used to draw the architecture, but it is not part of runtime execution.

This project does not contain research-paper results. Reports are calculated only from artifacts produced by actual experiment runs; missing measurements are shown as `N/A` or `null`/`unavailable`.

## 1. Project Objective

Compare a legitimate HTTP baseline with bounded SYN traffic under no defense, SYN Cookies, and SYN Cookies plus an experimental router rate limit. Collect raw request records, process samples, packet captures, and derived summaries with an experiment ID for each run.

## 2. Research Motivation

Campus LAN services may experience degraded application availability and server load during bursts of TCP connection attempts. An isolated emulator enables repeatable measurements without sending test traffic to a campus network, a public address, or an external system.

## 3. Architecture

Mininet creates separate host network namespaces and virtual links. An Open vSwitch core carries VLAN 10, 20, and 30. A Mininet router provides inter-VLAN routing. The topology has no NAT, external uplink, or default route. The DMZ server runs a Python standard-library HTTP service on TCP port 80. Monitoring and mitigations run in Mininet namespaces; result analysis runs locally from saved files.

## 4. Network Topology and IP Addressing

| Segment | VLAN | Subnet | Gateway | Example host |
| --- | ---: | --- | --- | --- |
| Student/Lab | 30 | `10.10.30.0/24` | `10.10.30.1` | `dclStudent` |
| Faculty/Admin | 20 | `10.10.20.0/24` | `10.10.20.1` | `dclFaculty` |
| Server DMZ | 10 | `10.10.10.0/24` | `10.10.10.1` | `dclWeb`, `10.10.10.100` |
| Edge transit | none | `172.16.1.0/30` | point-to-point | router `.1`, edge `.2` |

The legitimate client is `dclLegit` (`10.10.30.20`); the controlled test source is `dclAttack` (`10.10.30.30`). The web server address and port are `10.10.10.100:80`. Exact host settings are in [config/config.yaml](config/config.yaml).

## 5. Software Requirements

- Ubuntu 22.04 or newer, Python 3.10 or newer
- Mininet and Open vSwitch (`mininet`, `openvswitch-switch`)
- `hping3` for the bounded SYN test
- `tcpdump`, `iproute2`, `iptables`, `iputils-ping`, and `curl`
- Python packages in [requirements.txt](requirements.txt): Flask, PyYAML, Matplotlib, pandas, psutil, and Scapy

Wireshark GUI, `tshark`, `sar`, and `mpstat` are optional. Wireshark can inspect saved PCAPs; experiment execution uses tcpdump/Scapy.

## 6. Hardware Requirements

Use an Ubuntu-capable Linux host with enough CPU and memory to run several network namespaces and an OVS bridge. Two or more CPU cores and 4 GB RAM are practical starting recommendations, not benchmark guarantees. Record the actual host/kernel configuration with each study; performance depends on the machine and load.

## 7. Installation

```bash
sudo apt update
sudo apt install mininet openvswitch-switch hping3 tcpdump iproute2 iptables iputils-ping curl python3 python3-pip python3-venv python3-yaml
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

The venv uses system site packages so it can import Ubuntu's Mininet package. Topology operations require root; the supported experiment wrappers request it only when needed.

## 8. Environment Verification

From the project root:

```bash
./scripts/check_environment.sh
./scripts/health_check.sh
```

The checker does not install packages. It exits nonzero and prints `ENVIRONMENT STATUS: NOT READY` if mandatory tools/modules are missing. If OVS is installed but stopped, it prints the safe start command; it does not start the service automatically.

## 9. Starting Mininet and the HTTP Server

Run an interactive topology:

```bash
sudo .venv/bin/python topology/campus_topology.py --start --scenario baseline
```

Or run topology and connectivity checks, then shut it down:

```bash
sudo .venv/bin/python topology/campus_topology.py --check --scenario baseline
```

The topology automatically starts the DMZ HTTP service inside `dclWeb`, bound only to `10.10.10.100:80`. It serves `/`, `/health`, and `/metrics`. It also starts process monitoring and timestamped server-facing packet capture. The health checks exercise the actual Mininet path. Use `--cleanup` for project-scoped cleanup after an interrupted run:

```bash
sudo .venv/bin/python topology/campus_topology.py --cleanup
```

Do not use `scripts/cleanup.sh --mininet-global-cleanup` unless you intentionally want host-wide `mn -c`, which can disrupt other Mininet projects.

## 10. Running the Four Experiments

Each wrapper checks the environment, starts a fresh project-scoped topology, runs its scenario, gathers data, rolls back mitigations, and cleans up. Each run receives a unique `EXP_YYYYMMDD_HHMMSS` ID.

```bash
./experiments/run_baseline.sh
./experiments/run_attack.sh
./experiments/run_syn_cookies.sh
./experiments/run_combined.sh
```

Run all four sequentially and stop at the first failure:

```bash
./experiments/run_all.sh
```

Scenario names are `baseline`, `syn_flood_no_defense`, `syn_cookies`, and `syn_cookies_rate_limit`. The configured traffic values are experimental parameters in `config/config.yaml`, not claims of optimal thresholds.

## 11. Controlled SYN Traffic

The SYN generator is for an authorized, isolated Mininet lab only. It requires `--lab-only`, accepts only the configured DMZ address, verifies the source namespace/route and OVS topology before invoking hping3, and has finite packet and duration caps. Scenario orchestration invokes it from `dclAttack`; do not run it against any non-Mininet target.

Manual invocation from the Mininet CLI is also bounded:

```text
mininet> dclAttack python3 traffic/syn_flood.py --lab-only --target 10.10.10.100 --count 50 --duration 10 --rate 5 --packet-size 64
```

The JSON run log records hping3-reported transmissions separately from delivery. Sender statistics are not proof that packets reached the server.

## 12. SYN Cookies

The scenario wrapper enables SYN Cookies only inside the Mininet DMZ host and resets the saved prior value before topology teardown. For manual use in an interactive topology, use the experiment ID printed by topology startup:

```text
mininet> dclWeb bash mitigation/syn_cookies.sh --enable --experiment-id EXP_YYYYMMDD_HHMMSS
mininet> dclWeb bash mitigation/reset_mitigation.sh --experiment-id EXP_YYYYMMDD_HHMMSS
```

The enable script logs the previous/new values and reads backlog/retry settings without changing them.

## 13. SYN Rate Limiting

The rate-limit rule is installed only in the Mininet router namespace, in the forwarding path from VLAN 30 to the DMZ server on TCP port 80. The rate and burst are configurable in YAML and explicitly experimental. The script verifies the exact rule, counters, and a health request from the legitimate Mininet client. It removes only its saved experiment-specific rules.

For manual operation, first obtain the Mininet client process PID, then pass it to the router script:

```text
mininet> dclLegit echo $$
mininet> dclRtr bash mitigation/rate_limit.sh --apply --experiment-id EXP_YYYYMMDD_HHMMSS --legitimate-pid <PID_PRINTED_ABOVE>
mininet> dclRtr bash mitigation/rate_limit.sh --remove --experiment-id EXP_YYYYMMDD_HHMMSS
```

The combined scenario applies SYN Cookies and rate limiting before controlled test traffic and resets both afterward.

## 14. Packet Capture and Analysis

Topology startup invokes [monitoring/capture_packets.sh](monitoring/capture_packets.sh) inside `dclWeb`. It discovers the interface assigned to `10.10.10.100`, verifies VLAN 10 and the exact configured OVS port inventory, and captures only `host 10.10.10.100 and tcp port 80`. It refuses the host network namespace and stops on topology shutdown or its bounded timeout. PCAPs and timestamped capture logs are stored under that experiment's `pcap/` and `logs/` directories.

The analyzer runs automatically after capture. To analyze a saved capture manually:

```bash
.venv/bin/python analysis/packet_analysis.py --experiment-id EXP_YYYYMMDD_HHMMSS --scenario baseline --pcap results/EXP_YYYYMMDD_HHMMSS/pcap/server_capture_<timestamp>.pcap --capture-log results/EXP_YYYYMMDD_HHMMSS/logs/server_capture_<timestamp>.log
```

The report distinguishes initial SYN (`tcp.flags.syn == 1 && tcp.flags.ack == 0`), SYN-ACK, and ACK packets. The SYN/ACK ratio is only a handshake imbalance indicator; it is not a percentage of failed connections. Throughput is labeled approximate and derived from captured bytes and measured duration.

## 15. Result Analysis

After all four scenarios have produced artifacts, generate comparison files:

```bash
sudo .venv/bin/python analysis/generate_results.py
```

This creates `results/summary.csv`, `summary.json`, `report.md`, `final_comparison.csv`, `final_comparison.json`, and `final_report.md`. It reads experiment artifacts only, shows missing metrics as N/A, and refuses to overwrite existing summaries. Move/archive existing summaries before generating a new set. CPU reduction is calculated relative to measured no-defense attack CPU. HTTP recovery is the measured completion-rate percentage-point difference relative to that attack scenario.

HTTP completion is `successful legitimate responses / total legitimate requests * 100`. SYN/ACK is `initial SYN / SYN-ACK`; no ratio is reported when the denominator is zero.

## 16. Rule-Based Detection

The detector is explainable rule-based scoring, not machine learning. It evaluates sustained SYN rate, handshake imbalance, CPU, memory, drops, HTTP completion, and response time against thresholds/weights in `config.yaml`. It does not block traffic.

```bash
.venv/bin/python detection/ddos_detector.py --experiment-id EXP_YYYYMMDD_HHMMSS --scenario syn_flood_no_defense
```

Alerts include contributing indicators and reasons. The configured thresholds are local experimental parameters, not universal security values; isolated single-sample spikes do not satisfy the sustained window.

## 17. Local Dashboard

Start the dashboard on loopback only:

```bash
.venv/bin/python dashboard/dashboard.py --results-root results --port 5050
```

Open `http://127.0.0.1:5050/`. It uses local result files, inline SVG graphs, and no external cloud/CDN. It labels live and historical measurements separately; if data is absent it says “No experiment data available.”

## 18. Output Layout

Each experiment has an isolated directory:

```text
results/<experiment_id>/
├── raw/         Per-request HTTP CSV, legitimate-client CSV, process samples
├── processed/   Packet metrics, HTTP aggregates, detector scores, reports
├── logs/        Manifest, scenario state, mitigation/capture/orchestration logs
└── pcap/        Server-facing packet capture
```

Raw CSV rows use `timestamp, experiment_id, scenario, metric_name, value, unit, status`; unavailable values are `null` with status `unavailable`. No prior experiment directory is reused.

## 19. Directory Structure

```text
analysis/       PCAP analyzer and comparison-result generator
config/         Topology, rate-limit, traffic, and detector parameters
dashboard/      Local Flask dashboard
detection/      Sustained rule-based detector
experiments/    Baseline, attack, mitigation, and sequential runners
mitigation/     Mininet-only SYN Cookie and rate-limit apply/reset scripts
monitoring/     HTTP, psutil, packet monitors, and scoped PCAP capture
scripts/        Environment, health, and cleanup utilities
topology/       Mininet campus VLAN topology
traffic/        Legitimate HTTP and bounded SYN generators
```

## 20. Hardware and Reproducibility Notes

A Linux host with resources for multiple Mininet namespaces and OVS is required; two CPU cores and 4 GB RAM are practical starting recommendations, not guarantees. Record the actual Ubuntu/kernel, Mininet/OVS versions, config, experiment ID, and scenario artifacts. Runs are sequential, use unique IDs, and preserve raw PCAP/CSV/log data. The paper's expected numbers are never copied into generated output.

## 21. Troubleshooting

- `ENVIRONMENT STATUS: NOT READY`: install only the missing Ubuntu/Python packages shown by the checker; it never installs automatically.
- `Open vSwitch is installed but not running.`: inspect the message and, if appropriate, run `sudo systemctl start openvswitch-switch` yourself.
- Missing Mininet/root errors: use the documented `.venv` interpreter with `sudo`; confirm Mininet is installed system-wide and the venv has `--system-site-packages`.
- Capture refuses an interface/bridge: do not bypass the check. Inspect the Mininet server IP, VLAN 10 tag, and OVS bridge port inventory.
- Existing experiment/results output: choose a new experiment ID; summary outputs must be archived or moved before regeneration.
- Mitigation reset error: keep the topology/router/server running and use the recorded experiment state; the scripts refuse to modify a different namespace or overwrite unrelated firewall/sysctl state.

## 22. Safety Restrictions

This project is for an authorized, isolated Mininet lab only. Never target public IPs, Internet hosts, physical host interfaces, Wi-Fi, or real campus devices. hping3 runs only after the attack host namespace, source route, target address, OVS ports/VLANs, and DMZ health are verified. The topology has no external uplink/NAT/default route. Do not disable these guards or run global firewall/kernel tuning.

## 23. Cleanup

Scenario wrappers clean the project topology and attempt mitigation rollback on success, errors, and Ctrl+C. For manual topology sessions, exit the Mininet CLI or run the project-scoped cleanup command:

```bash
sudo .venv/bin/python topology/campus_topology.py --cleanup
```

The host-wide `mn -c` option is separate and may disrupt unrelated labs; it is not used by experiment runners.

## 24. Limitations

Mininet is a software emulator, not a campus production network. CPU scheduling, kernel version, packet capture drops, and local hardware affect observed measurements. hping3 transmission counts do not establish server delivery. Packet metrics depend on successfully finalized PCAPs; unavailable measurements remain N/A. Detector thresholds and rate-limit settings require study-specific justification and are not asserted to be optimal. Live experiment execution requires Mininet, OVS, hping3, Scapy, psutil, and the configured local Python dependencies.
