# Event Mill

**Event record analysis platform for Security Operations, OT/ICS Security, and Detection Engineering teams.**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

---

## What is Event Mill?

Event Mill is an open-source platform for analyzing unfamiliar event sources before committing to full SIEM integration. It lives upstream of the SIEM — in the gap between "we just got access to a new event source" and "we have a parser, field mappings, and detection rules in production."

### Value Propositions

1. **New source triage**: Speed up initial analysis of unfamiliar event sources.
2. **Incident-time analysis**: During incidents, gain context on event artifacts (logs, PCAPs, audit exports) quickly.
3. **OT/ICS Network Forensics**: Analyze industrial control system traffic with Modbus, DNP3, S7, CIP, OPC-UA, BACnet protocol awareness.
4. **Network Operations Health**: Assess STP, OSPF, EIGRP, ARP, HSRP/VRRP control plane health from PCAPs.

---

## Quick Start

### Installation

```bash
git clone https://github.com/dleecefft/eventmill_v01.git
cd eventmill_v01
pip install -e .[all]
```

### Running Locally

```bash
eventmill
# Or:
python -m framework.cli.shell
```

### Cloud Run Deployment

```bash
gcloud builds submit \
  --project=YOUR_PROJECT_ID \
  --config=cloud_install/cloudbuild.yaml \
  --substitutions=COMMIT_SHA=$(git rev-parse --short HEAD),_BUCKET_PREFIX=YOUR_PROJECT_ID-eventmill .
```

---

## CLI Command Reference

### Session Management

| Command | Usage | Description |
|---------|-------|-------------|
| `new` | `new [description]` | Create a new investigation session |
| `sessions` | `sessions` | List all sessions |
| `load_session` | `load_session <id>` | Switch to an existing session |
| `delete_session` | `delete_session <id>` | Delete a session |
| `status` | `status` | Show current session info |

### Pillar & Workspace

| Command | Usage | Description |
|---------|-------|-------------|
| `pillar` | `pillar network_forensics` | Set active investigation pillar |
| `workspace` | `workspace [folder\|clear]` | Set/show/clear workspace folder in bucket |
| `files` | `files` | List files in current pillar bucket |
| `buckets` | `buckets` | Show configured storage buckets |

### Loading Artifacts

| Command | Usage | Description |
|---------|-------|-------------|
| `load` | `load <file> [--fast] [--merge]` | Load a PCAP/log file |
| `load` | `load <folder> --merge --fast` | Load all PCAPs in folder, merged |
| `export` | `export <artifact_id>` | Export artifact to common bucket |

**Flags:**
- `--fast` — Use dpkt (5-10x faster, recommended for PCAPs >100 MB)
- `--merge` — Cumulative load, merge multiple PCAPs into one session

### Zeek Integration (Cloud Build)

Process large PCAPs (multi-GB) on dedicated Cloud Build machines:

| Command | Usage | Description |
|---------|-------|-------------|
| `zeek <file>` | `zeek capture.pcap` | Submit single PCAP to Zeek |
| `zeek <folder> --parallel` | `zeek Dragos_report/ --parallel` | Submit all PCAPs in parallel (one machine each) |
| `zeek <file> --async` | `zeek big.pcap --async` | Submit and return immediately |
| `zeek status` | `zeek status [--batch]` | Check job status |
| `zeek list` | `zeek list` | List available Zeek outputs |
| `zeek load` | `zeek load <folder>` | Load Zeek output into session |
| `zeek load --merge` | `zeek load --merge` | Merge all parallel batch outputs |
| `zeek jobs` | `zeek jobs` | List submitted jobs |

**Parallel processing** submits one Cloud Build job per PCAP (E2_HIGHCPU_32: 32 vCPU, 32 GB RAM, 500 GB disk). All run simultaneously, auto-merge when complete.

### Network Discovery

Subnets are automatically discovered during PCAP parsing from OSPF, DHCP, ARP, and broadcast traffic:

| Command | Usage | Description |
|---------|-------|-------------|
| `networks` | `networks` | Show discovered networks |
| `networks enrich` | `networks enrich --table <t> --network-column <col> --fields <f>` | Overlay BQ subnet data |
| `networks assume` | `networks assume /22` | Change default mask assumption |
| `networks export` | `networks export json\|csv` | Export network list |
| `networks clear` | `networks clear` | Clear BQ enrichment |

### IP Enrichment (BigQuery)

| Command | Usage | Description |
|---------|-------|-------------|
| `enrich` | `enrich --table <t> --fields <f> [--ip-column <c>]` | Enrich all PCAP IPs from BQ |
| `enrich` | `enrich --table <t> --fields <f> --ip <addr>` | Single IP lookup |
| `enrich show` | `enrich show` | Show cached enrichment |
| `enrich clear` | `enrich clear` | Clear cache |

### AI Analysis Tools

Run tools with: `run <tool_name> --flag value`

#### pcap_ai_analyzer

AI-powered PCAP analysis with multiple modes:

```bash
run pcap_ai_analyzer --mode triage_summary              # Quick triage
run pcap_ai_analyzer --mode ot_triage                   # OT/ICS focused triage
run pcap_ai_analyzer --mode ot_threat_hunt              # OT threat hunting (MITRE ATT&CK for ICS)
run pcap_ai_analyzer --mode ot_report --export-type pdf # Full OT report as PDF
run pcap_ai_analyzer --mode netops_health               # Network operations health
run pcap_ai_analyzer --mode hunt_beacons                # Beacon detection
run pcap_ai_analyzer --mode hunt_dns                    # DNS anomaly hunting
run pcap_ai_analyzer --mode hunt_lateral                # Lateral movement detection
run pcap_ai_analyzer --mode report --export-type pdf    # Full report as PDF

# Focus on specific IPs only:
run pcap_ai_analyzer --mode ot_triage --focus-ips 10.1.5.1,10.1.5.2
```

**Modes:** `triage_summary`, `hunt_talkers`, `hunt_beacons`, `hunt_dns`, `hunt_tls`, `hunt_lateral`, `hunt_exfil`, `report`, `ot_triage`, `ot_threat_hunt`, `ot_report`, `netops_triage`, `netops_health`, `netops_report`

**Flags:** `--mode`, `--export-type pdf`, `--condition-orange true`, `--focus-ips <ip1,ip2,...>`

#### pcap_threat_hunter

Static (non-AI) threat hunting:

```bash
run pcap_threat_hunter --hunt talkers    # Top talkers analysis
run pcap_threat_hunter --hunt beacons    # Beacon/C2 detection
run pcap_threat_hunter --hunt dns        # DNS anomalies
run pcap_threat_hunter --hunt lateral    # Lateral movement
run pcap_threat_hunter --hunt exfil      # Data exfiltration
```

#### pcap_metadata_summary

```bash
run pcap_metadata_summary --mode summary          # Overview
run pcap_metadata_summary --mode conversations    # Connection table
run pcap_metadata_summary --mode dns              # DNS queries
run pcap_metadata_summary --mode tls              # TLS handshakes
```

#### pcap_flow_analyzer

```bash
run pcap_flow_analyzer --mode bidirectional       # Bidirectional flow analysis
run pcap_flow_analyzer --mode long_connections    # Long-lived connections
run pcap_flow_analyzer --mode protocol_breakdown  # Protocol distribution
```

#### pcap_ip_search

```bash
run pcap_ip_search --query 10.1.5.22             # Search for specific IP
run pcap_ip_search --mode ioc                    # IOC-focused search
```

#### firewall_log_aggregator

```bash
run firewall_log_aggregator --mode load --log-format auto
run firewall_log_aggregator --mode summary
run firewall_log_aggregator --mode deny_hotspots
run firewall_log_aggregator --mode port_scan
```

### LLM Connection

| Command | Usage | Description |
|---------|-------|-------------|
| `models` | `models` | List available LLM models |
| `connect` | `connect [model_id]` | Connect to LLM (tiered auto-routing) |
| `ask:` | `ask: <question>` | Query LLM with session context |
| `route` | `route <query>` | Show routing decision |

### Utility

| Command | Usage | Description |
|---------|-------|-------------|
| `tools` | `tools [pillar]` | List available tools |
| `help` | `help [command\|tool]` | Show help |
| `artifacts` | `artifacts` | List loaded artifacts |
| `history` | `history [clear]` | LLM conversation history |
| `exit` | `exit` | Exit Event Mill |

---

## PCAP Parsing Engines

| Engine | Speed | Use Case | Protocols |
|--------|-------|----------|-----------|
| **Scapy** | Slow | Small PCAPs, full protocol decode | All L2-L7 |
| **dpkt** (`--fast`) | 5-10x faster | Large PCAPs (>100 MB) | All L2-L7 |
| **Zeek** (Cloud Build) | Parallel | Multi-GB PCAPs | Full analysis with OT plugins |

All three engines produce identical `PcapSession` objects with:
- Conversations, DNS, HTTP, TLS, OT/ICS protocols
- STP/RSTP/MSTP BPDU analysis
- CDP/LLDP switch identity discovery
- OSPF/EIGRP/HSRP/VRRP control plane
- ARP health, ICMP errors, routing loops
- Cleartext credential detection
- Network/subnet discovery

---

## OT/ICS Protocol Support

| Protocol | Source | Detection |
|----------|--------|-----------|
| Modbus TCP | All engines | Function codes, unit IDs, writes, diagnostics |
| DNP3 | All engines | Objects, function codes, unsolicited responses |
| S7comm | All engines | CPU control, block transfers |
| EtherNet/IP + CIP | All engines | Service codes, class/instance |
| OPC-UA Binary | All engines | Service types, session management |
| BACnet | All engines | Object access, write property |
| IEC 60870-5-104 | Zeek only | ASDU types, IOA addressing |

---

## Network Operations Features

- **STP Analysis**: BPDU counts, root elections, topology changes, BPDU starvation detection, port roles/states
- **CDP/LLDP**: Switch identity from PCAP — device IDs, platforms, management IPs, port descriptions
- **OSPF**: Hello adjacencies, LSA updates, network mask extraction, area/router inventory
- **EIGRP**: AS numbers, update/query/reply tracking
- **HSRP/VRRP**: Gateway redundancy state tracking
- **ARP Health**: Storm detection, IP conflicts, gratuitous ARP, unanswered requests
- **Network Discovery**: Automatic subnet inference from OSPF, DHCP, ARP, broadcasts

---

## Cloud Run Configuration

| Setting | Value |
|---------|-------|
| Memory | 32 Gi |
| CPU | 8 vCPU |
| Timeout | 3600s |
| Min instances | 1 |
| Concurrency | 5 |
| Region | northamerica-northeast2 |

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     FRAMEWORK LAYER                          │
│  CLI • Session Management • LLM Orchestration • Routing     │
│  Artifact Registry • Plugin Lifecycle • Cloud Abstraction   │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                      PLUGIN LAYER                            │
│  Self-describing tools following EventMillToolProtocol      │
│  Organized by investigation pillar                          │
└─────────────────────────────────────────────────────────────┘
                              │
┌─────────────────────────────────────────────────────────────┐
│                     ROUTING LAYER                            │
│  Controls which plugins are visible to LLM per request      │
│  Prevents context bloat from full tool catalog              │
└─────────────────────────────────────────────────────────────┘
```

### Investigation Pillars

| Pillar | Purpose | Tools |
|--------|---------|-------|
| `network_forensics` | PCAP analysis, firewall logs, OT/ICS | 8 tools |
| `log_analysis` | Event source triage, threat intel | 5 tools |
| `threat_modeling` | Attack path visualization | Post-MVP |
| `cloud_investigation` | Cloud audit log analysis | Post-MVP |
| `risk_assessment` | Risk scoring | Post-MVP |

---

## Directory Structure

```
eventmill_v01/
├── framework/              # Framework layer
│   ├── cli/               # Metasploit-style command shell
│   ├── session/           # Session management (SQLite)
│   ├── routing/           # Plugin routing and filtering
│   ├── llm/               # LLM orchestration (Gemini Flash/Pro)
│   ├── artifacts/         # Artifact registry
│   ├── plugins/           # Plugin lifecycle management
│   ├── reference_data/    # MITRE ATT&CK lookup
│   ├── logging/           # Structured logging (Cloud Logging)
│   └── cloud/             # GCS storage resolver, Zeek Cloud Build
├── plugins/               # Plugin layer
│   ├── log_analysis/      # Log tools (investigator, searcher, patterns)
│   ├── network_forensics/ # PCAP tools (8 tools)
│   ├── threat_modeling/   # Attack path tools
│   ├── cloud_investigation/
│   └── risk_assessment/
├── cloud_install/         # Cloud Run deployment (Dockerfile, cloudbuild.yaml)
├── tests/                 # Test suites
├── scripts/               # Utility scripts
└── docs/                  # Documentation
```

---

## License

Apache License 2.0 — see [LICENSE](LICENSE).
