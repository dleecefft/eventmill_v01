# Event Mill

**Event record analysis platform for Security Operations and Detection Engineering teams.**

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)

---

## What is Event Mill?

Event Mill is an open-source platform for analyzing unfamiliar event sources before committing to full SIEM integration. It lives upstream of the SIEM — in the gap between "we just got access to a new event source" and "we have a parser, field mappings, and detection rules in production."

### Value Propositions

1. **New source triage**: Speed up initial analysis of unfamiliar event sources to determine whether they contain enough security-relevant information to warrant engineering investment.

2. **Incident-time analysis**: During incidents, analysts receive event artifacts (logs, PCAPs, audit exports) for unfamiliar systems. Event Mill helps gain context quickly without requiring full knowledge of the event record structure.

### What Event Mill is NOT

- Not a SIEM replacement
- Not a real-time collection system
- Not an alerting platform

---

## Architecture

Event Mill uses a three-layer architecture:

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

| Pillar | Purpose | Status |
|--------|---------|--------|
| `log_analysis` | Event source triage, threat intel ingestion, image analysis | MVP |
| `network_forensics` | PCAP triage, firewall log analysis | MVP |
| `threat_modeling` | Shostack 4-question framework, attack path visualization | MVP |
| `cloud_investigation` | Cloud audit log analysis | Post-MVP |
| `risk_assessment` | Risk scoring, control effectiveness | Post-MVP |

---

## Quick Start

### Installation

```bash
# Clone the repository
git clone https://github.com/dleecefft/event_mill.git
cd event_mill

# Install with pip
pip install -e .[all]

# Or install specific components
pip install -e .[dev,plugins-log-analysis]
```

### Configuration

```bash
# Copy example environment file
cp .env.example .env

# Edit with your API keys and settings
# Required: GEMINI_API_KEY, ANTHROPIC_API_KEY, or OPENAI_API_KEY
```

### Running

```bash
# Start the CLI
eventmill

# Or run directly
python -m framework.cli.shell
```

### IP Enrichment (BigQuery)

Enrich all IPs from a loaded PCAP with asset/threat data from BigQuery:

```bash
# After loading a PCAP, enrich IPs from a BQ table
enrich --table <project.dataset.table> --fields <col1,col2,...> [--ip-column <column_name>]

# Example: OT asset enrichment
enrich --table ot-asset-inventory.ot2ai_inventory.gold_ot_assets_bqt --ip-column ip_address --fields ot_network,asset_type,criticality,host_name,purdue_level

# Single IP lookup
enrich --table myproj.dataset.assets --fields hostname,zone --ip 10.1.5.20

# Show cached enrichment / clear cache
enrich show
enrich clear
```

Enrichment data is automatically injected into all `pcap_ai_analyzer` modes (triage, hunt, OT, netops, report).

**Requires:** `pip install eventmill[gcp]` and `roles/bigquery.jobUser` + `roles/bigquery.dataViewer` on the service account.

---

## Directory Structure

```
event_mill/
├── framework/              # Framework layer
│   ├── cli/               # Metasploit-style command shell
│   ├── session/           # Session management (SQLite)
│   ├── routing/           # Plugin routing and filtering
│   ├── llm/               # MCP client and LLM orchestration
│   ├── artifacts/         # Artifact registry
│   ├── plugins/           # Plugin lifecycle management
│   ├── reference_data/    # MITRE ATT&CK, attack chains, vetted sources
│   ├── logging/           # Structured logging
│   └── cloud/             # Cloud abstraction (GCP, local)
├── plugins/               # Plugin layer
│   ├── log_analysis/
│   ├── network_forensics/
│   ├── cloud_investigation/
│   ├── risk_assessment/
│   └── threat_modeling/
├── tests/                 # Test suites
├── scripts/               # CI and utility scripts
├── docs/                  # Documentation
│   ├── specs/            # Normative specifications
│   ├── guides/           # User guides
│   └── reference/        # Reference documentation
└── workspace/             # Runtime data (gitignored)
```

---

## Plugin Development

Plugins are self-describing tools following the `EventMillToolProtocol`. Each plugin provides:

- `manifest.json` — Metadata, capabilities, schemas
- `tool.py` — Protocol implementation
- `schemas/` — Input/output JSON schemas
- `examples/` — Request/response examples
- `tests/` — Contract tests

See [Plugin Development Guide](docs/guides/plugin_development.md) and [Tool Plugin Spec](docs/specs/tool_plugin_spec.md).

---

## Documentation

| Document | Purpose |
|----------|---------|
| [Grounding Document](docs/specs/eventmill_v1_1.md) | Strategic context and MVP scope |
| [Framework Architecture](docs/specs/framework_architecture.md) | Component responsibilities and data flow |
| [Tool Plugin Spec](docs/specs/tool_plugin_spec.md) | Normative plugin contract |
| [Router Design](docs/specs/router_design.md) | Routing architecture and scoring |

---

## Contributing

Contributions welcome! Please read the plugin development guide before submitting new tools.

```bash
# Run tests
pytest

# Validate manifests
python scripts/validate_manifests.py

# Validate schemas
python scripts/validate_schemas.py
```

---

## License

Apache License 2.0. See [LICENSE](LICENSE) for details.
