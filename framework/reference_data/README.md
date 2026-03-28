# Event Mill Reference Data

This directory contains shared reference data available to all tools.
Data is loaded at startup and made available via the `ReferenceDataView` interface.

## Contents

- `mitre_attack_enterprise.json` — MITRE ATT&CK Enterprise taxonomy
- `mitre_attack_ics.json` — MITRE ATT&CK ICS taxonomy
- `attack_chain_patterns.json` — Common attack chain patterns
- `vetted_sources.json` — Curated URLs for threat intel, research, regulatory bodies

## Usage

Plugins access reference data via `context.reference_data.get("key")`.

Plugin-specific reference data in a plugin's `data/` directory can extend
or override these entries when that plugin is active.
