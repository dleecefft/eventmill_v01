# Threat Intel Ingester

Event Mill plugin for ingesting threat intelligence reports and extracting structured IOC data.

## Purpose

Ingests threat intelligence reports (PDF, HTML, STIX, CSV/JSON IOC lists) and extracts structured IOC data with MITRE ATT&CK mapping.

## Supported Artifact Types

**Consumed:**
- `pdf_report` — PDF threat intel reports, vendor advisories
- `html_report` — HTML blog posts, advisories, CERT bulletins
- `text` — Plain text, CSV, STIX bundles

**Produced:**
- `json_events` — Structured IOC records

## Output Persistence

This plugin manages its own output persistence. On successful completion it writes the full IOC dataset to:
```
workspace/artifacts/<artifact_id>_ti_iocs.json
```
The file is registered as a `json_events` session artifact with the ID shown in the run summary (e.g., `Output artifact: art_04d30b48 (json_events)`). Use that ID directly as input to `attack_path_visualizer` via `artifact_id`. Use `export <artifact_id>` to push the JSON to `common/exports/threat_intel_ingester/` in cloud storage for external access or troubleshooting.

## LLM Dependency

**requires_llm: true**

This plugin uses LLM capabilities for:
- Contextual IOC extraction beyond regex patterns
- Confidence scoring and priority assessment
- MITRE ATT&CK technique inference
- False positive filtering

If the MCP connection is unavailable, the plugin falls back to regex-only extraction with low confidence scores.

## Example Request

```json
{
  "artifact_id": "art_0001",
  "source_context": "Mandiant M-Trends 2025 Report",
  "ioc_types": ["ip", "domain", "hash_sha256", "url", "cve", "mitre_technique"],
  "confidence_threshold": "low",
  "max_pages": 50
}
```

## Example summarize_for_llm() Output

```
Ingested pdf_report (12 pages): APT29 Campaign Analysis. Attributed to APT29 (high confidence), campaign: SolarWinds Follow-on. Extracted 47 IOCs: 23 ips, 12 domains, 8 hash_sha256s, 4 cves. 3 IOCs flagged as high-priority. Mapped to 6 MITRE techniques: T1566.001 (Spearphishing Attachment), T1059.001 (PowerShell), T1053.005 (Scheduled Task), T1071.001 (Web Protocols), T1486 (Data Encrypted for Impact), T1048.003 (Exfiltration Over Unencrypted Protocol). Output artifact: art_0002 (json_events).
```

## Limitations

- PDF extraction quality depends on document structure
- LLM refinement adds latency (~5-15 seconds)
- Maximum 200 pages per PDF
- STIX 2.1 parsing not yet implemented

## Safety Notes

**safe_for_auto_invoke: true**

This tool is read-only and low-risk. It processes local artifacts and does not make external network calls beyond the MCP connection.

## Dependencies

Beyond framework baseline:
- `pdfplumber>=0.10.0`
- `beautifulsoup4>=4.12.0`
- `stix2>=3.0.0` (for future STIX support)

## Reference Data Overrides

None.
