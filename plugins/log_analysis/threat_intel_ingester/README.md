# Threat Intel Ingester

Event Mill plugin for ingesting threat intelligence reports and extracting structured IOC data.

## Purpose

Ingests threat intelligence reports (PDF, HTML, STIX, CSV/JSON IOC lists) and extracts structured IOC data with MITRE ATT&CK mapping.

For **PDF reports**, the plugin now supports **native PDF ingestion via the Gemini API** — the full PDF document is sent directly to the model, preserving tables, formatting, and cross-page context that text extraction loses. The plugin automatically selects the best ingestion path and falls back to chunked text extraction when native ingestion is unavailable.

## How to Run

### Prerequisites

1. **Gemini API keys** — set in your environment or deploy config:
   ```bash
   export GEMINI_FLASH_API_KEY="your-flash-key"
   export GEMINI_PRO_API_KEY="your-pro-key"
   ```
2. **Python dependencies** — installed via `pip install ".[plugins-log-analysis]"` from the project root.
3. **MITRE ATT&CK lookup** (one-time setup) — build the local technique database:
   ```bash
   python scripts/build_mitre_lookup.py
   ```
   This downloads the Enterprise and ICS ATT&CK STIX bundles from the
   [MITRE CTI repository](https://github.com/mitre/cti) (currently pinned
   to **ATT&CK v18.1**) and writes a compact lookup file to
   `plugins/log_analysis/threat_intel_ingester/data/mitre_techniques.json`
   (~774 techniques). The plugin uses this file to:
   - **Enrich** LLM output with authoritative technique names and tactics
   - **Backfill** technique IDs referenced in attack graphs but missing from mappings
   - **Validate** every technique ID and mark non-ATT&CK IDs with `(non-ATT&CK ID)`
     and `"mitre_validated": false` so analysts know when an ID was LLM-generated

   Re-run the script after a new ATT&CK version is released to pick up new
   techniques. The plugin works without the file but skips enrichment and
   validation — a warning is logged on first use.

### Running in Event Mill

```bash
# Start Event Mill
eventmill

# Load an artifact (PDF, HTML, or text file)
load /path/to/threat_report.pdf

# Check loaded artifacts
artifacts

# Run the ingester on the loaded artifact
run threat_intel_ingester {"artifact_id": "<artifact_id>"}

# View the structured output
result

# Chain to attack_path_visualizer using the output artifact
run attack_path_visualizer {"artifact_id": "<output_artifact_id>"}

# Export the JSON output to cloud storage
export <output_artifact_id>
```

### Input Parameters

| Parameter | Required | Default | Description |
|---|---|---|---|
| `artifact_id` | **Yes** | — | ID of the loaded artifact to process |
| `source_context` | No | `""` | Describes the report source (e.g. "Mandiant M-Trends 2025") |
| `ioc_types` | No | ip, domain, hash_sha256, url, cve, mitre_technique | Which IOC types to extract |
| `confidence_threshold` | No | `"low"` | Minimum confidence to include: `low`, `medium`, `high` |
| `max_pages` | No | `50` | Maximum PDF pages to process (1–200) |

### Example Request

```json
{
  "artifact_id": "art_0001",
  "source_context": "Mandiant M-Trends 2025 Report",
  "ioc_types": ["ip", "domain", "hash_sha256", "url", "cve", "mitre_technique"],
  "confidence_threshold": "low",
  "max_pages": 50
}
```

## Supported Artifact Types

**Consumed:**
- `pdf_report` — PDF threat intel reports, vendor advisories (**native Gemini ingestion**)
- `html_report` — HTML blog posts, advisories, CERT bulletins
- `text` — Plain text, CSV, STIX bundles

**Produced:**
- `json_events` — Structured IOC records

## PDF Processing Paths

The plugin uses a dual-path architecture for PDFs:

### Path 1: Native PDF Ingestion (preferred)

When the Gemini API is connected and supports native PDF, the full document is sent
directly to the model via `query_with_document()`. The dispatcher resolves the transport
automatically:

- **GCS URI** (`gs://...`) — zero-copy, the model reads directly from cloud storage
- **Inline bytes** — local file uploaded as raw bytes

The native path uses `QueryHints(tier="heavy", prefers_native_file=True)` and a single
LLM call with `max_tokens=8192`, eliminating the context loss from chunking.

The `LLMResponse.transport_path` field records which ingestion method was used.

### Path 2: Chunked Text Extraction (fallback)

If native ingestion is unavailable (no API connection, model doesn't support PDFs, or
the native call fails), the plugin falls back to:

1. Text extraction via `pdfplumber`
2. Paragraph-bounded chunking (~6000 chars per chunk)
3. Multiple `query_text()` calls with `QueryHints(tier="light")`
4. Result merging and deduplication across chunks

This path always works but may lose table formatting and cross-page context.

### Regex Pre-Scan

Both paths are preceded by a regex extraction pass that identifies IOC candidates.
For the native path, these candidates are included in the prompt so the model can
validate them against the full document. For the chunked path, candidates are batched
per chunk.

## Output Persistence

On successful completion the plugin writes the full IOC dataset to:
```
workspace/artifacts/<artifact_id>_ti_iocs.json
```
The file is registered as a `json_events` session artifact with the ID shown in the run summary (e.g., `Output artifact: art_04d30b48 (json_events)`). Use that ID directly as input to `attack_path_visualizer` via `artifact_id`. Use `export <artifact_id>` to push the JSON to `common/exports/threat_intel_ingester/` in cloud storage for external access or troubleshooting.

## LLM Dependency

**requires_llm: true**

This plugin uses the `LLMQueryInterface` from the execution context for:
- **Native PDF analysis** — full-document ingestion via `query_with_document()`
- **Capability detection** — `supports_native_document("application/pdf")` to choose path
- **Contextual IOC extraction** beyond regex patterns
- **Confidence scoring** and priority assessment
- **MITRE ATT&CK technique inference** and attack graph construction
- **False positive filtering**

All LLM calls pass `QueryHints` to guide model selection:
- Native PDF: `tier="heavy"`, `prefers_native_file=True`, `needs_structured_output=True`
- Chunked text: `tier="light"`, `needs_structured_output=True`

If the LLM connection is unavailable, the plugin falls back to regex-only extraction with low confidence scores.

## Example summarize_for_llm() Output

```
Ingested pdf_report (12 pages): APT29 Campaign Analysis. Attributed to APT29 (high confidence), campaign: SolarWinds Follow-on. Extracted 47 IOCs: 23 ips, 12 domains, 8 hash_sha256s, 4 cves. 3 IOCs flagged as high-priority. Mapped to 6 MITRE techniques: T1566.001 (Spearphishing Attachment), T1059.001 (PowerShell), T1053.005 (Scheduled Task), T1071.001 (Web Protocols), T1486 (Data Encrypted for Impact), T1048.003 (Exfiltration Over Unencrypted Protocol). Attack graph: 2 path(s) identified, converging at T1059.001. Output artifact: art_0002 (json_events).
```

## Limitations

- Native PDF ingestion requires a live Gemini API connection with `GEMINI_PRO_API_KEY`
- Chunked fallback path may lose table formatting and cross-page context
- Maximum 200 pages per PDF (Gemini native limit: 1000 pages / 50 MB)
- LLM refinement adds latency (~5-15 seconds chunked, ~10-30 seconds native for large PDFs)
- STIX 2.1 parsing not yet implemented

## Safety Notes

**safe_for_auto_invoke: true**

This tool is read-only and low-risk. It processes local artifacts and makes external calls only to the Gemini API via the framework's LLM dispatcher.

## Dependencies

Beyond framework baseline:
- `pdfplumber>=0.10.0` (text extraction fallback)
- `beautifulsoup4>=4.12.0` (HTML processing)
- `stix2>=3.0.0` (for future STIX support)
- `google-genai>=1.0.0` (provided by framework — native PDF ingestion)

## Reference Data Overrides

- **`data/mitre_techniques.json`** — Local ATT&CK technique lookup (Enterprise + ICS).
  Built by `scripts/build_mitre_lookup.py` from official MITRE STIX bundles.
  Used for technique name/tactic enrichment and ID validation. See Prerequisites
  step 3 for setup instructions.
