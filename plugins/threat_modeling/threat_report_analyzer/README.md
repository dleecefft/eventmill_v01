# Threat Report Analyzer

**Summarize threat intelligence reports from the common bucket into context for analysis tools.**

## What It Does

Reads threat intelligence reports (MITRE ATT&CK, CAPEC, CISA advisories, vendor bulletins) from the common bucket and generates 1500-2000 word markdown summaries for use as context in other analysis tools.

Three actions:

1. **list_reports** — List available threat reports in the common bucket
2. **summarize** — Generate LLM-powered markdown summary of a specific report
3. **search_reports** — Search across report content for keywords

## Common Bucket Structure

Expected directory structure in the common bucket:

```
{prefix}-common/
├── mitre/                    # MITRE ATT&CK framework data
├── capec/                    # CAPEC attack patterns
├── cisa/                     # CISA advisories and KEV catalog
├── vendor_advisories/        # Vendor security bulletins
├── threat_actors/           # Threat actor profiles
├── campaigns/               # Threat campaign reports
└── vulnerabilities/         # CVE/vulnerability data
```

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | — | — |
| Produced | `text` | Markdown summaries for other tools |

## Example Usage

### List Available Reports
```json
{"action": "list_reports"}
```

### Summarize a Report
```json
{"action": "summarize", "report_path": "mitre/enterprise-attack.json", "max_word_count": 2000}
```

### Summarize with Focus Areas
```json
{"action": "summarize", "report_path": "capec/capec-stix.xml", "focus_areas": ["attack_techniques", "mitigations"]}
```

### Search Reports
```json
{"action": "search_reports", "query": "ransomware"}
```

## LLM Integration

The summarize action requires an active LLM connection via `connect`. Without LLM, it returns the raw report content truncated to the first 50KB.

When LLM is connected, it generates structured markdown summaries with:
- Executive Summary
- Key Threat Actors/Techniques
- Relevant ATT&CK Techniques (with IDs)
- Detection Opportunities
- Recommended Security Controls

## Chains

- **To**: `risk_assessment_analyzer`, `attack_path_visualizer`
- **From**: — (entry point for threat intel workflow)

## Notes

- Supports JSON, XML, Markdown, TXT, CSV, and STIX file formats
- Falls back to local `framework/reference_data/` directory when common bucket unavailable
- Extracts MITRE ATT&CK technique IDs (T1234 format) from summaries
- Maximum content passed to LLM: 50KB (truncated for token limits)
