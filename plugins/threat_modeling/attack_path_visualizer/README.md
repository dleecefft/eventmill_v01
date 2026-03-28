# Attack Path Visualizer

**Generate ASCII art, Mermaid diagrams, and compact flow visualizations of attack paths.**

## What It Does

Four output formats for attack path visualization:

1. **ascii** — Detailed box-and-arrow diagrams with control effectiveness bars, gaps, and MITRE ATT&CK technique IDs
2. **mermaid** — Flowchart syntax for markdown/GitHub rendering with color-coded protection status and control coverage matrix
3. **compact** — Single-line flow diagram with stage/control/gap counts
4. **both** — Combined ASCII + Mermaid output

## Color Coding (Mermaid)

- **Green** — Stage has controls
- **Yellow** — Stage has no controls (unprotected)
- **Red** — Stage has detected gaps

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | `json_events` | Stage data from risk_assessment_analyzer or threat_model_analyzer |
| Produced | `text` | Rendered visualization |

## Example

```json
{
  "format": "ascii",
  "attack_type": "ransomware",
  "stages": [
    {"name": "Initial Access", "mitre_technique_id": "T1566", "stage_present": true, "controls": [...]}
  ]
}
```

## Chains

- **From**: `threat_model_analyzer`, `risk_assessment_analyzer`

## Notes

- No LLM required — purely deterministic rendering
- Safe for auto-invoke
