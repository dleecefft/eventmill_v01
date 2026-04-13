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
| Consumed | `json_events` | IOC/MITRE data from `threat_intel_ingester`, or stage data from `risk_assessment_analyzer`/`threat_model_analyzer` |
| Produced | `text` | Rendered visualization |

## Output Persistence

The tool writes the visualization directly to a format-specific file:

| Format | Output file |
|--------|-------------|
| `mermaid` | `workspace/artifacts/attack_path_mermaid_<ts>.mmd` |
| `ascii` | `workspace/artifacts/attack_path_ascii_<ts>.txt` |
| `compact` | `workspace/artifacts/attack_path_compact_<ts>.txt` |
| `both` | `workspace/artifacts/attack_path_both_<ts>.txt` |

The file is registered as a `text` session artifact. The artifact ID and full path are shown in the run summary. `.mmd` files can be rendered directly in GitHub, VS Code, or any Mermaid-compatible viewer.

## Example — Direct from threat_intel_ingester

```json
{"artifact_id": "art_04d30b48", "format": "mermaid"}
```

Stages are automatically derived from the MITRE technique mappings in the `json_events` artifact, ordered by kill-chain sequence.

## Example — Inline stages

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
