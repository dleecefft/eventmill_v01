# Threat Model Analyzer

**Analyze threat models, track scenarios, controls, attack events, and identify defense gaps.**

## What It Does

Seven actions for comprehensive threat modeling:

1. **analyze_document** — AI-powered analysis of threat model documents or tabletop exercise minutes
2. **create_scenario** — Create a trackable threat scenario with actor, objectives, assets
3. **add_control** — Add security controls with defense layer, bypass difficulty, implementation status
4. **add_event** — Add attack sequence events with MITRE ATT&CK mapping and control references
5. **list_scenarios** — List all tracked scenarios with summary stats
6. **gap_analysis** — Identify unprotected steps, weak controls, and easy bypasses
7. **export** — Generate markdown report with full scenario details

## Artifacts

| Direction | Type | Description |
|-----------|------|-------------|
| Consumed | `text`, `pdf` | Threat model documents |
| Produced | `json_events`, `text` | Analysis results, markdown reports |

## Defense Layers

`perimeter`, `network`, `endpoint`, `application`, `data`, `identity`, `monitoring`

## Example Workflow

```
1. analyze_document → AI extracts attack paths from document
2. create_scenario → Track the scenario with ID
3. add_control (x N) → Map existing security controls
4. add_event (x N) → Map attack sequence with MITRE ATT&CK
5. gap_analysis → Identify defense weaknesses
6. export → Generate markdown report
```

## Chains

- **From**: `log_investigator`
- **To**: `attack_path_visualizer`
