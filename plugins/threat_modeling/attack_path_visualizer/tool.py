"""
Attack Path Visualizer — Generate ASCII art, Mermaid diagrams, and compact flow visualizations.

Ported from Event Mill v1.0 visualization.py with improvements:
- Conforms to EventMillToolProtocol
- Structured JSON output wrapping visualization text
- Multiple output formats: ascii, mermaid, compact, both
- Control coverage matrix rendering
- summarize_for_llm() for context-optimized output
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


# ---------------------------------------------------------------------------
# Protocol-compatible result types
# ---------------------------------------------------------------------------

@dataclass
class ToolResult:
    ok: bool
    result: dict[str, Any] | None = None
    error_code: str | None = None
    message: str | None = None
    output_artifacts: list[str] | None = None
    details: dict[str, Any] | None = None


@dataclass
class ValidationResult:
    ok: bool
    errors: list[str] | None = None


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------

def _wrap_text(text: str, width: int) -> list[str]:
    """Wrap text to specified width."""
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        if len(current) + len(word) + 1 <= width:
            current += (" " if current else "") + word
        else:
            if current:
                lines.append(current)
            current = word
    if current:
        lines.append(current)
    return lines


EFF_BAR = {"strong": "███", "moderate": "██░", "weak": "█░░", "nominal": "░░░"}


# ---------------------------------------------------------------------------
# ASCII Rendering
# ---------------------------------------------------------------------------

def _render_ascii(stages: list[dict], attack_type: str, narrative: str) -> str:
    """Render detailed ASCII box-and-arrow attack path."""
    present = [s for s in stages if s.get("stage_present", True)]
    missing_req = [s for s in stages if not s.get("stage_present", True) and s.get("relevance") == "required"]

    if not present and not missing_req:
        return "No attack stages provided."

    box_width = 100
    lines: list[str] = []

    # Header
    lines.append("")
    header_w = box_width + 4
    lines.append("+" + "=" * header_w + "+")
    lines.append("|" + f" ATTACK PATH - {attack_type.upper()} ".center(header_w) + "|")
    lines.append("+" + "=" * header_w + "+")
    lines.append("")

    if narrative:
        for ln in _wrap_text(narrative, box_width)[:4]:
            lines.append(f"  {ln}")
        lines.append("")

    # Detailed stage boxes
    for i, stage in enumerate(present):
        name = stage.get("name", "Unknown")
        technique = stage.get("technique_claimed", "")
        mitre_id = stage.get("mitre_technique_id", "")
        controls = stage.get("controls", [])
        gaps = stage.get("gaps_detected", [])

        lines.append("  +" + "-" * box_width + "+")

        header = f" {i + 1}. {name}"
        if mitre_id:
            header += f" ({mitre_id})"
        lines.append("  |" + header.ljust(box_width) + "|")

        if technique:
            for j, tl in enumerate(_wrap_text(technique, box_width - 16)[:2]):
                prefix = "    Technique: " if j == 0 else "               "
                lines.append("  |" + (prefix + tl).ljust(box_width) + "|")

        if controls:
            lines.append("  |" + "    Controls:".ljust(box_width) + "|")
            for ctrl in controls[:4]:
                cn = ctrl.get("control_name", "?")
                ct = ctrl.get("control_type", "?")[0].upper()
                eff = EFF_BAR.get(ctrl.get("effectiveness_rating", ""), "???")
                max_name = box_width - 20
                if len(cn) > max_name:
                    cn = cn[: max_name - 3] + "..."
                cl = f"      [{ct}] {cn} {eff}"
                lines.append("  |" + cl.ljust(box_width) + "|")
            if len(controls) > 4:
                lines.append("  |" + f"      ... +{len(controls) - 4} more".ljust(box_width) + "|")

        if gaps:
            lines.append("  |" + "    Gaps:".ljust(box_width) + "|")
            for gap in gaps[:3]:
                for j, gl in enumerate(_wrap_text(gap, box_width - 10)[:2]):
                    prefix = "      - " if j == 0 else "        "
                    lines.append("  |" + (prefix + gl).ljust(box_width) + "|")

        lines.append("  +" + "-" * box_width + "+")

        if i < len(present) - 1:
            lines.append("           |")
            lines.append("           V")

    if missing_req:
        lines.append("")
        lines.append("  MISSING REQUIRED STAGES:")
        for s in missing_req:
            lines.append(f"      X {s.get('name', 'Unknown')}")

    lines.append("")
    lines.append("  " + "-" * (box_width + 2))
    lines.append("  Legend: ### strong | ##. moderate | #.. weak | ... nominal")
    lines.append("          [P] preventive | [D] detective | [R] responsive")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Compact Rendering
# ---------------------------------------------------------------------------

def _render_compact(stages: list[dict], attack_type: str) -> str:
    """Render compact single-line flow."""
    present = [s for s in stages if s.get("stage_present", True)]
    if not present:
        return "No attack stages to visualize."

    boxes = []
    for s in present:
        name = s.get("name", "?")
        if len(name) > 15:
            name = name[:12] + "..."
        boxes.append(name)

    flow = "  " + " --> ".join(f"[{b}]" for b in boxes)

    total_controls = sum(len(s.get("controls", [])) for s in present)
    total_gaps = sum(len(s.get("gaps_detected", [])) for s in present)

    lines = [
        f"\n  {attack_type.upper()} ATTACK PATH:",
        "",
        flow,
        "",
        f"  Stages: {len(present)} | Controls: {total_controls} | Gaps: {total_gaps}",
        "",
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Mermaid Rendering
# ---------------------------------------------------------------------------

def _render_mermaid(stages: list[dict], attack_type: str, include_controls: bool) -> str:
    """Render Mermaid flowchart diagram."""
    present = [s for s in stages if s.get("stage_present", True)]
    if not present:
        return "```mermaid\nflowchart TB\n    A[No stages found]\n```"

    lines = [
        "```mermaid",
        "flowchart TB",
        f'    subgraph attack["{attack_type.upper()} Attack Path"]',
        "    direction TB",
    ]

    for i, stage in enumerate(present):
        name = stage.get("name", "Unknown")
        mitre_id = stage.get("mitre_technique_id", "")
        controls = stage.get("controls", [])
        gaps = stage.get("gaps_detected", [])
        nid = f"S{i}"

        label = name
        if mitre_id:
            label += f"<br/><small>{mitre_id}</small>"

        if gaps:
            label += f"<br/><small>! {len(gaps)} gap(s)</small>"
            lines.append(f'    {nid}[["{label}"]]')
        elif controls:
            label += f"<br/><small>{len(controls)} control(s)</small>"
            lines.append(f'    {nid}["{label}"]')
        else:
            lines.append(f'    {nid}(["{label}"])')

    for i in range(len(present) - 1):
        lines.append(f"    S{i} --> S{i + 1}")

    lines.append("    end")
    lines.append("")
    lines.append("    %% Styling")

    for i, stage in enumerate(present):
        gaps = stage.get("gaps_detected", [])
        controls = stage.get("controls", [])
        if gaps:
            lines.append(f"    style S{i} fill:#ffcccc,stroke:#cc0000")
        elif not controls:
            lines.append(f"    style S{i} fill:#ffffcc,stroke:#cccc00")
        else:
            lines.append(f"    style S{i} fill:#ccffcc,stroke:#00cc00")

    lines.append("```")

    if include_controls:
        lines.append("")
        lines.append(_render_mermaid_control_matrix(present))

    return "\n".join(lines)


def _render_mermaid_control_matrix(stages: list[dict]) -> str:
    """Render control coverage matrix as Mermaid."""
    all_controls: dict[str, dict] = {}
    for stage in stages:
        for ctrl in stage.get("controls", []):
            cn = ctrl.get("control_name", "Unknown")
            if cn not in all_controls:
                all_controls[cn] = {
                    "effectiveness": ctrl.get("effectiveness_rating", "unknown"),
                    "stages": [],
                }
            all_controls[cn]["stages"].append(stage.get("name", "?"))

    if not all_controls:
        return ""

    lines = [
        "```mermaid",
        "flowchart LR",
        '    subgraph controls["Control Coverage Matrix"]',
    ]

    for i, (cn, info) in enumerate(all_controls.items()):
        eff = info["effectiveness"]
        sc = len(info["stages"])
        label = f"{cn[:25]}<br/><small>{eff} | {sc} stage(s)</small>"
        lines.append(f'    C{i}["{label}"]')

    lines.append("    end")
    lines.append("")

    eff_colors = {
        "strong": "fill:#00cc00,color:#fff",
        "moderate": "fill:#cccc00",
        "weak": "fill:#ff9900",
        "nominal": "fill:#cc0000,color:#fff",
    }
    for i, (_, info) in enumerate(all_controls.items()):
        style = eff_colors.get(info["effectiveness"], "fill:#999")
        lines.append(f"    style C{i} {style}")

    lines.append("```")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Plugin Implementation
# ---------------------------------------------------------------------------

class AttackPathVisualizer:
    """Generate visual representations of attack paths."""

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "attack_path_visualizer",
            "version": "1.0.0",
            "pillar": "threat_modeling",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []

        if "stages" not in payload:
            errors.append("'stages' is required")
        elif not isinstance(payload["stages"], list):
            errors.append("'stages' must be a list")

        fmt = payload.get("format", "ascii")
        if fmt not in ("ascii", "mermaid", "compact", "both"):
            errors.append(f"Invalid format '{fmt}'. Must be ascii, mermaid, compact, or both.")

        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(
        self,
        payload: dict[str, Any],
        context: Any,
    ) -> ToolResult:
        """Render attack path visualization."""
        fmt = payload.get("format", "ascii")
        stages = payload["stages"]
        attack_type = payload.get("attack_type", "unknown")
        narrative = payload.get("attack_narrative", "")
        include_controls = payload.get("include_controls", True)

        try:
            present = [s for s in stages if s.get("stage_present", True)]
            missing_req = [s for s in stages if not s.get("stage_present", True) and s.get("relevance") == "required"]

            parts: list[str] = []

            if fmt in ("ascii", "both"):
                parts.append(_render_ascii(stages, attack_type, narrative))

            if fmt == "compact":
                parts.append(_render_compact(stages, attack_type))

            if fmt in ("mermaid", "both"):
                parts.append(_render_mermaid(stages, attack_type, include_controls))

            visualization = "\n".join(parts)

            return ToolResult(
                ok=True,
                result={
                    "format": fmt,
                    "visualization": visualization,
                    "stages_rendered": len(present),
                    "missing_required": len(missing_req),
                },
            )

        except Exception as e:
            return ToolResult(
                ok=False,
                error_code="INTERNAL_ERROR",
                message=str(e),
            )

    def summarize_for_llm(self, result: ToolResult) -> str:
        """Compress output for LLM context."""
        if not result.ok:
            return f"attack_path_visualizer failed: {result.message}"

        data = result.result or {}
        rendered = data.get("stages_rendered", 0)
        missing = data.get("missing_required", 0)
        fmt = data.get("format", "?")

        summary = f"Rendered {rendered} attack stages ({fmt} format)."
        if missing:
            summary += f" {missing} required stage(s) missing."

        # Include compact flow if available, truncate if too long
        viz = data.get("visualization", "")
        if len(viz) > 1500:
            # Try to extract just the compact flow or first few lines
            lines = viz.split("\n")
            preview = "\n".join(lines[:20])
            summary += f"\n{preview}\n... (truncated)"
        elif viz:
            summary += f"\n{viz}"

        return summary[:2000]
