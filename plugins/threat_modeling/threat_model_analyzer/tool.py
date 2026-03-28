"""
Threat Model Analyzer — Analyze documents, track scenarios, controls, events, and identify gaps.

Ported from Event Mill v1.0 threat_modeling.py with improvements:
- Conforms to EventMillToolProtocol
- Self-contained scenario tracker (no external system_context dependency)
- Structured JSON output
- LLM integration via ExecutionContext.llm_query
- Defense-in-depth gap analysis
- Markdown export
- summarize_for_llm() for context-optimized output
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
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
# Defense Layer Types
# ---------------------------------------------------------------------------

class DefenseLayerType(Enum):
    PERIMETER = "perimeter"
    NETWORK = "network"
    ENDPOINT = "endpoint"
    APPLICATION = "application"
    DATA = "data"
    IDENTITY = "identity"
    MONITORING = "monitoring"


DEFENSE_LAYER_MAP: dict[str, DefenseLayerType] = {
    t.value: t for t in DefenseLayerType
}


# ---------------------------------------------------------------------------
# Scenario Data Models
# ---------------------------------------------------------------------------

@dataclass
class SecurityControl:
    control_id: str
    name: str
    control_type: DefenseLayerType
    description: str
    implementation_status: str = "implemented"
    bypass_difficulty: str = "medium"
    bypass_requirements: list[str] = field(default_factory=list)
    detection_capability: str = "medium"

    def to_dict(self) -> dict[str, Any]:
        return {
            "control_id": self.control_id,
            "name": self.name,
            "control_type": self.control_type.value,
            "description": self.description,
            "implementation_status": self.implementation_status,
            "bypass_difficulty": self.bypass_difficulty,
            "bypass_requirements": self.bypass_requirements,
            "detection_capability": self.detection_capability,
        }


@dataclass
class AttackEvent:
    event_id: str
    name: str
    description: str
    sequence_order: int
    target_asset: str = ""
    attack_technique: str = ""
    technique_id: str = ""
    required_access: str = "none"
    resulting_access: str = "none"
    blocking_controls: list[str] = field(default_factory=list)
    detecting_controls: list[str] = field(default_factory=list)
    success_indicators: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "name": self.name,
            "description": self.description,
            "sequence_order": self.sequence_order,
            "target_asset": self.target_asset,
            "attack_technique": self.attack_technique,
            "technique_id": self.technique_id,
            "required_access": self.required_access,
            "resulting_access": self.resulting_access,
            "blocking_controls": self.blocking_controls,
            "detecting_controls": self.detecting_controls,
        }


@dataclass
class ThreatScenario:
    scenario_id: str
    name: str
    description: str
    source_type: str = "threat_model"
    source_document: str = ""
    threat_actor_profile: str = ""
    attack_objective: str = ""
    target_assets: list[str] = field(default_factory=list)
    entry_vectors: list[str] = field(default_factory=list)
    security_controls: list[SecurityControl] = field(default_factory=list)
    attack_sequence: list[AttackEvent] = field(default_factory=list)
    created_at: str = ""

    def __post_init__(self):
        if not self.created_at:
            self.created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def get_weakest_point(self) -> AttackEvent | None:
        """Find the attack event with least protection."""
        if not self.attack_sequence:
            return None
        return min(
            self.attack_sequence,
            key=lambda e: len(e.blocking_controls) + len(e.detecting_controls),
        )

    def get_defense_coverage(self) -> dict[str, dict]:
        """Get defense-in-depth coverage by layer."""
        coverage: dict[str, dict] = {}
        for layer in DefenseLayerType:
            controls = [c for c in self.security_controls if c.control_type == layer]
            status = {"implemented": 0, "partial": 0, "planned": 0, "missing": 0}
            for c in controls:
                status[c.implementation_status] = status.get(c.implementation_status, 0) + 1
            coverage[layer.value] = {
                "control_count": len(controls),
                "implementation_status": status,
            }
        return coverage

    def to_dict(self) -> dict[str, Any]:
        return {
            "scenario_id": self.scenario_id,
            "name": self.name,
            "description": self.description,
            "source_type": self.source_type,
            "threat_actor_profile": self.threat_actor_profile,
            "attack_objective": self.attack_objective,
            "target_assets": self.target_assets,
            "entry_vectors": self.entry_vectors,
            "controls_count": len(self.security_controls),
            "events_count": len(self.attack_sequence),
            "unprotected_count": len([e for e in self.attack_sequence if not e.blocking_controls]),
            "created_at": self.created_at,
        }


# ---------------------------------------------------------------------------
# Scenario Tracker (session-scoped)
# ---------------------------------------------------------------------------

class ScenarioTracker:
    """In-memory tracker for threat scenarios within a session."""

    def __init__(self):
        self._scenarios: dict[str, ThreatScenario] = {}
        self._next_id = 1
        self._next_control_id = 1
        self._next_event_id = 1

    def create_scenario(self, **kwargs) -> ThreatScenario:
        sid = f"TS-{self._next_id:04d}"
        self._next_id += 1
        scenario = ThreatScenario(scenario_id=sid, **kwargs)
        self._scenarios[sid] = scenario
        return scenario

    def get_scenario(self, scenario_id: str) -> ThreatScenario | None:
        return self._scenarios.get(scenario_id)

    def get_all_scenarios(self) -> list[ThreatScenario]:
        return list(self._scenarios.values())

    def add_control(self, scenario_id: str, **kwargs) -> SecurityControl | None:
        scenario = self.get_scenario(scenario_id)
        if not scenario:
            return None
        cid = f"SC-{self._next_control_id:04d}"
        self._next_control_id += 1
        control = SecurityControl(control_id=cid, **kwargs)
        scenario.security_controls.append(control)
        return control

    def add_event(self, scenario_id: str, **kwargs) -> AttackEvent | None:
        scenario = self.get_scenario(scenario_id)
        if not scenario:
            return None
        eid = f"AE-{self._next_event_id:04d}"
        self._next_event_id += 1
        event = AttackEvent(event_id=eid, **kwargs)
        scenario.attack_sequence.append(event)
        scenario.attack_sequence.sort(key=lambda e: e.sequence_order)
        return event


# ---------------------------------------------------------------------------
# LLM Prompt Templates
# ---------------------------------------------------------------------------

THREAT_MODEL_PROMPT = """You are a Senior Security Architect analyzing a threat model document.

DOCUMENT TYPE: {source_type}
DOCUMENT CONTENT:
{document_content}

Provide a structured analysis with:

1. **Attack Surface Summary**: Key assets and entry points identified
2. **Threat Actors**: Likely adversaries and their capabilities
3. **Attack Paths**: Step-by-step attack sequences with MITRE ATT&CK mapping
4. **Security Controls**: Existing controls and their effectiveness
5. **Defense Gaps**: Unprotected attack steps and weak controls
6. **Recommendations**: Prioritized remediation actions

For each attack path step, note:
- Required access level
- Relevant MITRE ATT&CK technique (ID + name)
- Whether blocking or detection controls exist

Keep response under 1000 words. Use structured formatting."""

TABLETOP_PROMPT = """You are a Senior Security Architect analyzing tabletop exercise minutes.

EXERCISE: {exercise_details}
MINUTES:
{minutes_content}

Provide a structured analysis with:

1. **Scenario Summary**: Attack scenario and threat actor profile
2. **Controls Tested**: Security controls evaluated and their effectiveness
3. **Gaps Identified**: Weaknesses revealed during the exercise
4. **Response Effectiveness**: How well the team responded
5. **Recommendations**: Prioritized improvements

Keep response under 800 words. Use structured formatting."""


# ---------------------------------------------------------------------------
# Plugin Implementation
# ---------------------------------------------------------------------------

class ThreatModelAnalyzer:
    """Analyze threat models, track scenarios, controls, events, and identify defense gaps."""

    def __init__(self):
        self._tracker = ScenarioTracker()

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "threat_model_analyzer",
            "version": "1.0.0",
            "pillar": "threat_modeling",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []
        action = payload.get("action")

        if not action:
            errors.append("'action' is required")
        elif action not in (
            "analyze_document", "create_scenario", "add_control",
            "add_event", "list_scenarios", "gap_analysis", "export",
        ):
            errors.append(f"Invalid action '{action}'.")

        if action == "analyze_document" and not payload.get("document_content"):
            errors.append("'document_content' is required for analyze_document action")

        if action == "create_scenario":
            if not payload.get("name"):
                errors.append("'name' is required for create_scenario")
            if not payload.get("description"):
                errors.append("'description' is required for create_scenario")

        if action == "add_control":
            if not payload.get("scenario_id"):
                errors.append("'scenario_id' is required for add_control")
            if not payload.get("name"):
                errors.append("'name' is required for add_control")
            if not payload.get("control_type"):
                errors.append("'control_type' is required for add_control")
            elif payload["control_type"] not in DEFENSE_LAYER_MAP:
                errors.append(f"Invalid control_type. Must be one of: {', '.join(DEFENSE_LAYER_MAP.keys())}")

        if action == "add_event":
            if not payload.get("scenario_id"):
                errors.append("'scenario_id' is required for add_event")
            if not payload.get("name"):
                errors.append("'name' is required for add_event")
            if not payload.get("sequence_order"):
                errors.append("'sequence_order' is required for add_event")

        if action in ("gap_analysis", "export"):
            if not payload.get("scenario_id"):
                errors.append(f"'scenario_id' is required for {action}")

        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(
        self,
        payload: dict[str, Any],
        context: Any,
    ) -> ToolResult:
        """Execute threat model action."""
        action = payload["action"]

        try:
            if action == "analyze_document":
                return self._analyze_document(payload, context)
            elif action == "create_scenario":
                return self._create_scenario(payload)
            elif action == "add_control":
                return self._add_control(payload)
            elif action == "add_event":
                return self._add_event(payload)
            elif action == "list_scenarios":
                return self._list_scenarios()
            elif action == "gap_analysis":
                return self._gap_analysis(payload)
            elif action == "export":
                return self._export(payload)
            else:
                return ToolResult(ok=False, error_code="INPUT_VALIDATION_FAILED", message=f"Unknown action: {action}")
        except Exception as e:
            return ToolResult(ok=False, error_code="INTERNAL_ERROR", message=str(e))

    def summarize_for_llm(self, result: ToolResult) -> str:
        """Compress output for LLM context."""
        if not result.ok:
            return f"threat_model_analyzer failed: {result.message}"

        data = result.result or {}
        action = data.get("action", "unknown")

        if action == "analyze_document":
            ai = data.get("ai_analysis")
            if ai:
                return ai[:1800]
            return "Document analyzed (no LLM available for AI analysis)."

        elif action == "create_scenario":
            return f"Created scenario {data.get('scenario_id')}: {data.get('name')}"

        elif action == "add_control":
            return f"Added control {data.get('control_id')}: {data.get('name')} ({data.get('control_type')})"

        elif action == "add_event":
            return f"Added event {data.get('event_id')}: Step {data.get('sequence_order')} - {data.get('name')}"

        elif action == "list_scenarios":
            scenarios = data.get("scenarios", [])
            if not scenarios:
                return "No threat scenarios created."
            parts = [f"{len(scenarios)} scenario(s):"]
            for s in scenarios:
                parts.append(f"  {s['scenario_id']}: {s['name']} ({s['controls_count']}C/{s['events_count']}E)")
            return "\n".join(parts)

        elif action == "gap_analysis":
            gap = data.get("gap_analysis", {})
            total = gap.get("total_issues", 0)
            return f"Gap analysis for {data.get('scenario_id')}: {total} issues found."

        elif action == "export":
            md = data.get("markdown", "")
            return md[:1800] if md else "Scenario exported."

        return f"threat_model_analyzer completed action '{action}'."

    # -------------------------------------------------------------------
    # Action implementations
    # -------------------------------------------------------------------

    def _analyze_document(self, payload: dict[str, Any], context: Any) -> ToolResult:
        """Analyze a threat model or tabletop document with LLM."""
        content = payload["document_content"]
        source_type = payload.get("source_type", "threat_model")

        ai_text = None
        if context and hasattr(context, "llm_query") and context.llm_query:
            try:
                if source_type == "tabletop_exercise":
                    prompt = TABLETOP_PROMPT.format(
                        exercise_details=payload.get("name", "Tabletop Exercise"),
                        minutes_content=content[:8000],
                    )
                else:
                    prompt = THREAT_MODEL_PROMPT.format(
                        source_type=source_type,
                        document_content=content[:8000],
                    )
                response = context.llm_query.query_text(prompt=prompt)
                if response.ok:
                    ai_text = response.text
            except Exception:
                pass

        return ToolResult(
            ok=True,
            result={
                "action": "analyze_document",
                "source_type": source_type,
                "content_length": len(content),
                "ai_analysis": ai_text,
            },
        )

    def _create_scenario(self, payload: dict[str, Any]) -> ToolResult:
        """Create a new threat scenario."""
        scenario = self._tracker.create_scenario(
            name=payload["name"],
            description=payload["description"],
            source_type=payload.get("source_type", "threat_model"),
            source_document=payload.get("source_document", ""),
            threat_actor_profile=payload.get("threat_actor", ""),
            attack_objective=payload.get("objective", ""),
            target_assets=payload.get("target_assets", []),
            entry_vectors=payload.get("entry_vectors", []),
        )

        return ToolResult(
            ok=True,
            result={
                "action": "create_scenario",
                **scenario.to_dict(),
            },
        )

    def _add_control(self, payload: dict[str, Any]) -> ToolResult:
        """Add a security control to a scenario."""
        scenario_id = payload["scenario_id"]
        layer_type = DEFENSE_LAYER_MAP.get(payload["control_type"])

        control = self._tracker.add_control(
            scenario_id=scenario_id,
            name=payload["name"],
            control_type=layer_type,
            description=payload.get("description", ""),
            implementation_status=payload.get("implementation_status", "implemented"),
            bypass_difficulty=payload.get("bypass_difficulty", "medium"),
            bypass_requirements=payload.get("bypass_requirements", []),
            detection_capability=payload.get("detection_capability", "medium"),
        )

        if control is None:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message=f"Scenario '{scenario_id}' not found.",
            )

        return ToolResult(
            ok=True,
            result={
                "action": "add_control",
                "scenario_id": scenario_id,
                **control.to_dict(),
            },
        )

    def _add_event(self, payload: dict[str, Any]) -> ToolResult:
        """Add an attack sequence event to a scenario."""
        scenario_id = payload["scenario_id"]

        event = self._tracker.add_event(
            scenario_id=scenario_id,
            name=payload["name"],
            description=payload.get("description", ""),
            sequence_order=payload["sequence_order"],
            target_asset=payload.get("target_asset", ""),
            attack_technique=payload.get("technique_name", ""),
            technique_id=payload.get("technique_id", ""),
            required_access=payload.get("required_access", "none"),
            resulting_access=payload.get("resulting_access", "none"),
            blocking_controls=payload.get("blocking_controls", []),
            detecting_controls=payload.get("detecting_controls", []),
            success_indicators=payload.get("success_indicators", []),
        )

        if event is None:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message=f"Scenario '{scenario_id}' not found.",
            )

        return ToolResult(
            ok=True,
            result={
                "action": "add_event",
                "scenario_id": scenario_id,
                **event.to_dict(),
            },
        )

    def _list_scenarios(self) -> ToolResult:
        """List all tracked scenarios."""
        scenarios = self._tracker.get_all_scenarios()
        return ToolResult(
            ok=True,
            result={
                "action": "list_scenarios",
                "scenarios": [s.to_dict() for s in scenarios],
            },
        )

    def _gap_analysis(self, payload: dict[str, Any]) -> ToolResult:
        """Analyze defense gaps in a scenario."""
        scenario_id = payload["scenario_id"]
        scenario = self._tracker.get_scenario(scenario_id)

        if not scenario:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message=f"Scenario '{scenario_id}' not found.",
            )

        unprotected = [
            {"event_id": e.event_id, "name": e.name, "sequence_order": e.sequence_order}
            for e in scenario.attack_sequence
            if not e.blocking_controls
        ]

        weak_controls = [
            {"control_id": c.control_id, "name": c.name, "status": c.implementation_status}
            for c in scenario.security_controls
            if c.implementation_status in ("partial", "planned", "missing")
        ]

        easy_bypass = [
            {"control_id": c.control_id, "name": c.name, "difficulty": c.bypass_difficulty}
            for c in scenario.security_controls
            if c.bypass_difficulty in ("trivial", "low")
        ]

        weakest = scenario.get_weakest_point()
        coverage = scenario.get_defense_coverage()

        total_issues = len(unprotected) + len(weak_controls) + len(easy_bypass)

        return ToolResult(
            ok=True,
            result={
                "action": "gap_analysis",
                "scenario_id": scenario_id,
                "scenario_name": scenario.name,
                "gap_analysis": {
                    "unprotected_events": unprotected,
                    "weak_controls": weak_controls,
                    "easy_bypass": easy_bypass,
                    "total_issues": total_issues,
                    "weakest_point": {
                        "event_id": weakest.event_id,
                        "name": weakest.name,
                    } if weakest else None,
                    "defense_coverage": coverage,
                },
            },
        )

    def _export(self, payload: dict[str, Any]) -> ToolResult:
        """Export a scenario to markdown."""
        scenario_id = payload["scenario_id"]
        scenario = self._tracker.get_scenario(scenario_id)

        if not scenario:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message=f"Scenario '{scenario_id}' not found.",
            )

        md = self._generate_markdown(scenario)

        output_path = payload.get("output_path")
        if output_path:
            Path(output_path).parent.mkdir(parents=True, exist_ok=True)
            Path(output_path).write_text(md, encoding="utf-8")

        return ToolResult(
            ok=True,
            result={
                "action": "export",
                "scenario_id": scenario_id,
                "output_path": output_path,
                "markdown": md,
            },
        )

    # -------------------------------------------------------------------
    # Markdown generation
    # -------------------------------------------------------------------

    def _generate_markdown(self, scenario: ThreatScenario) -> str:
        """Generate a markdown report for a scenario."""
        lines = [
            f"# Threat Scenario: {scenario.name}",
            "",
            f"**ID:** {scenario.scenario_id}",
            f"**Source:** {scenario.source_type}",
            f"**Created:** {scenario.created_at}",
        ]

        if scenario.threat_actor_profile:
            lines.append(f"**Threat Actor:** {scenario.threat_actor_profile}")
        if scenario.attack_objective:
            lines.append(f"**Objective:** {scenario.attack_objective}")
        if scenario.target_assets:
            lines.append(f"**Target Assets:** {', '.join(scenario.target_assets)}")
        if scenario.entry_vectors:
            lines.append(f"**Entry Vectors:** {', '.join(scenario.entry_vectors)}")

        lines.append("")
        lines.append(f"> {scenario.description}")
        lines.append("")

        # Security Controls
        lines.append("## Security Controls")
        lines.append("")
        if scenario.security_controls:
            lines.append("| ID | Name | Layer | Status | Bypass |")
            lines.append("|---|---|---|---|---|")
            for c in scenario.security_controls:
                lines.append(
                    f"| {c.control_id} | {c.name} | {c.control_type.value} "
                    f"| {c.implementation_status} | {c.bypass_difficulty} |"
                )
        else:
            lines.append("*No controls added yet.*")

        lines.append("")

        # Attack Sequence
        lines.append("## Attack Sequence")
        lines.append("")
        if scenario.attack_sequence:
            for e in scenario.attack_sequence:
                protection = "PROTECTED" if e.blocking_controls else (
                    "DETECT ONLY" if e.detecting_controls else "UNPROTECTED"
                )
                lines.append(f"### Step {e.sequence_order}: {e.name} [{protection}]")
                lines.append("")
                if e.description:
                    lines.append(f"{e.description}")
                    lines.append("")
                if e.technique_id:
                    lines.append(f"- **MITRE ATT&CK:** {e.attack_technique} ({e.technique_id})")
                if e.target_asset:
                    lines.append(f"- **Target:** {e.target_asset}")
                lines.append(f"- **Access:** {e.required_access} -> {e.resulting_access}")
                if e.blocking_controls:
                    lines.append(f"- **Blocking Controls:** {', '.join(e.blocking_controls)}")
                if e.detecting_controls:
                    lines.append(f"- **Detecting Controls:** {', '.join(e.detecting_controls)}")
                lines.append("")
        else:
            lines.append("*No attack events added yet.*")

        # Gap Summary
        unprotected = [e for e in scenario.attack_sequence if not e.blocking_controls]
        weak = [c for c in scenario.security_controls if c.implementation_status in ("partial", "planned", "missing")]

        lines.append("## Gap Summary")
        lines.append("")
        lines.append(f"- **Total Controls:** {len(scenario.security_controls)}")
        lines.append(f"- **Total Attack Steps:** {len(scenario.attack_sequence)}")
        lines.append(f"- **Unprotected Steps:** {len(unprotected)}")
        lines.append(f"- **Incomplete Controls:** {len(weak)}")
        lines.append("")

        return "\n".join(lines)
