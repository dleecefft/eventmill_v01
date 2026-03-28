"""Contract compliance tests for attack_path_visualizer."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent

def _load_tool_module():
    _name = "attack_path_visualizer_tool"
    spec = importlib.util.spec_from_file_location(_name, PLUGIN_DIR / "tool.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules[_name] = mod
    spec.loader.exec_module(mod)
    return mod

_tool_mod = _load_tool_module()


@pytest.fixture
def manifest():
    with open(PLUGIN_DIR / "manifest.json") as f:
        return json.load(f)


@pytest.fixture
def plugin_instance():
    return _tool_mod.AttackPathVisualizer()


@pytest.fixture
def sample_stages():
    """Ransomware attack path with controls and gaps."""
    return [
        {
            "name": "Initial Access",
            "technique_claimed": "Spear phishing with malicious attachment",
            "mitre_technique_id": "T1566.001",
            "stage_present": True,
            "relevance": "required",
            "controls": [
                {
                    "control_name": "Email Gateway Filter",
                    "control_type": "preventive",
                    "effectiveness_rating": "moderate",
                },
                {
                    "control_name": "Security Awareness Training",
                    "control_type": "preventive",
                    "effectiveness_rating": "weak",
                },
            ],
            "gaps_detected": [],
        },
        {
            "name": "Execution",
            "technique_claimed": "User opens malicious macro",
            "mitre_technique_id": "T1204.002",
            "stage_present": True,
            "relevance": "required",
            "controls": [
                {
                    "control_name": "EDR Agent",
                    "control_type": "detective",
                    "effectiveness_rating": "strong",
                },
            ],
            "gaps_detected": [],
        },
        {
            "name": "Privilege Escalation",
            "technique_claimed": "Exploiting unpatched service",
            "mitre_technique_id": "T1068",
            "stage_present": True,
            "relevance": "required",
            "controls": [
                {
                    "control_name": "EDR Agent",
                    "control_type": "detective",
                    "effectiveness_rating": "strong",
                },
            ],
            "gaps_detected": ["Patching cadence is 30+ days behind schedule"],
        },
        {
            "name": "Impact/Action on Objective",
            "technique_claimed": "Data encryption for ransom",
            "mitre_technique_id": "T1486",
            "stage_present": True,
            "relevance": "required",
            "controls": [],
            "gaps_detected": ["No ransomware-specific controls"],
        },
        {
            "name": "Exfiltration",
            "stage_present": False,
            "relevance": "not_applicable",
            "controls": [],
            "gaps_detected": [],
        },
    ]


@pytest.fixture
def stages_with_missing(sample_stages):
    """Stages with a missing required stage."""
    return sample_stages + [
        {
            "name": "Lateral Movement",
            "stage_present": False,
            "relevance": "required",
            "controls": [],
            "gaps_detected": [],
        },
    ]


class TestManifest:
    def test_required_fields(self, manifest):
        for field in ["tool_name", "version", "pillar", "entry_point", "class_name"]:
            assert field in manifest

    def test_pillar_matches_directory(self, manifest):
        assert manifest["pillar"] == PLUGIN_DIR.parent.name

    def test_tool_name(self, manifest):
        assert manifest["tool_name"] == "attack_path_visualizer"

    def test_schemas_exist(self, manifest):
        assert (PLUGIN_DIR / manifest["input_schema"]).exists()
        assert (PLUGIN_DIR / manifest["output_schema"]).exists()

    def test_safe_for_auto_invoke(self, manifest):
        assert manifest["safe_for_auto_invoke"] is True

    def test_no_llm_required(self, manifest):
        assert manifest["requires_llm"] is False


class TestProtocol:
    def test_metadata(self, plugin_instance):
        meta = plugin_instance.metadata()
        assert meta["tool_name"] == "attack_path_visualizer"

    def test_validate_valid(self, plugin_instance, sample_stages):
        result = plugin_instance.validate_inputs({"stages": sample_stages})
        assert result.ok

    def test_validate_missing_stages(self, plugin_instance):
        result = plugin_instance.validate_inputs({})
        assert not result.ok

    def test_validate_invalid_format(self, plugin_instance, sample_stages):
        result = plugin_instance.validate_inputs({"stages": sample_stages, "format": "html"})
        assert not result.ok

    def test_validate_all_formats(self, plugin_instance, sample_stages):
        for fmt in ("ascii", "mermaid", "compact", "both"):
            result = plugin_instance.validate_inputs({"stages": sample_stages, "format": fmt})
            assert result.ok, f"Failed for format={fmt}"


class TestAsciiRendering:
    def test_ascii_output(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({
            "stages": sample_stages,
            "format": "ascii",
            "attack_type": "ransomware",
            "attack_narrative": "APT group deploys ransomware via spear phishing",
        }, None)
        assert result.ok
        viz = result.result["visualization"]
        assert "RANSOMWARE" in viz
        assert "Initial Access" in viz
        assert "T1566.001" in viz
        assert "Email Gateway Filter" in viz
        assert "Patching cadence" in viz

    def test_ascii_stages_counted(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({"stages": sample_stages, "format": "ascii"}, None)
        assert result.ok
        assert result.result["stages_rendered"] == 4  # 4 present, 1 N/A

    def test_ascii_missing_required(self, plugin_instance, stages_with_missing):
        result = plugin_instance.execute({"stages": stages_with_missing, "format": "ascii"}, None)
        assert result.ok
        assert result.result["missing_required"] == 1
        assert "MISSING REQUIRED" in result.result["visualization"]
        assert "Lateral Movement" in result.result["visualization"]

    def test_ascii_empty_stages(self, plugin_instance):
        result = plugin_instance.execute({"stages": [], "format": "ascii"}, None)
        assert result.ok
        assert "No attack stages" in result.result["visualization"]


class TestCompactRendering:
    def test_compact_output(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({
            "stages": sample_stages,
            "format": "compact",
            "attack_type": "ransomware",
        }, None)
        assert result.ok
        viz = result.result["visualization"]
        assert "RANSOMWARE" in viz
        assert "-->" in viz
        assert "Stages: 4" in viz

    def test_compact_truncates_long_names(self, plugin_instance):
        stages = [{
            "name": "Very Long Stage Name That Exceeds Limit",
            "stage_present": True,
            "controls": [],
        }]
        result = plugin_instance.execute({"stages": stages, "format": "compact"}, None)
        assert result.ok
        # Name should be truncated to 15 chars
        viz = result.result["visualization"]
        assert "..." in viz


class TestMermaidRendering:
    def test_mermaid_output(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({
            "stages": sample_stages,
            "format": "mermaid",
            "attack_type": "ransomware",
        }, None)
        assert result.ok
        viz = result.result["visualization"]
        assert "```mermaid" in viz
        assert "flowchart TB" in viz
        assert "RANSOMWARE" in viz
        assert "S0 --> S1" in viz

    def test_mermaid_gap_styling(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({"stages": sample_stages, "format": "mermaid"}, None)
        viz = result.result["visualization"]
        # Privilege Escalation has gaps -> red styling
        assert "fill:#ffcccc" in viz

    def test_mermaid_unprotected_styling(self, plugin_instance):
        stages = [{"name": "No Controls", "stage_present": True, "controls": [], "gaps_detected": []}]
        result = plugin_instance.execute({"stages": stages, "format": "mermaid"}, None)
        viz = result.result["visualization"]
        assert "fill:#ffffcc" in viz  # yellow for unprotected

    def test_mermaid_control_matrix(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({
            "stages": sample_stages,
            "format": "mermaid",
            "include_controls": True,
        }, None)
        viz = result.result["visualization"]
        assert "Control Coverage Matrix" in viz
        assert "EDR Agent" in viz

    def test_mermaid_no_control_matrix(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({
            "stages": sample_stages,
            "format": "mermaid",
            "include_controls": False,
        }, None)
        viz = result.result["visualization"]
        assert "Control Coverage Matrix" not in viz


class TestBothFormat:
    def test_both_includes_ascii_and_mermaid(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({
            "stages": sample_stages,
            "format": "both",
            "attack_type": "ransomware",
        }, None)
        assert result.ok
        viz = result.result["visualization"]
        # Should contain ASCII elements
        assert "ATTACK PATH" in viz
        # Should contain Mermaid elements
        assert "```mermaid" in viz


class TestSummarize:
    def test_summarize_success(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({"stages": sample_stages, "format": "compact"}, None)
        summary = plugin_instance.summarize_for_llm(result)
        assert "4 attack stages" in summary
        assert len(summary) <= 2000

    def test_summarize_with_missing(self, plugin_instance, stages_with_missing):
        result = plugin_instance.execute({"stages": stages_with_missing, "format": "compact"}, None)
        summary = plugin_instance.summarize_for_llm(result)
        assert "missing" in summary.lower()

    def test_summarize_failure(self, plugin_instance):
        result = _tool_mod.ToolResult(ok=False, message="Bad data")
        summary = plugin_instance.summarize_for_llm(result)
        assert "failed" in summary.lower()

    def test_summarize_truncation(self, plugin_instance, sample_stages):
        result = plugin_instance.execute({
            "stages": sample_stages,
            "format": "both",
            "attack_type": "ransomware",
        }, None)
        summary = plugin_instance.summarize_for_llm(result)
        assert len(summary) <= 2000
