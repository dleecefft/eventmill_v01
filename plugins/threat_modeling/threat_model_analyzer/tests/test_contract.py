"""Contract compliance tests for threat_model_analyzer."""

import importlib.util
import json
import sys
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent

def _load_tool_module():
    _name = "threat_model_analyzer_tool"
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
    return _tool_mod.ThreatModelAnalyzer()


@pytest.fixture
def scenario_with_data(plugin_instance):
    """Create a scenario pre-populated with controls and events."""
    # Create scenario
    result = plugin_instance.execute({
        "action": "create_scenario",
        "name": "Ransomware via Phishing",
        "description": "APT group targets org via spear phishing",
        "source_type": "threat_model",
        "threat_actor": "APT29",
        "objective": "Deploy ransomware and exfiltrate data",
        "target_assets": ["email_server", "domain_controller", "file_shares"],
        "entry_vectors": ["spear_phishing", "watering_hole"],
    }, None)
    scenario_id = result.result["scenario_id"]

    # Add controls
    plugin_instance.execute({
        "action": "add_control",
        "scenario_id": scenario_id,
        "name": "Email Gateway",
        "control_type": "perimeter",
        "description": "Filters malicious attachments",
        "implementation_status": "implemented",
        "bypass_difficulty": "medium",
    }, None)

    plugin_instance.execute({
        "action": "add_control",
        "scenario_id": scenario_id,
        "name": "EDR Agent",
        "control_type": "endpoint",
        "description": "Endpoint detection and response",
        "implementation_status": "partial",
        "bypass_difficulty": "high",
    }, None)

    plugin_instance.execute({
        "action": "add_control",
        "scenario_id": scenario_id,
        "name": "Legacy Firewall",
        "control_type": "network",
        "description": "Old network firewall",
        "implementation_status": "implemented",
        "bypass_difficulty": "low",
    }, None)

    # Add events
    plugin_instance.execute({
        "action": "add_event",
        "scenario_id": scenario_id,
        "name": "Phishing Email Delivery",
        "description": "Send spear phishing email with malicious attachment",
        "sequence_order": 1,
        "technique_name": "Phishing",
        "technique_id": "T1566",
        "target_asset": "email_server",
        "blocking_controls": ["SC-0001"],
    }, None)

    plugin_instance.execute({
        "action": "add_event",
        "scenario_id": scenario_id,
        "name": "Malware Execution",
        "description": "User opens attachment, malware executes",
        "sequence_order": 2,
        "technique_name": "User Execution",
        "technique_id": "T1204",
        "target_asset": "workstation",
        "detecting_controls": ["SC-0002"],
    }, None)

    plugin_instance.execute({
        "action": "add_event",
        "scenario_id": scenario_id,
        "name": "Lateral Movement",
        "description": "Move to domain controller",
        "sequence_order": 3,
        "technique_name": "Remote Services",
        "technique_id": "T1021",
        "target_asset": "domain_controller",
    }, None)

    return scenario_id


class TestManifest:
    def test_required_fields(self, manifest):
        for field in ["tool_name", "version", "pillar", "entry_point", "class_name"]:
            assert field in manifest

    def test_pillar_matches_directory(self, manifest):
        assert manifest["pillar"] == PLUGIN_DIR.parent.name

    def test_tool_name(self, manifest):
        assert manifest["tool_name"] == "threat_model_analyzer"

    def test_schemas_exist(self, manifest):
        assert (PLUGIN_DIR / manifest["input_schema"]).exists()
        assert (PLUGIN_DIR / manifest["output_schema"]).exists()


class TestProtocol:
    def test_metadata(self, plugin_instance):
        meta = plugin_instance.metadata()
        assert meta["tool_name"] == "threat_model_analyzer"

    def test_validate_analyze_valid(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "action": "analyze_document", "document_content": "Test content"
        })
        assert result.ok

    def test_validate_analyze_missing_content(self, plugin_instance):
        result = plugin_instance.validate_inputs({"action": "analyze_document"})
        assert not result.ok

    def test_validate_create_valid(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "action": "create_scenario", "name": "Test", "description": "Desc"
        })
        assert result.ok

    def test_validate_create_missing_name(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "action": "create_scenario", "description": "Desc"
        })
        assert not result.ok

    def test_validate_add_control_valid(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "action": "add_control", "scenario_id": "TS-0001",
            "name": "WAF", "control_type": "application"
        })
        assert result.ok

    def test_validate_add_control_invalid_type(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "action": "add_control", "scenario_id": "TS-0001",
            "name": "WAF", "control_type": "invalid"
        })
        assert not result.ok

    def test_validate_add_event_valid(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "action": "add_event", "scenario_id": "TS-0001",
            "name": "Step 1", "sequence_order": 1
        })
        assert result.ok

    def test_validate_gap_missing_id(self, plugin_instance):
        result = plugin_instance.validate_inputs({"action": "gap_analysis"})
        assert not result.ok

    def test_validate_invalid_action(self, plugin_instance):
        result = plugin_instance.validate_inputs({"action": "destroy"})
        assert not result.ok


class TestCreateScenario:
    def test_create(self, plugin_instance):
        result = plugin_instance.execute({
            "action": "create_scenario",
            "name": "Test Scenario",
            "description": "A test threat scenario",
            "threat_actor": "APT1",
            "target_assets": ["web_server"],
        }, None)
        assert result.ok
        assert result.result["scenario_id"] == "TS-0001"
        assert result.result["name"] == "Test Scenario"

    def test_create_multiple(self, plugin_instance):
        plugin_instance.execute({
            "action": "create_scenario", "name": "S1", "description": "D1"
        }, None)
        result = plugin_instance.execute({
            "action": "create_scenario", "name": "S2", "description": "D2"
        }, None)
        assert result.result["scenario_id"] == "TS-0002"


class TestAddControl:
    def test_add_control(self, plugin_instance):
        plugin_instance.execute({
            "action": "create_scenario", "name": "S1", "description": "D1"
        }, None)
        result = plugin_instance.execute({
            "action": "add_control",
            "scenario_id": "TS-0001",
            "name": "WAF",
            "control_type": "application",
            "description": "Web application firewall",
            "bypass_difficulty": "high",
        }, None)
        assert result.ok
        assert result.result["control_id"] == "SC-0001"
        assert result.result["control_type"] == "application"

    def test_add_to_nonexistent_scenario(self, plugin_instance):
        result = plugin_instance.execute({
            "action": "add_control",
            "scenario_id": "TS-9999",
            "name": "WAF",
            "control_type": "application",
        }, None)
        assert not result.ok
        assert result.error_code == "ARTIFACT_NOT_FOUND"


class TestAddEvent:
    def test_add_event(self, plugin_instance):
        plugin_instance.execute({
            "action": "create_scenario", "name": "S1", "description": "D1"
        }, None)
        result = plugin_instance.execute({
            "action": "add_event",
            "scenario_id": "TS-0001",
            "name": "Initial Access",
            "description": "Phishing email",
            "sequence_order": 1,
            "technique_name": "Phishing",
            "technique_id": "T1566",
        }, None)
        assert result.ok
        assert result.result["event_id"] == "AE-0001"
        assert result.result["technique_id"] == "T1566"

    def test_add_to_nonexistent_scenario(self, plugin_instance):
        result = plugin_instance.execute({
            "action": "add_event",
            "scenario_id": "TS-9999",
            "name": "Step 1",
            "sequence_order": 1,
        }, None)
        assert not result.ok


class TestListScenarios:
    def test_empty(self, plugin_instance):
        result = plugin_instance.execute({"action": "list_scenarios"}, None)
        assert result.ok
        assert result.result["scenarios"] == []

    def test_with_data(self, plugin_instance, scenario_with_data):
        result = plugin_instance.execute({"action": "list_scenarios"}, None)
        assert result.ok
        scenarios = result.result["scenarios"]
        assert len(scenarios) == 1
        assert scenarios[0]["scenario_id"] == scenario_with_data
        assert scenarios[0]["controls_count"] == 3
        assert scenarios[0]["events_count"] == 3


class TestGapAnalysis:
    def test_gap_analysis(self, plugin_instance, scenario_with_data):
        result = plugin_instance.execute({
            "action": "gap_analysis",
            "scenario_id": scenario_with_data,
        }, None)
        assert result.ok
        gap = result.result["gap_analysis"]

        # Step 2 (detect only) and Step 3 (unprotected) should be unprotected
        assert len(gap["unprotected_events"]) == 2

        # EDR Agent is partial
        assert len(gap["weak_controls"]) == 1
        assert gap["weak_controls"][0]["name"] == "EDR Agent"

        # Legacy Firewall is low bypass difficulty
        assert len(gap["easy_bypass"]) == 1
        assert gap["easy_bypass"][0]["name"] == "Legacy Firewall"

        assert gap["total_issues"] == 4  # 2 unprotected + 1 weak + 1 easy

    def test_gap_nonexistent(self, plugin_instance):
        result = plugin_instance.execute({
            "action": "gap_analysis", "scenario_id": "TS-9999"
        }, None)
        assert not result.ok


class TestExport:
    def test_export_markdown(self, plugin_instance, scenario_with_data):
        result = plugin_instance.execute({
            "action": "export",
            "scenario_id": scenario_with_data,
        }, None)
        assert result.ok
        md = result.result["markdown"]
        assert "Ransomware via Phishing" in md
        assert "T1566" in md
        assert "Email Gateway" in md
        assert "UNPROTECTED" in md

    def test_export_to_file(self, plugin_instance, scenario_with_data, tmp_path):
        out = str(tmp_path / "scenario.md")
        result = plugin_instance.execute({
            "action": "export",
            "scenario_id": scenario_with_data,
            "output_path": out,
        }, None)
        assert result.ok
        assert Path(out).exists()
        content = Path(out).read_text()
        assert "Ransomware" in content

    def test_export_nonexistent(self, plugin_instance):
        result = plugin_instance.execute({
            "action": "export", "scenario_id": "TS-9999"
        }, None)
        assert not result.ok


class TestAnalyzeDocument:
    def test_analyze_without_llm(self, plugin_instance):
        result = plugin_instance.execute({
            "action": "analyze_document",
            "document_content": "This is a sample threat model document describing attack paths.",
            "source_type": "threat_model",
        }, None)
        assert result.ok
        assert result.result["ai_analysis"] is None
        assert result.result["content_length"] > 0


class TestSummarize:
    def test_summarize_create(self, plugin_instance):
        result = plugin_instance.execute({
            "action": "create_scenario", "name": "Test", "description": "D"
        }, None)
        summary = plugin_instance.summarize_for_llm(result)
        assert "TS-0001" in summary

    def test_summarize_list(self, plugin_instance, scenario_with_data):
        result = plugin_instance.execute({"action": "list_scenarios"}, None)
        summary = plugin_instance.summarize_for_llm(result)
        assert "1 scenario" in summary

    def test_summarize_gap(self, plugin_instance, scenario_with_data):
        result = plugin_instance.execute({
            "action": "gap_analysis", "scenario_id": scenario_with_data
        }, None)
        summary = plugin_instance.summarize_for_llm(result)
        assert "issues" in summary.lower()

    def test_summarize_failure(self, plugin_instance):
        result = _tool_mod.ToolResult(ok=False, message="Not found")
        summary = plugin_instance.summarize_for_llm(result)
        assert "failed" in summary.lower()
