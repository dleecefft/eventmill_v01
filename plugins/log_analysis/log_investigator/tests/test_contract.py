"""Contract compliance tests for log_investigator."""

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent

def _load_tool_module():
    _name = "log_investigator_tool"
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
    return _tool_mod.LogInvestigator()


@pytest.fixture
def sample_log_file():
    content = "\n".join([
        '192.168.1.100 - admin [15/Jan/2025:10:30:00 +0000] "GET /api/users HTTP/1.1" 200 1234',
        '10.0.0.55 - - [15/Jan/2025:10:30:01 +0000] "POST /api/login HTTP/1.1" 401 89',
        '192.168.1.100 - admin [15/Jan/2025:10:30:02 +0000] "GET /api/data HTTP/1.1" 200 5678',
        '172.16.0.1 - scanner [15/Jan/2025:10:30:03 +0000] "PROPFIND / HTTP/1.1" 405 0',
        '10.0.0.55 - - [15/Jan/2025:10:30:04 +0000] "GET /index.html HTTP/1.1" 200 2345',
        '192.168.1.100 - admin [15/Jan/2025:10:30:05 +0000] "DELETE /api/session HTTP/1.1" 204 0',
        'ERROR 2025-01-15 10:30:06 - Connection timeout from 10.0.0.99',
        'WARNING 2025-01-15 10:30:07 - Rate limit exceeded for user admin',
        'ERROR 2025-01-15 10:30:08 - SQL injection attempt: union select * from users',
        '192.168.1.100 - admin [15/Jan/2025:10:30:09 +0000] "GET /api/status HTTP/1.1" 200 100',
    ])
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(content)
        return Path(f.name)


class TestManifest:
    def test_required_fields(self, manifest):
        for field in ["tool_name", "version", "pillar", "entry_point", "class_name"]:
            assert field in manifest

    def test_pillar_matches_directory(self, manifest):
        assert manifest["pillar"] == PLUGIN_DIR.parent.name

    def test_tool_name(self, manifest):
        assert manifest["tool_name"] == "log_investigator"

    def test_requires_llm(self, manifest):
        assert manifest["requires_llm"] is True

    def test_not_safe_for_auto_invoke(self, manifest):
        assert manifest["safe_for_auto_invoke"] is False


class TestProtocol:
    def test_metadata(self, plugin_instance):
        meta = plugin_instance.metadata()
        assert meta["tool_name"] == "log_investigator"

    def test_validate_investigate_valid(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "mode": "investigate", "file_path": "/tmp/test.log", "search_term": "192.168.1.100"
        })
        assert result.ok

    def test_validate_investigate_missing_term(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "mode": "investigate", "file_path": "/tmp/test.log"
        })
        assert not result.ok

    def test_validate_workflow_valid(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "mode": "workflow", "file_path": "/tmp/test.log", "workflow_type": "top_talkers"
        })
        assert result.ok

    def test_validate_workflow_missing_type(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "mode": "workflow", "file_path": "/tmp/test.log"
        })
        assert not result.ok

    def test_validate_workflow_invalid_type(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "mode": "workflow", "file_path": "/tmp/test.log", "workflow_type": "nonexistent"
        })
        assert not result.ok

    def test_validate_investigate_ip_needs_target(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "mode": "workflow", "file_path": "/tmp/test.log",
            "workflow_type": "investigate_ip"
        })
        assert not result.ok

    def test_validate_missing_mode(self, plugin_instance):
        result = plugin_instance.validate_inputs({"file_path": "/tmp/test.log"})
        assert not result.ok


class TestInvestigateMode:
    def test_investigate_with_matches(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"mode": "investigate", "file_path": str(sample_log_file), "search_term": "192.168.1.100"},
            None,
        )
        assert result.ok
        data = result.result
        assert data["mode"] == "investigate"
        assert data["total_matches"] == 4
        assert data["lines_scanned"] == 10
        assert len(data["sample_matches"]) == 4
        # No LLM context provided, so ai_analysis should be None
        assert data["ai_analysis"] is None

    def test_investigate_no_matches(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"mode": "investigate", "file_path": str(sample_log_file), "search_term": "NONEXISTENT_TERM"},
            None,
        )
        assert result.ok
        assert result.result["total_matches"] == 0

    def test_investigate_file_not_found(self, plugin_instance):
        result = plugin_instance.execute(
            {"mode": "investigate", "file_path": "/nonexistent/file.log", "search_term": "test"},
            None,
        )
        assert not result.ok
        assert result.error_code == "ARTIFACT_NOT_FOUND"


class TestWorkflowMode:
    def test_top_talkers(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"mode": "workflow", "file_path": str(sample_log_file), "workflow_type": "top_talkers"},
            None,
        )
        assert result.ok
        data = result.result
        assert data["workflow_type"] == "top_talkers"
        sections = data["workflow_results"]
        assert len(sections) > 0

        # IP Addresses section should exist
        ip_section = next((s for s in sections if s["section"] == "IP Addresses"), None)
        assert ip_section is not None
        assert len(ip_section["entries"]) > 0

        # 192.168.1.100 should be top IP
        top_ip = ip_section["entries"][0]
        assert top_ip["value"] == "192.168.1.100"
        assert top_ip["count"] == 4

    def test_investigate_ip_workflow(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"mode": "workflow", "file_path": str(sample_log_file),
             "workflow_type": "investigate_ip", "target": "10.0.0.55"},
            None,
        )
        assert result.ok
        data = result.result
        assert data["workflow_type"] == "investigate_ip"
        sections = data["workflow_results"]
        assert len(sections) == 1
        assert len(sections[0]["entries"]) == 2  # 10.0.0.55 appears twice

    def test_security_events(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"mode": "workflow", "file_path": str(sample_log_file),
             "workflow_type": "security_events"},
            None,
        )
        assert result.ok
        sections = result.result["workflow_results"]
        section_names = [s["section"] for s in sections]
        # Should find HTTP errors (401, 405) and error messages
        assert "HTTP Errors" in section_names
        assert "Error Messages" in section_names

    def test_attack_patterns(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"mode": "workflow", "file_path": str(sample_log_file),
             "workflow_type": "attack_patterns"},
            None,
        )
        assert result.ok
        data = result.result
        assert data["workflow_type"] == "attack_patterns"
        assert data["lines_sampled"] > 0
        sections = data["workflow_results"]
        assert len(sections) == 1
        assert sections[0]["section"] == "Structural Patterns"
        assert len(sections[0]["entries"]) > 0

    def test_workflow_file_not_found(self, plugin_instance):
        result = plugin_instance.execute(
            {"mode": "workflow", "file_path": "/nonexistent/file.log",
             "workflow_type": "top_talkers"},
            None,
        )
        assert not result.ok


class TestSummarize:
    def test_summarize_investigate(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"mode": "investigate", "file_path": str(sample_log_file),
             "search_term": "192.168.1.100"},
            None,
        )
        summary = plugin_instance.summarize_for_llm(result)
        assert len(summary) <= 2000
        assert "192.168.1.100" in summary
        assert "4 matches" in summary

    def test_summarize_workflow(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"mode": "workflow", "file_path": str(sample_log_file),
             "workflow_type": "top_talkers"},
            None,
        )
        summary = plugin_instance.summarize_for_llm(result)
        assert len(summary) <= 2000
        assert "top_talkers" in summary

    def test_summarize_failure(self, plugin_instance):
        result = _tool_mod.ToolResult(ok=False, message="File missing")
        summary = plugin_instance.summarize_for_llm(result)
        assert "failed" in summary.lower()
