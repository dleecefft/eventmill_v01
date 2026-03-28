"""Contract compliance tests for log_pattern_analyzer."""

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent

def _load_tool_module():
    _name = "log_pattern_analyzer_tool"
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
    return _tool_mod.LogPatternAnalyzer()


@pytest.fixture
def sample_log_file():
    """Create a temporary log file for testing."""
    content = "\n".join([
        '192.168.1.100 - admin [15/Jan/2025:10:30:00 +0000] "GET /api/users HTTP/1.1" 200 1234',
        '10.0.0.55 - - [15/Jan/2025:10:30:01 +0000] "POST /api/login HTTP/1.1" 401 89',
        '192.168.1.100 - admin [15/Jan/2025:10:30:02 +0000] "GET /api/data HTTP/1.1" 200 5678',
        '172.16.0.1 - scanner [15/Jan/2025:10:30:03 +0000] "PROPFIND / HTTP/1.1" 405 0',
        '10.0.0.55 - - [15/Jan/2025:10:30:04 +0000] "GET /index.html HTTP/1.1" 200 2345',
        '192.168.1.100 - admin [15/Jan/2025:10:30:05 +0000] "DELETE /api/session HTTP/1.1" 204 0',
        'ERROR 2025-01-15 10:30:06 - Connection timeout from 10.0.0.99',
        'WARNING 2025-01-15 10:30:07 - Rate limit exceeded for user admin',
        'INFO 2025-01-15 10:30:08 - Health check passed',
        '192.168.1.100 - admin [15/Jan/2025:10:30:09 +0000] "GET /api/status HTTP/1.1" 200 100',
    ])
    with tempfile.NamedTemporaryFile(mode="w", suffix=".log", delete=False) as f:
        f.write(content)
        return Path(f.name)


class TestManifest:
    def test_required_fields(self, manifest):
        required = ["tool_name", "version", "pillar", "entry_point", "class_name"]
        for field in required:
            assert field in manifest, f"Missing required field: {field}"

    def test_pillar_matches_directory(self, manifest):
        assert manifest["pillar"] == PLUGIN_DIR.parent.name

    def test_tool_name(self, manifest):
        assert manifest["tool_name"] == "log_pattern_analyzer"

    def test_capabilities(self, manifest):
        caps = manifest["capabilities"]
        assert "log_analysis:pattern_discovery" in caps
        assert "log_analysis:grok_analysis" in caps
        assert "log_analysis:regex_analysis" in caps

    def test_schemas_exist(self, manifest):
        input_schema = PLUGIN_DIR / manifest.get("input_schema", "schemas/input.schema.json")
        output_schema = PLUGIN_DIR / manifest.get("output_schema", "schemas/output.schema.json")
        assert input_schema.exists()
        assert output_schema.exists()


class TestProtocol:
    def test_metadata(self, plugin_instance):
        meta = plugin_instance.metadata()
        assert meta["tool_name"] == "log_pattern_analyzer"
        assert "version" in meta

    def test_validate_grok_valid(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "mode": "grok", "file_path": "/tmp/test.log", "pattern": "IP"
        })
        assert result.ok

    def test_validate_grok_invalid_pattern(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "mode": "grok", "file_path": "/tmp/test.log", "pattern": "NONEXISTENT"
        })
        assert not result.ok
        assert any("Unknown GROK pattern" in e for e in result.errors)

    def test_validate_regex_valid(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "mode": "regex", "file_path": "/tmp/test.log", "pattern": r"(\d+)"
        })
        assert result.ok

    def test_validate_regex_invalid(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "mode": "regex", "file_path": "/tmp/test.log", "pattern": r"(["
        })
        assert not result.ok

    def test_validate_discover_valid(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "mode": "discover", "file_path": "/tmp/test.log"
        })
        assert result.ok

    def test_validate_missing_mode(self, plugin_instance):
        result = plugin_instance.validate_inputs({"file_path": "/tmp/test.log"})
        assert not result.ok

    def test_validate_missing_file(self, plugin_instance):
        result = plugin_instance.validate_inputs({"mode": "discover"})
        assert not result.ok


class TestExecution:
    def test_grok_ip_analysis(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"mode": "grok", "file_path": str(sample_log_file), "pattern": "IP"},
            None,
        )
        assert result.ok
        assert result.result["mode"] == "grok"
        assert result.result["matches_found"] > 0
        assert len(result.result["top_results"]) > 0

        # 192.168.1.100 appears most often
        top = result.result["top_results"][0]
        assert top["value"] == "192.168.1.100"

    def test_grok_httpstatus(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"mode": "grok", "file_path": str(sample_log_file), "pattern": "HTTPSTATUS"},
            None,
        )
        assert result.ok
        assert result.result["matches_found"] > 0

    def test_grok_loglevel(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"mode": "grok", "file_path": str(sample_log_file), "pattern": "LOGLEVEL"},
            None,
        )
        assert result.ok

    def test_regex_analysis(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"mode": "regex", "file_path": str(sample_log_file), "pattern": r'"(\w+)\s'},
            None,
        )
        assert result.ok
        assert result.result["mode"] == "regex"
        assert result.result["matches_found"] > 0

    def test_discover_mode(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"mode": "discover", "file_path": str(sample_log_file)},
            None,
        )
        assert result.ok
        assert result.result["mode"] == "discover"
        assert result.result["lines_processed"] > 0
        assert len(result.result["patterns"]) > 0

        # Check pattern structure
        p = result.result["patterns"][0]
        assert "signature" in p
        assert "count" in p
        assert "percentage" in p
        assert "example" in p

    def test_file_not_found(self, plugin_instance):
        result = plugin_instance.execute(
            {"mode": "discover", "file_path": "/nonexistent/file.log"},
            None,
        )
        assert not result.ok
        assert result.error_code == "ARTIFACT_NOT_FOUND"

    def test_limit_parameter(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"mode": "grok", "file_path": str(sample_log_file), "pattern": "IP", "limit": 2},
            None,
        )
        assert result.ok
        assert len(result.result["top_results"]) <= 2


class TestSummarize:
    def test_summarize_grok(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"mode": "grok", "file_path": str(sample_log_file), "pattern": "IP"},
            None,
        )
        summary = plugin_instance.summarize_for_llm(result)
        assert len(summary) <= 2000
        assert "192.168.1.100" in summary

    def test_summarize_discover(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"mode": "discover", "file_path": str(sample_log_file)},
            None,
        )
        summary = plugin_instance.summarize_for_llm(result)
        assert len(summary) <= 2000
        assert "discovery" in summary.lower()

    def test_summarize_failure(self, plugin_instance):
        result = _tool_mod.ToolResult(ok=False, error_code="ARTIFACT_NOT_FOUND", message="File missing")
        summary = plugin_instance.summarize_for_llm(result)
        assert "failed" in summary.lower()
