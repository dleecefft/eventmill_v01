"""Contract compliance tests for log_searcher."""

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent

def _load_tool_module():
    _name = "log_searcher_tool"
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
    return _tool_mod.LogSearcher()


@pytest.fixture
def sample_log_file():
    content = "\n".join([
        "INFO 2025-01-15 10:00:00 Application started",
        "INFO 2025-01-15 10:00:01 Health check passed",
        "WARNING 2025-01-15 10:00:02 Slow query detected (1200ms)",
        "ERROR 2025-01-15 10:00:03 Connection refused to db-primary",
        "INFO 2025-01-15 10:00:04 Request from 192.168.1.100",
        "ERROR 2025-01-15 10:00:05 Authentication failed for user admin",
        "INFO 2025-01-15 10:00:06 Request from 10.0.0.55",
        "WARNING 2025-01-15 10:00:07 Certificate expires in 7 days",
        "ERROR 2025-01-15 10:00:08 Timeout waiting for response",
        "INFO 2025-01-15 10:00:09 Shutdown complete",
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
        assert manifest["tool_name"] == "log_searcher"


class TestProtocol:
    def test_metadata(self, plugin_instance):
        meta = plugin_instance.metadata()
        assert meta["tool_name"] == "log_searcher"

    def test_validate_valid(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "file_path": "/tmp/test.log", "query": "error"
        })
        assert result.ok

    def test_validate_missing_query(self, plugin_instance):
        result = plugin_instance.validate_inputs({"file_path": "/tmp/test.log"})
        assert not result.ok

    def test_validate_missing_file(self, plugin_instance):
        result = plugin_instance.validate_inputs({"query": "error"})
        assert not result.ok

    def test_validate_regex_valid(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "file_path": "/tmp/test.log", "query": r"ERROR.*\d+", "mode": "regex"
        })
        assert result.ok

    def test_validate_regex_invalid(self, plugin_instance):
        result = plugin_instance.validate_inputs({
            "file_path": "/tmp/test.log", "query": r"[invalid", "mode": "regex"
        })
        assert not result.ok


class TestExecution:
    def test_text_search(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"file_path": str(sample_log_file), "query": "ERROR"},
            None,
        )
        assert result.ok
        assert result.result["total_matches"] == 3
        assert result.result["lines_scanned"] == 10

    def test_case_insensitive(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"file_path": str(sample_log_file), "query": "error"},
            None,
        )
        assert result.ok
        assert result.result["total_matches"] == 3

    def test_regex_search(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"file_path": str(sample_log_file), "query": r"ERROR.*(?:refused|failed)", "mode": "regex"},
            None,
        )
        assert result.ok
        assert result.result["total_matches"] == 2

    def test_max_results(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"file_path": str(sample_log_file), "query": "INFO", "max_results": 2},
            None,
        )
        assert result.ok
        assert len(result.result["matches"]) == 2
        assert result.result["truncated"] is True

    def test_context_lines(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"file_path": str(sample_log_file), "query": "Connection refused", "context_lines": 1},
            None,
        )
        assert result.ok
        assert result.result["total_matches"] == 1
        match = result.result["matches"][0]
        assert match["line_number"] == 4
        assert "context_before" in match
        assert "context_after" in match

    def test_invert(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"file_path": str(sample_log_file), "query": "INFO", "invert": True},
            None,
        )
        assert result.ok
        # 10 lines total, 5 are INFO, so 5 non-INFO
        assert result.result["total_matches"] == 5

    def test_no_matches(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"file_path": str(sample_log_file), "query": "CRITICAL"},
            None,
        )
        assert result.ok
        assert result.result["total_matches"] == 0

    def test_file_not_found(self, plugin_instance):
        result = plugin_instance.execute(
            {"file_path": "/nonexistent/file.log", "query": "test"},
            None,
        )
        assert not result.ok
        assert result.error_code == "ARTIFACT_NOT_FOUND"


class TestSummarize:
    def test_summarize_with_results(self, plugin_instance, sample_log_file):
        result = plugin_instance.execute(
            {"file_path": str(sample_log_file), "query": "ERROR"},
            None,
        )
        summary = plugin_instance.summarize_for_llm(result)
        assert len(summary) <= 2000
        assert "ERROR" in summary
        assert "3 matches" in summary

    def test_summarize_failure(self, plugin_instance):
        result = _tool_mod.ToolResult(ok=False, message="File missing")
        summary = plugin_instance.summarize_for_llm(result)
        assert "failed" in summary.lower()
