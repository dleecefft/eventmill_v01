"""Contract compliance tests for log_navigator."""

import importlib.util
import json
import sys
import tempfile
from pathlib import Path

import pytest

PLUGIN_DIR = Path(__file__).resolve().parent.parent

def _load_tool_module():
    _name = "log_navigator_tool"
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
    return _tool_mod.LogNavigator()


@pytest.fixture
def sample_dir(tmp_path):
    """Create a temporary directory with sample log files."""
    # Create subdirectory
    sub = tmp_path / "subdir"
    sub.mkdir()

    # Create files
    (tmp_path / "access.log").write_text(
        "\n".join([f"Line {i}: log entry {i}" for i in range(1, 51)])
    )
    (tmp_path / "error.log").write_text("ERROR line 1\nERROR line 2\n")
    (tmp_path / "app.log").write_text("INFO startup\nWARNING slow\n")
    (sub / "nested.log").write_text("nested content\n")

    return tmp_path


class TestManifest:
    def test_required_fields(self, manifest):
        for field in ["tool_name", "version", "pillar", "entry_point", "class_name"]:
            assert field in manifest

    def test_pillar_matches_directory(self, manifest):
        assert manifest["pillar"] == PLUGIN_DIR.parent.name

    def test_tool_name(self, manifest):
        assert manifest["tool_name"] == "log_navigator"


class TestProtocol:
    def test_metadata(self, plugin_instance):
        meta = plugin_instance.metadata()
        assert meta["tool_name"] == "log_navigator"

    def test_validate_valid_list(self, plugin_instance):
        result = plugin_instance.validate_inputs({"action": "list", "path": "/tmp"})
        assert result.ok

    def test_validate_valid_read(self, plugin_instance):
        result = plugin_instance.validate_inputs({"action": "read", "path": "/tmp/test.log"})
        assert result.ok

    def test_validate_valid_metadata(self, plugin_instance):
        result = plugin_instance.validate_inputs({"action": "metadata", "path": "/tmp/test.log"})
        assert result.ok

    def test_validate_missing_action(self, plugin_instance):
        result = plugin_instance.validate_inputs({"path": "/tmp"})
        assert not result.ok

    def test_validate_invalid_action(self, plugin_instance):
        result = plugin_instance.validate_inputs({"action": "delete", "path": "/tmp"})
        assert not result.ok

    def test_validate_missing_path(self, plugin_instance):
        result = plugin_instance.validate_inputs({"action": "list"})
        assert not result.ok


class TestListAction:
    def test_list_directory(self, plugin_instance, sample_dir):
        result = plugin_instance.execute(
            {"action": "list", "path": str(sample_dir)}, None
        )
        assert result.ok
        data = result.result
        assert data["action"] == "list"
        assert data["file_count"] == 3
        assert data["dir_count"] == 1

        # Directories should come first
        names = [e["name"] for e in data["entries"]]
        assert names[0] == "subdir/"

    def test_list_with_prefix(self, plugin_instance, sample_dir):
        result = plugin_instance.execute(
            {"action": "list", "path": str(sample_dir), "prefix": "acc"}, None
        )
        assert result.ok
        assert len(result.result["entries"]) == 1
        assert result.result["entries"][0]["name"] == "access.log"

    def test_list_max_results(self, plugin_instance, sample_dir):
        result = plugin_instance.execute(
            {"action": "list", "path": str(sample_dir), "max_results": 2}, None
        )
        assert result.ok
        assert len(result.result["entries"]) == 2

    def test_list_nonexistent(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "list", "path": "/nonexistent/dir"}, None
        )
        assert not result.ok
        assert result.error_code == "ARTIFACT_NOT_FOUND"

    def test_list_file_sizes(self, plugin_instance, sample_dir):
        result = plugin_instance.execute(
            {"action": "list", "path": str(sample_dir)}, None
        )
        assert result.ok
        file_entries = [e for e in result.result["entries"] if e["type"] == "file"]
        for entry in file_entries:
            assert "size" in entry
            assert entry["size"] > 0


class TestReadAction:
    def test_read_segment(self, plugin_instance, sample_dir):
        log_path = str(sample_dir / "access.log")
        result = plugin_instance.execute(
            {"action": "read", "path": log_path, "line_limit": 10}, None
        )
        assert result.ok
        data = result.result
        assert data["action"] == "read"
        assert data["lines_read"] == 10
        assert data["has_more"] is True
        assert len(data["lines"]) == 10

    def test_read_with_offset(self, plugin_instance, sample_dir):
        log_path = str(sample_dir / "access.log")
        result = plugin_instance.execute(
            {"action": "read", "path": log_path, "offset_lines": 45, "line_limit": 10}, None
        )
        assert result.ok
        assert result.result["lines_read"] == 5
        assert result.result["has_more"] is False

    def test_read_past_eof(self, plugin_instance, sample_dir):
        log_path = str(sample_dir / "error.log")
        result = plugin_instance.execute(
            {"action": "read", "path": log_path, "offset_lines": 1000}, None
        )
        assert result.ok
        assert result.result["lines_read"] == 0

    def test_read_nonexistent(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "read", "path": "/nonexistent/file.log"}, None
        )
        assert not result.ok
        assert result.error_code == "ARTIFACT_NOT_FOUND"


class TestMetadataAction:
    def test_get_metadata(self, plugin_instance, sample_dir):
        log_path = str(sample_dir / "access.log")
        result = plugin_instance.execute(
            {"action": "metadata", "path": log_path}, None
        )
        assert result.ok
        meta = result.result["metadata"]
        assert meta["name"] == "access.log"
        assert meta["size_bytes"] > 0
        assert meta["line_count"] == 50
        assert "modified" in meta

    def test_metadata_nonexistent(self, plugin_instance):
        result = plugin_instance.execute(
            {"action": "metadata", "path": "/nonexistent/file.log"}, None
        )
        assert not result.ok


class TestSummarize:
    def test_summarize_list(self, plugin_instance, sample_dir):
        result = plugin_instance.execute(
            {"action": "list", "path": str(sample_dir)}, None
        )
        summary = plugin_instance.summarize_for_llm(result)
        assert len(summary) <= 2000
        assert "3 files" in summary

    def test_summarize_read(self, plugin_instance, sample_dir):
        log_path = str(sample_dir / "access.log")
        result = plugin_instance.execute(
            {"action": "read", "path": log_path, "line_limit": 5}, None
        )
        summary = plugin_instance.summarize_for_llm(result)
        assert len(summary) <= 2000
        assert "5 lines" in summary

    def test_summarize_metadata(self, plugin_instance, sample_dir):
        log_path = str(sample_dir / "access.log")
        result = plugin_instance.execute(
            {"action": "metadata", "path": log_path}, None
        )
        summary = plugin_instance.summarize_for_llm(result)
        assert "access.log" in summary

    def test_summarize_failure(self, plugin_instance):
        result = _tool_mod.ToolResult(ok=False, message="Not found")
        summary = plugin_instance.summarize_for_llm(result)
        assert "failed" in summary.lower()
