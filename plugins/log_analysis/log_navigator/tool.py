"""
Log Navigator — List, read, and inspect log files from local or cloud storage.

Ported from Event Mill v1.0 navigation.py with improvements:
- Conforms to EventMillToolProtocol
- Decoupled from GCS (works with local filesystem, cloud via storage backend)
- Structured JSON output
- Pagination support for large files
- summarize_for_llm() for context-optimized output
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any


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


class LogNavigator:
    """Navigate log file collections: list, read segments, get metadata.

    Actions:
    - list: List files and directories at a path
    - read: Read a paginated segment of a log file
    - metadata: Get file size, modification time, line count
    """

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "log_navigator",
            "version": "1.0.0",
            "pillar": "log_analysis",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []

        if "action" not in payload:
            errors.append("'action' is required (list, read, or metadata)")
        elif payload["action"] not in ("list", "read", "metadata"):
            errors.append(f"Invalid action '{payload['action']}'. Must be list, read, or metadata.")

        if "path" not in payload:
            errors.append("'path' is required")

        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(
        self,
        payload: dict[str, Any],
        context: Any,
    ) -> ToolResult:
        """Execute navigation action."""
        action = payload["action"]
        path = payload["path"]

        try:
            if action == "list":
                return self._list_directory(path, payload)
            elif action == "read":
                return self._read_segment(path, payload, context)
            elif action == "metadata":
                return self._get_metadata(path, context)
            else:
                return ToolResult(
                    ok=False,
                    error_code="INPUT_VALIDATION_FAILED",
                    message=f"Unknown action: {action}",
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
            return f"log_navigator failed: {result.message}"

        data = result.result or {}
        action = data.get("action", "unknown")

        if action == "list":
            files = data.get("file_count", 0)
            dirs = data.get("dir_count", 0)
            entries = data.get("entries", [])
            parts = [f"Listed {data.get('path', '')}: {files} files, {dirs} directories."]
            for entry in entries[:15]:
                icon = "D" if entry["type"] == "directory" else "F"
                size_info = f" ({entry['size']}B)" if entry.get("size") and entry["type"] == "file" else ""
                parts.append(f"  [{icon}] {entry['name']}{size_info}")
            if len(entries) > 15:
                parts.append(f"  ... and {len(entries) - 15} more")
            return "\n".join(parts)

        elif action == "read":
            offset = data.get("offset", 0)
            lines_read = data.get("lines_read", 0)
            has_more = data.get("has_more", False)
            lines = data.get("lines", [])
            parts = [
                f"Read {lines_read} lines from offset {offset}.",
                f"Has more: {has_more}",
            ]
            # Show first/last few lines
            if lines:
                for line in lines[:5]:
                    parts.append(f"  {line[:120]}")
                if len(lines) > 10:
                    parts.append(f"  ... ({len(lines) - 10} lines omitted)")
                    for line in lines[-5:]:
                        parts.append(f"  {line[:120]}")
                elif len(lines) > 5:
                    for line in lines[5:]:
                        parts.append(f"  {line[:120]}")
            return "\n".join(parts)

        elif action == "metadata":
            meta = data.get("metadata", {})
            return (
                f"File: {meta.get('name', '?')}\n"
                f"Size: {meta.get('size_bytes', 0)} bytes\n"
                f"Lines: {meta.get('line_count', '?')}\n"
                f"Modified: {meta.get('modified', '?')}"
            )

        return f"log_navigator completed action '{action}'."

    # -------------------------------------------------------------------
    # Action implementations
    # -------------------------------------------------------------------

    def _list_directory(
        self, path: str, payload: dict[str, Any]
    ) -> ToolResult:
        """List files and directories at a path."""
        dir_path = Path(path)
        prefix = payload.get("prefix", "")
        max_results = payload.get("max_results", 50)

        if not dir_path.exists():
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message=f"Directory not found: {path}",
            )

        if not dir_path.is_dir():
            return ToolResult(
                ok=False,
                error_code="INPUT_VALIDATION_FAILED",
                message=f"Path is not a directory: {path}",
            )

        entries: list[dict[str, Any]] = []
        file_count = 0
        dir_count = 0

        try:
            items = sorted(dir_path.iterdir(), key=lambda p: (not p.is_dir(), p.name.lower()))

            for item in items:
                if prefix and not item.name.lower().startswith(prefix.lower()):
                    continue

                if len(entries) >= max_results:
                    break

                if item.is_dir():
                    entries.append({
                        "name": item.name + "/",
                        "type": "directory",
                    })
                    dir_count += 1
                elif item.is_file():
                    entries.append({
                        "name": item.name,
                        "type": "file",
                        "size": item.stat().st_size,
                    })
                    file_count += 1

        except PermissionError:
            return ToolResult(
                ok=False,
                error_code="PERMISSION_DENIED",
                message=f"Permission denied: {path}",
            )

        return ToolResult(
            ok=True,
            result={
                "action": "list",
                "path": str(dir_path),
                "entries": entries,
                "file_count": file_count,
                "dir_count": dir_count,
            },
        )

    def _read_segment(
        self, path: str, payload: dict[str, Any], context: Any
    ) -> ToolResult:
        """Read a paginated segment of a log file."""
        file_path = self._resolve_file(path, context)
        if file_path is None:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message=f"File not found: {path}",
            )

        offset_lines = payload.get("offset_lines", 0)
        line_limit = payload.get("line_limit", 100)

        lines: list[str] = []
        lines_read = 0

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            # Skip to offset
            for i in range(offset_lines):
                if not f.readline():
                    return ToolResult(
                        ok=True,
                        result={
                            "action": "read",
                            "path": str(file_path),
                            "offset": offset_lines,
                            "lines_read": 0,
                            "has_more": False,
                            "lines": [],
                        },
                    )

            # Read segment
            for _ in range(line_limit):
                line = f.readline()
                if not line:
                    break
                lines.append(line.rstrip("\n"))
                lines_read += 1

            # Check if more data exists
            has_more = bool(f.readline())

        return ToolResult(
            ok=True,
            result={
                "action": "read",
                "path": str(file_path),
                "offset": offset_lines,
                "lines_read": lines_read,
                "has_more": has_more,
                "lines": lines,
            },
        )

    def _get_metadata(self, path: str, context: Any) -> ToolResult:
        """Get file metadata: size, modification time, line count."""
        file_path = self._resolve_file(path, context)
        if file_path is None:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message=f"File not found: {path}",
            )

        stat = file_path.stat()

        # Count lines
        line_count = 0
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for _ in f:
                line_count += 1

        modified = datetime.fromtimestamp(stat.st_mtime).strftime("%Y-%m-%d %H:%M:%S")

        return ToolResult(
            ok=True,
            result={
                "action": "metadata",
                "path": str(file_path),
                "metadata": {
                    "name": file_path.name,
                    "size_bytes": stat.st_size,
                    "modified": modified,
                    "line_count": line_count,
                },
            },
        )

    def _resolve_file(self, file_path: str, context: Any) -> Path | None:
        """Resolve file path, checking artifact registry if available."""
        p = Path(file_path)
        if p.exists() and p.is_file():
            return p

        if context and hasattr(context, "artifacts"):
            for art in (context.artifacts or []):
                if hasattr(art, "file_path"):
                    art_path = Path(art.file_path)
                    if art_path.name == p.name and art_path.exists():
                        return art_path

        return None
