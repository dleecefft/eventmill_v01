"""
Log Searcher — Search log files for text or regex patterns.

Ported from Event Mill v1.0 search.py with improvements:
- Conforms to EventMillToolProtocol
- Decoupled from GCS (works with local files via artifact registry)
- Structured JSON output with line numbers
- Optional surrounding context lines
- Invert mode for exclusion filtering
- summarize_for_llm() for context-optimized output
"""

from __future__ import annotations

import re
from collections import deque
from dataclasses import dataclass
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


class LogSearcher:
    """Search log files for text or regex patterns with context."""

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "log_searcher",
            "version": "1.0.0",
            "pillar": "log_analysis",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []

        if "file_path" not in payload:
            errors.append("'file_path' is required")
        if "query" not in payload:
            errors.append("'query' is required")
        elif not payload["query"]:
            errors.append("'query' must not be empty")

        mode = payload.get("mode", "text")
        if mode not in ("text", "regex"):
            errors.append(f"Invalid mode '{mode}'. Must be 'text' or 'regex'.")

        if mode == "regex" and payload.get("query"):
            try:
                re.compile(payload["query"])
            except re.error as e:
                errors.append(f"Invalid regex pattern: {e}")

        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(
        self,
        payload: dict[str, Any],
        context: Any,
    ) -> ToolResult:
        """Execute log search."""
        file_path = payload["file_path"]
        query = payload["query"]
        mode = payload.get("mode", "text")
        max_results = payload.get("max_results", 50)
        context_lines = payload.get("context_lines", 0)
        invert = payload.get("invert", False)

        # Resolve file path
        resolved = self._resolve_file(file_path, context)
        if resolved is None:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message=f"File not found: {file_path}",
            )

        try:
            matches, lines_scanned, total_matches, truncated = self._search(
                file_path=resolved,
                query=query,
                mode=mode,
                max_results=max_results,
                context_lines=context_lines,
                invert=invert,
            )

            return ToolResult(
                ok=True,
                result={
                    "query": query,
                    "mode": mode,
                    "total_matches": total_matches,
                    "lines_scanned": lines_scanned,
                    "truncated": truncated,
                    "matches": matches,
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
            return f"log_searcher failed: {result.message}"

        data = result.result or {}
        query = data.get("query", "")
        total = data.get("total_matches", 0)
        scanned = data.get("lines_scanned", 0)
        truncated = data.get("truncated", False)
        matches = data.get("matches", [])

        parts = [
            f"Search for '{query}': {total} matches in {scanned} lines.",
        ]

        if truncated:
            parts.append(f"(Results truncated, showing {len(matches)} of {total})")

        # Show first few matches compactly
        for m in matches[:10]:
            line_text = m["text"][:120]
            parts.append(f"  L{m['line_number']}: {line_text}")

        if len(matches) > 10:
            parts.append(f"  ... and {len(matches) - 10} more matches")

        return "\n".join(parts)

    def _search(
        self,
        file_path: Path,
        query: str,
        mode: str,
        max_results: int,
        context_lines: int,
        invert: bool,
    ) -> tuple[list[dict], int, int, bool]:
        """Core search implementation.

        Returns:
            (matches, lines_scanned, total_matches, truncated)
        """
        if mode == "regex":
            compiled = re.compile(query, re.IGNORECASE)
            match_fn = lambda line: bool(compiled.search(line))
        else:
            query_lower = query.lower()
            match_fn = lambda line: query_lower in line.lower()

        matches: list[dict[str, Any]] = []
        lines_scanned = 0
        total_matches = 0
        truncated = False

        # Read all lines if we need context, otherwise stream
        if context_lines > 0:
            matches, lines_scanned, total_matches, truncated = self._search_with_context(
                file_path, match_fn, max_results, context_lines, invert
            )
        else:
            matches, lines_scanned, total_matches, truncated = self._search_simple(
                file_path, match_fn, max_results, invert
            )

        return matches, lines_scanned, total_matches, truncated

    def _search_simple(
        self,
        file_path: Path,
        match_fn,
        max_results: int,
        invert: bool,
    ) -> tuple[list[dict], int, int, bool]:
        """Simple line-by-line search without context."""
        matches: list[dict[str, Any]] = []
        lines_scanned = 0
        total_matches = 0
        truncated = False

        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                lines_scanned += 1
                is_match = match_fn(line)

                if invert:
                    is_match = not is_match

                if is_match:
                    total_matches += 1
                    if len(matches) < max_results:
                        matches.append({
                            "line_number": lines_scanned,
                            "text": line.rstrip(),
                        })
                    elif total_matches == max_results + 1:
                        truncated = True

        return matches, lines_scanned, total_matches, truncated

    def _search_with_context(
        self,
        file_path: Path,
        match_fn,
        max_results: int,
        context_lines: int,
        invert: bool,
    ) -> tuple[list[dict], int, int, bool]:
        """Search with surrounding context lines."""
        # Read all lines for context access
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            all_lines = [line.rstrip() for line in f]

        lines_scanned = len(all_lines)
        matches: list[dict[str, Any]] = []
        total_matches = 0
        truncated = False

        for i, line in enumerate(all_lines):
            is_match = match_fn(line)
            if invert:
                is_match = not is_match

            if is_match:
                total_matches += 1
                if len(matches) < max_results:
                    # Gather context
                    before_start = max(0, i - context_lines)
                    after_end = min(len(all_lines), i + context_lines + 1)

                    context_before = all_lines[before_start:i]
                    context_after = all_lines[i + 1:after_end]

                    entry: dict[str, Any] = {
                        "line_number": i + 1,
                        "text": line,
                    }
                    if context_before:
                        entry["context_before"] = context_before
                    if context_after:
                        entry["context_after"] = context_after

                    matches.append(entry)
                elif total_matches == max_results + 1:
                    truncated = True

        return matches, lines_scanned, total_matches, truncated

    def _resolve_file(self, file_path: str, context: Any) -> Path | None:
        """Resolve file path, checking artifact registry if available."""
        p = Path(file_path)
        if p.exists():
            return p

        if context and hasattr(context, "artifacts"):
            for art in (context.artifacts or []):
                if hasattr(art, "file_path"):
                    art_path = Path(art.file_path)
                    if art_path.name == p.name and art_path.exists():
                        return art_path

        return None
