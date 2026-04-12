"""
Threat Report Analyzer — Summarize threat intelligence reports from common bucket.

Reads threat intelligence reports (MITRE ATT&CK, CAPEC, CISA advisories, vendor
bulletins) from the common bucket and generates 1500-2000 word markdown summaries
for use as context in other analysis tools.

Conforms to EventMillToolProtocol with three actions:
- list_reports: List available reports in common bucket
- summarize: Generate LLM-powered summary of a specific report
- search_reports: Search across report content
"""

from __future__ import annotations

import json
import os
import re
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


SUMMARIZATION_PROMPT_TEMPLATE = """You are a Senior Threat Intelligence Analyst creating a concise reference document.

SOURCE REPORT: {report_name}
SOURCE TYPE: {report_type}
WORD LIMIT: {max_words} words

INSTRUCTIONS:
1. Create a comprehensive 1500-2000 word summary suitable for security analysts
2. Focus on actionable intelligence: attack techniques, threat actors, mitigations
3. Include specific MITRE ATT&CK technique IDs where applicable
4. Highlight detection opportunities and SIEM-relevant indicators
5. Use clear section headers for scannability

FOCUS AREAS (if specified): {focus_areas}

REPORT CONTENT:
{content}

Generate a well-structured markdown summary with:
- Executive Summary (2-3 sentences)
- Key Threat Actors/Techniques
- Relevant ATT&CK Techniques (with IDs)
- Detection Opportunities
- Recommended Security Controls
- Sources and References

Output ONLY the markdown summary, no preamble."""


class ThreatReportAnalyzer:
    """Analyze threat intelligence reports from common bucket.

    Actions:
    - list_reports: List available reports in common bucket
    - summarize: Generate LLM-powered summary of a report
    - search_reports: Search across report content
    """

    # Common bucket subdirectories for threat reports
    REPORT_DIRECTORIES = [
        "mitre",
        "capec",
        "cisa",
        "vendor_advisories",
        "threat_actors",
        "campaigns",
        "vulnerabilities",
    ]

    # File extensions to look for
    SUPPORTED_EXTENSIONS = {".json", ".xml", ".md", ".txt", ".csv", ".stix"}

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "threat_report_analyzer",
            "version": "1.0.0",
            "pillar": "threat_modeling",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []

        action = payload.get("action")
        if not action:
            errors.append("'action' is required")
        elif action not in ("list_reports", "summarize", "search_reports"):
            errors.append(
                f"Invalid action '{action}'. Must be list_reports, summarize, or search_reports."
            )

        if action == "summarize" and not payload.get("report_path"):
            errors.append("'report_path' is required for summarize action")

        if action == "search_reports" and not payload.get("query"):
            errors.append("'query' is required for search_reports action")

        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(
        self,
        payload: dict[str, Any],
        context: Any,
    ) -> ToolResult:
        """Execute threat report analysis action."""
        action = payload["action"]

        try:
            if action == "list_reports":
                return self._list_reports(context)
            elif action == "summarize":
                return self._summarize_report(payload, context)
            elif action == "search_reports":
                return self._search_reports(payload, context)
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
            return f"threat_report_analyzer failed: {result.message}"

        data = result.result or {}
        action = data.get("action", "unknown")

        if action == "list_reports":
            reports = data.get("reports", [])
            return f"Found {len(reports)} threat reports in common bucket: {', '.join(r['name'] for r in reports[:10])}"

        elif action == "summarize":
            summaries = data.get("summaries", [])
            if summaries:
                s = summaries[0]
                wc = s.get("word_count", 0)
                return f"Summarized {s['report_path']} ({wc} words)"
            return "Report summarized"

        elif action == "search_reports":
            results = data.get("search_results", [])
            total_matches = sum(len(r.get("matches", [])) for r in results)
            return f"Search found {total_matches} matches across {len(results)} reports"

        return f"threat_report_analyzer completed action '{action}'."

    # -------------------------------------------------------------------
    # Action implementations
    # -------------------------------------------------------------------

    def _list_reports(self, context: Any) -> ToolResult:
        """List available threat reports in common bucket."""
        reports = []

        # Try to get common bucket path from config or environment
        common_path = self._get_common_bucket_path(context)

        if common_path and common_path.exists():
            reports = self._scan_directory(common_path)
        else:
            # Fallback: scan local reference data directory
            local_reports = self._scan_local_reference_data()
            reports.extend(local_reports)

        return ToolResult(
            ok=True,
            result={
                "action": "list_reports",
                "reports": reports,
            },
            message=f"Found {len(reports)} threat reports",
        )

    def _summarize_report(self, payload: dict[str, Any], context: Any) -> ToolResult:
        """Generate LLM-powered summary of a threat report."""
        report_path = payload["report_path"]
        max_words = payload.get("max_word_count", 2000)
        focus_areas = payload.get("focus_areas", [])

        # Read report content
        content = self._read_report_content(report_path, context)

        if not content:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message=f"Report not found: {report_path}",
            )

        # Determine report type from extension
        report_type = self._get_report_type(report_path)
        report_name = report_path.rsplit("/", 1)[-1] if "/" in report_path else report_path

        summary_text = content
        key_findings = []
        relevant_techniques = []

        # Use LLM if available
        if context and hasattr(context, "llm_query") and context.llm_query:
            try:
                prompt = SUMMARIZATION_PROMPT_TEMPLATE.format(
                    report_name=report_name,
                    report_type=report_type,
                    max_words=max_words,
                    focus_areas=", ".join(focus_areas) if focus_areas else "General threat overview",
                    content=content[:50000],  # Limit content size
                )

                response = context.llm_query.query_text(
                    prompt=prompt,
                    max_tokens=4096,
                )

                if response.ok:
                    summary_text = response.text.strip()
                    # Extract key findings and techniques from summary
                    key_findings = self._extract_key_findings(summary_text)
                    relevant_techniques = self._extract_techniques(summary_text)
            except Exception as e:
                import logging

                logging.getLogger("eventmill.plugin.threat_report_analyzer").warning(
                    "LLM summarization failed: %s", e
                )

        word_count = len(summary_text.split())

        return ToolResult(
            ok=True,
            result={
                "action": "summarize",
                "summaries": [
                    {
                        "report_path": report_path,
                        "word_count": word_count,
                        "summary": summary_text,
                        "key_findings": key_findings,
                        "relevant_techniques": relevant_techniques,
                    }
                ],
            },
            message=f"Summarized {report_path} ({word_count} words)",
        )

    def _search_reports(self, payload: dict[str, Any], context: Any) -> ToolResult:
        """Search across threat report content."""
        query = payload["query"].lower()
        search_results = []

        # Get all reports
        reports = []
        common_path = self._get_common_bucket_path(context)

        if common_path and common_path.exists():
            reports = self._scan_directory(common_path)

        # Search each report
        for report in reports:
            report_file = report.get("path")
            if not report_file:
                continue

            try:
                if Path(report_file).exists():
                    with open(report_file, "r", encoding="utf-8", errors="replace") as f:
                        content = f.read().lower()

                    # Find matches
                    matches = []
                    for i, line in enumerate(content.split("\n"), 1):
                        if query in line:
                            matches.append(f"Line {i}: {line.strip()[:200]}")

                    if matches:
                        search_results.append(
                            {
                                "report_path": report.get("path", ""),
                                "matches": matches[:20],  # Limit matches per report
                            }
                        )
            except Exception:
                continue

        return ToolResult(
            ok=True,
            result={
                "action": "search_reports",
                "query": payload["query"],
                "search_results": search_results,
            },
            message=f"Search found {len(search_results)} reports with matches",
        )

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    def _get_common_bucket_path(self, context: Any) -> Path | None:
        """Get the common bucket path from context or environment."""
        # Try to get from context config
        if context and hasattr(context, "config"):
            config = context.config or {}
            bucket_prefix = config.get("EVENTMILL_BUCKET_PREFIX", "eventmill")
            common_bucket = f"{bucket_prefix}-common"
        else:
            bucket_prefix = os.environ.get("EVENTMILL_BUCKET_PREFIX", "eventmill")
            common_bucket = f"{bucket_prefix}-common"

        # Check if running in Cloud Run (GCS) or local
        if os.environ.get("K_SERVICE"):
            # In Cloud Run, we'd need GCS client - return None to use fallback
            return None
        else:
            # Local development: use local storage path
            workspace_path = Path.cwd() / "workspace" / "storage" / common_bucket
            return workspace_path if workspace_path.exists() else None

    def _scan_directory(self, base_path: Path) -> list[dict[str, Any]]:
        """Scan a directory for threat report files."""
        reports = []

        for ext in self.SUPPORTED_EXTENSIONS:
            for file_path in base_path.rglob(f"*{ext}"):
                if file_path.is_file():
                    try:
                        size = file_path.stat().st_size
                        reports.append(
                            {
                                "path": str(file_path),
                                "name": file_path.name,
                                "size_bytes": size,
                            }
                        )
                    except Exception:
                        continue

        return sorted(reports, key=lambda r: r["name"])

    def _scan_local_reference_data(self) -> list[dict[str, Any]]:
        """Scan local reference data directory as fallback."""
        reports = []
        ref_data_path = Path(__file__).parent.parent.parent / "framework" / "reference_data"

        if ref_data_path.exists():
            for file_path in ref_data_path.rglob("*"):
                if file_path.is_file() and file_path.suffix in self.SUPPORTED_EXTENSIONS:
                    try:
                        size = file_path.stat().st_size
                        reports.append(
                            {
                                "path": str(file_path),
                                "name": file_path.name,
                                "size_bytes": size,
                            }
                        )
                    except Exception:
                        continue

        return sorted(reports, key=lambda r: r["name"])

    def _read_report_content(self, report_path: str, context: Any) -> str | None:
        """Read content from a report file."""
        # Try direct path first
        file_path = Path(report_path)
        if file_path.exists():
            try:
                with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                    return f.read()
            except Exception:
                return None

        # Try relative to common bucket
        common_path = self._get_common_bucket_path(context)
        if common_path:
            # Handle nested paths like "mitre/attack.json"
            relative_path = report_path
            if "/" in report_path:
                # Extract just filename if full path provided
                relative_path = report_path.split("/", 1)[-1]

            file_path = common_path / relative_path
            if file_path.exists():
                try:
                    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                        return f.read()
                except Exception:
                    return None

        return None

    def _get_report_type(self, report_path: str) -> str:
        """Determine report type from path."""
        path_lower = report_path.lower()

        if "mitre" in path_lower or "attack" in path_lower:
            return "MITRE ATT&CK Framework"
        elif "capec" in path_lower:
            return "CAPEC (Common Attack Pattern Enumeration)"
        elif "cisa" in path_lower or "kev" in path_lower:
            return "CISA Advisory"
        elif "vendor" in path_lower or "msrc" in path_lower:
            return "Vendor Security Advisory"
        elif "threat_actor" in path_lower:
            return "Threat Actor Profile"
        elif "campaign" in path_lower:
            return "Threat Campaign Report"
        elif "vulnerability" in path_lower or "cve" in path_lower:
            return "Vulnerability Report"
        else:
            return "Threat Intelligence Report"

    def _extract_key_findings(self, summary: str) -> list[str]:
        """Extract key findings from summary."""
        findings = []

        # Look for bullet points or numbered items
        lines = summary.split("\n")
        for line in lines:
            line = line.strip()
            if line and (line.startswith("- ") or line.startswith("* ")):
                finding = line[2:].strip()
                if finding and len(finding) > 10:
                    findings.append(finding)
            elif line and re.match(r"^\d+[\.\)]\s", line):
                match = re.match(r"^\d+[\.\)]\s(.+)", line)
                if match:
                    findings.append(match.group(1).strip())

        return findings[:10]  # Limit to 10 findings

    def _extract_techniques(self, summary: str) -> list[str]:
        """Extract MITRE ATT&CK technique IDs from summary."""
        # Match patterns like T1234, T1566, etc.
        techniques = re.findall(r"T\d{4}(?:\.\d{3})?", summary)
        return list(set(techniques))[:20]  # Dedupe and limit
