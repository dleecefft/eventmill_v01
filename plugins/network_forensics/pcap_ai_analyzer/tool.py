"""
PCAP AI Analyzer — AI-enhanced PCAP analysis with Condition Orange support.

Ported from Event Mill v1.0 pcap_hunting.py (ai_hunt_*) and system_context.py
(PCAP prompt tiers) with improvements:
- Conforms to EventMillToolProtocol
- Three prompt tiers: triage, threat_hunt, reporting
- Condition Orange toggle modifies LLM analysis posture
- Uses LLMQueryInterface from ExecutionContext (not direct Gemini calls)
- Structured JSON output with both static and AI sections
- summarize_for_llm() for context-optimized output
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("eventmill.plugins.pcap_ai_analyzer")


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
# PCAP System Identity (shared across all prompt tiers)
# ---------------------------------------------------------------------------

PCAP_SYSTEM_IDENTITY = """SYSTEM IDENTITY:
You are an AI-powered Network Forensics Analyst working within a Security Operations Center (SOC).

CRITICAL UNDERSTANDING:
- You are analyzing PARSED metadata from network traffic captures (PCAP files).
- These are EXPORTED captures, not live traffic. You cannot interact with the network.
- Your analysis is based on statistical summaries, not raw packet payloads.
- You can only READ and ANALYZE — you CANNOT take remediation actions.

YOUR ROLE:
1. ANALYZE: Identify anomalous network patterns, suspicious flows, and potential threats.
2. CORRELATE: Connect indicators across DNS, HTTP, TLS, and flow data.
3. PRIORITIZE: Rank findings by severity with clear justification.
4. RECOMMEND: Suggest specific next steps for human analysts to execute.
"""

# ---------------------------------------------------------------------------
# Prompt templates (three tiers)
# ---------------------------------------------------------------------------

TRIAGE_PROMPT = """{system_identity}
{alert_condition}
{investigation_context}CURRENT TASK:
You are a SOC Analyst conducting initial triage on a parsed network traffic capture.

SUMMARY DATA:
{pcap_summary_data}

ANALYSIS TASKS:
1. THE BASELINE CHECK: Review the 'Top Talkers' and flow indicators. Identify anomalous patterns
   (unusual port usage, unexpected internal-to-internal communication, data exfiltration spikes).
2. C2 BEACONING HUNTER: Look for indicators of Command and Control beaconing —
   repetitive connections to external IPs, uniform payload sizes, consistent intervals
   over ports 80/443 or unusual high-numbered ports.
3. PRIORITIZATION: Rank the top 3 findings by severity (Critical/High/Medium/Low) with
   justification based on standard network baseline behavior.
4. NEXT STEPS: Recommend 2 specific next steps for the human analyst.

Keep response concise, prioritized, and action-oriented.

End with:
⚡ TL;DR
- One-line risk verdict
- Top 1-3 bullet points: most critical findings
"""

THREAT_HUNT_PROMPT = """{system_identity}
{alert_condition}
{investigation_context}CURRENT TASK:
You are a proactive Threat Hunter analyzing parsed PCAP data for advanced persistent threats (APTs)
or stealthy network intrusions.

SUMMARY DATA:
{pcap_summary_data}

ANALYSIS TASKS:
1. MITRE ATT&CK MAPPING: Map observed behavior to MITRE ATT&CK Tactics and Techniques (with IDs).
   Provide brief justification for each mapping.
2. HYPOTHESIS GENERATION: Formulate three (3) distinct hypotheses about attacker objectives
   (e.g., "Hypothesis 1: Data Exfiltration via DNS Tunneling").
3. EVIDENCE GATHERING: For each hypothesis, state what secondary logs the analyst should query
   to confirm or deny (e.g., Windows Event Logs, AD auth logs, application logs).

End with:
⚡ TL;DR
- One-line risk verdict
- Top 1-3 bullet points: most critical hypotheses and next checks
"""

REPORTING_PROMPT = """{system_identity}
{alert_condition}
{investigation_context}CURRENT TASK:
You are a Senior Incident Responder preparing documentation for the SOC.

SUMMARY DATA:
{pcap_summary_data}

ANALYSIS TASKS:
1. EXECUTIVE SUMMARY: Concise shift handover note summarizing traffic scope and critical findings.
2. INDICATORS OF COMPROMISE (IoCs): Extract all potential IoCs as:
   [Type (IP/Domain/Port)] | [Value] | [Context/Reason for suspicion]
   Exclude standard RFC 1918 IPs unless confirmed internal lateral movement source.
3. IMMEDIATE ACTIONS: Clear next steps for the incoming analyst or IR team.
4. LIMITATION CAVEATS: What cannot be determined from this parsed PCAP data alone.

Format as a professional shift-handover report.

End with:
⚡ TL;DR
- One-line risk verdict
- Top 1-3 bullet points: most urgent IOCs and immediate actions
"""

# Mode → (prompt_template, underlying_hunt_type)
MODE_CONFIG: dict[str, tuple[str, str | None]] = {
    "triage_summary": (TRIAGE_PROMPT, None),        # Uses pcap_metadata_summary
    "hunt_talkers": (TRIAGE_PROMPT, "talkers"),
    "hunt_beacons": (THREAT_HUNT_PROMPT, "beacons"),
    "hunt_dns": (THREAT_HUNT_PROMPT, "dns"),
    "hunt_tls": (THREAT_HUNT_PROMPT, "tls"),
    "hunt_lateral": (THREAT_HUNT_PROMPT, "lateral"),
    "hunt_exfil": (REPORTING_PROMPT, "exfil"),
    "report": (REPORTING_PROMPT, None),              # Uses pcap_metadata_summary
}


class PcapAiAnalyzer:
    """AI-enhanced PCAP analysis with Condition Orange support."""

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "pcap_ai_analyzer",
            "version": "1.0.0",
            "pillar": "network_forensics",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []
        mode = payload.get("mode")
        if not mode:
            errors.append("'mode' is required.")
        elif mode not in MODE_CONFIG:
            errors.append(
                f"Invalid mode '{mode}'. Must be one of: {', '.join(MODE_CONFIG.keys())}"
            )
        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(
        self,
        payload: dict[str, Any],
        context: Any,
    ) -> ToolResult:
        from plugins.network_forensics.pcap_metadata_summary.tool import get_pcap_session

        session = get_pcap_session()
        if not session:
            return ToolResult(
                ok=False,
                error_code="ARTIFACT_NOT_FOUND",
                message="No PCAP loaded. Use pcap_metadata_summary (mode=load) first.",
            )

        if not context or not hasattr(context, "llm_query") or not context.llm_query:
            return ToolResult(
                ok=False,
                error_code="LLM_UNAVAILABLE",
                message="LLM not available. pcap_ai_analyzer requires an LLM connection.",
            )

        mode = payload["mode"]
        condition_orange = payload.get("condition_orange", False)

        # Also check context.config for condition_orange (set by CLI --orange flag)
        if not condition_orange and hasattr(context, "config"):
            condition_orange = context.config.get("condition_orange", False)

        try:
            # Step 1: Get static output
            static_output = self._get_static_output(session, mode, payload)

            # Step 2: Load investigation context from any markdown/text artifact
            investigation_context = self._load_investigation_context(context)

            # Step 3: Build prompt
            prompt_template, _ = MODE_CONFIG[mode]
            alert_condition = self._get_alert_condition(condition_orange)
            prompt = prompt_template.format(
                system_identity=PCAP_SYSTEM_IDENTITY,
                alert_condition=alert_condition,
                investigation_context=investigation_context,
                pcap_summary_data=static_output,
            )

            # Pre-call token estimate:
            # PCAP summaries contain dense structured data (IPs, ports, numbers, JSON)
            # which tokenizes at ~3 chars/token vs ~4 for plain English.
            # Split prompt into template prose vs injected PCAP data for a blended estimate,
            # then apply a 1.4x correction factor — empirically calibrated against actual usage.
            pcap_data_len = len(static_output)
            prose_len = len(prompt) - pcap_data_len
            est_input_tokens = int(((prose_len // 4) + (pcap_data_len // 3)) * 1.4)
            # Output estimate: structured AI analysis responses run ~50% of input tokens
            est_output_tokens = min(int(est_input_tokens * 0.50), 4096)
            est_total_tokens = est_input_tokens + est_output_tokens
            print(
                f"\n  🔢 Token estimate: ~{est_input_tokens:,} input"
                f" + ~{est_output_tokens:,} output"
                f" = ~{est_total_tokens:,} total (pre-call)"
            )

            # Step 4: Query LLM
            response = context.llm_query.query_text(
                prompt=prompt,
                system_context=PCAP_SYSTEM_IDENTITY,
                max_tokens=4096,
            )

            # Post-call actuals — compare against estimate
            if response.token_usage:
                actual_in = response.token_usage.get("prompt_tokens", 0)
                actual_out = response.token_usage.get("completion_tokens", 0)
                actual_total = response.token_usage.get("total_tokens", actual_in + actual_out)
                accuracy = (actual_in / est_input_tokens * 100) if est_input_tokens else 0
                print(
                    f"  📊 Actual tokens: {actual_in:,} input + {actual_out:,} output"
                    f" = {actual_total:,} total"
                    f"  (estimate accuracy: {accuracy:.0f}%)"
                )

            if not response.ok:
                return ToolResult(
                    ok=True,
                    result={
                        "mode": mode,
                        "condition_orange": condition_orange,
                        "static_output": static_output,
                        "ai_analysis": None,
                        "combined_output": (
                            static_output + "\n\n[AI Analysis Failed: "
                            + (response.error or "Unknown error") + "]"
                        ),
                    },
                )

            ai_text = response.text or ""
            combined = (
                static_output
                + "\n\n" + "=" * 60 + "\n"
                + "🔍 AI ANALYSIS"
                + (" 🚨 CONDITION ORANGE" if condition_orange else "")
                + "\n" + "=" * 60 + "\n"
                + ai_text
            )

            return ToolResult(
                ok=True,
                result={
                    "mode": mode,
                    "condition_orange": condition_orange,
                    "static_output": static_output,
                    "ai_analysis": ai_text,
                    "combined_output": combined,
                },
            )

        except Exception as e:
            logger.error("AI analysis failed: %s", e, exc_info=True)
            return ToolResult(ok=False, error_code="INTERNAL_ERROR", message=str(e))

    def summarize_for_llm(self, result: ToolResult) -> str:
        if not result.ok:
            return f"pcap_ai_analyzer failed: {result.message}"

        data = result.result or {}
        # Show the full combined output (static data + AI analysis) to the user
        combined = data.get("combined_output", "")
        if combined:
            return combined

        mode = data.get("mode", "?")
        orange = " [CONDITION ORANGE]" if data.get("condition_orange") else ""
        return f"pcap_ai_analyzer {mode}{orange}: AI analysis not available."

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    @staticmethod
    def _load_investigation_context(context: Any) -> str:
        """Return an INVESTIGATION CONTEXT block if a markdown/text artifact is loaded.

        Looks for text artifacts (loaded via 'load notes.md') whose filename ends
        in .md, .markdown, or .txt.  Returns an empty string if nothing is found
        so the prompt placeholder is safely replaced with nothing.
        """
        if not context or not hasattr(context, "artifacts"):
            return ""

        md_exts = {".md", ".markdown", ".txt"}
        loaded: list[tuple[str, str]] = []  # (filename, content)
        seen_paths: set[str] = set()  # deduplicate by resolved file path

        for artifact in context.artifacts:
            if getattr(artifact, "artifact_type", "") != "text":
                continue
            file_path = getattr(artifact, "file_path", None)
            if not file_path:
                continue
            import os
            resolved = os.path.realpath(file_path)
            if resolved in seen_paths:
                continue
            seen_paths.add(resolved)
            ext = os.path.splitext(file_path)[1].lower()
            if ext not in md_exts:
                continue
            try:
                with open(file_path, "r", encoding="utf-8") as fh:
                    content = fh.read().strip()
                if content:
                    loaded.append((os.path.basename(file_path), content))
            except Exception:
                pass  # Silently skip unreadable files

        if not loaded:
            return ""

        parts = ["INVESTIGATION CONTEXT (analyst-provided notes):"]
        for filename, content in loaded:
            parts.append(f"--- {filename} ---")
            parts.append(content)
        parts.append("--- END INVESTIGATION CONTEXT ---\n")
        block = "\n".join(parts) + "\n"

        filenames = ", ".join(f for f, _ in loaded)
        print(f"  📋 Investigation context loaded: {filenames}")
        return block

    @staticmethod
    def _get_alert_condition(condition_orange: bool) -> str:
        if condition_orange:
            return (
                "\n🚨 CONDITION ORANGE ACTIVE: The organization is in a heightened state of alert. "
                "Be highly paranoid. Flag even slightly anomalous behavior as potentially malicious. "
                "Connect weak signals and assume the worst-case scenario.\n"
            )
        return (
            "\n✅ NORMAL CONDITION: Base your analysis strictly on clear evidence. "
            "Do not be overly cautious. If there is no solid evidence of a threat, state so clearly.\n"
        )

    @staticmethod
    def _get_static_output(session: Any, mode: str, payload: dict) -> str:
        """Run the underlying static analysis tool and get its text output."""
        _, hunt_type = MODE_CONFIG[mode]

        # Build PCAP context header — always included
        header = PcapAiAnalyzer._build_pcap_header(session)

        if hunt_type is None:
            # triage_summary and report modes — comprehensive overview
            return PcapAiAnalyzer._build_comprehensive_summary(session, header)

        # Hunt-specific modes — PCAP header + hunt output
        from plugins.network_forensics.pcap_threat_hunter.tool import PcapThreatHunter

        hunter = PcapThreatHunter()
        hunt_payload = {"hunt": hunt_type}
        if payload.get("hunt_payload"):
            hunt_payload.update(payload["hunt_payload"])

        result = hunter.execute(hunt_payload, None)
        hunt_text = ""
        if result.ok and result.result:
            hunt_text = result.result.get("summary_text", "No output.")
        else:
            hunt_text = f"Hunt '{hunt_type}' failed: {result.message}"

        return header + "\n\n" + hunt_text

    @staticmethod
    def _build_pcap_header(session: Any) -> str:
        """Build a PCAP context header with key metadata."""
        from plugins.network_forensics.pcap_metadata_summary.tool import is_internal, _format_bytes

        duration = session.duration_seconds
        internal_ips = [ip for ip in session.unique_ips if is_internal(ip)]
        external_ips = [ip for ip in session.unique_ips if not is_internal(ip)]

        lines = [
            "=" * 60,
            f"PCAP ANALYSIS: {session.filename}",
            "=" * 60,
            f"Size: {_format_bytes(session.file_size)} | "
            f"Packets: {session.packet_count:,} | Duration: {duration:.1f}s",
        ]
        if session.start_time:
            from datetime import datetime, timezone
            start = datetime.fromtimestamp(session.start_time, tz=timezone.utc)
            end = datetime.fromtimestamp(session.end_time, tz=timezone.utc)
            lines.append(f"Time: {start.strftime('%Y-%m-%d %H:%M:%S')} → {end.strftime('%H:%M:%S')} UTC")

        lines.append(
            f"IPs: {len(session.unique_ips)} total "
            f"({len(internal_ips)} internal, {len(external_ips)} external)"
        )

        # Protocols
        lines.append("\nProtocols:")
        for proto, count in session.protocols.most_common(10):
            pct = (count / session.packet_count * 100) if session.packet_count else 0
            lines.append(f"  {proto:<10} {count:>8,} pkts  ({pct:.1f}%)")

        lines.append(f"\nDNS: {len(session.dns_queries)} queries | "
                     f"HTTP: {len(session.http_requests)} requests | "
                     f"TLS: {len(session.tls_handshakes)} handshakes")

        return "\n".join(lines)

    @staticmethod
    def _build_comprehensive_summary(session: Any, header: str) -> str:
        """Build comprehensive summary for triage_summary and report modes."""
        from plugins.network_forensics.pcap_metadata_summary.tool import is_internal, _format_bytes
        from plugins.network_forensics.pcap_threat_hunter.tool import PcapThreatHunter

        lines = [header]

        # --- Top Talkers ---
        hunter = PcapThreatHunter()
        talkers_result = hunter.execute({"hunt": "talkers", "top_n": 15}, None)
        if talkers_result.ok and talkers_result.result:
            lines.append("\n" + talkers_result.result.get("summary_text", ""))

        # --- Top Conversations ---
        conv_list = []
        for (src, dst, dport, proto), stats in session.conversations.items():
            conv_list.append((src, dst, dport, proto, stats["bytes_out"], stats["packets"],
                              stats.get("last_seen", 0) - stats.get("first_seen", 0)))
        conv_list.sort(key=lambda c: c[4], reverse=True)

        if conv_list:
            lines.append(f"\n{'=' * 60}")
            lines.append(f"Top {min(20, len(conv_list))} Conversations (by bytes)")
            lines.append(f"{'=' * 60}")
            lines.append(
                f"{'#':<4} {'Source':<18} {'Destination':<18} {'Port':<7} {'Proto':<6} "
                f"{'Bytes':<10} {'Pkts':<8} {'Dir'}"
            )
            lines.append("-" * 80)
            for i, (src, dst, dport, proto, bytes_out, pkts, dur) in enumerate(conv_list[:20], 1):
                src_t = "INT" if is_internal(src) else "EXT"
                dst_t = "INT" if is_internal(dst) else "EXT"
                direction = f"{src_t}→{dst_t}"
                lines.append(
                    f"{i:<4} {src:<18} {dst:<18} {dport:<7} {proto:<6} "
                    f"{_format_bytes(bytes_out):<10} {pkts:<8} {direction}"
                )

        # --- Port Analysis ---
        ports_result = hunter.execute({"hunt": "ports"}, None)
        if ports_result.ok and ports_result.result:
            port_text = ports_result.result.get("summary_text", "")
            if port_text:
                lines.append(f"\n{'=' * 60}")
                lines.append("Port Analysis")
                lines.append(f"{'=' * 60}")
                lines.append(port_text)

        # --- Beaconing Check ---
        beacons_result = hunter.execute({"hunt": "beacons"}, None)
        if beacons_result.ok and beacons_result.result:
            beacon_text = beacons_result.result.get("summary_text", "")
            if beacon_text and "No C2 beaconing" not in beacon_text:
                lines.append(f"\n{'=' * 60}")
                lines.append("Beaconing Detection")
                lines.append(f"{'=' * 60}")
                lines.append(beacon_text)

        # --- DNS Summary ---
        if session.dns_queries:
            dns_result = hunter.execute({"hunt": "dns"}, None)
            if dns_result.ok and dns_result.result:
                dns_text = dns_result.result.get("summary_text", "")
                if dns_text and "No DNS anomalies" not in dns_text:
                    lines.append(f"\n{'=' * 60}")
                    lines.append("DNS Analysis")
                    lines.append(f"{'=' * 60}")
                    lines.append(dns_text)

        # --- TLS Summary ---
        if session.tls_handshakes:
            tls_result = hunter.execute({"hunt": "tls"}, None)
            if tls_result.ok and tls_result.result:
                tls_text = tls_result.result.get("summary_text", "")
                if tls_text:
                    lines.append(f"\n{'=' * 60}")
                    lines.append("TLS Analysis")
                    lines.append(f"{'=' * 60}")
                    lines.append(tls_text)

        # --- Exfil Check ---
        exfil_result = hunter.execute({"hunt": "exfil"}, None)
        if exfil_result.ok and exfil_result.result:
            exfil_text = exfil_result.result.get("summary_text", "")
            if exfil_text and "No data exfiltration" not in exfil_text:
                lines.append(f"\n{'=' * 60}")
                lines.append("Exfiltration Indicators")
                lines.append(f"{'=' * 60}")
                lines.append(exfil_text)

        # --- Lateral Movement ---
        lateral_result = hunter.execute({"hunt": "lateral"}, None)
        if lateral_result.ok and lateral_result.result:
            lateral_text = lateral_result.result.get("summary_text", "")
            if lateral_text and "No lateral movement" not in lateral_text:
                lines.append(f"\n{'=' * 60}")
                lines.append("Lateral Movement")
                lines.append(f"{'=' * 60}")
                lines.append(lateral_text)

        return "\n".join(lines)
