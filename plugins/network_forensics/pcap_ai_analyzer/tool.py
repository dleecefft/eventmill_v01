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
import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
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
# OT / ICS System Identity
# ---------------------------------------------------------------------------

PCAP_OT_SYSTEM_IDENTITY = """SYSTEM IDENTITY:
You are an AI-powered OT/ICS Network Forensics Analyst specializing in Industrial Control System
security within a Critical Infrastructure Security Operations Center.

CRITICAL UNDERSTANDING:
- You are analyzing PARSED metadata from network traffic captures (PCAP files) containing
  Operational Technology (OT) and Industrial Control System (ICS) protocols.
- These are EXPORTED captures, not live traffic. You cannot interact with the control network.
- Your analysis covers both IT protocols traversing the OT network AND native ICS protocols
  (Modbus/TCP, DNP3, S7comm, EtherNet/IP-CIP, OPC-UA, BACnet, IEC-104, etc.).
- OT networks have DIFFERENT baselines than IT: predictable polling cycles, fixed device roles,
  minimal DNS, rare new connections. Any deviation is significant.
- You can only READ and ANALYZE — you CANNOT take remediation actions.

YOUR ROLE:
1. ANALYZE: Identify anomalous OT protocol behavior — unauthorized writes, unexpected function
   codes, rogue devices, polling disruptions, and IT-to-OT zone crossover traffic.
2. CORRELATE: Connect indicators across ICS protocols, cleartext credentials, network flows,
   and any IT traffic on the OT segment.
3. ASSESS: Evaluate potential SAFETY IMPACT — can the observed activity affect physical
   processes (valve positions, breaker states, setpoints, safety instrumented systems)?
4. REFERENCE: Map findings to MITRE ATT&CK for ICS framework (not Enterprise).
5. RECOMMEND: Suggest specific next steps aligned with IEC 62443 zones/conduits model.

KEY OT SECURITY PRINCIPLES:
- The Purdue Model defines network segmentation levels (0-5). Traffic crossing levels
  (especially Level 3 IT → Level 1/0 control) is inherently suspicious.
- In OT, AVAILABILITY and SAFETY outweigh confidentiality. A write to a safety PLC register
  is more critical than data exfiltration.
- Many ICS protocols have NO authentication by design (Modbus, older DNP3, BACnet).
  Unauthorized access is trivial — the question is whether it happened.
- Cleartext credentials on OT networks are a severe finding — they enable lateral movement
  from IT to safety-critical systems.
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

# ---------------------------------------------------------------------------
# OT / ICS Prompt templates
# ---------------------------------------------------------------------------

OT_TRIAGE_PROMPT = """{system_identity}
{alert_condition}
{investigation_context}CURRENT TASK:
You are an OT Security Analyst conducting initial triage on a network capture from an
industrial control system (ICS) / SCADA environment.

SUMMARY DATA:
{pcap_summary_data}

ANALYSIS TASKS:
1. OT PROTOCOL BASELINE: Review ICS protocol transactions (Modbus, DNP3, S7, CIP, OPC-UA,
   BACnet, IEC-104). Identify unexpected function codes, write operations from unusual sources,
   diagnostic/restart commands, and exception responses.
2. ZONE VIOLATION CHECK: Identify any traffic crossing Purdue Model boundaries — IT subnet
   IPs communicating with control network devices, external IPs reaching ICS ports, or
   unexpected internal-to-internal OT lateral movement.
3. CREDENTIAL EXPOSURE: Review cleartext credential detections. Assess severity based on
   which protocols and which network segments are affected. Flag any credentials that could
   enable IT-to-OT pivot.
4. DEVICE INVENTORY ANOMALY: Check for rogue devices — IPs that appear as OT protocol
   sources/destinations but seem unusual (e.g., workstation IPs sending Modbus writes).
5. PRIORITIZATION: Rank the top 3 findings by severity using OT-specific criteria:
   - CRITICAL: Direct process impact risk (unauthorized writes to PLCs, safety system commands)
   - HIGH: Zone violations, credential exposure, unauthorized access to ICS protocols
   - MEDIUM: Reconnaissance activity, unusual polling patterns
   - LOW: Minor anomalies, informational
6. SAFETY ASSESSMENT: Could any observed activity lead to physical process manipulation?

End with:
⚡ TL;DR
- One-line safety/risk verdict
- Top 1-3 bullet points: most critical OT-specific findings
"""

OT_THREAT_HUNT_PROMPT = """{system_identity}
{alert_condition}
{investigation_context}CURRENT TASK:
You are an OT Threat Hunter analyzing parsed PCAP data for ICS-targeted intrusions,
state-sponsored ICS attacks (TRITON/TRISIS, Industroyer, PIPEDREAM/INCONTROLLER patterns),
or insider threats targeting operational technology.

SUMMARY DATA:
{pcap_summary_data}

ANALYSIS TASKS:
1. MITRE ATT&CK FOR ICS MAPPING: Map observed behavior to MITRE ATT&CK for ICS Tactics and
   Techniques (use ICS-specific technique IDs like T0803, T0855, T0836, etc.).
   Key tactics to evaluate:
   - Initial Access (T0819, T0886) — IT-to-OT pivot evidence
   - Execution (T0807, T0823) — Command execution on controllers
   - Inhibit Response Function (T0803, T0804, T0816) — Safety system manipulation
   - Impair Process Control (T0836, T0855) — Setpoint changes, unauthorized writes
   - Collection (T0801, T0802) — Process data gathering/reconnaissance
2. ATTACK PATTERN MATCHING: Compare observed traffic patterns against known ICS attack
   playbooks:
   - TRITON/TRISIS: Safety Instrumented System (SIS) communication anomalies
   - Industroyer: IEC-104 unauthorized commands to breaker controls
   - PIPEDREAM/INCONTROLLER: Multi-protocol reconnaissance + targeted writes
   - Stuxnet-style: Legitimate-looking writes with subtly modified values
3. HYPOTHESIS GENERATION: Formulate three (3) hypotheses about attacker objectives
   specific to OT (e.g., "Hypothesis 1: Process Disruption via Unauthorized Modbus
   Register Writes", "Hypothesis 2: Safety System Bypass via S7 PLC Stop Command").
4. EVIDENCE GAPS: What additional data sources would confirm/deny each hypothesis?
   (Engineering workstation logs, historian data, change management records, physical
   process readings)

End with:
⚡ TL;DR
- One-line safety/risk verdict
- Top 1-3 bullet points: most critical OT hypotheses and next checks
"""

OT_REPORTING_PROMPT = """{system_identity}
{alert_condition}
{investigation_context}CURRENT TASK:
You are a Senior OT Incident Responder preparing documentation for the OT Security Team
and Plant Operations.

SUMMARY DATA:
{pcap_summary_data}

ANALYSIS TASKS:
1. EXECUTIVE SUMMARY: Concise summary for both cybersecurity leadership AND plant operations
   management. Include potential SAFETY IMPACT assessment.
2. OT-SPECIFIC IoCs: Extract all potential indicators as:
   [Type] | [Value] | [OT Context/Risk]
   Include: unauthorized ICS protocol sources, suspicious function codes, write targets,
   credential exposure, zone violations.
3. PROCESS SAFETY ASSESSMENT:
   - Were any writes detected to safety-critical registers or PLCs?
   - Were any PLC stop/start/restart commands observed?
   - Were any diagnostic/firmware commands detected?
   - Could observed activity affect Safety Instrumented Systems (SIS)?
4. IMMEDIATE ACTIONS (prioritized for OT):
   - Process safety actions (verify physical process state)
   - Network containment (isolate without disrupting running processes)
   - Forensic preservation (controller backups, historian snapshots)
5. IEC 62443 COMPLIANCE: Which security levels (SL) and zones are affected?
6. LIMITATION CAVEATS: What cannot be determined from parsed PCAP alone.

Format as a professional OT incident report suitable for both CISO and Plant Manager.

End with:
⚡ TL;DR
- One-line safety verdict
- Top 1-3 bullet points: most urgent safety/security actions
"""

# Mode → (prompt_template, underlying_hunt_type, system_identity_override)
MODE_CONFIG: dict[str, tuple[str, str | None, str | None]] = {
    "triage_summary": (TRIAGE_PROMPT, None, None),
    "hunt_talkers": (TRIAGE_PROMPT, "talkers", None),
    "hunt_beacons": (THREAT_HUNT_PROMPT, "beacons", None),
    "hunt_dns": (THREAT_HUNT_PROMPT, "dns", None),
    "hunt_tls": (THREAT_HUNT_PROMPT, "tls", None),
    "hunt_lateral": (THREAT_HUNT_PROMPT, "lateral", None),
    "hunt_exfil": (REPORTING_PROMPT, "exfil", None),
    "report": (REPORTING_PROMPT, None, None),
    # OT / ICS modes
    "ot_triage": (OT_TRIAGE_PROMPT, None, PCAP_OT_SYSTEM_IDENTITY),
    "ot_threat_hunt": (OT_THREAT_HUNT_PROMPT, None, PCAP_OT_SYSTEM_IDENTITY),
    "ot_report": (OT_REPORTING_PROMPT, None, PCAP_OT_SYSTEM_IDENTITY),
}


# ---------------------------------------------------------------------------
# PDF export helper (fpdf2)
# ---------------------------------------------------------------------------

def _export_pdf(
    content: str,
    output_dir: Path,
    filename: str,
    mode: str = "",
    condition_orange: bool = False,
) -> Path | None:
    """Render report text to a PDF file using fpdf2. Returns path or None on failure."""
    try:
        from fpdf import FPDF
    except ImportError:
        print("  ⚠️  fpdf2 not installed — PDF export skipped. Install with: pip install fpdf2")
        return None

    try:
        pdf = FPDF()
        pdf.set_auto_page_break(auto=True, margin=20)
        pdf.add_page()

        # --- Title ---
        pdf.set_font("Helvetica", "B", 16)
        title = "Event Mill — PCAP AI Analysis Report"
        if mode.startswith("ot_"):
            title = "Event Mill — OT/ICS PCAP Analysis Report"
        pdf.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT", align="C")

        # Subtitle with mode and timestamp
        pdf.set_font("Helvetica", "I", 10)
        subtitle = f"Mode: {mode}"
        if condition_orange:
            subtitle += "  |  CONDITION ORANGE"
        ts_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
        subtitle += f"  |  Generated: {ts_str}"
        pdf.cell(0, 6, subtitle, new_x="LMARGIN", new_y="NEXT", align="C")
        pdf.ln(6)

        # --- Body ---
        pdf.set_font("Courier", "", 8)
        effective_width = pdf.w - pdf.l_margin - pdf.r_margin

        for line in content.split("\n"):
            # Section headers (lines starting with '=' or containing emoji headers)
            if line.startswith("====") or line.startswith("----"):
                pdf.set_font("Courier", "", 8)
                pdf.cell(0, 4, line[:120], new_x="LMARGIN", new_y="NEXT")
                continue

            if line.startswith("🔍 ") or line.startswith("⚡ "):
                pdf.set_font("Helvetica", "B", 12)
                # Strip emoji for PDF (fpdf2 built-in fonts don't support them)
                clean = line.encode("ascii", "ignore").decode("ascii").strip()
                if clean:
                    pdf.cell(0, 8, clean, new_x="LMARGIN", new_y="NEXT")
                pdf.set_font("Courier", "", 8)
                continue

            # Bold-ish markers for severity lines
            if any(marker in line for marker in ("CRITICAL", "🔴", "🟡", "⚠️")):
                pdf.set_font("Courier", "B", 8)
                clean = line.encode("ascii", "ignore").decode("ascii")
                pdf.multi_cell(effective_width, 4, clean)
                pdf.set_font("Courier", "", 8)
                continue

            # Regular line — strip non-ASCII (emoji) for built-in font compat
            clean = line.encode("ascii", "ignore").decode("ascii")
            if clean.strip():
                pdf.multi_cell(effective_width, 4, clean)
            else:
                pdf.ln(3)

        pdf_path = output_dir / filename
        pdf.output(str(pdf_path))
        print(f"  📑 PDF report saved: {pdf_path}")
        return pdf_path

    except Exception as e:
        logger.warning("PDF export failed: %s", e)
        print(f"  ⚠️  PDF export failed: {e}")
        return None


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
        is_ot_mode = mode.startswith("ot_")

        # Also check context.config for condition_orange (set by CLI --orange flag)
        if not condition_orange and hasattr(context, "config"):
            condition_orange = context.config.get("condition_orange", False)

        try:
            # Step 1: Get static output (OT modes get OT-enriched summary)
            if is_ot_mode:
                static_output = self._get_ot_static_output(session)
            else:
                static_output = self._get_static_output(session, mode, payload)

            # Step 2: Load investigation context from any markdown/text artifact
            investigation_context = self._load_investigation_context(context)

            # Step 3: Build prompt
            prompt_template, _, system_identity_override = MODE_CONFIG[mode]
            system_identity = system_identity_override or PCAP_SYSTEM_IDENTITY
            alert_condition = self._get_alert_condition(condition_orange)
            prompt = prompt_template.format(
                system_identity=system_identity,
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
            est_output_tokens = min(int(est_input_tokens * 0.50), 16384)
            est_total_tokens = est_input_tokens + est_output_tokens
            print(
                f"\n  🔢 Token estimate: ~{est_input_tokens:,} input"
                f" + ~{est_output_tokens:,} output"
                f" = ~{est_total_tokens:,} total (pre-call)"
            )

            # Step 4: Query LLM
            response = context.llm_query.query_text(
                prompt=prompt,
                system_context=system_identity,
                max_tokens=16384,
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
            mode_label = f"OT/ICS ANALYSIS" if is_ot_mode else "AI ANALYSIS"
            combined = (
                static_output
                + "\n\n" + "=" * 60 + "\n"
                + f"🔍 {mode_label}"
                + (" 🚨 CONDITION ORANGE" if condition_orange else "")
                + "\n" + "=" * 60 + "\n"
                + ai_text
            )

            # Write full output to a markdown file so it's always accessible
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            workspace = Path(os.environ.get("EVENTMILL_WORKSPACE", "./workspace"))
            output_dir = workspace / "artifacts"
            output_dir.mkdir(parents=True, exist_ok=True)
            md_filename = f"pcap_ai_analyzer_{mode}_{ts}.md"
            md_path = output_dir / md_filename
            md_path.write_text(combined, encoding="utf-8")
            print(f"  📄 Full report saved: {md_path}")

            # Optional PDF export
            export_type = payload.get("export_type", "").lower()
            pdf_path = None
            if export_type == "pdf":
                pdf_path = _export_pdf(
                    combined, output_dir,
                    f"pcap_ai_analyzer_{mode}_{ts}.pdf",
                    mode=mode,
                    condition_orange=condition_orange,
                )

            # Register the markdown file as an artifact
            if hasattr(context, "register_artifact"):
                context.register_artifact(
                    artifact_type="text",
                    file_path=str(md_path),
                    source_tool="pcap_ai_analyzer",
                    metadata={"mode": mode, "condition_orange": condition_orange},
                )
                if pdf_path:
                    context.register_artifact(
                        artifact_type="text",
                        file_path=str(pdf_path),
                        source_tool="pcap_ai_analyzer",
                        metadata={"mode": mode, "condition_orange": condition_orange, "format": "pdf"},
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
        _, hunt_type, _ = MODE_CONFIG[mode]

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
    def _get_ot_static_output(session: Any) -> str:
        """Build OT/ICS-focused static summary for OT analysis modes."""
        from plugins.network_forensics.pcap_metadata_summary.tool import (
            is_internal, _format_bytes, _OT_PORT_PROTOCOL,
            _MODBUS_FUNC_NAMES,
        )
        from plugins.network_forensics.pcap_threat_hunter.tool import PcapThreatHunter
        from collections import Counter, defaultdict

        lines = []

        # --- Standard PCAP header ---
        header = PcapAiAnalyzer._build_pcap_header(session)
        lines.append(header)

        # --- OT Protocol Summary ---
        ot = session.ot_transactions
        if ot:
            lines.append(f"\n{'=' * 60}")
            lines.append("OT / ICS PROTOCOL ACTIVITY")
            lines.append(f"{'=' * 60}")

            ot_protos = Counter(t["protocol"] for t in ot)
            lines.append(f"\nTotal OT transactions: {len(ot):,}")
            lines.append("\nProtocol breakdown:")
            for proto, cnt in ot_protos.most_common():
                lines.append(f"  {proto:<18} {cnt:>6,} transactions")

            # Unique OT endpoints
            ot_sources = set(t["src"] for t in ot)
            ot_dests = set(t["dst"] for t in ot)
            ot_endpoints = ot_sources | ot_dests
            int_ot = [ip for ip in ot_endpoints if is_internal(ip)]
            ext_ot = [ip for ip in ot_endpoints if not is_internal(ip)]
            lines.append(f"\nOT endpoints: {len(ot_endpoints)} total "
                         f"({len(int_ot)} internal, {len(ext_ot)} external)")
            if ext_ot:
                lines.append(f"  ⚠️  EXTERNAL IPs on OT protocols: {', '.join(sorted(ext_ot)[:10])}")

            # Write operations
            writes = [t for t in ot if t.get("is_write")]
            if writes:
                lines.append(f"\n🔶 WRITE OPERATIONS: {len(writes):,}")
                lines.append("-" * 60)
                write_by_src = defaultdict(list)
                for w in writes:
                    write_by_src[w["src"]].append(w)
                for src, ws in sorted(write_by_src.items(), key=lambda x: len(x[1]), reverse=True)[:15]:
                    dsts = sorted(set(w["dst"] for w in ws))
                    protos = sorted(set(w["protocol"] for w in ws))
                    func_names = sorted(set(w.get("function_name", "?") for w in ws))
                    lines.append(
                        f"  {src} → {', '.join(dsts[:5])} | "
                        f"{', '.join(protos)} | {len(ws)} writes | "
                        f"Functions: {', '.join(func_names[:5])}"
                    )

            # Control commands (PLC stop/start/restart, direct operate)
            controls = [t for t in ot if t.get("is_control")]
            if controls:
                lines.append(f"\n🔴 CONTROL COMMANDS: {len(controls):,}")
                lines.append("-" * 60)
                for c in controls[:20]:
                    func = c.get("function_name") or c.get("function", "?")
                    lines.append(
                        f"  {c['src']} → {c['dst']}:{c['port']} ({c['protocol']}) "
                        f"— {func}"
                    )

            # Exception responses
            exceptions = [t for t in ot if t.get("is_exception")]
            if exceptions:
                lines.append(f"\n⚠️  EXCEPTION RESPONSES: {len(exceptions):,}")
                lines.append("-" * 60)
                exc_by_func = Counter(
                    (t.get("function_name", "?"), t.get("exception_code", "?"))
                    for t in exceptions
                )
                for (func, exc_code), cnt in exc_by_func.most_common(10):
                    lines.append(f"  {func} exception code={exc_code} — {cnt} occurrence(s)")

            # Diagnostic/firmware commands
            diags = [t for t in ot if t.get("is_diagnostic")]
            if diags:
                lines.append(f"\n⚠️  DIAGNOSTIC COMMANDS: {len(diags):,}")
                lines.append("-" * 60)
                for d in diags[:10]:
                    func = d.get("function_name", "?")
                    lines.append(
                        f"  {d['src']} → {d['dst']}:{d['port']} ({d['protocol']}) — {func}"
                    )

            # Per-protocol function code distribution (Modbus detail)
            modbus_txns = [t for t in ot if t["protocol"] == "Modbus" and "function_code" in t]
            if modbus_txns:
                lines.append(f"\nModbus Function Code Distribution ({len(modbus_txns):,} parsed):")
                func_dist = Counter(
                    (t["function_code"], t.get("function_name", "?"))
                    for t in modbus_txns
                )
                for (fc, fname), cnt in func_dist.most_common():
                    marker = " ⚠️ WRITE" if fc in {5, 6, 15, 16, 22, 23} else ""
                    marker = " 🔴 DIAG" if fc in {8, 43} else marker
                    lines.append(f"  FC {fc:>3} ({fname:<28}) {cnt:>6,}{marker}")

            # Modbus unit IDs seen
            unit_ids = sorted(set(t.get("unit_id", -1) for t in modbus_txns if "unit_id" in t))
            if unit_ids:
                lines.append(f"\nModbus Unit IDs: {', '.join(str(u) for u in unit_ids[:30])}")

        else:
            lines.append(f"\n{'=' * 60}")
            lines.append("OT / ICS PROTOCOL ACTIVITY")
            lines.append(f"{'=' * 60}")
            lines.append("No OT/ICS protocol transactions detected in this capture.")
            lines.append("(Checked ports: " + ", ".join(
                f"{p}/{n}" for p, n in sorted(_OT_PORT_PROTOCOL.items())
            ) + ")")

        # --- Cleartext Credentials ---
        creds = session.cleartext_creds
        if creds:
            lines.append(f"\n{'=' * 60}")
            lines.append(f"⚠️  CLEARTEXT CREDENTIALS DETECTED: {len(creds)} instance(s)")
            lines.append(f"{'=' * 60}")
            cred_by_proto = defaultdict(list)
            for c in creds:
                cred_by_proto[c["protocol"]].append(c)
            for proto, detections in sorted(cred_by_proto.items(), key=lambda x: len(x[1]), reverse=True):
                src_dst_pairs = sorted(set((d["src"], d["dst"]) for d in detections))
                desc = detections[0].get("description", "")
                lines.append(
                    f"  {proto:<22} {len(detections):>4} detection(s)  — {desc}"
                )
                for src, dst in src_dst_pairs[:5]:
                    lines.append(f"    {src} → {dst}")
                if len(src_dst_pairs) > 5:
                    lines.append(f"    ... +{len(src_dst_pairs) - 5} more pairs")

        # --- Standard IT hunts (beacons, lateral, exfil) ---
        hunter = PcapThreatHunter()

        beacons_result = hunter.execute({"hunt": "beacons"}, None)
        if beacons_result.ok and beacons_result.result:
            beacon_text = beacons_result.result.get("summary_text", "")
            if beacon_text and "No C2 beaconing" not in beacon_text:
                lines.append(f"\n{'=' * 60}")
                lines.append("C2 Beaconing Detection")
                lines.append(f"{'=' * 60}")
                lines.append(beacon_text)

        lateral_result = hunter.execute({"hunt": "lateral"}, None)
        if lateral_result.ok and lateral_result.result:
            lateral_text = lateral_result.result.get("summary_text", "")
            if lateral_text and "No lateral movement" not in lateral_text:
                lines.append(f"\n{'=' * 60}")
                lines.append("Lateral Movement & ICS Cross-Zone")
                lines.append(f"{'=' * 60}")
                lines.append(lateral_text)

        ports_result = hunter.execute({"hunt": "ports"}, None)
        if ports_result.ok and ports_result.result:
            port_text = ports_result.result.get("summary_text", "")
            if port_text:
                lines.append(f"\n{'=' * 60}")
                lines.append("Port Analysis")
                lines.append(f"{'=' * 60}")
                lines.append(port_text)

        return "\n".join(lines)

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

        if session.ot_transactions:
            lines.append(f"OT/ICS: {len(session.ot_transactions):,} transactions")
        if session.cleartext_creds:
            lines.append(f"⚠️  Cleartext credentials: {len(session.cleartext_creds)} detection(s)")

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
