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
# PDF export helper (fpdf2) — professional report renderer
# ---------------------------------------------------------------------------

# Unicode → ASCII replacements for PDF rendering with built-in fonts
_PDF_UNICODE_MAP = {
    "\u2014": "--",   # em dash
    "\u2013": "-",    # en dash
    "\u2018": "'",    # left single quote
    "\u2019": "'",    # right single quote
    "\u201c": '"',    # left double quote
    "\u201d": '"',    # right double quote
    "\u2022": "*",    # bullet
    "\u2026": "...",  # ellipsis
    "\u2192": "->",   # right arrow
    "\u2190": "<-",   # left arrow
    "\u2502": "|",    # box drawing vertical
    "\u2500": "-",    # box drawing horizontal
    "\u00d7": "x",    # multiplication sign
    "\u00b7": ".",    # middle dot
    "\u2212": "-",    # minus sign
    "\u00a0": " ",    # non-breaking space
    "\u2705": "[OK]",    # check mark
    "\u274c": "[X]",     # cross mark
    "\u25cf": "*",       # black circle
    "\u25cb": "o",       # white circle
    "\u25ba": ">",       # right pointer
    "\u00ab": "<<",      # left guillemet
    "\u00bb": ">>",      # right guillemet
}

# Sections that contain dense repetitive data — truncate after N visible lines
_DATA_HEAVY_SECTIONS = {
    "INTERNAL LATERAL MOVEMENT",
    "ICS PROTOCOL CROSS-ZONE TRAFFIC",
    "PORT SCAN PATTERNS",
    "UNKNOWN HIGH PORTS",
}
_DATA_SECTION_MAX_LINES = 20  # Show at most this many data lines per section


def _pdf_safe(text: str) -> str:
    """Convert Unicode text to ASCII-safe string for PDF built-in fonts."""
    for uc, repl in _PDF_UNICODE_MAP.items():
        text = text.replace(uc, repl)
    return text.encode("ascii", "ignore").decode("ascii")


def _export_pdf(
    content: str,
    output_dir: Path,
    filename: str,
    mode: str = "",
    condition_orange: bool = False,
) -> Path | None:
    """Render a professional, executive-readable PDF report using fpdf2."""
    try:
        from fpdf import FPDF
    except ImportError:
        print("  ⚠️  fpdf2 not installed -- PDF export skipped. Install with: pip install fpdf2")
        return None

    # --- Colour palette ---
    CLR_GREY_FOOTER = (100, 100, 100)
    CLR_NAVY = (22, 42, 72)          # section header background
    CLR_DARK_SLATE = (47, 62, 80)    # sub-header background
    CLR_WHITE = (255, 255, 255)
    CLR_BLACK = (0, 0, 0)
    CLR_RED = (180, 30, 30)          # CRITICAL text
    CLR_ORANGE = (200, 100, 20)      # HIGH / warning text
    CLR_GREY = (100, 100, 100)       # secondary text
    CLR_LIGHT_GREY = (230, 230, 230) # zebra row background
    CLR_ACCENT_LINE = (22, 42, 72)   # thin accent lines

    try:
        # Subclass for automatic page footer
        class _ReportPDF(FPDF):
            def footer(self):
                self.set_y(-15)
                self.set_font("Helvetica", "I", 7)
                self.set_text_color(*CLR_GREY_FOOTER)
                self.cell(0, 4, f"Event Mill  |  Page {self.page_no()} of {{nb}}",
                          align="C")

        pdf = _ReportPDF()
        pdf.alias_nb_pages()
        pdf.set_auto_page_break(auto=True, margin=22)

        eff_w = pdf.w - pdf.l_margin - pdf.r_margin  # effective width

        # ===================================================================
        # COVER PAGE
        # ===================================================================
        pdf.add_page()
        # Navy banner at top
        pdf.set_fill_color(*CLR_NAVY)
        pdf.rect(0, 0, 210, 55, "F")

        # Title
        pdf.set_y(12)
        pdf.set_text_color(*CLR_WHITE)
        pdf.set_font("Helvetica", "B", 22)
        if mode.startswith("ot_"):
            pdf.cell(0, 10, "OT / ICS  PCAP Analysis Report", align="C",
                     new_x="LMARGIN", new_y="NEXT")
        else:
            pdf.cell(0, 10, "PCAP AI Analysis Report", align="C",
                     new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("Helvetica", "", 11)
        pdf.cell(0, 7, "Event Mill  |  Network Forensics Division", align="C",
                 new_x="LMARGIN", new_y="NEXT")

        # Condition Orange banner (if active)
        if condition_orange:
            pdf.set_y(55)
            pdf.set_fill_color(220, 80, 20)
            pdf.rect(0, 55, 210, 10, "F")
            pdf.set_font("Helvetica", "B", 11)
            pdf.set_text_color(*CLR_WHITE)
            pdf.cell(0, 10, "!! CONDITION ORANGE -- HEIGHTENED ALERT POSTURE !!", align="C",
                     new_x="LMARGIN", new_y="NEXT")

        # Meta info box
        pdf.set_y(75)
        pdf.set_text_color(*CLR_BLACK)
        pdf.set_font("Helvetica", "", 10)
        ts_str = datetime.now().strftime("%Y-%m-%d  %H:%M:%S UTC")
        mode_display = mode.replace("_", " ").upper()

        # Extract PCAP filename and key stats from the content header
        pcap_name = ""
        pcap_stats_lines: list[str] = []
        for raw_line in content.split("\n")[:30]:
            ln = raw_line.strip()
            if ln.startswith("PCAP ANALYSIS:"):
                pcap_name = ln.split(":", 1)[1].strip()
            elif ln.startswith(("Size:", "Time:", "IPs:", "DNS:")):
                pcap_stats_lines.append(ln)
            elif ln.startswith(("TCP", "UDP", "ICMP", "OTHER")):
                pcap_stats_lines.append("  " + ln)
            elif ln.startswith("Protocols:"):
                pcap_stats_lines.append(ln)
            elif ln.startswith("OT/ICS:") or "Cleartext credentials:" in ln:
                pcap_stats_lines.append(ln)

        meta_items = [
            ("Analysis Mode:", mode_display),
            ("Generated:", ts_str),
        ]
        if pcap_name:
            meta_items.insert(0, ("PCAP File:", pcap_name))

        for label, val in meta_items:
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(40, 6, label)
            pdf.set_font("Helvetica", "", 10)
            pdf.cell(0, 6, _pdf_safe(val), new_x="LMARGIN", new_y="NEXT")

        # Key stats summary
        if pcap_stats_lines:
            pdf.ln(3)
            pdf.set_draw_color(*CLR_ACCENT_LINE)
            pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
            pdf.ln(3)
            pdf.set_font("Helvetica", "B", 10)
            pdf.cell(0, 6, "Capture Summary", new_x="LMARGIN", new_y="NEXT")
            pdf.set_font("Helvetica", "", 9)
            for stat_line in pcap_stats_lines:
                pdf.cell(0, 5, _pdf_safe(stat_line), new_x="LMARGIN", new_y="NEXT")

        # Classification footer on cover
        pdf.set_y(260)
        pdf.set_draw_color(*CLR_ACCENT_LINE)
        pdf.line(pdf.l_margin, pdf.get_y(), pdf.w - pdf.r_margin, pdf.get_y())
        pdf.ln(2)
        pdf.set_font("Helvetica", "I", 8)
        pdf.set_text_color(*CLR_GREY)
        pdf.cell(0, 4, "Confidential -- For authorized security personnel only",
                 align="C", new_x="LMARGIN", new_y="NEXT")
        pdf.cell(0, 4, "Full data export available in companion .md file",
                 align="C", new_x="LMARGIN", new_y="NEXT")

        # ===================================================================
        # BODY PAGES — parse content into structured sections
        # ===================================================================

        # Helper: draw a coloured section header bar
        def _section_header(title_text: str, bg: tuple = CLR_NAVY) -> None:
            pdf.ln(4)
            pdf.set_x(pdf.l_margin)
            pdf.set_fill_color(*bg)
            pdf.set_text_color(*CLR_WHITE)
            pdf.set_font("Helvetica", "B", 11)
            pdf.cell(eff_w, 8, "  " + _pdf_safe(title_text),
                     fill=True, new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*CLR_BLACK)
            pdf.ln(2)

        # Helper: draw a sub-section header
        def _sub_header(title_text: str) -> None:
            pdf.ln(2)
            pdf.set_x(pdf.l_margin)
            pdf.set_fill_color(*CLR_DARK_SLATE)
            pdf.set_text_color(*CLR_WHITE)
            pdf.set_font("Helvetica", "B", 9)
            pdf.cell(eff_w, 6, "  " + _pdf_safe(title_text),
                     fill=True, new_x="LMARGIN", new_y="NEXT")
            pdf.set_text_color(*CLR_BLACK)
            pdf.ln(1)

        # Helper: clean markdown artifacts from text for PDF display
        def _clean_md(text: str) -> str:
            """Strip **, backticks, leading *-bullets for PDF body text."""
            t = text.replace("**", "").replace("`", "")
            # Strip leading bullet markers ("*   ", "* ", "- ")
            s = t.lstrip()
            if s.startswith("*   "):
                t = s[4:]
            elif s.startswith("* "):
                t = s[2:]
            elif s.startswith("- "):
                t = s[2:]
            return t.strip()

        # Helper: body text line — ALWAYS resets X to prevent overflow
        def _body_line(text: str, bold: bool = False, color: tuple = CLR_BLACK,
                       font_size: float = 9, indent: float = 0) -> None:
            pdf.set_text_color(*color)
            pdf.set_font("Helvetica", "B" if bold else "", font_size)
            pdf.set_x(pdf.l_margin + indent)   # always reset X
            pdf.multi_cell(0, 4.5, _pdf_safe(text))  # 0 = auto-fill to right margin

        # Helper: monospace data line (small) — ALWAYS resets X
        def _data_line(text: str, bold: bool = False) -> None:
            pdf.set_text_color(*CLR_BLACK)
            pdf.set_font("Courier", "B" if bold else "", 7)
            pdf.set_x(pdf.l_margin)             # always reset X
            pdf.multi_cell(0, 3.5, _pdf_safe(text))  # 0 = auto-fill

        # Helper: render a table with header + rows (zebra-striped)
        def _table(headers: list[str], rows: list[list[str]],
                   col_widths: list[float] | None = None,
                   font_size: float = 7.5) -> None:
            """Draw a simple table. col_widths should sum to ~eff_w."""
            if not rows:
                return
            n_cols = len(headers)
            if col_widths is None:
                col_widths = [eff_w / n_cols] * n_cols

            # Header row
            pdf.set_x(pdf.l_margin)
            pdf.set_font("Helvetica", "B", font_size)
            pdf.set_fill_color(*CLR_DARK_SLATE)
            pdf.set_text_color(*CLR_WHITE)
            for i, hdr in enumerate(headers):
                pdf.cell(col_widths[i], 5, _pdf_safe(hdr), border=0, fill=True)
            pdf.ln()

            # Data rows
            pdf.set_font("Courier", "", font_size)
            for row_idx, row in enumerate(rows):
                # Zebra striping
                if row_idx % 2 == 0:
                    pdf.set_fill_color(*CLR_LIGHT_GREY)
                    fill = True
                else:
                    fill = False
                pdf.set_x(pdf.l_margin)
                pdf.set_text_color(*CLR_BLACK)
                for i, cell_text in enumerate(row):
                    pdf.cell(col_widths[i], 4, _pdf_safe(cell_text[:50]),
                             border=0, fill=fill)
                pdf.ln()
            pdf.ln(1)

        # Helper: parse credential lines into table rows
        def _render_credential_table(lines: list[str]) -> None:
            """Parse credential section lines into a structured table."""
            cred_rows: list[list[str]] = []
            current_proto = ""
            current_count = ""
            current_desc = ""
            ip_pairs: list[str] = []

            def _flush() -> None:
                if current_proto:
                    pairs_str = "; ".join(ip_pairs[:4])
                    if len(ip_pairs) > 4:
                        pairs_str += f" (+{len(ip_pairs)-4})"
                    cred_rows.append([current_proto, current_count,
                                      current_desc, pairs_str])

            for ln in lines:
                s = ln.strip()
                if not s:
                    continue
                if "detection(s)" in s:
                    _flush()
                    ip_pairs = []
                    # Parse "LDAP-SimpleBind   308 detection(s)  -- LDAP simple bind"
                    parts = s.split()
                    current_proto = parts[0] if parts else ""
                    # Find the count (digits before "detection(s)")
                    current_count = ""
                    for p in parts[1:]:
                        if p == "detection(s)":
                            break
                        current_count = p
                    # Description after "--"
                    if "--" in s:
                        current_desc = s.split("--", 1)[1].strip()
                    else:
                        current_desc = ""
                elif "->" in s and not s.startswith("..."):
                    ip_pairs.append(s.replace("->", ">"))
                elif s.startswith("..."):
                    pass  # skip overflow markers

            _flush()

            if cred_rows:
                _table(
                    ["Protocol", "Count", "Type", "Source > Destination"],
                    cred_rows,
                    col_widths=[35, 15, 45, eff_w - 95],
                )

        # Helper: parse lateral movement lines into table rows
        def _render_lateral_table(lines: list[str], max_rows: int = 20) -> None:
            """Parse lateral movement lines into a structured table."""
            lat_rows: list[list[str]] = []
            total_sources = 0

            for ln in lines:
                s = ln.strip()
                if not s:
                    continue
                # Source line: "10.70.4.176 -> 10 targets (RDP)  SCAN?"
                if (s.startswith("10.") and "->" in s and "targets" in s):
                    total_sources += 1
                    if len(lat_rows) >= max_rows:
                        continue
                    parts = s.split("->", 1)
                    src = parts[0].strip()
                    rest = parts[1].strip() if len(parts) > 1 else ""
                    # Parse "10 targets (RDP)  SCAN?"
                    tgt_count = ""
                    proto = ""
                    flag = ""
                    tokens = rest.split()
                    if tokens:
                        tgt_count = tokens[0]
                    for t in tokens:
                        if t.startswith("(") and t.endswith(")"):
                            proto = t[1:-1]
                        elif "(" in t:
                            proto = t.split("(")[1].rstrip(")")
                        if t == "SCAN?":
                            flag = "SCAN?"
                    lat_rows.append([src, tgt_count, proto, flag])

            if lat_rows:
                _table(
                    ["Source IP", "Targets", "Protocol", "Flag"],
                    lat_rows,
                    col_widths=[45, 20, 30, 20],
                )
                if total_sources > max_rows:
                    pdf.set_font("Helvetica", "I", 7.5)
                    pdf.set_text_color(*CLR_GREY)
                    pdf.set_x(pdf.l_margin)
                    pdf.cell(0, 4,
                             f"  Showing top {max_rows} of {total_sources} sources "
                             "(see .md for complete listing)",
                             new_x="LMARGIN", new_y="NEXT")
                    pdf.set_text_color(*CLR_BLACK)

        # Helper: parse port scan lines into table rows
        def _render_scan_table(lines: list[str]) -> None:
            """Parse port scan pattern lines into a table."""
            scan_rows: list[list[str]] = []
            for ln in lines:
                s = ln.strip()
                if not s or not s[0].isdigit():
                    # Source line: "10.70.144.155 -> 108 hosts on port 5450 (5450)"
                    if s.startswith("10.") and "hosts on port" in s:
                        parts = s.split("->", 1)
                        src = parts[0].strip()
                        rest = parts[1].strip() if len(parts) > 1 else ""
                        # "108 hosts on port 5450 (5450)"
                        tokens = rest.split()
                        count = tokens[0] if tokens else ""
                        port = ""
                        svc = ""
                        if "port" in rest:
                            after_port = rest.split("port", 1)[1].strip()
                            port_tokens = after_port.split()
                            port = port_tokens[0] if port_tokens else ""
                            if len(port_tokens) > 1:
                                svc = port_tokens[1].strip("()")
                        scan_rows.append([src, count, port, svc])

            if scan_rows:
                _table(
                    ["Scanner IP", "Hosts", "Port", "Service"],
                    scan_rows,
                    col_widths=[45, 18, 18, eff_w - 81],
                )

        # --- Parse content into sections (split on ===== dividers) ---
        raw_sections: list[tuple[str, list[str]]] = []
        current_title = ""
        current_lines: list[str] = []

        for raw_line in content.split("\n"):
            stripped = raw_line.strip()
            # Detect section headers: a line of ====, then the title, then ====
            if stripped.startswith("=" * 10):
                # If we already captured a title but no content lines yet,
                # this is the closing ==== of a ====TITLE==== pair – skip it.
                if current_title and current_title != "__DIVIDER__" and not current_lines:
                    continue
                # Otherwise save any pending section
                if current_title or current_lines:
                    raw_sections.append((current_title, current_lines))
                    current_lines = []
                # Next non-empty, non-==== line is the title
                current_title = "__DIVIDER__"
                continue
            if current_title == "__DIVIDER__":
                current_title = stripped
                continue
            current_lines.append(raw_line)
        # Save final section
        if current_title or current_lines:
            raw_sections.append((current_title, current_lines))

        # --- Render each section ---
        pdf.add_page()

        for sec_title, sec_lines in raw_sections:
            if not sec_title or sec_title == "__DIVIDER__":
                # Pre-header content — already shown on cover page, skip
                continue

            # Skip the "PCAP ANALYSIS: filename" section (cover page duplicate)
            if sec_title.startswith("PCAP ANALYSIS:"):
                # But render any lines that aren't already on the cover
                non_cover = [
                    ln for ln in sec_lines if ln.strip()
                    and not ln.strip().startswith(("Size:", "Time:", "IPs:", "OT/ICS:", "Cleartext"))
                    and not ln.strip().startswith("Protocols:")
                    and not ln.strip().startswith(("TCP", "UDP", "ICMP", "OTHER", "DNS:"))
                ]
                if non_cover:
                    _section_header("Capture Details")
                    for ln in non_cover:
                        _body_line(ln.strip(), font_size=9)
                continue

            # Determine if this is a data-heavy section to truncate
            is_data_heavy = any(tag in sec_title for tag in _DATA_HEAVY_SECTIONS)
            # Identify the AI analysis section (most important)
            is_ai_section = ("AI ANALYSIS" in sec_title.upper()
                             or "OT/ICS ANALYSIS" in sec_title.upper())

            # Section header colour
            if is_ai_section:
                _section_header(sec_title, bg=(15, 82, 35))  # dark green for AI analysis
            elif "CREDENTIAL" in sec_title.upper():
                _section_header(sec_title, bg=(140, 30, 30))  # dark red for credentials
            elif "OT" in sec_title.upper() or "ICS" in sec_title.upper():
                _section_header(sec_title, bg=(130, 70, 10))  # amber for OT
            else:
                _section_header(sec_title)

            # --- Check for table-friendly sections and render as tables ---
            is_credential_section = "CREDENTIAL" in sec_title.upper()
            is_lateral_section = "LATERAL" in sec_title.upper() or "CROSS-ZONE" in sec_title.upper()

            if is_credential_section:
                _render_credential_table(sec_lines)
                continue

            if is_lateral_section:
                # Split into sub-sections by sub-header keywords
                subsections: list[tuple[str, list[str]]] = []
                cur_sub = ""
                cur_lines: list[str] = []
                for ln in sec_lines:
                    s = ln.strip()
                    if s.startswith(("INTERNAL LATERAL", "ICS PROTOCOL CROSS-ZONE",
                                     "PORT SCAN PATTERNS")):
                        if cur_sub or cur_lines:
                            subsections.append((cur_sub, cur_lines))
                        cur_sub = s
                        cur_lines = []
                        continue
                    cur_lines.append(ln)
                if cur_sub or cur_lines:
                    subsections.append((cur_sub, cur_lines))

                for sub_title, sub_lines in subsections:
                    if sub_title:
                        _sub_header(sub_title)
                    if "LATERAL" in sub_title.upper():
                        _render_lateral_table(sub_lines, max_rows=20)
                    elif "CROSS-ZONE" in sub_title.upper():
                        # Cross-zone: render as table too
                        xz_rows: list[list[str]] = []
                        for ln in sub_lines:
                            s = ln.strip()
                            if not s or s.startswith("-"):
                                continue
                            if "(INT)" in s and "(EXT)" in s:
                                # "10.70.1.75 (INT) -> 161.141.96.182 (EXT):44818 (EtherNet/IP) -- 2 pkts"
                                parts = s.split("->", 1)
                                src = parts[0].replace("(INT)", "").strip()
                                rest = parts[1].strip() if len(parts) > 1 else ""
                                # Parse dest, port, proto, pkts
                                dst_part = rest.split("--")[0].strip() if "--" in rest else rest
                                pkts = rest.split("--")[1].strip() if "--" in rest else ""
                                # "161.141.96.182 (EXT):44818 (EtherNet/IP)"
                                dst_ip = dst_part.split("(EXT)")[0].strip()
                                port_proto = dst_part.split("(EXT)")[1].strip(": ") if "(EXT)" in dst_part else ""
                                xz_rows.append([src, dst_ip, port_proto, pkts])
                        if xz_rows:
                            show = xz_rows[:20]
                            _table(
                                ["Internal IP", "External IP", "Port / Protocol", "Volume"],
                                show,
                                col_widths=[38, 38, 55, eff_w - 131],
                            )
                            if len(xz_rows) > 20:
                                pdf.set_font("Helvetica", "I", 7.5)
                                pdf.set_text_color(*CLR_GREY)
                                pdf.set_x(pdf.l_margin)
                                pdf.cell(0, 4,
                                         f"  Showing 20 of {len(xz_rows)} cross-zone flows "
                                         "(see .md for complete listing)",
                                         new_x="LMARGIN", new_y="NEXT")
                                pdf.set_text_color(*CLR_BLACK)
                    elif "SCAN" in sub_title.upper():
                        _render_scan_table(sub_lines)
                    else:
                        # Fallback: render as data lines
                        for ln in sub_lines:
                            s = ln.strip()
                            if s:
                                _data_line(s)
                continue

            # --- Port Analysis section → render as tables ---
            is_port_section = "PORT ANALYSIS" in sec_title.upper()
            if is_port_section:
                # Split into sub-sections
                port_subs: list[tuple[str, list[str]]] = []
                cur_sub_title = ""
                cur_sub_lines: list[str] = []
                for ln in sec_lines:
                    s = ln.strip()
                    if s.startswith(("STANDARD SERVICES", "ICS/SCADA PROTOCOLS",
                                     "SUSPICIOUS PORTS", "UNKNOWN HIGH PORTS")):
                        if cur_sub_title or cur_sub_lines:
                            port_subs.append((cur_sub_title, cur_sub_lines))
                        cur_sub_title = s
                        cur_sub_lines = []
                        continue
                    cur_sub_lines.append(ln)
                if cur_sub_title or cur_sub_lines:
                    port_subs.append((cur_sub_title, cur_sub_lines))

                for psub_title, psub_lines in port_subs:
                    if psub_title:
                        _sub_header(psub_title)
                    port_rows: list[list[str]] = []
                    for ln in psub_lines:
                        s = ln.strip()
                        if not s or s.startswith("-"):
                            continue
                        # "443    HTTPS   flows=160  sources=112  1.5 MB"
                        # or "502    Modbus  flows=422  sources=9"
                        tokens = s.split()
                        if tokens and tokens[0].isdigit():
                            port = tokens[0]
                            svc = tokens[1] if len(tokens) > 1 else ""
                            flows = ""
                            sources = ""
                            vol = ""
                            for t in tokens[2:]:
                                if t.startswith("flows="):
                                    flows = t.split("=")[1]
                                elif t.startswith("sources="):
                                    sources = t.split("=")[1]
                                else:
                                    vol = (vol + " " + t).strip()
                            port_rows.append([port, svc, flows, sources, vol])
                    if port_rows:
                        _table(
                            ["Port", "Service", "Flows", "Sources", "Volume"],
                            port_rows,
                            col_widths=[18, 35, 22, 22, eff_w - 97],
                        )
                continue

            # Track data lines for truncation (at section and sub-section level)
            data_line_count = 0
            truncated = False
            in_data_heavy_subsection = is_data_heavy

            for ln in sec_lines:
                stripped = ln.strip()
                if not stripped:
                    pdf.ln(2)
                    continue

                # Sub-section dividers (----)
                if stripped.startswith("-" * 10):
                    pdf.set_draw_color(*CLR_LIGHT_GREY)
                    pdf.line(pdf.l_margin, pdf.get_y(), pdf.l_margin + eff_w, pdf.get_y())
                    pdf.ln(1)
                    continue

                # Detect sub-headers (emoji prefixed or all-caps short lines)
                if stripped.startswith(("WRITE OPERATIONS", "CONTROL COMMANDS",
                                       "EXCEPTION RESPONSES", "DIAGNOSTIC COMMANDS",
                                       "STANDARD SERVICES", "ICS/SCADA PROTOCOLS",
                                       "SUSPICIOUS PORTS", "UNKNOWN HIGH PORTS",
                                       "PORT SCAN PATTERNS", "INTERNAL LATERAL",
                                       "ICS PROTOCOL CROSS-ZONE",
                                       "EXTERNAL IPs")):
                    _sub_header(stripped)
                    data_line_count = 0
                    truncated = False
                    # Check if this sub-section is data-heavy
                    in_data_heavy_subsection = any(
                        tag in stripped for tag in _DATA_HEAVY_SECTIONS
                    )
                    continue

                # Data-heavy truncation
                if in_data_heavy_subsection and not is_ai_section:
                    # Count lines that look like data (start with IP or indent)
                    if (stripped.startswith("10.") or stripped.startswith("161.")
                            or stripped.startswith("->") or stripped.startswith("...")):
                        data_line_count += 1
                        if data_line_count > _DATA_SECTION_MAX_LINES and not truncated:
                            pdf.ln(2)
                            pdf.set_font("Helvetica", "I", 8)
                            pdf.set_text_color(*CLR_GREY)
                            remaining = sum(
                                1 for x in sec_lines
                                if x.strip().startswith(("10.", "161.", "->"))
                            ) - _DATA_SECTION_MAX_LINES
                            pdf.cell(eff_w, 4,
                                     f"    ... +{remaining} more entries "
                                     "(see companion .md file for complete listing)",
                                     new_x="LMARGIN", new_y="NEXT")
                            pdf.set_text_color(*CLR_BLACK)
                            truncated = True
                            continue
                        if truncated:
                            continue

                # --- Render AI analysis content (the most important part) ---
                if is_ai_section:
                    # Numbered findings (e.g. "1. OT PROTOCOL BASELINE REVIEW:")
                    if (len(stripped) > 2 and stripped[0].isdigit()
                            and stripped[1] in ".)" and stripped[2] == " "):
                        pdf.ln(3)
                        display = _clean_md(stripped)
                        _body_line(stripped, bold=True, font_size=10,
                                   color=CLR_NAVY)
                        continue

                    # Severity markers
                    if "CRITICAL" in stripped.upper():
                        color = CLR_RED
                    elif "HIGH" in stripped.upper():
                        color = CLR_ORANGE
                    else:
                        color = CLR_BLACK

                    display = _clean_md(stripped)

                    # Bold markdown lines (**text**)
                    if stripped.startswith("**") or stripped.startswith("*   **"):
                        _body_line(display, bold=True, color=color, font_size=9,
                                   indent=4 if stripped.startswith("*") else 0)
                        continue

                    # Bullet points (* item or - item)
                    if stripped.startswith("* ") or stripped.startswith("- "):
                        _body_line(display, color=color, font_size=9, indent=6)
                        continue

                    # MITRE / IEC references (deeper indent)
                    if stripped.startswith("*   "):
                        _body_line(display, font_size=8.5, indent=10, color=CLR_GREY)
                        continue

                    # TL;DR section
                    if stripped.upper().startswith("TL;DR"):
                        pdf.ln(3)
                        _sub_header("TL;DR -- Executive Summary")
                        continue

                    _body_line(display, color=color, font_size=9)
                    continue

                # --- Standard data section rendering ---
                # Protocol summary lines (e.g. "Modbus  1,997 transactions")
                if any(stripped.startswith(p) for p in (
                    "Modbus", "EtherNet", "DNP3", "OPC", "BACnet", "S7",
                    "Total OT", "OT endpoints", "Protocol breakdown"
                )):
                    _body_line(stripped, bold=True, font_size=9)
                    continue

                # Credential detail lines
                if "detection(s)" in stripped:
                    parts = stripped.split("detection(s)")
                    _body_line(stripped, bold=True, font_size=9,
                               color=CLR_ORANGE if int(''.join(c for c in parts[0] if c.isdigit()) or "0") > 50 else CLR_BLACK)
                    continue

                # FC distribution lines (Modbus)
                if stripped.startswith("FC "):
                    is_write = "WRITE" in stripped.upper()
                    is_diag = "DIAG" in stripped.upper()
                    _data_line(
                        stripped,
                        bold=is_write or is_diag,
                    )
                    continue

                # Port analysis lines (port number + service)
                if stripped and stripped[0].isdigit() and ("flows=" in stripped or "hosts on port" in stripped):
                    _data_line(stripped)
                    continue

                # Indented data (arrow lines, IP listings)
                if stripped.startswith("->") or stripped.startswith("..."):
                    _data_line("    " + stripped)
                    continue

                # IP flow lines (10.x.x.x -> ...)
                if stripped.startswith("10.") or stripped.startswith("161."):
                    _data_line(stripped)
                    continue

                # SCAN? lines
                if "SCAN?" in stripped:
                    _body_line(stripped, bold=True, font_size=8.5, color=CLR_ORANGE)
                    continue

                # Cobalt-Strike / suspicious
                if "Cobalt" in stripped or "SUSPICIOUS" in stripped.upper():
                    _body_line(stripped, bold=True, color=CLR_RED, font_size=9)
                    continue

                # Default
                clean = _clean_md(stripped)
                if "CRITICAL" in stripped.upper():
                    _body_line(clean, color=CLR_RED, font_size=9)
                elif any(kw in stripped.upper() for kw in ("WARNING", "HIGH")):
                    _body_line(clean, color=CLR_ORANGE, font_size=9)
                else:
                    _body_line(clean, font_size=9)

        pdf_path = output_dir / filename
        pdf.output(str(pdf_path))
        print(f"  PDF report saved: {pdf_path}")
        return pdf_path

    except Exception as e:
        logger.warning("PDF export failed: %s", e)
        print(f"  PDF export failed: {e}")
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
