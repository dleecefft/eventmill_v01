"""
Zeek Log Parser — Converts Zeek JSON logs into PcapSession

Reads Zeek's JSON-format log files (conn.log, dns.log, ssl.log,
http.log, files.log, notice.log, weird.log) and populates a
PcapSession object identical to what the scapy/dpkt parsers produce.
OT/ICS protocol support:
  Parses dedicated Zeek OT analyzer logs produced by the icsnpp
  package family — modbus.log, dnp3.log, bacnet.log, s7comm.log,
  enip.log / cip.log, opcua_binary.log.  Falls back to service-field
  detection in conn.log when dedicated logs are absent.
This allows all downstream tools (pcap_threat_hunter, pcap_ai_analyzer,
pcap_ip_search, pcap_flow_analyzer, pcap_report_correlator) to work
on Zeek output with zero changes.
"""

from __future__ import annotations

import json
import logging
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("eventmill.plugins.network_forensics.zeek_loader")

# Protocol name mapping: Zeek proto field → EventMill protocol names
_PROTO_MAP = {
    "tcp": "TCP",
    "udp": "UDP",
    "icmp": "ICMP",
}

# OT/ICS service names that Zeek may identify
_OT_SERVICES = {
    "modbus", "dnp3", "bacnet", "enip", "cip", "s7comm",
    "opcua", "iec104", "goose", "mms",
}

# Modbus function code names (matches scapy/dpkt parser)
_MODBUS_FUNC_NAMES: Dict[int, str] = {
    1: "Read Coils", 2: "Read Discrete Inputs",
    3: "Read Holding Registers", 4: "Read Input Registers",
    5: "Write Single Coil", 6: "Write Single Register",
    8: "Diagnostics", 15: "Write Multiple Coils",
    16: "Write Multiple Registers", 22: "Mask Write Register",
    23: "Read/Write Multiple Registers", 43: "Read Device ID",
}
_MODBUS_WRITE_FUNCS = {5, 6, 15, 16, 22, 23}
_MODBUS_DIAG_FUNCS = {8, 43}

# DNP3 function code names
_DNP3_FUNC_NAMES: Dict[int, str] = {
    0: "Confirm", 1: "Read", 2: "Write",
    3: "Select", 4: "Operate", 5: "Direct-Operate",
    13: "Cold-Restart", 14: "Warm-Restart",
    18: "Stop-Application", 19: "Start-Application",
    129: "Response", 130: "Unsolicited-Response",
}
_DNP3_WRITE_FUNCS = {2, 3, 4, 5}
_DNP3_CONTROL_FUNCS = {5, 13, 14, 18, 19}

# S7comm PDU type names
_S7_PDU_NAMES: Dict[int, str] = {1: "Job", 2: "Ack", 3: "Ack-Data", 7: "Userdata"}
_S7_FUNC_NAMES: Dict[int, str] = {
    4: "Read", 5: "Write", 0x28: "PLC-Stop",
    0x29: "PLC-Start", 0x1A: "Upload", 0x1B: "Download",
}

# Dedicated OT log files produced by icsnpp packages
_OT_LOG_FILES = (
    "modbus.log", "modbus_detailed.log",
    "dnp3.log", "dnp3_objects.log",
    "bacnet.log",
    "s7comm.log", "s7comm_plus.log", "s7comm_read_szl.log",
    "enip.log", "cip.log", "cip_identity.log",
    "opcua_binary.log",
)


def parse_zeek_logs(log_dir: str | Path) -> "PcapSession":
    """Parse all Zeek JSON log files in a directory into a PcapSession.

    Args:
        log_dir: Directory containing Zeek .log files (JSON format).

    Returns:
        Populated PcapSession instance.
    """
    # Import PcapSession and helpers from the canonical location
    from plugins.network_forensics.pcap_metadata_summary.tool import PcapSession

    log_dir = Path(log_dir)
    session = PcapSession()
    session.filename = f"zeek:{log_dir.name}"
    session.file_path = str(log_dir)

    # Parse each log type
    conn_path = log_dir / "conn.log"
    if conn_path.exists():
        _parse_conn_log(conn_path, session)

    dns_path = log_dir / "dns.log"
    if dns_path.exists():
        _parse_dns_log(dns_path, session)

    ssl_path = log_dir / "ssl.log"
    if ssl_path.exists():
        _parse_ssl_log(ssl_path, session)

    http_path = log_dir / "http.log"
    if http_path.exists():
        _parse_http_log(http_path, session)

    notice_path = log_dir / "notice.log"
    if notice_path.exists():
        _parse_notice_log(notice_path, session)

    weird_path = log_dir / "weird.log"
    if weird_path.exists():
        _parse_weird_log(weird_path, session)

    # --- OT/ICS dedicated protocol logs (icsnpp packages) ---
    _ot_log_parsers: Dict[str, Any] = {
        "modbus.log": _parse_modbus_log,
        "modbus_detailed.log": _parse_modbus_detailed_log,
        "dnp3.log": _parse_dnp3_log,
        "bacnet.log": _parse_bacnet_log,
        "s7comm.log": _parse_s7comm_log,
        "s7comm_plus.log": _parse_s7comm_log,
        "enip.log": _parse_enip_log,
        "cip.log": _parse_cip_log,
        "cip_identity.log": _parse_cip_log,
        "opcua_binary.log": _parse_opcua_log,
    }
    ot_files_parsed: List[str] = []
    for log_name, parser_fn in _ot_log_parsers.items():
        ot_path = log_dir / log_name
        if ot_path.exists():
            parser_fn(ot_path, session)
            ot_files_parsed.append(log_name)

    if ot_files_parsed:
        logger.info("Zeek OT/ICS logs parsed: %s", ", ".join(ot_files_parsed))

    # Estimate packet count from connection metadata
    if session.packet_count == 0:
        # Sum orig_pkts + resp_pkts from conversations if we tracked them
        for conv_stats in session.conversations.values():
            session.packet_count += conv_stats.get("packets", 0)

    _ALL_KNOWN_LOGS = {
        "conn.log", "dns.log", "ssl.log", "http.log", "notice.log", "weird.log",
    } | set(_OT_LOG_FILES)
    files_parsed = [
        f.name for f in log_dir.glob("*.log")
        if f.name in _ALL_KNOWN_LOGS
    ]
    logger.info(
        "Zeek logs parsed: %d files, %d conversations, %d IPs, duration %s",
        len(files_parsed),
        len(session.conversations),
        len(session.unique_ips),
        session.duration_str,
    )

    return session


def _read_zeek_json(path: Path):
    """Yield parsed JSON objects from a Zeek JSON log file.

    Handles both Zeek's one-JSON-object-per-line format and
    lines that start with '#' (Zeek header comments in some formats).
    """
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def _ts_to_epoch(ts_val) -> float | None:
    """Convert Zeek timestamp to epoch float.

    Zeek JSON timestamps can be epoch floats or ISO strings.
    """
    if ts_val is None:
        return None
    if isinstance(ts_val, (int, float)):
        return float(ts_val)
    if isinstance(ts_val, str):
        try:
            return float(ts_val)
        except ValueError:
            pass
        # Try ISO format
        try:
            from datetime import datetime, timezone
            dt = datetime.fromisoformat(ts_val.replace("Z", "+00:00"))
            return dt.timestamp()
        except (ValueError, TypeError):
            pass
    return None


def _update_time_range(session, ts: float | None):
    """Update session start/end time bounds."""
    if ts is None:
        return
    if session.start_time is None or ts < session.start_time:
        session.start_time = ts
    if session.end_time is None or ts > session.end_time:
        session.end_time = ts


def _parse_conn_log(path: Path, session) -> None:
    """Parse conn.log — the core connection log.

    Maps to PcapSession.conversations, src/dst_ips, src/dst_ports, protocols.
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        src_ip = entry.get("id.orig_h", "")
        dst_ip = entry.get("id.resp_h", "")
        src_port = int(entry.get("id.orig_p", 0))
        dst_port = int(entry.get("id.resp_p", 0))
        proto = entry.get("proto", "tcp").lower()
        service = entry.get("service", "")

        proto_upper = _PROTO_MAP.get(proto, proto.upper())

        # Update IP counters
        if src_ip:
            session.src_ips[src_ip] += 1
        if dst_ip:
            session.dst_ips[dst_ip] += 1

        # Update port counters
        if dst_port:
            session.dst_ports[dst_port] += 1
            session.port_proto[dst_port] = proto_upper
        if src_port:
            session.src_ports[src_port] += 1

        # Protocol distribution
        session.protocols[proto_upper] += 1
        if service:
            session.protocols[service.upper()] += 1

        # Build conversation key (matches scapy/dpkt parser format)
        conv_key = (src_ip, dst_ip, dst_port, proto_upper)

        orig_bytes = int(entry.get("orig_bytes") or entry.get("orig_ip_bytes") or 0)
        resp_bytes = int(entry.get("resp_bytes") or entry.get("resp_ip_bytes") or 0)
        orig_pkts = int(entry.get("orig_pkts", 0))
        resp_pkts = int(entry.get("resp_pkts", 0))

        conv = session.conversations[conv_key]
        conv["packets"] += orig_pkts + resp_pkts
        conv["bytes_out"] += orig_bytes
        conv["bytes_in"] += resp_bytes

        if ts:
            if conv["first_seen"] is None or ts < conv["first_seen"]:
                conv["first_seen"] = ts
            if conv["last_seen"] is None or ts > conv["last_seen"]:
                conv["last_seen"] = ts

            # Timestamps for beacon detection (capped to avoid memory blow-up)
            if len(conv["timestamps"]) < 2000:
                conv["timestamps"].append(ts)

        duration = entry.get("duration")
        if duration is not None:
            try:
                conv["duration"] = float(duration)
            except (ValueError, TypeError):
                pass

        # Track connection state for threat hunting
        conn_state = entry.get("conn_state", "")
        if conn_state:
            conv["conn_state"] = conn_state

        # -----------------------------------------------------------
        # TCP health from conn.log fields (retransmit, RST, etc.)
        # -----------------------------------------------------------
        if proto == "tcp":
            # Retransmission detection from Zeek's history field:
            #   'T' = originator retransmitted, 't' = responder retransmitted
            history = entry.get("history", "")
            retx_count = history.count("T") + history.count("t")
            if retx_count > 0:
                session.tcp_retransmissions += retx_count
                session.conv_health[conv_key]["retransmit"] += retx_count

            # RST detection from conn_state:
            #   RSTO = originator sent RST, RSTR = responder sent RST
            #   Also check history for 'R'/'r'
            rst_count = history.count("R") + history.count("r")
            if rst_count > 0:
                session.tcp_rst_count += rst_count
                session.conv_health[conv_key]["rst"] += rst_count

            # SYN / FIN counting from history
            if "S" in history or "s" in history:
                session.tcp_syn_count += 1
            if "F" in history or "f" in history:
                session.tcp_fin_count += 1

            # Zero-window: Zeek doesn't track this directly, skip

        # Detect OT/ICS services
        if service and service.lower() in _OT_SERVICES:
            session.ot_transactions.append({
                "protocol": service.upper(),
                "port": dst_port,
                "src": src_ip,
                "dst": dst_ip,
                "ts": ts,
                "function_code": None,
                "description": f"Zeek-detected {service} connection",
            })

        # -----------------------------------------------------------
        # Control plane protocol detection from conn.log
        # Zeek sees OSPF/EIGRP/VRRP/HSRP as connections; we can count
        # them even though Zeek doesn't deeply parse them.
        # -----------------------------------------------------------
        proto_lower = proto.lower()

        # HSRP: UDP port 1985 or 2029
        if proto_lower == "udp" and dst_port in (1985, 2029):
            session.hsrp_hello_count += 1
            session.hsrp_events.append({
                "src": src_ip, "group": 0, "state": "Unknown",
                "priority": 0, "vip": dst_ip, "ts": ts,
            })

        # VRRP: IP protocol 112 — Zeek may log as proto="vrrp" or service="vrrp"
        if proto_lower == "vrrp" or (service and service.lower() == "vrrp"):
            session.vrrp_advert_count += 1
            session.vrrp_events.append({
                "src": src_ip, "vrid": 0,
                "priority": 0, "ts": ts,
            })

        # OSPF: IP protocol 89 — Zeek may log as proto="ospf"
        if proto_lower == "ospf" or (service and service.lower() == "ospf"):
            session.ospf_total_count += 1
            session.ospf_hello_count += 1  # best approximation
            session.ospf_router_ids.add(src_ip)
            neighbor_key = (src_ip, dst_ip)
            if ts:
                session.ospf_neighbor_hellos[neighbor_key].append(ts)

        # EIGRP: IP protocol 88 — Zeek may log as proto="eigrp"
        if proto_lower == "eigrp" or (service and service.lower() == "eigrp"):
            session.eigrp_total_count += 1
            session.eigrp_hello_count += 1  # best approximation


def _parse_dns_log(path: Path, session) -> None:
    """Parse dns.log — DNS queries and responses."""
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        query_name = entry.get("query", "")
        qtype = entry.get("qtype_name", entry.get("qtype", ""))
        rcode = entry.get("rcode_name", entry.get("rcode", ""))
        answers = entry.get("answers", [])
        src_ip = entry.get("id.orig_h", "")
        dst_ip = entry.get("id.resp_h", "")

        if query_name:
            session.dns_queries.append({
                "query": query_name,
                "type": str(qtype),
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "timestamp": ts,
            })

        if answers and isinstance(answers, list):
            for answer in answers:
                session.dns_responses.append({
                    "query": query_name,
                    "type": str(qtype),
                    "answer": str(answer),
                    "rcode": str(rcode),
                    "src_ip": dst_ip,  # DNS server responds
                    "dst_ip": src_ip,
                    "timestamp": ts,
                })


def _parse_ssl_log(path: Path, session) -> None:
    """Parse ssl.log — TLS handshake metadata."""
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        session.tls_handshakes.append({
            "src_ip": entry.get("id.orig_h", ""),
            "dst_ip": entry.get("id.resp_h", ""),
            "src_port": int(entry.get("id.orig_p", 0)),
            "dst_port": int(entry.get("id.resp_p", 0)),
            "server_name": entry.get("server_name", ""),
            "version": entry.get("version", ""),
            "cipher": entry.get("cipher", ""),
            "ja3": entry.get("ja3", ""),
            "ja3s": entry.get("ja3s", ""),
            "subject": entry.get("subject", ""),
            "issuer": entry.get("issuer", ""),
            "validation_status": entry.get("validation_status", ""),
            "timestamp": ts,
        })


def _parse_http_log(path: Path, session) -> None:
    """Parse http.log — HTTP request/response metadata."""
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        session.http_requests.append({
            "src_ip": entry.get("id.orig_h", ""),
            "dst_ip": entry.get("id.resp_h", ""),
            "src_port": int(entry.get("id.orig_p", 0)),
            "dst_port": int(entry.get("id.resp_p", 0)),
            "method": entry.get("method", ""),
            "host": entry.get("host", ""),
            "uri": entry.get("uri", ""),
            "user_agent": entry.get("user_agent", ""),
            "status_code": entry.get("status_code"),
            "content_type": entry.get("resp_mime_types", [None])[0] if isinstance(entry.get("resp_mime_types"), list) else entry.get("resp_mime_types"),
            "request_body_len": int(entry.get("request_body_len", 0)),
            "response_body_len": int(entry.get("response_body_len", 0)),
            "timestamp": ts,
        })


def _parse_notice_log(path: Path, session) -> None:
    """Parse notice.log — Zeek-generated security notices.

    These map conceptually to cleartext_creds and other anomaly detections.
    Stored as cleartext_creds entries for compatibility with threat_hunter.
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        note = entry.get("note", "")
        msg = entry.get("msg", "")
        src_ip = entry.get("src", entry.get("id.orig_h", ""))
        dst_ip = entry.get("dst", entry.get("id.resp_h", ""))

        # Cleartext password notices
        if "Password" in note or "Cleartext" in note or "HTTP::Basic" in note:
            session.cleartext_creds.append({
                "protocol": note,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "username": "[redacted by Zeek]",
                "service": entry.get("sub", ""),
                "timestamp": ts,
            })


def _parse_weird_log(path: Path, session) -> None:
    """Parse weird.log — protocol anomalies.

    Stored in a session attribute for the AI analyzer to reference.
    """
    weirdness: list[dict] = []
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        weirdness.append({
            "name": entry.get("name", ""),
            "src_ip": entry.get("id.orig_h", ""),
            "dst_ip": entry.get("id.resp_h", ""),
            "addl": entry.get("addl", ""),
            "timestamp": ts,
        })

    # Store as an extra attribute — downstream tools can check for it
    session._zeek_weird = weirdness  # type: ignore[attr-defined]
    if weirdness:
        logger.info("Parsed %d weird entries from Zeek", len(weirdness))


# ---------------------------------------------------------------------------
# OT / ICS dedicated protocol log parsers (icsnpp Zeek packages)
# ---------------------------------------------------------------------------
# Output format matches the ot_transactions entries produced by scapy/dpkt
# parsers so all downstream tools (pcap_threat_hunter, pcap_ai_analyzer)
# work identically.
# ---------------------------------------------------------------------------

def _ot_entry_base(entry: dict, protocol: str, port: int) -> Dict[str, Any]:
    """Build the base OT transaction dict matching scapy/dpkt format."""
    return {
        "protocol": protocol,
        "port": port,
        "src": entry.get("id.orig_h", ""),
        "dst": entry.get("id.resp_h", ""),
        "ts": _ts_to_epoch(entry.get("ts")),
    }


def _parse_modbus_log(path: Path, session) -> None:
    """Parse modbus.log — icsnpp-modbus Zeek package output.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    func, exception, track_address, request_len, response_len, unit_id, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "Modbus", 502)

        # Function code — icsnpp stores as string name or integer
        func_raw = entry.get("func", entry.get("function_code", ""))
        func_code: Optional[int] = None
        func_name: str = str(func_raw)

        if isinstance(func_raw, (int, float)):
            func_code = int(func_raw)
            func_name = _MODBUS_FUNC_NAMES.get(func_code, f"FC-{func_code}")
        elif isinstance(func_raw, str) and func_raw.strip():
            # icsnpp often stores the function name as a string
            func_name = func_raw
            # Try to reverse-map to a code for is_write/is_diagnostic
            for code, name in _MODBUS_FUNC_NAMES.items():
                if name.lower() == func_raw.lower().replace("_", " "):
                    func_code = code
                    break

        ot["function_code"] = func_code
        ot["function_name"] = func_name
        ot["unit_id"] = _safe_int(entry.get("unit_id"))

        # Exception detection
        exception_raw = entry.get("exception", "")
        ot["is_exception"] = bool(exception_raw and exception_raw != "-")
        if ot["is_exception"]:
            ot["exception_code"] = exception_raw

        ot["is_write"] = func_code in _MODBUS_WRITE_FUNCS if func_code else False
        ot["is_diagnostic"] = func_code in _MODBUS_DIAG_FUNCS if func_code else False

        # Register address tracking (icsnpp-modbus provides this)
        track_addr = entry.get("track_address")
        if track_addr and track_addr != "-":
            ot["register_address"] = track_addr

        if len(session.ot_transactions) < 50000:
            session.ot_transactions.append(ot)

    logger.info("Parsed Modbus log: %s", path.name)


def _parse_modbus_detailed_log(path: Path, session) -> None:
    """Parse modbus_detailed.log — register-level detail from icsnpp-modbus.

    Provides per-register read/write values. We merge notable entries
    into ot_transactions with register detail.
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "Modbus", 502)
        ot["function_code"] = _safe_int(entry.get("func", entry.get("function_code")))
        ot["function_name"] = str(entry.get("func", "detailed"))

        # Register-level detail
        ot["register_type"] = entry.get("register_type", "")
        ot["register_addr"] = _safe_int(entry.get("register_addr"))
        ot["register_value"] = entry.get("register_value")
        ot["is_write"] = ot["function_code"] in _MODBUS_WRITE_FUNCS if ot["function_code"] else False
        ot["is_diagnostic"] = False
        ot["is_exception"] = False

        if len(session.ot_transactions) < 50000:
            session.ot_transactions.append(ot)


def _parse_dnp3_log(path: Path, session) -> None:
    """Parse dnp3.log — icsnpp-dnp3 Zeek package output.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    fc_request, fc_reply, iin, obj_type, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "DNP3", 20000)

        # Function code — icsnpp-dnp3 logs fc_request / fc_reply as strings
        fc_req = entry.get("fc_request", "")
        fc_rep = entry.get("fc_reply", "")
        func_str = fc_req or fc_rep or entry.get("function_code", "")

        func_code: Optional[int] = None
        func_name: str = str(func_str) if func_str else "Unknown"

        if isinstance(func_str, (int, float)):
            func_code = int(func_str)
            func_name = _DNP3_FUNC_NAMES.get(func_code, f"FC-{func_code}")
        elif isinstance(func_str, str) and func_str.strip():
            func_name = func_str
            for code, name in _DNP3_FUNC_NAMES.items():
                if name.lower() == func_str.lower().replace("_", " ").replace("-", " "):
                    func_code = code
                    break

        ot["function_code"] = func_code
        ot["function_name"] = func_name
        ot["is_write"] = func_code in _DNP3_WRITE_FUNCS if func_code else False
        ot["is_control"] = func_code in _DNP3_CONTROL_FUNCS if func_code else False

        # IIN (Internal Indications) — important for DNP3 health
        iin = entry.get("iin")
        if iin and iin != "-":
            ot["iin"] = iin

        # Object type / count
        obj_type = entry.get("obj_type", entry.get("object_type"))
        if obj_type and obj_type != "-":
            ot["object_type"] = obj_type

        if len(session.ot_transactions) < 50000:
            session.ot_transactions.append(ot)

    logger.info("Parsed DNP3 log: %s", path.name)


def _parse_bacnet_log(path: Path, session) -> None:
    """Parse bacnet.log — icsnpp-bacnet Zeek package output.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    bvlc_function, pdu_type, pdu_service, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "BACnet", 47808)

        bvlc_func = entry.get("bvlc_function", "")
        pdu_type = entry.get("pdu_type", "")
        pdu_service = entry.get("pdu_service", "")

        func_name = pdu_service or pdu_type or bvlc_func or "Unknown"
        ot["function_name"] = func_name
        ot["function_code"] = None  # BACnet doesn't use numeric codes like Modbus
        ot["pdu_type"] = pdu_type
        ot["bvlc_function"] = bvlc_func
        ot["is_write"] = any(
            w in func_name.lower()
            for w in ("write", "create", "delete", "reinitialize")
        )
        ot["is_control"] = any(
            c in func_name.lower()
            for c in ("reinitialize", "device-communication-control", "restart")
        )

        # Object / property info
        obj_type = entry.get("object_type")
        if obj_type and obj_type != "-":
            ot["object_type"] = obj_type
        prop_id = entry.get("property_identifier", entry.get("property"))
        if prop_id and prop_id != "-":
            ot["property"] = prop_id

        if len(session.ot_transactions) < 50000:
            session.ot_transactions.append(ot)

    logger.info("Parsed BACnet log: %s", path.name)


def _parse_s7comm_log(path: Path, session) -> None:
    """Parse s7comm.log / s7comm_plus.log — icsnpp-s7comm Zeek package output.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    rosctr, pdu_type, func_code, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "S7comm", 102)

        # PDU type / ROSCTR
        rosctr = entry.get("rosctr", entry.get("pdu_type"))
        pdu_type_int = _safe_int(rosctr)
        if pdu_type_int is not None:
            ot["pdu_type"] = _S7_PDU_NAMES.get(pdu_type_int, f"0x{pdu_type_int:02x}")
        else:
            ot["pdu_type"] = str(rosctr) if rosctr else "Unknown"

        # Function code
        func_raw = entry.get("func_code", entry.get("function_code", entry.get("parameter_code")))
        func_code = _safe_int(func_raw)
        if func_code is not None:
            ot["function"] = _S7_FUNC_NAMES.get(func_code, f"0x{func_code:02x}")
            ot["function_code"] = func_code
            ot["is_write"] = func_code in (5, 0x1B)
            ot["is_control"] = func_code in (0x28, 0x29)
        else:
            func_str = str(func_raw) if func_raw else ""
            ot["function"] = func_str
            ot["function_code"] = None
            ot["is_write"] = "write" in func_str.lower() or "download" in func_str.lower()
            ot["is_control"] = "stop" in func_str.lower() or "start" in func_str.lower()

        # Sub-function / item details
        sub_func = entry.get("sub_func_code", entry.get("item_area"))
        if sub_func and sub_func != "-":
            ot["sub_function"] = sub_func

        if len(session.ot_transactions) < 50000:
            session.ot_transactions.append(ot)

    logger.info("Parsed S7comm log: %s", path.name)


def _parse_enip_log(path: Path, session) -> None:
    """Parse enip.log — icsnpp-enip Zeek package output.

    EtherNet/IP encapsulation layer.
    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    command, length, session_handle, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "EtherNet/IP-CIP", 44818)

        command = entry.get("command", entry.get("enip_command", ""))
        ot["function_name"] = str(command) if command else "Unknown"
        ot["function_code"] = _safe_int(entry.get("command_code"))
        ot["session_handle"] = entry.get("session_handle")
        ot["is_write"] = False
        ot["is_control"] = False

        if len(session.ot_transactions) < 50000:
            session.ot_transactions.append(ot)

    logger.info("Parsed ENIP log: %s", path.name)


def _parse_cip_log(path: Path, session) -> None:
    """Parse cip.log / cip_identity.log — icsnpp-enip Zeek package.

    CIP (Common Industrial Protocol) layer inside EtherNet/IP.
    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    service, cip_class_id, cip_instance_id, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "EtherNet/IP-CIP", 44818)

        service = entry.get("service", "")
        service_code = _safe_int(entry.get("service_code"))
        ot["function_name"] = str(service) if service else "Unknown"
        ot["function_code"] = service_code

        class_id = entry.get("cip_class_id", entry.get("class_id"))
        instance_id = entry.get("cip_instance_id", entry.get("instance_id"))
        if class_id and class_id != "-":
            ot["class_id"] = class_id
        if instance_id and instance_id != "-":
            ot["instance_id"] = instance_id

        ot["is_write"] = any(
            w in str(service).lower() for w in ("set", "write", "reset", "create", "delete")
        )
        ot["is_control"] = any(
            c in str(service).lower() for c in ("reset", "stop", "start", "change")
        )

        if len(session.ot_transactions) < 50000:
            session.ot_transactions.append(ot)

    logger.info("Parsed CIP log: %s", path.name)


def _parse_opcua_log(path: Path, session) -> None:
    """Parse opcua_binary.log — icsnpp-opcua-binary Zeek package.

    Fields: ts, uid, id.orig_h, id.orig_p, id.resp_h, id.resp_p,
    msg_type, msg_size, ...
    """
    for entry in _read_zeek_json(path):
        ts = _ts_to_epoch(entry.get("ts"))
        _update_time_range(session, ts)

        ot = _ot_entry_base(entry, "OPC-UA", 4840)

        msg_type = entry.get("msg_type", entry.get("opcua_msg_type", ""))
        ot["function_name"] = str(msg_type) if msg_type else "Unknown"
        ot["function_code"] = None  # OPC-UA uses message types, not numeric FCs

        service = entry.get("service", entry.get("opcua_service", ""))
        if service and service != "-":
            ot["function_name"] = str(service)

        ot["is_write"] = any(
            w in str(service).lower() for w in ("write", "create", "delete", "call")
        )
        ot["is_control"] = any(
            c in str(service).lower() for c in ("call", "transfer", "close")
        )

        if len(session.ot_transactions) < 50000:
            session.ot_transactions.append(ot)

    logger.info("Parsed OPC-UA log: %s", path.name)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_int(val) -> Optional[int]:
    """Convert a value to int, returning None on failure."""
    if val is None or val == "-" or val == "":
        return None
    try:
        return int(val)
    except (ValueError, TypeError):
        return None
