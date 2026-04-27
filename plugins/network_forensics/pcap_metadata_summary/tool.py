"""
PCAP Metadata Summary — Load, parse, and summarize network captures.

Faithful port of Event Mill v1.0 tools/pcap_parser.py.
All modes operate on a module-level PcapSession singleton shared
across every network-forensics plugin in the same process.
"""

from __future__ import annotations

import logging
import os
import sys
import tempfile
import ipaddress
import atexit
from collections import Counter, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("eventmill.plugins.pcap_metadata_summary")

MAX_PCAP_SIZE_BYTES = 50 * 1024 * 1024  # 50 MB

# RFC 1918 private ranges
PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]


def is_internal(ip_str: str) -> bool:
    """Check if an IP is in RFC1918 private ranges."""
    try:
        addr = ipaddress.ip_address(ip_str)
        return any(addr in net for net in PRIVATE_NETWORKS)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# Result types (match framework protocol)
# ---------------------------------------------------------------------------

from dataclasses import dataclass, field


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
# PcapSession — singleton holding ALL parsed state (matches event_mill v1)
# ---------------------------------------------------------------------------

class PcapSession:
    """Stores parsed PCAP metadata for hunt queries.

    Mirrors event_mill v1 PcapSession exactly so all downstream
    tools (threat hunter, AI analyzer, report correlator) work
    identically.
    """

    def __init__(self) -> None:
        self.filename: str = ""
        self.file_path: str = ""
        self._temp_path: Optional[str] = None
        self.file_size: int = 0
        self.packet_count: int = 0
        self.start_time: Optional[float] = None
        self.end_time: Optional[float] = None

        # Conversations: (src, dst, dport, proto) -> stats
        self.conversations: Dict[
            Tuple[str, str, int, str], Dict
        ] = defaultdict(lambda: {
            "packets": 0,
            "bytes_out": 0,
            "bytes_in": 0,
            "first_seen": None,
            "last_seen": None,
            "timestamps": [],
        })

        # Port counters
        self.dst_ports: Counter = Counter()
        self.src_ports: Counter = Counter()
        self.port_proto: Dict[int, str] = {}

        # Protocol distribution
        self.protocols: Counter = Counter()

        # DNS records
        self.dns_queries: List[Dict] = []
        self.dns_responses: List[Dict] = []

        # HTTP transactions
        self.http_requests: List[Dict] = []

        # TLS metadata
        self.tls_handshakes: List[Dict] = []

        # Unique IPs
        self.src_ips: Counter = Counter()
        self.dst_ips: Counter = Counter()

    @property
    def unique_ips(self) -> set:
        """All unique IPs seen (src + dst)."""
        return set(self.src_ips.keys()) | set(self.dst_ips.keys())

    @property
    def duration_seconds(self) -> float:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return 0.0

    @property
    def duration_str(self) -> str:
        secs = self.duration_seconds
        if secs < 60:
            return f"{secs:.1f}s"
        if secs < 3600:
            return f"{secs / 60:.1f}min"
        return f"{secs / 3600:.1f}hrs"


# ---------------------------------------------------------------------------
# Process-global session storage — survives module reimport / loader aliasing
# ---------------------------------------------------------------------------
# The plugin loader imports this file as 'eventmill_plugin_network_forensics_
# pcap_metadata_summary' while the shell imports it via the normal package path.
# A module-level global would be invisible across those two sys.modules entries.
# Storing the session on 'sys' makes it truly process-wide.

if not hasattr(sys, '_eventmill_pcap_sessions'):
    sys._eventmill_pcap_sessions = {}  # type: ignore[attr-defined]


def get_pcap_session() -> Optional[PcapSession]:
    """Return the active PcapSession (process-global)."""
    return sys._eventmill_pcap_sessions.get('active')  # type: ignore[attr-defined]


def set_pcap_session(session: Optional[PcapSession]) -> None:
    """Store the active PcapSession (process-global)."""
    sys._eventmill_pcap_sessions['active'] = session  # type: ignore[attr-defined]


def _cleanup_pcap_temp():
    """Clean up any temporary PCAP files on exit."""
    s = get_pcap_session()
    if s and getattr(s, "_temp_path", None):
        try:
            if os.path.exists(s._temp_path):
                os.unlink(s._temp_path)
        except OSError:
            pass


atexit.register(_cleanup_pcap_temp)


def _format_bytes(n: int) -> str:
    """Human-readable byte sizes."""
    if n < 1024:
        return f"{n} B"
    if n < 1024**2:
        return f"{n / 1024:.1f} KB"
    if n < 1024**3:
        return f"{n / (1024**2):.1f} MB"
    return f"{n / (1024**3):.1f} GB"


def _format_duration(secs: float) -> str:
    if secs < 60:
        return f"{secs:.1f}s"
    if secs < 3600:
        return f"{secs / 60:.1f}min"
    return f"{secs / 3600:.1f}hrs"


# ---------------------------------------------------------------------------
# Scapy import with IPv6 monkey-patch (mirrors event_mill v1)
# ---------------------------------------------------------------------------

SCAPY_AVAILABLE = False
SCAPY_TLS_AVAILABLE = False

try:
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    # Monkey-patch scapy to handle missing IPv6 'scope' key in
    # containers with limited network namespaces (Cloud Run, Docker).
    import scapy.arch
    _orig_read_routes6 = getattr(scapy.arch, "read_routes6", None)
    if _orig_read_routes6:
        def _safe_read_routes6():
            try:
                return _orig_read_routes6()
            except KeyError:
                return []
        scapy.arch.read_routes6 = _safe_read_routes6

    from scapy.utils import PcapReader
    from scapy.layers.inet import IP, TCP, UDP, ICMP
    from scapy.layers.dns import DNS, DNSQR, DNSRR
    from scapy.layers.http import HTTPRequest, HTTPResponse
    from scapy.packet import Raw
    SCAPY_AVAILABLE = True

    try:
        from scapy.layers.tls.record import TLS
        from scapy.layers.tls.handshake import TLSClientHello, TLSServerHello
        from scapy.layers.tls.extensions import ServerName
        SCAPY_TLS_AVAILABLE = True
    except Exception:
        TLS = None
        TLSClientHello = None
        TLSServerHello = None
        ServerName = None
        SCAPY_TLS_AVAILABLE = False
except Exception as e:
    logger.warning("scapy not available: %s — PCAP parsing disabled", e)


# ---------------------------------------------------------------------------
# Core parser (streaming, packet-by-packet) — identical to event_mill v1
# ---------------------------------------------------------------------------

def parse_pcap_file(file_path: str) -> PcapSession:
    """Parse a PCAP file using scapy streaming PcapReader."""
    if not SCAPY_AVAILABLE:
        raise RuntimeError("scapy is required for PCAP parsing. Install with: pip install scapy")

    session = PcapSession()
    session.filename = os.path.basename(file_path)
    session.file_path = file_path
    session.file_size = os.path.getsize(file_path)

    with PcapReader(file_path) as reader:
        for pkt in reader:
            session.packet_count += 1
            ts = float(pkt.time)

            if session.start_time is None or ts < session.start_time:
                session.start_time = ts
            if session.end_time is None or ts > session.end_time:
                session.end_time = ts

            if not pkt.haslayer(IP):
                continue

            ip_layer = pkt[IP]
            src_ip = ip_layer.src
            dst_ip = ip_layer.dst
            pkt_len = len(pkt)

            session.src_ips[src_ip] += 1
            session.dst_ips[dst_ip] += 1

            # Protocol & ports
            proto = "OTHER"
            sport = 0
            dport = 0

            if pkt.haslayer(TCP):
                proto = "TCP"
                sport = pkt[TCP].sport
                dport = pkt[TCP].dport
            elif pkt.haslayer(UDP):
                proto = "UDP"
                sport = pkt[UDP].sport
                dport = pkt[UDP].dport
            elif pkt.haslayer(ICMP):
                proto = "ICMP"

            session.protocols[proto] += 1

            if dport:
                session.dst_ports[dport] += 1
                session.port_proto[dport] = proto
            if sport:
                session.src_ports[sport] += 1

            # Conversation tracking
            conv_key = (src_ip, dst_ip, dport, proto)
            conv = session.conversations[conv_key]
            conv["packets"] += 1
            conv["bytes_out"] += pkt_len
            if conv["first_seen"] is None or ts < conv["first_seen"]:
                conv["first_seen"] = ts
            if conv["last_seen"] is None or ts > conv["last_seen"]:
                conv["last_seen"] = ts
            if len(conv["timestamps"]) < 2000:
                conv["timestamps"].append(ts)

            # DNS extraction
            if pkt.haslayer(DNS):
                dns = pkt[DNS]
                if dns.qr == 0 and pkt.haslayer(DNSQR):
                    qname = pkt[DNSQR].qname
                    if isinstance(qname, bytes):
                        qname = qname.decode("utf-8", errors="replace")
                    qname = qname.rstrip(".")
                    session.dns_queries.append({
                        "query": qname, "type": pkt[DNSQR].qtype,
                        "src": src_ip, "ts": ts,
                    })
                elif dns.qr == 1 and pkt.haslayer(DNSRR):
                    qname = ""
                    if pkt.haslayer(DNSQR):
                        qname = pkt[DNSQR].qname
                        if isinstance(qname, bytes):
                            qname = qname.decode("utf-8", errors="replace")
                        qname = qname.rstrip(".")
                    rdata = pkt[DNSRR].rdata
                    if isinstance(rdata, bytes):
                        rdata = rdata.decode("utf-8", errors="replace")
                    session.dns_responses.append({
                        "query": qname, "answer": str(rdata),
                        "type": pkt[DNSRR].type, "src": src_ip, "ts": ts,
                    })

            # HTTP extraction
            if pkt.haslayer(HTTPRequest):
                req = pkt[HTTPRequest]
                method = req.Method.decode("utf-8", errors="replace") if isinstance(req.Method, bytes) else str(req.Method)
                path = req.Path.decode("utf-8", errors="replace") if isinstance(req.Path, bytes) else str(req.Path)
                host = req.Host.decode("utf-8", errors="replace") if isinstance(req.Host, bytes) else str(req.Host)
                session.http_requests.append({
                    "method": method, "host": host, "path": path,
                    "src": src_ip, "dst": dst_ip, "ts": ts,
                })

            # TLS Client Hello extraction
            if SCAPY_TLS_AVAILABLE and pkt.haslayer(TLS):
                try:
                    if pkt.haslayer(TLSClientHello):
                        ch = pkt[TLSClientHello]
                        sni = ""
                        if hasattr(ch, "ext") and ch.ext:
                            for ext in ch.ext:
                                if hasattr(ext, "servernames"):
                                    for sn in ext.servernames:
                                        name = sn.servername
                                        if isinstance(name, bytes):
                                            name = name.decode("utf-8", errors="replace")
                                        sni = name
                                        break
                        session.tls_handshakes.append({
                            "type": "ClientHello", "sni": sni,
                            "src": src_ip, "dst": dst_ip,
                            "dport": dport, "ts": ts,
                        })
                except Exception:
                    pass

    return session


# ---------------------------------------------------------------------------
# GCS download helper
# ---------------------------------------------------------------------------

def _get_bucket_name(context: Any, pillar_slug: str) -> Optional[str]:
    """Derive bucket name from context config or env."""
    prefix = os.environ.get("EVENTMILL_BUCKET_PREFIX", "eventmill")
    return f"{prefix}-{pillar_slug}"


def _download_from_gcs(file_path: str, context: Any) -> Optional[str]:
    """Try to download a file from GCS. Returns local path or None."""
    try:
        from google.cloud import storage as gcs_storage
    except ImportError:
        return None

    client = gcs_storage.Client()
    filename = os.path.basename(file_path)

    # Try pillar bucket first, then common bucket
    prefix = os.environ.get("EVENTMILL_BUCKET_PREFIX", "eventmill")
    buckets_to_try = [f"{prefix}-network-forensics", f"{prefix}-common"]
    if file_path.startswith("gs://"):
        parts = file_path.replace("gs://", "").split("/", 1)
        buckets_to_try = [parts[0]]
        filename = parts[1] if len(parts) > 1 else parts[0]

    for bucket_name in buckets_to_try:
        try:
            bucket = client.bucket(bucket_name)
            blob = bucket.blob(filename)
            if not blob.exists():
                continue
            blob.reload()
            if blob.size and blob.size > MAX_PCAP_SIZE_BYTES:
                logger.warning("File %s too large (%s)", filename, _format_bytes(blob.size))
                return None
            tmp = tempfile.NamedTemporaryFile(suffix=".pcap", delete=False)
            blob.download_to_filename(tmp.name)
            tmp.close()
            logger.info("Downloaded %s from gs://%s/%s", filename, bucket_name, filename)
            return tmp.name
        except Exception as exc:
            logger.debug("Bucket %s: %s", bucket_name, exc)
            continue

    return None


# ---------------------------------------------------------------------------
# File resolution (filesystem → artifact registry → workspace → GCS)
# ---------------------------------------------------------------------------

def _resolve_file(file_path: str, context: Any) -> Optional[str]:
    """Resolve a file path through multiple fallback layers."""
    # 1. Direct filesystem
    if os.path.exists(file_path):
        return file_path

    filename = os.path.basename(file_path)

    # 2. Artifact registry
    if hasattr(context, "artifacts"):
        for art in context.artifacts:
            if os.path.basename(art.file_path) == filename and os.path.exists(art.file_path):
                return art.file_path

    # 3. Workspace artifacts directory
    workspace = os.environ.get("EVENTMILL_WORKSPACE", "/workspace")
    candidates = [
        os.path.join(workspace, "artifacts", filename),
        os.path.join(workspace, filename),
    ]
    for cand in candidates:
        if os.path.exists(cand):
            return cand

    # 4. GCS download
    local = _download_from_gcs(file_path, context)
    if local:
        return local

    return None


# =========================================================================
# EventMillToolProtocol implementation
# =========================================================================

class PcapMetadataSummary:
    """Load, parse, and summarize PCAP network captures.

    Modes: load, summary, conversations, dns, http, tls, timeline, ioc
    """

    def metadata(self) -> dict[str, Any]:
        return {
            "tool_name": "pcap_metadata_summary",
            "version": "1.0.0",
            "pillar": "network_forensics",
            "description": "Load, parse, and summarize PCAP network captures.",
        }

    def validate_inputs(self, payload: dict[str, Any]) -> ValidationResult:
        errors: list[str] = []
        mode = payload.get("mode", "load")
        valid_modes = ("load", "summary", "conversations", "dns", "http", "tls", "timeline", "ioc")
        if mode not in valid_modes:
            errors.append(f"Invalid mode '{mode}'. Must be one of: {', '.join(valid_modes)}")
        if mode == "load" and "file_path" not in payload:
            errors.append("'file_path' is required for load mode")
        elif mode not in ("load",):
            if get_pcap_session() is None:
                errors.append(f"No PCAP loaded. Use mode 'load' first before '{mode}'.")
        if errors:
            return ValidationResult(ok=False, errors=errors)
        return ValidationResult(ok=True)

    def execute(self, payload: dict[str, Any], context: Any) -> ToolResult:
        mode = payload.get("mode", "load")
        try:
            if mode == "load":
                return self._load_pcap(payload, context)
            elif mode == "summary":
                return self._summary()
            elif mode == "conversations":
                return self._conversations(payload)
            elif mode == "dns":
                return self._dns_summary(payload)
            elif mode == "http":
                return self._http_summary(payload)
            elif mode == "tls":
                return self._tls_summary()
            elif mode == "timeline":
                return self._timeline(payload)
            elif mode == "ioc":
                return self._ioc_search(payload)
            else:
                return ToolResult(ok=False, error_code="INVALID_MODE", message=f"Unknown mode: {mode}")
        except Exception as e:
            logger.error("PCAP error: %s", e, exc_info=True)
            return ToolResult(ok=False, error_code="EXECUTION_ERROR", message=str(e))

    def summarize_for_llm(self, result: ToolResult) -> str:
        if not result.ok:
            return f"Error: {result.message}"
        if not result.result:
            return "No result data."
        return result.result.get("text", str(result.result))

    # ----- load -----
    def _load_pcap(self, payload: dict[str, Any], context: Any) -> ToolResult:
        if not SCAPY_AVAILABLE:
            return ToolResult(ok=False, error_code="MISSING_DEP", message="scapy not installed")

        file_path = payload["file_path"]
        resolved = _resolve_file(file_path, context)
        if not resolved:
            return ToolResult(ok=False, error_code="FILE_NOT_FOUND", message=f"File not found: {file_path}")

        fsize = os.path.getsize(resolved)
        if fsize > MAX_PCAP_SIZE_BYTES:
            return ToolResult(ok=False, error_code="FILE_TOO_LARGE", message=f"File ({_format_bytes(fsize)}) exceeds 50 MB limit")

        # Clean up previous temp
        old = get_pcap_session()
        if old and getattr(old, "_temp_path", None):
            try:
                if os.path.exists(old._temp_path):
                    os.unlink(old._temp_path)
            except OSError:
                pass

        set_pcap_session(parse_pcap_file(resolved))

        s = get_pcap_session()
        lines = []
        lines.append("✅ PCAP Loaded Successfully")
        lines.append("")
        lines.append(f"  File:      {s.filename}")
        lines.append(f"  Size:      {_format_bytes(s.file_size)}")
        lines.append(f"  Packets:   {s.packet_count:,}")
        lines.append(f"  Duration:  {s.duration_str}")
        if s.start_time:
            t0 = datetime.utcfromtimestamp(s.start_time)
            t1 = datetime.utcfromtimestamp(s.end_time)
            lines.append(f"  Time:      {t0:%Y-%m-%d %H:%M:%S} → {t1:%H:%M:%S} UTC")
        lines.append(f"  Unique Src IPs:  {len(s.src_ips)}")
        lines.append(f"  Unique Dst IPs:  {len(s.dst_ips)}")
        lines.append("")
        lines.append("  Protocols:")
        for proto, cnt in s.protocols.most_common(10):
            lines.append(f"    {proto:<8} {cnt:>8,} packets")
        lines.append("")
        lines.append(f"  Conversations:   {len(s.conversations):,}")
        lines.append(f"  DNS queries:     {len(s.dns_queries):,}")
        lines.append(f"  HTTP requests:   {len(s.http_requests):,}")
        lines.append(f"  TLS handshakes:  {len(s.tls_handshakes):,}")

        return ToolResult(ok=True, result={"text": "\n".join(lines)})

    # ----- summary -----
    def _summary(self) -> ToolResult:
        s = get_pcap_session()
        lines = []
        lines.append("=== PCAP Summary ===")
        lines.append(f"  File:      {s.filename}")
        lines.append(f"  Size:      {_format_bytes(s.file_size)}")
        lines.append(f"  Packets:   {s.packet_count:,}")
        lines.append(f"  Duration:  {s.duration_str}")
        if s.start_time:
            t0 = datetime.utcfromtimestamp(s.start_time)
            t1 = datetime.utcfromtimestamp(s.end_time)
            lines.append(f"  Time:      {t0:%Y-%m-%d %H:%M:%S} → {t1:%H:%M:%S} UTC")
        lines.append("")
        lines.append("  Protocols:")
        for proto, cnt in s.protocols.most_common(10):
            pct = cnt / s.packet_count * 100 if s.packet_count else 0
            lines.append(f"    {proto:<8} {cnt:>8,} pkts  ({pct:.1f}%)")
        lines.append("")
        lines.append(f"  Unique Src IPs:    {len(s.src_ips)}")
        lines.append(f"  Unique Dst IPs:    {len(s.dst_ips)}")
        lines.append(f"  Conversations:     {len(s.conversations):,}")
        lines.append(f"  DNS queries:       {len(s.dns_queries):,}")
        lines.append(f"  HTTP requests:     {len(s.http_requests):,}")
        lines.append(f"  TLS handshakes:    {len(s.tls_handshakes):,}")
        return ToolResult(ok=True, result={"text": "\n".join(lines)})

    # ----- conversations -----
    def _conversations(self, payload: dict[str, Any]) -> ToolResult:
        s = get_pcap_session()
        top_n = payload.get("top_n", 20)
        sort_by = payload.get("sort_by", "bytes")

        convs = []
        for (src, dst, dport, proto), stats in s.conversations.items():
            duration = 0
            if stats["first_seen"] and stats["last_seen"]:
                duration = stats["last_seen"] - stats["first_seen"]
            convs.append({
                "src": src, "dst": dst, "dport": dport, "proto": proto,
                "packets": stats["packets"], "bytes_out": stats["bytes_out"],
                "first": stats["first_seen"], "last": stats["last_seen"],
                "duration": duration,
            })

        if sort_by == "packets":
            convs.sort(key=lambda c: c["packets"], reverse=True)
        elif sort_by == "duration":
            convs.sort(key=lambda c: c["duration"], reverse=True)
        else:
            convs.sort(key=lambda c: c["bytes_out"], reverse=True)

        lines = []
        lines.append(f"=== Top {top_n} Conversations (by {sort_by}) ===")
        lines.append(f"{'#':<4} {'Source':<18} {'Destination':<18} {'Port':<7} {'Proto':<6} {'Bytes':<10} {'Pkts':<8} {'Duration':<10} {'Dir'}")
        lines.append("-" * 95)
        for i, c in enumerate(convs[:top_n], 1):
            src_int = "INT" if is_internal(c["src"]) else "EXT"
            dst_int = "INT" if is_internal(c["dst"]) else "EXT"
            direction = f"{src_int}→{dst_int}"
            dur = f"{c['duration']:.1f}s" if c["duration"] < 60 else f"{c['duration'] / 60:.1f}m"
            lines.append(f"{i:<4} {c['src']:<18} {c['dst']:<18} {c['dport']:<7} {c['proto']:<6} {_format_bytes(c['bytes_out']):<10} {c['packets']:<8,} {dur:<10} {direction}")
        return ToolResult(ok=True, result={"text": "\n".join(lines)})

    # ----- dns -----
    def _dns_summary(self, payload: dict[str, Any]) -> ToolResult:
        s = get_pcap_session()
        top_n = payload.get("top_n", 30)

        if not s.dns_queries and not s.dns_responses:
            return ToolResult(ok=True, result={"text": "No DNS activity found in PCAP."})

        domain_counts: Counter = Counter()
        domain_sources: Dict[str, set] = defaultdict(set)
        for q in s.dns_queries:
            domain_counts[q["query"]] += 1
            domain_sources[q["query"]].add(q["src"])

        domain_answers: Dict[str, set] = defaultdict(set)
        for r in s.dns_responses:
            if r["query"]:
                domain_answers[r["query"]].add(r["answer"])

        lines = []
        lines.append(f"=== DNS Activity ({len(s.dns_queries)} queries, {len(s.dns_responses)} responses) ===")
        lines.append(f"{'#':<4} {'Domain':<40} {'Queries':<9} {'Sources':<9} {'Resolved To'}")
        lines.append("-" * 90)
        for i, (domain, cnt) in enumerate(domain_counts.most_common(top_n), 1):
            sources = len(domain_sources[domain])
            answers = ", ".join(list(domain_answers.get(domain, set()))[:3])
            if len(domain_answers.get(domain, set())) > 3:
                answers += "..."
            lines.append(f"{i:<4} {domain:<40} {cnt:<9} {sources:<9} {answers}")
        return ToolResult(ok=True, result={"text": "\n".join(lines)})

    # ----- http -----
    def _http_summary(self, payload: dict[str, Any]) -> ToolResult:
        s = get_pcap_session()
        top_n = payload.get("top_n", 30)

        if not s.http_requests:
            return ToolResult(ok=True, result={"text": "No HTTP requests found in PCAP."})

        lines = []
        lines.append(f"=== HTTP Requests ({len(s.http_requests)} total) ===")
        lines.append(f"{'#':<4} {'Time':<12} {'Source':<18} {'Method':<8} {'Host':<30} {'Path'}")
        lines.append("-" * 100)
        for i, req in enumerate(s.http_requests[:top_n], 1):
            ts = datetime.utcfromtimestamp(req["ts"])
            lines.append(f"{i:<4} {ts:%H:%M:%S}    {req['src']:<18} {req['method']:<8} {req['host']:<30} {req['path'][:50]}")
        if len(s.http_requests) > top_n:
            lines.append(f"\n... {len(s.http_requests) - top_n} more requests not shown")
        return ToolResult(ok=True, result={"text": "\n".join(lines)})

    # ----- tls -----
    def _tls_summary(self) -> ToolResult:
        s = get_pcap_session()
        if not s.tls_handshakes:
            return ToolResult(ok=True, result={"text": "No TLS handshakes found in PCAP."})

        sni_counts: Counter = Counter()
        no_sni = []
        sni_details: Dict[str, List] = defaultdict(list)
        for th in s.tls_handshakes:
            sni = th.get("sni", "")
            if sni:
                sni_counts[sni] += 1
                sni_details[sni].append(th)
            else:
                no_sni.append(th)

        lines = []
        lines.append(f"=== TLS Analysis ({len(s.tls_handshakes)} handshakes) ===")
        if no_sni:
            lines.append(f"\n🟡 TLS WITHOUT SNI — {len(no_sni)} connection(s)")
            lines.append("-" * 60)
            seen = set()
            for th in no_sni[:20]:
                key = (th["src"], th["dst"], th["dport"])
                if key not in seen:
                    seen.add(key)
                    dst_loc = "INT" if is_internal(th["dst"]) else "EXT"
                    lines.append(f"  {th['src']} → {th['dst']}:{th['dport']} ({dst_loc})")
        lines.append("\n=== TLS Server Names (SNI) ===")
        lines.append(f"{'#':<4} {'SNI':<45} {'Count':<8} {'Dest IPs'}")
        lines.append("-" * 80)
        for i, (sni, cnt) in enumerate(sni_counts.most_common(30), 1):
            dst_ips = set(th["dst"] for th in sni_details[sni])
            ips_str = ", ".join(list(dst_ips)[:3])
            if len(dst_ips) > 3:
                ips_str += "..."
            lines.append(f"{i:<4} {sni:<45} {cnt:<8} {ips_str}")
        return ToolResult(ok=True, result={"text": "\n".join(lines)})

    # ----- timeline -----
    def _timeline(self, payload: dict[str, Any]) -> ToolResult:
        s = get_pcap_session()
        ip_address = payload.get("ip_address", "")
        top_n = payload.get("top_n", 50)

        events = []
        for (src, dst, dport, proto), stats in s.conversations.items():
            if ip_address and ip_address not in (src, dst):
                continue
            if stats["first_seen"]:
                events.append({
                    "ts": stats["first_seen"], "type": "CONN",
                    "detail": f"{src} → {dst}:{dport}/{proto} ({stats['packets']} pkts, {_format_bytes(stats['bytes_out'])})",
                })
        for q in s.dns_queries:
            if ip_address and q["src"] != ip_address:
                continue
            events.append({"ts": q["ts"], "type": "DNS", "detail": f"{q['src']} queried {q['query']}"})
        for req in s.http_requests:
            if ip_address and req["src"] != ip_address:
                continue
            events.append({"ts": req["ts"], "type": "HTTP", "detail": f"{req['src']} → {req['method']} {req['host']}{req['path'][:40]}"})

        events.sort(key=lambda e: e["ts"])
        title = f"=== Timeline for {ip_address} ===" if ip_address else "=== Network Timeline ==="
        lines = [title, f"{'Time':<12} {'Type':<6} {'Detail'}", "-" * 80]
        for ev in events[:top_n]:
            ts = datetime.utcfromtimestamp(ev["ts"])
            lines.append(f"{ts:%H:%M:%S}    {ev['type']:<6} {ev['detail']}")
        if len(events) > top_n:
            lines.append(f"\n... {len(events) - top_n} more events not shown")
        return ToolResult(ok=True, result={"text": "\n".join(lines)})

    # ----- ioc -----
    def _ioc_search(self, payload: dict[str, Any]) -> ToolResult:
        s = get_pcap_session()
        indicator = payload.get("indicator", "")
        if not indicator:
            return ToolResult(ok=False, error_code="MISSING_PARAM", message="'indicator' required for ioc mode")

        results = []

        # Port?
        try:
            port = int(indicator)
            cnt = s.dst_ports.get(port, 0)
            if cnt:
                results.append(f"Port {port}: {cnt} connections as destination")
                for (src, dst, dport, proto), stats in s.conversations.items():
                    if dport == port:
                        results.append(f"  {src} → {dst}:{dport}/{proto} ({stats['packets']} pkts, {_format_bytes(stats['bytes_out'])})")
            else:
                results.append(f"Port {port}: not found in PCAP")
            return ToolResult(ok=True, result={"text": "\n".join(results)})
        except ValueError:
            pass

        # IP?
        if indicator.count(".") == 3:
            found = False
            src_cnt = s.src_ips.get(indicator, 0)
            dst_cnt = s.dst_ips.get(indicator, 0)
            if src_cnt or dst_cnt:
                found = True
                loc = "Internal" if is_internal(indicator) else "External"
                results.append(f"IP {indicator} ({loc}):")
                results.append(f"  As source: {src_cnt:,} packets")
                results.append(f"  As destination: {dst_cnt:,} packets")
                results.append("")
                results.append("  Conversations:")
                for (src, dst, dport, proto), stats in s.conversations.items():
                    if indicator in (src, dst):
                        results.append(f"    {src} → {dst}:{dport}/{proto}  {stats['packets']} pkts  {_format_bytes(stats['bytes_out'])}")
            for r in s.dns_responses:
                if r["answer"] == indicator:
                    results.append(f"  DNS: {r['query']} → {indicator}")
                    found = True
            if not found:
                results.append(f"IP {indicator}: not found in PCAP")
            return ToolResult(ok=True, result={"text": "\n".join(results)})

        # Domain
        indicator_lower = indicator.lower()
        found = False
        for q in s.dns_queries:
            if indicator_lower in q["query"].lower():
                if not found:
                    results.append(f"Domain matching '{indicator}':")
                    found = True
                results.append(f"  DNS query: {q['query']} from {q['src']}")
        for r in s.dns_responses:
            if indicator_lower in r["query"].lower():
                results.append(f"  DNS answer: {r['query']} → {r['answer']}")
        for req in s.http_requests:
            if indicator_lower in req["host"].lower():
                if not found:
                    results.append(f"Domain matching '{indicator}':")
                    found = True
                results.append(f"  HTTP: {req['method']} {req['host']}{req['path'][:40]}")
        for th in s.tls_handshakes:
            if indicator_lower in th.get("sni", "").lower():
                if not found:
                    results.append(f"Domain matching '{indicator}':")
                    found = True
                results.append(f"  TLS SNI: {th['sni']} ({th['src']} → {th['dst']}:{th['dport']})")
        if not found:
            results.append(f"IOC '{indicator}': not found in PCAP")
        return ToolResult(ok=True, result={"text": "\n".join(results)})
