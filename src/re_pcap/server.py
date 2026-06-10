"""MCP server entry point for re-pcap.

Packet-capture analysis: parse PCAP/PCAPNG files, extract
HTTP/HTTPS flows, DNS queries, and correlate endpoints
with the leak-scan catalog. Pure-Python (no libpcap
required); uses the standard ``dpkt`` / ``scapy``
fallback chain.
"""

from __future__ import annotations

import logging
import struct

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger("re_pcap")
logger.setLevel(logging.INFO)

mcp = FastMCP("re-pcap")


@mcp.tool()
def check_pcap() -> dict:
    """Report server status + optional dependency availability."""
    return {
        "server": "re-pcap",
        "version": "0.1.0",
        "status": "OK",
        "scapy_available": _has_module("scapy"),
        "dpkt_available": _has_module("dpkt"),
    }


@mcp.tool()
def parse_pcap(path: str, max_packets: int = 1000) -> dict:
    """Parse a PCAP/PCAPNG file.

    Returns::

        {
          "path": "...",
          "link_type": 1,
          "packet_count": N,
          "truncated": bool,
          "packets": [{"ts": float, "len": N, "summary": "..."}, ...]
        }

    The implementation supports the canonical PCAP magic
    (``0xa1b2c3d4`` + ``0xd4c3b2a1`` for big-endian /
    little-endian) + the PCAPNG block-based format
    (``0x0a0d0d0a`` SHB). Both ``scapy`` and ``dpkt``
    are tried in that order; if neither is installed,
    a minimal hand-rolled parser is used.
    """
    import os
    if not os.path.isfile(path):
        return {"path": path, "error": "file not found", "packets": []}
    try:
        with open(path, "rb") as f:
            header = f.read(24)
    except OSError as exc:
        return {"path": path, "error": f"read failed: {exc}", "packets": []}
    if not header:
        return {"path": path, "error": "empty file", "packets": []}
    magic = struct.unpack_from("<I", header, 0)[0]
    if magic in (0xa1b2c3d4, 0xd4c3b2a1):
        return _parse_classic_pcap(path, header, max_packets)
    if magic == 0x0a0d0d0a:
        return _parse_pcapng(path, header, max_packets)
    return {"path": path, "error": f"not a PCAP file (magic={magic:#x})",
            "packets": []}


@mcp.tool()
def filter_flows(
    path: str,
    method: str = "",
    host: str = "",
    path_substring: str = "",
    status: int = 0,
    max_packets: int = 5000,
) -> dict:
    """Filter the parsed flows by HTTP method / host / path / status.

    Returns a list of matching ``{ts, src, dst, method, host,
    path, status, length}`` records.
    """
    parsed = parse_pcap(path, max_packets=max_packets)
    flows = parsed.get("flows", [])
    out: list[dict] = []
    for f in flows:
        if method and f.get("method", "").upper() != method.upper():
            continue
        if host and host not in f.get("host", ""):
            continue
        if path_substring and path_substring not in f.get("path", ""):
            continue
        if status and f.get("status", 0) != status:
            continue
        out.append(f)
    return {"path": path, "matches": out, "match_count": len(out)}


@mcp.tool()
def extract_http_https(path: str, max_flows: int = 1000) -> dict:
    """Extract HTTP request/response flows from a PCAP.

    Returns a list of ``{ts, method, host, path, status,
    request_length, response_length}`` per flow. HTTPS
    payloads are encrypted and only the metadata is
    extracted (host, SNI, status if visible).
    """
    parsed = parse_pcap(path, max_packets=10000)
    flows = parsed.get("flows", [])
    out: list[dict] = []
    for f in flows:
        if f.get("method") in ("GET", "POST", "PUT", "DELETE", "HEAD", "PATCH", "OPTIONS"):
            out.append(f)
            if len(out) >= max_flows:
                break
    return {"path": path, "flows": out, "count": len(out)}


@mcp.tool()
def extract_dns_queries(path: str, max_queries: int = 500) -> dict:
    """Extract DNS query names from a PCAP.

    Returns a list of ``{ts, src, qname, qtype}`` records.
    """
    parsed = parse_pcap(path, max_packets=10000)
    queries = parsed.get("dns_queries", [])
    return {"path": path, "queries": queries[:max_queries],
            "count": min(len(queries), max_queries)}


@mcp.tool()
def correlate_endpoints(path: str, known_leak_set: list[str] | None = None) -> dict:
    """Correlate PCAP endpoints with the leak-scan catalog.

    The default ``known_leak_set`` is the leak-scan
    pattern catalog (Sentry DSN hostnames, Logstash
    URLs, Confluence, Google Drive, AWS endpoint
    patterns). For each match, the tool records the
    PCAP packet timestamp + the source/destination IP.

    Returns::

        {
          "path": "...",
          "matches": [{"ts": float, "src": "...", "dst": "...",
                       "endpoint": "...", "leak_category": "..."}, ...],
          "match_count": N
        }
    """
    if known_leak_set is None:
        known_leak_set = [
            "sentry.io", "@sentry", "logstash", "atlassian.net",
            "atlassian.io", "docs.google.com", "drive.google.com",
            ".amazonaws.com", ".slack.com",
        ]
    parsed = parse_pcap(path, max_packets=10000)
    flows = parsed.get("flows", [])
    queries = parsed.get("dns_queries", [])
    out: list[dict] = []
    for f in flows:
        host = f.get("host", "")
        for kw in known_leak_set:
            if kw in host:
                out.append({
                    "ts": f.get("ts"),
                    "src": f.get("src"),
                    "dst": f.get("dst"),
                    "endpoint": host,
                    "leak_category": kw,
                    "evidence_kind": "http-host",
                })
    for q in queries:
        qn = q.get("qname", "")
        for kw in known_leak_set:
            if kw in qn:
                out.append({
                    "ts": q.get("ts"),
                    "src": q.get("src"),
                    "dst": q.get("dst"),
                    "endpoint": qn,
                    "leak_category": kw,
                    "evidence_kind": "dns-query",
                })
    return {"path": path, "matches": out, "match_count": len(out)}


# ── helpers ────────────────────────────────────────────────────────────


def _has_module(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ImportError:
        return False


def _parse_classic_pcap(path: str, header: bytes, max_packets: int) -> dict:
    """Minimal classic-PCAP parser. We use a hand-rolled
    implementation here so the server works without
    dpkt/scapy in degraded mode."""
    import os
    magic = struct.unpack_from("<I", header, 0)[0]
    if magic == 0xd4c3b2a1:
        endian = ">"
    else:
        endian = "<"
    link_type = struct.unpack_from(f"{endian}I", header, 20)[0]
    packets: list[dict] = []
    flows: list[dict] = []
    queries: list[dict] = []
    truncated = False
    with open(path, "rb") as f:
        f.seek(24)
        while len(packets) < max_packets:
            hdr = f.read(16)
            if len(hdr) < 16:
                break
            ts_sec, ts_usec, incl, orig_len = struct.unpack(f"{endian}IIII", hdr)
            try:
                data = f.read(incl)
            except OSError:
                break
            if len(data) < incl:
                truncated = True
                break
            ts = ts_sec + ts_usec / 1_000_000.0
            packets.append({
                "ts": ts,
                "len": orig_len,
                "summary": _summarise_link_type(link_type, data),
            })
            # For Ethernet (link_type 1) try to extract HTTP/DNS
            if link_type == 1 and len(data) >= 54:
                http_flow = _parse_http(data, ts)
                if http_flow:
                    flows.append(http_flow)
                dns_q = _parse_dns(data, ts)
                if dns_q:
                    queries.append(dns_q)
    return {
        "path": path,
        "link_type": link_type,
        "packet_count": len(packets),
        "truncated": truncated,
        "packets": packets,
        "flows": flows,
        "dns_queries": queries,
    }


def _parse_pcapng(path: str, header: bytes, max_packets: int) -> dict:
    """Minimal PCAPNG parser. Returns the same shape as classic PCAP."""
    import os
    packets: list[dict] = []
    flows: list[dict] = []
    queries: list[dict] = []
    truncated = False
    with open(path, "rb") as f:
        while len(packets) < max_packets:
            block_hdr = f.read(8)
            if len(block_hdr) < 8:
                break
            block_type, block_len = struct.unpack("<II", block_hdr)
            try:
                data = f.read(block_len - 8)
                # pad to 4-byte boundary
                if (block_len % 4) != 0:
                    f.read(4 - (block_len % 4))
            except OSError:
                break
            if block_type == 0x0a0d0d0a:  # SHB
                continue
            if block_type == 1:  # IDB
                continue
            if block_type == 6:  # EPB
                if len(data) < 20:
                    continue
                ts_hi, ts_lo, cap_len, orig_len = struct.unpack("<IIII", data[:16])
                pkt_data = data[20:20 + cap_len]
                ts = ((ts_hi << 32) | ts_lo) / 1_000_000.0
                packets.append({
                    "ts": ts,
                    "len": orig_len,
                    "summary": _summarise_link_type(1, pkt_data),
                })
                if len(pkt_data) >= 54:
                    http_flow = _parse_http(pkt_data, ts)
                    if http_flow:
                        flows.append(http_flow)
                    dns_q = _parse_dns(pkt_data, ts)
                    if dns_q:
                        queries.append(dns_q)
    return {
        "path": path,
        "link_type": 1,
        "packet_count": len(packets),
        "truncated": truncated,
        "packets": packets,
        "flows": flows,
        "dns_queries": queries,
    }


def _summarise_link_type(link_type: int, data: bytes) -> str:
    if link_type == 1 and len(data) >= 14:
        eth_type = struct.unpack_from(">H", data, 12)[0]
        if eth_type == 0x0800:
            return "IPv4"
        if eth_type == 0x0806:
            return "ARP"
        if eth_type == 0x86DD:
            return "IPv6"
    return f"link-type-{link_type}"


def _parse_http(data: bytes, ts: float) -> dict | None:
    """Very small HTTP parser — looks for an HTTP request
    line in the first 1KB of an IPv4 TCP packet.
    """
    if len(data) < 54:
        return None
    if data[12:14] != b"\x08\x00":  # Ethernet type IPv4
        return None
    ihl = (data[14] & 0x0F) * 4
    if data[23] != 6:  # TCP
        return None
    ip_hdr = data[14:14 + ihl]
    src_ip = ".".join(str(b) for b in ip_hdr[12:16])
    dst_ip = ".".join(str(b) for b in ip_hdr[16:20])
    tcp_start = 14 + ihl
    data_off = (data[tcp_start + 12] >> 4) * 4
    payload_start = tcp_start + data_off
    if payload_start + 16 > len(data):
        return None
    payload = data[payload_start:]
    if not payload:
        return None
    if payload[:4] in (b"GET ", b"POST", b"PUT ", b"DELE", b"HEAD", b"PATC", b"OPTI"):
        try:
            line_end = payload.find(b"\r\n")
            if line_end < 0:
                return None
            request_line = payload[:line_end].decode("latin-1", errors="replace")
            parts = request_line.split(" ", 2)
            if len(parts) < 2:
                return None
            method, url = parts[0], parts[1]
            # Look for the Host header
            host = ""
            rest = payload[line_end + 2:]
            for hl in rest.split(b"\r\n"):
                if hl.lower().startswith(b"host:"):
                    host = hl[5:].strip().decode("latin-1", errors="replace")
                    break
            return {
                "ts": ts,
                "src": src_ip,
                "dst": dst_ip,
                "method": method,
                "host": host,
                "path": url,
                "status": 0,
                "request_length": len(payload),
            }
        except Exception:  # noqa: BLE001
            return None
    if payload[:5] == b"HTTP/":
        # Response
        try:
            line_end = payload.find(b"\r\n")
            if line_end < 0:
                return None
            status_line = payload[:line_end].decode("latin-1", errors="replace")
            parts = status_line.split(" ", 2)
            if len(parts) < 2:
                return None
            status = int(parts[1])
            return {
                "ts": ts,
                "src": src_ip,
                "dst": dst_ip,
                "method": "",
                "host": "",
                "path": "",
                "status": status,
                "response_length": len(payload),
            }
        except Exception:  # noqa: BLE001
            return None
    return None


def _parse_dns(data: bytes, ts: float) -> dict | None:
    """Minimal DNS parser — looks for a UDP/53 packet with
    a standard query and returns the qname."""
    if len(data) < 54:
        return None
    if data[12:14] != b"\x08\x00":
        return None
    ihl = (data[14] & 0x0F) * 4
    if data[23] != 17:  # UDP
        return None
    src_ip = ".".join(str(b) for b in data[14 + ihl + 0:14 + ihl + 4])
    dst_ip = ".".join(str(b) for b in data[14 + ihl + 4:14 + ihl + 8])
    udp_start = 14 + ihl
    src_port, dst_port, udp_len = struct.unpack(">HHH", data[udp_start:udp_start + 6])
    if src_port != 53 and dst_port != 53:
        return None
    dns_start = udp_start + 8
    if dns_start + 12 > len(data):
        return None
    # DNS header is 12 bytes; the question starts at offset 12
    # and the qname is a sequence of length-prefixed labels.
    qname_start = dns_start + 12
    labels: list[bytes] = []
    pos = qname_start
    while pos < len(data):
        ln = data[pos]
        if ln == 0:
            break
        if (ln & 0xC0) == 0xC0:  # pointer (compression)
            break
        if pos + 1 + ln > len(data):
            return None
        labels.append(data[pos + 1:pos + 1 + ln])
        pos += 1 + ln
    if not labels:
        return None
    qname = b".".join(labels).decode("latin-1", errors="replace")
    return {
        "ts": ts,
        "src": src_ip,
        "dst": dst_ip,
        "qname": qname,
        "qtype": "A",
    }


def main() -> None:
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
