#!/usr/bin/env python3
"""
Analyze pcapng captures from str0m browser integration tests.

Parses the pcapng files written by the Rust server, identifies protocol
phases (STUN, DTLS, SCTP/data), counts round-trips, and generates:
  1. A markdown summary table for $GITHUB_STEP_SUMMARY
  2. A PNG bar chart comparing RTT counts across tests

Usage:
  python scripts/analyze_pcaps.py <pcap_dir> [--output-dir <dir>]

The pcap files are named: {session_id}_server.pcapng
Session IDs encode: {browser}_{test_name} or {browser}_{feature}_{role}
"""

import argparse
import os
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# pcapng parser (minimal, matches our write_pcapng format)
# ---------------------------------------------------------------------------

@dataclass
class Packet:
    timestamp_us: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    payload: bytes



def parse_pcapng(filepath: Path) -> list[Packet]:
    """Parse a pcapng file and return a list of Packet objects."""
    packets = []
    data = filepath.read_bytes()
    offset = 0

    while offset < len(data) - 8:
        block_type = struct.unpack_from("<I", data, offset)[0]
        block_len = struct.unpack_from("<I", data, offset + 4)[0]

        if block_len < 12 or offset + block_len > len(data):
            break

        if block_type == 0x00000006:  # Enhanced Packet Block
            # Interface ID (4) + ts_high (4) + ts_low (4) + captured_len (4) + orig_len (4)
            ts_high = struct.unpack_from("<I", data, offset + 12)[0]
            ts_low = struct.unpack_from("<I", data, offset + 16)[0]
            captured_len = struct.unpack_from("<I", data, offset + 20)[0]
            timestamp_us = (ts_high << 32) | ts_low

            frame_start = offset + 28
            frame_data = data[frame_start : frame_start + captured_len]

            pkt = parse_ipv4_udp(frame_data, timestamp_us)
            if pkt:
                packets.append(pkt)

        offset += block_len

    return packets


def parse_ipv4_udp(frame: bytes, timestamp_us: int) -> Packet | None:
    """Parse an IPv4/UDP frame and extract the UDP payload."""
    if len(frame) < 28:  # min IPv4 (20) + UDP (8)
        return None

    version_ihl = frame[0]
    if (version_ihl >> 4) != 4:
        return None

    ihl = (version_ihl & 0x0F) * 4
    protocol = frame[9]
    if protocol != 17:  # UDP
        return None

    src_ip = f"{frame[12]}.{frame[13]}.{frame[14]}.{frame[15]}"
    dst_ip = f"{frame[16]}.{frame[17]}.{frame[18]}.{frame[19]}"

    udp_offset = ihl
    if len(frame) < udp_offset + 8:
        return None

    src_port = struct.unpack_from(">H", frame, udp_offset)[0]
    dst_port = struct.unpack_from(">H", frame, udp_offset + 2)[0]
    udp_len = struct.unpack_from(">H", frame, udp_offset + 4)[0]

    payload = frame[udp_offset + 8 : udp_offset + udp_len]

    return Packet(
        timestamp_us=timestamp_us,
        src_ip=src_ip,
        src_port=src_port,
        dst_ip=dst_ip,
        dst_port=dst_port,
        payload=payload,
    )


# ---------------------------------------------------------------------------
# Protocol identification
# ---------------------------------------------------------------------------

# STUN constants
_STUN_BINDING_REQUEST = 0x0001
_STUN_BINDING_RESPONSE = 0x0101
_STUN_MAGIC = 0x2112A442

# DTLS content types
_DTLS_CCS = 20
_DTLS_ALERT = 21
_DTLS_HANDSHAKE = 22
_DTLS_APP_DATA = 23

# DTLS handshake message types (cleartext, epoch 0)
_HS_CLIENT_HELLO = 1
_HS_SERVER_HELLO = 2
_HS_HELLO_VERIFY_REQUEST = 3
_HS_CERTIFICATE = 11
_HS_SERVER_KEY_EXCHANGE = 12
_HS_SERVER_HELLO_DONE = 14
_HS_CLIENT_KEY_EXCHANGE = 16


def classify_packet(payload: bytes) -> str:
    """Classify a packet's top-level protocol layer (first byte)."""
    if not payload:
        return "empty"
    first = payload[0]

    if first in (0x00, 0x01) and len(payload) >= 20:
        msg_type = struct.unpack_from(">H", payload, 0)[0]
        if msg_type == _STUN_BINDING_REQUEST:
            return "STUN-REQ"
        elif msg_type == _STUN_BINDING_RESPONSE:
            return "STUN-RESP"
        return "STUN-OTHER"

    # DTLS 1.2 plaintext record layer: content types 20-25
    if 20 <= first <= 25:
        if first == _DTLS_CCS:
            return "DTLS-CCS"
        elif first == _DTLS_HANDSHAKE:
            return "DTLS-HS"
        elif first == _DTLS_APP_DATA:
            return "DTLS-APP"
        elif first == _DTLS_ALERT:
            return "DTLS-ALERT"
        return "DTLS-OTHER"

    # DTLS 1.3 unified header (RFC 9147 Section 4):
    # Fixed bits 001xxxxx -> byte range 0x20-0x3F
    # Epoch in low 2 bits: epoch 2 = encrypted HS, epoch 3 = app data
    if 0x20 <= first <= 0x3F:
        epoch = first & 0x03
        if epoch == 2:
            return "DTLS13-HS"   # encrypted handshake (Finished, etc.)
        elif epoch == 3:
            return "DTLS13-APP"  # encrypted application data (SCTP)
        return "DTLS13-OTHER"

    return "OTHER"


def parse_stun_txn_id(payload: bytes) -> str | None:
    """Extract the 12-byte STUN transaction ID as a hex string."""
    if len(payload) < 20:
        return None
    magic = struct.unpack_from(">I", payload, 4)[0]
    if magic != _STUN_MAGIC:
        return None
    return payload[8:20].hex()


@dataclass
class DtlsRecord:
    """A single DTLS record parsed from a UDP payload."""
    content_type: int    # 20-25
    epoch: int
    record_len: int
    hs_type: int | None = None   # set for cleartext HS records (epoch 0, ct 22)


def parse_dtls_records(payload: bytes) -> list[DtlsRecord]:
    """Parse all DTLS records from a UDP payload.

    Handles both DTLS 1.2 plaintext record layer (content types 20-25)
    and DTLS 1.3 unified header (0x20-0x3F, RFC 9147 Section 4).

    A single UDP datagram can carry multiple coalesced records, e.g.
    CCS + encrypted Finished + APP data.  Parsing all of them is
    essential for correct SCTP-handshake detection in SNAP sessions
    where the first APP record is coalesced with the last DTLS flight.
    """
    records: list[DtlsRecord] = []
    off = 0
    while off < len(payload):
        if off + 1 > len(payload):
            break
        first = payload[off]

        # DTLS 1.2 plaintext record: ct(1) + version(2) + epoch(2) + seq(6) + length(2) = 13 bytes
        if 20 <= first <= 25:
            if off + 13 > len(payload):
                break
            ct = first
            epoch = struct.unpack_from(">H", payload, off + 3)[0]
            rec_len = struct.unpack_from(">H", payload, off + 11)[0]
            rec_data = payload[off + 13 : off + 13 + rec_len]

            rec = DtlsRecord(content_type=ct, epoch=epoch, record_len=rec_len)
            if ct == _DTLS_HANDSHAKE and epoch == 0 and len(rec_data) >= 12:
                rec.hs_type = rec_data[0]

            records.append(rec)
            off += 13 + rec_len
            continue

        # DTLS 1.3 unified header (RFC 9147 Section 4):
        # Fixed bits: 001CSLEE
        #   C = Connection ID present
        #   S = Sequence number length (0=8bit, 1=16bit)
        #   L = Length present
        #   EE = Epoch low 2 bits
        if 0x20 <= first <= 0x3F:
            epoch = first & 0x03
            has_cid = bool(first & 0x10)
            seq_16bit = bool(first & 0x08)
            has_length = bool(first & 0x04)

            hdr_len = 1  # first byte
            if has_cid:
                break  # CID length is variable, can't parse without context
            hdr_len += 2 if seq_16bit else 1  # sequence number

            if has_length:
                if off + hdr_len + 2 > len(payload):
                    break
                rec_len = struct.unpack_from(">H", payload, off + hdr_len)[0]
                hdr_len += 2
            else:
                # No length field: rest of UDP payload is this record
                rec_len = len(payload) - off - hdr_len

            # Map epoch to equivalent content type for analysis
            if epoch == 2:
                ct = _DTLS_HANDSHAKE  # encrypted handshake
            elif epoch == 3:
                ct = _DTLS_APP_DATA   # application data
            else:
                ct = _DTLS_APP_DATA   # other epochs treated as APP

            records.append(DtlsRecord(
                content_type=ct, epoch=epoch, record_len=rec_len,
            ))
            off += hdr_len + rec_len
            continue

        # Not a DTLS record
        break

    return records


# ---------------------------------------------------------------------------
# RTT analysis
# ---------------------------------------------------------------------------

@dataclass
class SessionAnalysis:
    session_id: str
    browser: str = ""
    platform: str = ""
    crypto: str = ""
    test_type: str = ""        # "base", "snap", "warp"
    test_role: str = ""        # "offerer_active_lite", etc.
    total_packets: int = 0
    stun_rtts: int = 0         # Unique completed STUN transactions (ICE)
    dtls_version: str = ""     # "1.2", "1.3", or "unknown"
    dtls_has_hvr: bool = False # HelloVerifyRequest observed
    dtls_rtts: float = 0       # DTLS handshake RTTs
    sctp_handshake: bool = False  # SCTP 4-way handshake detected
    sctp_rtts: float = 0       # SCTP handshake RTTs (2 or 0)
    total_rtts: float = 0      # STUN + DTLS + SCTP RTTs
    phases: list[str] = field(default_factory=list)
    error: str = ""


def analyze_session(packets: list[Packet], session_id: str) -> SessionAnalysis:
    """Analyze a session's packets and count RTTs per protocol phase.

    ICE (STUN):
      Matches STUN Binding requests to responses by transaction ID.
      Each unique completed transaction = 1 ICE RTT.

    DTLS handshake:
      Detects DTLS version from cleartext handshake messages:
        - Certificate / ServerKeyExchange visible  -> DTLS 1.2
        - Only ClientHello / ServerHello visible   -> DTLS 1.3
      Counts direction changes among DTLS-HS records; each pair of
      opposing flights = 1 RTT.  Works correctly for both versions:
        - DTLS 1.2 w/o HVR: CH -> SH..SHD -> Cert..Fin -> CCS+Fin = 2 RTTs
        - DTLS 1.2 w/  HVR: + CH -> HVR extra flight          = 3 RTTs
        - DTLS 1.3 w/o HVR: CH -> SH (rest encrypted)         = 1 RTT
        - DTLS 1.3 w/  HVR: + CH -> HRR extra flight           = 2 RTTs

    SCTP handshake:
      With SNAP the 4-way handshake (INIT/INIT-ACK/COOKIE-ECHO/COOKIE-ACK)
      is skipped entirely.  Detection uses the SCTP COOKIE-ACK fingerprint:
      it always produces a DTLS-APP record of ~40 bytes (16-byte SCTP
      payload + AEAD overhead).  No other SCTP message is that small.
      If record_len <= 44 appears among the first 8 APP records, the
      handshake is present (2 RTTs); otherwise it was skipped (0 RTTs).
    """
    result = SessionAnalysis(session_id=session_id)
    result.total_packets = len(packets)

    if not packets:
        result.error = "no packets"
        return result

    server_addr = (packets[0].src_ip, packets[0].src_port)

    # ── Pass 1: extract protocol details from every packet ───────
    stun_txns: dict[str, dict[str, bool]] = {}  # txn_id -> {req, resp}
    cleartext_hs_types: set[int] = set()
    dtls_hs_directions: list[str] = []    # direction per HS record
    dtls_app_record_lens: list[int] = []  # record_len of every APP record
    pkt_top_protos: list[str] = []        # top-level proto per packet

    for pkt in packets:
        payload = pkt.payload
        if not payload:
            pkt_top_protos.append("empty")
            continue

        direction = "->" if (pkt.src_ip, pkt.src_port) == server_addr else "<-"
        top_proto = classify_packet(payload)
        pkt_top_protos.append(top_proto)
        first = payload[0]

        # ── STUN: track transactions by ID ──────────────────────
        if first in (0x00, 0x01) and len(payload) >= 20:
            msg_type = struct.unpack_from(">H", payload, 0)[0]
            txn = parse_stun_txn_id(payload)
            if txn:
                entry = stun_txns.setdefault(txn, {"req": False, "resp": False})
                if msg_type == _STUN_BINDING_REQUEST:
                    entry["req"] = True
                elif msg_type == _STUN_BINDING_RESPONSE:
                    entry["resp"] = True

        # ── DTLS: parse all records (handles coalesced payloads
        #    and both 1.2 plaintext + 1.3 unified headers) ────────
        elif (20 <= first <= 25) or (0x20 <= first <= 0x3F):
            for rec in parse_dtls_records(payload):
                if rec.content_type == _DTLS_HANDSHAKE:
                    # Only count epoch-0 (cleartext) HS records for
                    # direction-change / RTT counting.  Encrypted HS
                    # records (epoch 1 in DTLS 1.2, epoch 2 in DTLS 1.3)
                    # are fire-and-forget continuations that don't add RTTs.
                    if rec.epoch == 0:
                        dtls_hs_directions.append(direction)
                        if rec.hs_type is not None:
                            cleartext_hs_types.add(rec.hs_type)
                elif rec.content_type == _DTLS_APP_DATA:
                    dtls_app_record_lens.append(rec.record_len)

    # ── ICE / STUN RTTs ─────────────────────────────────────────
    result.stun_rtts = sum(
        1 for t in stun_txns.values() if t["req"] and t["resp"]
    )

    # ── DTLS version detection ──────────────────────────────────
    dtls12_indicators = {
        _HS_CERTIFICATE, _HS_SERVER_KEY_EXCHANGE,
        _HS_SERVER_HELLO_DONE, _HS_CLIENT_KEY_EXCHANGE,
    }
    result.dtls_has_hvr = _HS_HELLO_VERIFY_REQUEST in cleartext_hs_types

    if cleartext_hs_types & dtls12_indicators:
        result.dtls_version = "1.2"
    elif _HS_CLIENT_HELLO in cleartext_hs_types:
        result.dtls_version = "1.3"
    else:
        result.dtls_version = "unknown"

    # ── DTLS RTTs (direction-change counting) ───────────────────
    hs_flights = 0
    last_dir = None
    for d in dtls_hs_directions:
        if d != last_dir:
            hs_flights += 1
            last_dir = d
    result.dtls_rtts = max(0, (hs_flights + 1) // 2)

    # ── SCTP RTTs (COOKIE-ACK fingerprint) ──────────────────────
    first_app = dtls_app_record_lens[:8]
    result.sctp_handshake = any(rl <= 44 for rl in first_app)
    result.sctp_rtts = 2 if result.sctp_handshake else 0

    # ── Total RTTs ──────────────────────────────────────────────
    result.total_rtts = result.stun_rtts + result.dtls_rtts + result.sctp_rtts

    # ── Phase summary (second pass using computed results) ──────
    phases: list[str] = []
    current_phase: str | None = None
    app_idx = 0
    sctp_zone = 4 if result.sctp_handshake else 0
    for proto in pkt_top_protos:
        if proto in ("DTLS-APP", "DTLS13-APP"):
            phase = "SCTP" if app_idx < sctp_zone else "DATA"
            app_idx += 1
        elif proto.startswith("DTLS"):
            phase = "DTLS"
        elif proto.startswith("STUN"):
            phase = "STUN"
        else:
            phase = "OTHER"
        if phase != current_phase:
            phases.append(phase)
            current_phase = phase
    result.phases = phases

    return result


def parse_session_id(session_id: str, platform: str, crypto: str, is_native: bool = False) -> dict:
    """Parse session_id into browser / test_type / role components."""
    parts = session_id.split("_")

    # Native tests have no browser prefix.
    # Session IDs: offerer_active_lite, answerer_active_full, etc.
    # SNAP tests:  snap_on_offerer_active_lite, snap_off_answerer_active_lite
    if is_native:
        test_type = "base"
        role = "_".join(parts)

        native_features = {"snap_on", "snap_off"}
        if len(parts) >= 2 and f"{parts[0]}_{parts[1]}" in native_features:
            test_type = f"{parts[0]}_{parts[1]}"
            role = "_".join(parts[2:]) if len(parts) > 2 else "unknown"

        return {
            "browser": "native",
            "test_type": test_type,
            "role": role,
            "platform": platform,
            "crypto": crypto,
        }

    browser = parts[0] if parts else "unknown"

    # Base test IDs: {browser}_{role}_{dtls}_{ice}
    # e.g. chrome_offerer_active_lite
    # WARP test IDs: {browser}_{feature}_{role}
    # e.g. chrome_snap_snap_offerer

    known_features = {"snap", "warp"}

    test_type = "base"
    role = "_".join(parts[1:]) if len(parts) > 1 else "unknown"

    if len(parts) >= 2 and parts[1] in known_features:
        test_type = parts[1]
        role = "_".join(parts[2:]) if len(parts) > 2 else "unknown"

    return {
        "browser": browser,
        "test_type": test_type,
        "role": role,
        "platform": platform,
        "crypto": crypto,
    }


# ---------------------------------------------------------------------------
# Output generation
# ---------------------------------------------------------------------------

# Scenario priority: offerer_active_lite (the standard browser config) first,
# then remaining base variants, then feature tests.
SCENARIO_ORDER = [
    "offerer_active_lite",
    "offerer_active_full",
    "offerer_passive_lite",
    "offerer_passive_full",
    "answerer_active_lite",
    "answerer_active_full",
]


def _sort_key(r: SessionAnalysis) -> tuple:
    """Sort key: scenario group first, then platform/crypto/browser."""
    try:
        scenario_idx = SCENARIO_ORDER.index(r.test_role)
    except ValueError:
        scenario_idx = len(SCENARIO_ORDER)
    return (r.test_type, scenario_idx, r.test_role, r.platform, r.crypto, r.browser)


def generate_markdown_table(results: list[SessionAnalysis]) -> str:
    """Generate a markdown table summarizing all sessions."""
    lines = []
    lines.append("## Connection RTT Analysis\n")
    lines.append("| Platform | Crypto | Browser | Test | Role | STUN RTTs | DTLS Ver | DTLS RTTs | SCTP RTTs | Total RTTs | Packets | Phases |")
    lines.append("|----------|--------|---------|------|------|-----------|----------|-----------|-----------|------------|---------|--------|")

    sorted_results = sorted(results, key=_sort_key)

    for r in sorted_results:
        if r.error:
            lines.append(f"| {r.platform} | {r.crypto} | {r.browser} | {r.test_type} | {r.test_role} | - | - | - | - | - | {r.total_packets} | {r.error} |")
        else:
            phases_str = " -> ".join(r.phases)
            hvr = " +HVR" if r.dtls_has_hvr else ""
            snap = "" if r.sctp_handshake else " (SNAP)"
            lines.append(
                f"| {r.platform} | {r.crypto} | {r.browser} | {r.test_type} | {r.test_role} "
                f"| {r.stun_rtts} | {r.dtls_version}{hvr} | {r.dtls_rtts:.0f} | {r.sctp_rtts:.0f}{snap} "
                f"| {r.total_rtts:.0f} | {r.total_packets} | {phases_str} |"
            )

    lines.append("")

    # Summary statistics
    valid = [r for r in results if not r.error]
    if valid:
        lines.append("### Summary\n")

        # Group by test_type
        by_type: dict[str, list[SessionAnalysis]] = {}
        for r in valid:
            by_type.setdefault(r.test_type, []).append(r)

        lines.append("| Test Type | Avg RTTs | Sessions |")
        lines.append("|-----------|----------|---------:|")
        for ttype, sessions in sorted(by_type.items()):
            avg_rtts = sum(s.total_rtts for s in sessions) / len(sessions)
            lines.append(f"| {ttype} | {avg_rtts:.1f} | {len(sessions)} |")

        lines.append("")

        # Group by crypto
        by_crypto: dict[str, list[SessionAnalysis]] = {}
        for r in valid:
            by_crypto.setdefault(r.crypto, []).append(r)

        lines.append("| Crypto Provider | Avg RTTs | Sessions |")
        lines.append("|-----------------|----------|---------:|")
        for crypto, sessions in sorted(by_crypto.items()):
            avg_rtts = sum(s.total_rtts for s in sessions) / len(sessions)
            lines.append(f"| {crypto} | {avg_rtts:.1f} | {len(sessions)} |")

        lines.append("")

        # Group by browser
        by_browser: dict[str, list[SessionAnalysis]] = {}
        for r in valid:
            by_browser.setdefault(r.browser, []).append(r)

        lines.append("| Browser | Avg RTTs | Sessions |")
        lines.append("|---------|----------|---------:|")
        for browser, sessions in sorted(by_browser.items()):
            avg_rtts = sum(s.total_rtts for s in sessions) / len(sessions)
            lines.append(f"| {browser} | {avg_rtts:.1f} | {len(sessions)} |")

    return "\n".join(lines)


def generate_chart(results: list[SessionAnalysis], output_dir: Path) -> list[Path]:
    """Generate PNG charts using matplotlib. Returns list of generated file paths."""
    try:
        import matplotlib
        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except ImportError:
        print("WARNING: matplotlib not available, skipping chart generation", file=sys.stderr)
        return []

    valid = [r for r in results if not r.error]
    if not valid:
        return []

    output_dir.mkdir(parents=True, exist_ok=True)
    generated = []

    # -- Chart 1: RTT count by test (grouped by browser x platform) ----
    fig, ax = plt.subplots(figsize=(max(14, len(valid) * 0.5), 7))

    labels = []
    stun_vals = []
    dtls_vals = []
    sctp_vals = []

    sorted_v = sorted(valid, key=_sort_key)
    for r in sorted_v:
        label = f"{r.browser}\n{r.test_type}/{r.test_role}\n{r.platform}/{r.crypto}"
        labels.append(label)
        stun_vals.append(r.stun_rtts)
        dtls_vals.append(r.dtls_rtts)
        sctp_vals.append(r.sctp_rtts)

    x = range(len(labels))
    width = 0.7

    import numpy as np
    stun_arr = np.array(stun_vals)
    dtls_arr = np.array(dtls_vals)
    sctp_arr = np.array(sctp_vals)

    ax.bar(x, stun_arr, width, label="STUN (ICE)", color="#4C72B0")
    ax.bar(x, dtls_arr, width, bottom=stun_arr, label="DTLS Handshake", color="#DD8452")
    ax.bar(x, sctp_arr, width, bottom=stun_arr + dtls_arr, label="SCTP Handshake", color="#55A868")

    ax.set_ylabel("Round-Trip Times")
    ax.set_title("Connection RTTs by Test Configuration")
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=6)
    ax.legend()
    ax.set_ylim(0, max(r.total_rtts for r in sorted_v) + 2)

    # Add total RTT labels on top of bars
    for i, r in enumerate(sorted_v):
        ax.text(i, r.total_rtts + 0.1, f"{r.total_rtts:.0f}", ha="center", va="bottom", fontsize=7)

    plt.tight_layout()
    path1 = output_dir / "rtt_by_test.png"
    fig.savefig(path1, dpi=150)
    plt.close(fig)
    generated.append(path1)
    print(f"  Chart: {path1}")

    # -- Chart 2: RTTs heatmap by browser x platform ----
    by_bp: dict[tuple[str, str], list[float]] = {}
    for r in valid:
        key = (r.browser, r.platform)
        by_bp.setdefault(key, []).append(r.total_rtts)

    browsers = sorted(set(r.browser for r in valid))
    platforms = sorted(set(r.platform for r in valid))

    if len(browsers) > 1 or len(platforms) > 1:
        fig2, ax2 = plt.subplots(figsize=(max(8, len(platforms) * 2.5), max(4, len(browsers) * 1.5)))

        heatmap_data = []
        for b in browsers:
            row = []
            for p in platforms:
                vals = by_bp.get((b, p), [])
                row.append(sum(vals) / len(vals) if vals else float("nan"))
            heatmap_data.append(row)

        import numpy as np
        hm = np.array(heatmap_data)
        im = ax2.imshow(hm, cmap="YlOrRd", aspect="auto")

        ax2.set_xticks(range(len(platforms)))
        ax2.set_xticklabels(platforms)
        ax2.set_yticks(range(len(browsers)))
        ax2.set_yticklabels(browsers)
        ax2.set_title("Avg RTTs: Browser x Platform")

        for i in range(len(browsers)):
            for j in range(len(platforms)):
                val = hm[i, j]
                if not (val != val):  # not NaN
                    ax2.text(j, i, f"{val:.1f}", ha="center", va="center", fontsize=12, fontweight="bold")

        fig2.colorbar(im, label="Avg RTTs")
        plt.tight_layout()

        path2 = output_dir / "rtt_heatmap.png"
        fig2.savefig(path2, dpi=150)
        plt.close(fig2)
        generated.append(path2)
        print(f"  Chart: {path2}")

    return generated


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def collect_pcap_files(pcap_dir: Path) -> list[tuple[Path, str, str, bool]]:
    """
    Collect all pcapng files, returning (path, platform, crypto, is_native).

    Expected directory structure under pcap_dir (download-artifact layout):
      Browser tests:  pcaps-{platform}-{crypto}-test-{test}/{session_id}_server.pcapng
      Native tests:   pcaps-{platform}-{crypto}-native/{session_id}_server.pcapng

    The platform and crypto are extracted from the parent directory name.
    """
    results = []

    for root, _dirs, files in os.walk(pcap_dir):
        root_path = Path(root)
        for f in files:
            if not f.endswith(".pcapng"):
                continue

            filepath = root_path / f

            platform = "unknown"
            crypto = "unknown"
            is_native = False

            for parent in [root_path] + list(root_path.parents):
                if parent.name.startswith("pcaps-"):
                    suffix = parent.name[len("pcaps-"):]

                    # Native tests: pcaps-{platform}-{crypto}-native
                    if suffix.endswith("-native"):
                        is_native = True
                        prefix = suffix[: -len("-native")]
                        dash_idx = prefix.find("-")
                        if dash_idx > 0:
                            platform = prefix[:dash_idx]
                            crypto = prefix[dash_idx + 1:]
                    else:
                        # Browser tests: pcaps-{platform}-{crypto}-test-{...}
                        test_idx = suffix.find("-test-")
                        if test_idx > 0:
                            prefix = suffix[:test_idx]
                            dash_idx = prefix.find("-")
                            if dash_idx > 0:
                                platform = prefix[:dash_idx]
                                crypto = prefix[dash_idx + 1:]
                        else:
                            parts = suffix.split("-", 1)
                            if len(parts) == 2:
                                platform = parts[0]
                                crypto = parts[1]
                    break

            results.append((filepath, platform, crypto, is_native))

    return results


def main():
    parser = argparse.ArgumentParser(description="Analyze pcapng captures from str0m integration tests")
    parser.add_argument("pcap_dir", help="Directory containing pcapng files (or subdirectories)")
    parser.add_argument("--output-dir", default="analysis", help="Output directory for charts and reports")
    parser.add_argument("--summary-file", default=None, help="Write markdown to this file (for $GITHUB_STEP_SUMMARY)")
    args = parser.parse_args()

    pcap_dir = Path(args.pcap_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    if not pcap_dir.exists():
        print(f"ERROR: pcap directory does not exist: {pcap_dir}", file=sys.stderr)
        sys.exit(1)

    # Collect all pcapng files
    pcap_files = collect_pcap_files(pcap_dir)
    print(f"Found {len(pcap_files)} pcapng files")

    if not pcap_files:
        print("No pcapng files found -- nothing to analyze.")
        # Write empty summary
        md = "## Connection RTT Analysis\n\nNo pcap files found -- tests may not have produced captures.\n"
        if args.summary_file:
            Path(args.summary_file).write_text(md, encoding="utf-8")
        return

    # Analyze each session
    results: list[SessionAnalysis] = []

    for filepath, platform, crypto, is_native in pcap_files:
        filename = filepath.stem  # e.g. "chrome_offerer_active_lite_server"
        # Remove the _server suffix
        session_id = filename.removesuffix("_server").removesuffix("_client")

        kind = "native" if is_native else "browser"
        print(f"  Parsing: {filepath.name} ({kind}, platform={platform}, crypto={crypto})")
        packets = parse_pcapng(filepath)

        analysis = analyze_session(packets, session_id)

        # Parse session_id components
        meta = parse_session_id(session_id, platform, crypto, is_native)
        analysis.browser = meta["browser"]
        analysis.platform = meta["platform"]
        analysis.crypto = meta["crypto"]
        analysis.test_type = meta["test_type"]
        analysis.test_role = meta["role"]

        results.append(analysis)

    print(f"\nAnalyzed {len(results)} sessions")

    # Generate markdown table
    md = generate_markdown_table(results)
    print("\n" + md)

    # Write markdown
    md_path = output_dir / "summary.md"
    md_path.write_text(md, encoding="utf-8")
    print(f"\nMarkdown summary: {md_path}")

    if args.summary_file:
        Path(args.summary_file).write_text(md, encoding="utf-8")
        print(f"GitHub step summary: {args.summary_file}")

    # Generate charts
    print("\nGenerating charts...")
    chart_paths = generate_chart(results, output_dir)

    if chart_paths:
        # For $GITHUB_STEP_SUMMARY, link to the artifact
        if args.summary_file:
            summary_md = md + "\n\n### Charts\n\n"
            summary_md += "> **Download the `rtt-analysis` artifact** to view the PNG charts:\n\n"
            for cp in chart_paths:
                summary_md += f"- `{cp.name}` -- {cp.stem.replace('_', ' ').title()}\n"
            summary_md += "\n"
            Path(args.summary_file).write_text(summary_md, encoding="utf-8")

    print("\nDone!")


if __name__ == "__main__":
    main()
