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

def classify_packet(payload: bytes) -> str:
    """Classify a packet's protocol layer."""
    if not payload:
        return "empty"
    first = payload[0]

    # STUN messages start with 0x00 or 0x01
    if first in (0x00, 0x01) and len(payload) >= 20:
        msg_type = struct.unpack_from(">H", payload, 0)[0]
        if msg_type == 0x0001:
            return "STUN-REQ"
        elif msg_type == 0x0101:
            return "STUN-RESP"
        else:
            return "STUN-OTHER"

    # DTLS record layer: content types 20-25
    if 20 <= first <= 25:
        if first == 20:
            return "DTLS-CCS"
        elif first == 22:
            return "DTLS-HS"
        elif first == 23:
            return "DTLS-APP"
        elif first == 21:
            return "DTLS-ALERT"
        return "DTLS-OTHER"

    return "OTHER"


# ---------------------------------------------------------------------------
# RTT analysis
# ---------------------------------------------------------------------------

@dataclass
class SessionAnalysis:
    session_id: str
    browser: str = ""
    platform: str = ""
    crypto: str = ""
    test_type: str = ""        # "base", "snap", "sped", "warp"
    test_role: str = ""        # "offerer_active_lite", etc.
    total_packets: int = 0
    stun_rtts: int = 0         # STUN request/response pairs (ICE)
    dtls_flights: int = 0      # DTLS-HS direction changes
    dtls_rtts: float = 0       # Estimated DTLS handshake RTTs
    sctp_flights: int = 0      # SCTP handshake flights (inside DTLS-APP)
    sctp_rtts: float = 0       # Estimated SCTP handshake RTTs
    total_rtts: float = 0      # STUN + DTLS + SCTP RTTs
    phases: list[str] = field(default_factory=list)
    error: str = ""


def analyze_session(packets: list[Packet], session_id: str) -> SessionAnalysis:
    """Analyze a session's packets and count RTTs."""
    result = SessionAnalysis(session_id=session_id)
    result.total_packets = len(packets)

    if not packets:
        result.error = "no packets"
        return result

    # Determine server address from first packet's src
    server_addr = (packets[0].src_ip, packets[0].src_port)

    # Classify all packets with direction
    classified = []
    for pkt in packets:
        proto = classify_packet(pkt.payload)
        is_outgoing = (pkt.src_ip, pkt.src_port) == server_addr
        direction = "->" if is_outgoing else "<-"
        classified.append((pkt, proto, direction))

    # Count STUN request/response pairs
    stun_requests = 0
    stun_responses = 0
    for _, proto, _ in classified:
        if proto == "STUN-REQ":
            stun_requests += 1
        elif proto == "STUN-RESP":
            stun_responses += 1
    result.stun_rtts = min(stun_requests, stun_responses)

    # Count DTLS handshake flights (direction changes in DTLS-HS packets)
    dtls_hs_packets = [(p, d) for p, proto, d in classified if proto == "DTLS-HS"]
    flights = 0
    last_dir = None
    for _, d in dtls_hs_packets:
        if d != last_dir:
            flights += 1
            last_dir = d
    result.dtls_flights = flights
    result.dtls_rtts = max(0, (flights + 1) // 2)

    # Separate SCTP handshake from data inside DTLS-APP.
    # SCTP 4-way: INIT -> INIT-ACK <- COOKIE-ECHO -> COOKIE-ACK <-
    # These are the first 4 DTLS-APP packets with alternating directions.
    # After that comes DCEP open/ack, then user data.
    dtls_app_packets = [(p, d) for p, proto, d in classified if proto == "DTLS-APP"]

    # Count SCTP handshake flights: direction changes in the first 4 DTLS-APP
    # packets (the 4-way handshake). Any additional early alternations before
    # data bursts are DCEP negotiation.
    sctp_hs_count = min(4, len(dtls_app_packets))
    sctp_flights = 0
    last_dir = None
    for _, d in dtls_app_packets[:sctp_hs_count]:
        if d != last_dir:
            sctp_flights += 1
            last_dir = d
    result.sctp_flights = sctp_flights
    result.sctp_rtts = max(0, (sctp_flights + 1) // 2)

    # Total RTTs
    result.total_rtts = result.stun_rtts + result.dtls_rtts + result.sctp_rtts

    # Build phase summary
    phases = []
    current_phase = None
    app_idx = 0
    for _, proto, _ in classified:
        if proto == "DTLS-APP":
            if app_idx < sctp_hs_count:
                phase = "SCTP"
            else:
                phase = "DATA"
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
    if is_native:
        return {
            "browser": "native",
            "test_type": "base",
            "role": "_".join(parts),
            "platform": platform,
            "crypto": crypto,
        }

    browser = parts[0] if parts else "unknown"

    # Base test IDs: {browser}_{role}_{dtls}_{ice}
    # e.g. chrome_offerer_active_lite
    # WARP test IDs: {browser}_{feature}_{role}
    # e.g. chrome_sped_snap_offerer

    known_features = {"snap", "sped", "warp"}

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
    lines.append("| Platform | Crypto | Browser | Test | Role | STUN RTTs | DTLS RTTs | SCTP RTTs | Total RTTs | Packets | Phases |")
    lines.append("|----------|--------|---------|------|------|-----------|-----------|-----------|------------|---------|--------|")

    sorted_results = sorted(results, key=_sort_key)

    for r in sorted_results:
        if r.error:
            lines.append(f"| {r.platform} | {r.crypto} | {r.browser} | {r.test_type} | {r.test_role} | - | - | - | - | {r.total_packets} | {r.error} |")
        else:
            phases_str = " -> ".join(r.phases)
            lines.append(
                f"| {r.platform} | {r.crypto} | {r.browser} | {r.test_type} | {r.test_role} "
                f"| {r.stun_rtts} | {r.dtls_rtts:.0f} | {r.sctp_rtts:.0f} | {r.total_rtts:.0f} "
                f"| {r.total_packets} | {phases_str} |"
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
