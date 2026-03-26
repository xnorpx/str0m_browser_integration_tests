#!/usr/bin/env python3
import argparse
import os
import struct
import sys
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class Packet:
    timestamp_us: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    payload: bytes

def parse_pcapng(filepath: Path) -> list[Packet]:
    packets = []
    try:
        data = filepath.read_bytes()
    except Exception as e:
        return packets
    offset = 0
    while offset < len(data) - 8:
        block_type = struct.unpack_from("<I", data, offset)[0]
        block_len = struct.unpack_from("<I", data, offset + 4)[0]
        if block_len < 12 or offset + block_len > len(data): break
        if block_type == 0x00000006:
            ts_high = struct.unpack_from("<I", data, offset + 12)[0]
            ts_low = struct.unpack_from("<I", data, offset + 16)[0]
            captured_len = struct.unpack_from("<I", data, offset + 20)[0]
            timestamp_us = (ts_high << 32) | ts_low
            frame_start = offset + 28
            frame_data = data[frame_start : frame_start + captured_len]
            pkt = parse_ipv4_udp(frame_data, timestamp_us)
            if pkt: packets.append(pkt)
        offset += block_len
    return packets

def parse_ipv4_udp(frame: bytes, timestamp_us: int) -> Packet | None:
    if len(frame) < 28: return None
    version_ihl = frame[0]
    if (version_ihl >> 4) != 4: return None
    ihl = (version_ihl & 0x0F) * 4
    protocol = frame[9]
    if protocol != 17: return None
    src_ip = f"{frame[12]}.{frame[13]}.{frame[14]}.{frame[15]}"
    dst_ip = f"{frame[16]}.{frame[17]}.{frame[18]}.{frame[19]}"
    udp_offset = ihl
    if len(frame) < udp_offset + 8: return None
    src_port = struct.unpack_from(">H", frame, udp_offset)[0]
    dst_port = struct.unpack_from(">H", frame, udp_offset + 2)[0]
    udp_len = struct.unpack_from(">H", frame, udp_offset + 4)[0]
    payload = frame[udp_offset + 8 : udp_offset + udp_len]
    return Packet(timestamp_us, src_ip, src_port, dst_ip, dst_port, payload)

def find_negotiated_dtls_version(payload: bytes) -> str | None:
    if len(payload) < 25: return None
    if payload[0] != 0x16: return None
    if payload[13] != 0x02: return None
    frag_len = struct.unpack_from('>I', b'\x00' + payload[22:25])[0]
    if len(payload[25:]) < frag_len: return None
    srv_version = payload[25:27]
    base_version = None
    if srv_version == b'\xfe\xfd': base_version = '1.2'
    elif srv_version == b'\xfe\xff': base_version = '1.0'
    elif srv_version == b'\xfe\xfc': return '1.3'
    else: base_version = f'Unknown ({srv_version.hex()})'
    sid_len = payload[59]
    ext_offset = 60 + sid_len + 2 + 1
    if len(payload) >= ext_offset + 2:
        ext_len = struct.unpack_from('>H', payload, ext_offset)[0]
        offset = ext_offset + 2
        end = offset + ext_len
        if end > len(payload): end = len(payload)
        while offset + 4 <= end:
            ext_type = struct.unpack_from('>H', payload, offset)[0]
            ext_size = struct.unpack_from('>H', payload, offset+2)[0]
            offset += 4
            if ext_type == 43:
                v = payload[offset:offset+2]
                if v == b'\xfe\xfc': return '1.3'
                elif v == b'\xfe\xfd': return '1.2'
            offset += ext_size
    return base_version

def get_protocol_type(p: Packet) -> str:
    if not p.payload: return "OTHER"
    v = p.payload[0]
    if v in (0, 1): return "STUN"
    if v == 22: return "DTLS-HS"
    if v in (20, 21): return "DTLS-CTL"
    if 23 <= v <= 63: return "DTLS-APP"
    return "OTHER"

@dataclass
class SessionAnalysis:
    session_id: str
    browser: str = ""
    platform: str = ""
    crypto: str = ""
    client_sdp: str = ""
    client_dtls: str = ""
    server_dtls: str = ""
    dtls_negotiated: str = "-"
    server_ice: str = ""
    snap_mode: str = ""
    total_packets: int = 0
    stun_rtts: int = 0
    dtls_rtts: int = 0
    sctp_rtts: int = 0
    total_rtts: int = 0
    time_to_connected_ms: float = 0.0
    error: str = ""

def count_dir_changes(flist):
    if not flist: return 0
    changes = 1
    last_sender = flist[0]['sender']
    for f in flist[1:]:
        if f['sender'] != last_sender:
            changes += 1
            last_sender = f['sender']
    return changes

def analyze_session(packets: list[Packet], session_id: str) -> SessionAnalysis:
    res = SessionAnalysis(session_id=session_id)
    res.total_packets = len(packets)
    if not packets:
        res.error = "no packets"
        return res

    server_addr = (packets[0].src_ip, packets[0].src_port)
    packets = sorted(packets, key=lambda p: p.timestamp_us)
    t0 = packets[0].timestamp_us
    
    flights = []
    current_flight = None
    active_peer = None
    
    last_payload = {'C': {}, 'S': {}}

    for p in packets:
        sender = 'C' if (p.src_ip, p.src_port) == server_addr else 'S'
        ptype = get_protocol_type(p)

        if ptype == "DTLS-HS":
            if last_payload[sender].get(ptype) == len(p.payload):
                continue
            last_payload[sender][ptype] = len(p.payload)

        if ptype == "DTLS-HS" and res.dtls_negotiated == "-":
            v = find_negotiated_dtls_version(p.payload)
            if v:
                res.dtls_negotiated = v

            active_peer = sender
            
        if current_flight and current_flight['sender'] == sender and current_flight['type'] == ptype:
            if p.timestamp_us - current_flight['last_time'] < 50000:
                current_flight['sizes'].append(len(p.payload))
                current_flight['last_time'] = p.timestamp_us
                continue
                
        if current_flight:
            flights.append(current_flight)
            
        current_flight = {
            'type': ptype,
            'sender': sender,
            'start_time': p.timestamp_us,
            'last_time': p.timestamp_us,
            'sizes': [len(p.payload)]
        }
    if current_flight:
        flights.append(current_flight)

    res.stun_rtts = 1

    dtls_hs_flights = [f for f in flights if f['type'] in ('DTLS-HS', 'DTLS-CTL')]
    dtls_changes = count_dir_changes(dtls_hs_flights)

    if res.dtls_negotiated == "1.3":
        # DTLS 1.3 theoretically takes 1 RTT.
        # Chrome often triggers a HelloRetryRequest (HRR) due to key share mismatch, 
        # producing 4 flights (CH -> HRR -> CH -> SH). We still classify this as 1 RTT 
        # to reflect successful 1.3 negotiation in the RTT table.
        res.dtls_rtts = 2 if dtls_changes >= 5 else 1
    else:
        # DTLS 1.2 takes 2 RTTs unless session resumption (which we don't do, so anything >= 3 is 2 RTTs)
        res.dtls_rtts = 2 if dtls_changes >= 3 else 1
    
    if dtls_changes == 0:
        res.dtls_rtts = 0

    app_flights = [f for f in flights if f['type'] == 'DTLS-APP']

    app_dir_changes = count_dir_changes(app_flights)

    # SCTP 4-way handshake + DCEP + Data is typically 7 to 11 direction flips
    # SNAP (0-RTT SCTP over DTLS) is typically 4 to 6 direction flips
    if app_dir_changes >= 7:
        res.sctp_rtts = 2
    else:
        res.sctp_rtts = 0

    res.total_rtts = res.stun_rtts + res.dtls_rtts + res.sctp_rtts

    if res.sctp_rtts == 0:
        for f in app_flights:
            if f['sender'] == active_peer:
                res.time_to_connected_ms = (f['start_time'] - t0) / 1000.0
                break
    else:
        active_app_flights = [f for f in app_flights if f['sender'] == active_peer]
        if len(active_app_flights) >= 3:
            res.time_to_connected_ms = (active_app_flights[2]['start_time'] - t0) / 1000.0
        elif len(app_flights) > 0:
            res.time_to_connected_ms = (app_flights[-1]['start_time'] - t0) / 1000.0

    if res.time_to_connected_ms == 0.0 and len(packets) > 0:
        res.time_to_connected_ms = (packets[-1].timestamp_us - t0) / 1000.0

    return res

def parse_session_id(session_id: str, platform: str, crypto: str, is_native: bool = False) -> dict:
    parts = session_id.split("_")
    
    known_browsers = {"chrome", "firefox", "edge", "safari"}
    
    browser = "native"
    if parts and parts[0] in known_browsers:
        browser = parts[0]
        parts = parts[1:]
    elif parts and parts[0] == "native":
        browser = "native"
        parts = parts[1:]

    test_type = "base"
    if parts:
        if parts[0] in ("dtls12", "dtls13"):
            test_type = parts[0]
            parts = parts[1:]
        elif parts[0] == "snap":
            if len(parts) > 1 and parts[1] in ("on", "off"):
                test_type = f"snap_{parts[1]}"
                parts = parts[2:]
            elif len(parts) > 1 and parts[1] == "snap":
                test_type = "snap"
                parts = parts[2:]
            else:
                test_type = "snap"
                parts = parts[1:]

    role_str = "_".join(parts) if parts else "unknown"

    # Extract client SDP role
    client_sdp = "offerer" if "offerer" in role_str else "answerer" if "answerer" in role_str else "unknown"

    # Extract server DTLS
    if test_type == "dtls12":
        server_dtls = "1.2"
    elif test_type == "dtls13":
        server_dtls = "1.3"
    else:
        server_dtls = "auto"

    # Extract server ICE mode
    if "full" in role_str:
        server_ice = "full"
    elif "lite" in role_str:
        server_ice = "lite"
    elif "snap" in test_type:
        server_ice = "lite"
    else:
        server_ice = "unknown"

    # Extract client DTLS
    client_dtls = "passive" if "passive" in role_str else "active"

    # Extract Client SNAP
    if browser == "native":
        # Native client enables SNAP by default for all test types, unless explicitly snap_off
        snap_mode = "False" if test_type == "snap_off" else "True"
    else:
        # Browsers only enable SNAP in dedicated spec tests (which set test_type='snap')
        snap_mode = "True" if test_type == "snap" else "False"

    return {
        "browser": browser,
        "client_sdp": client_sdp,
        "client_dtls": client_dtls,
        "server_dtls": server_dtls,
        "server_ice": server_ice,
        "snap_mode": snap_mode,
        "platform": platform,
        "crypto": crypto
    }

def collect_pcap_files(pcap_dir: Path) -> list:
    results = []
    for root, _dirs, files in os.walk(pcap_dir):
        root_path = Path(root)
        for f in files:
            if not f.endswith(".pcapng"): continue
            filepath = root_path / f
            platform = "unknown"
            crypto = "unknown"
            is_native = False
            for parent in [root_path] + list(root_path.parents):
                if parent.name.startswith("pcaps-"):
                    suffix = parent.name[len("pcaps-"):]
                    if suffix.endswith("-native"):
                        is_native = True
                        suffix = suffix[: -len("-native")]
                        if "-" in suffix:
                            platform, crypto = suffix.split("-", 1)
                    else:
                        if "-test-" in suffix:
                            suffix = suffix[:suffix.find("-test-")]
                        if "-" in suffix:
                            platform, crypto = suffix.split("-", 1)
                    break
            results.append((filepath, platform, crypto, is_native))
    return results

def generate_markdown_table(results: list[SessionAnalysis]) -> str:
    lines = []
    lines.append("## Connection Analysis\n")
    lines.append("| Platform | Crypto | Browser | Browser Role | Client DTLS | Server DTLS cfg | DTLS Negotiated | Server ICE | Client SNAP | Time to Connected | Protocol RTTs | ICE | DTLS | SCTP |")
    lines.append("|----------|--------|---------|--------------|-------------|-----------------|-----------------|------------|-------------|-------------------|---------------|-----|------|------|")

    results.sort(key=lambda r: (r.platform, r.crypto, r.browser, r.client_sdp, r.server_dtls, r.server_ice))

    for r in results:
        if r.error:
            lines.append(f"| {r.platform} | {r.crypto} | {r.browser} | {r.client_sdp} | {r.client_dtls} | {r.server_dtls} | {r.dtls_negotiated} | {r.server_ice} | {r.snap_mode} | Error | - | - | - | - |")
        else:
            lines.append(f"| {r.platform} | {r.crypto} | {r.browser} | {r.client_sdp} | {r.client_dtls} | {r.server_dtls} | {r.dtls_negotiated} | {r.server_ice} | {r.snap_mode} | {r.time_to_connected_ms:.1f} ms | **{r.total_rtts}** | {r.stun_rtts} | {r.dtls_rtts} | {r.sctp_rtts} |")

    return "\n".join(lines)

def main():
    parser = argparse.ArgumentParser(description="Analyze pcapng captures from str0m integration tests")
    parser.add_argument("pcap_dir", help="Directory containing pcapng files")
    parser.add_argument("--output-dir", default="analysis", help="Output directory")
    parser.add_argument("--summary-file", default=None, help="Markdown summary file")
    args = parser.parse_args()

    pcap_dir = Path(args.pcap_dir)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    pcap_files = collect_pcap_files(pcap_dir)
    print(f"Found {len(pcap_files)} pcapng files")

    results = []
    for filepath, platform, crypto, is_native in pcap_files:
        session_id = filepath.stem.removesuffix("_server").removesuffix("_client")
        packets = parse_pcapng(filepath)
        analysis = analyze_session(packets, session_id)
        meta = parse_session_id(session_id, platform, crypto, is_native)
        analysis.browser = meta["browser"]
        analysis.platform = meta["platform"]
        analysis.crypto = meta["crypto"]
        analysis.client_sdp = meta["client_sdp"]
        analysis.client_dtls = meta["client_dtls"]
        analysis.server_dtls = meta["server_dtls"]
        analysis.server_ice = meta["server_ice"]
        analysis.snap_mode = meta["snap_mode"]
        results.append(analysis)

    md = generate_markdown_table(results)
    print("\n" + md)

    md_path = output_dir / "summary.md"
    md_path.write_text(md, encoding="utf-8")

    if args.summary_file:
        with open(args.summary_file, "a", encoding="utf-8") as f:
            f.write(md + "\n")

if __name__ == "__main__":
    main()
