#!/usr/bin/env python3
"""Debug script to deeply parse pcap captures and show protocol details."""
import struct
from pathlib import Path

def parse_pcapng(filepath):
    packets = []
    data = filepath.read_bytes()
    offset = 0
    while offset < len(data) - 8:
        block_type = struct.unpack_from('<I', data, offset)[0]
        block_len = struct.unpack_from('<I', data, offset + 4)[0]
        if block_len < 12 or offset + block_len > len(data): break
        if block_type == 0x00000006:
            ts_high = struct.unpack_from('<I', data, offset + 12)[0]
            ts_low = struct.unpack_from('<I', data, offset + 16)[0]
            captured_len = struct.unpack_from('<I', data, offset + 20)[0]
            timestamp_us = (ts_high << 32) | ts_low
            frame_start = offset + 28
            frame_data = data[frame_start : frame_start + captured_len]
            if len(frame_data) >= 28:
                ihl = (frame_data[0] & 0x0F) * 4
                if frame_data[9] == 17:
                    src_ip = '.'.join(str(b) for b in frame_data[12:16])
                    dst_ip = '.'.join(str(b) for b in frame_data[16:20])
                    src_port = struct.unpack_from('>H', frame_data, ihl)[0]
                    dst_port = struct.unpack_from('>H', frame_data, ihl + 2)[0]
                    udp_len = struct.unpack_from('>H', frame_data, ihl + 4)[0]
                    payload = frame_data[ihl + 8 : ihl + udp_len]
                    packets.append((timestamp_us, src_ip, src_port, dst_ip, dst_port, payload))
        offset += block_len
    return packets

def parse_stun_txn(payload):
    if len(payload) < 20: return None
    magic = struct.unpack_from('>I', payload, 4)[0]
    if magic != 0x2112A442: return None
    return payload[8:20].hex()

HS_NAMES = {1:'CH', 2:'SH', 3:'HVR', 4:'NST', 8:'EE', 11:'Cert', 12:'SKE',
            13:'CertReq', 14:'SHD', 15:'CV', 16:'CKE', 20:'Fin'}
CT_NAMES = {20:'CCS', 21:'Alert', 22:'HS', 23:'APP', 24:'HB', 25:'ACK'}

def parse_dtls_records(payload):
    records = []
    off = 0
    while off + 13 <= len(payload):
        ct = payload[off]
        if not (20 <= ct <= 25): break
        epoch = struct.unpack_from('>H', payload, off + 3)[0]
        length = struct.unpack_from('>H', payload, off + 11)[0]
        rec = {'ct': ct, 'epoch': epoch, 'len': length}
        rec_data = payload[off + 13 : off + 13 + length]
        if ct == 22 and epoch == 0 and len(rec_data) >= 12:
            hs_type = rec_data[0]
            rec['hs'] = HS_NAMES.get(hs_type, f'Unknown({hs_type})')
            rec['msg_seq'] = struct.unpack_from('>H', rec_data, 4)[0]
        records.append(rec)
        off += 13 + length
    return records

pcap_dir = Path('target/pcap')
for f in sorted(pcap_dir.glob('*.pcapng')):
    pkts = parse_pcapng(f)
    if not pkts:
        print(f'=== {f.name} (empty) ===\n')
        continue
    server_addr = (pkts[0][1], pkts[0][2])
    print(f'=== {f.name} ({len(pkts)} pkts) ===')

    # Track STUN transaction IDs
    stun_txns = {}
    dtls_hs_types = set()
    dtls_app_sizes = []

    for i, (ts, sip, sp, dip, dp, payload) in enumerate(pkts):
        d = '->' if (sip, sp) == server_addr else '<-'
        first = payload[0] if payload else -1

        if first in (0x00, 0x01) and len(payload) >= 20:
            msg_type = struct.unpack_from('>H', payload, 0)[0]
            txn = parse_stun_txn(payload)
            nm = {0x0001:'REQ', 0x0101:'RESP'}.get(msg_type, f'0x{msg_type:04x}')
            txn_short = txn[:8] if txn else 'no-magic'
            print(f'  [{i:3d}] {d} STUN-{nm:<5s} txn={txn_short}  len={len(payload)}')
            if txn:
                if txn not in stun_txns:
                    stun_txns[txn] = {'req': False, 'resp': False}
                if msg_type == 0x0001:
                    stun_txns[txn]['req'] = True
                elif msg_type == 0x0101:
                    stun_txns[txn]['resp'] = True
        elif 20 <= first <= 25:
            recs = parse_dtls_records(payload)
            parts = []
            for r in recs:
                name = CT_NAMES.get(r['ct'], f'?{r["ct"]}')
                e = f'e{r["epoch"]}'
                if 'hs' in r:
                    parts.append(f'{name}({r["hs"]},seq={r["msg_seq"]},{e})')
                    if r['epoch'] == 0:
                        dtls_hs_types.add(r.get('hs', ''))
                else:
                    parts.append(f'{name}({e},rl={r["len"]})')
                if r['ct'] == 23:
                    dtls_app_sizes.append(len(payload))
            print(f'  [{i:3d}] {d} DTLS  {" + ".join(parts)}  udp={len(payload)}')
        else:
            print(f'  [{i:3d}] {d} OTHER first=0x{first:02x}  len={len(payload)}')

    # Summary
    completed_txns = sum(1 for t in stun_txns.values() if t['req'] and t['resp'])
    has_cleartext_cert = 'Cert' in dtls_hs_types
    dtls_ver = '1.2' if has_cleartext_cert else '1.3'

    # SCTP handshake detection: look for COOKIE-ACK signature
    first_apps = dtls_app_sizes[:6]
    has_small = any(s <= 57 for s in first_apps)
    has_large = any(s > 95 for s in first_apps)
    sctp_hs = has_small and has_large

    print(f'  --- Summary ---')
    print(f'  STUN unique txns: {completed_txns} (total txns: {len(stun_txns)})')
    print(f'  DTLS HS types (cleartext): {sorted(dtls_hs_types)}')
    print(f'  DTLS version: {dtls_ver}')
    print(f'  DTLS-APP sizes (first 6): {first_apps}')
    print(f'  SCTP handshake detected: {sctp_hs} (small<=57: {has_small}, large>95: {has_large})')
    print(f'  Proposed RTTs: STUN={completed_txns}, DTLS={2 if dtls_ver=="1.2" else 1}, SCTP={2 if sctp_hs else 0}')
    print()
