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

    # DTLS record layer: content types 20-25 (decimal: 0x14-0x19)
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

    # DTLS 1.3 unified header: first byte = 0b001CSLEE (0x20-0x3F)
    # All records using the unified header are encrypted.
    if 0x20 <= first <= 0x3F:
        return "DTLS-APP"

    return "OTHER"


def _dtls_epoch(payload: bytes) -> int | None:
    """Extract the DTLS epoch from a record header.

    Supports both the traditional DTLS record format and the DTLS 1.3
    unified header.

    Traditional format:
      type(1) + version(2) + epoch(2) + seq(6) + length(2) = 13 bytes
      epoch is a big-endian uint16 at offset 3.

    Unified header (DTLS 1.3):
      First byte = 0b001CSLEE
      epoch is the lowest 2 bits of the first byte.
    """
    if not payload:
        return None
    first = payload[0]
    # Traditional DTLS record (content_type 20-25 decimal = 0x14-0x19)
    if 20 <= first <= 25 and len(payload) >= 13:
        return struct.unpack_from(">H", payload, 3)[0]
    # DTLS 1.3 unified header: 0b001xxxxx = 0x20-0x3F
    if 0x20 <= first <= 0x3F:
        return first & 0x03
    return None


# ---------------------------------------------------------------------------
# TLS / DTLS ClientHello parsing
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Comprehensive cipher suite registry for DTLS 1.2 and DTLS 1.3
# ---------------------------------------------------------------------------
CIPHER_SUITE_NAMES: dict[int, str] = {
    # === DTLS 1.3 / TLS 1.3 cipher suites (RFC 8446, RFC 9147) ===
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",

    # === DTLS 1.2 / TLS 1.2 ECDHE cipher suites ===
    # ECDHE-ECDSA (RFC 4492, RFC 5289, RFC 6367)
    0xC006: "TLS_ECDHE_ECDSA_WITH_NULL_SHA",
    0xC007: "TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
    0xC008: "TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC009: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
    0xC00A: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
    0xC023: "TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC024: "TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC02B: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02C: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xCCA9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC0AC: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM",
    0xC0AD: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM",
    0xC0AE: "TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8",
    0xC0AF: "TLS_ECDHE_ECDSA_WITH_AES_256_CCM_8",
    0xC048: "TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
    0xC049: "TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
    0xC05C: "TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
    0xC05D: "TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
    0xC072: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xC073: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
    0xC086: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC087: "TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",

    # ECDHE-RSA (RFC 4492, RFC 5289)
    0xC010: "TLS_ECDHE_RSA_WITH_NULL_SHA",
    0xC011: "TLS_ECDHE_RSA_WITH_RC4_128_SHA",
    0xC012: "TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
    0xC014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
    0xC027: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
    0xC028: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
    0xC02F: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xC030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCA8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC04A: "TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
    0xC04B: "TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
    0xC05E: "TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
    0xC05F: "TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
    0xC076: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
    0xC077: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
    0xC08A: "TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
    0xC08B: "TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",

    # DHE-RSA (RFC 5246, RFC 5288, RFC 6655)
    0x0033: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
    0x0039: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
    0x0067: "TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
    0x006B: "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
    0x009E: "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    0x009F: "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    0xCCAA: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xC09E: "TLS_DHE_RSA_WITH_AES_128_CCM",
    0xC09F: "TLS_DHE_RSA_WITH_AES_256_CCM",
    0xC0A2: "TLS_DHE_RSA_WITH_AES_128_CCM_8",
    0xC0A3: "TLS_DHE_RSA_WITH_AES_256_CCM_8",
    0x0016: "TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",

    # DHE-DSS
    0x0032: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
    0x0038: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
    0x0040: "TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
    0x006A: "TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
    0x00A2: "TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
    0x00A3: "TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",

    # ECDH-ECDSA (static, RFC 4492)
    0xC001: "TLS_ECDH_ECDSA_WITH_NULL_SHA",
    0xC002: "TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
    0xC003: "TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
    0xC004: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
    0xC005: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
    0xC025: "TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
    0xC026: "TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
    0xC02D: "TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
    0xC02E: "TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",

    # ECDH-RSA (static, RFC 4492)
    0xC00B: "TLS_ECDH_RSA_WITH_NULL_SHA",
    0xC00C: "TLS_ECDH_RSA_WITH_RC4_128_SHA",
    0xC00D: "TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
    0xC00E: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
    0xC00F: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
    0xC029: "TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
    0xC02A: "TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
    0xC031: "TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
    0xC032: "TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",

    # PSK suites (RFC 4279, RFC 5487, RFC 5489, RFC 6655, RFC 7905)
    0x008C: "TLS_PSK_WITH_AES_128_CBC_SHA",
    0x008D: "TLS_PSK_WITH_AES_256_CBC_SHA",
    0x00AE: "TLS_PSK_WITH_AES_128_CBC_SHA256",
    0x00AF: "TLS_PSK_WITH_AES_256_CBC_SHA384",
    0x00A8: "TLS_PSK_WITH_AES_128_GCM_SHA256",
    0x00A9: "TLS_PSK_WITH_AES_256_GCM_SHA384",
    0xC0A4: "TLS_PSK_WITH_AES_128_CCM",
    0xC0A5: "TLS_PSK_WITH_AES_256_CCM",
    0xC0A8: "TLS_PSK_WITH_AES_128_CCM_8",
    0xC0A9: "TLS_PSK_WITH_AES_256_CCM_8",
    0xCCAB: "TLS_PSK_WITH_CHACHA20_POLY1305_SHA256",
    0x008A: "TLS_PSK_WITH_RC4_128_SHA",
    0x008B: "TLS_PSK_WITH_3DES_EDE_CBC_SHA",
    0x002C: "TLS_PSK_WITH_NULL_SHA",
    0x00B0: "TLS_PSK_WITH_NULL_SHA256",
    0x00B1: "TLS_PSK_WITH_NULL_SHA384",

    # DHE-PSK (RFC 4279, RFC 5487, RFC 6655, RFC 7905)
    0x0090: "TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
    0x0091: "TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
    0x00B2: "TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
    0x00B3: "TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
    0x00AA: "TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
    0x00AB: "TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
    0xC0A6: "TLS_DHE_PSK_WITH_AES_128_CCM",
    0xC0A7: "TLS_DHE_PSK_WITH_AES_256_CCM",
    0xCCAD: "TLS_DHE_PSK_WITH_CHACHA20_POLY1305_SHA256",

    # ECDHE-PSK (RFC 5489, RFC 7905, RFC 8442)
    0xC033: "TLS_ECDHE_PSK_WITH_RC4_128_SHA",
    0xC034: "TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
    0xC035: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
    0xC036: "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
    0xC037: "TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
    0xC038: "TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
    0xD001: "TLS_ECDHE_PSK_WITH_AES_128_GCM_SHA256",
    0xD002: "TLS_ECDHE_PSK_WITH_AES_256_GCM_SHA384",
    0xCCAC: "TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256",
    0xD005: "TLS_ECDHE_PSK_WITH_AES_128_CCM_SHA256",

    # RSA suites (RFC 5246, RFC 5288)
    0x002F: "TLS_RSA_WITH_AES_128_CBC_SHA",
    0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
    0x003C: "TLS_RSA_WITH_AES_128_CBC_SHA256",
    0x003D: "TLS_RSA_WITH_AES_256_CBC_SHA256",
    0x009C: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009D: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xC09C: "TLS_RSA_WITH_AES_128_CCM",
    0xC09D: "TLS_RSA_WITH_AES_256_CCM",
    0xC0A0: "TLS_RSA_WITH_AES_128_CCM_8",
    0xC0A1: "TLS_RSA_WITH_AES_256_CCM_8",
    0x000A: "TLS_RSA_WITH_3DES_EDE_CBC_SHA",
    0x0004: "TLS_RSA_WITH_RC4_128_MD5",
    0x0005: "TLS_RSA_WITH_RC4_128_SHA",
    0x0000: "TLS_NULL_WITH_NULL_NULL",
    0x003B: "TLS_RSA_WITH_NULL_SHA256",

    # Signalling cipher suite values
    0x00FF: "TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
    0x5600: "TLS_FALLBACK_SCSV",

    # GREASE values (RFC 8701) — browsers send these to test extension tolerance
    0x0A0A: "GREASE (0x0A0A)",
    0x1A1A: "GREASE (0x1A1A)",
    0x2A2A: "GREASE (0x2A2A)",
    0x3A3A: "GREASE (0x3A3A)",
    0x4A4A: "GREASE (0x4A4A)",
    0x5A5A: "GREASE (0x5A5A)",
    0x6A6A: "GREASE (0x6A6A)",
    0x7A7A: "GREASE (0x7A7A)",
    0x8A8A: "GREASE (0x8A8A)",
    0x9A9A: "GREASE (0x9A9A)",
    0xAAAA: "GREASE (0xAAAA)",
    0xBABA: "GREASE (0xBABA)",
    0xCACA: "GREASE (0xCACA)",
    0xDADA: "GREASE (0xDADA)",
    0xEAEA: "GREASE (0xEAEA)",
    0xFAFA: "GREASE (0xFAFA)",
}

# ---------------------------------------------------------------------------
# Named groups / supported_groups (DTLS 1.2 & 1.3)
# ---------------------------------------------------------------------------
NAMED_GROUP_NAMES: dict[int, str] = {
    # Elliptic curves (RFC 4492, RFC 8422)
    0x0001: "sect163k1",
    0x0002: "sect163r1",
    0x0003: "sect163r2",
    0x0004: "sect193r1",
    0x0005: "sect193r2",
    0x0006: "sect233k1",
    0x0007: "sect233r1",
    0x0008: "sect239k1",
    0x0009: "sect283k1",
    0x000A: "sect283r1",
    0x000B: "sect409k1",
    0x000C: "sect409r1",
    0x000D: "sect571k1",
    0x000E: "sect571r1",
    0x000F: "secp160k1",
    0x0010: "secp160r1",
    0x0011: "secp160r2",
    0x0012: "secp192k1",
    0x0013: "secp192r1",
    0x0014: "secp224k1",
    0x0015: "secp224r1",
    0x0016: "secp256k1",
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001D: "x25519",
    0x001E: "x448",
    0x001F: "brainpoolP256r1tls13",
    0x0020: "brainpoolP384r1tls13",
    0x0021: "brainpoolP512r1tls13",
    0x0022: "GC256A",
    0x0023: "GC256B",
    0x0024: "GC256C",
    0x0025: "GC256D",
    0x0026: "GC512A",
    0x0027: "GC512B",
    0x0028: "GC512C",
    # Finite field groups (RFC 7919)
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
    0x0103: "ffdhe6144",
    0x0104: "ffdhe8192",
    # Post-quantum / hybrid (TLS WG, IANA assignments)
    0x0200: "secp256r1_mlkem768",
    0x0201: "x25519_mlkem768",  # note: also used for sig_algs, context-dependent
    0x11EB: "ML-KEM-512",
    0x11EC: "ML-KEM-768",
    0x11ED: "ML-KEM-1024",
    0x4588: "X25519MLKEM768",
    0x6399: "X25519Kyber768Draft00",
    0x639A: "SecP256r1Kyber768Draft00",
    # GREASE (RFC 8701)
    0x0A0A: "GREASE (0x0A0A)",
    0x1A1A: "GREASE (0x1A1A)",
    0x2A2A: "GREASE (0x2A2A)",
    0x3A3A: "GREASE (0x3A3A)",
    0x4A4A: "GREASE (0x4A4A)",
    0x5A5A: "GREASE (0x5A5A)",
    0x6A6A: "GREASE (0x6A6A)",
    0x7A7A: "GREASE (0x7A7A)",
    0x8A8A: "GREASE (0x8A8A)",
    0x9A9A: "GREASE (0x9A9A)",
    0xAAAA: "GREASE (0xAAAA)",
    0xBABA: "GREASE (0xBABA)",
    0xCACA: "GREASE (0xCACA)",
    0xDADA: "GREASE (0xDADA)",
    0xEAEA: "GREASE (0xEAEA)",
    0xFAFA: "GREASE (0xFAFA)",
}

# ---------------------------------------------------------------------------
# Signature algorithms (DTLS 1.2 & 1.3, RFC 8446 §4.2.3)
# ---------------------------------------------------------------------------
SIG_ALG_NAMES: dict[int, str] = {
    # RSASSA-PKCS1-v1_5 (DTLS 1.2 only, forbidden in 1.3 for handshake)
    0x0201: "rsa_pkcs1_sha1",
    0x0401: "rsa_pkcs1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    # ECDSA
    0x0203: "ecdsa_sha1",
    0x0403: "ecdsa_secp256r1_sha256",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0603: "ecdsa_secp521r1_sha512",
    # RSASSA-PSS with rsaEncryption OID (DTLS 1.2 & 1.3)
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    # EdDSA (DTLS 1.3)
    0x0807: "ed25519",
    0x0808: "ed448",
    # RSASSA-PSS with RSASSA-PSS OID (DTLS 1.3)
    0x0809: "rsa_pss_pss_sha256",
    0x080A: "rsa_pss_pss_sha384",
    0x080B: "rsa_pss_pss_sha512",
    # Legacy (hash+sign = SHA-224)
    0x0301: "rsa_pkcs1_sha224",
    0x0302: "dsa_sha224",
    0x0303: "ecdsa_sha224",
    # DSA (rare, but in the IANA registry)
    0x0202: "dsa_sha1",
    0x0402: "dsa_sha256",
    0x0502: "dsa_sha384",
    0x0602: "dsa_sha512",
    # GREASE (RFC 8701)
    0x0A0A: "GREASE (0x0A0A)",
    0x1A1A: "GREASE (0x1A1A)",
    0x2A2A: "GREASE (0x2A2A)",
    0x3A3A: "GREASE (0x3A3A)",
    0x4A4A: "GREASE (0x4A4A)",
    0x5A5A: "GREASE (0x5A5A)",
    0x6A6A: "GREASE (0x6A6A)",
    0x7A7A: "GREASE (0x7A7A)",
    0x8A8A: "GREASE (0x8A8A)",
    0x9A9A: "GREASE (0x9A9A)",
    0xAAAA: "GREASE (0xAAAA)",
    0xBABA: "GREASE (0xBABA)",
    0xCACA: "GREASE (0xCACA)",
    0xDADA: "GREASE (0xDADA)",
    0xEAEA: "GREASE (0xEAEA)",
    0xFAFA: "GREASE (0xFAFA)",
}

# TLS / DTLS version values
TLS_VERSION_NAMES: dict[int, str] = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3",
    0xFEFF: "DTLS 1.0",
    0xFEFD: "DTLS 1.2",
    0xFEFC: "DTLS 1.3",  # not actually used on the wire; negotiated via supported_versions
    # GREASE (RFC 8701)
    0x0A0A: "GREASE",
    0x1A1A: "GREASE",
    0x2A2A: "GREASE",
    0x3A3A: "GREASE",
    0x4A4A: "GREASE",
    0x5A5A: "GREASE",
    0x6A6A: "GREASE",
    0x7A7A: "GREASE",
    0x8A8A: "GREASE",
    0x9A9A: "GREASE",
    0xAAAA: "GREASE",
    0xBABA: "GREASE",
    0xCACA: "GREASE",
    0xDADA: "GREASE",
    0xEAEA: "GREASE",
    0xFAFA: "GREASE",
}

# SRTP protection profile names (RFC 5764, RFC 7714)
SRTP_PROFILE_NAMES: dict[int, str] = {
    0x0001: "SRTP_AES128_CM_HMAC_SHA1_80",
    0x0002: "SRTP_AES128_CM_HMAC_SHA1_32",
    0x0005: "SRTP_NULL_HMAC_SHA1_80",
    0x0006: "SRTP_NULL_HMAC_SHA1_32",
    0x0007: "SRTP_AEAD_AES_128_GCM",
    0x0008: "SRTP_AEAD_AES_256_GCM",
    0x000C: "DOUBLE_AEAD_AES_128_GCM_AEAD_AES_128_GCM",
    0x000D: "DOUBLE_AEAD_AES_256_GCM_AEAD_AES_256_GCM",
}

# EC point formats
EC_POINT_FORMAT_NAMES: dict[int, str] = {
    0: "uncompressed",
    1: "ansiX962_compressed_prime",
    2: "ansiX962_compressed_char2",
}

# Well-known extension type names
EXTENSION_TYPE_NAMES: dict[int, str] = {
    0: "server_name",
    1: "max_fragment_length",
    2: "client_certificate_url",
    3: "trusted_ca_keys",
    4: "truncated_hmac",
    5: "status_request",
    6: "user_mapping",
    7: "client_authz",
    8: "server_authz",
    9: "cert_type",
    10: "supported_groups",
    11: "ec_point_formats",
    12: "srp",
    13: "signature_algorithms",
    14: "use_srtp",
    15: "heartbeat",
    16: "application_layer_protocol_negotiation",
    17: "status_request_v2",
    18: "signed_certificate_timestamp",
    19: "client_certificate_type",
    20: "server_certificate_type",
    21: "padding",
    22: "encrypt_then_mac",
    23: "extended_master_secret",
    24: "token_binding",
    25: "cached_info",
    27: "compress_certificate",
    28: "record_size_limit",
    35: "session_ticket",
    41: "pre_shared_key",
    42: "early_data",
    43: "supported_versions",
    44: "cookie",
    45: "psk_key_exchange_modes",
    47: "certificate_authorities",
    48: "oid_filters",
    49: "post_handshake_auth",
    50: "signature_algorithms_cert",
    51: "key_share",
    53: "connection_id",
    54: "connection_id_deprecated",
    57: "quic_transport_parameters",
    0x0044: "delegated_credentials",
    0xFF01: "renegotiation_info",
    # GREASE (RFC 8701)
    0x0A0A: "GREASE",
    0x1A1A: "GREASE",
    0x2A2A: "GREASE",
    0x3A3A: "GREASE",
    0x4A4A: "GREASE",
    0x5A5A: "GREASE",
    0x6A6A: "GREASE",
    0x7A7A: "GREASE",
    0x8A8A: "GREASE",
    0x9A9A: "GREASE",
    0xAAAA: "GREASE",
    0xBABA: "GREASE",
    0xCACA: "GREASE",
    0xDADA: "GREASE",
    0xEAEA: "GREASE",
    0xFAFA: "GREASE",
}


@dataclass
class ClientHelloCrypto:
    """Crypto parameters offered in a DTLS/TLS ClientHello."""
    record_version: str = ""
    client_version: str = ""
    cipher_suites: list[str] = field(default_factory=list)
    compression_methods: list[int] = field(default_factory=list)
    supported_versions: list[str] = field(default_factory=list)
    supported_groups: list[str] = field(default_factory=list)
    signature_algorithms: list[str] = field(default_factory=list)
    ec_point_formats: list[str] = field(default_factory=list)
    key_share_groups: list[str] = field(default_factory=list)
    srtp_profiles: list[int] = field(default_factory=list)
    alpn_protocols: list[str] = field(default_factory=list)
    extensions_present: list[str] = field(default_factory=list)
    raw_cipher_suite_ids: list[int] = field(default_factory=list)


def _parse_extensions(data: bytes, offset: int, length: int) -> dict[int, bytes]:
    """Parse TLS extensions and return {type: data} dict."""
    extensions: dict[int, bytes] = {}
    end = offset + length
    while offset + 4 <= end:
        ext_type = struct.unpack_from(">H", data, offset)[0]
        ext_len = struct.unpack_from(">H", data, offset + 2)[0]
        offset += 4
        if offset + ext_len > end:
            break
        extensions[ext_type] = data[offset : offset + ext_len]
        offset += ext_len
    return extensions


def parse_dtls_client_hello(payload: bytes) -> ClientHelloCrypto | None:
    """Parse a DTLS ClientHello from a raw UDP payload.

    Walks through DTLS record(s) in the payload looking for one with
    handshake type = 1 (ClientHello) and extracts crypto parameters.
    Returns None if no ClientHello is found.
    """
    result = ClientHelloCrypto()
    pos = 0

    while pos + 13 <= len(payload):
        content_type = payload[pos]
        if content_type != 22:  # Not a Handshake record
            # Skip to next record
            if pos + 13 <= len(payload):
                rec_len = struct.unpack_from(">H", payload, pos + 11)[0]
                pos += 13 + rec_len
                continue
            break

        # DTLS record header
        rec_version = struct.unpack_from(">H", payload, pos + 1)[0]
        rec_len = struct.unpack_from(">H", payload, pos + 11)[0]
        rec_start = pos + 13

        result.record_version = TLS_VERSION_NAMES.get(rec_version, f"0x{rec_version:04X}")

        # DTLS handshake header: 12 bytes
        hs_offset = rec_start
        if hs_offset + 12 > len(payload):
            pos += 13 + rec_len
            continue

        hs_type = payload[hs_offset]
        hs_length = (payload[hs_offset + 1] << 16) | (payload[hs_offset + 2] << 8) | payload[hs_offset + 3]
        frag_offset = (payload[hs_offset + 6] << 16) | (payload[hs_offset + 7] << 8) | payload[hs_offset + 8]

        if hs_type != 1 or frag_offset != 0:
            # Not ClientHello or fragmented — skip record
            pos += 13 + rec_len
            continue

        # ClientHello body starts after 12-byte handshake header
        ch = payload[hs_offset + 12:]
        idx = 0

        # client_version (2)
        if idx + 2 > len(ch):
            return None
        cv = struct.unpack_from(">H", ch, idx)[0]
        result.client_version = TLS_VERSION_NAMES.get(cv, f"0x{cv:04X}")
        idx += 2

        # random (32)
        idx += 32
        if idx > len(ch):
            return None

        # session_id
        if idx + 1 > len(ch):
            return None
        sid_len = ch[idx]
        idx += 1 + sid_len

        # cookie (DTLS only)
        if idx + 1 > len(ch):
            return None
        cookie_len = ch[idx]
        idx += 1 + cookie_len

        # cipher_suites
        if idx + 2 > len(ch):
            return None
        cs_len = struct.unpack_from(">H", ch, idx)[0]
        idx += 2
        if idx + cs_len > len(ch):
            return None
        for i in range(0, cs_len, 2):
            suite_id = struct.unpack_from(">H", ch, idx + i)[0]
            result.raw_cipher_suite_ids.append(suite_id)
            name = CIPHER_SUITE_NAMES.get(suite_id, f"0x{suite_id:04X}")
            result.cipher_suites.append(name)
        idx += cs_len

        # compression_methods
        if idx + 1 > len(ch):
            return result  # partial parse is fine
        cm_len = ch[idx]
        idx += 1
        if idx + cm_len > len(ch):
            return result
        result.compression_methods = list(ch[idx : idx + cm_len])
        idx += cm_len

        # extensions
        if idx + 2 > len(ch):
            return result
        ext_total_len = struct.unpack_from(">H", ch, idx)[0]
        idx += 2
        if idx + ext_total_len > len(ch):
            ext_total_len = len(ch) - idx  # best effort

        extensions = _parse_extensions(ch, idx, ext_total_len)

        # Record which extensions are present
        for ext_type in sorted(extensions.keys()):
            name = EXTENSION_TYPE_NAMES.get(ext_type, f"unknown(0x{ext_type:04X})")
            result.extensions_present.append(name)

        # supported_versions (ext 43)
        if 43 in extensions:
            sv_data = extensions[43]
            if sv_data and len(sv_data) >= 1:
                sv_list_len = sv_data[0]
                for i in range(1, 1 + sv_list_len, 2):
                    if i + 2 <= len(sv_data):
                        ver = struct.unpack_from(">H", sv_data, i)[0]
                        result.supported_versions.append(
                            TLS_VERSION_NAMES.get(ver, f"0x{ver:04X}")
                        )

        # supported_groups (ext 10)
        if 10 in extensions:
            sg_data = extensions[10]
            if len(sg_data) >= 2:
                sg_list_len = struct.unpack_from(">H", sg_data, 0)[0]
                for i in range(2, 2 + sg_list_len, 2):
                    if i + 2 <= len(sg_data):
                        gid = struct.unpack_from(">H", sg_data, i)[0]
                        result.supported_groups.append(
                            NAMED_GROUP_NAMES.get(gid, f"0x{gid:04X}")
                        )

        # signature_algorithms (ext 13)
        if 13 in extensions:
            sa_data = extensions[13]
            if len(sa_data) >= 2:
                sa_list_len = struct.unpack_from(">H", sa_data, 0)[0]
                for i in range(2, 2 + sa_list_len, 2):
                    if i + 2 <= len(sa_data):
                        sig = struct.unpack_from(">H", sa_data, i)[0]
                        result.signature_algorithms.append(
                            SIG_ALG_NAMES.get(sig, f"0x{sig:04X}")
                        )

        # ec_point_formats (ext 11)
        if 11 in extensions:
            ep_data = extensions[11]
            if ep_data and len(ep_data) >= 1:
                ep_count = ep_data[0]
                for i in range(1, 1 + ep_count):
                    if i < len(ep_data):
                        result.ec_point_formats.append(
                            EC_POINT_FORMAT_NAMES.get(ep_data[i], f"0x{ep_data[i]:02X}")
                        )

        # key_share (ext 51) — extract just which groups have key shares
        if 51 in extensions:
            ks_data = extensions[51]
            if len(ks_data) >= 2:
                ks_list_len = struct.unpack_from(">H", ks_data, 0)[0]
                ki = 2
                while ki + 4 <= 2 + ks_list_len and ki + 4 <= len(ks_data):
                    ks_group = struct.unpack_from(">H", ks_data, ki)[0]
                    ks_kex_len = struct.unpack_from(">H", ks_data, ki + 2)[0]
                    result.key_share_groups.append(
                        NAMED_GROUP_NAMES.get(ks_group, f"0x{ks_group:04X}")
                    )
                    ki += 4 + ks_kex_len

        # use_srtp (ext 14)
        if 14 in extensions:
            srtp_data = extensions[14]
            if len(srtp_data) >= 2:
                srtp_len = struct.unpack_from(">H", srtp_data, 0)[0]
                for i in range(2, 2 + srtp_len, 2):
                    if i + 2 <= len(srtp_data):
                        profile = struct.unpack_from(">H", srtp_data, i)[0]
                        result.srtp_profiles.append(profile)

        # ALPN (ext 16)
        if 16 in extensions:
            alpn_data = extensions[16]
            if len(alpn_data) >= 2:
                alpn_list_len = struct.unpack_from(">H", alpn_data, 0)[0]
                ai = 2
                while ai < 2 + alpn_list_len and ai < len(alpn_data):
                    proto_len = alpn_data[ai]
                    ai += 1
                    if ai + proto_len <= len(alpn_data):
                        result.alpn_protocols.append(
                            alpn_data[ai : ai + proto_len].decode("ascii", errors="replace")
                        )
                    ai += proto_len

        return result

        # Move to next record (normally we return above)
        pos += 13 + rec_len

    return None


def detect_dtls_version(classified: list[tuple["Packet", str, str]]) -> str:
    """Detect DTLS version from the handshake packets.

    DTLS 1.3 is detected by looking at the record-layer version field and
    the handshake pattern.  In DTLS 1.3:
      - ClientHello record has version 0xFEFD (same as 1.2 for compat)
      - ServerHello record has version 0xFEFD but the supported_versions
        extension inside says 0x0304.
      - After the ServerHello (DTLS-HS), the rest of the server's flight
        is sent as encrypted records (content_type=23, i.e. DTLS-APP).
      - There is NO ChangeCipherSpec (DTLS-CCS) in DTLS 1.3.

    In DTLS 1.2 we always see a CCS record before the encrypted Finished.

    So the simplest reliable heuristic: if there is a CCS record it's 1.2,
    if there isn't it's 1.3 (assuming there IS a DTLS-HS record).
    """
    has_hs = False
    has_ccs = False
    for _, proto, _ in classified:
        if proto == "DTLS-HS":
            has_hs = True
        elif proto == "DTLS-CCS":
            has_ccs = True
    if not has_hs:
        return "unknown"
    return "1.2" if has_ccs else "1.3"


def _split_dtls13_handshake_and_sctp(
    classified: list[tuple["Packet", str, str]],
) -> tuple[int, int]:
    """For DTLS 1.3, figure out where encrypted handshake ends and SCTP begins.

    Uses the DTLS epoch from the record header:
      - Epoch <= 2  →  encrypted handshake (EncryptedExtensions, Certificate,
                       CertificateVerify, Finished)
      - Epoch >= 3  →  application data (SCTP, data channels)

    Returns (encrypted_hs_count, sctp_start_index) where sctp_start_index is
    the index into the DTLS-APP sub-list where SCTP begins.
    """
    dtls_app_packets = [(pkt, d) for pkt, proto, d in classified if proto == "DTLS-APP"]
    if not dtls_app_packets:
        return 0, 0

    encrypted_hs_count = 0
    for i, (pkt, _) in enumerate(dtls_app_packets):
        epoch = _dtls_epoch(pkt.payload)
        if epoch is not None and epoch <= 2:
            encrypted_hs_count += 1
        else:
            # First packet with epoch >= 3 (or unknown) marks SCTP start
            break

    return encrypted_hs_count, encrypted_hs_count


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
    dtls_version: str = ""     # "1.2", "1.3", "unknown"
    stun_rtts: int = 0         # STUN request/response pairs (ICE)
    dtls_flights: int = 0      # DTLS handshake direction changes
    dtls_rtts: float = 0       # Estimated DTLS handshake RTTs
    sctp_flights: int = 0      # SCTP handshake flights (inside DTLS-APP)
    sctp_rtts: float = 0       # Estimated SCTP handshake RTTs
    total_rtts: float = 0      # STUN + DTLS + SCTP RTTs
    phases: list[str] = field(default_factory=list)
    client_hello: ClientHelloCrypto | None = None  # Parsed ClientHello crypto
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

    # Detect DTLS version (1.2 vs 1.3)
    dtls_ver = detect_dtls_version(classified)
    result.dtls_version = dtls_ver

    # Parse ClientHello crypto from the first incoming DTLS-HS packet
    for pkt, proto, direction in classified:
        if proto == "DTLS-HS" and direction == "<-":
            ch = parse_dtls_client_hello(pkt.payload)
            if ch is not None:
                result.client_hello = ch
            break

    # Count STUN request/response pairs
    stun_requests = 0
    stun_responses = 0
    for _, proto, _ in classified:
        if proto == "STUN-REQ":
            stun_requests += 1
        elif proto == "STUN-RESP":
            stun_responses += 1
    result.stun_rtts = min(stun_requests, stun_responses)

    # --- DTLS and SCTP RTT counting ---
    dtls_app_packets = [(p, d) for p, proto, d in classified if proto == "DTLS-APP"]

    if dtls_ver == "1.3":
        # DTLS 1.3: encrypted handshake records appear as DTLS-APP.
        # Count visible DTLS-HS flights (ClientHello <-> ServerHello) plus
        # the encrypted continuation.
        #
        # The visible DTLS-HS records give us 2 flights (CH -> SH), which
        # is 1 RTT in DTLS 1.3.  The encrypted Finished records are
        # follow-up in the same RTT and don't add extra RTTs.

        dtls_hs_packets = [(p, d) for p, proto, d in classified if proto == "DTLS-HS"]
        flights = 0
        last_dir = None
        for _, d in dtls_hs_packets:
            if d != last_dir:
                flights += 1
                last_dir = d
        result.dtls_flights = flights
        # DTLS 1.3 is a 1-RTT handshake: CH -> SH+Fin <- Fin ->
        result.dtls_rtts = 1 if flights >= 2 else max(0, flights)

        # Separate encrypted handshake DTLS-APP packets from SCTP DTLS-APP packets
        encrypted_hs_count, sctp_start = _split_dtls13_handshake_and_sctp(classified)

        # SCTP packets are the DTLS-APP records after the encrypted handshake
        sctp_app_packets = dtls_app_packets[sctp_start:]

    else:
        # DTLS 1.2: standard analysis.  All DTLS-HS records are visible.
        dtls_hs_packets = [(p, d) for p, proto, d in classified if proto == "DTLS-HS"]
        flights = 0
        last_dir = None
        for _, d in dtls_hs_packets:
            if d != last_dir:
                flights += 1
                last_dir = d
        result.dtls_flights = flights
        result.dtls_rtts = max(0, (flights + 1) // 2)

        encrypted_hs_count = 0
        sctp_app_packets = dtls_app_packets

    # Count SCTP handshake flights in the SCTP portion of DTLS-APP.
    # SCTP 4-way: INIT -> INIT-ACK <- COOKIE-ECHO -> COOKIE-ACK <-
    sctp_hs_count = min(4, len(sctp_app_packets))
    sctp_flights = 0
    last_dir = None
    for _, d in sctp_app_packets[:sctp_hs_count]:
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
            if app_idx < encrypted_hs_count:
                phase = "DTLS"  # encrypted handshake (DTLS 1.3)
            elif app_idx < encrypted_hs_count + sctp_hs_count:
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
    lines.append("| Platform | Crypto | Browser | Test | Role | DTLS | STUN RTTs | DTLS RTTs | SCTP RTTs | Total RTTs | Packets | Phases |")
    lines.append("|----------|--------|---------|------|------|------|-----------|-----------|-----------|------------|---------|--------|")

    sorted_results = sorted(results, key=_sort_key)

    for r in sorted_results:
        if r.error:
            lines.append(f"| {r.platform} | {r.crypto} | {r.browser} | {r.test_type} | {r.test_role} | {r.dtls_version} | - | - | - | - | {r.total_packets} | {r.error} |")
        else:
            phases_str = " -> ".join(r.phases)
            lines.append(
                f"| {r.platform} | {r.crypto} | {r.browser} | {r.test_type} | {r.test_role} "
                f"| {r.dtls_version} "
                f"| {r.stun_rtts} | {r.dtls_rtts:.0f} | {r.sctp_rtts:.0f} | {r.total_rtts:.0f} "
                f"| {r.total_packets} | {phases_str} |"
            )

    lines.append("")

    # --- ClientHello Offered Crypto section ---
    ch_results = [r for r in results if r.client_hello is not None]
    if ch_results:
        lines.append("## ClientHello Offered Crypto\n")

        # Group by browser to show one entry per distinct browser
        by_browser: dict[str, list[SessionAnalysis]] = {}
        for r in ch_results:
            by_browser.setdefault(r.browser, []).append(r)

        for browser in sorted(by_browser.keys()):
            sessions = by_browser[browser]
            # Use the first session's ClientHello as representative
            ch = sessions[0].client_hello
            assert ch is not None

            lines.append(f"### {browser}\n")

            # Record / Client version
            lines.append(f"**Record version:** {ch.record_version}  ")
            lines.append(f"**Client version:** {ch.client_version}  ")
            if ch.supported_versions:
                lines.append(f"**Supported versions:** {', '.join(ch.supported_versions)}  ")
            lines.append("")

            # Cipher suites table
            lines.append("**Cipher Suites:**\n")
            lines.append("| # | ID | Name |")
            lines.append("|---|------|------|")
            for i, (sid, name) in enumerate(zip(ch.raw_cipher_suite_ids, ch.cipher_suites), 1):
                lines.append(f"| {i} | 0x{sid:04X} | {name} |")
            lines.append("")

            # Supported groups
            if ch.supported_groups:
                lines.append(f"**Supported Groups:** {', '.join(ch.supported_groups)}  ")

            # Key share groups
            if ch.key_share_groups:
                lines.append(f"**Key Share Groups:** {', '.join(ch.key_share_groups)}  ")

            # Signature algorithms
            if ch.signature_algorithms:
                lines.append(f"**Signature Algorithms:** {', '.join(ch.signature_algorithms)}  ")

            # EC point formats
            if ch.ec_point_formats:
                lines.append(f"**EC Point Formats:** {', '.join(ch.ec_point_formats)}  ")

            # SRTP profiles
            if ch.srtp_profiles:
                srtp_strs = [SRTP_PROFILE_NAMES.get(p, f"0x{p:04X}") for p in ch.srtp_profiles]
                lines.append(f"**SRTP Profiles:** {', '.join(srtp_strs)}  ")

            # ALPN
            if ch.alpn_protocols:
                lines.append(f"**ALPN Protocols:** {', '.join(ch.alpn_protocols)}  ")

            # Extensions present
            if ch.extensions_present:
                lines.append(f"**Extensions:** {', '.join(ch.extensions_present)}  ")

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
