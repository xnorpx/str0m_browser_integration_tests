use std::net::SocketAddr;

pub struct CapturedPacket {
    pub timestamp_us: u64,
    pub src: SocketAddr,
    pub dst: SocketAddr,
    pub payload: Vec<u8>,
}

pub fn write_pcapng(packets: &[CapturedPacket]) -> Vec<u8> {
    let mut buf = Vec::new();
    write_shb(&mut buf);
    write_idb(&mut buf);
    for pkt in packets {
        write_epb(&mut buf, pkt);
    }
    buf
}

fn put_u16(buf: &mut Vec<u8>, v: u16) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_u32(buf: &mut Vec<u8>, v: u32) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn put_u64(buf: &mut Vec<u8>, v: u64) {
    buf.extend_from_slice(&v.to_le_bytes());
}

fn write_shb(buf: &mut Vec<u8>) {
    let block_len: u32 = 28;
    put_u32(buf, 0x0A0D_0D0A); // Block Type
    put_u32(buf, block_len);
    put_u32(buf, 0x1A2B_3C4D); // Byte-Order Magic
    put_u16(buf, 1); // Major Version
    put_u16(buf, 0); // Minor Version
    put_u64(buf, 0xFFFF_FFFF_FFFF_FFFF); // Section Length (unspecified)
    put_u32(buf, block_len);
}

fn write_idb(buf: &mut Vec<u8>) {
    let block_len: u32 = 20;
    put_u32(buf, 0x0000_0001); // Block Type
    put_u32(buf, block_len);
    put_u16(buf, 101); // LinkType: LINKTYPE_RAW (raw IPv4/IPv6)
    put_u16(buf, 0); // Reserved
    put_u32(buf, 0x0000_FFFF); // SnapLen
    put_u32(buf, block_len);
}

fn write_epb(buf: &mut Vec<u8>, pkt: &CapturedPacket) {
    let frame = build_ipv4_udp_frame(pkt);
    let captured_len = frame.len() as u32;
    let padded_len = (captured_len + 3) & !3;
    let block_len = 32 + padded_len;

    let ts_high = (pkt.timestamp_us >> 32) as u32;
    let ts_low = (pkt.timestamp_us & 0xFFFF_FFFF) as u32;

    put_u32(buf, 0x0000_0006); // Block Type: EPB
    put_u32(buf, block_len);
    put_u32(buf, 0); // Interface ID
    put_u32(buf, ts_high);
    put_u32(buf, ts_low);
    put_u32(buf, captured_len);
    put_u32(buf, captured_len); // Original Packet Length
    buf.extend_from_slice(&frame);

    let padding = padded_len - captured_len;
    for _ in 0..padding {
        buf.push(0);
    }

    put_u32(buf, block_len);
}

fn build_ipv4_udp_frame(pkt: &CapturedPacket) -> Vec<u8> {
    let payload_len = pkt.payload.len();
    let udp_len = 8 + payload_len;
    let ip_total_len = 20 + udp_len;

    let src_ip = match pkt.src {
        SocketAddr::V4(a) => a.ip().octets(),
        _ => [0; 4],
    };
    let dst_ip = match pkt.dst {
        SocketAddr::V4(a) => a.ip().octets(),
        _ => [0; 4],
    };

    let mut frame = Vec::with_capacity(ip_total_len);

    frame.push(0x45); // Version (4) + IHL (5)
    frame.push(0x00); // DSCP + ECN
    frame.extend_from_slice(&(ip_total_len as u16).to_be_bytes());
    frame.extend_from_slice(&[0, 0]); // Identification
    frame.extend_from_slice(&[0x40, 0x00]); // Flags (DF) + Fragment Offset
    frame.push(64); // TTL
    frame.push(17); // Protocol: UDP
    let checksum_offset = frame.len();
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(&src_ip);
    frame.extend_from_slice(&dst_ip);

    let checksum = ip_checksum(&frame[..20]);
    frame[checksum_offset] = (checksum >> 8) as u8;
    frame[checksum_offset + 1] = (checksum & 0xFF) as u8;

    frame.extend_from_slice(&pkt.src.port().to_be_bytes());
    frame.extend_from_slice(&pkt.dst.port().to_be_bytes());
    frame.extend_from_slice(&(udp_len as u16).to_be_bytes());
    frame.extend_from_slice(&[0, 0]); // UDP checksum (skip)

    frame.extend_from_slice(&pkt.payload);

    frame
}

fn ip_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..header.len()).step_by(2) {
        let word = u16::from_be_bytes([header[i], header[i + 1]]);
        sum += word as u32;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}
