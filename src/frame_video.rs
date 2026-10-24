#![forbid(unsafe_code)]

use crate::av1::{self, EncodedFrame};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};
use str0m::Rtc;
use str0m::format::Codec;
use str0m::media::{Direction, Frequency, MediaAdded, MediaData, MediaKind, MediaTime, Mid, Pt};
use str0m::rtp::dependency_descriptor::{
    DecodeTargetIndication, DependencyDescriptor, DependencyDescriptorReceiver,
    ParsedDependencyDescriptor, ReceivedDependencyDescriptor, SharedStructure,
    SharedStructureTemplate, URI,
};
use str0m::rtp::{RawPacket, RtpHeader};

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DdPacketSummary {
    pub packets: u64,
    pub frames: u64,
    pub single_packet_frames: u64,
    pub multi_packet_frames: u64,
    pub first_only: u64,
    pub middle: u64,
    pub last_only: u64,
    pub first_and_last: u64,
    pub structures: u64,
    pub semantic_roundtrips: u64,
    pub dd_bytes: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FrameVideoReport {
    pub rust_frames_encoded: u64,
    pub rust_frames_sent: u64,
    pub chrome_frames_received: u64,
    pub rust_frames_decoded: u64,
    pub rust_unique_decoded_images: u64,
    pub decoded_width: u32,
    pub decoded_height: u32,
    pub frame_dd_roundtrips: u64,
    pub chrome_to_rust: DdPacketSummary,
    pub rust_to_chrome: DdPacketSummary,
}

#[derive(Serialize)]
struct PacketSample {
    elapsed_ms: f64,
    ssrc: u32,
    payload_type: u8,
    sequence: u16,
    timestamp: u32,
    frame_number: i64,
    packet_index_in_frame: u64,
    first: bool,
    last: bool,
    marker: bool,
    structure: bool,
    dd_bytes: usize,
    dd_hex: String,
    packet_bytes: usize,
}

#[derive(Default)]
struct PacketProfiler {
    receiver: DependencyDescriptorReceiver,
    current: Option<(i64, u32)>,
    packet_count: u64,
    first_by_frame: HashMap<u16, Vec<u8>>,
    samples: Vec<PacketSample>,
    summary: DdPacketSummary,
}

impl PacketProfiler {
    fn observe(
        &mut self,
        header: &RtpHeader,
        raw: &DependencyDescriptor,
        bytes: usize,
        elapsed: Duration,
    ) -> Result<(), String> {
        let ReceivedDependencyDescriptor::Parsed {
            frame_number,
            descriptor,
        } = self.receiver.receive(raw)
        else {
            return Err("Wire DD failed stateful deserialization".into());
        };
        semantic_roundtrip(&descriptor, self.receiver.latest_shared_structure())?;
        self.summary.semantic_roundtrips += 1;
        if descriptor.is_first_packet {
            if self.current.is_some() {
                return Err("New DD frame before previous last packet".into());
            }
            self.current = Some((frame_number, header.timestamp));
            self.packet_count = 0;
            self.first_by_frame
                .insert(descriptor.truncated_frame_number, raw.as_bytes().to_vec());
        }
        if self.current != Some((frame_number, header.timestamp)) {
            return Err("DD frame number or RTP timestamp changed inside packetized frame".into());
        }
        if descriptor.is_last_packet != header.marker {
            return Err("Single-spatial-layer DD last-packet flag differs from RTP marker".into());
        }
        let attached = descriptor.attached_structure.is_some();
        if attached && !descriptor.is_first_packet {
            return Err("DD structure sent on a non-first packet".into());
        }
        self.summary.structures += u64::from(attached);
        self.summary.packets += 1;
        self.summary.dd_bytes += raw.as_bytes().len() as u64;
        self.packet_count += 1;
        match (descriptor.is_first_packet, descriptor.is_last_packet) {
            (true, false) => self.summary.first_only += 1,
            (false, false) => self.summary.middle += 1,
            (false, true) => self.summary.last_only += 1,
            (true, true) => self.summary.first_and_last += 1,
        }
        if descriptor.is_last_packet {
            self.summary.frames += 1;
            self.summary.single_packet_frames += u64::from(self.packet_count == 1);
            self.summary.multi_packet_frames += u64::from(self.packet_count > 1);
            self.current = None;
        }
        self.samples.push(PacketSample {
            elapsed_ms: elapsed.as_secs_f64() * 1000.0,
            ssrc: *header.ssrc,
            payload_type: *header.payload_type,
            sequence: header.sequence_number,
            timestamp: header.timestamp,
            frame_number,
            packet_index_in_frame: self.packet_count - 1,
            first: descriptor.is_first_packet,
            last: descriptor.is_last_packet,
            marker: header.marker,
            structure: attached,
            dd_bytes: raw.as_bytes().len(),
            dd_hex: raw
                .as_bytes()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect(),
            packet_bytes: bytes,
        });
        Ok(())
    }
}

fn semantic_roundtrip(
    parsed: &ParsedDependencyDescriptor,
    structure: Option<&SharedStructure>,
) -> Result<DependencyDescriptor, String> {
    let serialized = parsed
        .serialize(structure)
        .map_err(|e| format!("DD serialization: {e}"))?;
    let decoded = serialized
        .parse(structure)
        .map_err(|e| format!("DD reparse: {e}"))?;
    if decoded != *parsed {
        return Err("DD serialize/deserialize changed descriptor semantics".into());
    }
    Ok(serialized)
}

pub struct FrameVideo {
    decoder: av1::Decoder,
    frames: Arc<Vec<EncodedFrame>>,
    frame_receiver: DependencyDescriptorReceiver,
    structure: SharedStructure,
    mid: Option<Mid>,
    pt: Option<Pt>,
    extension_id: Option<u8>,
    started: Instant,
    next_send: Option<Instant>,
    incoming: PacketProfiler,
    outgoing: PacketProfiler,
    checksums: HashSet<u64>,
    pub report: FrameVideoReport,
}

impl FrameVideo {
    pub fn new() -> Result<Self, String> {
        let template = |dti, diffs| SharedStructureTemplate {
            spatial_layer_id: 0,
            temporal_layer_id: 0,
            decode_target_indication_by_decode_target_index: vec![dti],
            referred_relative_frame_numbers: diffs,
            previous_relative_frame_number_by_chain_index: vec![],
        };
        let structure = SharedStructure::new(
            0,
            vec![
                template(DecodeTargetIndication::Switch, vec![]),
                template(DecodeTargetIndication::Required, vec![1]),
            ],
            &[],
            None,
        )
        .map_err(|e| format!("DD encoder structure: {e}"))?;
        Ok(Self {
            decoder: av1::decoder()?,
            frames: Arc::new(Vec::new()),
            frame_receiver: DependencyDescriptorReceiver::default(),
            structure,
            mid: None,
            pt: None,
            extension_id: None,
            started: Instant::now(),
            next_send: None,
            incoming: PacketProfiler::default(),
            outgoing: PacketProfiler::default(),
            checksums: HashSet::new(),
            report: FrameVideoReport::default(),
        })
    }

    pub fn set_frames(&mut self, frames: Arc<Vec<EncodedFrame>>) {
        self.frames = frames;
        self.report.rust_frames_encoded = self.frames.len() as u64;
    }

    pub fn set_media(&mut self, rtc: &mut Rtc, media: MediaAdded) -> Result<(), String> {
        if media.kind != MediaKind::Video
            || media.direction != Direction::SendRecv
            || self.mid.replace(media.mid).is_some()
        {
            return Err("Frame interop requires one sendrecv video m-line".into());
        }
        self.extension_id = rtc
            .media(media.mid)
            .ok_or("Missing frame media")?
            .remote_extmap()
            .iter()
            .find(|(_, ext)| ext.as_uri() == URI)
            .map(|(id, _)| id);
        if self.extension_id.is_none() {
            return Err("DD was not negotiated for frame-mode media".into());
        }
        self.pt = rtc
            .writer(media.mid)
            .ok_or("No frame-mode writer")?
            .payload_params()
            .find(|p| p.spec().codec == Codec::Av1)
            .map(|p| p.pt());
        if self.pt.is_none() {
            return Err("AV1 was not negotiated for frame-mode media".into());
        }
        Ok(())
    }

    pub fn start(&mut self) {
        self.started = Instant::now();
        self.next_send = Some(self.started);
    }

    pub fn deadline(&self) -> Option<Instant> {
        self.next_send.filter(|_| !self.frames.is_empty())
    }

    pub fn send_due(&mut self, rtc: &mut Rtc) -> Result<(), String> {
        if self.frames.is_empty() {
            return Ok(());
        }
        let now = Instant::now();
        if !self.next_send.is_some_and(|deadline| now >= deadline) {
            return Ok(());
        }
        let index = self.report.rust_frames_sent as usize;
        let encoded = self
            .frames
            .get(index)
            .ok_or("No encoded AV1 frame available")?;
        // rav1e low-latency output has no hidden/reordered frames. The conservative
        // delta template depends on the previous frame; keyframes attach the structure.
        let mut parsed = ParsedDependencyDescriptor::from_template(
            &self.structure,
            u8::from(!encoded.keyframe),
            65530_u16.wrapping_add(index as u16),
        )
        .map_err(|e| format!("Construct frame DD: {e}"))?;
        if encoded.keyframe {
            parsed.attached_structure = Some(self.structure.clone());
        }
        let descriptor = semantic_roundtrip(&parsed, Some(&self.structure))?;
        let mid = self.mid.ok_or("Frame media not negotiated")?;
        rtc.writer(mid)
            .ok_or("Missing frame writer")?
            .user_extension_value(descriptor)
            .write(
                self.pt.ok_or("No AV1 PT")?,
                now,
                MediaTime::new(index as u64 * 9000, Frequency::NINETY_KHZ),
                encoded.data.clone(),
            )
            .map_err(|e| format!("Frame-mode AV1 write: {e}"))?;
        self.report.rust_frames_sent += 1;
        self.next_send =
            (index + 1 < self.frames.len()).then_some(now + Duration::from_millis(100));
        Ok(())
    }

    pub fn receive(&mut self, data: MediaData) -> Result<(), String> {
        if data.params.spec().codec != Codec::Av1 || !data.contiguous {
            return Err("Expected contiguous frame-mode AV1".into());
        }
        let raw = data
            .ext_vals
            .user_values
            .get::<DependencyDescriptor>()
            .ok_or("Frame-mode MediaData lost DD")?;
        let ReceivedDependencyDescriptor::Parsed { descriptor, .. } =
            self.frame_receiver.receive(raw)
        else {
            return Err("Frame-mode DD deserialization failed".into());
        };
        if self
            .incoming
            .first_by_frame
            .remove(&descriptor.truncated_frame_number)
            .as_deref()
            != Some(raw.as_bytes())
        {
            return Err("Frame-mode DD differs from first RTP packet's DD".into());
        }
        semantic_roundtrip(&descriptor, self.frame_receiver.latest_shared_structure())?;
        self.report.frame_dd_roundtrips += 1;
        self.report.chrome_frames_received += 1;
        for frame in av1::decode(&mut self.decoder, &data.data)
            .map_err(|e| format!("Decode Chrome AV1: {e}"))?
        {
            self.count_decoded(&frame)?;
        }
        Ok(())
    }

    fn count_decoded(&mut self, frame: &av1::Picture) -> Result<(), String> {
        self.report.rust_frames_decoded += 1;
        self.report.decoded_width = frame.width();
        self.report.decoded_height = frame.height();
        self.checksums.insert(av1::luma_checksum(frame)?);
        self.report.rust_unique_decoded_images = self.checksums.len() as u64;
        Ok(())
    }

    pub fn observe(&mut self, packet: &RawPacket) -> Result<(), String> {
        let (header, bytes, outgoing) = match packet {
            RawPacket::RtpRx(header, payload) if Some(header.payload_type) == self.pt => {
                if payload.is_empty() {
                    return Ok(());
                }
                (header, payload, false)
            }
            RawPacket::RtpTx(header, bytes) if Some(header.payload_type) == self.pt => {
                let payload = bytes
                    .get(header.header_len..)
                    .ok_or("Truncated outgoing RTP")?;
                if header.has_padding
                    && payload
                        .last()
                        .is_some_and(|pad| usize::from(*pad) == payload.len())
                {
                    return Ok(());
                }
                (header, bytes, true)
            }
            _ => return Ok(()),
        };
        let raw = header
            .ext_vals
            .user_values
            .get::<DependencyDescriptor>()
            .ok_or("Video packet missing wire DD")?;
        if outgoing {
            let wire = wire_extension(bytes, self.extension_id.ok_or("No DD extension ID")?)?
                .ok_or("DD absent from serialized RTP bytes")?;
            if wire != raw.as_bytes() {
                return Err("Serialized RTP DD differs from packet metadata".into());
            }
            self.outgoing
                .observe(header, raw, bytes.len(), self.started.elapsed())?;
            self.report.rust_to_chrome = self.outgoing.summary.clone();
        } else {
            self.incoming.observe(
                header,
                raw,
                bytes.len() + header.header_len,
                self.started.elapsed(),
            )?;
            self.report.chrome_to_rust = self.incoming.summary.clone();
        }
        Ok(())
    }

    pub fn save_profile(&self, session_id: &str) -> Result<(), String> {
        let path = std::path::Path::new("target").join("dd-profile");
        std::fs::create_dir_all(&path).map_err(|e| format!("Create DD profile directory: {e}"))?;
        // Session ids are also used by the existing pcap writer; keep profiling names local.
        let name: String = session_id
            .chars()
            .map(|c| {
                if c.is_ascii_alphanumeric() || c == '_' || c == '-' {
                    c
                } else {
                    '_'
                }
            })
            .collect();
        let file = std::fs::File::create(path.join(format!("{name}.json")))
            .map_err(|e| format!("Create DD profile: {e}"))?;
        serde_json::to_writer_pretty(
            file,
            &serde_json::json!({
                "schema_version": 2,
                "session_id": session_id,
                "dd_extension_id": self.extension_id,
                "time_origin": "elapsed_ms since str0m Connected (ICE + DTLS)",
                "encoder": "rav1e 0.8.1, assembly disabled",
                "decoder": "rusty_av1d 1.2.1, BSD-2-Clause, assembly disabled, 8-bit",
                "incomplete_frames": {
                    "chrome_to_rust": self.incoming.current.is_some(),
                    "rust_to_chrome": self.outgoing.current.is_some(),
                },
                "report": self.report,
                "chrome_to_rust": self.incoming.samples,
                "rust_to_chrome": self.outgoing.samples,
            }),
        )
        .map_err(|e| format!("Write DD profile: {e}"))
    }
}

/// Read one negotiated extension from the actual pre-SRTP RTP bytes, independently
/// of str0m's header metadata. Both RFC 8285 extension forms are accepted.
fn wire_extension(bytes: &[u8], wanted: u8) -> Result<Option<&[u8]>, String> {
    if bytes.len() < 12 || bytes[0] >> 6 != 2 || bytes[0] & 0x10 == 0 {
        return Err("Invalid RTP extension header".into());
    }
    let offset = 12 + usize::from(bytes[0] & 0xf) * 4;
    let header = bytes
        .get(offset..offset + 4)
        .ok_or("Truncated extension header")?;
    let profile = u16::from_be_bytes([header[0], header[1]]);
    let len = usize::from(u16::from_be_bytes([header[2], header[3]])) * 4;
    let mut data = bytes
        .get(offset + 4..offset + 4 + len)
        .ok_or("Truncated RTP extensions")?;
    while !data.is_empty() {
        let tag = data[0];
        data = &data[1..];
        if tag == 0 {
            continue;
        }
        let (id, len) = if profile == 0xbede {
            if tag >> 4 == 15 {
                break;
            }
            (tag >> 4, usize::from(tag & 15) + 1)
        } else if profile & 0xfff0 == 0x1000 {
            let len = *data.first().ok_or("Truncated two-byte RTP extension")?;
            data = &data[1..];
            (tag, usize::from(len))
        } else {
            return Err(format!("Unsupported RTP extension profile {profile:#x}"));
        };
        let value = data.get(..len).ok_or("Truncated RTP extension value")?;
        if id == wanted {
            return Ok(Some(value));
        }
        data = &data[len..];
    }
    Ok(None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use str0m::rtp::ExtensionValues;

    #[test]
    fn waits_for_fixtures_before_scheduling_media() {
        let mut video = FrameVideo::new().unwrap();
        video.start();
        assert!(video.deadline().is_none());
        video.set_frames(Arc::new(vec![EncodedFrame {
            data: vec![],
            keyframe: true,
        }]));
        assert!(video.deadline().is_some());
        assert_eq!(video.report.rust_frames_encoded, 1);
    }

    fn header(marker: bool, sequence: u16, timestamp: u32) -> RtpHeader {
        RtpHeader {
            version: 2,
            has_padding: false,
            has_extension: true,
            csrc_count: 0,
            marker,
            payload_type: 45.into(),
            sequence_number: sequence,
            timestamp,
            ssrc: 1000.into(),
            csrc: [0; 15],
            ext_vals: ExtensionValues::default(),
            header_len: 20,
        }
    }

    #[test]
    fn profiles_single_multi_packet_flags_structures_and_frame_number_wrap() {
        let mut profiler = PacketProfiler::default();
        for (sequence, bytes, flags) in [
            (0, vec![0xc0, 0xff, 0xff, 0x80, 0, 0xe0], (true, false)),
            (1, vec![0, 0xff, 0xff], (false, false)),
            (2, vec![0, 0xff, 0xff], (false, true)),
            (3, vec![0, 0, 0], (true, true)),
        ] {
            let mut dd = DependencyDescriptor::from_bytes(bytes).unwrap();
            dd.set_packet_flags(flags.0, flags.1);
            profiler
                .observe(
                    &header(flags.1, sequence, if sequence == 3 { 9000 } else { 0 }),
                    &dd,
                    100,
                    Duration::ZERO,
                )
                .unwrap();
        }
        assert_eq!(profiler.summary.frames, 2);
        assert_eq!(profiler.summary.multi_packet_frames, 1);
        assert_eq!(profiler.summary.single_packet_frames, 1);
        assert_eq!(profiler.summary.structures, 1);
        assert_eq!(profiler.summary.semantic_roundtrips, 4);
        assert_eq!(profiler.summary.first_only, 1);
        assert_eq!(profiler.summary.middle, 1);
        assert_eq!(profiler.summary.last_only, 1);
        assert_eq!(profiler.summary.first_and_last, 1);
        assert_eq!(profiler.samples[3].frame_number, 65536);
    }

    #[test]
    fn rejects_marker_mismatches_missing_first_and_changed_timestamp() {
        let raw = DependencyDescriptor::from_bytes([0x80, 0, 0, 0x80, 0, 0xe0]).unwrap();
        let mut profiler = PacketProfiler::default();
        assert!(
            profiler
                .observe(&header(true, 1, 0), &raw, 100, Duration::ZERO)
                .is_err()
        );
        let mut profiler = PacketProfiler::default();
        profiler
            .observe(&header(false, 1, 0), &raw, 100, Duration::ZERO)
            .unwrap();
        let last = DependencyDescriptor::from_bytes([0x40, 0, 0]).unwrap();
        assert!(
            profiler
                .observe(&header(true, 2, 1), &last, 100, Duration::ZERO)
                .is_err()
        );
        let mut profiler = PacketProfiler::default();
        assert!(
            profiler
                .observe(&header(true, 2, 0), &last, 100, Duration::ZERO)
                .is_err()
        );
    }

    #[test]
    fn reads_actual_wire_dd_in_both_rfc8285_forms_and_rejects_truncation() {
        for (profile, payload) in [
            (0xbede_u16, vec![0xd2, 0xc0, 0, 42]),
            (0x1000_u16, vec![13, 3, 0xc0, 0, 42, 0, 0, 0]),
        ] {
            let mut packet = vec![0; 12];
            packet[0] = 0x90;
            packet.extend_from_slice(&profile.to_be_bytes());
            packet.extend_from_slice(&((payload.len() / 4) as u16).to_be_bytes());
            packet.extend_from_slice(&payload);
            assert_eq!(
                wire_extension(&packet, 13).unwrap(),
                Some([0xc0, 0, 42].as_slice())
            );
            assert_eq!(wire_extension(&packet, 14).unwrap(), None);
            packet.pop();
            assert!(wire_extension(&packet, 13).is_err());
        }
    }
}
