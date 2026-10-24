use crate::protocol::{VideoLoopbackConfig, VideoLoopbackReport};
use std::time::Instant;
use str0m::Rtc;
use str0m::media::{Direction, MediaAdded, MediaKind, Mid};
use str0m::rtp::dependency_descriptor::{
    DecodeTargetIndication, DependencyDescriptor, DependencyDescriptorReceiver,
    ReceivedDependencyDescriptor,
};
use str0m::rtp::{RtpPacket, RtpWrite, Ssrc};

/// A single-stream SFU: no depacketization, transcoding, or payload rewriting.
pub struct VideoLoopback {
    config: VideoLoopbackConfig,
    receiver: DependencyDescriptorReceiver,
    mid: Option<Mid>,
    source: Option<Ssrc>,
    frame: Option<i64>,
    drop_frame: bool,
    next_seq: u64,
    pub report: VideoLoopbackReport,
}

impl VideoLoopback {
    pub fn new(config: VideoLoopbackConfig) -> Self {
        Self {
            config,
            receiver: DependencyDescriptorReceiver::default(),
            mid: None,
            source: None,
            frame: None,
            drop_frame: false,
            next_seq: 1000,
            report: VideoLoopbackReport::default(),
        }
    }

    pub fn set_media(&mut self, media: MediaAdded) -> Result<(), String> {
        if media.kind != MediaKind::Video
            || media.direction != Direction::SendRecv
            || self.mid.replace(media.mid).is_some()
        {
            return Err("Video loopback requires exactly one sendrecv video m-line".into());
        }
        Ok(())
    }

    fn inspect(&mut self, raw: &DependencyDescriptor) -> Result<bool, String> {
        self.report.packets_received += 1;
        let ReceivedDependencyDescriptor::Parsed {
            frame_number,
            descriptor,
        } = self.receiver.receive(raw)
        else {
            return Err(
                "Incoming dependency descriptor cannot be parsed with current structure".into(),
            );
        };
        self.report.descriptors_parsed += 1;
        if descriptor.attached_structure.is_some() {
            self.report.structures_received += 1;
        }
        let structure = self
            .receiver
            .latest_shared_structure()
            .ok_or("Missing DD structure")?;
        let template = structure
            .template(descriptor.template_id)
            .ok_or("Missing DD template")?;
        let temporal_id = template.temporal_layer_id;
        if template.spatial_layer_id != 0 {
            return Err("Video loopback requires a single spatial layer".into());
        }
        self.report.max_temporal_id = self.report.max_temporal_id.max(temporal_id);
        if self.frame != Some(frame_number) {
            if !descriptor.is_first_packet {
                return Err("Video loopback received a frame without its first packet".into());
            }
            let index = self.report.frames_received;
            self.report.frames_received += 1;
            let in_window = index >= self.config.drop_start
                && index - self.config.drop_start < self.config.drop_duration;
            // Dropping only globally discardable top-layer frames also permits forwarding
            // every subsequent frame without a keyframe or a decode-target rewrite.
            let discardable = descriptor
                .decode_target_indication_by_decode_target_index
                .iter()
                .all(|dti| {
                    matches!(
                        dti,
                        DecodeTargetIndication::NotPresent | DecodeTargetIndication::Discardable
                    )
                });
            self.drop_frame = in_window
                && temporal_id == 2
                && discardable
                && descriptor.attached_structure.is_none();
            self.frame = Some(frame_number);
            if self.drop_frame {
                self.report.frames_dropped += 1;
            } else {
                self.report.frames_forwarded += 1;
                if self.report.frames_dropped > 0
                    && index >= self.config.drop_start + self.config.drop_duration
                    && temporal_id == 2
                {
                    self.report.enhancement_frames_forwarded_after_drop += 1;
                }
            }
        }
        if self.drop_frame {
            self.report.packets_dropped += 1;
        }
        Ok(!self.drop_frame)
    }

    pub fn forward(&mut self, rtc: &mut Rtc, packet: RtpPacket) -> Result<(), String> {
        // Bandwidth probes contain only RTP padding, not a video frame or DD.
        if packet.payload.is_empty() && packet.header.has_padding {
            return Ok(());
        }
        if let Some(source) = self.source {
            if source != packet.header.ssrc {
                return Err("Video loopback received more than one RTP source".into());
            }
        } else {
            self.source = Some(packet.header.ssrc);
        }
        let raw = packet
            .header
            .ext_vals
            .user_values
            .get::<DependencyDescriptor>()
            .ok_or_else(|| {
                format!(
                    "Video RTP packet has no dependency descriptor: header={:?}, payload_len={}",
                    packet.header,
                    packet.payload.len()
                )
            })?;
        if !self.inspect(raw)? {
            return Ok(());
        }
        let mid = self.mid.ok_or("Video RTP arrived before MediaAdded")?;
        let mut api = rtc.direct_api();
        let stream = api
            .stream_tx_by_mid(mid, None)
            .ok_or("No negotiated video send stream")?;
        // Sequence numbers hide intentional SFU drops; DD frame numbers and RTP timestamps
        // remain untouched because the decoder's dependency references use them.
        stream.write_rtp(
            RtpWrite::new(
                packet.header.payload_type,
                self.next_seq.into(),
                packet.header.timestamp,
                Instant::now(),
                packet.payload,
            )
            .marker(packet.header.marker)
            .ext_vals(packet.header.ext_vals)
            .nackable(true),
        );
        self.next_seq += 1;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use str0m::rtp::dependency_descriptor::{
        ParsedDependencyDescriptor, SharedStructure, SharedStructureTemplate,
    };

    fn structure() -> SharedStructure {
        use DecodeTargetIndication::{Discardable, NotPresent, Switch};
        SharedStructure::new(
            0,
            vec![
                SharedStructureTemplate {
                    spatial_layer_id: 0,
                    temporal_layer_id: 0,
                    decode_target_indication_by_decode_target_index: vec![Switch, Switch],
                    referred_relative_frame_numbers: vec![],
                    previous_relative_frame_number_by_chain_index: vec![],
                },
                SharedStructureTemplate {
                    spatial_layer_id: 0,
                    temporal_layer_id: 1,
                    decode_target_indication_by_decode_target_index: vec![NotPresent, Switch],
                    referred_relative_frame_numbers: vec![1],
                    previous_relative_frame_number_by_chain_index: vec![],
                },
                SharedStructureTemplate {
                    spatial_layer_id: 0,
                    temporal_layer_id: 2,
                    decode_target_indication_by_decode_target_index: vec![NotPresent, Discardable],
                    referred_relative_frame_numbers: vec![1],
                    previous_relative_frame_number_by_chain_index: vec![],
                },
            ],
            &[],
            None,
        )
        .unwrap()
    }

    #[test]
    fn drops_whole_discardable_frames_and_resumes_with_original_frame_numbers() {
        let structure = structure();
        let mut video = VideoLoopback::new(VideoLoopbackConfig {
            drop_start: 1,
            drop_duration: 2,
        });
        for (index, template) in [0, 2, 0, 2].into_iter().enumerate() {
            let mut descriptor = ParsedDependencyDescriptor::from_template(
                &structure,
                template,
                (65534_u16).wrapping_add(index as u16),
            )
            .unwrap();
            if index == 0 {
                descriptor.attached_structure = Some(structure.clone());
            }
            for part in 0..3 {
                descriptor.is_first_packet = part == 0;
                descriptor.is_last_packet = part == 2;
                let raw = descriptor.serialize(Some(&structure)).unwrap();
                assert_eq!(video.inspect(&raw).unwrap(), index != 1);
                assert_eq!(
                    raw.truncated_frame_number(),
                    descriptor.truncated_frame_number
                );
                descriptor.attached_structure = None;
            }
        }
        assert_eq!(video.report.frames_received, 4);
        assert_eq!(video.report.frames_dropped, 1);
        assert_eq!(video.report.packets_dropped, 3);
        assert_eq!(video.report.descriptors_parsed, 12);
        assert_eq!(video.report.enhancement_frames_forwarded_after_drop, 1);
    }

    #[test]
    fn no_drop_control_and_required_frames_are_never_filtered() {
        let structure = structure();
        for duration in [0, 10] {
            let mut video = VideoLoopback::new(VideoLoopbackConfig {
                drop_start: 0,
                drop_duration: duration,
            });
            let mut descriptor =
                ParsedDependencyDescriptor::from_template(&structure, 2, 42).unwrap();
            descriptor.attached_structure = Some(structure.clone());
            let raw = descriptor.serialize(Some(&structure)).unwrap();
            assert!(video.inspect(&raw).unwrap());
            descriptor.attached_structure = None;
            descriptor.truncated_frame_number = 43;
            let raw = descriptor.serialize(Some(&structure)).unwrap();
            assert_eq!(video.inspect(&raw).unwrap(), duration == 0);
            descriptor.truncated_frame_number = 44;
            descriptor.decode_target_indication_by_decode_target_index[1] =
                DecodeTargetIndication::Required;
            let raw = descriptor.serialize(Some(&structure)).unwrap();
            assert!(video.inspect(&raw).unwrap());
            assert_eq!(video.report.frames_dropped, u64::from(duration > 0));
        }
    }

    #[test]
    fn rejects_descriptor_without_structure() {
        let mut video = VideoLoopback::new(VideoLoopbackConfig {
            drop_start: 0,
            drop_duration: 0,
        });
        let raw = DependencyDescriptor::from_bytes([0xc0, 0, 0]).unwrap();
        assert!(video.inspect(&raw).is_err());
    }
}
