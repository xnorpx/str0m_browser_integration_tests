//! Small, deterministic AV1 fixtures using the codecs' safe Rust APIs.
#![forbid(unsafe_code)]

use rav1e::prelude::*;
use rusty_av1d::Rav1dError;
pub use rusty_av1d::rust_api::{Decoder, Picture};
use rusty_av1d::rust_api::{PlanarImageComponent, Settings};
use std::sync::{Arc, OnceLock};

pub const WIDTH: usize = 160;
pub const HEIGHT: usize = 96;
pub const FRAME_COUNT: usize = 32;

pub struct EncodedFrame {
    pub data: Vec<u8>,
    pub keyframe: bool,
}

pub fn decoder() -> Result<Decoder, String> {
    let mut settings = Settings::default();
    settings.set_n_threads(1);
    settings.set_max_frame_delay(1);
    settings.set_frame_size_limit(640 * 360);
    Decoder::with_settings(&settings).map_err(|e| format!("Create AV1 decoder: {e}"))
}

/// Honor decoder backpressure: drain available pictures before retrying pending data.
pub fn decode(decoder: &mut Decoder, data: &[u8]) -> Result<Vec<Picture>, String> {
    let mut status = decoder.send_data(data.into(), None, None, None);
    let mut frames = Vec::new();
    loop {
        let pending = match status {
            Ok(()) => false,
            Err(Rav1dError::TryAgain) => true,
            Err(error) => return Err(format!("Submit AV1 data: {error}")),
        };
        let before = frames.len();
        loop {
            match decoder.get_picture() {
                Ok(frame) => frames.push(frame),
                Err(Rav1dError::TryAgain) => break,
                Err(error) => return Err(format!("Decode AV1 picture: {error}")),
            }
        }
        if !pending {
            return Ok(frames);
        }
        if frames.len() == before {
            return Err("Single-threaded AV1 decoder stalled with pending data".into());
        }
        status = decoder.send_pending_data();
    }
}

pub fn luma_checksum(frame: &Picture) -> Result<u64, String> {
    if frame.bit_depth() != 8 {
        return Err("Expected 8-bit AV1 output".into());
    }
    let width = frame.width() as usize;
    let height = frame.height() as usize;
    let stride = frame.stride(PlanarImageComponent::Y) as usize;
    let plane = frame.plane(PlanarImageComponent::Y);
    if stride < width || stride == 0 || plane.len() / stride < height {
        return Err("Invalid decoded AV1 luma plane dimensions".into());
    }
    Ok(plane
        .chunks_exact(stride)
        .take(height)
        .flat_map(|row| &row[..width])
        .fold(0xcbf29ce484222325, |hash, pixel| {
            (hash ^ u64::from(*pixel)).wrapping_mul(0x100000001b3)
        }))
}

/// Encoded once, off the network event loop, and reused across browser sessions.
pub fn fixtures() -> Result<Arc<Vec<EncodedFrame>>, String> {
    static FRAMES: OnceLock<Result<Arc<Vec<EncodedFrame>>, String>> = OnceLock::new();
    FRAMES.get_or_init(|| encode().map(Arc::new)).clone()
}

fn encode() -> Result<Vec<EncodedFrame>, String> {
    let mut encoder = EncoderConfig::with_speed_preset(10);
    encoder.width = WIDTH;
    encoder.height = HEIGHT;
    encoder.low_latency = true;
    encoder.quantizer = 100;
    encoder.min_key_frame_interval = 16;
    encoder.max_key_frame_interval = 16;
    encoder.time_base = Rational { num: 1, den: 10 };
    let mut context: Context<u8> = Config::new()
        .with_encoder_config(encoder)
        .with_threads(1)
        .new_context()
        .map_err(|e| format!("Create safe AV1 encoder: {e}"))?;
    let mut frames = Vec::new();
    for index in 0..FRAME_COUNT {
        let mut frame = context.new_frame();
        let mut y = vec![0; WIDTH * HEIGHT];
        let mut noise = 12345_u32 + (index / 16) as u32;
        for (offset, pixel) in y.iter_mut().enumerate() {
            noise = noise.wrapping_mul(1664525).wrapping_add(1013904223);
            *pixel = 32 + (noise >> 25) as u8;
            let x = offset % WIDTH;
            let row = offset / WIDTH;
            if (index * 4..index * 4 + 12).contains(&x) && (30..50).contains(&row) {
                *pixel = 220;
            }
        }
        frame.planes[0].copy_from_raw_u8(&y, WIDTH, 1);
        for plane in &mut frame.planes[1..] {
            plane.copy_from_raw_u8(&vec![128; WIDTH * HEIGHT / 4], WIDTH / 2, 1);
        }
        context
            .send_frame(frame)
            .map_err(|e| format!("AV1 send frame: {e}"))?;
        drain_encoder(&mut context, &mut frames, false)?;
    }
    context.flush();
    drain_encoder(&mut context, &mut frames, true)?;
    if frames.len() != FRAME_COUNT || !frames[0].keyframe {
        return Err(format!(
            "AV1 encoder produced {} frames, expected {FRAME_COUNT}",
            frames.len()
        ));
    }
    Ok(frames)
}

fn drain_encoder(
    context: &mut Context<u8>,
    frames: &mut Vec<EncodedFrame>,
    flushing: bool,
) -> Result<(), String> {
    loop {
        match context.receive_packet() {
            Ok(packet) => frames.push(EncodedFrame {
                data: packet.data,
                keyframe: packet.frame_type == FrameType::KEY,
            }),
            Err(EncoderStatus::Encoded) => continue,
            Err(EncoderStatus::NeedMoreData) if !flushing => return Ok(()),
            Err(EncoderStatus::LimitReached) if flushing => return Ok(()),
            Err(error) => return Err(format!("AV1 receive packet: {error}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decoder_drains_pending_frames_from_one_input() {
        let frames = fixtures().unwrap();
        let data: Vec<u8> = frames
            .iter()
            .take(3)
            .flat_map(|frame| frame.data.iter().copied())
            .collect();
        let decoded = decode(&mut decoder().unwrap(), &data).unwrap();
        assert_eq!(decoded.len(), 3);
        let checksums: std::collections::HashSet<_> = decoded
            .iter()
            .map(|frame| luma_checksum(frame).unwrap())
            .collect();
        assert_eq!(checksums.len(), 3);
    }

    #[test]
    fn decoder_reports_malformed_input() {
        assert!(decode(&mut decoder().unwrap(), &[0xff]).is_err());
    }

    #[test]
    fn safe_codecs_round_trip_real_key_and_delta_frames() {
        let frames = fixtures().unwrap();
        let mut decoder = decoder().unwrap();
        let mut checksums = std::collections::HashSet::new();
        let mut count = 0;
        for encoded in frames.iter() {
            let decoded = decode(&mut decoder, &encoded.data).unwrap();
            assert_eq!(decoded.len(), 1, "one visible frame per encoded packet");
            let frame = &decoded[0];
            assert_eq!(
                (frame.width(), frame.height()),
                (WIDTH as u32, HEIGHT as u32)
            );
            checksums.insert(luma_checksum(frame).unwrap());
            count += 1;
        }
        assert_eq!(count, FRAME_COUNT);
        assert!(checksums.len() > 16);
        assert_eq!(frames.iter().filter(|f| f.keyframe).count(), 2);
        assert!(matches!(decoder.get_picture(), Err(Rav1dError::TryAgain)));
    }
}
