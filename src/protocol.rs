use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SdpRole {
    Offerer,
    Answerer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IceMode {
    Full,
    Lite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DtlsRole {
    Active,
    Passive,
    Auto,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerDtlsVersion {
    Dtls12,
    /// `DtlsVersion::Auto`: accept either version as DTLS server, offer both as DTLS client.
    /// Falls back to DTLS 1.2 on crypto backends without DTLS 1.3.
    #[default]
    Auto,
    Dtls13,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub client_sdp_role: SdpRole,
    pub server_ice_mode: IceMode,
    pub client_dtls_role: DtlsRole,
    #[serde(default)]
    pub server_dtls_version: ServerDtlsVersion,
    /// Whether str0m puts `a=sctp-init` (SNAP) in its own offers. Defaults to `true`.
    /// str0m always reciprocates SNAP when the remote offer carries `a=sctp-init`.
    #[serde(default)]
    pub server_snap: Option<bool>,
    /// str0m-netem network emulation on the str0m side. When absent, the server's
    /// `--netem*` command line defaults apply.
    #[serde(default)]
    pub server_netem: Option<NetemSettings>,
    /// AV1 RTP loopback with dependency-descriptor validation and optional filtering.
    #[serde(default)]
    pub video_loopback: Option<VideoLoopbackConfig>,
    /// Independent AV1 encoding/decoding in frame mode, with DD packet profiling.
    #[serde(default)]
    pub video_frame_mode: bool,
}

impl SessionConfig {
    /// Config with server defaults: DTLS auto, SNAP enabled, no netem.
    pub const fn new(
        client_sdp_role: SdpRole,
        server_ice_mode: IceMode,
        client_dtls_role: DtlsRole,
    ) -> Self {
        Self {
            client_sdp_role,
            server_ice_mode,
            client_dtls_role,
            server_dtls_version: ServerDtlsVersion::Auto,
            server_snap: None,
            server_netem: None,
            video_loopback: None,
            video_frame_mode: false,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VideoLoopbackConfig {
    /// Zero-based received frame index at which filtering starts.
    pub drop_start: u64,
    /// Number of input frames in the filtering window; zero means forward everything.
    pub drop_duration: u64,
}

#[derive(Debug, Default, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VideoLoopbackReport {
    pub packets_received: u64,
    pub descriptors_parsed: u64,
    pub structures_received: u64,
    pub frames_received: u64,
    pub frames_forwarded: u64,
    pub frames_dropped: u64,
    pub packets_dropped: u64,
    pub enhancement_frames_forwarded_after_drop: u64,
    pub max_temporal_id: u8,
}

/// Named str0m-netem presets (`NetemConfig::wifi()` etc).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetemPreset {
    Wifi,
    WifiLossy,
    WifiCongested,
    Cellular,
    Satellite,
    Congested,
}

/// One direction of str0m-netem emulation. Unset fields keep the preset's value
/// (or str0m-netem's default: no delay, no loss).
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetemLink {
    pub preset: Option<NetemPreset>,
    /// Random loss in percent (0-100). Combined with `burst_*` it becomes the
    /// background loss outside of bursts.
    pub loss_percent: Option<f32>,
    /// Correlation (0-1) between consecutive random loss decisions.
    pub loss_correlation: Option<f32>,
    /// Gilbert-Elliot bursty loss: mean number of packets between bursts.
    pub burst_interval: Option<f32>,
    /// Gilbert-Elliot bursty loss: mean number of packets lost per burst.
    pub burst_length: Option<f32>,
    pub latency_ms: Option<u64>,
    pub jitter_ms: Option<u64>,
    /// Duplicated packets in percent (0-100).
    pub duplicate_percent: Option<f32>,
    /// Every Nth packet skips the delay queue.
    pub reorder_gap: Option<u32>,
    /// Bottleneck link rate. Packets beyond `buffer_bytes` of queue are tail dropped.
    pub rate_kbps: Option<u64>,
    pub buffer_bytes: Option<u64>,
    /// RNG seed. Defaults to a value derived from the session id, so a test case
    /// sees the same loss pattern on every run.
    pub seed: Option<u64>,
}

/// str0m-netem emulation applied inside the str0m peer, between `Rtc` and the UDP socket.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetemSettings {
    /// Packets str0m sends (str0m -> remote).
    pub egress: Option<NetemLink>,
    /// Packets str0m receives (remote -> str0m).
    pub ingress: Option<NetemLink>,
}

/// Counters for one netem direction.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct NetemStats {
    /// Packets handed to the emulator.
    pub packets: u64,
    /// Packets dropped by the loss model or a full link buffer.
    pub dropped: u64,
    /// Extra copies injected by `duplicate_percent`.
    pub duplicated: u64,
}

/// What the str0m peer observed during a session. Returned in `destroyed`.
#[derive(Debug, Default, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct SessionReport {
    /// Negotiated DTLS version: "1.2", "1.3" (or the raw wire version in hex).
    pub dtls_version: Option<String>,
    /// Milliseconds from peer start until ICE + DTLS connected.
    pub connected_ms: Option<f64>,
    /// Milliseconds from peer start until the data channel opened.
    pub channel_open_ms: Option<f64>,
    /// Packets str0m sent / received (before egress netem, after ingress netem).
    pub packets_sent: u64,
    pub packets_received: u64,
    pub netem_egress: Option<NetemStats>,
    pub netem_ingress: Option<NetemStats>,
    pub video_loopback: Option<VideoLoopbackReport>,
    pub video_frame_mode: Option<Box<crate::frame_video::FrameVideoReport>>,
    /// Set when the peer event loop ended with an error.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Create {
        session_id: String,
        config: Box<SessionConfig>,
    },
    Destroy {
        session_id: String,
    },
    Sdp {
        session_id: String,
        sdp: String,
    },
    Ready {
        session_id: String,
    },
    /// Ask for the server's capabilities (answered with `ServerMessage::Info`).
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Created {
        session_id: String,
    },
    Destroyed {
        session_id: String,
        /// Present when the session's peer event loop was running.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        report: Option<SessionReport>,
    },
    Info {
        /// Active str0m crypto backend (cargo feature name).
        crypto: String,
        /// Whether the backend can negotiate DTLS 1.3 (and therefore `auto`).
        dtls13: bool,
        /// Netem applied to sessions that don't send their own `server_netem`.
        default_netem: Option<NetemSettings>,
    },
    Sdp {
        session_id: String,
        sdp: String,
    },
    Ready {
        session_id: String,
    },
    Error {
        session_id: Option<String>,
        message: String,
    },
}
