//! str0m-netem integration: turns [`NetemLink`] settings into emulators that sit
//! between str0m's `Rtc` and the UDP socket of a [`crate::Peer`].

use std::net::SocketAddr;
use std::str::FromStr;
use std::time::{Duration, Instant};

use str0m_netem::{
    Bitrate, DataSize, GilbertElliot, Input, Netem, NetemConfig, Output, Probability, RandomLoss,
};

use crate::protocol::{NetemLink, NetemPreset, NetemSettings, NetemStats};

const DEFAULT_BURST_INTERVAL: f32 = 50.0;
const DEFAULT_BURST_LENGTH: f32 = 2.0;
const DEFAULT_BUFFER_BYTES: u64 = 64 * 1024;

/// Mixed into the session seed so egress and ingress draw independent loss patterns.
const INGRESS_SEED_SALT: u64 = 0x9E37_79B9_7F4A_7C15;

impl NetemPreset {
    pub const ALL: [Self; 6] = [
        Self::Wifi,
        Self::WifiLossy,
        Self::WifiCongested,
        Self::Cellular,
        Self::Satellite,
        Self::Congested,
    ];

    pub const fn name(self) -> &'static str {
        match self {
            Self::Wifi => "wifi",
            Self::WifiLossy => "wifi_lossy",
            Self::WifiCongested => "wifi_congested",
            Self::Cellular => "cellular",
            Self::Satellite => "satellite",
            Self::Congested => "congested",
        }
    }

    fn config(self) -> NetemConfig {
        match self {
            Self::Wifi => NetemConfig::wifi(),
            Self::WifiLossy => NetemConfig::wifi_lossy(),
            Self::WifiCongested => NetemConfig::wifi_congested(),
            Self::Cellular => NetemConfig::cellular(),
            Self::Satellite => NetemConfig::satellite(),
            Self::Congested => NetemConfig::congested(),
        }
    }
}

impl FromStr for NetemPreset {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let wanted = s.trim().replace('-', "_").to_ascii_lowercase();
        Self::ALL
            .into_iter()
            .find(|p| p.name() == wanted)
            .ok_or_else(|| {
                let names: Vec<_> = Self::ALL.iter().map(|p| p.name()).collect();
                format!("unknown netem preset {s:?} (expected one of {names:?})")
            })
    }
}

impl NetemLink {
    /// Reject values str0m-netem can't represent.
    pub fn validate(&self) -> Result<(), String> {
        let percent = |name: &str, v: Option<f32>| match v {
            Some(v) if !(0.0..=100.0).contains(&v) => {
                Err(format!("{name} must be within 0..=100, got {v}"))
            }
            _ => Ok(()),
        };
        percent("loss_percent", self.loss_percent)?;
        percent("duplicate_percent", self.duplicate_percent)?;
        if let Some(c) = self.loss_correlation
            && !(0.0..=1.0).contains(&c)
        {
            return Err(format!("loss_correlation must be within 0..=1, got {c}"));
        }
        if self.loss_correlation.is_some() && self.loss_percent.is_none() {
            return Err("loss_correlation requires loss_percent".into());
        }
        if self.loss_correlation.is_some() && self.is_bursty() {
            return Err("loss_correlation can't be combined with burst loss".into());
        }
        for (name, v) in [
            ("burst_interval", self.burst_interval),
            ("burst_length", self.burst_length),
        ] {
            if let Some(v) = v
                && (v < 1.0 || !v.is_finite())
            {
                return Err(format!("{name} must be >= 1 packet, got {v}"));
            }
        }
        if self.reorder_gap == Some(0) {
            return Err("reorder_gap must be >= 1".into());
        }
        if self.rate_kbps == Some(0) {
            return Err("rate_kbps must be > 0".into());
        }
        if self.buffer_bytes.is_some() && self.rate_kbps.is_none() {
            return Err("buffer_bytes requires rate_kbps".into());
        }
        Ok(())
    }

    const fn is_bursty(&self) -> bool {
        self.burst_interval.is_some() || self.burst_length.is_some()
    }

    /// Build the str0m-netem configuration. `default_seed` is used unless `seed` is set.
    pub fn to_config(&self, default_seed: u64) -> NetemConfig {
        let mut config = self
            .preset
            .map_or_else(NetemConfig::new, NetemPreset::config);

        if let Some(ms) = self.latency_ms {
            config = config.latency(Duration::from_millis(ms));
        }
        if let Some(ms) = self.jitter_ms {
            config = config.jitter(Duration::from_millis(ms));
        }
        if self.is_bursty() {
            let mut ge = GilbertElliot::new()
                .good_duration(self.burst_interval.unwrap_or(DEFAULT_BURST_INTERVAL))
                .bad_duration(self.burst_length.unwrap_or(DEFAULT_BURST_LENGTH));
            if let Some(pct) = self.loss_percent {
                ge = ge.loss_in_good(percent(pct));
            }
            config = config.loss(ge);
        } else if let Some(pct) = self.loss_percent {
            let mut loss = RandomLoss::new(percent(pct));
            if let Some(c) = self.loss_correlation {
                loss = loss.correlation(Probability::new(c.clamp(0.0, 1.0)));
            }
            config = config.loss(loss);
        }
        if let Some(pct) = self.duplicate_percent {
            config = config.duplicate(percent(pct));
        }
        if let Some(gap) = self.reorder_gap {
            config = config.reorder_gap(gap);
        }
        if let Some(kbps) = self.rate_kbps {
            let buffer = self.buffer_bytes.unwrap_or(DEFAULT_BUFFER_BYTES);
            config = config.link(
                Bitrate::kbps(kbps),
                DataSize::bytes(i64::try_from(buffer).unwrap_or(i64::MAX)),
            );
        }
        config.seed(self.seed.unwrap_or(default_seed))
    }
}

fn percent(value: f32) -> Probability {
    Probability::new((value / 100.0).clamp(0.0, 1.0))
}

/// Parses the compact command line form: a preset name and/or comma separated
/// `key=value` pairs, e.g. `loss=5`, `cellular,seed=7` or `burst=20:3,latency=40ms`.
///
/// Keys: `preset`, `loss` (%), `corr` (0-1), `burst` (`interval:length` packets),
/// `latency`/`jitter` (ms), `dup` (%), `reorder` (gap), `rate` (kbps), `buffer` (bytes), `seed`.
impl FromStr for NetemLink {
    type Err = String;

    fn from_str(spec: &str) -> Result<Self, Self::Err> {
        let mut link = Self::default();
        for part in spec.split(',').map(str::trim).filter(|p| !p.is_empty()) {
            let Some((key, value)) = part.split_once('=') else {
                link.preset = Some(part.parse()?);
                continue;
            };
            let value = value.trim();
            match key.trim().to_ascii_lowercase().as_str() {
                "preset" => link.preset = Some(value.parse()?),
                "loss" => link.loss_percent = Some(parse_num(key, value.trim_end_matches('%'))?),
                "corr" | "loss_corr" | "loss_correlation" => {
                    link.loss_correlation = Some(parse_num(key, value)?);
                }
                "burst" => {
                    let (interval, length) = value.split_once(':').ok_or_else(|| {
                        format!("burst expects <interval>:<length>, got {value:?}")
                    })?;
                    link.burst_interval = Some(parse_num(key, interval)?);
                    link.burst_length = Some(parse_num(key, length)?);
                }
                "latency" | "delay" => link.latency_ms = Some(parse_ms(key, value)?),
                "jitter" => link.jitter_ms = Some(parse_ms(key, value)?),
                "dup" | "duplicate" => {
                    link.duplicate_percent = Some(parse_num(key, value.trim_end_matches('%'))?);
                }
                "reorder" => link.reorder_gap = Some(parse_num(key, value)?),
                "rate" => link.rate_kbps = Some(parse_num(key, value.trim_end_matches("kbps"))?),
                "buffer" => link.buffer_bytes = Some(parse_num(key, value)?),
                "seed" => link.seed = Some(parse_num(key, value)?),
                other => return Err(format!("unknown netem key {other:?} in {spec:?}")),
            }
        }
        link.validate()?;
        Ok(link)
    }
}

fn parse_num<T: FromStr>(key: &str, value: &str) -> Result<T, String> {
    value
        .trim()
        .parse()
        .map_err(|_| format!("invalid value {value:?} for netem key {key:?}"))
}

fn parse_ms(key: &str, value: &str) -> Result<u64, String> {
    parse_num(key, value.trim().trim_end_matches("ms"))
}

impl NetemSettings {
    pub fn validate(&self) -> Result<(), String> {
        if let Some(link) = &self.egress {
            link.validate().map_err(|e| format!("egress: {e}"))?;
        }
        if let Some(link) = &self.ingress {
            link.validate().map_err(|e| format!("ingress: {e}"))?;
        }
        Ok(())
    }

    pub const fn is_empty(&self) -> bool {
        self.egress.is_none() && self.ingress.is_none()
    }
}

/// Stable seed for a session (FNV-1a), so a test case replays the same loss pattern.
pub fn session_seed(session_id: &str) -> u64 {
    session_id.bytes().fold(0xcbf2_9ce4_8422_2325, |hash, b| {
        (hash ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// A datagram travelling through a [`NetemPath`]. `addr` is the destination for
/// egress and the source for ingress.
#[derive(Clone)]
pub(crate) struct NetPacket {
    pub addr: SocketAddr,
    pub data: Vec<u8>,
}

impl AsRef<[u8]> for NetPacket {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// One emulated direction plus counters.
pub(crate) struct NetemPath {
    netem: Netem<NetPacket>,
    stats: NetemStats,
}

impl NetemPath {
    pub(crate) fn new(config: NetemConfig) -> Self {
        Self {
            netem: Netem::new(config),
            stats: NetemStats::default(),
        }
    }

    /// Build the (egress, ingress) paths for a session.
    pub(crate) fn from_settings(
        settings: &NetemSettings,
        seed: u64,
    ) -> (Option<Self>, Option<Self>) {
        let egress = settings
            .egress
            .as_ref()
            .map(|l| Self::new(l.to_config(seed)));
        let ingress = settings
            .ingress
            .as_ref()
            .map(|l| Self::new(l.to_config(seed ^ INGRESS_SEED_SALT)));
        (egress, ingress)
    }

    pub(crate) fn push(&mut self, now: Instant, packet: NetPacket) {
        let before = self.netem.queue_len();
        self.netem.handle_input(Input::Packet(now, packet));
        let queued = self.netem.queue_len().saturating_sub(before) as u64;
        self.stats.packets += 1;
        if queued == 0 {
            self.stats.dropped += 1;
        } else {
            self.stats.duplicated += queued - 1;
        }
    }

    /// Next packet whose emulated delay has elapsed at `now`.
    pub(crate) fn pop(&mut self, now: Instant) -> Option<NetPacket> {
        self.netem.handle_input(Input::Timeout(now));
        match self.netem.poll_output() {
            Some(Output::Packet(packet)) => Some(packet),
            Some(Output::Timeout(_)) | None => None,
        }
    }

    pub(crate) fn next_deadline(&self) -> Option<Instant> {
        (!self.netem.is_empty()).then(|| self.netem.poll_timeout())
    }

    pub(crate) const fn stats(&self) -> NetemStats {
        self.stats
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_compact_specs() {
        let link: NetemLink = "loss=5,latency=40ms,jitter=5,seed=7".parse().unwrap();
        assert_eq!(
            link,
            NetemLink {
                loss_percent: Some(5.0),
                latency_ms: Some(40),
                jitter_ms: Some(5),
                seed: Some(7),
                ..Default::default()
            }
        );

        let link: NetemLink = "wifi-lossy,burst=20:3,dup=1%".parse().unwrap();
        assert_eq!(link.preset, Some(NetemPreset::WifiLossy));
        assert_eq!(link.burst_interval, Some(20.0));
        assert_eq!(link.burst_length, Some(3.0));
        assert_eq!(link.duplicate_percent, Some(1.0));

        assert!("loss=150".parse::<NetemLink>().is_err());
        assert!("corr=0.5".parse::<NetemLink>().is_err());
        assert!("lte".parse::<NetemLink>().is_err());
        assert!("bogus=1".parse::<NetemLink>().is_err());
    }

    #[test]
    fn json_round_trip() {
        let settings: NetemSettings = serde_json::from_str(
            r#"{"egress":{"loss_percent":10},"ingress":{"preset":"cellular"}}"#,
        )
        .unwrap();
        assert_eq!(settings.egress.unwrap().loss_percent, Some(10.0));
        assert_eq!(
            settings.ingress.unwrap().preset,
            Some(NetemPreset::Cellular)
        );
        assert!(serde_json::from_str::<NetemSettings>(r#"{"egress":{"lost":1}}"#).is_err());
    }

    #[test]
    fn counts_drops_and_delays_packets() {
        let addr: SocketAddr = "127.0.0.1:1".parse().unwrap();
        let packet = || NetPacket {
            addr,
            data: vec![0; 100],
        };
        let start = Instant::now();

        let mut lossy = NetemPath::new(
            NetemLink {
                loss_percent: Some(100.0),
                ..Default::default()
            }
            .to_config(1),
        );
        lossy.push(start, packet());
        assert!(lossy.pop(start).is_none());
        assert_eq!(lossy.stats().dropped, 1);

        let mut delayed = NetemPath::new(
            NetemLink {
                latency_ms: Some(30),
                ..Default::default()
            }
            .to_config(1),
        );
        delayed.push(start, packet());
        assert!(delayed.pop(start).is_none());
        assert_eq!(
            delayed.next_deadline(),
            Some(start + Duration::from_millis(30))
        );
        assert!(delayed.pop(start + Duration::from_millis(30)).is_some());
        assert_eq!(delayed.stats().dropped, 0);
    }

    #[test]
    fn session_seed_is_stable() {
        assert_eq!(session_seed("abc"), session_seed("abc"));
        assert_ne!(session_seed("abc"), session_seed("abd"));
    }
}
