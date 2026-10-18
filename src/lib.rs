pub mod client;
mod net;
pub mod netem;
pub mod pcap;
pub mod peer;
pub mod protocol;
pub mod server;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Instant;

use str0m::config::{DtlsCert, DtlsVersion};

pub use net::detect_public_ip;
pub use peer::Peer;
pub use protocol::*;

/// State for a single WebRTC session.
pub struct Session {
    pub config: SessionConfig,
    pub peer: Peer,
}

/// Shared server state across all WebSocket connections.
pub type Sessions = Arc<Mutex<HashMap<String, Session>>>;

/// Allocates UDP ports from a configurable range.
///
/// When `start` is 0, every call returns 0 (OS-assigned).
/// Otherwise, ports are handed out sequentially starting from `start`.
pub struct UdpPortAllocator {
    next: AtomicU16,
    start: u16,
}

impl UdpPortAllocator {
    pub const fn new(start: u16) -> Self {
        Self {
            next: AtomicU16::new(start),
            start,
        }
    }

    /// Return the next UDP port. Returns 0 when the allocator was
    /// created with start=0 (OS-assigned mode).
    pub fn next_port(&self) -> u16 {
        if self.start == 0 {
            return 0;
        }
        let port = self.next.fetch_add(1, Ordering::Relaxed);
        if port == u16::MAX {
            panic!("UDP port allocator exhausted");
        }
        port
    }
}

/// Initialise the str0m crypto provider (safe to call multiple times).
pub fn init_crypto() {
    str0m::crypto::from_feature_flags().install_process_default();
}

/// Log filter from `RUST_LOG`, defaulting to `info`.
///
/// Directives match targets by prefix, so `str0m=warn` would also silence this crate
/// (`str0m_browser_integration_tests`); keep it at `info` unless `RUST_LOG` names it.
pub fn log_filter() -> tracing_subscriber::EnvFilter {
    use tracing_subscriber::EnvFilter;

    const CRATE: &str = env!("CARGO_CRATE_NAME");
    let spec = std::env::var("RUST_LOG").unwrap_or_default();
    let filter = match spec.trim() {
        "" => EnvFilter::new("info"),
        spec => EnvFilter::try_new(spec).unwrap_or_else(|_| EnvFilter::new("info")),
    };
    if spec.contains(CRATE) {
        return filter;
    }
    filter.add_directive(
        format!("{CRATE}=info")
            .parse()
            .expect("valid crate directive"),
    )
}

/// Return a lazily-generated DTLS certificate that is reused across all peers.
/// This avoids the ~100-140 ms key-generation cost on every `Peer::new` call.
static SHARED_CERT: OnceLock<DtlsCert> = OnceLock::new();

pub fn shared_dtls_cert() -> &'static DtlsCert {
    SHARED_CERT.get_or_init(|| {
        let provider = str0m::crypto::from_feature_flags();
        provider
            .dtls_provider
            .generate_certificate()
            .expect("failed to generate DTLS certificate")
    })
}

/// Whether the active crypto backend can run DTLS 1.3 (and therefore `DtlsVersion::Auto`).
///
/// Probed at runtime because `RtcConfig::build` panics when the backend rejects the
/// configured version (plain `openssl` is DTLS 1.2 only).
pub fn dtls13_supported() -> bool {
    static SUPPORTED: OnceLock<bool> = OnceLock::new();
    *SUPPORTED.get_or_init(|| {
        let provider = str0m::crypto::from_feature_flags();
        provider
            .dtls_provider
            .new_dtls(
                shared_dtls_cert(),
                Instant::now(),
                DtlsVersion::Dtls13,
                None,
            )
            .is_ok()
    })
}

/// Cargo feature name of the crypto backend `str0m::crypto::from_feature_flags` picks.
pub const fn crypto_backend_name() -> &'static str {
    if cfg!(feature = "aws-lc-rs") {
        "aws-lc-rs"
    } else if cfg!(feature = "rust-crypto") {
        "rust-crypto"
    } else if cfg!(feature = "openssl-dimpl") {
        "openssl-dimpl"
    } else if cfg!(feature = "openssl") {
        "openssl"
    } else if cfg!(feature = "apple-crypto") {
        "apple-crypto"
    } else if cfg!(feature = "wincrypto-dimpl") {
        "wincrypto-dimpl"
    } else {
        "unknown"
    }
}
