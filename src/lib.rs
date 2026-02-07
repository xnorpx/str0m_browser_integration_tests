pub mod client;
mod net;
pub mod pcap;
pub mod peer;
pub mod protocol;
pub mod server;

use std::collections::HashMap;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use str0m::config::DtlsCert;

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
        self.next.fetch_add(1, Ordering::Relaxed)
    }
}

/// Initialise the str0m crypto provider (safe to call multiple times).
pub fn init_crypto() {
    str0m::crypto::from_feature_flags().install_process_default();
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
