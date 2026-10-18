use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use clap::Parser;
use mimalloc::MiMalloc;
use str0m_browser_integration_tests::{NetemLink, NetemSettings, server::ServerOptions};
use tracing::info;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// str0m browser integration test server
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// WebSocket port for signaling
    #[arg(long, default_value_t = 9090)]
    ws_port: u16,

    /// First UDP port for WebRTC peers (each peer gets the next port).
    /// Set to 0 for OS-assigned ports.
    #[arg(long, default_value_t = 30000)]
    udp_port_start: u16,

    /// Advertised public IP address. If not given, auto-detects from network interfaces.
    #[arg(long)]
    adv_addr: Option<IpAddr>,

    /// str0m-netem emulation for both directions of every session that doesn't send its
    /// own `server_netem`. A preset and/or comma separated key=value pairs, e.g.
    /// "loss=5", "cellular", "burst=20:3,latency=40ms". Keys: preset, loss (%), corr,
    /// burst (interval:length), latency (ms), jitter (ms), dup (%), reorder, rate (kbps),
    /// buffer (bytes), seed.
    #[arg(long, value_name = "SPEC")]
    netem: Option<NetemLink>,

    /// Like --netem, but only for packets str0m sends. Overrides --netem.
    #[arg(long, value_name = "SPEC")]
    netem_egress: Option<NetemLink>,

    /// Like --netem, but only for packets str0m receives. Overrides --netem.
    #[arg(long, value_name = "SPEC")]
    netem_ingress: Option<NetemLink>,
}

impl Cli {
    fn default_netem(&self) -> Option<NetemSettings> {
        let settings = NetemSettings {
            egress: self.netem_egress.clone().or_else(|| self.netem.clone()),
            ingress: self.netem_ingress.clone().or_else(|| self.netem.clone()),
        };
        (!settings.is_empty()).then_some(settings)
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(str0m_browser_integration_tests::log_filter())
        .init();
    str0m_browser_integration_tests::init_crypto();

    let cli = Cli::parse();

    let adv_addr = match cli.adv_addr {
        Some(addr) => addr,
        None => str0m_browser_integration_tests::detect_public_ip()?,
    };

    let sessions: str0m_browser_integration_tests::Sessions = Arc::new(Mutex::new(HashMap::new()));
    let udp_ports = Arc::new(str0m_browser_integration_tests::UdpPortAllocator::new(
        cli.udp_port_start,
    ));
    let options = ServerOptions {
        default_netem: cli.default_netem(),
    };

    info!(ws_port = cli.ws_port, udp_port_start = cli.udp_port_start, %adv_addr, "Starting server");

    str0m_browser_integration_tests::server::run_server(
        cli.ws_port,
        sessions,
        adv_addr,
        udp_ports,
        options,
    )
    .await
}
