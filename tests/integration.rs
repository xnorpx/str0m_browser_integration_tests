use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use str0m::config::DtlsVersion;
use str0m_browser_integration_tests::peer::DataChannelAction;
use str0m_browser_integration_tests::protocol::*;
use str0m_browser_integration_tests::server::ServerOptions;
use str0m_browser_integration_tests::{Peer, Sessions, UdpPortAllocator, dtls13_supported};
use tokio::sync::oneshot;
use tracing::info;

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

static NEXT_WS_PORT: AtomicU16 = AtomicU16::new(19200);

fn alloc_ws_port() -> u16 {
    NEXT_WS_PORT.fetch_add(1, Ordering::Relaxed)
}

fn init() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(str0m_browser_integration_tests::log_filter())
        .with_test_writer()
        .try_init();
    str0m_browser_integration_tests::init_crypto();
}

macro_rules! expect_msg {
    ($variant:ident { $($field:ident),+ } from $msg:expr) => {
        match $msg {
            ServerMessage::$variant { $($field),+, .. } => ($($field),+),
            other => panic!(
                "Expected {}, got: {other:?}",
                stringify!($variant)
            ),
        }
    };
}

async fn start_server(ws_port: u16, options: ServerOptions) -> Sessions {
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let sessions_for_server = sessions.clone();
    let udp_ports = Arc::new(UdpPortAllocator::new(0));

    tokio::spawn(async move {
        str0m_browser_integration_tests::server::run_server(
            ws_port,
            sessions_for_server,
            LOCALHOST,
            udp_ports,
            options,
        )
        .await
        .expect("server failed");
    });

    tokio::time::sleep(Duration::from_millis(100)).await;

    sessions
}

async fn connect_ws(
    ws_port: u16,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let ws_addr = format!("ws://127.0.0.1:{ws_port}");
    let (ws, _) = tokio_tungstenite::connect_async(&ws_addr)
        .await
        .expect("WS connect failed");
    ws
}

use str0m_browser_integration_tests::client;

/// How the native client peer is set up for a test.
struct ClientOpts {
    snap_enabled: bool,
    dtls_version: Option<DtlsVersion>,
    max_echo_rtt: Duration,
    server_options: ServerOptions,
}

impl Default for ClientOpts {
    fn default() -> Self {
        Self {
            snap_enabled: true,
            dtls_version: None,
            // Loopback without netem: anything slower means the sctp-proto rwnd fix is missing.
            max_echo_rtt: Duration::from_millis(50),
            server_options: ServerOptions::default(),
        }
    }
}

struct Outcome {
    echo_rtt: Duration,
    client: SessionReport,
    server: SessionReport,
}

async fn run_connect_and_verify(test_name: &str, config: SessionConfig) {
    run_connect_and_verify_full(test_name, config, true, None).await;
}

async fn run_connect_and_verify_full(
    test_name: &str,
    config: SessionConfig,
    snap_enabled: bool,
    dtls_version: Option<DtlsVersion>,
) {
    let opts = ClientOpts {
        snap_enabled,
        dtls_version,
        ..Default::default()
    };
    run_session(test_name, config, opts).await;
}

async fn run_session(test_name: &str, config: SessionConfig, opts: ClientOpts) -> Outcome {
    init();

    let ws_port = alloc_ws_port();
    let _ = start_server(ws_port, opts.server_options).await;
    let mut ws = connect_ws(ws_port).await;

    let sid = test_name;

    info!(%sid, ?config, "=== Starting test ===");

    let msg = client::create_session(&mut ws, sid, config.clone())
        .await
        .unwrap();
    let session_id = expect_msg!(Created { session_id } from msg);
    assert_eq!(session_id, sid);

    let cert = str0m_browser_integration_tests::shared_dtls_cert();
    let mut client_peer = Peer::with_cert(
        false,
        LOCALHOST,
        0,
        Some(cert),
        opts.snap_enabled,
        opts.dtls_version,
    )
    .expect("client peer");

    match config.client_sdp_role {
        SdpRole::Offerer => {
            let offer_sdp = client_peer.create_offer("test-data").expect("offer");

            client::send_msg(
                &mut ws,
                &ClientMessage::Sdp {
                    session_id: sid.into(),
                    sdp: offer_sdp,
                },
            )
            .await
            .unwrap();

            let msg = client::recv_msg(&mut ws).await.unwrap();
            let (_, answer_sdp) = expect_msg!(Sdp { session_id, sdp } from msg);

            client_peer
                .accept_answer(&answer_sdp)
                .expect("accept answer");
        }
        SdpRole::Answerer => {
            let msg = client::recv_msg(&mut ws).await.unwrap();
            let (_, offer_sdp) = expect_msg!(Sdp { session_id, sdp } from msg);

            let answer_sdp = client_peer.accept_offer(&offer_sdp).expect("accept offer");

            client::send_msg(
                &mut ws,
                &ClientMessage::Sdp {
                    session_id: sid.into(),
                    sdp: answer_sdp,
                },
            )
            .await
            .unwrap();
        }
    }

    client::send_msg(
        &mut ws,
        &ClientMessage::Ready {
            session_id: sid.into(),
        },
    )
    .await
    .unwrap();
    let msg = client::recv_msg(&mut ws).await.unwrap();
    let _ = expect_msg!(Ready { session_id } from msg);

    let (client_connected_tx, client_connected_rx) = oneshot::channel();
    let (client_chan_open_tx, client_chan_open_rx) = oneshot::channel();
    let (client_shutdown_tx, client_shutdown_rx) = oneshot::channel();

    let ping_message = b"hello from browser!".to_vec();
    let (echo_result_tx, echo_result_rx) = oneshot::channel();

    let sid_client = sid.to_string();
    let client_handle = tokio::spawn(async move {
        client_peer
            .run(
                &sid_client,
                "client",
                client_connected_tx,
                client_chan_open_tx,
                DataChannelAction::SendAndExpectEcho {
                    message: ping_message,
                    result_tx: echo_result_tx,
                },
                client_shutdown_rx,
            )
            .await
    });

    within("client connect", client_connected_rx)
        .await
        .expect("client never connected");

    within("client channel open", client_chan_open_rx)
        .await
        .expect("client channel never opened");

    let echo_rtt = within("echo", echo_result_rx)
        .await
        .expect("echo result channel dropped");
    let rtt = echo_rtt.expect("Data channel echo did not match the sent message");

    assert!(
        rtt < opts.max_echo_rtt,
        "Echo RTT too high: {rtt:?} (expected < {:?})",
        opts.max_echo_rtt
    );

    info!(%sid, ?rtt, "Data channel echo verified");

    client::send_msg(
        &mut ws,
        &ClientMessage::Destroy {
            session_id: sid.into(),
        },
    )
    .await
    .unwrap();

    let msg = client::recv_msg(&mut ws).await.unwrap();
    let (destroyed_id, server_report) = expect_msg!(Destroyed { session_id, report } from msg);
    assert_eq!(destroyed_id, sid);
    let server_report = server_report.expect("destroyed carries the server report");
    assert_eq!(server_report.error, None, "server peer failed");

    ws.close(None).await.ok();

    let _ = client_shutdown_tx.send(());

    let client_report = client_handle.await.expect("client task panicked");
    assert_eq!(client_report.error, None, "client run failed");
    assert_eq!(
        client_report.dtls_version, server_report.dtls_version,
        "both peers must agree on the negotiated DTLS version"
    );

    info!(%sid, ?server_report, "=== Test passed ===");

    Outcome {
        echo_rtt: rtt,
        client: client_report,
        server: server_report,
    }
}

/// Highest DTLS version both sides can negotiate when the server runs `Auto`.
fn auto_version() -> &'static str {
    if dtls13_supported() { "1.3" } else { "1.2" }
}

/// Fail instead of hanging when a connection never completes (generous for netem tests).
async fn within<F: std::future::IntoFuture>(what: &str, fut: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(60), fut)
        .await
        .unwrap_or_else(|_| panic!("timed out waiting for {what}"))
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_offerer_dtls_active_ice_lite() {
    run_connect_and_verify(
        "offerer_active_lite",
        SessionConfig::new(SdpRole::Offerer, IceMode::Lite, DtlsRole::Active),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_offerer_dtls_active_ice_full() {
    run_connect_and_verify(
        "offerer_active_full",
        SessionConfig::new(SdpRole::Offerer, IceMode::Full, DtlsRole::Active),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_offerer_dtls_passive_ice_lite() {
    run_connect_and_verify(
        "offerer_passive_lite",
        SessionConfig::new(SdpRole::Offerer, IceMode::Lite, DtlsRole::Passive),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_offerer_dtls_passive_ice_full() {
    run_connect_and_verify(
        "offerer_passive_full",
        SessionConfig::new(SdpRole::Offerer, IceMode::Full, DtlsRole::Passive),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_answerer_dtls_active_ice_lite() {
    run_connect_and_verify(
        "answerer_active_lite",
        SessionConfig::new(SdpRole::Answerer, IceMode::Lite, DtlsRole::Active),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_answerer_dtls_active_ice_full() {
    run_connect_and_verify(
        "answerer_active_full",
        SessionConfig::new(SdpRole::Answerer, IceMode::Full, DtlsRole::Active),
    )
    .await;
}

// ---------------------------------------------------------------------------
// SNAP tests: verify connection with SNAP enabled and disabled (native only)
// ---------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
async fn snap_on_offerer_active_lite() {
    run_connect_and_verify_full(
        "snap_on_offerer_active_lite",
        SessionConfig::new(SdpRole::Offerer, IceMode::Lite, DtlsRole::Active),
        true,
        None,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn snap_off_offerer_active_lite() {
    run_connect_and_verify_full(
        "snap_off_offerer_active_lite",
        SessionConfig::new(SdpRole::Offerer, IceMode::Lite, DtlsRole::Active),
        false,
        None,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn snap_on_answerer_active_lite() {
    run_connect_and_verify_full(
        "snap_on_answerer_active_lite",
        SessionConfig::new(SdpRole::Answerer, IceMode::Lite, DtlsRole::Active),
        true,
        None,
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn snap_off_answerer_active_lite() {
    run_connect_and_verify_full(
        "snap_off_answerer_active_lite",
        SessionConfig::new(SdpRole::Answerer, IceMode::Lite, DtlsRole::Active),
        false,
        None,
    )
    .await;
}

// ---------------------------------------------------------------------------
// DTLS version tests: verify connection with forced DTLS 1.2 and 1.3
// ---------------------------------------------------------------------------

const fn with_server_dtls(mut config: SessionConfig, version: ServerDtlsVersion) -> SessionConfig {
    config.server_dtls_version = version;
    config
}

#[tokio::test(flavor = "multi_thread")]
async fn dtls12_offerer_active_lite() {
    run_connect_and_verify_full(
        "dtls12_offerer_active_lite",
        with_server_dtls(
            SessionConfig::new(SdpRole::Offerer, IceMode::Lite, DtlsRole::Active),
            ServerDtlsVersion::Dtls12,
        ),
        true,
        Some(DtlsVersion::Dtls12),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dtls12_answerer_active_lite() {
    run_connect_and_verify_full(
        "dtls12_answerer_active_lite",
        with_server_dtls(
            SessionConfig::new(SdpRole::Answerer, IceMode::Lite, DtlsRole::Active),
            ServerDtlsVersion::Dtls12,
        ),
        true,
        Some(DtlsVersion::Dtls12),
    )
    .await;
}

/// Runs a DTLS 1.3 session; it must pass on backends that support DTLS 1.3 and is
/// rejected by the server (create -> error) on the others (plain openssl).
async fn run_dtls13(test_name: &'static str, sdp_role: SdpRole) {
    init();
    let config = with_server_dtls(
        SessionConfig::new(sdp_role, IceMode::Lite, DtlsRole::Active),
        ServerDtlsVersion::Dtls13,
    );
    let result = tokio::spawn(run_connect_and_verify_full(
        test_name,
        config,
        true,
        Some(DtlsVersion::Dtls13),
    ))
    .await;

    if dtls13_supported() {
        result.expect("DTLS 1.3 must work on a backend that supports it");
    } else {
        assert!(
            result.is_err(),
            "server must reject DTLS 1.3 on this backend"
        );
        eprintln!("{test_name}: rejected as expected (crypto backend has no DTLS 1.3)");
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn dtls13_offerer_active_lite() {
    run_dtls13("dtls13_offerer_active_lite", SdpRole::Offerer).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dtls13_answerer_active_lite() {
    run_dtls13("dtls13_answerer_active_lite", SdpRole::Answerer).await;
}

// ---------------------------------------------------------------------------
// DTLS auto tests: `auto` must pick the highest version the remote supports,
// both when str0m is the DTLS server and when it is the DTLS client.
// ---------------------------------------------------------------------------

/// `DtlsVersion::Auto` where the backend supports it; plain `openssl` is DTLS 1.2 only
/// and `RtcConfig::build` panics on anything else.
fn client_auto() -> DtlsVersion {
    if dtls13_supported() {
        DtlsVersion::Auto
    } else {
        DtlsVersion::Dtls12
    }
}

async fn run_auto(
    test_name: &str,
    client_dtls_role: DtlsRole,
    client_version: DtlsVersion,
    expected: &str,
) {
    init();
    let client_version = if dtls13_supported() {
        client_version
    } else {
        DtlsVersion::Dtls12
    };
    let outcome = run_session(
        test_name,
        SessionConfig::new(SdpRole::Offerer, IceMode::Lite, client_dtls_role),
        ClientOpts {
            dtls_version: Some(client_version),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(outcome.server.dtls_version.as_deref(), Some(expected));
}

#[tokio::test(flavor = "multi_thread")]
async fn dtls_auto_server_auto_client() {
    run_auto(
        "auto_cauto_offerer_active_lite",
        DtlsRole::Active,
        DtlsVersion::Auto,
        auto_version(),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dtls_auto_client_auto_server() {
    run_auto(
        "auto_cauto_offerer_passive_lite",
        DtlsRole::Passive,
        DtlsVersion::Auto,
        auto_version(),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dtls_auto_server_falls_back_to_dtls12_client() {
    run_auto(
        "auto_c12_offerer_active_lite",
        DtlsRole::Active,
        DtlsVersion::Dtls12,
        "1.2",
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn dtls_auto_client_falls_back_to_dtls12_server() {
    run_auto(
        "auto_c12_offerer_passive_lite",
        DtlsRole::Passive,
        DtlsVersion::Dtls12,
        "1.2",
    )
    .await;
}

// ---------------------------------------------------------------------------
// Netem tests: str0m-netem on the server's egress and ingress path.
// ---------------------------------------------------------------------------

fn with_netem(mut config: SessionConfig, link: NetemLink) -> SessionConfig {
    config.server_netem = Some(NetemSettings {
        egress: Some(link.clone()),
        ingress: Some(link),
    });
    config
}

/// str0m's plain OpenSSL DTLS backend never retransmits handshake flights, so a single
/// lost handshake packet stalls it; loss recovery is only testable on the dimpl backends.
fn skip_loss_test(test_name: &str) -> bool {
    let skip = str0m_browser_integration_tests::crypto_backend_name() == "openssl";
    if skip {
        eprintln!(
            "{test_name}: skipped, the plain openssl backend doesn't retransmit DTLS flights"
        );
    }
    skip
}

#[tokio::test(flavor = "multi_thread")]
async fn netem_latency_delays_both_directions() {
    let outcome = run_session(
        "netem_latency_offerer_active_lite",
        with_netem(
            SessionConfig::new(SdpRole::Offerer, IceMode::Lite, DtlsRole::Active),
            NetemLink {
                latency_ms: Some(25),
                ..Default::default()
            },
        ),
        ClientOpts {
            max_echo_rtt: Duration::from_secs(2),
            ..Default::default()
        },
    )
    .await;

    // The ping waits 25 ms on server ingress and the echo 25 ms on server egress.
    assert!(
        outcome.echo_rtt >= Duration::from_millis(50),
        "echo RTT {:?} must include both netem delays",
        outcome.echo_rtt
    );
    for stats in [outcome.server.netem_egress, outcome.server.netem_ingress] {
        let stats = stats.expect("netem stats in report");
        assert!(stats.packets > 0);
        assert_eq!(stats.dropped, 0);
    }
    assert_eq!(outcome.client.netem_egress, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn netem_loss_recovers_dtls_auto_offerer() {
    if skip_loss_test("netem_loss_recovers_dtls_auto_offerer") {
        return;
    }
    let outcome = run_session(
        "netem_loss10_offerer_active_lite",
        with_netem(
            SessionConfig::new(SdpRole::Offerer, IceMode::Lite, DtlsRole::Active),
            NetemLink {
                loss_percent: Some(10.0),
                ..Default::default()
            },
        ),
        ClientOpts {
            dtls_version: Some(client_auto()),
            max_echo_rtt: Duration::from_secs(20),
            ..Default::default()
        },
    )
    .await;

    // The loss pattern is seeded from the session id, so this is deterministic.
    let dropped: u64 = [outcome.server.netem_egress, outcome.server.netem_ingress]
        .into_iter()
        .map(|s| s.expect("netem stats in report").dropped)
        .sum();
    assert!(
        dropped > 0,
        "10% loss must drop packets: {:?}",
        outcome.server
    );
    assert_eq!(outcome.server.dtls_version.as_deref(), Some(auto_version()));
}

#[tokio::test(flavor = "multi_thread")]
async fn netem_burst_loss_recovers_dtls12_answerer() {
    if skip_loss_test("netem_burst_loss_recovers_dtls12_answerer") {
        return;
    }
    let config = with_server_dtls(
        SessionConfig::new(SdpRole::Answerer, IceMode::Lite, DtlsRole::Active),
        ServerDtlsVersion::Dtls12,
    );
    let outcome = run_session(
        "netem_burst_answerer_active_lite",
        with_netem(
            config,
            NetemLink {
                burst_interval: Some(15.0),
                burst_length: Some(3.0),
                ..Default::default()
            },
        ),
        ClientOpts {
            dtls_version: Some(DtlsVersion::Dtls12),
            max_echo_rtt: Duration::from_secs(20),
            ..Default::default()
        },
    )
    .await;
    assert_eq!(outcome.server.dtls_version.as_deref(), Some("1.2"));
}

#[tokio::test(flavor = "multi_thread")]
async fn netem_server_default_applies_without_session_netem() {
    let outcome = run_session(
        "netem_default_offerer_active_lite",
        SessionConfig::new(SdpRole::Offerer, IceMode::Lite, DtlsRole::Active),
        ClientOpts {
            max_echo_rtt: Duration::from_secs(2),
            server_options: ServerOptions {
                default_netem: Some(NetemSettings {
                    egress: None,
                    ingress: Some("latency=30ms".parse().expect("valid spec")),
                }),
            },
            ..Default::default()
        },
    )
    .await;

    assert!(outcome.echo_rtt >= Duration::from_millis(30));
    assert!(outcome.server.netem_ingress.is_some());
    assert_eq!(outcome.server.netem_egress, None);
}

#[tokio::test(flavor = "multi_thread")]
async fn server_info_and_netem_validation() {
    init();
    let ws_port = alloc_ws_port();
    let _ = start_server(ws_port, ServerOptions::default()).await;
    let mut ws = connect_ws(ws_port).await;

    client::send_msg(&mut ws, &ClientMessage::Info)
        .await
        .unwrap();
    match client::recv_msg(&mut ws).await.unwrap() {
        ServerMessage::Info { crypto, dtls13, .. } => {
            assert_eq!(
                crypto,
                str0m_browser_integration_tests::crypto_backend_name()
            );
            assert_eq!(dtls13, dtls13_supported());
        }
        other => panic!("Expected Info, got: {other:?}"),
    }

    let config = with_netem(
        SessionConfig::new(SdpRole::Offerer, IceMode::Lite, DtlsRole::Active),
        NetemLink {
            loss_percent: Some(150.0),
            ..Default::default()
        },
    );
    let msg = client::create_session(&mut ws, "invalid_netem", config)
        .await
        .unwrap();
    let (_, message) = expect_msg!(Error { session_id, message } from msg);
    assert!(message.contains("loss_percent"), "{message}");
}
