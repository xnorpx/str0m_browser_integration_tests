use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};

use str0m_browser_integration_tests::peer::DataChannelAction;
use str0m_browser_integration_tests::protocol::*;
use str0m_browser_integration_tests::{Peer, Sessions, UdpPortAllocator};
use tokio::sync::oneshot;
use tracing::info;

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

static NEXT_WS_PORT: AtomicU16 = AtomicU16::new(19200);

fn alloc_ws_port() -> u16 {
    NEXT_WS_PORT.fetch_add(1, Ordering::Relaxed)
}

fn init() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    str0m_browser_integration_tests::init_crypto();
}

macro_rules! expect_msg {
    ($variant:ident { $($field:ident),+ } from $msg:expr) => {
        match $msg {
            ServerMessage::$variant { $($field),+ } => ($($field),+),
            other => panic!(
                "Expected {}, got: {other:?}",
                stringify!($variant)
            ),
        }
    };
}

async fn start_server(ws_port: u16) -> Sessions {
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let sessions_for_server = sessions.clone();
    let udp_ports = Arc::new(UdpPortAllocator::new(0));

    tokio::spawn(async move {
        str0m_browser_integration_tests::server::run_server(
            ws_port,
            sessions_for_server,
            LOCALHOST,
            udp_ports,
        )
        .await
        .expect("server failed");
    });

    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

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

async fn run_connect_and_verify(test_name: &str, config: SessionConfig) {
    init();

    let ws_port = alloc_ws_port();
    let _ = start_server(ws_port).await;
    let mut ws = connect_ws(ws_port).await;

    let sid = test_name;

    info!(%sid, ?config, "=== Starting test ===");

    let msg = client::create_session(&mut ws, sid, config.clone())
        .await
        .unwrap();
    let session_id = expect_msg!(Created { session_id } from msg);
    assert_eq!(session_id, sid);

    let cert = str0m_browser_integration_tests::shared_dtls_cert();
    let mut client_peer = Peer::with_cert(false, LOCALHOST, 0, Some(cert)).expect("client peer");

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

    client_connected_rx.await.expect("client never connected");

    client_chan_open_rx
        .await
        .expect("client channel never opened");

    let echo_rtt = echo_result_rx.await.expect("echo result channel dropped");
    let rtt = echo_rtt.expect("Data channel echo did not match the sent message");

    assert!(
        rtt < std::time::Duration::from_millis(50),
        "Echo RTT too high: {rtt:?} (expected < 50ms - is the sctp-proto rwnd fix applied?)"
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
    let destroyed_id = expect_msg!(Destroyed { session_id } from msg);
    assert_eq!(destroyed_id, sid);

    ws.close(None).await.ok();

    let _ = client_shutdown_tx.send(());

    client_handle
        .await
        .expect("client task panicked")
        .expect("client run failed");

    info!(%sid, "=== Test passed ===");
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_offerer_dtls_active_ice_lite() {
    run_connect_and_verify(
        "offerer_active_lite",
        SessionConfig {
            client_sdp_role: SdpRole::Offerer,
            server_ice_mode: IceMode::Lite,
            client_dtls_role: DtlsRole::Active,
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_offerer_dtls_active_ice_full() {
    run_connect_and_verify(
        "offerer_active_full",
        SessionConfig {
            client_sdp_role: SdpRole::Offerer,
            server_ice_mode: IceMode::Full,
            client_dtls_role: DtlsRole::Active,
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_offerer_dtls_passive_ice_lite() {
    run_connect_and_verify(
        "offerer_passive_lite",
        SessionConfig {
            client_sdp_role: SdpRole::Offerer,
            server_ice_mode: IceMode::Lite,
            client_dtls_role: DtlsRole::Passive,
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_offerer_dtls_passive_ice_full() {
    run_connect_and_verify(
        "offerer_passive_full",
        SessionConfig {
            client_sdp_role: SdpRole::Offerer,
            server_ice_mode: IceMode::Full,
            client_dtls_role: DtlsRole::Passive,
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_answerer_dtls_active_ice_lite() {
    run_connect_and_verify(
        "answerer_active_lite",
        SessionConfig {
            client_sdp_role: SdpRole::Answerer,
            server_ice_mode: IceMode::Lite,
            client_dtls_role: DtlsRole::Active,
        },
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn browser_answerer_dtls_active_ice_full() {
    run_connect_and_verify(
        "answerer_active_full",
        SessionConfig {
            client_sdp_role: SdpRole::Answerer,
            server_ice_mode: IceMode::Full,
            client_dtls_role: DtlsRole::Active,
        },
    )
    .await;
}
