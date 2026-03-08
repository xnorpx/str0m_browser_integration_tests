use std::net::IpAddr;

use clap::Parser;
use mimalloc::MiMalloc;
use str0m_browser_integration_tests::peer::DataChannelAction;
use str0m_browser_integration_tests::protocol::*;
use str0m_browser_integration_tests::{Peer, client};
use tokio::sync::oneshot;
use tracing::info;

#[global_allocator]
static GLOBAL: MiMalloc = MiMalloc;

/// str0m WebRTC client – connects to a signaling server and runs a data channel echo test.
#[derive(Parser, Debug)]
#[command(version, about)]
struct Cli {
    /// WebSocket URL of the signaling server (e.g. ws://127.0.0.1:9090)
    #[arg(long)]
    ws_url: String,

    /// Session ID
    #[arg(long, default_value = "str0m-client")]
    session_id: String,

    /// SDP role for this client: offerer or answerer
    #[arg(long, default_value = "offerer")]
    sdp_role: String,

    /// Server ICE mode: full or lite
    #[arg(long, default_value = "full")]
    ice_mode: String,

    /// Client DTLS role: active, passive, or auto
    #[arg(long, default_value = "active")]
    dtls_role: String,

    /// Advertised IP address. If not given, auto-detects.
    #[arg(long)]
    adv_addr: Option<IpAddr>,

    /// Timeout in seconds for the entire test
    #[arg(long, default_value_t = 30)]
    timeout: u64,

    /// Message to send through the data channel for echo testing
    #[arg(long, default_value = "hello from str0m client!")]
    message: String,
}

fn parse_sdp_role(s: &str) -> SdpRole {
    match s {
        "offerer" => SdpRole::Offerer,
        "answerer" => SdpRole::Answerer,
        other => panic!("Unknown SDP role: {other}"),
    }
}

fn parse_ice_mode(s: &str) -> IceMode {
    match s {
        "full" => IceMode::Full,
        "lite" => IceMode::Lite,
        other => panic!("Unknown ICE mode: {other}"),
    }
}

fn parse_dtls_role(s: &str) -> DtlsRole {
    match s {
        "active" => DtlsRole::Active,
        "passive" => DtlsRole::Passive,
        "auto" => DtlsRole::Auto,
        other => panic!("Unknown DTLS role: {other}"),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt::init();
    str0m_browser_integration_tests::init_crypto();

    let cli = Cli::parse();

    let adv_addr = match cli.adv_addr {
        Some(addr) => addr,
        None => str0m_browser_integration_tests::detect_public_ip()?,
    };

    let config = SessionConfig {
        client_sdp_role: parse_sdp_role(&cli.sdp_role),
        server_ice_mode: parse_ice_mode(&cli.ice_mode),
        client_dtls_role: parse_dtls_role(&cli.dtls_role),
    };

    info!(ws_url = %cli.ws_url, session_id = %cli.session_id, ?config, "Starting str0m client");

    let timeout = tokio::time::timeout(
        std::time::Duration::from_secs(cli.timeout),
        run_client(&cli.ws_url, &cli.session_id, config, adv_addr, &cli.message),
    );

    match timeout.await {
        Ok(Ok(())) => {
            println!("CLIENT OK");
            Ok(())
        }
        Ok(Err(e)) => {
            eprintln!("CLIENT FAIL: {e}");
            std::process::exit(1);
        }
        Err(_) => {
            eprintln!("CLIENT FAIL: timeout after {}s", cli.timeout);
            std::process::exit(1);
        }
    }
}

async fn run_client(
    ws_url: &str,
    session_id: &str,
    config: SessionConfig,
    adv_addr: IpAddr,
    message: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let (ws_stream, _) = tokio_tungstenite::connect_async(ws_url).await?;
    let mut ws = ws_stream;

    // Create session
    let msg = client::create_session(&mut ws, session_id, config.clone()).await?;
    match msg {
        ServerMessage::Created { .. } => {}
        ServerMessage::Error { message, .. } => {
            return Err(format!("Server error: {message}").into());
        }
        other => return Err(format!("Unexpected response: {other:?}").into()),
    }

    let cert = str0m_browser_integration_tests::shared_dtls_cert();
    let mut peer = Peer::with_cert(false, adv_addr, 0, Some(cert))?;

    match config.client_sdp_role {
        SdpRole::Offerer => {
            let offer_sdp = peer.create_offer("test-data")?;

            client::send_msg(
                &mut ws,
                &ClientMessage::Sdp {
                    session_id: session_id.into(),
                    sdp: offer_sdp,
                },
            )
            .await?;

            let msg = client::recv_msg(&mut ws).await?;
            match msg {
                ServerMessage::Sdp { sdp, .. } => {
                    peer.accept_answer(&sdp)?;
                }
                ServerMessage::Error { message, .. } => {
                    return Err(format!("Server error: {message}").into());
                }
                other => return Err(format!("Expected SDP, got: {other:?}").into()),
            }
        }
        SdpRole::Answerer => {
            let msg = client::recv_msg(&mut ws).await?;
            match msg {
                ServerMessage::Sdp { sdp, .. } => {
                    let answer_sdp = peer.accept_offer(&sdp)?;
                    client::send_msg(
                        &mut ws,
                        &ClientMessage::Sdp {
                            session_id: session_id.into(),
                            sdp: answer_sdp,
                        },
                    )
                    .await?;
                }
                ServerMessage::Error { message, .. } => {
                    return Err(format!("Server error: {message}").into());
                }
                other => return Err(format!("Expected SDP, got: {other:?}").into()),
            }
        }
    }

    // Signal ready
    client::send_msg(
        &mut ws,
        &ClientMessage::Ready {
            session_id: session_id.into(),
        },
    )
    .await?;

    let msg = client::recv_msg(&mut ws).await?;
    match msg {
        ServerMessage::Ready { .. } => {}
        ServerMessage::Error { message, .. } => {
            return Err(format!("Server error: {message}").into());
        }
        other => return Err(format!("Expected Ready, got: {other:?}").into()),
    }

    // Run the peer
    let (connected_tx, connected_rx) = oneshot::channel();
    let (chan_open_tx, chan_open_rx) = oneshot::channel();
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (echo_result_tx, echo_result_rx) = oneshot::channel();

    let ping_message = message.as_bytes().to_vec();
    let sid = session_id.to_string();

    let peer_handle = tokio::spawn(async move {
        peer.run(
            &sid,
            "client",
            connected_tx,
            chan_open_tx,
            DataChannelAction::SendAndExpectEcho {
                message: ping_message,
                result_tx: echo_result_tx,
            },
            shutdown_rx,
        )
        .await
    });

    connected_rx.await.map_err(|_| "Peer never connected")?;
    info!("Connected!");

    chan_open_rx
        .await
        .map_err(|_| "Data channel never opened")?;
    info!("Data channel open!");

    let echo_rtt = echo_result_rx
        .await
        .map_err(|_| "Echo result channel dropped")?;
    let rtt = echo_rtt.ok_or("Data channel echo did not match")?;

    info!(?rtt, "Echo verified");

    // Destroy session
    client::send_msg(
        &mut ws,
        &ClientMessage::Destroy {
            session_id: session_id.into(),
        },
    )
    .await?;

    let msg = client::recv_msg(&mut ws).await?;
    match msg {
        ServerMessage::Destroyed { .. } => {}
        other => return Err(format!("Expected Destroyed, got: {other:?}").into()),
    }

    let _ = shutdown_tx.send(());
    peer_handle.await??;

    info!(?rtt, "Test passed");
    Ok(())
}
