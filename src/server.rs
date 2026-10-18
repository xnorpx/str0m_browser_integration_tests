use crate::{
    Session, Sessions, UdpPortAllocator,
    netem::session_seed,
    peer::{DataChannelAction, Peer},
    protocol::*,
};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::time::Duration;
use std::{
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};
use str0m::config::DtlsVersion;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};

/// How long `destroy` waits for a running peer to stop and hand over its report.
const REPORT_TIMEOUT: Duration = Duration::from_secs(3);

/// Server-wide settings.
#[derive(Debug, Clone, Default)]
pub struct ServerOptions {
    /// Netem for sessions that don't send their own `server_netem`.
    pub default_netem: Option<NetemSettings>,
}

struct RunningPeer {
    shutdown: oneshot::Sender<()>,
    report: oneshot::Receiver<SessionReport>,
}

impl RunningPeer {
    async fn stop(self) -> Option<SessionReport> {
        let _ = self.shutdown.send(());
        tokio::time::timeout(REPORT_TIMEOUT, self.report)
            .await
            .ok()?
            .ok()
    }
}

type RunningSessions = Arc<Mutex<HashMap<String, RunningPeer>>>;

enum ServerAction {
    None,
    SpawnPeer {
        session_id: String,
        session: Box<Session>,
    },
    StopPeer {
        session_id: String,
    },
}

pub async fn run_server(
    ws_port: u16,
    sessions: Sessions,
    adv_addr: IpAddr,
    udp_ports: Arc<UdpPortAllocator>,
    options: ServerOptions,
) -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = format!("0.0.0.0:{ws_port}");
    let listener = TcpListener::bind(&bind_addr).await?;
    let running: RunningSessions = Arc::new(Mutex::new(HashMap::new()));
    let options = Arc::new(options);

    info!(
        crypto = crate::crypto_backend_name(),
        dtls13 = crate::dtls13_supported(),
        default_netem = ?options.default_netem,
        "Server capabilities"
    );
    println!("SERVER READY ws://{adv_addr}:{ws_port}");
    info!(%adv_addr, "WebSocket server listening on {bind_addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        info!(%peer, "New TCP connection");

        tokio::spawn(handle_connection(
            stream,
            peer,
            sessions.clone(),
            running.clone(),
            udp_ports.clone(),
            adv_addr,
            options.clone(),
        ));
    }
}

async fn handle_connection(
    stream: TcpStream,
    peer: SocketAddr,
    sessions: Sessions,
    running: RunningSessions,
    udp_ports: Arc<UdpPortAllocator>,
    adv_addr: IpAddr,
    options: Arc<ServerOptions>,
) {
    let ws_stream = match tokio_tungstenite::accept_async(stream).await {
        Ok(ws) => ws,
        Err(e) => {
            warn!(%peer, "WebSocket handshake failed: {e}");
            return;
        }
    };
    info!(%peer, "WebSocket connection established");

    let (mut sink, mut stream) = ws_stream.split();
    // Sessions created on this connection and not destroyed yet.
    let mut owned: Vec<String> = Vec::new();

    while let Some(msg) = stream.next().await {
        match msg {
            Ok(Message::Text(text)) => {
                let (mut responses, action) =
                    handle_client_message(&sessions, &text, adv_addr, &udp_ports, &options);

                for response in &responses {
                    if let ServerMessage::Created { session_id } = response {
                        owned.push(session_id.clone());
                    }
                }

                match action {
                    ServerAction::SpawnPeer {
                        session_id,
                        session,
                    } => spawn_peer(&running, session_id, session),
                    ServerAction::StopPeer { session_id } => {
                        owned.retain(|id| *id != session_id);
                        let running_peer = running
                            .lock()
                            .expect("running sessions lock poisoned")
                            .remove(&session_id);
                        if let Some(running_peer) = running_peer {
                            let report = running_peer.stop().await;
                            for response in &mut responses {
                                if let ServerMessage::Destroyed {
                                    session_id: id,
                                    report: slot,
                                } = response
                                    && *id == session_id
                                {
                                    slot.clone_from(&report);
                                }
                            }
                        }
                    }
                    ServerAction::None => {}
                }

                for response in responses {
                    let json = serde_json::to_string(&response).expect("failed to serialize");
                    if let Err(e) = sink.send(Message::Text(json.into())).await {
                        warn!(%peer, "Send failed: {e}");
                        break;
                    }
                }
            }
            Ok(Message::Close(_)) => {
                info!(%peer, "Connection closed");
                break;
            }
            Ok(_) => {} // ignore binary/ping/pong
            Err(e) => {
                warn!(%peer, "Error: {e}");
                break;
            }
        }
    }

    // Don't leave peers (and their netem timers) running for clients that went away.
    for session_id in owned {
        sessions
            .lock()
            .expect("sessions lock poisoned")
            .remove(&session_id);
        let running_peer = running
            .lock()
            .expect("running sessions lock poisoned")
            .remove(&session_id);
        if let Some(running_peer) = running_peer {
            info!(%peer, %session_id, "Stopping peer left behind by closed connection");
            running_peer.stop().await;
        }
    }
}

fn spawn_peer(running: &RunningSessions, session_id: String, mut session: Box<Session>) {
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let (report_tx, report_rx) = oneshot::channel();
    running
        .lock()
        .expect("running sessions lock poisoned")
        .insert(
            session_id.clone(),
            RunningPeer {
                shutdown: shutdown_tx,
                report: report_rx,
            },
        );
    tokio::spawn(async move {
        let (connected_tx, _) = oneshot::channel();
        let (open_tx, _) = oneshot::channel();
        let report = session
            .peer
            .run(
                &session_id,
                "server",
                connected_tx,
                open_tx,
                DataChannelAction::Echo {
                    send_ready_beacon: true,
                },
                shutdown_rx,
            )
            .await;
        let _ = report_tx.send(report);
    });
}

/// Map the requested version onto what the crypto backend can do. `RtcConfig::build`
/// panics on versions the backend rejects, so this must never hand out an unsupported one.
fn resolve_dtls_version(requested: ServerDtlsVersion) -> Result<DtlsVersion, String> {
    let dtls13 = crate::dtls13_supported();
    match requested {
        ServerDtlsVersion::Dtls12 => Ok(DtlsVersion::Dtls12),
        ServerDtlsVersion::Auto if dtls13 => Ok(DtlsVersion::Auto),
        // Auto-negotiation on a DTLS 1.2 only backend can only ever end up at 1.2.
        ServerDtlsVersion::Auto => Ok(DtlsVersion::Dtls12),
        ServerDtlsVersion::Dtls13 if dtls13 => Ok(DtlsVersion::Dtls13),
        ServerDtlsVersion::Dtls13 => {
            Err("Backend does not support DTLS 1.3. Skipping test.".to_string())
        }
    }
}

fn error_response(session_id: String, message: String) -> (Vec<ServerMessage>, ServerAction) {
    (
        vec![ServerMessage::Error {
            session_id: Some(session_id),
            message,
        }],
        ServerAction::None,
    )
}

fn handle_client_message(
    sessions: &Sessions,
    text: &str,
    adv_addr: IpAddr,
    udp_ports: &UdpPortAllocator,
    options: &ServerOptions,
) -> (Vec<ServerMessage>, ServerAction) {
    let msg: ClientMessage = match serde_json::from_str(text) {
        Ok(m) => m,
        Err(e) => {
            warn!("Failed to parse client message: {e}");
            return (
                vec![ServerMessage::Error {
                    session_id: None,
                    message: format!("Invalid message: {e}"),
                }],
                ServerAction::None,
            );
        }
    };

    match msg {
        ClientMessage::Create { session_id, config } => {
            info!(%session_id, ?config, "Creating session");

            let dtls_version = match resolve_dtls_version(config.server_dtls_version) {
                Ok(v) => v,
                Err(message) => return error_response(session_id, message),
            };
            let netem = config
                .server_netem
                .clone()
                .or_else(|| options.default_netem.clone());
            if let Some(Err(e)) = netem.as_ref().map(NetemSettings::validate) {
                return error_response(session_id, format!("Invalid server_netem: {e}"));
            }

            let ice_lite = config.server_ice_mode == IceMode::Lite;
            let snap_enabled = config.server_snap.unwrap_or(true);
            let udp_port = udp_ports.next_port();
            let cert = crate::shared_dtls_cert();

            let mut peer = match Peer::with_cert(
                ice_lite,
                adv_addr,
                udp_port,
                Some(cert),
                snap_enabled,
                Some(dtls_version),
            ) {
                Ok(p) => p,
                Err(e) => return error_response(session_id, format!("Failed to create peer: {e}")),
            };
            if let Some(netem) = netem {
                peer.set_netem(netem, session_seed(&session_id));
            }

            let mut responses = vec![ServerMessage::Created {
                session_id: session_id.clone(),
            }];

            if config.client_sdp_role == SdpRole::Answerer {
                match peer.create_offer("test-data") {
                    Ok(sdp) => {
                        responses.push(ServerMessage::Sdp {
                            session_id: session_id.clone(),
                            sdp,
                        });
                    }
                    Err(e) => {
                        return error_response(session_id, format!("Failed to create offer: {e}"));
                    }
                }
            }

            sessions.lock().expect("sessions lock poisoned").insert(
                session_id,
                Session {
                    config: *config,
                    peer,
                },
            );

            (responses, ServerAction::None)
        }

        ClientMessage::Destroy { session_id } => {
            info!(%session_id, "Destroying session");
            sessions
                .lock()
                .expect("sessions lock poisoned")
                .remove(&session_id);
            (
                vec![ServerMessage::Destroyed {
                    session_id: session_id.clone(),
                    report: None,
                }],
                ServerAction::StopPeer { session_id },
            )
        }

        ClientMessage::Info => (
            vec![ServerMessage::Info {
                crypto: crate::crypto_backend_name().to_string(),
                dtls13: crate::dtls13_supported(),
                default_netem: options.default_netem.clone(),
            }],
            ServerAction::None,
        ),

        ClientMessage::Sdp { session_id, sdp } => {
            info!(%session_id, "Received SDP from client ({} bytes)", sdp.len());
            let mut sessions = sessions.lock().expect("sessions lock poisoned");
            let Some(session) = sessions.get_mut(&session_id) else {
                return (
                    vec![ServerMessage::Error {
                        session_id: Some(session_id),
                        message: "Session not found".into(),
                    }],
                    ServerAction::None,
                );
            };

            if session.config.client_sdp_role == SdpRole::Offerer {
                if session.config.client_dtls_role == DtlsRole::Passive
                    && let Err(e) = session.peer.force_dtls_active()
                {
                    return (
                        vec![ServerMessage::Error {
                            session_id: Some(session_id),
                            message: format!("Failed to force DTLS active: {e}"),
                        }],
                        ServerAction::None,
                    );
                }

                match session.peer.accept_offer(&sdp) {
                    Ok(answer_sdp) => (
                        vec![ServerMessage::Sdp {
                            session_id,
                            sdp: answer_sdp,
                        }],
                        ServerAction::None,
                    ),
                    Err(e) => (
                        vec![ServerMessage::Error {
                            session_id: Some(session_id),
                            message: format!("Failed to accept offer: {e}"),
                        }],
                        ServerAction::None,
                    ),
                }
            } else {
                match session.peer.accept_answer(&sdp) {
                    Ok(()) => (vec![], ServerAction::None),
                    Err(e) => (
                        vec![ServerMessage::Error {
                            session_id: Some(session_id),
                            message: format!("Failed to accept answer: {e}"),
                        }],
                        ServerAction::None,
                    ),
                }
            }
        }

        ClientMessage::Ready { session_id } => {
            info!(%session_id, "Client signaling complete, spawning peer event loop");
            let session = sessions
                .lock()
                .expect("sessions lock poisoned")
                .remove(&session_id);
            match session {
                Some(s) => (
                    vec![ServerMessage::Ready {
                        session_id: session_id.clone(),
                    }],
                    ServerAction::SpawnPeer {
                        session_id,
                        session: Box::new(s),
                    },
                ),
                None => (
                    vec![ServerMessage::Error {
                        session_id: Some(session_id),
                        message: "Session not found (already started or destroyed)".into(),
                    }],
                    ServerAction::None,
                ),
            }
        }
    }
}
