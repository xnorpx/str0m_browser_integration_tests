use crate::{
    Session, Sessions, UdpPortAllocator,
    peer::{DataChannelAction, Peer},
    protocol::*,
};
use futures_util::{SinkExt, StreamExt};
use std::collections::HashMap;
use std::{
    net::IpAddr,
    sync::{Arc, Mutex},
};
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};

type RunningSessions = Arc<Mutex<HashMap<String, oneshot::Sender<()>>>>;

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
) -> Result<(), Box<dyn std::error::Error>> {
    let bind_addr = format!("0.0.0.0:{ws_port}");
    let listener = TcpListener::bind(&bind_addr).await?;
    let running: RunningSessions = Arc::new(Mutex::new(HashMap::new()));

    println!("SERVER READY ws://{adv_addr}:{ws_port}");
    info!(%adv_addr, "WebSocket server listening on {bind_addr}");

    loop {
        let (stream, peer) = listener.accept().await?;
        info!(%peer, "New TCP connection");

        let sessions = sessions.clone();
        let running = running.clone();
        let udp_ports = udp_ports.clone();
        tokio::spawn(async move {
            let ws_stream = match tokio_tungstenite::accept_async(stream).await {
                Ok(ws) => ws,
                Err(e) => {
                    warn!(%peer, "WebSocket handshake failed: {e}");
                    return;
                }
            };
            info!(%peer, "WebSocket connection established");

            let (mut sink, mut stream) = ws_stream.split();

            while let Some(msg) = stream.next().await {
                match msg {
                    Ok(Message::Text(text)) => {
                        let (responses, action) =
                            handle_client_message(&sessions, &text, adv_addr, &udp_ports);

                        match action {
                            ServerAction::SpawnPeer {
                                session_id,
                                mut session,
                            } => {
                                let (shutdown_tx, shutdown_rx) = oneshot::channel();
                                running
                                    .lock()
                                    .unwrap()
                                    .insert(session_id.clone(), shutdown_tx);
                                let sid = session_id;
                                tokio::spawn(async move {
                                    let (connected_tx, _) = oneshot::channel();
                                    let (open_tx, _) = oneshot::channel();
                                    if let Err(e) = session
                                        .peer
                                        .run(
                                            &sid,
                                            "server",
                                            connected_tx,
                                            open_tx,
                                            DataChannelAction::Echo {
                                                send_ready_beacon: true,
                                            },
                                            shutdown_rx,
                                        )
                                        .await
                                    {
                                        warn!(session_id = %sid, "Peer event loop error: {e}");
                                    }
                                });
                            }
                            ServerAction::StopPeer { session_id } => {
                                let value = running.lock().unwrap().remove(&session_id);
                                if let Some(tx) = value {
                                    let _ = tx.send(());
                                }
                            }
                            ServerAction::None => {}
                        }

                        for response in responses {
                            let json =
                                serde_json::to_string(&response).expect("failed to serialize");
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
        });
    }
}

fn handle_client_message(
    sessions: &Sessions,
    text: &str,
    adv_addr: IpAddr,
    udp_ports: &UdpPortAllocator,
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

            let ice_lite = config.server_ice_mode == IceMode::Lite;
            let udp_port = udp_ports.next_port();
            let cert = crate::shared_dtls_cert();
            let mut peer = match Peer::with_cert(ice_lite, adv_addr, udp_port, Some(cert)) {
                Ok(p) => p,
                Err(e) => {
                    return (
                        vec![ServerMessage::Error {
                            session_id: Some(session_id),
                            message: format!("Failed to create peer: {e}"),
                        }],
                        ServerAction::None,
                    );
                }
            };

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
                        return (
                            vec![ServerMessage::Error {
                                session_id: Some(session_id),
                                message: format!("Failed to create offer: {e}"),
                            }],
                            ServerAction::None,
                        );
                    }
                }
            }

            sessions
                .lock()
                .unwrap()
                .insert(session_id, Session { config, peer });

            (responses, ServerAction::None)
        }

        ClientMessage::Destroy { session_id } => {
            info!(%session_id, "Destroying session");
            sessions.lock().unwrap().remove(&session_id);
            (
                vec![ServerMessage::Destroyed {
                    session_id: session_id.clone(),
                }],
                ServerAction::StopPeer { session_id },
            )
        }

        ClientMessage::Sdp { session_id, sdp } => {
            info!(%session_id, "Received SDP from client ({} bytes)", sdp.len());
            let mut sessions = sessions.lock().unwrap();
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
            let session = sessions.lock().unwrap().remove(&session_id);
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
