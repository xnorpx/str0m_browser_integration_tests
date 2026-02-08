//! WebSocket signaling client helpers.

use futures_util::StreamExt;
use tokio_tungstenite::tungstenite::Message;
use tracing::{info, warn};

use crate::protocol::*;

/// Create a session on the server and return the Created response.
pub async fn create_session(
    ws_stream: &mut (
             impl futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
             + futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
             + Unpin
         ),
    session_id: &str,
    config: SessionConfig,
) -> Result<ServerMessage, Box<dyn std::error::Error>> {
    let msg = ClientMessage::Create {
        session_id: session_id.to_string(),
        config,
    };
    send_msg(ws_stream, &msg).await?;
    recv_msg(ws_stream).await
}

/// Destroy a session on the server.
pub async fn destroy_session(
    ws_stream: &mut (
             impl futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error>
             + futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
             + Unpin
         ),
    session_id: &str,
) -> Result<ServerMessage, Box<dyn std::error::Error>> {
    let msg = ClientMessage::Destroy {
        session_id: session_id.to_string(),
    };
    send_msg(ws_stream, &msg).await?;
    recv_msg(ws_stream).await
}

/// Send a signaling message as JSON over the WebSocket.
pub async fn send_msg(
    ws_stream: &mut (
             impl futures_util::Sink<Message, Error = tokio_tungstenite::tungstenite::Error> + Unpin
         ),
    msg: &ClientMessage,
) -> Result<(), Box<dyn std::error::Error>> {
    use futures_util::SinkExt;
    let json = serde_json::to_string(msg)?;
    info!("Sending: {json}");
    ws_stream.send(Message::Text(json.into())).await?;
    Ok(())
}

/// Receive and parse a server message from the WebSocket.
pub async fn recv_msg(
    ws_stream: &mut (
             impl futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
             + Unpin
         ),
) -> Result<ServerMessage, Box<dyn std::error::Error>> {
    while let Some(msg) = ws_stream.next().await {
        match msg? {
            Message::Text(text) => {
                info!("Received: {text}");
                let server_msg: ServerMessage = serde_json::from_str(&text)?;
                return Ok(server_msg);
            }
            Message::Close(_) => {
                return Err("Connection closed unexpectedly".into());
            }
            other => {
                warn!("Ignoring non-text message: {other:?}");
            }
        }
    }
    Err("WebSocket stream ended".into())
}
