use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SdpRole {
    Offerer,
    Answerer,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IceMode {
    Full,
    Lite,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DtlsRole {
    Active,
    Passive,
    Auto,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionConfig {
    pub client_sdp_role: SdpRole,
    pub server_ice_mode: IceMode,
    pub client_dtls_role: DtlsRole,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ClientMessage {
    Create {
        session_id: String,
        config: SessionConfig,
    },
    Destroy {
        session_id: String,
    },
    Sdp {
        session_id: String,
        sdp: String,
    },
    Ready {
        session_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ServerMessage {
    Created {
        session_id: String,
    },
    Destroyed {
        session_id: String,
    },
    Sdp {
        session_id: String,
        sdp: String,
    },
    Ready {
        session_id: String,
    },
    Error {
        session_id: Option<String>,
        message: String,
    },
}
