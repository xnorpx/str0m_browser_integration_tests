// Package protocol mirrors the Rust protocol.rs signaling types.
package protocol

// SdpRole indicates whether the client is the SDP offerer or answerer.
type SdpRole string

const (
	SdpRoleOfferer  SdpRole = "offerer"
	SdpRoleAnswerer SdpRole = "answerer"
)

// IceMode indicates ICE full or lite mode for the server.
type IceMode string

const (
	IceModeFull IceMode = "full"
	IceModeLite IceMode = "lite"
)

// DtlsRole indicates the DTLS role for the client.
type DtlsRole string

const (
	DtlsRoleActive  DtlsRole = "active"
	DtlsRolePassive DtlsRole = "passive"
	DtlsRoleAuto    DtlsRole = "auto"
)

// SessionConfig mirrors the Rust SessionConfig struct.
type SessionConfig struct {
	ClientSdpRole  SdpRole  `json:"client_sdp_role"`
	ServerIceMode  IceMode  `json:"server_ice_mode"`
	ClientDtlsRole DtlsRole `json:"client_dtls_role"`
}

// ClientMessage is a tagged union matching the Rust ClientMessage enum.
// The "type" field determines the variant.
type ClientMessage struct {
	Type      string         `json:"type"`
	SessionID string         `json:"session_id"`
	Config    *SessionConfig `json:"config,omitempty"`
	Sdp       string         `json:"sdp,omitempty"`
}

// ServerMessage is a tagged union matching the Rust ServerMessage enum.
type ServerMessage struct {
	Type      string  `json:"type"`
	SessionID *string `json:"session_id,omitempty"`
	Sdp       string  `json:"sdp,omitempty"`
	Message   string  `json:"message,omitempty"`
}
