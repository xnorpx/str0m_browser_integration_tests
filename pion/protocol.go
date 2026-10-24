package main

// Signaling messages, mirroring src/protocol.rs. Zero values are omitted, which
// matches the server's defaults for every optional field.

// SessionConfig is the "config" of a "create" message.
type SessionConfig struct {
	ClientSdpRole     string         `json:"client_sdp_role"`
	ServerIceMode     string         `json:"server_ice_mode"`
	ClientDtlsRole    string         `json:"client_dtls_role"`
	ServerDtlsVersion string         `json:"server_dtls_version"`
	ServerSnap        *bool          `json:"server_snap,omitempty"`
	ServerNetem       *NetemSettings `json:"server_netem,omitempty"`
	VideoFrameMode    bool           `json:"video_frame_mode,omitempty"`
}

// NetemLink configures one direction of str0m-netem on the server.
type NetemLink struct {
	Preset           string  `json:"preset,omitempty"`
	LossPercent      float64 `json:"loss_percent,omitempty"`
	LossCorrelation  float64 `json:"loss_correlation,omitempty"`
	BurstInterval    float64 `json:"burst_interval,omitempty"`
	BurstLength      float64 `json:"burst_length,omitempty"`
	LatencyMs        uint64  `json:"latency_ms,omitempty"`
	JitterMs         uint64  `json:"jitter_ms,omitempty"`
	DuplicatePercent float64 `json:"duplicate_percent,omitempty"`
	ReorderGap       uint32  `json:"reorder_gap,omitempty"`
	RateKbps         uint64  `json:"rate_kbps,omitempty"`
	BufferBytes      uint64  `json:"buffer_bytes,omitempty"`
	Seed             uint64  `json:"seed,omitempty"`
}

// NetemSettings is str0m-side network emulation. Egress is str0m -> Pion.
type NetemSettings struct {
	Egress  *NetemLink `json:"egress,omitempty"`
	Ingress *NetemLink `json:"ingress,omitempty"`
}

// NetemStats counts what one netem direction did to a session's packets.
type NetemStats struct {
	Packets    uint64 `json:"packets"`
	Dropped    uint64 `json:"dropped"`
	Duplicated uint64 `json:"duplicated"`
}

// SessionReport is the str0m side's view of a session, sent with "destroyed".
type SessionReport struct {
	DtlsVersion     *string           `json:"dtls_version"`
	ConnectedMs     *float64          `json:"connected_ms"`
	ChannelOpenMs   *float64          `json:"channel_open_ms"`
	PacketsSent     uint64            `json:"packets_sent"`
	PacketsReceived uint64            `json:"packets_received"`
	NetemEgress     *NetemStats       `json:"netem_egress"`
	NetemIngress    *NetemStats       `json:"netem_ingress"`
	Error           *string           `json:"error"`
	VideoFrameMode  *FrameVideoReport `json:"video_frame_mode,omitempty"`
}

type DdPacketSummary struct {
	Packets    uint64 `json:"packets"`
	Frames     uint64 `json:"frames"`
	Structures uint64 `json:"structures"`
}

type FrameVideoReport struct {
	RustFramesSent uint64          `json:"rust_frames_sent"`
	RustToChrome   DdPacketSummary `json:"rust_to_chrome"`
}

// ClientMessage is any message sent to the server.
type ClientMessage struct {
	Type      string         `json:"type"`
	SessionID string         `json:"session_id,omitempty"`
	Config    *SessionConfig `json:"config,omitempty"`
	Sdp       string         `json:"sdp,omitempty"`
}

// ServerMessage is any message received from the server; fields depend on Type.
type ServerMessage struct {
	Type         string         `json:"type"`
	SessionID    *string        `json:"session_id"`
	Sdp          string         `json:"sdp"`
	Message      string         `json:"message"`
	Report       *SessionReport `json:"report"`
	Crypto       string         `json:"crypto"`
	Dtls13       bool           `json:"dtls13"`
	DefaultNetem *NetemSettings `json:"default_netem"`
}

// ServerInfo describes the str0m server under test.
type ServerInfo struct {
	Crypto       string         `json:"crypto"`
	Dtls13       bool           `json:"dtls13"`
	DefaultNetem *NetemSettings `json:"default_netem,omitempty"`
}
