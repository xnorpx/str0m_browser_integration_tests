/**
 * Signaling protocol types - mirrors the Rust `protocol.rs` definitions.
 *
 * All messages are JSON-serialized and exchanged over WebSocket.
 * The `type` field is snake_case and matches the Rust serde(tag = "type") convention.
 */

export type SdpRole = 'offerer' | 'answerer';
export type IceMode = 'full' | 'lite';
export type DtlsRole = 'active' | 'passive' | 'auto';
export type ServerDtlsVersion = 'dtls12' | 'auto' | 'dtls13';
export type NetemPreset = 'wifi' | 'wifi_lossy' | 'wifi_congested' | 'cellular' | 'satellite' | 'congested';

/** One direction of str0m-netem emulation on the server. */
export interface NetemLink {
  preset?: NetemPreset;
  loss_percent?: number;
  loss_correlation?: number;
  burst_interval?: number;
  burst_length?: number;
  latency_ms?: number;
  jitter_ms?: number;
  duplicate_percent?: number;
  reorder_gap?: number;
  rate_kbps?: number;
  buffer_bytes?: number;
  seed?: number;
}

/** Egress = packets str0m sends, ingress = packets str0m receives. */
export interface NetemSettings {
  egress?: NetemLink;
  ingress?: NetemLink;
}

export interface SessionConfig {
  client_sdp_role: SdpRole;
  server_ice_mode: IceMode;
  client_dtls_role: DtlsRole;
  server_dtls_version?: ServerDtlsVersion;
  /** Whether str0m offers SNAP (a=sctp-init). Defaults to true. */
  server_snap?: boolean;
  server_netem?: NetemSettings;
}

export interface NetemStats {
  packets: number;
  dropped: number;
  duplicated: number;
}

/** The str0m peer's view of a session, sent with `destroyed`. */
export interface SessionReport {
  dtls_version: string | null;
  connected_ms: number | null;
  channel_open_ms: number | null;
  packets_sent: number;
  packets_received: number;
  netem_egress: NetemStats | null;
  netem_ingress: NetemStats | null;
  error: string | null;
}

export interface CreateMessage {
  type: 'create';
  session_id: string;
  config: SessionConfig;
}

export interface DestroyMessage {
  type: 'destroy';
  session_id: string;
}

export interface SdpMessage {
  type: 'sdp';
  session_id: string;
  sdp: string;
}

export interface ReadyMessage {
  type: 'ready';
  session_id: string;
}

export interface InfoMessage {
  type: 'info';
}

export type ClientMessage = CreateMessage | DestroyMessage | SdpMessage | ReadyMessage | InfoMessage;

export interface CreatedMessage {
  type: 'created';
  session_id: string;
}

export interface DestroyedMessage {
  type: 'destroyed';
  session_id: string;
  report?: SessionReport;
}

export interface ServerSdpMessage {
  type: 'sdp';
  session_id: string;
  sdp: string;
}

export interface ServerReadyMessage {
  type: 'ready';
  session_id: string;
}

export interface ServerErrorMessage {
  type: 'error';
  session_id: string | null;
  message: string;
}

export interface ServerInfoMessage {
  type: 'info';
  crypto: string;
  dtls13: boolean;
  default_netem: NetemSettings | null;
}

export type ServerMessage =
  | CreatedMessage
  | DestroyedMessage
  | ServerSdpMessage
  | ServerReadyMessage
  | ServerErrorMessage
  | ServerInfoMessage;
