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
  video_loopback?: {drop_start: number; drop_duration: number};
  video_frame_mode?: boolean;
}

export interface DdPacketSummary {
  packets: number;
  frames: number;
  single_packet_frames: number;
  multi_packet_frames: number;
  first_only: number;
  middle: number;
  last_only: number;
  first_and_last: number;
  structures: number;
  semantic_roundtrips: number;
  dd_bytes: number;
}

export interface FrameVideoReport {
  rust_frames_encoded: number;
  rust_frames_sent: number;
  chrome_frames_received: number;
  rust_frames_decoded: number;
  rust_unique_decoded_images: number;
  decoded_width: number;
  decoded_height: number;
  frame_dd_roundtrips: number;
  chrome_to_rust: DdPacketSummary;
  rust_to_chrome: DdPacketSummary;
}

export interface VideoLoopbackReport {
  packets_received: number;
  descriptors_parsed: number;
  structures_received: number;
  frames_received: number;
  frames_forwarded: number;
  frames_dropped: number;
  packets_dropped: number;
  enhancement_frames_forwarded_after_drop: number;
  max_temporal_id: number;
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
  video_loopback: VideoLoopbackReport | null;
  video_frame_mode: FrameVideoReport | null;
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
