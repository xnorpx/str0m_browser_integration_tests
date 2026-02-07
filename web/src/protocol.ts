/**
 * Signaling protocol types - mirrors the Rust `protocol.rs` definitions.
 *
 * All messages are JSON-serialized and exchanged over WebSocket.
 * The `type` field is snake_case and matches the Rust serde(tag = "type") convention.
 */

export type SdpRole = 'offerer' | 'answerer';
export type IceMode = 'full' | 'lite';
export type DtlsRole = 'active' | 'passive' | 'auto';

export interface SessionConfig {
  client_sdp_role: SdpRole;
  server_ice_mode: IceMode;
  client_dtls_role: DtlsRole;
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

export type ClientMessage = CreateMessage | DestroyMessage | SdpMessage | ReadyMessage;

export interface CreatedMessage {
  type: 'created';
  session_id: string;
}

export interface DestroyedMessage {
  type: 'destroyed';
  session_id: string;
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

export type ServerMessage =
  | CreatedMessage
  | DestroyedMessage
  | ServerSdpMessage
  | ServerReadyMessage
  | ServerErrorMessage;
