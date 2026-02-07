/**
 * WebSocket signaling client - mirrors the Rust `client.rs` helpers.
 *
 * Provides a thin async wrapper around the browser WebSocket API
 * for exchanging JSON signaling messages with the str0m test server.
 */

import {ClientMessage, ServerMessage} from './protocol';

/**
 * Open a WebSocket connection to the signaling server.
 * Resolves once the connection is open.
 */
export function connectWs(url: string): Promise<WebSocket> {
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(url);
    ws.onopen = () => resolve(ws);
    ws.onerror = (e) => reject(new Error(`WebSocket connection failed: ${e}`));
  });
}

/**
 * Send a signaling message as JSON over the WebSocket.
 */
export function sendMsg(ws: WebSocket, msg: ClientMessage): void {
  const json = JSON.stringify(msg);
  console.log(`[signaling] -> ${json}`);
  ws.send(json);
}

/**
 * Receive and parse the next server message from the WebSocket.
 * Rejects if the socket closes before a message arrives.
 */
export function recvMsg(ws: WebSocket): Promise<ServerMessage> {
  return new Promise((resolve, reject) => {
    const onMessage = (event: MessageEvent) => {
      cleanup();
      const text = typeof event.data === 'string' ? event.data : '';
      console.log(`[signaling] <- ${text}`);
      try {
        resolve(JSON.parse(text) as ServerMessage);
      } catch (e) {
        reject(new Error(`Failed to parse server message: ${text}`));
      }
    };

    const onClose = () => {
      cleanup();
      reject(new Error('WebSocket closed while waiting for message'));
    };

    const onError = (e: Event) => {
      cleanup();
      reject(new Error(`WebSocket error while waiting for message: ${e}`));
    };

    function cleanup() {
      ws.removeEventListener('message', onMessage);
      ws.removeEventListener('close', onClose);
      ws.removeEventListener('error', onError);
    }

    ws.addEventListener('message', onMessage);
    ws.addEventListener('close', onClose);
    ws.addEventListener('error', onError);
  });
}

/**
 * Wait for ICE gathering to complete so all candidates are embedded in the SDP.
 * This is the browser equivalent of str0m's "vanilla ICE" approach where
 * candidates are bundled into the SDP offer/answer.
 */
export function waitForIceGathering(pc: RTCPeerConnection): Promise<void> {
  return new Promise((resolve) => {
    if (pc.iceGatheringState === 'complete') {
      resolve();
      return;
    }
    pc.addEventListener('icegatheringstatechange', () => {
      if (pc.iceGatheringState === 'complete') {
        resolve();
      }
    });
  });
}

/**
 * Close a WebSocket connection gracefully.
 */
export function closeWs(ws: WebSocket): Promise<void> {
  return new Promise((resolve) => {
    if (ws.readyState === WebSocket.CLOSED || ws.readyState === WebSocket.CLOSING) {
      resolve();
      return;
    }
    ws.onclose = () => resolve();
    ws.close();
  });
}
