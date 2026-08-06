/**
 * SNAP feature tests for str0m browser integration.
 *
 * These tests exercise the SNAP (SCTP Negotiation Acceleration Protocol)
 * WebRTC connection acceleration feature (draft-hancke-tsvwg-snap).
 *
 * SNAP removes the SCTP 4-way handshake entirely by exchanging SCTP init
 * parameters declaratively in SDP, saving 2 RTTs.
 *
 * The server always runs with SNAP enabled. The browser enables SNAP via
 * the Chromium field trial: WebRTC-Sctp-Snap
 *
 * Run via:
 *   npm run test:snap:chrome   # SNAP on Chrome
 */

import {SessionConfig, ServerMessage} from './protocol';
import {connectWs, sendMsg, recvMsg, waitForIceGathering, closeWs} from './signaling';

/** Read the server WS port injected by karma-str0m-server plugin. */
function getServerWsPort(): number {
  const karma = (window as any).__karma__;
  if (karma?.config?.serverWsPort) {
    return karma.config.serverWsPort;
  }
  return 9090;
}

function isWarpMode(): boolean {
  return Boolean((window as any).__karma__?.config?.warpMode);
}

/** Detect browser from user-agent. */
function detectBrowser(): string {
  const ua = navigator.userAgent;
  if (/Edg\//i.test(ua)) return 'edge';
  if (/Firefox\//i.test(ua)) return 'firefox';
  if (/Chrome\//i.test(ua)) return 'chrome';
  return 'unknown';
}

/**
 * Build a session ID encoding browser and test case.
 * Format: `{browser}_snap_{role}` e.g. `chrome_snap_offerer`
 */
function allocSessionId(role: string): string {
  const browser = detectBrowser();
  const mode = isWarpMode() ? 'warp_dtls13' : 'snap';
  return `${browser}_${mode}_${role}`;
}

/** Assert a server message matches the expected type. */
function expectMsg<T extends ServerMessage['type']>(
  msg: ServerMessage,
  expectedType: T,
): Extract<ServerMessage, {type: T}> {
  if (msg.type !== expectedType) {
    throw new Error(`Expected ${expectedType}, got ${msg.type}: ${JSON.stringify(msg)}`);
  }
  return msg as Extract<ServerMessage, {type: T}>;
}

/**
 * Run a connect-and-verify flow with SNAP-prefixed session IDs
 * for distinct pcap captures.
 */
async function runSnapTest(role: string, config: SessionConfig): Promise<void> {
  const wsPort = getServerWsPort();
  const wsUrl = `ws://127.0.0.1:${wsPort}`;
  const sid = allocSessionId(role);
  const PING_MESSAGE = 'hello from snap!';
  const ECHO_TIMEOUT_MS = 10000;
  const RTT_THRESHOLD_MS = 2000;

  const effectiveConfig: SessionConfig = isWarpMode()
    ? {...config, server_dtls_version: 'dtls13'}
    : config;

  console.log(`[snap] ${role}: connecting to ${wsUrl}, session=${sid}`);

  const ws = await connectWs(wsUrl);

  try {
    sendMsg(ws, {type: 'create', session_id: sid, config: effectiveConfig});
    const created = await recvMsg(ws);
    expectMsg(created, 'created');

    let pc: RTCPeerConnection;
    let dc: RTCDataChannel;

    if (effectiveConfig.client_sdp_role === 'offerer') {
      pc = new RTCPeerConnection({iceServers: []});
      dc = pc.createDataChannel('test-data', {negotiated: true, id: 0});

      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await waitForIceGathering(pc);

      const completeSdp = pc.localDescription!.sdp;
      expect(completeSdp).withContext('SNAP offer must contain SCTP initialization parameters').toContain('a=sctp-init:');
      console.log(`[snap] Sending offer (${completeSdp.length} bytes)`);

      sendMsg(ws, {type: 'sdp', session_id: sid, sdp: completeSdp});
      const answerMsg = await recvMsg(ws);
      const {sdp: answerSdp} = expectMsg(answerMsg, 'sdp');

      console.log(`[snap] Received answer (${answerSdp.length} bytes)`);
      await pc.setRemoteDescription({type: 'answer', sdp: answerSdp});
    } else {
      pc = new RTCPeerConnection({iceServers: []});
      dc = pc.createDataChannel('test-data', {negotiated: true, id: 0});

      const offerMsg = await recvMsg(ws);
      const {sdp: offerSdp} = expectMsg(offerMsg, 'sdp');

      console.log(`[snap] Received offer (${offerSdp.length} bytes)`);
      await pc.setRemoteDescription({type: 'offer', sdp: offerSdp});

      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      await waitForIceGathering(pc);

      const completeSdp = pc.localDescription!.sdp;
      expect(completeSdp).withContext('SNAP answer must contain SCTP initialization parameters').toContain('a=sctp-init:');
      console.log(`[snap] Sending answer (${completeSdp.length} bytes)`);

      sendMsg(ws, {type: 'sdp', session_id: sid, sdp: completeSdp});
    }

    sendMsg(ws, {type: 'ready', session_id: sid});
    const ready = await recvMsg(ws);
    expectMsg(ready, 'ready');

    if (dc.readyState !== 'open') {
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(
          () => reject(new Error(`Data channel did not open (state: ${dc.readyState})`)),
          ECHO_TIMEOUT_MS,
        );
        dc.onopen = () => {
          clearTimeout(timeout);
          resolve();
        };
        if (dc.readyState === 'open') {
          clearTimeout(timeout);
          resolve();
        }
      });
    }

    console.log(`[snap] Data channel "${dc.label}" is open`);

    const sendTime = performance.now();

    const echoPromise = new Promise<string>((resolve, reject) => {
      const timeout = setTimeout(
        () => reject(new Error('Timed out waiting for echo reply')),
        ECHO_TIMEOUT_MS,
      );
      dc.onmessage = (event) => {
        const data = typeof event.data === 'string'
          ? event.data
          : new TextDecoder().decode(event.data);
        if (data === PING_MESSAGE) {
          clearTimeout(timeout);
          resolve(data);
        } else {
          console.log(`[snap] Ignoring non-echo message: "${data}"`);
        }
      };
    });

    dc.send(PING_MESSAGE);
    console.log(`[snap] Sent: "${PING_MESSAGE}"`);

    const retryTimer = setTimeout(() => {
      if (dc.readyState === 'open') {
        dc.send(PING_MESSAGE);
        console.log(`[snap] Retry sent: "${PING_MESSAGE}"`);
      }
    }, 200);

    const echoReply = await echoPromise;
    clearTimeout(retryTimer);
    const rttMs = performance.now() - sendTime;

    console.log(`[snap] Echo: "${echoReply}" (RTT: ${rttMs.toFixed(2)}ms)`);

    expect(echoReply).toBe(PING_MESSAGE);
    expect(rttMs).toBeLessThan(RTT_THRESHOLD_MS);

    console.log(`[snap] ${role}: PASSED (RTT: ${rttMs.toFixed(2)}ms)`);

    sendMsg(ws, {type: 'destroy', session_id: sid});
    const destroyed = await recvMsg(ws);
    expectMsg(destroyed, 'destroyed');

    pc.close();
  } finally {
    await closeWs(ws);
  }
}

describe('SNAP Feature Tests', () => {
  const TEST_TIMEOUT_MS = 30_000;

  beforeAll(() => {
    jasmine.DEFAULT_TIMEOUT_INTERVAL = TEST_TIMEOUT_MS;
  });

  describe('SNAP (SCTP out-of-band signaling)', () => {
    it('should connect as offerer with SNAP enabled', async () => {
      await runSnapTest('snap_offerer', {
        client_sdp_role: 'offerer',
        server_ice_mode: 'lite',
        client_dtls_role: 'active',
      });
    });

    it('should connect as answerer with SNAP enabled', async () => {
      await runSnapTest('snap_answerer', {
        client_sdp_role: 'answerer',
        server_ice_mode: 'lite',
        client_dtls_role: 'active',
      });
    });
  });
});
