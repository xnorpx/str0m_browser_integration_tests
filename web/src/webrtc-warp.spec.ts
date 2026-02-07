/**
 * WARP / SNAP / SPED feature tests for str0m browser integration.
 *
 * These tests exercise experimental WebRTC connection acceleration features:
 *
 *   SNAP  - SCTP Negotiation Acceleration Protocol (draft-hancke-tsvwg-snap)
 *           Sends SCTP INIT/INIT-ACK out-of-band in ICE candidates, allowing
 *           the data channel to open ~1 RTT earlier.
 *           Chromium field trial: WebRTC-Sctp-Snap
 *
 *   SPED  - STUN Protocol for Embedding DTLS (draft-okonkwo-ice-dtlsice)
 *           Embeds the DTLS ClientHello inside the STUN connectivity check,
 *           reducing STUN + DTLS from 2 RTTs to 1 RTT.
 *           Chromium field trial: WebRTC-IceHandshakeDtls
 *
 *   WARP  - WebRTC Accelerated Rendezvous Protocol (SNAP + SPED combined)
 *           Reduces overall connection setup from 4–6 RTTs to 1–2 RTTs.
 *
 * Note: DTLS 1.3 (RFC 9147) is enabled by default in Chrome/Edge since
 * Oct 2025 (issues.webrtc.org/383141571), so the base tests already
 * exercise it - no separate test needed.
 *
 * str0m does NOT implement SNAP or SPED yet, but browsers fall back
 * gracefully to standard handshakes when the server doesn't support
 * them. These tests verify the fallback works correctly.
 *
 * Run via:
 *   npm run test:snap:chrome   # SNAP on Chrome (Chrome-only)
 *   npm run test:sped:edge     # SPED on Edge
 *   npm run test:sped:chrome   # SPED on Chrome
 *   npm run test:warp:chrome   # WARP on Chrome (Chrome-only, SNAP+SPED)
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

/** Read the WARP feature name injected by karma.warp.conf.js. */
function getWarpFeature(): string {
  const karma = (window as any).__karma__;
  return karma?.config?.warpFeature || 'warp';
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
 * Build a session ID encoding browser, feature, and test case.
 * Format: `{browser}_{feature}_{role}` e.g. `edge_snap_offerer`
 */
function allocSessionId(role: string): string {
  const browser = detectBrowser();
  const feature = getWarpFeature();
  return `${browser}_${feature}_${role}`;
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
 * Run a connect-and-verify flow, same as the base tests but with
 * feature-prefixed session IDs for distinct pcap captures.
 */
async function runFeatureTest(role: string, config: SessionConfig): Promise<void> {
  const wsPort = getServerWsPort();
  const wsUrl = `ws://127.0.0.1:${wsPort}`;
  const sid = allocSessionId(role);
  const feature = getWarpFeature();
  const PING_MESSAGE = `hello from ${feature}!`;
  const ECHO_TIMEOUT_MS = 10000; // longer timeout - experimental features may be slower
  const RTT_THRESHOLD_MS = 2000; // generous for experimental path

  console.log(`[${feature}] ${role}: connecting to ${wsUrl}, session=${sid}`);

  const ws = await connectWs(wsUrl);

  try {
    sendMsg(ws, {type: 'create', session_id: sid, config});
    const created = await recvMsg(ws);
    expectMsg(created, 'created');

    let pc: RTCPeerConnection;
    let dc: RTCDataChannel;
    let dcPromise: Promise<RTCDataChannel> | undefined;

    if (config.client_sdp_role === 'offerer') {
      pc = new RTCPeerConnection({iceServers: []});
      dc = pc.createDataChannel('test-data');

      const offer = await pc.createOffer();
      await pc.setLocalDescription(offer);
      await waitForIceGathering(pc);

      const completeSdp = pc.localDescription!.sdp;
      console.log(`[${feature}] Sending offer (${completeSdp.length} bytes)`);

      sendMsg(ws, {type: 'sdp', session_id: sid, sdp: completeSdp});
      const answerMsg = await recvMsg(ws);
      const {sdp: answerSdp} = expectMsg(answerMsg, 'sdp');

      console.log(`[${feature}] Received answer (${answerSdp.length} bytes)`);
      await pc.setRemoteDescription({type: 'answer', sdp: answerSdp});
    } else {
      pc = new RTCPeerConnection({iceServers: []});

      dcPromise = new Promise<RTCDataChannel>((resolve, reject) => {
        const timeout = setTimeout(
          () => reject(new Error('Timed out waiting for ondatachannel')),
          ECHO_TIMEOUT_MS,
        );
        pc.ondatachannel = (event) => {
          clearTimeout(timeout);
          resolve(event.channel);
        };
      });

      const offerMsg = await recvMsg(ws);
      const {sdp: offerSdp} = expectMsg(offerMsg, 'sdp');

      console.log(`[${feature}] Received offer (${offerSdp.length} bytes)`);
      await pc.setRemoteDescription({type: 'offer', sdp: offerSdp});

      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      await waitForIceGathering(pc);

      const completeSdp = pc.localDescription!.sdp;
      console.log(`[${feature}] Sending answer (${completeSdp.length} bytes)`);

      sendMsg(ws, {type: 'sdp', session_id: sid, sdp: completeSdp});
    }

    sendMsg(ws, {type: 'ready', session_id: sid});
    const ready = await recvMsg(ws);
    expectMsg(ready, 'ready');

    if (dcPromise) {
      dc = await dcPromise;
    }

    if (dc!.readyState !== 'open') {
      await new Promise<void>((resolve, reject) => {
        const timeout = setTimeout(
          () => reject(new Error(`Data channel did not open (state: ${dc!.readyState})`)),
          ECHO_TIMEOUT_MS,
        );
        dc!.onopen = () => {
          clearTimeout(timeout);
          resolve();
        };
        if (dc!.readyState === 'open') {
          clearTimeout(timeout);
          resolve();
        }
      });
    }

    console.log(`[${feature}] Data channel "${dc!.label}" is open`);

    const sendTime = performance.now();

    const echoPromise = new Promise<string>((resolve, reject) => {
      const timeout = setTimeout(
        () => reject(new Error('Timed out waiting for echo reply')),
        ECHO_TIMEOUT_MS,
      );
      dc!.onmessage = (event) => {
        const data = typeof event.data === 'string'
          ? event.data
          : new TextDecoder().decode(event.data);
        if (data === PING_MESSAGE) {
          clearTimeout(timeout);
          resolve(data);
        } else {
          console.log(`[${feature}] Ignoring non-echo message: "${data}"`);
        }
      };
    });

    dc!.send(PING_MESSAGE);
    console.log(`[${feature}] Sent: "${PING_MESSAGE}"`);

    // Retry sending after 200ms in case Chrome's SCTP didn't flush the
    // initial send (observed with ICE-lite on Linux headless Chrome).
    const retryTimer = setTimeout(() => {
      if (dc!.readyState === 'open') {
        dc!.send(PING_MESSAGE);
        console.log(`[${feature}] Retry sent: "${PING_MESSAGE}"`);
      }
    }, 200);

    const echoReply = await echoPromise;
    clearTimeout(retryTimer);
    const rttMs = performance.now() - sendTime;

    console.log(`[${feature}] Echo: "${echoReply}" (RTT: ${rttMs.toFixed(2)}ms)`);

    expect(echoReply).toBe(PING_MESSAGE);
    expect(rttMs).toBeLessThan(RTT_THRESHOLD_MS);

    console.log(`[${feature}] ${role}: PASSED (RTT: ${rttMs.toFixed(2)}ms)`);

    sendMsg(ws, {type: 'destroy', session_id: sid});
    const destroyed = await recvMsg(ws);
    expectMsg(destroyed, 'destroyed');

    pc.close();
  } finally {
    await closeWs(ws);
  }
}

describe('WARP Feature Tests', () => {
  const TEST_TIMEOUT_MS = 30_000;

  beforeAll(() => {
    jasmine.DEFAULT_TIMEOUT_INTERVAL = TEST_TIMEOUT_MS;
  });

  describe('SNAP (SCTP out-of-band signaling)', () => {
    it('should connect as offerer with SNAP enabled', async () => {
      await runFeatureTest('snap_offerer', {
        client_sdp_role: 'offerer',
        server_ice_mode: 'lite',
        client_dtls_role: 'active',
      });
    });

    it('should connect as answerer with SNAP enabled', async () => {
      await runFeatureTest('snap_answerer', {
        client_sdp_role: 'answerer',
        server_ice_mode: 'lite',
        client_dtls_role: 'active',
      });
    });
  });

  describe('SPED (DTLS-in-STUN embedding)', () => {
    it('should connect as offerer with SPED enabled', async () => {
      await runFeatureTest('sped_offerer', {
        client_sdp_role: 'offerer',
        server_ice_mode: 'lite',
        client_dtls_role: 'active',
      });
    });

    it('should connect as answerer with SPED enabled', async () => {
      await runFeatureTest('sped_answerer', {
        client_sdp_role: 'answerer',
        server_ice_mode: 'lite',
        client_dtls_role: 'active',
      });
    });
  });

  describe('WARP (SNAP + SPED combined)', () => {
    it('should connect as offerer with WARP enabled', async () => {
      await runFeatureTest('warp_offerer', {
        client_sdp_role: 'offerer',
        server_ice_mode: 'lite',
        client_dtls_role: 'active',
      });
    });

    it('should connect as answerer with WARP enabled', async () => {
      await runFeatureTest('warp_answerer', {
        client_sdp_role: 'answerer',
        server_ice_mode: 'lite',
        client_dtls_role: 'active',
      });
    });
  });
});
