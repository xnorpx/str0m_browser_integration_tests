/**
 * Browser WebRTC integration tests for str0m - mirrors tests/integration.rs.
 *
 * Each test:
 *   1. Connects to the Rust signaling server via WebSocket.
 *   2. Creates a session with a specific config (offerer/answerer, ICE mode, DTLS role).
 *   3. Exchanges SDP offer/answer through the signaling server.
 *   4. Waits for ICE+DTLS+SCTP to complete and data channel to open.
 *   5. Sends "hello from browser!" and verifies the server echoes it back.
 *   6. Measures round-trip time.
 *   7. Destroys the session and cleans up.
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

/** Detect the browser from the user-agent string. */
function detectBrowser(): string {
  const ua = navigator.userAgent;
  if (/Edg\//i.test(ua)) return 'edge';
  if (/Firefox\//i.test(ua)) return 'firefox';
  if (/Chrome\//i.test(ua)) return 'chrome';
  return 'unknown';
}

/**
 * Build a session ID that encodes the browser and test case name.
 * The server uses this as the pcap filename, so keep it deterministic and readable.
 * Format: `{browser}_{testName}` e.g. `edge_offerer_active_lite`
 */
function allocSessionId(testName: string): string {
  const browser = detectBrowser();
  return `${browser}_${testName}`;
}

/** Assert a server message matches the expected type, or throw. */
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
 * Run a complete connect-and-verify test flow.
 * This is the browser-side equivalent of `run_connect_and_verify()` in integration.rs.
 */
async function runConnectAndVerify(testName: string, config: SessionConfig): Promise<void> {
  const wsPort = getServerWsPort();
  const wsUrl = `ws://127.0.0.1:${wsPort}`;
  const sid = allocSessionId(testName);
  const PING_MESSAGE = 'hello from browser!';
  const ECHO_TIMEOUT_MS = 7000;
  const RTT_THRESHOLD_MS = 500; // generous for browser overhead

  console.log(`[test] ${testName}: connecting to ${wsUrl}, session=${sid}`);

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
      console.log(`[test] Sending offer (${completeSdp.length} bytes)`);

      sendMsg(ws, {type: 'sdp', session_id: sid, sdp: completeSdp});
      const answerMsg = await recvMsg(ws);
      const {sdp: answerSdp} = expectMsg(answerMsg, 'sdp');

      console.log(`[test] Received answer (${answerSdp.length} bytes)`);
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

      console.log(`[test] Received offer (${offerSdp.length} bytes)`);
      await pc.setRemoteDescription({type: 'offer', sdp: offerSdp});

      const answer = await pc.createAnswer();
      await pc.setLocalDescription(answer);
      await waitForIceGathering(pc);

      const completeSdp = pc.localDescription!.sdp;
      console.log(`[test] Sending answer (${completeSdp.length} bytes)`);

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

    console.log(`[test] Data channel "${dc!.label}" is open`);

    const sendTime = performance.now();

    const echoPromise = new Promise<string>((resolve, reject) => {
      const timeout = setTimeout(
        () => reject(new Error('Timed out waiting for echo reply')),
        ECHO_TIMEOUT_MS,
      );
      dc!.onmessage = (event) => {
        const data = typeof event.data === 'string' ? event.data : new TextDecoder().decode(event.data);
        if (data === PING_MESSAGE) {
          clearTimeout(timeout);
          resolve(data);
        } else {
          console.log(`[test] Ignoring non-echo message: "${data}"`);
        }
      };
    });

    dc!.send(PING_MESSAGE);
    console.log(`[test] Sent: "${PING_MESSAGE}"`);

    // Retry sending after 200ms in case Chrome's SCTP didn't flush the
    // initial send (observed with ICE-lite on Linux headless Chrome).
    const retryTimer = setTimeout(() => {
      if (dc!.readyState === 'open') {
        dc!.send(PING_MESSAGE);
        console.log(`[test] Retry sent: "${PING_MESSAGE}"`);
      }
    }, 200);

    const echoReply = await echoPromise;
    clearTimeout(retryTimer);
    const rttMs = performance.now() - sendTime;

    console.log(`[test] Echo: "${echoReply}" (RTT: ${rttMs.toFixed(2)}ms)`);

    expect(echoReply).toBe(PING_MESSAGE);
    expect(rttMs).toBeLessThan(RTT_THRESHOLD_MS);

    console.log(`[test] ${testName}: PASSED (RTT: ${rttMs.toFixed(2)}ms)`);

    sendMsg(ws, {type: 'destroy', session_id: sid});
    const destroyed = await recvMsg(ws);
    expectMsg(destroyed, 'destroyed');

    pc.close();
  } finally {
    await closeWs(ws);
  }
}

describe('str0m Browser Integration Tests', () => {
  const TEST_TIMEOUT_MS = 30_000;

  beforeAll(() => {
    jasmine.DEFAULT_TIMEOUT_INTERVAL = TEST_TIMEOUT_MS;
  });

  describe('Browser Offerer, DTLS Active', () => {
    it('should connect with server ICE Lite', async () => {
      await runConnectAndVerify('offerer_active_lite', {
        client_sdp_role: 'offerer',
        server_ice_mode: 'lite',
        client_dtls_role: 'active',
      });
    });

    it('should connect with server ICE Full', async () => {
      await runConnectAndVerify('offerer_active_full', {
        client_sdp_role: 'offerer',
        server_ice_mode: 'full',
        client_dtls_role: 'active',
      });
    });
  });

  describe('Browser Offerer, DTLS Passive', () => {
    it('should connect with server ICE Lite', async () => {
      await runConnectAndVerify('offerer_passive_lite', {
        client_sdp_role: 'offerer',
        server_ice_mode: 'lite',
        client_dtls_role: 'passive',
      });
    });

    it('should connect with server ICE Full', async () => {
      await runConnectAndVerify('offerer_passive_full', {
        client_sdp_role: 'offerer',
        server_ice_mode: 'full',
        client_dtls_role: 'passive',
      });
    });
  });

  describe('Browser Answerer, DTLS Active', () => {
    it('should connect with server ICE Lite', async () => {
      await runConnectAndVerify('answerer_active_lite', {
        client_sdp_role: 'answerer',
        server_ice_mode: 'lite',
        client_dtls_role: 'active',
      });
    });

    it('should connect with server ICE Full', async () => {
      await runConnectAndVerify('answerer_active_full', {
        client_sdp_role: 'answerer',
        server_ice_mode: 'full',
        client_dtls_role: 'active',
      });
    });
  });
});
