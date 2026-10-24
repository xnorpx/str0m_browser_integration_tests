import {DdPacketSummary, FrameVideoReport} from './protocol';
import {closeWs, connectWs, recvMsg, sendMsg, waitForIceGathering} from './signaling';
import {DD_URI, channelStats, decoded, expectMessage, syntheticVideo, until} from './video-helpers';

function verifyPacketPlacement(profile: DdPacketSummary): void {
  expect(profile.packets).toBeGreaterThan(profile.frames);
  expect(profile.semantic_roundtrips).toBe(profile.packets);
  expect(profile.single_packet_frames).toBeGreaterThan(0);
  expect(profile.multi_packet_frames).toBeGreaterThan(0);
  expect(profile.middle).toBeGreaterThan(0);
  expect(profile.first_only).toBe(profile.multi_packet_frames);
  expect(profile.last_only).toBe(profile.multi_packet_frames);
  expect(profile.first_and_last).toBe(profile.single_packet_frames);
  expect(profile.structures).toBeGreaterThan(0);
  expect(profile.dd_bytes).toBeGreaterThan(profile.packets * 3);
}

describe('AV1 frame-mode DD interop', () => {
  it('encodes, decodes and verifies wire DD in both Chrome/str0m directions', async () => {
    const karma = (window as Window & {__karma__?: {config?: {serverWsPort?: number}}}).__karma__;
    const ws = await connectWs(`ws://127.0.0.1:${karma?.config?.serverWsPort ?? 9090}`);
    const sid = 'chrome_dd_av1_frame_mode';
    const pc = new RTCPeerConnection({iceServers: []});
    const source = syntheticVideo(320, 180, true);
    const video = document.createElement('video');
    video.autoplay = true;
    video.muted = true;
    video.playsInline = true;
    document.body.appendChild(video);
    let created = false;
    try {
      const av1 = RTCRtpSender.getCapabilities('video')?.codecs.filter(c => c.mimeType.toLowerCase() === 'video/av1');
      if (!av1?.length) throw new Error('Chrome AV1 encoder required; no codec fallback');
      sendMsg(ws, {type: 'create', session_id: sid, config: {
        client_sdp_role: 'offerer', server_ice_mode: 'lite', client_dtls_role: 'active',
        server_netem: {}, video_frame_mode: true,
      }});
      expectMessage(await recvMsg(ws), 'created');
      created = true;
      pc.ontrack = event => { video.srcObject = new MediaStream([event.track]); };
      const encoding: RTCRtpEncodingParameters & {scalabilityMode: string} = {
        scalabilityMode: 'L1T3', maxBitrate: 1500000,
      };
      const transceiver = pc.addTransceiver(source.stream.getVideoTracks()[0], {
        direction: 'sendrecv', streams: [source.stream], sendEncodings: [encoding],
      });
      transceiver.setCodecPreferences(av1);
      const dc = pc.createDataChannel('frame-stats');
      await pc.setLocalDescription(await pc.createOffer());
      await waitForIceGathering(pc);
      const offer = pc.localDescription?.sdp;
      if (!offer?.includes(DD_URI)) throw new Error('Chrome did not offer DD');
      sendMsg(ws, {type: 'sdp', session_id: sid, sdp: offer});
      const answer = expectMessage(await recvMsg(ws), 'sdp').sdp;
      if (!answer.includes(DD_URI)) throw new Error('str0m did not negotiate DD');
      await pc.setRemoteDescription({type: 'answer', sdp: answer});
      sendMsg(ws, {type: 'ready', session_id: sid});
      expectMessage(await recvMsg(ws), 'ready');
      await until('frame-mode data channel', async () => dc.readyState, state => state === 'open');
      const sample = async () => ({
        rust: await channelStats<FrameVideoReport>(dc, 'video-frame-stats'),
        chrome: await decoded(pc),
      });
      const result = await until('real AV1 decoding at both endpoints', sample, value =>
        value.rust.rust_frames_sent === 32 && value.chrome.frames === 32
        && value.rust.rust_frames_decoded >= 32
        && value.rust.chrome_to_rust.single_packet_frames > 0
        && value.rust.chrome_to_rust.multi_packet_frames > 0
        && value.rust.chrome_to_rust.first_only === value.rust.chrome_to_rust.multi_packet_frames
        && value.rust.chrome_frames_received === value.rust.chrome_to_rust.frames);
      expect(result.chrome.codec.toLowerCase()).toBe('video/av1');
      expect(result.chrome.keys).toBe(2);
      expect(result.rust.rust_frames_encoded).toBe(32);
      expect(result.rust.rust_frames_decoded).toBe(result.rust.chrome_frames_received);
      expect(result.rust.frame_dd_roundtrips).toBe(result.rust.chrome_frames_received);
      expect(result.rust.rust_unique_decoded_images).toBeGreaterThan(16);
      expect([result.rust.decoded_width, result.rust.decoded_height]).toEqual([320, 180]);
      verifyPacketPlacement(result.rust.chrome_to_rust);
      verifyPacketPlacement(result.rust.rust_to_chrome);
      expect(result.rust.rust_to_chrome.frames).toBe(32);
      expect(result.rust.rust_to_chrome.structures).toBe(2);
      await until('Rust video rendering', async () => video.getVideoPlaybackQuality(),
        quality => quality.totalVideoFrames - quality.droppedVideoFrames >= 20);
      expect([video.videoWidth, video.videoHeight]).toEqual([160, 96]);
      // Stop drawing, not the track: stopping the track can discard queued packets
      // halfway through the final frame. Drain the sender before ending the session.
      source.pause();
      let previousPackets = -1;
      let quietSamples = 0;
      const final = await until('complete final DD frame and sender drain', () =>
        channelStats<FrameVideoReport>(dc, 'video-frame-stats'), value => {
        quietSamples = value.chrome_to_rust.packets === previousPackets ? quietSamples + 1 : 0;
        previousPackets = value.chrome_to_rust.packets;
        return quietSamples >= 3
          && value.chrome_to_rust.first_only === value.chrome_to_rust.multi_packet_frames
          && value.chrome_frames_received === value.chrome_to_rust.frames;
      });
      console.log(`[frame-video] ${JSON.stringify({rust: final, chrome: result.chrome})}`);
      sendMsg(ws, {type: 'destroy', session_id: sid});
      const destroyed = expectMessage(await recvMsg(ws), 'destroyed');
      created = false;
      expect(destroyed.report?.error).toBeNull();
      expect(destroyed.report?.video_frame_mode?.rust_to_chrome.frames).toBe(32);
      const finalReport = destroyed.report?.video_frame_mode;
      if (!finalReport) throw new Error('Missing final frame-mode report');
      verifyPacketPlacement(finalReport.chrome_to_rust);
      verifyPacketPlacement(finalReport.rust_to_chrome);
    } finally {
      pc.close();
      source.stop();
      video.srcObject = null;
      video.remove();
      try {
        if (created && ws.readyState === WebSocket.OPEN) {
          sendMsg(ws, {type: 'destroy', session_id: sid});
          console.log(`[frame-video] teardown: ${JSON.stringify(await recvMsg(ws))}`);
        }
      } finally {
        await closeWs(ws);
      }
    }
  }, 120000);
});
