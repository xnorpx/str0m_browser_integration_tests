import {VideoLoopbackReport} from './protocol';
import {closeWs, connectWs, recvMsg, sendMsg, waitForIceGathering} from './signaling';
import {DD_URI, delay, expectMessage, until, syntheticVideo, channelStats, decoded} from './video-helpers';

const DROP_START = 60;
const DROP_DURATION = 120;
const serverStats = (dc: RTCDataChannel) => channelStats<VideoLoopbackReport>(dc, 'video-loopback-stats');

async function runVideoLoopback(drop: boolean): Promise<void> {
  const karma = (window as Window & {__karma__?: {config?: {serverWsPort?: number}}}).__karma__;
  const ws = await connectWs(`ws://127.0.0.1:${karma?.config?.serverWsPort ?? 9090}`);
  const sid = `${/Edg\//.test(navigator.userAgent) ? 'edge' : 'chrome'}_dd_av1_${drop ? 'drop' : 'control'}`;
  const pc = new RTCPeerConnection({iceServers: []});
  const source = syntheticVideo();
  const video = document.createElement('video');
  video.autoplay = true;
  video.muted = true;
  video.playsInline = true;
  document.body.appendChild(video);
  let created = false;
  try {
    const capabilities = RTCRtpSender.getCapabilities('video');
    if (!capabilities) throw new Error('Video sender capabilities unavailable');
    const av1 = capabilities.codecs.filter(codec => codec.mimeType.toLowerCase() === 'video/av1');
    if (!av1.length) throw new Error('AV1 encoder required for DD interop (no codec fallback)');

    sendMsg(ws, {type: 'create', session_id: sid, config: {
      client_sdp_role: 'offerer', server_ice_mode: 'lite', client_dtls_role: 'active',
      server_netem: {},
      video_loopback: {drop_start: DROP_START, drop_duration: drop ? DROP_DURATION : 0},
    }});
    expectMessage(await recvMsg(ws), 'created');
    created = true;
    pc.ontrack = event => { video.srcObject = new MediaStream([event.track]); };
    const encoding: RTCRtpEncodingParameters & {scalabilityMode: string} = {
      scalabilityMode: 'L1T3', maxBitrate: 1000000,
    };
    const transceiver = pc.addTransceiver(source.stream.getVideoTracks()[0], {
      direction: 'sendrecv',
      streams: [source.stream],
      sendEncodings: [encoding],
    });
    transceiver.setCodecPreferences(av1);
    const dc = pc.createDataChannel('video-stats');
    await pc.setLocalDescription(await pc.createOffer());
    await waitForIceGathering(pc);
    const offer = pc.localDescription?.sdp;
    if (!offer?.includes(DD_URI)) throw new Error('Chrome offer did not advertise dependency descriptor');
    sendMsg(ws, {type: 'sdp', session_id: sid, sdp: offer});
    const answer = expectMessage(await recvMsg(ws), 'sdp').sdp;
    if (!answer.includes(DD_URI)) throw new Error('str0m answer did not negotiate dependency descriptor');
    await pc.setRemoteDescription({type: 'answer', sdp: answer});
    sendMsg(ws, {type: 'ready', session_id: sid});
    expectMessage(await recvMsg(ws), 'ready');
    await until('data channel open', async () => dc.readyState, state => state === 'open');
    await until('remote video track', async () => video.srcObject, stream => stream !== null);
    await Promise.race([
      video.play(),
      delay(10000).then(() => { throw new Error('Remote video did not start playing'); }),
    ]);

    const baseline = await until('baseline AV1 decode', () => decoded(pc), stats => stats.frames >= 10);
    expect(baseline.codec.toLowerCase()).toBe('video/av1');
    const sample = async () => {
      const sfu = await serverStats(dc);
      const decoder = await decoded(pc);
      const quality = video.getVideoPlaybackQuality();
      return {sfu, decoder, rendered: quality.totalVideoFrames - quality.droppedVideoFrames};
    };
    const before = await sample();
    expect(before.sfu.frames_received).toBeLessThan(DROP_START);
    let filtered = before;
    let resumed = before;
    if (drop) {
      const started = await until('SFU starts filtering', sample, value => value.sfu.frames_dropped > 0);
      filtered = await until('decode while SFU filters top temporal layer', sample,
        value => value.sfu.frames_dropped >= 15 && value.decoder.frames >= started.decoder.frames + 10);
      expect(filtered.sfu.frames_received).toBeLessThan(DROP_START + DROP_DURATION);
      expect(filtered.sfu.packets_dropped).toBeGreaterThan(0);
      expect(filtered.rendered).toBeGreaterThan(started.rendered);
      resumed = await until('SFU resumes full temporal stream', sample,
        value => value.sfu.enhancement_frames_forwarded_after_drop > 0);
    }
    const recovered = await until('sustained decode after forwarding resumes', sample, value =>
      value.sfu.frames_received >= (drop ? DROP_START + DROP_DURATION + 60 : 90)
      && value.decoder.frames >= resumed.decoder.frames + 30
      && (!drop || value.sfu.enhancement_frames_forwarded_after_drop >= 20));
    expect(recovered.sfu.max_temporal_id).toBe(2);
    expect(recovered.sfu.structures_received).toBeGreaterThan(0);
    expect(recovered.sfu.descriptors_parsed).toBe(recovered.sfu.packets_received);
    expect(recovered.rendered).toBeGreaterThan(filtered.rendered);
    expect(video.videoWidth).toBe(640);
    expect(video.videoHeight).toBe(360);
    if (!drop) expect(recovered.sfu.frames_dropped).toBe(0);
    // Removing discardable frames must not require a recovery keyframe.
    if (drop) expect(recovered.decoder.keys).toBe(baseline.keys);
    console.log(`[video] ${sid}: ${JSON.stringify({baseline, before, filtered, resumed, recovered})}`);

    sendMsg(ws, {type: 'destroy', session_id: sid});
    const destroyed = expectMessage(await recvMsg(ws), 'destroyed');
    created = false;
    expect(destroyed.report).toBeDefined();
    expect(destroyed.report?.error).toBeNull();
    expect(destroyed.report?.video_loopback?.frames_received).toBeGreaterThanOrEqual(recovered.sfu.frames_received);
  } finally {
    pc.close();
    source.stop();
    video.srcObject = null;
    video.remove();
    try {
      if (created && ws.readyState === WebSocket.OPEN) {
        sendMsg(ws, {type: 'destroy', session_id: sid});
        const response = await recvMsg(ws);
        console.log(`[video] failure teardown: ${JSON.stringify(response)}`);
      }
    } finally {
      await closeWs(ws);
    }
  }
}

describe('str0m dependency descriptor browser interop', () => {
  it('loops back generated AV1 L1T3 with DD and no drops', async () => {
    await runVideoLoopback(false);
  }, 45000);

  it('decodes through DD-guided whole-frame drops and temporal-layer resumption', async () => {
    await runVideoLoopback(true);
  }, 45000);
});
