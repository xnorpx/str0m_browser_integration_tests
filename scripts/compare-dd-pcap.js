'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');

// This reader deliberately supports the harness's little-endian, LINKTYPE_RAW,
// IPv4/UDP PCAPNG format, not arbitrary external captures.
function readCapture(data) {
  const packets = [];
  const interfaces = [];
  let section = false;
  for (let offset = 0; offset < data.length;) {
    assert(offset + 12 <= data.length, 'Truncated PCAPNG block');
    const type = data.readUInt32LE(offset);
    const length = data.readUInt32LE(offset + 4);
    assert(length >= 12 && length % 4 === 0 && offset + length <= data.length,
      'Invalid PCAPNG block length');
    assert.equal(data.readUInt32LE(offset + length - 4), length, 'PCAPNG block trailer mismatch');
    const block = data.subarray(offset, offset + length);
    if (type === 0x0a0d0d0a) {
      assert(length >= 28 && block.readUInt32LE(8) === 0x1a2b3c4d,
        'Expected little-endian PCAPNG section');
      interfaces.length = 0;
      section = true;
    } else {
      assert(section, 'Missing PCAPNG section header');
      if (type === 1) {
        assert(length >= 20, 'Truncated interface description');
        interfaces.push(block.readUInt16LE(8));
      } else if (type === 6) {
        assert(length >= 32, 'Truncated enhanced packet block');
        assert.equal(interfaces[block.readUInt32LE(8)], 101, 'Expected LINKTYPE_RAW');
        const captured = block.readUInt32LE(20);
        assert.equal(captured, block.readUInt32LE(24), 'Capture truncated a packet');
        assert(28 + Math.ceil(captured / 4) * 4 + 4 <= length, 'Truncated captured data');
        const ip = block.subarray(28, 28 + captured);
        assert(ip.length >= 20 && ip[0] >>> 4 === 4, 'Expected IPv4 packet');
        const ihl = (ip[0] & 15) * 4;
        const total = ip.readUInt16BE(2);
        assert(ihl >= 20 && total >= ihl + 8 && total <= ip.length, 'Invalid IPv4 length');
        assert.equal(ip[9], 17, 'Expected UDP');
        assert.equal(ip.readUInt16BE(6) & 0x3fff, 0, 'Fragmented IPv4 is unsupported');
        const udp = ip.subarray(ihl, total);
        const udpLength = udp.readUInt16BE(4);
        assert(udpLength >= 8 && udpLength === udp.length, 'Invalid UDP length');
        const endpoint = (start, port) =>
          `${Array.from(ip.subarray(start, start + 4)).join('.')}:${port}`;
        packets.push({
          source: endpoint(12, udp.readUInt16BE(0)),
          destination: endpoint(16, udp.readUInt16BE(2)),
          data: udp.subarray(8),
        });
      }
    }
    offset += length;
  }
  assert(section && packets.length > 0, 'Empty PCAPNG capture');
  return packets;
}

function readRtp(data) {
  // RFC 7983 / RFC 5761: exclude STUN, DTLS and (S)RTCP before parsing RTP.
  if (data.length === 0 || data[0] < 128 || data[0] > 191) return null;
  assert(data.length >= 2, 'Truncated RTP/RTCP packet');
  if (data[1] >= 192 && data[1] <= 223) return null;
  assert(data.length >= 12, 'Truncated RTP header');
  let offset = 12 + (data[0] & 15) * 4;
  assert(offset <= data.length, 'Truncated RTP CSRC list');
  const extensions = new Map();
  let extensionProfile = null;
  if (data[0] & 0x10) {
    assert(offset + 4 <= data.length, 'Truncated RTP extension header');
    extensionProfile = data.readUInt16BE(offset);
    const end = offset + 4 + data.readUInt16BE(offset + 2) * 4;
    offset += 4;
    assert(end <= data.length, 'Truncated RTP extension block');
    assert(extensionProfile === 0xbede || (extensionProfile & 0xfff0) === 0x1000,
      `Unsupported RTP extension profile ${extensionProfile.toString(16)}`);
    while (offset < end) {
      const tag = data[offset++];
      if (tag === 0) continue;
      let id;
      let length;
      if (extensionProfile === 0xbede) {
        id = tag >>> 4;
        if (id === 15) break;
        assert(id !== 0, 'Invalid one-byte padding element');
        length = (tag & 15) + 1;
      } else {
        id = tag;
        assert(offset < end, 'Truncated two-byte extension length');
        length = data[offset++];
      }
      assert(offset + length <= end, 'Truncated RTP extension value');
      assert(!extensions.has(id), `Duplicate RTP extension ID ${id}`);
      extensions.set(id, data.subarray(offset, offset + length));
      offset += length;
    }
    offset = end;
  }
  return {
    ssrc: data.readUInt32BE(8),
    payload_type: data[1] & 127,
    sequence: data.readUInt16BE(2),
    timestamp: data.readUInt32BE(4),
    marker: Boolean(data[1] & 128),
    padding: Boolean(data[0] & 0x20),
    header_bytes: offset,
    extension_profile: extensionProfile,
    extensions,
  };
}

function readDd(data) {
  assert(data.length >= 3, 'Truncated mandatory DD fields');
  return {
    first: Boolean(data[0] & 128),
    last: Boolean(data[0] & 64),
    template_id: data[0] & 63,
    frame_number: data.readUInt16BE(1),
    structure: data.length > 3 && Boolean(data[3] & 128),
  };
}

function compareCapture(data, profile) {
  assert.equal(profile.schema_version, 2, 'Regenerate the version-2 DD profile with the server');
  const id = profile.dd_extension_id;
  assert(Number.isInteger(id) && id >= 1 && id <= 255, 'Missing negotiated DD extension ID');
  const directions = ['chrome_to_rust', 'rust_to_chrome'];
  const streams = new Map();
  const states = {};
  for (const direction of directions) {
    assert(Array.isArray(profile[direction]) && profile[direction].length > 0,
      `Empty ${direction} profile`);
    assert.equal(profile.incomplete_frames[direction], false, `${direction} profile is incomplete`);
    states[direction] = {
      expected: profile[direction], index: 0, current: null, previousFrame: null,
      summary: {
        packets: 0, frames: 0, first_only: 0, middle: 0, last_only: 0, first_and_last: 0,
        structures: 0, frame_number_wraps: 0, dd_bytes: 0, padding_without_dd: 0,
        dd_lengths: {}, template_ids: {}, extension_profiles: {},
      },
    };
    for (const sample of profile[direction]) {
      const key = `${sample.ssrc}:${sample.payload_type}`;
      assert(!streams.has(key) || streams.get(key) === direction,
        'Both directions use the same SSRC/PT; cannot disambiguate capture');
      streams.set(key, direction);
    }
  }
  for (const packet of readCapture(data)) {
    const rtp = readRtp(packet.data);
    if (!rtp) continue;
    const direction = streams.get(`${rtp.ssrc}:${rtp.payload_type}`);
    if (!direction) continue;
    const state = states[direction];
    const summary = state.summary;
    const bytes = rtp.extensions.get(id);
    if (!bytes && rtp.padding) {
      // Padding length is encrypted. These are candidates for bandwidth probes,
      // not independently proven pure padding; expected packets must still match.
      summary.padding_without_dd++;
      continue;
    }
    assert(bytes, `${direction} sequence ${rtp.sequence}: missing negotiated DD`);
    const label = `${direction} packet ${state.index} sequence ${rtp.sequence}`;
    const expected = state.expected[state.index++];
    assert(expected, `${label}: unexpected extra media packet`);
    for (const field of ['ssrc', 'payload_type', 'sequence', 'timestamp', 'marker']) {
      assert.equal(rtp[field], expected[field], `${label}: ${field} mismatch`);
    }
    assert.equal(bytes.toString('hex'), expected.dd_hex, `${label}: wire DD bytes mismatch`);
    assert.equal(bytes.length, expected.dd_bytes, `${label}: DD length mismatch`);
    const dd = readDd(bytes);
    for (const field of ['first', 'last', 'structure']) {
      assert.equal(dd[field], expected[field], `${label}: DD ${field} mismatch`);
    }
    assert.equal(dd.frame_number, ((expected.frame_number % 65536) + 65536) % 65536,
      `${label}: DD frame number mismatch`);
    assert.equal(rtp.marker, dd.last, `${label}: marker must equal DD last for these L1 streams`);
    assert(!dd.structure || dd.first, `${label}: structure on continuation packet`);
    if (dd.first) {
      assert.equal(state.current, null, `${label}: previous frame never ended`);
      if (state.previousFrame !== null) {
        const step = (dd.frame_number - state.previousFrame + 65536) % 65536;
        assert(step > 0 && step < 32768, `${label}: non-increasing DD frame number`);
        if (dd.frame_number < state.previousFrame) summary.frame_number_wraps++;
      }
      state.previousFrame = dd.frame_number;
      state.current = {
        frame_number: dd.frame_number, timestamp: rtp.timestamp, ssrc: rtp.ssrc, packets: 0,
      };
    }
    assert(state.current, `${label}: continuation without first packet`);
    for (const field of ['frame_number', 'timestamp', 'ssrc']) {
      assert.equal(state.current[field], field === 'frame_number' ? dd[field] : rtp[field],
        `${label}: ${field} changed inside frame`);
    }
    assert.equal(expected.packet_index_in_frame, state.current.packets++,
      `${label}: packet index mismatch`);
    if (summary.source === undefined) {
      summary.source = packet.source;
      summary.destination = packet.destination;
    }
    assert.equal(packet.source, summary.source, `${label}: source endpoint changed`);
    assert.equal(packet.destination, summary.destination, `${label}: destination endpoint changed`);
    const category = dd.first ? (dd.last ? 'first_and_last' : 'first_only')
      : (dd.last ? 'last_only' : 'middle');
    summary[category]++;
    summary.packets++;
    summary.structures += Number(dd.structure);
    summary.dd_bytes += bytes.length;
    for (const [counts, value] of [
      [summary.dd_lengths, bytes.length], [summary.template_ids, dd.template_id],
      [summary.extension_profiles, `0x${rtp.extension_profile.toString(16)}`],
    ]) {
      counts[value] = (counts[value] ?? 0) + 1;
    }
    if (dd.last) {
      summary.frames++;
      state.current = null;
    }
  }
  for (const direction of directions) {
    const {index, expected, current, summary} = states[direction];
    assert.equal(index, expected.length, `${direction}: missing captured media packets`);
    assert.equal(current, null, `${direction}: incomplete captured frame`);
    for (const field of [
      'packets', 'frames', 'first_only', 'middle', 'last_only', 'first_and_last',
      'structures', 'dd_bytes',
    ]) {
      assert.equal(summary[field], profile.report[direction][field],
        `${direction}: ${field} differs from runtime summary`);
    }
  }
  assert.equal(states.chrome_to_rust.summary.source, states.rust_to_chrome.summary.destination,
    'Directions do not have reversed endpoints');
  assert.equal(states.chrome_to_rust.summary.destination, states.rust_to_chrome.summary.source,
    'Directions do not have reversed endpoints');
  assert(states.rust_to_chrome.summary.frame_number_wraps > 0, 'Rust DD wrap was not exercised');
  return {
    schema_version: 1,
    session_id: profile.session_id,
    dd_extension_id: id,
    capture_point: 'str0m UDP boundary; original SRTP bytes, synthesized IPv4/UDP envelopes',
    checks: 'Exact RTP identity, marker, DD bytes and mandatory DD fields; independent frame grouping',
    chrome_to_rust: states.chrome_to_rust.summary,
    rust_to_chrome: states.rust_to_chrome.summary,
  };
}

function main() {
  const root = path.resolve(__dirname, '..');
  const args = process.argv.slice(2);
  assert(args.length === 0 || args.length === 3,
    'Usage: node compare-dd-pcap.js [capture.pcapng profile.json comparison.json]');
  const [capture, profile, output] = args.length ? args.map(file => path.resolve(file)) : [
    path.join(root, 'target', 'pcap', 'chrome_dd_av1_frame_mode_server.pcapng'),
    path.join(root, 'target', 'dd-profile', 'chrome_dd_av1_frame_mode.json'),
    path.join(root, 'target', 'dd-profile', 'chrome_dd_av1_frame_mode_pcap_comparison.json'),
  ];
  const result = compareCapture(fs.readFileSync(capture), JSON.parse(fs.readFileSync(profile, 'utf8')));
  fs.writeFileSync(output, `${JSON.stringify(result, null, 2)}\n`);
  console.log(`[dd-pcap] ${JSON.stringify(result)}`);
}

module.exports = {readCapture, readRtp, readDd, compareCapture};
if (require.main === module) main();
