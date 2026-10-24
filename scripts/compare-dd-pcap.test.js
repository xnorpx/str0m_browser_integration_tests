'use strict';

const assert = require('node:assert/strict');
const {test} = require('node:test');
const {readCapture, readRtp, readDd, compareCapture} = require('./compare-dd-pcap');

function rtp(ssrc, sequence, timestamp, dd, twoByte = false) {
  const element = Buffer.concat([Buffer.from(twoByte ? [13, dd.length] : [0xd0 | (dd.length - 1)]), dd]);
  const extension = Buffer.alloc(Math.ceil(element.length / 4) * 4);
  element.copy(extension);
  const header = Buffer.alloc(20);
  header[0] = 0x91; // Extension plus one CSRC.
  header[1] = 45 | ((dd[0] & 64) ? 128 : 0);
  header.writeUInt16BE(sequence, 2);
  header.writeUInt32BE(timestamp, 4);
  header.writeUInt32BE(ssrc, 8);
  header.writeUInt32BE(42, 12);
  header.writeUInt16BE(twoByte ? 0x100f : 0xbede, 16);
  header.writeUInt16BE(extension.length / 4, 18);
  return Buffer.concat([header, extension, Buffer.alloc(20, 0xa5)]);
}

function block(type, body) {
  const result = Buffer.alloc(12 + Math.ceil(body.length / 4) * 4);
  result.writeUInt32LE(type, 0);
  result.writeUInt32LE(result.length, 4);
  body.copy(result, 8);
  result.writeUInt32LE(result.length, result.length - 4);
  return result;
}

function capture(packets) {
  const section = Buffer.alloc(16);
  section.writeUInt32LE(0x1a2b3c4d);
  section.writeUInt16LE(1, 4);
  section.fill(0xff, 8);
  const iface = Buffer.alloc(8);
  iface.writeUInt16LE(101);
  iface.writeUInt32LE(65535, 4);
  return Buffer.concat([block(0x0a0d0d0a, section), block(1, iface), ...packets.map((data, i) => {
    const ip = Buffer.alloc(28);
    ip[0] = 0x45;
    ip.writeUInt16BE(ip.length + data.length, 2);
    ip[9] = 17;
    ip.set([127, 0, 0, 1], 12);
    ip.set([127, 0, 0, 1], 16);
    ip.writeUInt16BE(i === 0 ? 5000 : 6000, 20);
    ip.writeUInt16BE(i === 0 ? 6000 : 5000, 22);
    ip.writeUInt16BE(8 + data.length, 24);
    const frame = Buffer.concat([ip, data]);
    const metadata = Buffer.alloc(20);
    metadata.writeUInt32LE(frame.length, 12);
    metadata.writeUInt32LE(frame.length, 16);
    return block(6, Buffer.concat([metadata, frame]));
  })]);
}

function fixture() {
  const chrome = [
    {ssrc: 100, sequence: 123, timestamp: 1000, frame_number: 1,
      dd_hex: 'c0000180', first: true, last: true, marker: true, structure: true,
      dd_bytes: 4, payload_type: 45, packet_index_in_frame: 0},
  ];
  const rust = [
    {ssrc: 200, sequence: 65534, timestamp: 9000, frame_number: 65535,
      dd_hex: '80ffff80', first: true, last: false, marker: false, structure: true,
      dd_bytes: 4, payload_type: 45, packet_index_in_frame: 0},
    {ssrc: 200, sequence: 65535, timestamp: 9000, frame_number: 65535,
      dd_hex: '40ffff', first: false, last: true, marker: true, structure: false,
      dd_bytes: 3, payload_type: 45, packet_index_in_frame: 1},
    {ssrc: 200, sequence: 0, timestamp: 18000, frame_number: 65536,
      dd_hex: 'c00000', first: true, last: true, marker: true, structure: false,
      dd_bytes: 3, payload_type: 45, packet_index_in_frame: 0},
  ];
  return {
    packets: [...chrome, ...rust].map((p, i) =>
      rtp(p.ssrc, p.sequence, p.timestamp, Buffer.from(p.dd_hex, 'hex'), i !== 0)),
    profile: {
      schema_version: 2, session_id: 'fixture', dd_extension_id: 13,
      incomplete_frames: {chrome_to_rust: false, rust_to_chrome: false},
      chrome_to_rust: chrome, rust_to_chrome: rust,
      report: {
        chrome_to_rust: {packets: 1, frames: 1, first_only: 0, middle: 0,
          last_only: 0, first_and_last: 1, structures: 1, dd_bytes: 4},
        rust_to_chrome: {packets: 3, frames: 2, first_only: 1, middle: 0,
          last_only: 1, first_and_last: 1, structures: 1, dd_bytes: 10},
      },
    },
  };
}

test('PCAP verifier matches both directions, RFC 8285 forms, CSRCs and frame/sequence wraps', () => {
  const {packets, profile} = fixture();
  const result = compareCapture(capture(packets), profile);
  assert.equal(result.chrome_to_rust.packets, 1);
  assert.equal(result.rust_to_chrome.packets, 3);
  assert.equal(result.rust_to_chrome.frame_number_wraps, 1);
  assert.equal(result.rust_to_chrome.extension_profiles['0x100f'], 3);
  assert.equal(result.chrome_to_rust.extension_profiles['0xbede'], 1);
});

test('RTP demultiplexing ignores STUN, DTLS and SR/RR RTCP', () => {
  for (const data of [Buffer.alloc(20), Buffer.from([22, 254, 253]), Buffer.from([128, 200])]) {
    assert.equal(readRtp(data), null);
  }
});

test('mandatory DD decoding exposes template ID, boundary flags, frame number and structure flag', () => {
  assert.deepEqual(readDd(Buffer.from('c5ffff80', 'hex')), {
    first: true, last: true, template_id: 5, frame_number: 65535, structure: true,
  });
  assert.throws(() => readDd(Buffer.alloc(2)), /Truncated/);
});

test('truncated and malformed PCAPNG blocks fail explicitly', () => {
  const {packets} = fixture();
  const bytes = capture(packets);
  for (const end of [0, 10, 25, bytes.length - 1]) {
    assert.throws(() => readCapture(bytes.subarray(0, end)));
  }
  bytes.writeUInt32LE(0, 4);
  assert.throws(() => readCapture(bytes), /block length/);
});

test('truncated or duplicate RTP extensions fail explicitly', () => {
  const {packets} = fixture();
  assert.throws(() => readRtp(packets[0].subarray(0, 21)), /extension block/);
  const bytes = Buffer.from(packets[0]);
  bytes[25] = 0xd0;
  bytes[26] = 0;
  assert.throws(() => readRtp(bytes), /Duplicate/);
});

test('changed wire DD, marker, sequence, timestamp, missing and extra packets are rejected', () => {
  for (const [offset, mask] of [[20, 1], [1, 128], [3, 1], [7, 1]]) {
    const {packets, profile} = fixture();
    packets[1][offset] ^= mask;
    assert.throws(() => compareCapture(capture(packets), profile), /mismatch|DD/);
  }
  const {packets, profile} = fixture();
  assert.throws(() => compareCapture(capture(packets.slice(0, -1)), profile), /missing captured/);
  assert.throws(() => compareCapture(capture([...packets, packets[3]]), profile), /extra media/);
});

test('invalid frame grouping fails even when the supplied profile agrees with mutated bytes', () => {
  const {packets, profile} = fixture();
  profile.rust_to_chrome[1].timestamp++;
  packets[2].writeUInt32BE(profile.rust_to_chrome[1].timestamp, 4);
  assert.throws(() => compareCapture(capture(packets), profile), /timestamp changed inside frame/);
});

test('incorrect negotiation and stale runtime summaries are rejected', () => {
  const {packets, profile} = fixture();
  profile.report.rust_to_chrome.packets++;
  assert.throws(() => compareCapture(capture(packets), profile), /differs from runtime summary/);
  profile.dd_extension_id = 12;
  assert.throws(() => compareCapture(capture(packets), profile), /missing negotiated DD/);
});

test('padding classification cannot conceal a missing expected media descriptor', () => {
  const {packets, profile} = fixture();
  packets[0][0] |= 0x20;
  packets[0][20] = 0xc3;
  assert.throws(() => compareCapture(capture(packets), profile), /missing captured media/);
});
