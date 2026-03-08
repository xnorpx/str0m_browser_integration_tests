// Package pcap writes pcapng files compatible with the Rust pcap.rs writer.
// Uses LINKTYPE_RAW (101) with synthetic IPv4/UDP framing.
package pcap

import (
	"encoding/binary"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Packet is a captured UDP packet.
type Packet struct {
	TimestampUS uint64
	Src         net.UDPAddr
	Dst         net.UDPAddr
	Payload     []byte
}

// Recorder collects packets and writes them to a pcapng file.
type Recorder struct {
	mu      sync.Mutex
	packets []Packet
}

// NewRecorder creates a new packet recorder.
func NewRecorder() *Recorder {
	return &Recorder{}
}

// Record adds a packet to the capture buffer.
func (r *Recorder) Record(src, dst net.UDPAddr, payload []byte) {
	buf := make([]byte, len(payload))
	copy(buf, payload)
	r.mu.Lock()
	r.packets = append(r.packets, Packet{
		TimestampUS: uint64(time.Now().UnixMicro()),
		Src:         src,
		Dst:         dst,
		Payload:     buf,
	})
	r.mu.Unlock()
}

// Save writes the accumulated packets to a pcapng file.
func (r *Recorder) Save(filename string) error {
	r.mu.Lock()
	packets := make([]Packet, len(r.packets))
	copy(packets, r.packets)
	r.mu.Unlock()

	if len(packets) == 0 {
		return nil
	}

	if err := os.MkdirAll(filepath.Dir(filename), 0o755); err != nil {
		return err
	}

	data := writePcapng(packets)
	return os.WriteFile(filename, data, 0o644)
}

// Count returns the number of captured packets.
func (r *Recorder) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.packets)
}

func writePcapng(packets []Packet) []byte {
	var buf []byte
	buf = writeSHB(buf)
	buf = writeIDB(buf)
	for i := range packets {
		buf = writeEPB(buf, &packets[i])
	}
	return buf
}

func writeSHB(buf []byte) []byte {
	blockLen := uint32(28)
	buf = putU32(buf, 0x0A0D0D0A) // Block Type
	buf = putU32(buf, blockLen)
	buf = putU32(buf, 0x1A2B3C4D)         // Byte-Order Magic
	buf = putU16(buf, 1)                   // Major Version
	buf = putU16(buf, 0)                   // Minor Version
	buf = putU64(buf, 0xFFFFFFFFFFFFFFFF)  // Section Length (unspecified)
	buf = putU32(buf, blockLen)
	return buf
}

func writeIDB(buf []byte) []byte {
	blockLen := uint32(20)
	buf = putU32(buf, 0x00000001) // Block Type
	buf = putU32(buf, blockLen)
	buf = putU16(buf, 101)        // LinkType: LINKTYPE_RAW
	buf = putU16(buf, 0)          // Reserved
	buf = putU32(buf, 0x0000FFFF) // SnapLen
	buf = putU32(buf, blockLen)
	return buf
}

func writeEPB(buf []byte, pkt *Packet) []byte {
	frame := buildIPv4UDPFrame(pkt)
	capturedLen := uint32(len(frame))
	paddedLen := (capturedLen + 3) & ^uint32(3)
	blockLen := 32 + paddedLen

	tsHigh := uint32(pkt.TimestampUS >> 32)
	tsLow := uint32(pkt.TimestampUS & 0xFFFFFFFF)

	buf = putU32(buf, 0x00000006) // Block Type: EPB
	buf = putU32(buf, blockLen)
	buf = putU32(buf, 0) // Interface ID
	buf = putU32(buf, tsHigh)
	buf = putU32(buf, tsLow)
	buf = putU32(buf, capturedLen)
	buf = putU32(buf, capturedLen) // Original Packet Length
	buf = append(buf, frame...)

	padding := paddedLen - capturedLen
	for i := uint32(0); i < padding; i++ {
		buf = append(buf, 0)
	}

	buf = putU32(buf, blockLen)
	return buf
}

func buildIPv4UDPFrame(pkt *Packet) []byte {
	payloadLen := len(pkt.Payload)
	udpLen := 8 + payloadLen
	ipTotalLen := 20 + udpLen

	srcIP := pkt.Src.IP.To4()
	dstIP := pkt.Dst.IP.To4()
	if srcIP == nil {
		srcIP = net.IPv4zero.To4()
	}
	if dstIP == nil {
		dstIP = net.IPv4zero.To4()
	}

	frame := make([]byte, 0, ipTotalLen)

	// IPv4 header
	frame = append(frame, 0x45)                                      // Version + IHL
	frame = append(frame, 0x00)                                      // DSCP + ECN
	frame = append(frame, byte(ipTotalLen>>8), byte(ipTotalLen))     // Total Length
	frame = append(frame, 0, 0)                                      // Identification
	frame = append(frame, 0x40, 0x00)                                // Flags (DF) + Fragment Offset
	frame = append(frame, 64)                                        // TTL
	frame = append(frame, 17)                                        // Protocol: UDP
	checksumOffset := len(frame)
	frame = append(frame, 0, 0)                                      // Header Checksum (placeholder)
	frame = append(frame, srcIP...)
	frame = append(frame, dstIP...)

	// Compute IP checksum
	cs := ipChecksum(frame[:20])
	frame[checksumOffset] = byte(cs >> 8)
	frame[checksumOffset+1] = byte(cs)

	// UDP header
	frame = append(frame, byte(pkt.Src.Port>>8), byte(pkt.Src.Port))
	frame = append(frame, byte(pkt.Dst.Port>>8), byte(pkt.Dst.Port))
	frame = append(frame, byte(udpLen>>8), byte(udpLen))
	frame = append(frame, 0, 0) // UDP checksum (skip)

	// Payload
	frame = append(frame, pkt.Payload...)

	return frame
}

func ipChecksum(header []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(header); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}

func putU16(buf []byte, v uint16) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, v)
	return append(buf, b...)
}

func putU32(buf []byte, v uint32) []byte {
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, v)
	return append(buf, b...)
}

func putU64(buf []byte, v uint64) []byte {
	b := make([]byte, 8)
	binary.LittleEndian.PutUint64(b, v)
	return append(buf, b...)
}
