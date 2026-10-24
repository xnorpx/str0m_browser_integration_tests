package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"

	dd "github.com/livekit/livekit-server/pkg/sfu/rtpextension/dependencydescriptor"
	"github.com/pion/rtp"
	"github.com/pion/webrtc/v5"
)

const ddURI = "https://aomediacodec.github.io/av1-rtp-spec/#dependency-descriptor-rtp-header-extension"

type DDVideoPacket struct {
	SSRC        uint32                   `json:"ssrc"`
	PayloadType uint8                    `json:"payload_type"`
	Sequence    uint16                   `json:"sequence"`
	Timestamp   uint32                   `json:"timestamp"`
	Marker      bool                     `json:"marker"`
	DDHex       string                   `json:"dd_hex"`
	Descriptor  *dd.DependencyDescriptor `json:"descriptor"`
}

type DDVideoReport struct {
	Parser               string          `json:"parser"`
	ExtensionID          uint8           `json:"extension_id"`
	Frames               int             `json:"frames"`
	Structures           int             `json:"structures"`
	FrameNumberWraps     int             `json:"frame_number_wraps"`
	SinglePacketFrames   int             `json:"single_packet_frames"`
	MultiPacketFrames    int             `json:"multi_packet_frames"`
	MiddlePackets        int             `json:"middle_packets"`
	Roundtrips           int             `json:"semantic_roundtrips"`
	MatchedSourcePackets int             `json:"matched_source_packets"`
	SourceProfile        string          `json:"source_profile,omitempty"`
	Packets              []DDVideoPacket `json:"packets"`
}

type ddVideoResult struct {
	report *DDVideoReport
	err    error
}

type ddVideoReceiver struct {
	report         DDVideoReport
	structure      *dd.FrameDependencyStructure
	inFrame        bool
	timestamp      uint32
	ssrc           uint32
	packetsInFrame int
}

func newDDVideoReceiver(id uint8) *ddVideoReceiver {
	return &ddVideoReceiver{report: DDVideoReport{
		Parser:      "LiveKit v1.9.0 dependencydescriptor (Apache-2.0), over Pion RTP",
		ExtensionID: id,
	}}
}

func (v *ddVideoReceiver) receive(packet *rtp.Packet) error {
	raw := packet.GetExtension(v.report.ExtensionID)
	if len(raw) == 0 {
		return errors.New("AV1 media packet is missing the negotiated DD extension")
	}
	descriptor := &dd.DependencyDescriptor{}
	extension := dd.DependencyDescriptorExtension{Descriptor: descriptor, Structure: v.structure}
	if _, err := extension.Unmarshal(raw); err != nil {
		return fmt.Errorf("LiveKit DD unmarshal: %w", err)
	}
	if descriptor.AttachedStructure != nil {
		v.structure = descriptor.AttachedStructure
		v.report.Structures++
		if !descriptor.FirstPacketInFrame {
			return errors.New("shared structure attached to a continuation packet")
		}
	}
	if v.structure == nil || v.structure.NumDecodeTargets != 1 || v.structure.NumChains != 0 ||
		len(v.structure.Templates) != 2 {
		return errors.New("unexpected or missing str0m L1T1 shared structure")
	}
	index := v.report.Frames
	if index >= 32 || descriptor.FrameNumber != uint16((65530+index)%65536) {
		return fmt.Errorf("unexpected DD frame number %d at frame index %d", descriptor.FrameNumber, index)
	}
	keyframe := index == 0 || index == 16
	dependencies := descriptor.FrameDependencies
	if dependencies == nil || dependencies.SpatialId != 0 || dependencies.TemporalId != 0 {
		return errors.New("invalid L1T1 frame dependency template")
	}
	wantDTI := dd.DecodeTargetRequired
	var wantDiffs []int
	if keyframe {
		wantDTI = dd.DecodeTargetSwitch
	} else {
		wantDiffs = []int{1}
	}
	if len(dependencies.DecodeTargetIndications) != 1 ||
		dependencies.DecodeTargetIndications[0] != wantDTI ||
		!equalDiffs(dependencies.FrameDiffs, wantDiffs) ||
		len(dependencies.ChainDiffs) != 0 {
		return fmt.Errorf("incorrect dependency semantics on frame %d: %+v", index, dependencies)
	}
	if descriptor.LastPacketInFrame != packet.Marker {
		return errors.New("DD last-packet flag differs from RTP marker")
	}
	if descriptor.FirstPacketInFrame {
		if v.inFrame {
			return errors.New("new DD frame before previous frame ended")
		}
		if (descriptor.AttachedStructure != nil) != keyframe {
			return errors.New("shared structures must appear exactly on keyframe first packets")
		}
		if descriptor.FrameNumber == 0 {
			v.report.FrameNumberWraps++
		}
		v.inFrame, v.timestamp, v.ssrc, v.packetsInFrame = true, packet.Timestamp, packet.SSRC, 0
	}
	if !v.inFrame || v.timestamp != packet.Timestamp || v.ssrc != packet.SSRC {
		return errors.New("invalid frame boundary, timestamp or SSRC")
	}
	// Independent semantic roundtrip; canonical serialization need not preserve
	// the original template choice or redundant optional fields byte-for-byte.
	extension.Structure = v.structure
	encoded, err := extension.Marshal()
	if err != nil {
		return fmt.Errorf("LiveKit DD marshal: %w", err)
	}
	again := &dd.DependencyDescriptor{}
	reparsed := dd.DependencyDescriptorExtension{Descriptor: again, Structure: v.structure}
	if _, err := reparsed.Unmarshal(encoded); err != nil {
		return fmt.Errorf("LiveKit DD reparse: %w", err)
	}
	if !reflect.DeepEqual(descriptor, again) {
		return errors.New("LiveKit DD roundtrip changed descriptor semantics")
	}
	v.report.Roundtrips++
	v.report.Packets = append(v.report.Packets, DDVideoPacket{
		SSRC: packet.SSRC, PayloadType: packet.PayloadType, Sequence: packet.SequenceNumber,
		Timestamp: packet.Timestamp, Marker: packet.Marker, DDHex: hex.EncodeToString(raw),
		Descriptor: descriptor,
	})
	v.packetsInFrame++
	if !descriptor.FirstPacketInFrame && !descriptor.LastPacketInFrame {
		v.report.MiddlePackets++
	}
	if descriptor.LastPacketInFrame {
		v.inFrame = false
		v.report.Frames++
		if v.packetsInFrame == 1 {
			v.report.SinglePacketFrames++
		} else {
			v.report.MultiPacketFrames++
		}
	}
	return nil
}

func equalDiffs(a, b []int) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func attachDDVideo(pc *webrtc.PeerConnection) (<-chan ddVideoResult, error) {
	// A bound, unsent local track negotiates sendrecv, as required by the shared
	// frame-mode harness. This test only receives; it does not encode or decode AV1.
	track, err := webrtc.NewTrackLocalStaticRTP(webrtc.RTPCodecCapability{
		MimeType: webrtc.MimeTypeAV1, ClockRate: 90000,
	}, "av1", "pion-dd")
	if err != nil {
		return nil, err
	}
	if _, err := pc.AddTrack(track); err != nil {
		return nil, err
	}
	done := make(chan ddVideoResult, 1)
	pc.OnTrack(func(track *webrtc.TrackRemote, receiver *webrtc.RTPReceiver) {
		var report *DDVideoReport
		receive := func() error {
			var id uint8
			for _, extension := range receiver.GetParameters().HeaderExtensions {
				if extension.URI == ddURI && extension.ID > 0 && extension.ID <= 255 {
					id = uint8(extension.ID)
				}
			}
			if id == 0 {
				return errors.New("Pion receiver has no negotiated DD extension ID")
			}
			video := newDDVideoReceiver(id)
			report = &video.report
			for video.report.Frames < 32 {
				packet, _, err := track.ReadRTP()
				if err != nil {
					return err
				}
				if !strings.EqualFold(track.Codec().MimeType, webrtc.MimeTypeAV1) {
					return fmt.Errorf("unexpected codec %s", track.Codec().MimeType)
				}
				if len(packet.Payload) == 0 && packet.Padding {
					continue
				}
				if err := video.receive(packet); err != nil {
					return err
				}
			}
			return nil
		}
		err := receive()
		done <- ddVideoResult{report: report, err: err}
	})
	return done, nil
}

func validateVideoReport(video *DDVideoReport, server *SessionReport) error {
	if video == nil || server == nil || server.VideoFrameMode == nil {
		return errors.New("missing Pion/str0m video report")
	}
	sent := server.VideoFrameMode
	if video.Frames != 32 || sent.RustFramesSent != 32 ||
		video.Structures != 2 || video.FrameNumberWraps != 1 ||
		video.SinglePacketFrames == 0 || video.MultiPacketFrames == 0 || video.MiddlePackets == 0 ||
		video.Roundtrips != len(video.Packets) ||
		video.MatchedSourcePackets != len(video.Packets) ||
		uint64(len(video.Packets)) != sent.RustToChrome.Packets ||
		uint64(video.Frames) != sent.RustToChrome.Frames ||
		uint64(video.Structures) != sent.RustToChrome.Structures {
		return fmt.Errorf("incomplete or inconsistent Pion DD video report: frames=%d packets=%d structures=%d",
			video.Frames, len(video.Packets), video.Structures)
	}
	return nil
}

func compareVideoSource(video *DDVideoReport, filename string) error {
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("read str0m DD source profile: %w", err)
	}
	var source struct {
		SchemaVersion int             `json:"schema_version"`
		ExtensionID   uint8           `json:"dd_extension_id"`
		Packets       []DDVideoPacket `json:"rust_to_chrome"`
	}
	if err := json.Unmarshal(data, &source); err != nil {
		return fmt.Errorf("parse str0m DD source profile: %w", err)
	}
	if source.SchemaVersion != 2 || source.ExtensionID != video.ExtensionID ||
		len(source.Packets) != len(video.Packets) || len(source.Packets) == 0 {
		return errors.New("Pion/str0m DD profile schema, negotiation or packet count mismatch")
	}
	for i, expected := range source.Packets {
		received := video.Packets[i]
		received.Descriptor = nil
		if received != expected {
			return fmt.Errorf("Pion/str0m RTP header or DD bytes differ at packet %d (sequence %d)",
				i, received.Sequence)
		}
	}
	video.MatchedSourcePackets = len(source.Packets)
	video.SourceProfile = filename
	return nil
}
