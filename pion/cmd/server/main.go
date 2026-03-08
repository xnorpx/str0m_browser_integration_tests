// Pion WebRTC signaling server – speaks the same WebSocket protocol as the str0m server.
// Accepts sessions, exchanges SDP, runs data channel echo.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/transport/v4/stdnet"
	"github.com/pion/webrtc/v4"

	"str0m-pion-interop/pcap"
	"str0m-pion-interop/protocol"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type session struct {
	config protocol.SessionConfig
	pc     *webrtc.PeerConnection
	cancel chan struct{}
}

type server struct {
	mu       sync.Mutex
	sessions map[string]*session
	advAddr  string
	pcapDir  string
	recorder *pcap.Recorder
	capNet   *pcap.CaptureNet
}

func main() {
	wsPort := flag.Int("ws-port", 9091, "WebSocket port for signaling")
	advAddr := flag.String("adv-addr", "", "Advertised IP address (auto-detect if empty)")
	pcapDir := flag.String("pcap-dir", "target/pcap", "Directory for pcap captures (empty to disable)")
	flag.Parse()

	if *advAddr == "" {
		detected, err := detectPublicIP()
		if err != nil {
			log.Fatalf("Failed to detect public IP: %v", err)
		}
		*advAddr = detected
	}

	// Create a capturing network wrapper for pcap
	recorder := pcap.NewRecorder()
	stdNet, err := stdnet.NewNet()
	if err != nil {
		log.Fatalf("Failed to create stdnet: %v", err)
	}
	capNet := pcap.NewCaptureNet(stdNet, recorder)

	srv := &server{
		sessions: make(map[string]*session),
		advAddr:  *advAddr,
		pcapDir:  *pcapDir,
		recorder: recorder,
		capNet:   capNet,
	}

	// Save pcap on shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		srv.savePcap("pion_server")
		os.Exit(0)
	}()

	http.HandleFunc("/", srv.handleWS)

	addr := fmt.Sprintf("0.0.0.0:%d", *wsPort)
	fmt.Printf("SERVER READY ws://%s:%d\n", *advAddr, *wsPort)
	log.Printf("Pion signaling server listening on %s", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func (s *server) handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("WebSocket upgrade failed: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("New WebSocket connection from %s", r.RemoteAddr)

	for {
		_, message, err := conn.ReadMessage()
		if err != nil {
			if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				log.Printf("Connection closed normally")
			} else {
				log.Printf("Read error: %v", err)
			}
			return
		}

		responses := s.handleMessage(message)
		for _, resp := range responses {
			data, err := json.Marshal(resp)
			if err != nil {
				log.Printf("Failed to marshal response: %v", err)
				continue
			}
			if err := conn.WriteMessage(websocket.TextMessage, data); err != nil {
				log.Printf("Write error: %v", err)
				return
			}
		}
	}
}

func (s *server) handleMessage(raw []byte) []protocol.ServerMessage {
	var msg protocol.ClientMessage
	if err := json.Unmarshal(raw, &msg); err != nil {
		log.Printf("Failed to parse client message: %v", err)
		return []protocol.ServerMessage{{
			Type:    "error",
			Message: fmt.Sprintf("Invalid message: %v", err),
		}}
	}

	switch msg.Type {
	case "create":
		return s.handleCreate(msg)
	case "sdp":
		return s.handleSdp(msg)
	case "ready":
		return s.handleReady(msg)
	case "destroy":
		return s.handleDestroy(msg)
	default:
		return []protocol.ServerMessage{{
			Type:      "error",
			SessionID: &msg.SessionID,
			Message:   fmt.Sprintf("Unknown message type: %s", msg.Type),
		}}
	}
}

func (s *server) handleCreate(msg protocol.ClientMessage) []protocol.ServerMessage {
	log.Printf("Creating session %s with config %+v", msg.SessionID, msg.Config)

	config := *msg.Config

	// Create a PeerConnection API with specific settings
	settingEngine := webrtc.SettingEngine{}

	// ICE lite mode
	if config.ServerIceMode == protocol.IceModeLite {
		settingEngine.SetLite(true)
	}

	// Use capturing network for pcap
	settingEngine.SetNet(s.capNet)

	// Create the API with our settings
	api := webrtc.NewAPI(webrtc.WithSettingEngine(settingEngine))

	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return []protocol.ServerMessage{{
			Type:      "error",
			SessionID: &msg.SessionID,
			Message:   fmt.Sprintf("Failed to create peer connection: %v", err),
		}}
	}

	sess := &session{
		config: config,
		pc:     pc,
		cancel: make(chan struct{}),
	}

	// Set up data channel echo handler
	pc.OnDataChannel(func(dc *webrtc.DataChannel) {
		log.Printf("[%s] DataChannel opened: %s", msg.SessionID, dc.Label())
		dc.OnOpen(func() {
			log.Printf("[%s] DataChannel '%s' is open, sending ready beacon", msg.SessionID, dc.Label())
			if err := dc.SendText("ready"); err != nil {
				log.Printf("[%s] Failed to send ready beacon: %v", msg.SessionID, err)
			}
		})
		dc.OnMessage(func(m webrtc.DataChannelMessage) {
			text := string(m.Data)
			log.Printf("[%s] Received: %s (%d bytes, binary=%v)", msg.SessionID, text, len(m.Data), m.IsString)
			// Echo it back
			if m.IsString {
				if err := dc.SendText(text); err != nil {
					log.Printf("[%s] Echo send failed: %v", msg.SessionID, err)
				}
			} else {
				if err := dc.Send(m.Data); err != nil {
					log.Printf("[%s] Echo send failed: %v", msg.SessionID, err)
				}
			}
		})
	})

	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		log.Printf("[%s] ICE connection state: %s", msg.SessionID, state.String())
	})

	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		log.Printf("[%s] Connection state: %s", msg.SessionID, state.String())
	})

	s.mu.Lock()
	s.sessions[msg.SessionID] = sess
	s.mu.Unlock()

	responses := []protocol.ServerMessage{{
		Type:      "created",
		SessionID: &msg.SessionID,
	}}

	// If client is answerer, server creates the offer
	if config.ClientSdpRole == protocol.SdpRoleAnswerer {
		// Create a data channel since server is offering
		dc, err := pc.CreateDataChannel("test-data", nil)
		if err != nil {
			return []protocol.ServerMessage{{
				Type:      "error",
				SessionID: &msg.SessionID,
				Message:   fmt.Sprintf("Failed to create data channel: %v", err),
			}}
		}

		dc.OnOpen(func() {
			log.Printf("[%s] Server-created DataChannel '%s' is open, sending ready beacon", msg.SessionID, dc.Label())
			if err := dc.SendText("ready"); err != nil {
				log.Printf("[%s] Failed to send ready beacon: %v", msg.SessionID, err)
			}
		})
		dc.OnMessage(func(m webrtc.DataChannelMessage) {
			text := string(m.Data)
			log.Printf("[%s] Received on server DC: %s", msg.SessionID, text)
			if m.IsString {
				if err := dc.SendText(text); err != nil {
					log.Printf("[%s] Echo send failed: %v", msg.SessionID, err)
				}
			} else {
				if err := dc.Send(m.Data); err != nil {
					log.Printf("[%s] Echo send failed: %v", msg.SessionID, err)
				}
			}
		})

		offer, err := pc.CreateOffer(nil)
		if err != nil {
			return []protocol.ServerMessage{{
				Type:      "error",
				SessionID: &msg.SessionID,
				Message:   fmt.Sprintf("Failed to create offer: %v", err),
			}}
		}

		if err := pc.SetLocalDescription(offer); err != nil {
			return []protocol.ServerMessage{{
				Type:      "error",
				SessionID: &msg.SessionID,
				Message:   fmt.Sprintf("Failed to set local description: %v", err),
			}}
		}

		// Wait for ICE gathering to complete
		<-webrtc.GatheringCompletePromise(pc)

		sdp := pc.LocalDescription().SDP
		responses = append(responses, protocol.ServerMessage{
			Type:      "sdp",
			SessionID: &msg.SessionID,
			Sdp:       sdp,
		})
	}

	return responses
}

func (s *server) handleSdp(msg protocol.ClientMessage) []protocol.ServerMessage {
	s.mu.Lock()
	sess, ok := s.sessions[msg.SessionID]
	s.mu.Unlock()

	if !ok {
		return []protocol.ServerMessage{{
			Type:      "error",
			SessionID: &msg.SessionID,
			Message:   "Session not found",
		}}
	}

	if sess.config.ClientSdpRole == protocol.SdpRoleOfferer {
		// Client sent an offer, we create an answer
		offer := webrtc.SessionDescription{
			Type: webrtc.SDPTypeOffer,
			SDP:  msg.Sdp,
		}

		if err := sess.pc.SetRemoteDescription(offer); err != nil {
			return []protocol.ServerMessage{{
				Type:      "error",
				SessionID: &msg.SessionID,
				Message:   fmt.Sprintf("Failed to set remote description: %v", err),
			}}
		}

		answer, err := sess.pc.CreateAnswer(nil)
		if err != nil {
			return []protocol.ServerMessage{{
				Type:      "error",
				SessionID: &msg.SessionID,
				Message:   fmt.Sprintf("Failed to create answer: %v", err),
			}}
		}

		if err := sess.pc.SetLocalDescription(answer); err != nil {
			return []protocol.ServerMessage{{
				Type:      "error",
				SessionID: &msg.SessionID,
				Message:   fmt.Sprintf("Failed to set local description: %v", err),
			}}
		}

		// Wait for ICE gathering to complete
		<-webrtc.GatheringCompletePromise(sess.pc)

		sdp := sess.pc.LocalDescription().SDP
		return []protocol.ServerMessage{{
			Type:      "sdp",
			SessionID: &msg.SessionID,
			Sdp:       sdp,
		}}
	}

	// Client sent an answer
	answer := webrtc.SessionDescription{
		Type: webrtc.SDPTypeAnswer,
		SDP:  msg.Sdp,
	}

	if err := sess.pc.SetRemoteDescription(answer); err != nil {
		return []protocol.ServerMessage{{
			Type:      "error",
			SessionID: &msg.SessionID,
			Message:   fmt.Sprintf("Failed to set remote description: %v", err),
		}}
	}

	return nil
}

func (s *server) handleReady(msg protocol.ClientMessage) []protocol.ServerMessage {
	log.Printf("Session %s: client signaling complete", msg.SessionID)
	return []protocol.ServerMessage{{
		Type:      "ready",
		SessionID: &msg.SessionID,
	}}
}

func (s *server) handleDestroy(msg protocol.ClientMessage) []protocol.ServerMessage {
	log.Printf("Destroying session %s", msg.SessionID)

	s.mu.Lock()
	sess, ok := s.sessions[msg.SessionID]
	if ok {
		delete(s.sessions, msg.SessionID)
	}
	s.mu.Unlock()

	if ok {
		close(sess.cancel)
		// Close PeerConnection with timeout to avoid hanging
		closeDone := make(chan struct{})
		go func() {
			sess.pc.Close()
			close(closeDone)
		}()
		select {
		case <-closeDone:
		case <-time.After(3 * time.Second):
			log.Printf("[%s] Warning: pc.Close() timed out", msg.SessionID)
		}
	}

	// Save pcap snapshot for this session
	s.savePcap(msg.SessionID + "_pion_server")

	return []protocol.ServerMessage{{
		Type:      "destroyed",
		SessionID: &msg.SessionID,
	}}
}

func (s *server) savePcap(name string) {
	if s.pcapDir == "" || s.recorder == nil {
		return
	}
	filename := filepath.Join(s.pcapDir, name+".pcapng")
	if err := s.recorder.Save(filename); err != nil {
		log.Printf("Failed to save pcap %s: %v", filename, err)
	} else {
		log.Printf("Pcap saved: %s (%d packets)", filename, s.recorder.Count())
	}
}

func detectPublicIP() (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		ipNet, ok := addr.(*net.IPNet)
		if !ok || ipNet.IP.IsLoopback() {
			continue
		}
		if ipNet.IP.To4() != nil {
			return ipNet.IP.String(), nil
		}
	}

	return "127.0.0.1", nil
}
