// Pion WebRTC client – connects to a str0m (or pion) signaling server and runs a data channel echo test.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/transport/v4/stdnet"
	"github.com/pion/webrtc/v4"

	"str0m-pion-interop/pcap"
	"str0m-pion-interop/protocol"
)

func main() {
	wsURL := flag.String("ws-url", "ws://127.0.0.1:9090", "WebSocket URL of the signaling server")
	sessionID := flag.String("session-id", "pion-client", "Session ID")
	sdpRole := flag.String("sdp-role", "offerer", "SDP role: offerer or answerer")
	iceMode := flag.String("ice-mode", "full", "Server ICE mode: full or lite")
	dtlsRole := flag.String("dtls-role", "active", "Client DTLS role: active, passive, or auto")
	timeout := flag.Duration("timeout", 30*time.Second, "Test timeout")
	message := flag.String("message", "hello from pion client!", "Message to send")
	pcapDir := flag.String("pcap-dir", "target/pcap", "Directory for pcap captures (empty to disable)")
	flag.Parse()

	done := make(chan error, 1)
	go func() {
		done <- runClient(*wsURL, *sessionID, *sdpRole, *iceMode, *dtlsRole, *message, *pcapDir)
	}()

	select {
	case err := <-done:
		if err != nil {
			fmt.Fprintf(os.Stderr, "CLIENT FAIL: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("CLIENT OK")
	case <-time.After(*timeout):
		fmt.Fprintf(os.Stderr, "CLIENT FAIL: timeout after %s\n", *timeout)
		os.Exit(1)
	}
}

func runClient(wsURL, sessionID, sdpRole, iceMode, dtlsRole, message, pcapDir string) error {
	config := protocol.SessionConfig{
		ClientSdpRole:  protocol.SdpRole(sdpRole),
		ServerIceMode:  protocol.IceMode(iceMode),
		ClientDtlsRole: protocol.DtlsRole(dtlsRole),
	}

	log.Printf("Connecting to %s, session=%s, config=%+v", wsURL, sessionID, config)

	conn, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		return fmt.Errorf("websocket connect: %w", err)
	}
	defer conn.Close()

	// Create session
	if err := sendMsg(conn, protocol.ClientMessage{
		Type:      "create",
		SessionID: sessionID,
		Config:    &config,
	}); err != nil {
		return fmt.Errorf("send create: %w", err)
	}

	msg, err := recvMsg(conn)
	if err != nil {
		return fmt.Errorf("recv created: %w", err)
	}
	if msg.Type == "error" {
		return fmt.Errorf("server error: %s", msg.Message)
	}
	if msg.Type != "created" {
		return fmt.Errorf("expected created, got %s", msg.Type)
	}

	// Create capturing network for pcap
	recorder := pcap.NewRecorder()
	stdNet, err := stdnet.NewNet()
	if err != nil {
		return fmt.Errorf("create stdnet: %w", err)
	}
	capNet := pcap.NewCaptureNet(stdNet, recorder)

	se := webrtc.SettingEngine{}
	se.SetNet(capNet)
	api := webrtc.NewAPI(webrtc.WithSettingEngine(se))

	// Create PeerConnection
	pc, err := api.NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		return fmt.Errorf("create peer connection: %w", err)
	}

	pc.OnICEConnectionStateChange(func(state webrtc.ICEConnectionState) {
		log.Printf("ICE connection state: %s", state.String())
	})
	pc.OnConnectionStateChange(func(state webrtc.PeerConnectionState) {
		log.Printf("Connection state: %s", state.String())
	})

	echoResult := make(chan time.Duration, 1)
	echoFail := make(chan error, 1)

	setupDataChannelHandler := func(dc *webrtc.DataChannel) {
		dc.OnOpen(func() {
			log.Printf("DataChannel '%s' open, sending message: %s", dc.Label(), message)
			if err := dc.SendText(message); err != nil {
				echoFail <- fmt.Errorf("send message: %w", err)
			}
		})

		sendTime := time.Now()
		dc.OnMessage(func(m webrtc.DataChannelMessage) {
			text := string(m.Data)
			log.Printf("Received: %s", text)
			if text == message {
				rtt := time.Since(sendTime)
				log.Printf("Echo matched! RTT: %s", rtt)
				select {
				case echoResult <- rtt:
				default:
				}
			} else if text == "ready" {
				// Server sends ready beacon, now send our message
				log.Printf("Got ready beacon, sending message: %s", message)
				sendTime = time.Now()
				if err := dc.SendText(message); err != nil {
					echoFail <- fmt.Errorf("send message after ready: %w", err)
				}
			}
		})
	}

	if sdpRole == "offerer" {
		// Client is offerer: create data channel and offer
		dc, err := pc.CreateDataChannel("test-data", nil)
		if err != nil {
			return fmt.Errorf("create data channel: %w", err)
		}
		setupDataChannelHandler(dc)

		offer, err := pc.CreateOffer(nil)
		if err != nil {
			return fmt.Errorf("create offer: %w", err)
		}
		if err := pc.SetLocalDescription(offer); err != nil {
			return fmt.Errorf("set local description: %w", err)
		}

		// Wait for ICE gathering
		<-webrtc.GatheringCompletePromise(pc)

		sdp := pc.LocalDescription().SDP
		log.Printf("Sending offer (%d bytes)", len(sdp))

		if err := sendMsg(conn, protocol.ClientMessage{
			Type:      "sdp",
			SessionID: sessionID,
			Sdp:       sdp,
		}); err != nil {
			return fmt.Errorf("send offer: %w", err)
		}

		msg, err := recvMsg(conn)
		if err != nil {
			return fmt.Errorf("recv answer: %w", err)
		}
		if msg.Type == "error" {
			return fmt.Errorf("server error: %s", msg.Message)
		}
		if msg.Type != "sdp" {
			return fmt.Errorf("expected sdp, got %s", msg.Type)
		}

		answer := webrtc.SessionDescription{
			Type: webrtc.SDPTypeAnswer,
			SDP:  msg.Sdp,
		}
		if err := pc.SetRemoteDescription(answer); err != nil {
			return fmt.Errorf("set remote description: %w", err)
		}
	} else {
		// Client is answerer: wait for offer from server
		pc.OnDataChannel(func(dc *webrtc.DataChannel) {
			log.Printf("DataChannel received: %s", dc.Label())
			setupDataChannelHandler(dc)
		})

		msg, err := recvMsg(conn)
		if err != nil {
			return fmt.Errorf("recv offer: %w", err)
		}
		if msg.Type == "error" {
			return fmt.Errorf("server error: %s", msg.Message)
		}
		if msg.Type != "sdp" {
			return fmt.Errorf("expected sdp, got %s", msg.Type)
		}

		offer := webrtc.SessionDescription{
			Type: webrtc.SDPTypeOffer,
			SDP:  msg.Sdp,
		}
		if err := pc.SetRemoteDescription(offer); err != nil {
			return fmt.Errorf("set remote description: %w", err)
		}

		answer, err := pc.CreateAnswer(nil)
		if err != nil {
			return fmt.Errorf("create answer: %w", err)
		}
		if err := pc.SetLocalDescription(answer); err != nil {
			return fmt.Errorf("set local description: %w", err)
		}

		// Wait for ICE gathering
		<-webrtc.GatheringCompletePromise(pc)

		sdp := pc.LocalDescription().SDP
		log.Printf("Sending answer (%d bytes)", len(sdp))

		if err := sendMsg(conn, protocol.ClientMessage{
			Type:      "sdp",
			SessionID: sessionID,
			Sdp:       sdp,
		}); err != nil {
			return fmt.Errorf("send answer: %w", err)
		}
	}

	// Signal ready
	if err := sendMsg(conn, protocol.ClientMessage{
		Type:      "ready",
		SessionID: sessionID,
	}); err != nil {
		return fmt.Errorf("send ready: %w", err)
	}

	msg, err = recvMsg(conn)
	if err != nil {
		return fmt.Errorf("recv ready: %w", err)
	}
	if msg.Type == "error" {
		return fmt.Errorf("server error: %s", msg.Message)
	}
	if msg.Type != "ready" {
		return fmt.Errorf("expected ready, got %s", msg.Type)
	}

	// Wait for echo
	log.Printf("Waiting for echo...")
	select {
	case rtt := <-echoResult:
		log.Printf("Echo verified, RTT: %s", rtt)
	case err := <-echoFail:
		return fmt.Errorf("echo failed: %w", err)
	case <-time.After(15 * time.Second):
		return fmt.Errorf("echo timeout")
	}

	// Destroy session
	if err := sendMsg(conn, protocol.ClientMessage{
		Type:      "destroy",
		SessionID: sessionID,
	}); err != nil {
		return fmt.Errorf("send destroy: %w", err)
	}

	msg, err = recvMsg(conn)
	if err != nil {
		return fmt.Errorf("recv destroyed: %w", err)
	}
	if msg.Type != "destroyed" {
		return fmt.Errorf("expected destroyed, got %s", msg.Type)
	}

	// Save pcap before closing (captures full session)
	if pcapDir != "" {
		filename := filepath.Join(pcapDir, sessionID+"_pion_client.pcapng")
		if err := recorder.Save(filename); err != nil {
			log.Printf("Failed to save pcap: %v", err)
		} else {
			log.Printf("Pcap saved: %s (%d packets)", filename, recorder.Count())
		}
	}

	// Close PeerConnection with timeout to avoid hanging
	closeDone := make(chan struct{})
	go func() {
		pc.Close()
		close(closeDone)
	}()
	select {
	case <-closeDone:
	case <-time.After(3 * time.Second):
		log.Printf("Warning: pc.Close() timed out")
	}

	log.Printf("Test passed!")
	return nil
}

func sendMsg(conn *websocket.Conn, msg protocol.ClientMessage) error {
	data, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	log.Printf("-> %s", string(data))
	return conn.WriteMessage(websocket.TextMessage, data)
}

func recvMsg(conn *websocket.Conn) (protocol.ServerMessage, error) {
	_, data, err := conn.ReadMessage()
	if err != nil {
		return protocol.ServerMessage{}, err
	}
	log.Printf("<- %s", string(data))
	var msg protocol.ServerMessage
	return msg, json.Unmarshal(data, &msg)
}
