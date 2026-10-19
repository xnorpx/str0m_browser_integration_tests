package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/pion/dtls/v4/pkg/protocol"
	"github.com/pion/ice/v5"
	"github.com/pion/logging"
	"github.com/pion/webrtc/v5"
)

const (
	pingMessage   = "hello from pion!"
	signalTimeout = 10 * time.Second
)

// Result is the outcome of one case.
type Result struct {
	Case
	Expect Expectation `json:"expect"`
	// Status is pass, fail, skip or xfail (failed the way a known upstream issue does).
	Status     string `json:"status"`
	Reason     string `json:"reason,omitempty"`
	KnownIssue string `json:"known_issue,omitempty"`

	Opened         bool    `json:"opened"`
	Echoed         bool    `json:"echoed"`
	PionDtls       string  `json:"pion_dtls_negotiated,omitempty"`
	Str0mDtls      string  `json:"str0m_dtls_negotiated,omitempty"`
	PionDtlsError  string  `json:"pion_dtls_error,omitempty"`
	SnapNegotiated bool    `json:"snap_negotiated"`
	OpenMs         float64 `json:"open_ms,omitempty"`
	EchoMs         float64 `json:"echo_ms,omitempty"`
	PionState      string  `json:"pion_state,omitempty"`
	DurationMs     float64 `json:"duration_ms"`
	LogFile        string  `json:"log_file,omitempty"`

	Str0m *SessionReport `json:"str0m,omitempty"`
}

type runEnv struct {
	wsURL         string
	info          ServerInfo
	logDir        string
	logLevel      logging.LogLevel
	keepLogs      bool
	openTimeout   time.Duration
	netemTimeout  time.Duration
	rejectTimeout time.Duration
}

func (e *runEnv) openTimeoutFor(c Case, exp Expectation) time.Duration {
	switch {
	case !exp.Connect:
		return e.rejectTimeout
	case c.Netem != "":
		return e.netemTimeout
	default:
		return e.openTimeout
	}
}

func msSince(t time.Time) float64 { return float64(time.Since(t).Microseconds()) / 1000 }

// signaling is a minimal client for the server's JSON-over-WebSocket protocol.
type signaling struct {
	conn *websocket.Conn
	sid  string
}

func (s *signaling) send(msg ClientMessage) error {
	msg.SessionID = s.sid
	_ = s.conn.SetWriteDeadline(time.Now().Add(signalTimeout))
	return s.conn.WriteJSON(msg)
}

func (s *signaling) recv(want string) (ServerMessage, error) {
	var msg ServerMessage
	_ = s.conn.SetReadDeadline(time.Now().Add(signalTimeout))
	if err := s.conn.ReadJSON(&msg); err != nil {
		return msg, fmt.Errorf("waiting for %q: %w", want, err)
	}
	if msg.Type == "error" {
		return msg, fmt.Errorf("server error while waiting for %q: %s", want, msg.Message)
	}
	if msg.Type != want {
		return msg, fmt.Errorf("expected %q, got %q", want, msg.Type)
	}
	return msg, nil
}

// observation is what the Pion side saw.
type observation struct {
	opened    bool
	echoed    bool
	openMs    float64
	echoMs    float64
	pionDtls  string
	snap      bool
	state     webrtc.PeerConnectionState
	setupErr  error
	failure   string
	holdError string
	pionError string
}

func runCase(c Case, exp Expectation, env *runEnv) (res Result) {
	start := time.Now()
	res = Result{Case: c, Expect: exp}
	defer func() { res.DurationMs = msSince(start) }()

	if exp.Skip != "" {
		res.Status, res.Reason = "skip", exp.Skip
		return res
	}

	logPath := filepath.Join(env.logDir, c.Name+".log")
	logFile, err := os.Create(logPath)
	if err != nil {
		res.Status, res.Reason = "fail", err.Error()
		return res
	}
	logs := &caseLog{w: logFile}
	defer func() {
		logs.close()
		if res.Status == "pass" && res.KnownIssue == "" && !env.keepLogs {
			_ = os.Remove(logPath)
		} else {
			res.LogFile = logPath
		}
	}()
	logs.printf("case %s: expect %+v", c.Name, exp)

	conn, _, err := websocket.DefaultDialer.Dial(env.wsURL, nil)
	if err != nil {
		res.Status, res.Reason = "fail", "signaling: "+err.Error()
		return res
	}
	defer conn.Close()
	sig := &signaling{conn: conn, sid: c.Name}

	cfg := c.sessionConfig()
	if err := sig.send(ClientMessage{Type: "create", Config: &cfg}); err != nil {
		res.Status, res.Reason = "fail", "signaling: "+err.Error()
		return res
	}
	if _, err := sig.recv("created"); err != nil {
		res.Status, res.Reason = "fail", err.Error()
		return res
	}

	pc, obs := runPion(c, exp, env, sig, logs)

	// Destroy stops the str0m peer, writes its pcap and returns its report.
	if err := sig.send(ClientMessage{Type: "destroy"}); err == nil {
		if msg, err := sig.recv("destroyed"); err == nil {
			res.Str0m = msg.Report
		} else {
			logs.printf("destroy: %v", err)
		}
	}
	// Before Close, which would make an unfinished DTLS handshake fail with "closed pipe".
	obs.pionError = logs.pionDtlsError()
	if pc != nil {
		_ = pc.Close()
	}

	evaluate(&res, obs)
	applyKnownIssues(&res, env.info)
	logs.printf("result: %s %s", res.Status, res.Reason)
	return res
}

// knownIssue is an open upstream bug that makes some cases fail in a recognisable way.
// Such failures are reported as xfail instead of failing the run.
type knownIssue struct {
	ID      string
	Summary string
	// always means every applicable case fails; passes are then reported as a possible fix.
	always  bool
	applies func(Case, ServerInfo) bool
	matches func(Result) bool
}

var knownIssues = []knownIssue{{
	ID: "str0m-openssl-no-dtls-retransmit",
	Summary: "str0m's plain OpenSSL DTLS backend never retransmits handshake flights (handle_timeout " +
		"doesn't drive OpenSSL's DTLS timer), so one lost handshake packet stalls the connection",
	applies: func(c Case, info ServerInfo) bool {
		p, ok := netemProfile(c.Netem)
		return info.Crypto == "openssl" && ok && p.Lossy
	},
	matches: func(r Result) bool {
		return !r.Opened && (r.Str0m == nil || r.Str0m.ConnectedMs == nil)
	},
}}

func applyKnownIssues(res *Result, info ServerInfo) {
	for _, issue := range knownIssues {
		if !issue.applies(res.Case, info) {
			continue
		}
		switch {
		case res.Status == "fail" && issue.matches(*res):
			res.Status, res.KnownIssue = "xfail", issue.ID
		case res.Status == "pass" && res.Expect.Connect && issue.always:
			res.KnownIssue = issue.ID
			res.Reason = "known issue " + issue.ID + " did not reproduce"
		}
		return
	}
}

func evaluate(res *Result, obs observation) {
	res.Opened, res.Echoed = obs.opened, obs.echoed
	res.OpenMs, res.EchoMs = obs.openMs, obs.echoMs
	res.PionDtls, res.SnapNegotiated = obs.pionDtls, obs.snap
	res.PionDtlsError = obs.pionError
	res.PionState = obs.state.String()
	if r := res.Str0m; r != nil && r.DtlsVersion != nil {
		res.Str0mDtls = *r.DtlsVersion
	}
	if obs.pionError != "" && obs.failure != "" {
		obs.failure += " (Pion DTLS: " + obs.pionError + ")"
	}

	exp := res.Expect
	var problems []string
	switch {
	case obs.setupErr != nil:
		problems = append(problems, obs.setupErr.Error())
	case !exp.Connect:
		if obs.opened {
			problems = append(problems, fmt.Sprintf("connected with DTLS %s although the versions are incompatible", obs.pionDtls))
		} else {
			res.Reason = "rejected: " + obs.failure
		}
	default:
		if !obs.opened || !obs.echoed {
			problems = append(problems, obs.failure)
		}
		if obs.holdError != "" {
			problems = append(problems, obs.holdError)
		}
		if obs.opened && obs.pionDtls != exp.Dtls {
			problems = append(problems, fmt.Sprintf("Pion negotiated DTLS %q, expected %s", obs.pionDtls, exp.Dtls))
		}
		if obs.opened && res.Str0mDtls != exp.Dtls {
			problems = append(problems, fmt.Sprintf("str0m negotiated DTLS %q, expected %s", res.Str0mDtls, exp.Dtls))
		}
		if obs.snap != exp.Snap {
			problems = append(problems, fmt.Sprintf("SNAP negotiated=%v, expected %v", obs.snap, exp.Snap))
		}
	}
	if r := res.Str0m; r == nil {
		problems = append(problems, "no report from str0m")
	} else if r.Error != nil && exp.Connect {
		problems = append(problems, "str0m: "+*r.Error)
	}

	if len(problems) == 0 {
		res.Status = "pass"
		return
	}
	res.Status = "fail"
	res.Reason = strings.Join(problems, "; ")
}

// pionAPI builds a Pion API for one case. Candidates are restricted to IPv4
// loopback to match the server, which advertises 127.0.0.1.
func pionAPI(c Case, logs *caseLog, level logging.LogLevel) *webrtc.API {
	se := webrtc.SettingEngine{
		LoggerFactory: &logging.DefaultLoggerFactory{
			Writer:          logs,
			DefaultLogLevel: level,
			ScopeLevels:     map[string]logging.LogLevel{},
		},
	}
	se.SetIncludeLoopbackCandidate(true)
	se.SetIPFilter(func(info webrtc.IPFilterInfo) bool { return info.IP.IsLoopback() })
	se.SetNetworkTypes([]webrtc.NetworkType{webrtc.NetworkTypeUDP4})
	se.SetICEMulticastDNSMode(ice.MulticastDNSModeDisabled)

	switch c.PionVer {
	case Dtls12:
		se.SetDTLSMinVersion(protocol.Version1_2)
		se.SetDTLSMaxVersion(protocol.Version1_2)
	case Dtls13:
		se.SetDTLSMinVersion(protocol.Version1_3)
		se.SetDTLSMaxVersion(protocol.Version1_3)
	default:
		se.SetDTLSMinVersion(protocol.Version1_2)
		se.SetDTLSMaxVersion(protocol.Version1_3)
	}

	se.EnableSctpSnap(c.Snap.pion())

	if c.SdpRole == "answerer" {
		role := webrtc.DTLSRoleClient
		if c.DtlsRole == "passive" {
			role = webrtc.DTLSRoleServer
		}
		_ = se.SetAnsweringDTLSRole(role)
	}
	return webrtc.NewAPI(webrtc.WithSettingEngine(se))
}

// runPion does signaling plus the data channel echo. The str0m side forces its
// own DTLS role for "offerer/passive", so Pion only needs to pick it when answering.
func runPion(c Case, exp Expectation, env *runEnv, sig *signaling, logs *caseLog) (*webrtc.PeerConnection, observation) {
	var obs observation
	pc, err := pionAPI(c, logs, env.logLevel).NewPeerConnection(webrtc.Configuration{})
	if err != nil {
		obs.setupErr = err
		return nil, obs
	}

	// The state callback runs on Pion goroutines; it only touches these two.
	var stateMu sync.Mutex
	state := webrtc.PeerConnectionStateNew
	// finish always hands back pc so the caller closes it, also after setup errors.
	finish := func() (*webrtc.PeerConnection, observation) {
		stateMu.Lock()
		defer stateMu.Unlock()
		obs.state = state
		return pc, obs
	}
	fail := func(err error) (*webrtc.PeerConnection, observation) {
		obs.setupErr = err
		return finish()
	}

	opened := make(chan *webrtc.DataChannel, 1)
	messages := make(chan string, 16)
	attach := func(dc *webrtc.DataChannel) {
		dc.OnOpen(func() {
			select {
			case opened <- dc:
			default:
			}
		})
		dc.OnMessage(func(m webrtc.DataChannelMessage) {
			select {
			case messages <- string(m.Data):
			default:
			}
		})
	}

	failed := make(chan webrtc.PeerConnectionState, 1)
	pc.OnConnectionStateChange(func(s webrtc.PeerConnectionState) {
		logs.printf("peer connection state: %s", s)
		stateMu.Lock()
		state = s
		stateMu.Unlock()
		if s == webrtc.PeerConnectionStateFailed || s == webrtc.PeerConnectionStateClosed {
			select {
			case failed <- s:
			default:
			}
		}
	})

	gathered := func(desc webrtc.SessionDescription) error {
		done := webrtc.GatheringCompletePromise(pc)
		if err := pc.SetLocalDescription(desc); err != nil {
			return err
		}
		select {
		case <-done:
			return nil
		case <-time.After(signalTimeout):
			return errors.New("ICE gathering timed out")
		}
	}

	if c.SdpRole == "offerer" {
		dc, err := pc.CreateDataChannel("test-data", nil)
		if err != nil {
			return fail(err)
		}
		attach(dc)
		offer, err := pc.CreateOffer(nil)
		if err != nil {
			return fail(err)
		}
		if err := gathered(offer); err != nil {
			return fail(err)
		}
		if err := sig.send(ClientMessage{Type: "sdp", Sdp: pc.LocalDescription().SDP}); err != nil {
			return fail(err)
		}
		answer, err := sig.recv("sdp")
		if err != nil {
			return fail(err)
		}
		if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeAnswer, SDP: answer.Sdp}); err != nil {
			return fail(fmt.Errorf("set remote answer: %w", err))
		}
	} else {
		pc.OnDataChannel(attach)
		offer, err := sig.recv("sdp")
		if err != nil {
			return fail(err)
		}
		if err := pc.SetRemoteDescription(webrtc.SessionDescription{Type: webrtc.SDPTypeOffer, SDP: offer.Sdp}); err != nil {
			return fail(fmt.Errorf("set remote offer: %w", err))
		}
		answer, err := pc.CreateAnswer(nil)
		if err != nil {
			return fail(err)
		}
		if err := gathered(answer); err != nil {
			return fail(err)
		}
		if err := sig.send(ClientMessage{Type: "sdp", Sdp: pc.LocalDescription().SDP}); err != nil {
			return fail(err)
		}
	}

	obs.snap = hasSctpInit(pc.LocalDescription().SDP) && hasSctpInit(pc.RemoteDescription().SDP)
	logs.printf("SDP done (snap=%v), local SDP:\n%s\nremote SDP:\n%s", obs.snap, pc.LocalDescription().SDP, pc.RemoteDescription().SDP)

	t0 := time.Now()
	if err := sig.send(ClientMessage{Type: "ready"}); err != nil {
		return fail(err)
	}
	if _, err := sig.recv("ready"); err != nil {
		return fail(err)
	}

	openTimeout := env.openTimeoutFor(c, exp)
	var dc *webrtc.DataChannel
	select {
	case dc = <-opened:
		obs.opened = true
		obs.openMs = msSince(t0)
	case s := <-failed:
		obs.failure = "peer connection " + s.String()
	case <-time.After(openTimeout):
		obs.failure = fmt.Sprintf("data channel not open after %s", openTimeout)
	}
	obs.pionDtls = negotiatedDtls(pc)

	if obs.opened {
		echoTimeout := openTimeout
		if ms, ok := echo(dc, messages, echoTimeout); ok {
			obs.echoed, obs.echoMs = true, ms
		} else {
			obs.failure = fmt.Sprintf("no echo within %s", echoTimeout)
		}
		if obs.echoed && c.Hold > 0 {
			logs.printf("holding the session for %s", c.Hold)
			select {
			case s := <-failed:
				obs.holdError = fmt.Sprintf("peer connection %s while idle", s)
			case <-time.After(c.Hold):
				if _, ok := echo(dc, messages, openTimeout); !ok {
					obs.holdError = fmt.Sprintf("no echo after %s idle", c.Hold)
				}
			}
		}
	}

	return finish()
}

// echo sends one ping and waits for it to come back (str0m's "ready" beacon is ignored).
func echo(dc *webrtc.DataChannel, messages <-chan string, timeout time.Duration) (float64, bool) {
	sent := time.Now()
	if err := dc.SendText(pingMessage); err != nil {
		return 0, false
	}
	deadline := time.After(timeout)
	for {
		select {
		case m := <-messages:
			if m == pingMessage {
				return msSince(sent), true
			}
		case <-deadline:
			return 0, false
		}
	}
}

func hasSctpInit(sdp string) bool { return strings.Contains(sdp, "a=sctp-init:") }

// negotiatedDtls maps Pion's TLSVersion stat ("FEFD"/"FEFC") to "1.2"/"1.3".
func negotiatedDtls(pc *webrtc.PeerConnection) string {
	sctp := pc.SCTP()
	if sctp == nil || sctp.Transport() == nil {
		return ""
	}
	switch v := sctp.Transport().Stats().TLSVersion; v {
	case "":
		return ""
	case "FEFD":
		return "1.2"
	case "FEFC":
		return "1.3"
	default:
		return v
	}
}

// caseLog is the per-case log file shared by Pion's loggers and the runner.
// Pion goroutines may still log after the case ended; those lines are dropped.
type caseLog struct {
	mu        sync.Mutex
	w         *os.File
	closed    bool
	dtlsError string
}

// pionDtlsFailure prefixes the warning Pion logs when its DTLS transport fails to start.
const pionDtlsFailure = "Failed to start manager: "

func (l *caseLog) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.dtlsError == "" {
		if i := strings.Index(string(p), pionDtlsFailure); i >= 0 {
			l.dtlsError = strings.TrimSpace(string(p[i+len(pionDtlsFailure):]))
		}
	}
	if l.closed {
		return len(p), nil
	}
	return l.w.Write(p)
}

// pionDtlsError is why Pion's DTLS transport failed, if it did.
func (l *caseLog) pionDtlsError() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.dtlsError
}

func (l *caseLog) close() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.closed = true
	_ = l.w.Close()
}

func (l *caseLog) printf(format string, args ...any) {
	_, _ = fmt.Fprintf(l, "%s runner: %s\n", time.Now().Format("15:04:05.000000"), fmt.Sprintf(format, args...))
}
