package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	"github.com/gorilla/websocket"
)

// readyRe matches the server's readiness line: SERVER READY ws://<ip>:<port>
var readyRe = regexp.MustCompile(`SERVER READY (ws://[\d.]+:\d+)`)

// str0mServer is a spawned instance of the repo's test server (src/bin/server.rs).
type str0mServer struct {
	cmd  *exec.Cmd
	url  string
	done chan struct{}
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// startServer runs the server in workdir (pcaps land in <workdir>/target/pcap)
// with all output going to log, and waits until it accepts connections.
func startServer(bin, workdir string, log io.Writer, extraArgs []string) (*str0mServer, error) {
	port, err := freePort()
	if err != nil {
		return nil, err
	}
	args := append([]string{
		"--ws-port", strconv.Itoa(port),
		"--udp-port-start", "0",
		"--adv-addr", "127.0.0.1",
	}, extraArgs...)

	cmd := exec.Command(bin, args...)
	cmd.Dir = workdir
	cmd.Env = append(os.Environ(), "NO_COLOR=1")
	if os.Getenv("RUST_LOG") == "" {
		cmd.Env = append(cmd.Env, "RUST_LOG=info,str0m=warn,sctp_proto=warn")
	}
	cmd.Stderr = log
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("start %s: %w", bin, err)
	}

	ready := make(chan string, 1)
	scanned := make(chan struct{})
	go func() {
		defer close(scanned)
		scanner := bufio.NewScanner(stdout)
		scanner.Buffer(make([]byte, 64*1024), 4*1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			_, _ = fmt.Fprintln(log, line)
			if m := readyRe.FindStringSubmatch(line); m != nil {
				select {
				case ready <- m[1]:
				default:
				}
			}
		}
	}()
	done := make(chan struct{})
	go func() {
		<-scanned
		_ = cmd.Wait()
		close(done)
	}()

	srv := &str0mServer{cmd: cmd, done: done}
	select {
	case srv.url = <-ready:
		return srv, nil
	case <-done:
		return nil, errors.New("server exited before it was ready (see server.log)")
	case <-time.After(60 * time.Second):
		srv.stop()
		return nil, errors.New("timed out waiting for SERVER READY (see server.log)")
	}
}

func (s *str0mServer) stop() {
	_ = s.cmd.Process.Kill()
	<-s.done
}

// queryInfo asks the server which crypto backend it runs and whether it has DTLS 1.3.
func queryInfo(url string) (ServerInfo, error) {
	conn, _, err := websocket.DefaultDialer.Dial(url, nil)
	if err != nil {
		return ServerInfo{}, err
	}
	defer conn.Close()
	sig := &signaling{conn: conn}
	if err := sig.send(ClientMessage{Type: "info"}); err != nil {
		return ServerInfo{}, err
	}
	msg, err := sig.recv("info")
	if err != nil {
		return ServerInfo{}, fmt.Errorf("%w (is the server older than the pion runner?)", err)
	}
	return ServerInfo{Crypto: msg.Crypto, Dtls13: msg.Dtls13, DefaultNetem: msg.DefaultNetem}, nil
}
