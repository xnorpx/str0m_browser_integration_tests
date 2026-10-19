// Command pion-interop runs a Pion (pion/webrtc v5) <-> str0m interop matrix against
// this repo's str0m test server: DTLS 1.2/auto/1.3 on both sides with each side as
// DTLS client and server, SDP offerer/answerer, SNAP, ICE lite/full and str0m-side
// network emulation (str0m-netem).
//
//	go -C pion run . -server-bin ../target/release/server
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/pion/logging"
)

func main() {
	os.Exit(run())
}

func run() int {
	profileNames := make([]string, len(netemProfiles))
	for i, p := range netemProfiles {
		profileNames[i] = p.Name
	}

	var (
		serverBin  = flag.String("server-bin", "", "str0m test server binary (default: $PREBUILT_SERVER_BINARY, else cargo build --release)")
		serverArgs = flag.String("server-args", "", `extra arguments for the spawned server, e.g. "--netem loss=2"`)
		wsURL      = flag.String("ws", "", "use an already running server at this ws:// URL instead of spawning one")
		workdir    = flag.String("workdir", "", "repository root; the server writes pcaps to <workdir>/target/pcap (default: auto-detect)")
		outDir     = flag.String("out", "", "directory for results.json, summary.md and logs (default: <workdir>/target/pion-interop)")
		suites     = flag.String("suites", strings.Join(allSuites, ","), "comma separated suites: "+strings.Join(allSuites, ", "))
		profiles   = flag.String("netem-profiles", strings.Join(profileNames, ","), "netem profiles used by the netem suite")
		runFilter  = flag.String("run", "", "only run cases whose name matches this regular expression")
		parallel   = flag.Int("parallel", 4, "number of cases to run concurrently")
		list       = flag.Bool("list", false, "list the selected cases and exit")
		osLabel    = flag.String("os", runtime.GOOS, "OS label for the report")
		crypto     = flag.String("crypto", "", "crypto backend label for the report (default: reported by the server)")
		summaryMd  = flag.String("summary-md", "", "append the markdown report to this file, e.g. $GITHUB_STEP_SUMMARY")
		pionLog    = flag.String("pion-log", "debug", "Pion log level in per-case logs: trace, debug, info, warn, error")
		keepLogs   = flag.Bool("keep-logs", false, "keep per-case logs of passing cases")
		openTO     = flag.Duration("open-timeout", 15*time.Second, "time for the data channel to open, and for each echo")
		netemTO    = flag.Duration("netem-timeout", 45*time.Second, "open/echo timeout for netem cases")
		rejectTO   = flag.Duration("reject-timeout", 8*time.Second, "how long incompatible DTLS versions get to (not) connect")
		hold       = flag.Duration("hold", 45*time.Second, "idle time before the second echo in the longlived suite")
	)
	flag.Parse()

	for _, s := range splitList(*suites) {
		if _, ok := suiteTitles[s]; !ok {
			return usageError("unknown suite %q", s)
		}
	}
	for _, p := range splitList(*profiles) {
		if _, ok := netemProfile(p); !ok {
			return usageError("unknown netem profile %q", p)
		}
	}
	level, ok := map[string]logging.LogLevel{
		"trace": logging.LogLevelTrace, "debug": logging.LogLevelDebug, "info": logging.LogLevelInfo,
		"warn": logging.LogLevelWarn, "error": logging.LogLevelError,
	}[*pionLog]
	if !ok {
		return usageError("unknown -pion-log level %q", *pionLog)
	}

	cases := buildCases(splitList(*suites), splitList(*profiles), *hold)
	if *runFilter != "" {
		re, err := regexp.Compile(*runFilter)
		if err != nil {
			return usageError("-run: %v", err)
		}
		var selected []Case
		for _, c := range cases {
			if re.MatchString(c.Name) {
				selected = append(selected, c)
			}
		}
		cases = selected
	}
	if *list {
		for _, c := range cases {
			fmt.Println(c.Name)
		}
		fmt.Fprintf(os.Stderr, "%d cases\n", len(cases))
		return 0
	}
	if len(cases) == 0 {
		return usageError("no cases selected")
	}

	root := *workdir
	if root == "" {
		root = findRepoRoot()
	}
	root, _ = filepath.Abs(root)
	out := *outDir
	if out == "" {
		out = filepath.Join(root, "target", "pion-interop")
	}
	logDir := filepath.Join(out, "logs")
	_ = os.RemoveAll(logDir)
	if err := os.MkdirAll(logDir, 0o755); err != nil {
		return fatal(err)
	}

	url := *wsURL
	if url == "" {
		bin, err := resolveServerBin(*serverBin, root)
		if err != nil {
			return fatal(err)
		}
		serverLog, err := os.Create(filepath.Join(out, "server.log"))
		if err != nil {
			return fatal(err)
		}
		defer serverLog.Close()
		srv, err := startServer(bin, root, serverLog, strings.Fields(*serverArgs))
		if err != nil {
			return fatal(err)
		}
		defer srv.stop()
		stopOnInterrupt(srv)
		url = srv.url
	}

	info, err := queryInfo(url)
	if err != nil {
		return fatal(fmt.Errorf("server info: %w", err))
	}
	if *crypto == "" {
		*crypto = info.Crypto
	}
	fmt.Printf("str0m server %s (crypto %s, DTLS 1.3: %v), %d cases, %d in parallel\n",
		url, info.Crypto, info.Dtls13, len(cases), *parallel)

	env := &runEnv{
		wsURL: url, info: info, logDir: logDir, logLevel: level, keepLogs: *keepLogs,
		openTimeout: *openTO, netemTimeout: *netemTO, rejectTimeout: *rejectTO,
	}

	started := time.Now()
	results := runAll(cases, env, *parallel)
	report := &Report{
		OS: *osLabel, Crypto: *crypto, Server: info, Pion: pionVersions(),
		Started: started, DurationS: time.Since(started).Seconds(),
		Counts: countStatuses(results), Results: results,
	}

	if err := writeOutputs(report, out, *summaryMd); err != nil {
		return fatal(err)
	}
	fmt.Print("\n" + consoleSummary(report))
	fmt.Printf("results: %s\n", filepath.Join(out, "results.json"))
	if report.Counts["fail"] > 0 {
		return 1
	}
	return 0
}

func runAll(cases []Case, env *runEnv, parallel int) []Result {
	results := make([]Result, len(cases))
	sem := make(chan struct{}, max(parallel, 1))
	var wg sync.WaitGroup
	var mu sync.Mutex
	done := 0
	for i, c := range cases {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			exp := expectationFor(c, env.info)
			r := runCase(c, exp, env)
			results[i] = r

			mu.Lock()
			defer mu.Unlock()
			done++
			detail := ""
			if r.Opened {
				detail = fmt.Sprintf(" dtls=%s open=%.0fms echo=%.1fms", negotiated(r), r.OpenMs, r.EchoMs)
			}
			if r.Reason != "" {
				detail += " (" + r.Reason + ")"
			}
			fmt.Printf("[%3d/%d] %-5s %s%s %.1fs\n", done, len(cases), strings.ToUpper(r.Status), c.Name, detail, r.DurationMs/1000)
		}()
	}
	wg.Wait()
	return results
}

func writeOutputs(report *Report, out, summaryMd string) error {
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(out, "results.json"), data, 0o644); err != nil {
		return err
	}
	md := report.markdown()
	if err := os.WriteFile(filepath.Join(out, "summary.md"), []byte(md), 0o644); err != nil {
		return err
	}
	if summaryMd == "" {
		return nil
	}
	f, err := os.OpenFile(summaryMd, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(md + "\n")
	return err
}

// findRepoRoot walks up from the working directory to the repo (Cargo.toml + pion/).
func findRepoRoot() string {
	cwd, _ := os.Getwd()
	for dir := cwd; ; dir = filepath.Dir(dir) {
		if isFile(filepath.Join(dir, "Cargo.toml")) && isFile(filepath.Join(dir, "pion", "go.mod")) {
			return dir
		}
		if filepath.Dir(dir) == dir {
			return cwd
		}
	}
}

func isFile(path string) bool {
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

func resolveServerBin(flagValue, root string) (string, error) {
	if flagValue != "" {
		return filepath.Abs(flagValue)
	}
	if env := os.Getenv("PREBUILT_SERVER_BINARY"); env != "" {
		return filepath.Abs(env)
	}
	cargo := os.Getenv("CARGO")
	if cargo == "" {
		cargo = "cargo"
	}
	fmt.Println("building the str0m test server: cargo build --release --bin server")
	cmd := exec.Command(cargo, "build", "--release", "--bin", "server")
	cmd.Dir = root
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("cargo build: %w", err)
	}
	bin := filepath.Join(root, "target", "release", "server")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	return bin, nil
}

func stopOnInterrupt(srv *str0mServer) {
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, os.Interrupt)
	go func() {
		<-sigs
		srv.stop()
		os.Exit(130)
	}()
}

func usageError(format string, args ...any) int {
	fmt.Fprintf(os.Stderr, "pion-interop: "+format+"\n", args...)
	return 2
}

func fatal(err error) int {
	fmt.Fprintf(os.Stderr, "pion-interop: %v\n", err)
	return 2
}
