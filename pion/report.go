package main

import (
	"fmt"
	"runtime/debug"
	"sort"
	"strings"
	"time"
)

// Report is written to results.json and rendered as markdown.
type Report struct {
	OS        string            `json:"os"`
	Crypto    string            `json:"crypto"`
	Server    ServerInfo        `json:"server"`
	Pion      map[string]string `json:"pion"`
	Started   time.Time         `json:"started"`
	DurationS float64           `json:"duration_s"`
	Counts    map[string]int    `json:"counts"`
	Results   []Result          `json:"results"`
}

// pionVersions reads the Pion module versions compiled into this binary.
func pionVersions() map[string]string {
	versions := map[string]string{}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return versions
	}
	for _, dep := range info.Deps {
		if dep.Replace != nil {
			dep = dep.Replace
		}
		for _, name := range []string{"webrtc", "dtls", "sctp", "ice", "rtp"} {
			path := strings.TrimPrefix(dep.Path, "github.com/pion/")
			if path == name || strings.HasPrefix(path, name+"/v") {
				versions[name] = dep.Version
			}
			if dep.Path == "github.com/livekit/livekit-server" {
				versions["livekit-dd-parser"] = dep.Version
			}
		}
	}
	return versions
}

func countStatuses(results []Result) map[string]int {
	counts := map[string]int{}
	for _, r := range results {
		counts[r.Status]++
	}
	return counts
}

func rejected(results []Result) int {
	n := 0
	for _, r := range results {
		if r.Status == "pass" && !r.Expect.Connect {
			n++
		}
	}
	return n
}

func statusIcon(r Result) string {
	switch r.Status {
	case "pass":
		if !r.Expect.Connect {
			return "🚫"
		}
		return "✅"
	case "skip":
		return "⏭️"
	case "xfail":
		return "⚠️"
	default:
		return "❌"
	}
}

func dtlsClient(c Case) string {
	if c.Str0mDtlsClient() {
		return "str0m"
	}
	return "Pion"
}

func snapLabel(m SnapMode) string {
	switch m {
	case SnapOn:
		return "both"
	case SnapStr0mOnly:
		return "str0m only"
	case SnapPionOnly:
		return "Pion only"
	default:
		return "off"
	}
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func fmtMs(v float64) string {
	if v == 0 {
		return "-"
	}
	return fmt.Sprintf("%.0f", v)
}

func fmtOptMs(v *float64) string {
	if v == nil {
		return "-"
	}
	return fmtMs(*v)
}

func drops(r Result) string {
	if r.Str0m == nil || (r.Str0m.NetemEgress == nil && r.Str0m.NetemIngress == nil) {
		return "-"
	}
	side := func(s *NetemStats) string {
		if s == nil {
			return "-"
		}
		return fmt.Sprintf("%d/%d", s.Dropped, s.Packets)
	}
	return side(r.Str0m.NetemEgress) + " · " + side(r.Str0m.NetemIngress)
}

// negotiated is the DTLS version cell content; it flags disagreeing peers.
func negotiated(r Result) string {
	switch {
	case !r.Opened:
		return "-"
	case r.PionDtls == r.Str0mDtls:
		return r.PionDtls
	default:
		return fmt.Sprintf("Pion %s / str0m %s", r.PionDtls, r.Str0mDtls)
	}
}

func (rep *Report) markdown() string {
	var b strings.Builder
	w := func(format string, args ...any) { fmt.Fprintf(&b, format, args...) }

	counts := rep.Counts
	w("## Pion ↔ str0m interop · %s · %s\n\n", rep.OS, rep.Crypto)
	w("**%d passed · %d failed · %d skipped", counts["pass"], counts["fail"], counts["skip"])
	if counts["xfail"] > 0 {
		w(" · %d known issues", counts["xfail"])
	}
	w("** of %d cases (%d incompatible DTLS pairs rejected as expected) in %s\n\n",
		len(rep.Results), rejected(rep.Results), (time.Duration(rep.DurationS) * time.Second).String())
	dtls13 := "❌"
	if rep.Server.Dtls13 {
		dtls13 = "✅"
	}
	w("str0m `%s` (DTLS 1.3 %s) · pion/webrtc `%s` · pion/dtls `%s` · pion/sctp `%s` · pion/ice `%s`\n\n",
		rep.Server.Crypto, dtls13, rep.Pion["webrtc"], rep.Pion["dtls"], rep.Pion["sctp"], rep.Pion["ice"])
	w("✅ pass · 🚫 rejected as expected (no common DTLS version) · ❌ fail · ⏭️ skipped · ⚠️ known upstream issue\n\n")

	bySuite := map[string][]Result{}
	for _, r := range rep.Results {
		bySuite[r.Suite] = append(bySuite[r.Suite], r)
	}

	for _, suite := range allSuites {
		results := bySuite[suite]
		if len(results) == 0 {
			continue
		}
		w("### %s\n\n", suiteTitles[suite])
		switch suite {
		case "video":
			w("Pion receives AV1/RTP; the Apache-2.0 LiveKit DD parser validates semantics (no AV1 decode).\n\n")
			w("| DTLS client | Result | Frames | Packets | Structures | DD roundtrips | Source header matches | DD wraps |\n|---|---|---|---|---|---|---|---|\n")
			for _, r := range results {
				if v := r.Video; v != nil {
					w("| %s | %s | %d | %d | %d | %d | %d | %d |\n", dtlsClient(r.Case), statusIcon(r),
						v.Frames, len(v.Packets), v.Structures, v.Roundtrips, v.MatchedSourcePackets, v.FrameNumberWraps)
				} else {
					w("| %s | %s | - | - | - | - | - | - |\n", dtlsClient(r.Case), statusIcon(r))
				}
			}
		case "dtls":
			writeDtlsPivot(&b, results)
		case "snap":
			w("| Pion SDP | DTLS client | DTLS | SNAP offered by | SNAP negotiated | Result | Open ms |\n|---|---|---|---|---|---|---|\n")
			for _, r := range results {
				w("| %s | %s | %s | %s | %s | %s | %s |\n", r.SdpRole, dtlsClient(r.Case), r.Str0mVer.label(),
					snapLabel(r.Snap), yesNo(r.SnapNegotiated), statusIcon(r), fmtMs(r.OpenMs))
			}
		case "ice":
			w("| Pion SDP | DTLS client | DTLS cfg | Negotiated | Result | Open ms |\n|---|---|---|---|---|---|\n")
			for _, r := range results {
				w("| %s | %s | %s | %s | %s | %s |\n", r.SdpRole, dtlsClient(r.Case), r.Str0mVer.label(),
					negotiated(r), statusIcon(r), fmtMs(r.OpenMs))
			}
		case "netem":
			for _, p := range netemProfiles {
				var rows []Result
				for _, r := range results {
					if r.Netem == p.Name {
						rows = append(rows, r)
					}
				}
				if len(rows) == 0 {
					continue
				}
				w("**%s**: %s\n\n", p.Name, p.Desc)
				w("| Pion SDP | DTLS client | DTLS | SNAP | Result | Pion open ms | str0m connected / open ms | Echo ms | str0m drops egress · ingress |\n|---|---|---|---|---|---|---|---|---|\n")
				for _, r := range rows {
					var connected, open *float64
					if r.Str0m != nil {
						connected, open = r.Str0m.ConnectedMs, r.Str0m.ChannelOpenMs
					}
					w("| %s | %s | %s | %s | %s | %s | %s / %s | %s | %s |\n", r.SdpRole, dtlsClient(r.Case),
						r.Str0mVer.label(), snapLabel(r.Snap), statusIcon(r), fmtMs(r.OpenMs),
						fmtOptMs(connected), fmtOptMs(open), fmtMs(r.EchoMs), drops(r))
				}
				w("\n")
			}
		case "longlived":
			w("| Pion SDP | DTLS client | DTLS | Idle | Result |\n|---|---|---|---|---|\n")
			for _, r := range results {
				w("| %s | %s | %s | %s | %s |\n", r.SdpRole, dtlsClient(r.Case), r.Str0mVer.label(), r.Hold, statusIcon(r))
			}
		}
		w("\n")
	}

	var problems []Result
	for _, r := range rep.Results {
		if r.Status == "fail" {
			problems = append(problems, r)
		}
	}
	if len(problems) > 0 {
		w("### Failures\n\n")
		for _, r := range problems {
			w("- `%s`: %s\n", r.Name, r.Reason)
		}
		w("\n")
	}

	var known []string
	for _, issue := range knownIssues {
		reproduced, fixed := 0, 0
		for _, r := range rep.Results {
			if r.KnownIssue != issue.ID {
				continue
			}
			if r.Status == "xfail" {
				reproduced++
			} else {
				fixed++
			}
		}
		if reproduced+fixed > 0 {
			known = append(known, fmt.Sprintf("- ⚠️ `%s` (%d cases, %d no longer fail): %s",
				issue.ID, reproduced+fixed, fixed, issue.Summary))
		}
	}
	if len(known) > 0 {
		w("### Known upstream issues\n\n%s\n\n", strings.Join(known, "\n"))
	}
	return b.String()
}

// writeDtlsPivot renders str0m versions as rows and Pion versions as columns.
func writeDtlsPivot(b *strings.Builder, results []Result) {
	type rowKey struct{ sdp, role string }
	cells := map[rowKey]map[DtlsVer]map[DtlsVer]Result{}
	for _, r := range results {
		k := rowKey{r.SdpRole, r.DtlsRole}
		if cells[k] == nil {
			cells[k] = map[DtlsVer]map[DtlsVer]Result{}
		}
		if cells[k][r.Str0mVer] == nil {
			cells[k][r.Str0mVer] = map[DtlsVer]Result{}
		}
		cells[k][r.Str0mVer][r.PionVer] = r
	}
	fmt.Fprintf(b, "Rows: str0m `server_dtls_version` · columns: Pion min/max DTLS version · cell: negotiated version\n\n")
	fmt.Fprintf(b, "| Pion SDP | DTLS client | str0m ↓ · Pion → | 1.2 | auto | 1.3 |\n|---|---|---|---|---|---|\n")
	for _, sdp := range sdpRoles {
		for _, role := range dtlsRoles {
			row := cells[rowKey{sdp, role}]
			if row == nil {
				continue
			}
			for _, sv := range allVersions {
				var line []string
				var anyCase Case
				for _, pv := range allVersions {
					r, ok := row[sv][pv]
					if !ok {
						line = append(line, "")
						continue
					}
					anyCase = r.Case
					cell := statusIcon(r)
					if r.Opened {
						cell += " " + negotiated(r)
					}
					line = append(line, cell)
				}
				fmt.Fprintf(b, "| %s | %s | **%s** | %s |\n", sdp, dtlsClient(anyCase), sv.label(), strings.Join(line, " | "))
			}
		}
	}
	fmt.Fprintf(b, "\n")
}

// consoleSummary lists failures for the terminal.
func consoleSummary(rep *Report) string {
	var b strings.Builder
	var failed []Result
	for _, r := range rep.Results {
		if r.Status == "fail" {
			failed = append(failed, r)
		}
	}
	sort.Slice(failed, func(i, j int) bool { return failed[i].Name < failed[j].Name })
	for _, r := range failed {
		fmt.Fprintf(&b, "FAIL  %s\n      %s\n", r.Name, r.Reason)
		if r.LogFile != "" {
			fmt.Fprintf(&b, "      log: %s\n", r.LogFile)
		}
	}
	c := rep.Counts
	fmt.Fprintf(&b, "\n%d passed, %d failed, %d skipped, %d known upstream issues (%d rejected as expected) of %d cases in %.1fs\n",
		c["pass"], c["fail"], c["skip"], c["xfail"], rejected(rep.Results), len(rep.Results), rep.DurationS)
	return b.String()
}
