package main

import (
	"fmt"
	"strings"
	"time"
)

// DtlsVer is a DTLS version setting. The same names are used for str0m's
// server_dtls_version and for Pion's min/max DTLS version.
type DtlsVer string

const (
	Dtls12   DtlsVer = "dtls12"
	DtlsAuto DtlsVer = "auto"
	Dtls13   DtlsVer = "dtls13"
)

var allVersions = []DtlsVer{Dtls12, DtlsAuto, Dtls13}

func (v DtlsVer) short() string {
	switch v {
	case Dtls12:
		return "12"
	case Dtls13:
		return "13"
	default:
		return "auto"
	}
}

func (v DtlsVer) label() string {
	switch v {
	case Dtls12:
		return "1.2"
	case Dtls13:
		return "1.3"
	default:
		return "auto"
	}
}

// negotiable lists the versions a side configured with v can end up with.
func (v DtlsVer) negotiable(dtls13 bool) []string {
	switch {
	case v == Dtls12 || !dtls13:
		return []string{"1.2"}
	case v == Dtls13:
		return []string{"1.3"}
	default:
		return []string{"1.2", "1.3"}
	}
}

// SnapMode says which side advertises SNAP (a=sctp-init) in its own SDP.
type SnapMode string

const (
	SnapOff       SnapMode = "off"
	SnapOn        SnapMode = "on"
	SnapStr0mOnly SnapMode = "str0m"
	SnapPionOnly  SnapMode = "pion"
)

func (m SnapMode) str0m() bool { return m == SnapOn || m == SnapStr0mOnly }
func (m SnapMode) pion() bool  { return m == SnapOn || m == SnapPionOnly }

// NetemProfile is a named str0m-side network emulation setting.
type NetemProfile struct {
	Name     string
	Desc     string
	Lossy    bool
	Settings NetemSettings
}

func symmetric(link NetemLink) NetemSettings {
	egress, ingress := link, link
	return NetemSettings{Egress: &egress, Ingress: &ingress}
}

var netemProfiles = []NetemProfile{
	{"loss5", "5% random loss each way", true, symmetric(NetemLink{LossPercent: 5})},
	{"loss15", "15% random loss each way", true, symmetric(NetemLink{LossPercent: 15})},
	{"burst", "bursty loss each way (bursts of ~3 packets every ~25)", true, symmetric(NetemLink{BurstInterval: 25, BurstLength: 3})},
	{"delay", "75 ms ± 10 ms latency each way", false, symmetric(NetemLink{LatencyMs: 75, JitterMs: 10})},
}

func netemProfile(name string) (NetemProfile, bool) {
	for _, p := range netemProfiles {
		if p.Name == name {
			return p, true
		}
	}
	return NetemProfile{}, false
}

// Suites in the order they are reported.
var allSuites = []string{"dtls", "snap", "ice", "netem", "longlived", "video"}

var suiteTitles = map[string]string{
	"dtls":      "DTLS version × role matrix",
	"snap":      "SNAP (a=sctp-init)",
	"ice":       "str0m ICE full",
	"netem":     "str0m-netem (loss / delay on the str0m side)",
	"longlived": "Long-lived sessions",
	"video":     "AV1 dependency descriptors (Pion + LiveKit parser)",
}

// Case is one Pion <-> str0m session.
type Case struct {
	Name  string `json:"name"`
	Suite string `json:"suite"`
	// SdpRole and DtlsRole are Pion's roles; str0m takes the opposite ones.
	SdpRole  string   `json:"pion_sdp_role"`
	DtlsRole string   `json:"pion_dtls_role"`
	IceMode  string   `json:"str0m_ice_mode"`
	Str0mVer DtlsVer  `json:"str0m_dtls"`
	PionVer  DtlsVer  `json:"pion_dtls"`
	Snap     SnapMode `json:"snap"`
	Netem    string   `json:"netem,omitempty"`
	// Hold keeps the session idle before a second echo round trip.
	Hold time.Duration `json:"hold_ns,omitempty"`
}

// Str0mDtlsClient reports whether str0m sends the ClientHello.
func (c Case) Str0mDtlsClient() bool { return c.DtlsRole == "passive" }

func (c Case) netemSettings() *NetemSettings {
	if p, ok := netemProfile(c.Netem); ok {
		s := p.Settings
		return &s
	}
	return nil
}

func (c Case) sessionConfig() SessionConfig {
	snap := c.Snap.str0m()
	return SessionConfig{
		ClientSdpRole:     c.SdpRole,
		ServerIceMode:     c.IceMode,
		ClientDtlsRole:    c.DtlsRole,
		ServerDtlsVersion: string(c.Str0mVer),
		ServerSnap:        &snap,
		ServerNetem:       c.netemSettings(),
		VideoFrameMode:    c.Suite == "video",
	}
}

func newCase(suite, sdp, role, ice string, sv, pv DtlsVer, snap SnapMode, netem string) Case {
	name := fmt.Sprintf("pion_%s_%s_%s_%s_s%s_p%s_snap%s", suite, sdp, role, ice, sv.short(), pv.short(), snap)
	if netem != "" {
		name += "_" + netem
	}
	return Case{
		Name: name, Suite: suite, SdpRole: sdp, DtlsRole: role, IceMode: ice,
		Str0mVer: sv, PionVer: pv, Snap: snap, Netem: netem,
	}
}

var (
	sdpRoles  = []string{"offerer", "answerer"}
	dtlsRoles = []string{"active", "passive"}
)

// buildCases expands the requested suites into cases.
func buildCases(suites []string, profiles []string, hold time.Duration) []Case {
	var cases []Case
	for _, suite := range suites {
		for _, sdp := range sdpRoles {
			for _, role := range dtlsRoles {
				switch suite {
				case "video":
					if sdp == "offerer" {
						cases = append(cases, newCase(suite, sdp, role, "lite", DtlsAuto, DtlsAuto, SnapOff, ""))
					}
				case "dtls":
					// Every str0m version against every Pion version, incompatible pairs included.
					for _, sv := range allVersions {
						for _, pv := range allVersions {
							cases = append(cases, newCase(suite, sdp, role, "lite", sv, pv, SnapOff, ""))
						}
					}
				case "snap":
					for _, v := range allVersions {
						cases = append(cases, newCase(suite, sdp, role, "lite", v, v, SnapOn, ""))
					}
					// Only one side advertising SNAP must fall back cleanly.
					cases = append(cases,
						newCase(suite, sdp, role, "lite", DtlsAuto, DtlsAuto, SnapStr0mOnly, ""),
						newCase(suite, sdp, role, "lite", DtlsAuto, DtlsAuto, SnapPionOnly, ""))
				case "ice":
					for _, v := range allVersions {
						cases = append(cases, newCase(suite, sdp, role, "full", v, v, SnapOff, ""))
					}
				case "netem":
					for _, profile := range profiles {
						for _, v := range allVersions {
							for _, snap := range []SnapMode{SnapOff, SnapOn} {
								cases = append(cases, newCase(suite, sdp, role, "lite", v, v, snap, profile))
							}
						}
					}
				case "longlived":
					// Outlive the 40 s DTLS handshake deadline in both DTLS roles.
					if sdp != "offerer" {
						continue
					}
					for _, v := range []DtlsVer{Dtls12, Dtls13} {
						c := newCase(suite, sdp, role, "lite", v, v, SnapOn, "")
						c.Hold = hold
						cases = append(cases, c)
					}
				}
			}
		}
	}
	return cases
}

// Expectation is what a case must produce against a given str0m server.
type Expectation struct {
	// Skip is set when the server can't run the case at all.
	Skip    string `json:"skip,omitempty"`
	Connect bool   `json:"connect"`
	Dtls    string `json:"dtls,omitempty"`
	Snap    bool   `json:"snap"`
}

func expectationFor(c Case, info ServerInfo) Expectation {
	if c.Str0mVer == Dtls13 && !info.Dtls13 {
		return Expectation{Skip: fmt.Sprintf("str0m backend %s has no DTLS 1.3", info.Crypto)}
	}
	str0m := c.Str0mVer.negotiable(info.Dtls13)
	pion := c.PionVer.negotiable(true)
	best := ""
	for _, v := range []string{"1.3", "1.2"} {
		if contains(str0m, v) && contains(pion, v) {
			best = v
			break
		}
	}
	if best == "" {
		return Expectation{Connect: false}
	}
	// str0m answers any offered a=sctp-init; Pion only does when SNAP is enabled.
	snap := c.Snap.pion() && (c.SdpRole == "offerer" || c.Snap.str0m())
	return Expectation{Connect: true, Dtls: best, Snap: snap}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func splitList(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}
