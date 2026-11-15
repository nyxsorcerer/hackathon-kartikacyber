// Command asset-monitor-agent is the On-server agent of GarudaNetra (ADR-0007).
//
//	asset-monitor-agent enroll --url URL --tls-pin PIN --dashboard-key KEY --key-id ID --agent-id ID --allow PATH...
//	asset-monitor-agent repin --key KEY --key-id ID
//	asset-monitor-agent run
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"
)

const (
	defaultConfigDir = "/etc/asset-monitor-agent"
	defaultUnitDir   = "/etc/systemd/system"
	binaryPath       = "/usr/local/bin/asset-monitor-agent"
	defaultPoll      = 30 * time.Second
	minPoll          = 2 * time.Second
)

// A hostile agent listener may answer with thousands of junk envelopes.
var (
	maxRefusalsPerPoll = 16
	maxRefusedKept     = 1024
)

var idPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{1,128}$`)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: asset-monitor-agent enroll|repin|run [flags]")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "enroll":
		err = enroll(os.Args[2:], os.Stdin, os.Stdout, os.Stderr, systemLookup)
	case "repin":
		err = repin(os.Args[2:], os.Stdout, os.Stderr)
	case "run":
		err = runCmd(os.Args[2:])
	default:
		err = fmt.Errorf("unknown subcommand %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "asset-monitor-agent:", err)
		os.Exit(1)
	}
}

// localConfig is written by enroll only, under the configuration directory.
type localConfig struct {
	AgentID      string   `json:"agent_id"`
	URL          string   `json:"url"`
	ListenerAddr string   `json:"listener_addr"`
	TLSPin       string   `json:"tls_pin"`
	DashboardKey string   `json:"dashboard_key"`
	KeyID        string   `json:"key_id"`
	AllowedPaths []string `json:"allowed_paths"`
}

type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func fingerprint(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return "sha256:" + hex.EncodeToString(sum[:])
}

// readCode reads the Enrollment code from standard input only.
func readCode(stdin io.Reader) (string, error) {
	line, err := bufio.NewReader(io.LimitReader(stdin, 1024)).ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	code := strings.TrimSpace(line)
	if len(code) < 8 || len(code) > 256 || strings.Trim(code, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._~:-") != "" {
		return "", errors.New("no valid Enrollment code on standard input")
	}
	return code, nil
}

type enrollRequest struct {
	AgentID        string   `json:"agent_id"`
	EnrollmentCode string   `json:"enrollment_code"`
	PublicKey      string   `json:"public_key"`
	AllowedPaths   []string `json:"allowed_paths"`
	Version        string   `json:"version"`
	OS             string   `json:"os"`
	Arch           string   `json:"arch"`
}

func enroll(args []string, stdin io.Reader, stdout, stderr io.Writer, lookup lookupFunc) error {
	fl := flag.NewFlagSet("enroll", flag.ContinueOnError)
	fl.SetOutput(stderr)
	rawURL := fl.String("url", "", "agent listener URL as this server sees it (https://host:port)")
	pin := fl.String("tls-pin", "", "SHA-256 of the agent listener's public key (base64 or hex)")
	dashKey := fl.String("dashboard-key", "", "public half of the Dashboard key (base64 or hex)")
	keyID := fl.String("key-id", "", "Dashboard key id")
	agentID := fl.String("agent-id", "", "agent id shown by the dashboard")
	configDir := fl.String("config-dir", defaultConfigDir, "configuration directory (tests only)")
	stateDir := fl.String("state-dir", defaultStateDir, "state directory (tests only)")
	unitDir := fl.String("unit-dir", defaultUnitDir, "where to write asset-monitor-agent.service")
	var allows multiFlag
	fl.Var(&allows, "allow", "an Allowed path (repeat); there is no default")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if fl.NArg() > 0 {
		return fmt.Errorf("unexpected argument %q; the Enrollment code is read from standard input only", fl.Arg(0))
	}
	if *rawURL == "" || *pin == "" || *dashKey == "" || *keyID == "" || *agentID == "" || len(allows) == 0 {
		return errors.New("--url, --tls-pin, --dashboard-key, --key-id, --agent-id and at least one --allow are required")
	}
	if !idPattern.MatchString(*keyID) || !idPattern.MatchString(*agentID) {
		return errors.New("bad --key-id or --agent-id")
	}
	pinB, err := decode32(*pin)
	if err != nil {
		return fmt.Errorf("--tls-pin: %w", err)
	}
	dk, err := decode32(*dashKey)
	if err != nil {
		return fmt.Errorf("--dashboard-key: %w", err)
	}
	extra := []string{filepath.Clean(*stateDir), filepath.Clean(*configDir)}
	if len(allows) > 32 {
		return errors.New("at most 32 --allow paths")
	}
	var allowed []string
	for _, a := range allows {
		real, err := resolveAllowed(a, extra...)
		if err != nil {
			return fmt.Errorf("--allow %s: %w", a, err)
		}
		if !slices.Contains(allowed, real) {
			allowed = append(allowed, real)
		}
	}
	base, addr, err := checkURL(*rawURL, lookup)
	if err != nil {
		return err
	}
	fmt.Fprint(stderr, "Enrollment code: ")
	code, err := readCode(stdin)
	if err != nil {
		return err
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	req := enrollRequest{AgentID: *agentID, EnrollmentCode: code, PublicKey: base64.StdEncoding.EncodeToString(pub),
		AllowedPaths: allowed, Version: agentVersion, OS: runtime.GOOS, Arch: runtime.GOARCH}
	if err := call(pinnedClient(addr, pinB), priv, *agentID, http.MethodPost, base, "/agent/v1/enroll", req, nil, time.Now()); err != nil {
		return fmt.Errorf("enrollment refused: %w", err)
	}
	cfg := localConfig{AgentID: *agentID, URL: base.String(), ListenerAddr: addr, TLSPin: hex.EncodeToString(pinB),
		DashboardKey: base64.StdEncoding.EncodeToString(dk), KeyID: *keyID, AllowedPaths: allowed}
	cfgJSON, _ := json.MarshalIndent(cfg, "", "  ")
	if err := writeRootFile(*configDir, "config.json", append(cfgJSON, '\n'), 0o600); err != nil {
		return err
	}
	seed := base64.StdEncoding.EncodeToString(priv.Seed()) + "\n"
	if err := writeRootFile(*configDir, "agent.key", []byte(seed), 0o600); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(addr)
	if err := writeRootFile(*unitDir, "asset-monitor-agent.service", []byte(renderUnit(allowed, host)), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "\nEnrollment sent. Agent key fingerprint: %s\nConfirm it in the dashboard, then run: systemctl enable --now asset-monitor-agent\n", fingerprint(pub))
	return nil
}

// repin pins a new Dashboard key and key id after Rotate Dashboard key. It keeps the Agent key,
// the sequences and everything else.
func repin(args []string, stdout, stderr io.Writer) error {
	fl := flag.NewFlagSet("repin", flag.ContinueOnError)
	fl.SetOutput(stderr)
	key := fl.String("key", "", "the new Dashboard key's public half (base64 or hex)")
	keyID := fl.String("key-id", "", "the new Dashboard key id")
	configDir := fl.String("config-dir", defaultConfigDir, "configuration directory (tests only)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	if fl.NArg() > 0 || !idPattern.MatchString(*keyID) {
		return errors.New("usage: repin --key KEY --key-id ID")
	}
	dk, err := decode32(*key)
	if err != nil {
		return fmt.Errorf("--key: %w", err)
	}
	data, err := os.ReadFile(filepath.Join(*configDir, "config.json"))
	if err != nil {
		return err
	}
	var cfg localConfig
	if err := json.Unmarshal(data, &cfg); err != nil || cfg.AgentID == "" {
		return errors.New("config.json is not an enrolled agent's")
	}
	cfg.DashboardKey, cfg.KeyID = base64.StdEncoding.EncodeToString(dk), *keyID
	cfgJSON, _ := json.MarshalIndent(cfg, "", "  ")
	if err := writeRootFile(*configDir, "config.json", append(cfgJSON, '\n'), 0o600); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "Dashboard key %s pinned. Run: systemctl restart asset-monitor-agent\n", *keyID)
	return nil
}

// writeRootFile atomically writes a root-owned file.
func writeRootFile(dir, name string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, "."+name+".*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err := f.Chown(0, 0); err != nil {
		f.Close()
		return fmt.Errorf("enroll must run as root: %w", err)
	}
	if err := f.Chmod(mode); err != nil {
		f.Close()
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), filepath.Join(dir, name))
}

func renderUnit(allowed []string, listenerIP string) string {
	var b strings.Builder
	b.WriteString(`[Unit]
Description=GarudaNetra On-server agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=` + binaryPath + ` run
Restart=on-failure
RestartSec=10s
StateDirectory=asset-monitor-agent
StateDirectoryMode=0700
ProtectSystem=strict
`)
	for _, a := range allowed {
		b.WriteString("ReadWritePaths=-" + a + "\n")
	}
	b.WriteString(`NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
SystemCallFilter=@system-service
UMask=0077
CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_FOWNER CAP_CHOWN
AmbientCapabilities=
RestrictAddressFamilies=AF_INET AF_INET6
IPAddressDeny=any
IPAddressAllow=` + listenerIP + `

[Install]
WantedBy=multi-user.target
`)
	return b.String()
}

// --- run ---

type configBody struct {
	WatchedRoots          []string `json:"watched_roots"`
	ReportIntervalSeconds int64    `json:"report_interval_seconds"`
	PollIntervalSeconds   int64    `json:"poll_interval_seconds"`
}

type state struct {
	ConfigSequence  int64       `json:"config_sequence"`
	CommandSequence int64       `json:"command_sequence"`
	ReportSequence  int64       `json:"report_sequence"`
	Configuration   *configBody `json:"configuration,omitempty"`
}

type commandBody struct {
	CommandID string `json:"command_id"`
	Name      string `json:"name"`
	Files     []struct {
		Root   string `json:"root"`
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	} `json:"files"`
	Entries []string `json:"entries"`
}

type wantedList struct {
	ReportSequence int64    `json:"report_sequence"`
	SHA256         []string `json:"sha256"`
}

type pollAnswer struct {
	Configuration *envelope   `json:"configuration"`
	Commands      []envelope  `json:"commands"`
	Wanted        *wantedList `json:"wanted"`
}

type result struct {
	Type      string       `json:"type"` // configuration | command
	Sequence  int64        `json:"sequence"`
	CommandID string       `json:"command_id,omitempty"`
	Name      string       `json:"name,omitempty"`
	Status    string       `json:"status"` // done | refused
	Reason    string       `json:"reason,omitempty"`
	Files     []fileResult `json:"files,omitempty"`
}

type uploadFile struct {
	SHA256  string `json:"sha256"`
	Content string `json:"content_b64"`
}

type skippedFile struct {
	SHA256 string `json:"sha256"`
	Reason string `json:"reason"`
}

type upload struct {
	ReportSequence int64         `json:"report_sequence"`
	Files          []uploadFile  `json:"files"`
	Skipped        []skippedFile `json:"skipped"`
	Complete       bool          `json:"complete"`
}

type agent struct {
	cfg      localConfig
	key      ed25519.PrivateKey
	dashKey  ed25519.PublicKey
	stateDir string
	client   *http.Client
	base     *url.URL
	vault    *vault
	st       state
	now      func() time.Time
	logf     func(string, ...any)

	lastReport  time.Time
	reportWhy   string
	manifest    map[string][]loc
	manifestSeq int64
	wantedDone  int64
	refused     map[string]bool
	refusals    int // refusal results sent during this poll
}

func runCmd(args []string) error {
	fl := flag.NewFlagSet("run", flag.ContinueOnError)
	configDir := fl.String("config-dir", defaultConfigDir, "configuration directory (tests only)")
	stateDir := fl.String("state-dir", defaultStateDir, "state directory (tests only)")
	if err := fl.Parse(args); err != nil {
		return err
	}
	a, err := loadAgent(*configDir, *stateDir)
	if err != nil {
		return err
	}
	a.vault.recover(a.logf)
	for {
		a.pollOnce(context.Background())
		time.Sleep(a.pollInterval())
	}
}

func loadAgent(configDir, stateDir string) (*agent, error) {
	var cfg localConfig
	data, err := os.ReadFile(filepath.Join(configDir, "config.json"))
	if err != nil {
		return nil, err
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	seedTxt, err := os.ReadFile(filepath.Join(configDir, "agent.key"))
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(seedTxt)))
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("bad agent.key")
	}
	pin, err := decode32(cfg.TLSPin)
	if err != nil {
		return nil, err
	}
	dk, err := decode32(cfg.DashboardKey)
	if err != nil {
		return nil, err
	}
	base, err := url.Parse(cfg.URL)
	if err != nil || base.Scheme != "https" {
		return nil, errors.New("bad url in config.json")
	}
	v, err := openVault(stateDir)
	if err != nil {
		return nil, err
	}
	a := &agent{cfg: cfg, key: ed25519.NewKeyFromSeed(seed), dashKey: dk, stateDir: stateDir,
		client: pinnedClient(cfg.ListenerAddr, pin), base: base, vault: v, now: time.Now,
		logf: log.Printf, refused: map[string]bool{}}
	if data, err := os.ReadFile(filepath.Join(stateDir, "state.json")); err == nil {
		if err := json.Unmarshal(data, &a.st); err != nil {
			return nil, fmt.Errorf("state.json: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return a, nil
}

func (a *agent) saveState() error {
	data, _ := json.Marshal(a.st)
	tmp := filepath.Join(a.stateDir, "state.json.tmp")
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(a.stateDir, "state.json"))
}

func (a *agent) pollInterval() time.Duration {
	if a.st.Configuration == nil || a.st.Configuration.PollIntervalSeconds <= 0 {
		return defaultPoll
	}
	return max(time.Duration(a.st.Configuration.PollIntervalSeconds)*time.Second, minPoll)
}

// checkRoot accepts a Watched root only inside an Allowed path, past the B03 refusals,
// in the current configuration, and as its own real path.
func (a *agent) checkRoot(root string) error {
	if a.st.Configuration == nil || !slices.Contains(a.st.Configuration.WatchedRoots, root) {
		return errors.New("not a Watched root of the current configuration")
	}
	return a.checkAllowedRoot(root)
}

func (a *agent) checkAllowedRoot(root string) error {
	if !slices.ContainsFunc(a.cfg.AllowedPaths, func(p string) bool { return within(root, p) }) {
		return errors.New("outside the Allowed paths")
	}
	if err := refusePath(root, a.stateDir); err != nil {
		return err
	}
	if real, err := filepath.EvalSymlinks(root); err != nil || real != root {
		return errors.New("not its own real path")
	}
	return nil
}

func (a *agent) call(method, pathQuery string, in, out any) error {
	return call(a.client, a.key, a.cfg.AgentID, method, a.base, pathQuery, in, out, a.now())
}

// refuse reports a refused signed message once per distinct envelope, and never for
// a re-delivery of a command this process already ran.
func (a *agent) refuse(env envelope, typ string, m *message, reason string) {
	k := typ + env.Payload + env.Signature
	if a.refused[k] {
		return
	}
	if a.refusals >= maxRefusalsPerPoll {
		return // the rest are answered at a later poll
	}
	a.refusals++
	if len(a.refused) >= maxRefusedKept {
		clear(a.refused) // ponytail: bounded memory; a forgotten refusal may be sent once more
	}
	a.refused[k] = true
	r := result{Type: typ, Status: "refused", Reason: reason}
	if m != nil {
		r.Sequence = m.Sequence
		var cb commandBody
		if typ == "command" && json.Unmarshal(m.Body, &cb) == nil {
			r.CommandID, r.Name = cb.CommandID, cb.Name
		}
	}
	a.logf("refused %s (sequence %d): %s", typ, r.Sequence, reason)
	a.postResult(r)
}

// postResult sends a result within B01's 64 KiB cap: files[i] answers the command's
// files[i] or entries[i], so paths and details are dropped first when it would not fit.
func (a *agent) postResult(r result) {
	if b, _ := json.Marshal(r); len(b) > maxSmallBody {
		for i := range r.Files {
			r.Files[i].Root, r.Files[i].Path, r.Files[i].Detail = "", "", ""
		}
	}
	if err := a.call(http.MethodPost, "/agent/v1/result", r, nil); err != nil {
		a.logf("result: %v", err)
	}
}

func (a *agent) pollOnce(ctx context.Context) {
	a.refusals = 0
	q := fmt.Sprintf("/agent/v1/poll?config_sequence=%d&command_sequence=%d&report_sequence=%d",
		a.st.ConfigSequence, a.st.CommandSequence, a.st.ReportSequence)
	var ans pollAnswer
	if err := a.call(http.MethodGet, q, nil, &ans); err != nil {
		a.logf("poll: %v", err)
		return
	}
	if ans.Configuration != nil {
		a.applyConfiguration(*ans.Configuration)
	}
	type verified struct {
		m   *message
		env envelope
	}
	var cmds []verified
	for _, env := range ans.Commands {
		m, err := verifyMessage(env, a.dashKey, a.cfg.KeyID, a.cfg.AgentID, "command", a.st.CommandSequence, a.now())
		if err != nil {
			a.refuse(env, "command", m, err.Error())
			continue
		}
		cmds = append(cmds, verified{m, env})
	}
	sort.Slice(cmds, func(i, j int) bool { return cmds[i].m.Sequence < cmds[j].m.Sequence })
	for _, c := range cmds {
		if c.m.Sequence <= a.st.CommandSequence {
			a.refuse(c.env, "command", c.m, errNotNewer.Error())
			continue
		}
		a.runCommand(c.env, c.m)
	}
	if a.st.Configuration != nil && a.reportWhy == "" && a.st.Configuration.ReportIntervalSeconds > 0 &&
		a.now().Sub(a.lastReport) >= time.Duration(a.st.Configuration.ReportIntervalSeconds)*time.Second {
		a.reportWhy = "scheduled"
	}
	if a.reportWhy != "" && a.st.Configuration != nil {
		a.sendReport(ctx)
	}
	if ans.Wanted != nil {
		a.sendWanted(*ans.Wanted)
	}
}

func (a *agent) applyConfiguration(env envelope) {
	m, err := verifyMessage(env, a.dashKey, a.cfg.KeyID, a.cfg.AgentID, "configuration", a.st.ConfigSequence, a.now())
	if errors.Is(err, errNotNewer) && m.Sequence == a.st.ConfigSequence {
		return // the configuration already held
	}
	if err != nil {
		a.refuse(env, "configuration", m, err.Error())
		return
	}
	var c configBody
	if err := json.Unmarshal(m.Body, &c); err != nil || len(c.WatchedRoots) == 0 || c.ReportIntervalSeconds < 0 {
		a.refuse(env, "configuration", m, "bad_body")
		return
	}
	for _, r := range c.WatchedRoots {
		if err := a.checkAllowedRoot(r); err != nil {
			a.refuse(env, "configuration", m, "watched_root_refused: "+r+": "+err.Error())
			return
		}
	}
	a.st.ConfigSequence, a.st.Configuration = m.Sequence, &c
	if err := a.saveState(); err != nil {
		a.logf("state: %v", err)
	}
	a.reportWhy = "configuration"
	a.postResult(result{Type: "configuration", Sequence: m.Sequence, Status: "done"})
}

func (a *agent) runCommand(env envelope, m *message) {
	// The sequence is spent before running, so a replay can never run a command twice.
	a.st.CommandSequence = m.Sequence
	a.refused["command"+env.Payload+env.Signature] = true // its re-delivery is silent
	if err := a.saveState(); err != nil {
		a.logf("state: %v", err)
		return
	}
	var c commandBody
	err := json.Unmarshal(m.Body, &c)
	r := result{Type: "command", Sequence: m.Sequence, CommandID: c.CommandID, Name: c.Name, Status: "done"}
	switch {
	case err != nil || !idPattern.MatchString(c.CommandID):
		r.Status, r.Reason = "refused", "bad_body"
	case len(c.Files) > maxCmdFiles || len(c.Entries) > maxCmdFiles:
		r.Status, r.Reason = "refused", "too_many_files"
	case c.Name == "rescan":
	case c.Name == "quarantine":
		for _, f := range c.Files {
			if !validRel(f.Path) || len(f.SHA256) != 64 || strings.Trim(f.SHA256, "0123456789abcdef") != "" {
				r.Files = append(r.Files, fileResult{Root: f.Root, Path: f.Path, SHA256: f.SHA256, Status: "failed", Detail: "bad path or sha256"})
				continue
			}
			if err := a.checkRoot(f.Root); err != nil {
				r.Files = append(r.Files, fileResult{Root: f.Root, Path: f.Path, SHA256: f.SHA256, Status: "failed", Detail: err.Error()})
				continue
			}
			r.Files = append(r.Files, a.vault.quarantine(f.Root, f.Path, f.SHA256, a.now()))
		}
	case c.Name == "restore":
		for _, id := range c.Entries {
			r.Files = append(r.Files, a.vault.restore(id, a.checkRoot))
		}
	default:
		r.Status, r.Reason = "refused", "unknown_command"
	}
	if r.Status == "done" {
		a.reportWhy = c.Name // rescan, and the rescan after a Quarantine or Restore
	}
	a.postResult(r)
}

func (a *agent) sendReport(ctx context.Context) {
	started := a.now()
	rep, index := walk(ctx, a.st.Configuration.WatchedRoots, a.checkRoot)
	a.st.ReportSequence++
	if err := a.saveState(); err != nil {
		a.logf("state: %v", err)
		return
	}
	rep.Sequence, rep.ConfigSequence, rep.Reason = a.st.ReportSequence, a.st.ConfigSequence, a.reportWhy
	rep.StartedAt, rep.FinishedAt = started.Unix(), a.now().Unix()
	if body, _ := json.Marshal(rep); len(body) > maxReportBody {
		rep.Roots, rep.OverLimit, index = []rootManifest{}, true, map[string][]loc{}
		rep.Issues = append(rep.Issues, issue{Reason: "report_too_large"})
	}
	a.reportWhy, a.lastReport = "", a.now()
	a.manifest, a.manifestSeq = index, rep.Sequence
	if err := a.call(http.MethodPost, "/agent/v1/report", rep, nil); err != nil {
		a.logf("report %d: %v", rep.Sequence, err)
	}
}

// sendWanted uploads the bytes the unsigned wanted list asks for, from the latest manifest only.
func (a *agent) sendWanted(w wantedList) {
	if a.manifest == nil || w.ReportSequence != a.manifestSeq || w.ReportSequence == a.wantedDone {
		return
	}
	up := upload{ReportSequence: w.ReportSequence, Files: []uploadFile{}, Skipped: []skippedFile{}}
	size, seen := 0, map[string]bool{}
	for _, sum := range w.SHA256 {
		if seen[sum] {
			continue
		}
		seen[sum] = true
		if len(sum) != 64 || strings.Trim(sum, "0123456789abcdef") != "" {
			continue
		}
		data, why := readWanted(sum, a.manifest, a.checkRoot)
		enc := base64.StdEncoding.EncodeToString(data)
		item := len(enc) + 128 // 128 bounds one entry's JSON around its content
		if size+item > maxUploadBody-(64<<10) && len(up.Files)+len(up.Skipped) > 0 {
			if err := a.call(http.MethodPost, "/agent/v1/upload", up, nil); err != nil {
				a.logf("upload: %v", err)
				return
			}
			up.Files, up.Skipped, size = []uploadFile{}, []skippedFile{}, 0
		}
		if why != "" {
			up.Skipped = append(up.Skipped, skippedFile{sum, why})
		} else {
			up.Files = append(up.Files, uploadFile{sum, enc})
		}
		size += item
	}
	up.Complete = true
	if err := a.call(http.MethodPost, "/agent/v1/upload", up, nil); err != nil {
		a.logf("upload: %v", err)
		return
	}
	a.wantedDone = w.ReportSequence
}
