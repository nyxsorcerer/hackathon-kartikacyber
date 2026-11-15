package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"debug/elf"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func seed(start byte) []byte {
	b := make([]byte, 32)
	for i := range b {
		b[i] = start + byte(i)
	}
	return b
}

var (
	testAgentKey = ed25519.NewKeyFromSeed(seed(0))
	testDashKey  = ed25519.NewKeyFromSeed(seed(0x20))
	testNow      = time.Unix(1763200000, 0)
)

func sha(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func signEnv(key ed25519.PrivateKey, m message) envelope {
	p, _ := json.Marshal(m)
	return envelope{Payload: base64.StdEncoding.EncodeToString(p), KeyID: m.KeyID,
		Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(key, messageBytes(p)))}
}

func cfgMsg(seq int64, roots ...string) message {
	b, _ := json.Marshal(configBody{WatchedRoots: roots, ReportIntervalSeconds: 0, PollIntervalSeconds: 2})
	return message{V: 1, Type: "configuration", AgentID: "agent-1", KeyID: "dk-1", Sequence: seq, IssuedAt: testNow.Unix(), Body: b}
}

func cmdMsg(seq int64, body string) message {
	return message{V: 1, Type: "command", AgentID: "agent-1", KeyID: "dk-1", Sequence: seq, IssuedAt: testNow.Unix(),
		ExpiresAt: testNow.Add(15 * time.Minute).Unix(), Body: json.RawMessage(body)}
}

// verifySigned is what the agent listener does: it checks the PROTOCOL.md headers and signature.
func verifySigned(r *http.Request, pub ed25519.PublicKey) ([]byte, error) {
	body, _ := io.ReadAll(r.Body)
	if r.Header.Get("X-Agent-Content-SHA256") != sha(body) {
		return nil, errors.New("body hash")
	}
	ts, _ := strconv.ParseInt(r.Header.Get("X-Agent-Timestamp"), 10, 64)
	sig, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Agent-Signature"))
	if !ed25519.Verify(pub, canonicalRequest(r.Method, r.URL.RequestURI(), ts, r.Header.Get("X-Agent-Nonce"), body), sig) {
		return nil, errors.New("signature")
	}
	return body, nil
}

func pinOf(srv *httptest.Server) []byte {
	s := sha256.Sum256(srv.Certificate().RawSubjectPublicKeyInfo)
	return s[:]
}

// --- protocol vectors (also in PROTOCOL.md) ---

func TestRequestSignatureVector(t *testing.T) {
	if got := base64.StdEncoding.EncodeToString(testAgentKey.Public().(ed25519.PublicKey)); got != "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=" {
		t.Fatalf("public key %s", got)
	}
	if fp := fingerprint(testAgentKey.Public().(ed25519.PublicKey)); fp != "sha256:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c" {
		t.Fatalf("fingerprint %s", fp)
	}
	c := canonicalRequest("POST", "/agent/v1/report", 1763200000, "00112233445566778899aabbccddeeff", []byte(`{"sequence":1}`))
	want := "asset-monitor-agent-request-v1\nPOST\n/agent/v1/report\n1763200000\n00112233445566778899aabbccddeeff\n603ff4b70ceeeda2a87631465b1a7089df62b5d48e4426d1bbe9bd2c219f0bfd"
	if string(c) != want {
		t.Fatalf("canonical form %q", c)
	}
	if s := base64.StdEncoding.EncodeToString(ed25519.Sign(testAgentKey, c)); s != "KDJeQWvVYRHhQWv9RAPqs2gw0KOyJufUrC4zZmTmUhe24yle96ZWuN8sX6cUD+wC9UQqeMlzpfzd65s4ioc1Aw==" {
		t.Fatalf("signature %s", s)
	}
	c = canonicalRequest("GET", "/agent/v1/poll?config_sequence=0&command_sequence=0&report_sequence=0", 1763200000, "00112233445566778899aabbccddeeff", nil)
	if s := base64.StdEncoding.EncodeToString(ed25519.Sign(testAgentKey, c)); s != "wZPPf2T6G3h/UKohvxV0EftI5ows1XxjkUKpGvJjcK3JZNyC2L6wNph00YwQGLSltvcSHDWIb2wdGdq1YthNBw==" {
		t.Fatalf("poll signature %s", s)
	}
	inDoc(t, "| Agent public key | `A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=` |",
		"| Agent fingerprint | `sha256:56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c` |",
		"- Signed bytes: `"+strings.ReplaceAll(want, "\n", `\n`)+"`", "- Signature: `KDJeQWvVYRHhQWv9RAPqs2gw0KOyJufUrC4zZmTmUhe24yle96ZWuN8sX6cUD+wC9UQqeMlzpfzd65s4ioc1Aw==`",
		"`/agent/v1/poll?config_sequence=0&command_sequence=0&report_sequence=0`", "- Signature: `wZPPf2T6G3h/UKohvxV0EftI5ows1XxjkUKpGvJjcK3JZNyC2L6wNph00YwQGLSltvcSHDWIb2wdGdq1YthNBw==`",
		"Body SHA-256: `"+sha([]byte(`{"sequence":1}`))+"`", "nonce `00112233445566778899aabbccddeeff` and body `{\"sequence\":1}`")
	// The headers the agent sets verify the same way, and cover the query string.
	base, _ := url.Parse("https://127.0.0.1:8792")
	req, err := signedRequest(testAgentKey, "agent-1", "GET", base, "/agent/v1/poll?a=1", nil, testNow)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifySigned(req, testAgentKey.Public().(ed25519.PublicKey)); err != nil {
		t.Fatal(err)
	}
	req.URL.RawQuery = "a=2"
	if _, err := verifySigned(req, testAgentKey.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("a changed query string still verified")
	}
}

func TestSignedMessageVector(t *testing.T) {
	pub := testDashKey.Public().(ed25519.PublicKey)
	if got := base64.StdEncoding.EncodeToString(pub); got != "Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=" {
		t.Fatalf("dashboard key %s", got)
	}
	env := envelope{KeyID: "dk-1",
		Payload:   "eyJ2IjoxLCJ0eXBlIjoiY29uZmlndXJhdGlvbiIsImFnZW50X2lkIjoiYWdlbnQtMSIsImtleV9pZCI6ImRrLTEiLCJzZXF1ZW5jZSI6MSwiaXNzdWVkX2F0IjoxNzYzMjAwMDAwLCJleHBpcmVzX2F0IjowLCJib2R5Ijp7IndhdGNoZWRfcm9vdHMiOlsiL3Zhci93d3cvaHRtbCJdLCJyZXBvcnRfaW50ZXJ2YWxfc2Vjb25kcyI6MzYwMCwicG9sbF9pbnRlcnZhbF9zZWNvbmRzIjozMH19",
		Signature: "MX3Av+7cgGwi9rdyvFlxlhA0BK26jLU0GHr2Nx8unhd6Oio6ye5eUHEQzUg8qhdXHoH7Ar9hHvKa7JOhU9FmBA=="}
	m, err := verifyMessage(env, pub, "dk-1", "agent-1", "configuration", 0, testNow)
	if err != nil || m.Sequence != 1 {
		t.Fatal(err)
	}
	cmd := envelope{KeyID: "dk-1",
		Payload:   "eyJ2IjoxLCJ0eXBlIjoiY29tbWFuZCIsImFnZW50X2lkIjoiYWdlbnQtMSIsImtleV9pZCI6ImRrLTEiLCJzZXF1ZW5jZSI6MiwiaXNzdWVkX2F0IjoxNzYzMjAwMDAwLCJleHBpcmVzX2F0IjoxNzYzMjAwOTAwLCJib2R5Ijp7ImNvbW1hbmRfaWQiOiJjbWQtMSIsIm5hbWUiOiJyZXNjYW4ifX0=",
		Signature: "LkOZ3EVu20RTFtqA5OqTyUV4lwnYngVuXbflAsbJFUqAFEk+Y8cnNOStls95eB7Xc+DoILRamQnUtaZt0BDdCg=="}
	if _, err := verifyMessage(cmd, pub, "dk-1", "agent-1", "command", 0, testNow); err != nil {
		t.Fatal(err)
	}
	// The payload bytes, on their own line, and the signatures are the ones PROTOCOL.md prints.
	inDoc(t, "| Dashboard public key | `Kay64UG8yvCyLhqU000LxzYeUm0L/hLIl5S8kyKWbdc=` |", "\n"+mustB64(env.Payload)+"\n",
		"- `payload`: `"+env.Payload+"`", "- `signature`: `"+env.Signature+"`", "\n"+mustB64(cmd.Payload)+"\n", "- `signature`: `"+cmd.Signature+"`", "`asset-monitor-dashboard-message-v1` + `\\n` + the payload bytes")
}

// inDoc fails unless PROTOCOL.md holds each string verbatim, so the document cannot drift from the tests.
func inDoc(t *testing.T, want ...string) {
	t.Helper()
	doc, err := os.ReadFile("PROTOCOL.md")
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range want {
		if !strings.Contains(string(doc), w) {
			t.Errorf("PROTOCOL.md lacks %q", w)
		}
	}
}

// --- Dashboard key pin, sequence order and expiry ---

func TestDashboardKeyPinAndOrder(t *testing.T) {
	pub := testDashKey.Public().(ed25519.PublicKey)
	other := ed25519.NewKeyFromSeed(seed(0x40))
	check := func(env envelope, typ string, last int64, now time.Time, want string) {
		t.Helper()
		_, err := verifyMessage(env, pub, "dk-1", "agent-1", typ, last, now)
		if (err == nil && want != "") || (err != nil && err.Error() != want) {
			t.Fatalf("want %q, got %v", want, err)
		}
	}
	check(signEnv(testDashKey, cfgMsg(5, "/srv")), "configuration", 4, testNow, "")
	check(signEnv(other, cfgMsg(5, "/srv")), "configuration", 4, testNow, "bad_signature")
	m := cfgMsg(5, "/srv")
	m.KeyID = "dk-2"
	check(signEnv(testDashKey, m), "configuration", 4, testNow, "unknown_key_id")
	m = cfgMsg(5, "/srv")
	m.AgentID = "agent-2"
	check(signEnv(testDashKey, m), "configuration", 4, testNow, "wrong_agent")
	check(signEnv(testDashKey, cfgMsg(5, "/srv")), "command", 4, testNow, "wrong_type")
	// Older or equal configuration and command are refused.
	check(signEnv(testDashKey, cfgMsg(4, "/srv")), "configuration", 5, testNow, "not_newer")
	check(signEnv(testDashKey, cfgMsg(5, "/srv")), "configuration", 5, testNow, "not_newer")
	check(signEnv(testDashKey, cmdMsg(3, `{}`)), "command", 3, testNow, "not_newer")
	// Expiry.
	check(signEnv(testDashKey, cmdMsg(4, `{}`)), "command", 3, testNow.Add(15*time.Minute), "expired")
	long := cmdMsg(4, `{}`)
	long.ExpiresAt = testNow.Add(24 * time.Hour).Unix()
	check(signEnv(testDashKey, long), "command", 3, testNow, "expiry_too_far")
	noExp := cmdMsg(4, `{}`)
	noExp.ExpiresAt = 0
	check(signEnv(testDashKey, noExp), "command", 3, testNow, "no_expiry")
	// A tampered payload does not verify.
	env := signEnv(testDashKey, cfgMsg(5, "/srv"))
	env.Payload = base64.StdEncoding.EncodeToString([]byte(strings.Replace(mustB64(env.Payload), `"/srv"`, `"/srx"`, 1)))
	check(env, "configuration", 4, testNow, "bad_signature")
}

func mustB64(s string) string { b, _ := base64.StdEncoding.DecodeString(s); return string(b) }

// --- transport ---

func TestTLSPin(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(`{}`)) }))
	defer srv.Close()
	base, _ := url.Parse(srv.URL)
	addr := srv.Listener.Addr().String()
	if err := call(pinnedClient(addr, pinOf(srv)), testAgentKey, "agent-1", "GET", base, "/agent/v1/poll", nil, nil, testNow); err != nil {
		t.Fatal(err)
	}
	wrong := make([]byte, 32)
	err := call(pinnedClient(addr, wrong), testAgentKey, "agent-1", "GET", base, "/agent/v1/poll", nil, nil, testNow)
	if err == nil || !strings.Contains(err.Error(), "TLS pin") {
		t.Fatalf("a wrong pin was accepted: %v", err)
	}
	// Plain http is never spoken.
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer plain.Close()
	pbase, _ := url.Parse(strings.Replace(plain.URL, "http:", "https:", 1))
	if err := call(pinnedClient(plain.Listener.Addr().String(), wrong), testAgentKey, "a", "GET", pbase, "/x", nil, nil, testNow); err == nil {
		t.Fatal("plain http accepted")
	}
	if _, _, err := checkURL(strings.Replace(srv.URL, "https:", "http:", 1), systemLookup); err == nil {
		t.Fatal("http URL accepted")
	}
}

func TestURLRules(t *testing.T) {
	fake := func(m map[string][]string) lookupFunc {
		return func(_ context.Context, h string) ([]netip.Addr, error) {
			var out []netip.Addr
			for _, s := range m[h] {
				out = append(out, netip.MustParseAddr(s))
			}
			return out, nil
		}
	}
	lk := fake(map[string][]string{"agent.lan": {"10.1.2.3"}, "evil": {"10.0.0.1", "93.184.216.34"}, "pub": {"1.1.1.1"}, "v6": {"fd00::1"}})
	for raw, wantAddr := range map[string]string{
		"https://127.0.0.1:8792":  "127.0.0.1:8792",
		"https://127.0.0.1:8792/": "127.0.0.1:8792",
		"https://agent.lan":       "10.1.2.3:443",
		"https://v6:9000":         "[fd00::1]:9000",
		"https://192.168.1.4:1":   "192.168.1.4:1",
		"https://[::1]:8792":      "[::1]:8792",
	} {
		_, addr, err := checkURL(raw, lk)
		if err != nil || addr != wantAddr {
			t.Fatalf("%s: %s %v", raw, addr, err)
		}
	}
	for _, raw := range []string{"http://127.0.0.1:8792", "https://8.8.8.8", "https://pub", "https://evil", "https://user@127.0.0.1",
		"https://127.0.0.1/x", "https://127.0.0.1?q", "https://169.254.1.1", "https://0.0.0.0", "https://127.0.0.1:0", "https://[fe80::1%25eth0]"} {
		if _, _, err := checkURL(raw, lk); err == nil {
			t.Fatalf("%s accepted", raw)
		}
	}
}

// --- Allowed paths ---

func TestAllowedPathRefusals(t *testing.T) {
	tmp := t.TempDir()
	state := filepath.Join(tmp, "state")
	os.MkdirAll(filepath.Join(state, "quarantine", "inner"), 0o700)
	www := filepath.Join(tmp, "www")
	os.Mkdir(www, 0o755)
	os.Symlink("/etc", filepath.Join(tmp, "etc-link"))
	for _, p := range []string{"/", "/etc", "/etc/ssl", "/var", "/usr/local", "/var/lib", "/var/lib/asset-monitor-agent", "/run", "/proc/1",
		state, filepath.Join(state, "quarantine"), filepath.Join(state, "quarantine", "inner"), tmp, filepath.Join(tmp, "etc-link"), "relative/path"} {
		if _, err := resolveAllowed(p, state, filepath.Join(state, "quarantine")); err == nil {
			t.Fatalf("--allow %s accepted", p)
		}
	}
	got, err := resolveAllowed(www, state)
	if err != nil || got != www {
		t.Fatalf("%s: %v", got, err)
	}
	// The agent refuses a Watched root outside its Allowed paths.
	a := &agent{cfg: localConfig{AllowedPaths: []string{www}}, stateDir: state}
	if a.checkAllowedRoot(tmp) == nil || a.checkAllowedRoot("/etc") == nil || a.checkAllowedRoot(www) != nil {
		t.Fatal("watched root check")
	}
}

// --- the walk, the secret list and links ---

func writeTree(t *testing.T, root string, files map[string]string) {
	t.Helper()
	for p, c := range files {
		full := filepath.Join(root, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		if err := os.WriteFile(full, []byte(c), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestSecretListAndLinks(t *testing.T) {
	for _, p := range []string{"/w/.env", "/w/.env.local", "/w/wp-config.php", "/w/.git/config", "/w/a/.ssh/x", "/w/id_rsa", "/w/dump.sql.gz",
		"/w/x.PEM", "/w/sites/default/settings.php", "/w/app/etc/env.php", "/w/LocalSettings.php", "/w/.bash_history", "/w/data.sqlite"} {
		if !isSecret(p) {
			t.Fatalf("%s not secret", p)
		}
	}
	for _, p := range []string{"/w/index.php", "/w/id_rsa.pub", "/w/settings.php", "/w/environment.php"} {
		if isSecret(p) {
			t.Fatalf("%s secret", p)
		}
	}

	tmp := t.TempDir()
	www, outside := filepath.Join(tmp, "www"), filepath.Join(tmp, "outside")
	writeTree(t, www, map[string]string{"index.php": "<?php echo 1;", ".env": "DB_PASS=hunter2", "wp-config.php": "secret", ".git/config": "[core]", "same.txt": "DB_PASS=hunter2"})
	writeTree(t, outside, map[string]string{"shadow": "root:x", "dir/f": "outside bytes"})
	os.Symlink(filepath.Join(outside, "shadow"), filepath.Join(www, "link-file"))
	os.Symlink(filepath.Join(outside, "dir"), filepath.Join(www, "link-dir"))
	ok := func(string) error { return nil }
	rep, index := walk(context.Background(), []string{www}, ok)
	byPath := map[string]entry{}
	for _, e := range rep.Roots[0].Entries {
		byPath[e.Path] = e
	}
	if e := byPath["link-file"]; e.Type != "symlink" || e.Target != filepath.Join(outside, "shadow") || e.SHA256 != "" {
		t.Fatalf("link-file %+v", e)
	}
	if e := byPath["link-dir"]; e.Type != "symlink" || e.SHA256 != "" {
		t.Fatalf("link-dir %+v", e)
	}
	if _, followed := byPath["link-dir/f"]; followed || len(byPath) != 7 {
		t.Fatalf("walk followed a link: %v", byPath)
	}
	if !byPath[".env"].Secret || !byPath[".git/config"].Secret || byPath[".env"].SHA256 != sha([]byte("DB_PASS=hunter2")) {
		t.Fatal("secret files are reported by hash")
	}
	for _, s := range []string{sha([]byte("DB_PASS=hunter2")), sha([]byte("secret")), sha([]byte("[core]")), sha([]byte("root:x")), sha([]byte("outside bytes"))} {
		if data, why := readWanted(s, index, ok); data != nil || why == "" {
			t.Fatalf("%s uploaded", s)
		}
	}
	if data, why := readWanted(sha([]byte("<?php echo 1;")), index, ok); string(data) != "<?php echo 1;" {
		t.Fatal(why)
	}
	// Bytes changed since the manifest are not uploaded.
	os.WriteFile(filepath.Join(www, "index.php"), []byte("changed"), 0o644)
	if data, _ := readWanted(sha([]byte("<?php echo 1;")), index, ok); data != nil {
		t.Fatal("stale bytes uploaded")
	}
}

func TestManifestLimits(t *testing.T) {
	www := t.TempDir()
	writeTree(t, www, map[string]string{"a": "1", "b": "22", "c/d": "333"})
	defer func(f int, h int64) { maxFiles, hashLimit = f, h }(maxFiles, hashLimit)
	maxFiles = 2
	rep, _ := walk(context.Background(), []string{www}, func(string) error { return nil })
	if !rep.OverLimit || len(rep.Roots) != 0 || rep.FileCount != 3 {
		t.Fatalf("over-limit report %+v", rep)
	}
	maxFiles, hashLimit = 10, 1
	rep, _ = walk(context.Background(), []string{www}, func(string) error { return nil })
	if rep.OverLimit || len(rep.Roots[0].Entries) != 3 {
		t.Fatalf("%+v", rep)
	}
	for _, e := range rep.Roots[0].Entries {
		if (e.Size > 1) != (e.OverHashLimit && e.SHA256 == "") {
			t.Fatalf("hash limit %+v", e)
		}
	}
}

// --- Quarantine and Restore ---

func newVault(t *testing.T) (*vault, string) {
	state := filepath.Join(t.TempDir(), "state")
	v, err := openVault(state)
	if err != nil {
		t.Fatal(err)
	}
	return v, state
}

func TestQuarantineAndRestore(t *testing.T) {
	v, state := newVault(t)
	www := t.TempDir()
	writeTree(t, www, map[string]string{"wp-content/shell.php": "<?php system($_GET[1]);", "other.php": "keep"})
	shell := filepath.Join(www, "wp-content/shell.php")
	os.Chmod(shell, 0o755|fs.ModeSetuid)
	mtime := time.Unix(1700000000, 0)
	os.Chtimes(shell, mtime, mtime)
	sum := sha([]byte("<?php system($_GET[1]);"))

	// A hash mismatch moves nothing.
	if r := v.quarantine(www, "other.php", sum, testNow); r.Status != "hash_mismatch" {
		t.Fatal(r)
	}
	if r := v.quarantine(www, "missing.php", sum, testNow); r.Status != "not_present" {
		t.Fatal(r)
	}
	r := v.quarantine(www, "wp-content/shell.php", sum, testNow)
	if r.Status != "quarantined" {
		t.Fatal(r)
	}
	if _, err := os.Lstat(shell); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("file still at its path")
	}
	if left, _ := filepath.Glob(filepath.Join(www, "wp-content", ".am-aside-*")); len(left) != 0 {
		t.Fatal("aside name left")
	}
	copyPath := filepath.Join(state, "quarantine", r.QuarantineID+".bin")
	fi, err := os.Stat(copyPath)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("quarantined copy %v %v", fi, err)
	}
	if b, _ := os.ReadFile(copyPath); sha(b) != sum {
		t.Fatal("copy bytes")
	}
	m, err := v.meta(r.QuarantineID)
	if err != nil || m.Path != "wp-content/shell.php" || m.Mode != 0o4755 || m.MtimeNs != mtime.UnixNano() {
		t.Fatalf("metadata %+v %v", m, err)
	}

	// Restore never overwrites.
	ok := func(string) error { return nil }
	os.WriteFile(shell, []byte("new owner file"), 0o644)
	if rr := v.restore(r.QuarantineID, ok); rr.Status != "path_taken" {
		t.Fatal(rr)
	}
	if b, _ := os.ReadFile(shell); string(b) != "new owner file" {
		t.Fatal("restore overwrote a file")
	}
	os.Remove(shell)
	// Nor through a link.
	os.Symlink(filepath.Join(www, "other.php"), shell)
	if rr := v.restore(r.QuarantineID, ok); rr.Status != "path_taken" {
		t.Fatal(rr)
	}
	os.Remove(shell)
	if rr := v.restore(r.QuarantineID, func(string) error { return errors.New("not watched") }); rr.Status != "failed" {
		t.Fatal(rr)
	}
	if rr := v.restore(r.QuarantineID, ok); rr.Status != "restored" {
		t.Fatal(rr)
	}
	fi, err = os.Lstat(shell)
	if err != nil || fi.Mode().Perm() != 0o755 || fi.Mode()&fs.ModeSetuid != 0 || !fi.ModTime().Equal(mtime) {
		t.Fatalf("restored %v %v", fi.Mode(), err)
	}
	if b, _ := os.ReadFile(shell); sha(b) != sum {
		t.Fatal("restored bytes")
	}
	if _, err := os.Stat(copyPath); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("quarantined copy kept after restore")
	}
}

func TestQuarantineRefusesLinks(t *testing.T) {
	v, _ := newVault(t)
	tmp := t.TempDir()
	www, real := filepath.Join(tmp, "www"), filepath.Join(tmp, "real")
	writeTree(t, real, map[string]string{"shell.php": "x"})
	os.Mkdir(www, 0o755)
	os.Symlink(real, filepath.Join(www, "linked"))
	os.Symlink(filepath.Join(real, "shell.php"), filepath.Join(www, "file-link.php"))
	sum := sha([]byte("x"))
	if r := v.quarantine(www, "linked/shell.php", sum, testNow); r.Status != "link_refused" {
		t.Fatal(r)
	}
	if r := v.quarantine(www, "file-link.php", sum, testNow); r.Status != "link_refused" {
		t.Fatal(r)
	}
	if b, err := os.ReadFile(filepath.Join(real, "shell.php")); err != nil || string(b) != "x" {
		t.Fatal("link target touched")
	}
	if fi, err := os.Lstat(filepath.Join(www, "file-link.php")); err != nil || fi.Mode()&fs.ModeSymlink == 0 {
		t.Fatal("link moved")
	}
}

func TestJournalRecovery(t *testing.T) {
	v, state := newVault(t)
	www := t.TempDir()
	writeTree(t, www, map[string]string{"a.php": "aaa"})
	sum := sha([]byte("aaa"))
	// Stopped after the rename aside, before the copy verified: put back.
	os.Rename(filepath.Join(www, "a.php"), filepath.Join(www, ".am-aside-1"))
	m := qmeta{ID: strings.Repeat("1", 32), Root: www, Path: "a.php", SHA256: sum}
	v.journal(journalEntry{Op: "quarantine", Stage: "aside", Meta: m, Aside: ".am-aside-1"})
	os.WriteFile(filepath.Join(state, "quarantine", m.ID+".json"), []byte(`{}`), 0o600) // written just before the stop
	v.recover(t.Logf)
	if b, _ := os.ReadFile(filepath.Join(www, "a.php")); string(b) != "aaa" {
		t.Fatal("not put back")
	}
	if _, err := os.Stat(filepath.Join(state, "quarantine", m.ID+".json")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("an undone Quarantine left its record")
	}
	// Stopped after the copy verified, before the aside name was removed: finish.
	os.Rename(filepath.Join(www, "a.php"), filepath.Join(www, ".am-aside-2"))
	m.ID = strings.Repeat("2", 32)
	os.WriteFile(filepath.Join(state, "quarantine", m.ID+".bin"), []byte("aaa"), 0o600)
	v.journal(journalEntry{Op: "quarantine", Stage: "copied", Meta: m, Aside: ".am-aside-2"})
	v.recover(t.Logf)
	if _, err := os.Lstat(filepath.Join(www, ".am-aside-2")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("aside not removed")
	}
	if names, _ := os.ReadDir(filepath.Join(state, "journal")); len(names) != 0 {
		t.Fatal("journal not cleared")
	}
}

// --- run against a fake agent listener ---

type fakeListener struct {
	mu       sync.Mutex
	config   *envelope
	commands []envelope
	wanted   *wantedList
	reports  []report
	uploads  []upload
	upSizes  []int
	results  []result
	errs     []error
}

func (f *fakeListener) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	body, err := verifySigned(r, testAgentKey.Public().(ed25519.PublicKey))
	if err != nil || r.Header.Get("X-Agent-Id") != "agent-1" {
		f.errs = append(f.errs, err)
		http.Error(w, `{"error":"bad_signature"}`, 401)
		return
	}
	switch r.URL.Path {
	case "/agent/v1/poll":
		json.NewEncoder(w).Encode(pollAnswer{Configuration: f.config, Commands: f.commands, Wanted: f.wanted})
		f.commands = nil
	case "/agent/v1/report":
		var rep report
		json.Unmarshal(body, &rep)
		f.reports = append(f.reports, rep)
		f.wanted = &wantedList{ReportSequence: rep.Sequence}
		for _, rm := range rep.Roots {
			for _, e := range rm.Entries {
				if e.SHA256 != "" {
					f.wanted.SHA256 = append(f.wanted.SHA256, e.SHA256) // a hostile listener asks for everything
				}
			}
		}
		w.WriteHeader(202)
	case "/agent/v1/upload":
		var u upload
		json.Unmarshal(body, &u)
		f.uploads = append(f.uploads, u)
		f.upSizes = append(f.upSizes, len(body))
		w.WriteHeader(202)
	case "/agent/v1/result":
		var res result
		json.Unmarshal(body, &res)
		f.results = append(f.results, res)
		w.WriteHeader(202)
	default:
		http.Error(w, `{"error":"not_found"}`, 404)
	}
}

func snapshot(t *testing.T, root, skip string) map[string]string {
	out := map[string]string{}
	filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if p == skip {
			return fs.SkipDir
		}
		fi, _ := os.Lstat(p)
		v := fi.Mode().String() + fi.ModTime().String()
		if fi.Mode().IsRegular() {
			b, _ := os.ReadFile(p)
			v += sha(b)
		}
		out[p] = v
		return nil
	})
	return out
}

type runEnv struct {
	a                       *agent
	fl                      *fakeListener
	tmp, www, state, cfgDir string
	before                  map[string]string // the tree before loadAgent, state directory left out
}

// newRunEnv is an enrolled agent with Watched root www, holding files, and a fake listener.
func newRunEnv(t *testing.T, files map[string]string) runEnv {
	fl := &fakeListener{}
	srv := httptest.NewTLSServer(fl)
	t.Cleanup(srv.Close)
	tmp := t.TempDir()
	e := runEnv{fl: fl, tmp: tmp, www: filepath.Join(tmp, "www"), state: filepath.Join(tmp, "state"), cfgDir: filepath.Join(tmp, "etc")}
	writeTree(t, e.www, files)
	base, _ := url.Parse(srv.URL)
	cfg := localConfig{AgentID: "agent-1", URL: base.String(), ListenerAddr: srv.Listener.Addr().String(),
		TLSPin: base64.StdEncoding.EncodeToString(pinOf(srv)), KeyID: "dk-1", AllowedPaths: []string{e.www},
		DashboardKey: base64.StdEncoding.EncodeToString(testDashKey.Public().(ed25519.PublicKey))}
	cj, _ := json.Marshal(cfg)
	writeTree(t, e.cfgDir, map[string]string{"config.json": string(cj), "agent.key": base64.StdEncoding.EncodeToString(seed(0))})
	os.Mkdir(e.state, 0o700) // systemd's StateDirectory
	os.Symlink("/etc/passwd", filepath.Join(e.www, "passwd-link"))
	e.before = snapshot(t, tmp, e.state)
	a, err := loadAgent(e.cfgDir, e.state)
	if err != nil {
		t.Fatal(err)
	}
	a.now = func() time.Time { return testNow }
	a.logf = t.Logf
	e.a = a
	cfgEnv := signEnv(testDashKey, cfgMsg(3, e.www))
	fl.config = &cfgEnv
	return e
}

func TestRunCycle(t *testing.T) {
	e := newRunEnv(t, map[string]string{"index.php": "<?php echo 1;", ".env": "DB_PASS=x", ".git/HEAD": "ref", "big.bin": strings.Repeat("z", 2<<20)})
	a, fl, tmp, www, state, before := e.a, e.fl, e.tmp, e.www, e.state, e.before
	a.pollOnce(context.Background()) // accepts the configuration and reports
	a.pollOnce(context.Background()) // gets the wanted list and uploads
	if len(fl.reports) != 1 || fl.reports[0].Sequence != 1 || fl.reports[0].ConfigSequence != 3 {
		t.Fatalf("reports %+v", fl.reports)
	}
	if len(fl.uploads) != 1 || !fl.uploads[0].Complete || len(fl.uploads[0].Files) != 1 || mustB64(fl.uploads[0].Files[0].Content) != "<?php echo 1;" {
		t.Fatalf("uploads %+v", fl.uploads)
	}
	reasons := map[string]bool{}
	for _, s := range fl.uploads[0].Skipped {
		reasons[s.Reason] = true
	}
	if !reasons["secret"] || !reasons["too_large"] || len(fl.uploads[0].Skipped) != 3 {
		t.Fatalf("skipped %+v", fl.uploads[0].Skipped)
	}

	// An older configuration and a replayed command are refused; a rescan reports again.
	old := signEnv(testDashKey, cfgMsg(2, www))
	fl.config = &old
	fl.commands = []envelope{signEnv(testDashKey, cmdMsg(7, `{"command_id":"c7","name":"rescan"}`))}
	a.pollOnce(context.Background())
	fl.commands = []envelope{signEnv(testDashKey, cmdMsg(7, `{"command_id":"c7","name":"rescan"}`)), // re-delivery: silent
		signEnv(testDashKey, cmdMsg(6, `{"command_id":"c6","name":"rescan"}`)), // older: refused
		signEnv(testDashKey, cmdMsg(8, `{"command_id":"c8","name":"shell","cmd":"id"}`))}
	a.pollOnce(context.Background())
	if len(fl.reports) != 2 || fl.reports[1].Reason != "rescan" || fl.reports[1].Sequence != 2 {
		t.Fatalf("reports %+v", fl.reports)
	}
	var refused []string
	for _, r := range fl.results {
		if r.Status == "refused" {
			refused = append(refused, r.Type+":"+r.Reason)
		}
	}
	if !slices.Equal(refused, []string{"configuration:not_newer", "command:not_newer", "command:unknown_command"}) {
		t.Fatalf("refusals %v", refused)
	}
	if len(fl.errs) != 0 {
		t.Fatal(fl.errs)
	}
	// Sequences and the configuration are kept in the state directory.
	b, _ := os.ReadFile(filepath.Join(state, "state.json"))
	var st struct {
		ConfigSequence  int64 `json:"config_sequence"`
		CommandSequence int64 `json:"command_sequence"`
		ReportSequence  int64 `json:"report_sequence"`
	}
	json.Unmarshal(b, &st)
	if st.ConfigSequence != 3 || st.CommandSequence != 8 || st.ReportSequence != 2 {
		t.Fatalf("state %+v", st)
	}
	// run wrote nothing outside the state directory.
	if after := snapshot(t, tmp, state); !mapsEqual(before, after) {
		t.Fatal("run wrote outside the state directory")
	}

	// A signed Quarantine command moves the file, reports its result, then rescans.
	q := signEnv(testDashKey, cmdMsg(9, `{"command_id":"c9","name":"quarantine","files":[{"root":"`+www+`","path":"index.php","sha256":"`+sha([]byte("<?php echo 1;"))+`"}]}`))
	fl.commands = []envelope{q}
	a.pollOnce(context.Background())
	last := fl.results[len(fl.results)-1]
	if last.CommandID != "c9" || len(last.Files) != 1 || last.Files[0].Status != "quarantined" || fl.reports[len(fl.reports)-1].Reason != "quarantine" {
		t.Fatalf("quarantine result %+v", last)
	}
	if _, err := os.Lstat(filepath.Join(www, "index.php")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatal("file not quarantined")
	}
	n := len(fl.results)
	fl.commands = []envelope{q}
	a.pollOnce(context.Background())
	if len(fl.results) != n {
		t.Fatal("a re-delivered command was answered again")
	}
}

func mapsEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

// --- enroll ---

func TestEnrollCodeAndUnit(t *testing.T) {
	var got enrollRequest
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &got)
		pub, _ := base64.StdEncoding.DecodeString(got.PublicKey)
		r.Body = io.NopCloser(bytes.NewReader(body))
		if _, err := verifySigned(r, pub); err != nil || r.URL.Path != "/agent/v1/enroll" {
			http.Error(w, `{"error":"bad_signature"}`, 401)
			return
		}
		w.WriteHeader(202)
	}))
	defer srv.Close()
	tmp := t.TempDir()
	www := filepath.Join(tmp, "www")
	os.Mkdir(www, 0o755)
	args := []string{"--url", srv.URL, "--tls-pin", hex.EncodeToString(pinOf(srv)), "--key-id", "dk-1", "--agent-id", "agent-1",
		"--dashboard-key", base64.StdEncoding.EncodeToString(testDashKey.Public().(ed25519.PublicKey)), "--allow", www,
		"--config-dir", filepath.Join(tmp, "etc"), "--state-dir", filepath.Join(tmp, "state"), "--unit-dir", filepath.Join(tmp, "unit")}
	t.Setenv("ENROLLMENT_CODE", "env-code-123456")
	t.Setenv("ASSET_MONITOR_ENROLLMENT_CODE", "env-code-123456")
	var out bytes.Buffer
	// Never from the arguments, never from the environment.
	if err := enroll(append(args, "argv-code-123456"), strings.NewReader("stdin-code-123456\n"), &out, io.Discard, systemLookup); err == nil {
		t.Fatal("a positional code was accepted")
	}
	if err := enroll(append(args, "--code", "argv-code-123456"), strings.NewReader("stdin-code-123456\n"), &out, io.Discard, systemLookup); err == nil {
		t.Fatal("--code was accepted")
	}
	if err := enroll(args, strings.NewReader(""), &out, io.Discard, systemLookup); err == nil {
		t.Fatal("enrolled with no code on stdin")
	}
	if err := enroll(args, strings.NewReader("stdin-code-123456\n"), &out, io.Discard, systemLookup); err != nil {
		t.Fatal(err)
	}
	if got.EnrollmentCode != "stdin-code-123456" || got.AgentID != "agent-1" || !slices.Equal(got.AllowedPaths, []string{www}) || got.Version == "" {
		t.Fatalf("enroll request %+v", got)
	}
	pub, _ := base64.StdEncoding.DecodeString(got.PublicKey)
	if !strings.Contains(out.String(), fingerprint(pub)) {
		t.Fatal("fingerprint not printed")
	}
	for _, f := range []string{"etc/config.json", "etc/agent.key"} {
		fi, err := os.Stat(filepath.Join(tmp, f))
		if err != nil || fi.Mode().Perm() != 0o600 || statT(fi).Uid != 0 {
			t.Fatalf("%s: %v %v", f, fi, err)
		}
	}
	unit, _ := os.ReadFile(filepath.Join(tmp, "unit", "asset-monitor-agent.service"))
	for _, d := range []string{"ProtectSystem=strict", "ReadWritePaths=-" + www + "\n", "StateDirectory=asset-monitor-agent", "StateDirectoryMode=0700",
		"NoNewPrivileges=yes", "PrivateTmp=yes", "PrivateDevices=yes", "ProtectKernelTunables=yes", "ProtectKernelModules=yes",
		"ProtectControlGroups=yes", "RestrictNamespaces=yes", "LockPersonality=yes", "MemoryDenyWriteExecute=yes",
		"SystemCallFilter=@system-service", "UMask=0077", "CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_DAC_OVERRIDE CAP_FOWNER CAP_CHOWN\n",
		"RestrictAddressFamilies=AF_INET AF_INET6\n", "IPAddressDeny=any\n", "IPAddressAllow=127.0.0.1\n", "ExecStart=/usr/local/bin/asset-monitor-agent run\n"} {
		if !strings.Contains(string(unit), d) {
			t.Fatalf("unit lacks %q", d)
		}
	}
	if n := strings.Count(string(unit), "ReadWritePaths="); n != 1 {
		t.Fatalf("%d ReadWritePaths lines", n)
	}
	// A public listener address is refused before any code is read.
	bad := slices.Clone(args)
	bad[1] = "https://8.8.8.8:8792"
	if err := enroll(bad, strings.NewReader("stdin-code-123456\n"), &out, io.Discard, systemLookup); err == nil {
		t.Fatal("public address accepted")
	}
}

// The code has no path from the environment: no source file reads it.
func TestNoEnvironmentReads(t *testing.T) {
	re := regexp.MustCompile(`os\.(Getenv|LookupEnv|Environ)\b|syscall\.Getenv`)
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, _ := os.ReadFile(f)
		if re.Match(b) {
			t.Fatalf("%s reads the environment", f)
		}
	}
}

// --- hardening ---

// A Watched root (or a parent) swapped for a link after it was checked never redirects the agent.
func TestRootSwappedForLink(t *testing.T) {
	v, _ := newVault(t)
	tmp := t.TempDir()
	www, outside := filepath.Join(tmp, "www"), filepath.Join(tmp, "outside")
	writeTree(t, www, map[string]string{"a.php": "same"})
	writeTree(t, outside, map[string]string{"a.php": "same", "shadow": "root:x"})
	ok := func(string) error { return nil } // the root check passed just before the swap
	_, index := walk(context.Background(), []string{www}, ok)
	os.Rename(www, www+".old")
	os.Symlink(outside, www)
	rep, _ := walk(context.Background(), []string{www}, ok)
	if len(rep.Roots) != 0 || len(rep.Issues) != 1 || rep.Issues[0].Reason != "root_refused" {
		t.Fatalf("walked through a swapped root: %+v", rep)
	}
	if data, why := readWanted(sha([]byte("same")), index, ok); data != nil {
		t.Fatalf("uploaded bytes from outside the root (%s)", why)
	}
	if r := v.quarantine(www, "a.php", sha([]byte("same")), testNow); r.Status != "link_refused" {
		t.Fatal(r)
	}
	if _, err := os.Stat(filepath.Join(outside, "a.php")); err != nil {
		t.Fatal("a file outside the root was moved")
	}
	// A link above the root is refused the same way.
	os.Remove(www)
	os.Rename(www+".old", filepath.Join(outside, "www"))
	os.Symlink(outside, filepath.Join(tmp, "p"))
	if r := v.quarantine(filepath.Join(tmp, "p", "www"), "a.php", sha([]byte("same")), testNow); r.Status != "link_refused" {
		t.Fatal(r)
	}
}

type endless struct{}

func (endless) Read(b []byte) (int, error) { clear(b); return len(b), nil }

// A file that keeps growing (a sparse file extended in a loop) cannot stall a walk or a Quarantine.
func TestHashingIsBounded(t *testing.T) {
	defer func(h int64) { hashLimit = h }(hashLimit)
	hashLimit = 1 << 20
	if _, err := hashReader(endless{}); !errors.Is(err, errTooLarge) {
		t.Fatal(err)
	}
	var sink bytes.Buffer
	if _, err := copyHashed(&sink, endless{}); !errors.Is(err, errTooLarge) || int64(sink.Len()) > hashLimit+1 {
		t.Fatalf("copied %d bytes: %v", sink.Len(), err)
	}
	hashLimit = 8
	v, _ := newVault(t)
	www := t.TempDir()
	writeTree(t, www, map[string]string{"big.php": strings.Repeat("x", 16)})
	if r := v.quarantine(www, "big.php", sha([]byte(strings.Repeat("x", 16))), testNow); r.Status != "failed" {
		t.Fatal(r)
	}
	if _, err := os.Stat(filepath.Join(www, "big.php")); err != nil {
		t.Fatal("moved a file it could not hash")
	}
}

// A hard link may be another name of a file outside the Watched roots: its bytes are never uploaded.
func TestHardLinkNotUploaded(t *testing.T) {
	tmp := t.TempDir()
	www, outside := filepath.Join(tmp, "www"), filepath.Join(tmp, "outside")
	writeTree(t, www, map[string]string{"index.php": "ok"})
	writeTree(t, outside, map[string]string{"shadow": "root:$6$secret"})
	if err := os.Link(filepath.Join(outside, "shadow"), filepath.Join(www, "notes.txt")); err != nil {
		t.Fatal(err)
	}
	ok := func(string) error { return nil }
	_, index := walk(context.Background(), []string{www}, ok)
	if data, why := readWanted(sha([]byte("root:$6$secret")), index, ok); data != nil || why != "hard_link" {
		t.Fatalf("hard link uploaded: %q %s", data, why)
	}
	if data, _ := readWanted(sha([]byte("ok")), index, ok); string(data) != "ok" {
		t.Fatal("a plain file was not uploaded")
	}
}

// Every upload request stays within its cap, however many entries are skipped.
func TestUploadRequestsStayUnderCap(t *testing.T) {
	defer func(n int) { maxUploadBody = n }(maxUploadBody)
	maxUploadBody = 64<<10 + 4096
	files := map[string]string{}
	for i := range 20 {
		files[strconv.Itoa(i)+".php"] = strings.Repeat(strconv.Itoa(i), 300)
	}
	e := newRunEnv(t, files)
	e.a.pollOnce(context.Background())
	for i := range 1000 { // a hostile listener asks for 1,000 hashes the manifest does not hold
		e.fl.wanted.SHA256 = append(e.fl.wanted.SHA256, sha([]byte(strconv.Itoa(i)+"junk")))
	}
	e.a.pollOnce(context.Background())
	nFiles, nSkipped := 0, 0
	for i, u := range e.fl.uploads {
		if e.fl.upSizes[i] > maxUploadBody || u.Complete != (i == len(e.fl.uploads)-1) {
			t.Fatalf("upload %d: %d bytes, complete %v", i, e.fl.upSizes[i], u.Complete)
		}
		nFiles, nSkipped = nFiles+len(u.Files), nSkipped+len(u.Skipped)
	}
	if nFiles != 20 || nSkipped != 1000 {
		t.Fatalf("%d files, %d skipped", nFiles, nSkipped)
	}
}

// A listener answering with junk envelopes gets a bounded number of refusals, and the agent's memory stays bounded.
func TestRefusalFloodIsBounded(t *testing.T) {
	defer func(n int) { maxRefusedKept = n }(maxRefusedKept)
	maxRefusedKept = 40
	e := newRunEnv(t, map[string]string{"index.php": "ok"})
	e.a.pollOnce(context.Background())
	sig := base64.StdEncoding.EncodeToString(make([]byte, 64))
	for poll := range 5 {
		n := len(e.fl.results)
		for i := range 200 {
			e.fl.commands = append(e.fl.commands, envelope{KeyID: "dk-1", Signature: sig,
				Payload: base64.StdEncoding.EncodeToString([]byte(strconv.Itoa(poll*1000 + i)))})
		}
		e.a.pollOnce(context.Background())
		if got := len(e.fl.results) - n; got != maxRefusalsPerPoll {
			t.Fatalf("poll %d: %d refusals", poll, got)
		}
		if len(e.a.refused) > maxRefusedKept {
			t.Fatalf("%d refusals kept", len(e.a.refused))
		}
	}
}

// Recovery never re-owns or changes the mode of a file that is not the one Restore created.
func TestRecoveryLeavesSwappedFile(t *testing.T) {
	v, state := newVault(t)
	www := t.TempDir()
	writeTree(t, www, map[string]string{"a.php": "aaa"})
	ours := filepath.Join(www, "a.php")
	fi, _ := os.Stat(ours)
	m := qmeta{ID: strings.Repeat("3", 32), Root: www, Path: "a.php", SHA256: sha([]byte("aaa")), Mode: 0o755, UID: 1234, GID: 1234}
	os.WriteFile(filepath.Join(state, "quarantine", m.ID+".bin"), []byte("aaa"), 0o600)
	os.WriteFile(filepath.Join(state, "quarantine", m.ID+".json"), []byte(`{}`), 0o600)
	v.journal(journalEntry{Op: "restore", Stage: "created", Meta: m, Dev: uint64(statT(fi).Dev), Ino: statT(fi).Ino})
	// The file Restore created was moved away and another with the same bytes put in its place.
	os.Rename(ours, filepath.Join(www, "moved"))
	os.WriteFile(ours, []byte("aaa"), 0o640)
	v.recover(t.Logf)
	got, _ := os.Stat(ours)
	if got.Mode().Perm() != 0o640 || statT(got).Uid == 1234 {
		t.Fatalf("another file was re-owned: %v uid %d", got.Mode(), statT(got).Uid)
	}
	if _, err := os.Stat(filepath.Join(state, "quarantine", m.ID+".bin")); err != nil {
		t.Fatal("the quarantine entry was dropped though nothing was restored")
	}
	// The file it did create, still in place and whole, is finished.
	os.Rename(filepath.Join(www, "moved"), ours)
	v.journal(journalEntry{Op: "restore", Stage: "created", Meta: m, Dev: uint64(statT(fi).Dev), Ino: statT(fi).Ino})
	v.recover(t.Logf)
	got, _ = os.Stat(ours)
	if got.Mode().Perm() != 0o755 || statT(got).Uid != 1234 {
		t.Fatalf("restore not finished: %v uid %d", got.Mode(), statT(got).Uid)
	}
}

func TestRepin(t *testing.T) {
	e := newRunEnv(t, map[string]string{"index.php": "ok"})
	keyBefore, _ := os.ReadFile(filepath.Join(e.cfgDir, "agent.key"))
	newKey := ed25519.NewKeyFromSeed(seed(0x60))
	if err := repin([]string{"--key", base64.StdEncoding.EncodeToString(newKey.Public().(ed25519.PublicKey)), "--config-dir", e.cfgDir}, io.Discard, io.Discard); err == nil {
		t.Fatal("repin without --key-id accepted")
	}
	args := []string{"--key", hex.EncodeToString(newKey.Public().(ed25519.PublicKey)), "--key-id", "dk-2", "--config-dir", e.cfgDir}
	if err := repin(args, io.Discard, io.Discard); err != nil {
		t.Fatal(err)
	}
	a, err := loadAgent(e.cfgDir, e.state)
	if err != nil {
		t.Fatal(err)
	}
	m := cfgMsg(5, e.www)
	m.KeyID = "dk-2"
	if _, err := verifyMessage(signEnv(newKey, m), a.dashKey, a.cfg.KeyID, a.cfg.AgentID, "configuration", 4, testNow); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyMessage(signEnv(testDashKey, cfgMsg(5, e.www)), a.dashKey, a.cfg.KeyID, a.cfg.AgentID, "configuration", 4, testNow); err == nil {
		t.Fatal("the old key is still pinned")
	}
	if keyAfter, _ := os.ReadFile(filepath.Join(e.cfgDir, "agent.key")); !bytes.Equal(keyBefore, keyAfter) {
		t.Fatal("repin changed the Agent key")
	}
	fi, _ := os.Stat(filepath.Join(e.cfgDir, "config.json"))
	if fi.Mode().Perm() != 0o600 || statT(fi).Uid != 0 {
		t.Fatalf("config.json %v", fi.Mode())
	}
}

// The built binaries match SHA256SUMS and are static: no interpreter, no needed libraries.
func TestDistBinaries(t *testing.T) {
	dir := cmp.Or(os.Getenv("AGENT_DIST"), "dist")
	sums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		t.Skip("no build output; run build.sh first")
	}
	var names []string
	for _, line := range strings.Split(strings.TrimSpace(string(sums)), "\n") {
		want, name, _ := strings.Cut(line, "  ")
		names = append(names, name)
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || sha(b) != want {
			t.Fatalf("%s does not match SHA256SUMS: %v", name, err)
		}
		f, err := elf.NewFile(bytes.NewReader(b))
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range f.Progs {
			if p.Type == elf.PT_INTERP || p.Type == elf.PT_DYNAMIC {
				t.Fatalf("%s is dynamically linked", name)
			}
		}
		if libs, err := f.ImportedLibraries(); err != nil || len(libs) != 0 {
			t.Fatalf("%s needs %v %v", name, libs, err)
		}
		if want := map[string]elf.Machine{"amd64": elf.EM_X86_64, "arm64": elf.EM_AARCH64}[name[strings.LastIndex(name, "-")+1:]]; f.Machine != want {
			t.Fatalf("%s is for %v", name, f.Machine)
		}
	}
	if !slices.Equal(names, []string{"asset-monitor-agent-linux-amd64", "asset-monitor-agent-linux-arm64"}) {
		t.Fatalf("SHA256SUMS lists %v", names)
	}
}
