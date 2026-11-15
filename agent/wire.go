package main

// The wire protocol of PROTOCOL.md: request signatures, Dashboard-signed
// messages, the URL rules and the pinned TLS client.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	requestPrefix  = "asset-monitor-agent-request-v1"
	messagePrefix  = "asset-monitor-dashboard-message-v1"
	agentVersion   = "0.1.0"
	maxResponse    = 4 << 20
	commandMaxLife = 15 * time.Minute
	clockSkew      = 5 * time.Minute
)

// canonicalRequest is the exact byte string the Agent key signs.
func canonicalRequest(method, pathQuery string, ts int64, nonce string, body []byte) []byte {
	sum := sha256.Sum256(body)
	return []byte(strings.Join([]string{
		requestPrefix, method, pathQuery, strconv.FormatInt(ts, 10), nonce, hex.EncodeToString(sum[:]),
	}, "\n"))
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// signedRequest builds a request to base+pathQuery carrying the PROTOCOL.md headers.
func signedRequest(key ed25519.PrivateKey, agentID, method string, base *url.URL, pathQuery string, body []byte, now time.Time) (*http.Request, error) {
	if strings.ContainsAny(pathQuery, "\n\r") || !strings.HasPrefix(pathQuery, "/") {
		return nil, errors.New("bad request path")
	}
	req, err := http.NewRequest(method, base.Scheme+"://"+base.Host+pathQuery, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	ts, nonce := now.Unix(), randHex(16)
	sum := sha256.Sum256(body)
	sig := ed25519.Sign(key, canonicalRequest(method, req.URL.RequestURI(), ts, nonce, body))
	h := req.Header
	h.Set("X-Agent-Id", agentID)
	h.Set("X-Agent-Timestamp", strconv.FormatInt(ts, 10))
	h.Set("X-Agent-Nonce", nonce)
	h.Set("X-Agent-Content-SHA256", hex.EncodeToString(sum[:]))
	h.Set("X-Agent-Signature", base64.StdEncoding.EncodeToString(sig))
	if len(body) > 0 {
		h.Set("Content-Type", "application/json")
	}
	return req, nil
}

type apiError struct {
	Status int
	Code   string
}

func (e *apiError) Error() string { return fmt.Sprintf("listener answered %d %s", e.Status, e.Code) }

// call sends one signed request and decodes a 2xx JSON answer into out.
func call(c *http.Client, key ed25519.PrivateKey, agentID, method string, base *url.URL, pathQuery string, in, out any, now time.Time) error {
	var body []byte
	if in != nil {
		var err error
		if body, err = json.Marshal(in); err != nil {
			return err
		}
	}
	req, err := signedRequest(key, agentID, method, base, pathQuery, body, now)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponse+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponse {
		return errors.New("response too large")
	}
	if resp.StatusCode/100 != 2 {
		var e struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &e)
		return &apiError{resp.StatusCode, e.Error}
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	return json.Unmarshal(data, out)
}

// decode32 reads a 32-byte value given as 64 hex digits or base64 (standard or URL, padded or not).
func decode32(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	if b, err := hex.DecodeString(s); err == nil && len(b) == 32 {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.Strict().DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, errors.New("want 32 bytes as 64 hex digits or base64")
}

type lookupFunc func(ctx context.Context, host string) ([]netip.Addr, error)

func systemLookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

// checkURL applies the B04 URL rules and returns the URL and the one address the agent may dial.
func checkURL(raw string, lookup lookupFunc) (*url.URL, string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, "", err
	}
	if u.Scheme != "https" {
		return nil, "", errors.New("the agent listener URL must be https")
	}
	if u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.Fragment != "" || (u.Path != "" && u.Path != "/") || u.Hostname() == "" {
		return nil, "", errors.New("the agent listener URL must be https://host[:port] with nothing else")
	}
	port := u.Port()
	if port == "" {
		port = "443"
	}
	if n, err := strconv.Atoi(port); err != nil || n < 1 || n > 65535 {
		return nil, "", errors.New("bad port")
	}
	var addrs []netip.Addr
	if a, err := netip.ParseAddr(u.Hostname()); err == nil {
		addrs = []netip.Addr{a}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if addrs, err = lookup(ctx, u.Hostname()); err != nil {
			return nil, "", err
		}
	}
	if len(addrs) == 0 {
		return nil, "", errors.New("the agent listener host has no address")
	}
	for i, a := range addrs {
		a = a.Unmap()
		if a.Zone() != "" || !(a.IsLoopback() || a.IsPrivate()) {
			return nil, "", fmt.Errorf("address %s is not loopback or private", a)
		}
		addrs[i] = a
	}
	return &url.URL{Scheme: "https", Host: u.Host}, net.JoinHostPort(addrs[0].String(), port), nil
}

// pinnedClient dials only addr and accepts only a certificate whose SubjectPublicKeyInfo hashes to pin.
func pinnedClient(addr string, pin []byte) *http.Client {
	d := &net.Dialer{Timeout: 15 * time.Second}
	return &http.Client{
		Timeout: 5 * time.Minute,
		Transport: &http.Transport{
			Proxy: nil, // never a proxy from the environment
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return d.DialContext(ctx, "tcp", addr)
			},
			TLSClientConfig: &tls.Config{
				MinVersion: tls.VersionTLS13,
				// No CA chain: the pin below is the only check, and it runs on every handshake.
				InsecureSkipVerify: true,
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 {
						return errors.New("no certificate")
					}
					sum := sha256.Sum256(cs.PeerCertificates[0].RawSubjectPublicKeyInfo)
					if subtle.ConstantTimeCompare(sum[:], pin) != 1 {
						return errors.New("agent listener key does not match the TLS pin")
					}
					return nil
				},
			},
			TLSHandshakeTimeout: 15 * time.Second,
			MaxIdleConns:        2,
			IdleConnTimeout:     90 * time.Second,
		},
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are refused") },
	}
}

// envelope is a Dashboard-signed message as it arrives in a poll answer.
type envelope struct {
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
	KeyID     string `json:"key_id"`
}

type message struct {
	V         int             `json:"v"`
	Type      string          `json:"type"`
	AgentID   string          `json:"agent_id"`
	KeyID     string          `json:"key_id"`
	Sequence  int64           `json:"sequence"`
	IssuedAt  int64           `json:"issued_at"`
	ExpiresAt int64           `json:"expires_at"`
	Body      json.RawMessage `json:"body"`
}

var errNotNewer = errors.New("not_newer")

type refusal struct{ reason string }

func (r refusal) Error() string { return r.reason }

func messageBytes(payload []byte) []byte {
	return append([]byte(messagePrefix+"\n"), payload...)
}

// verifyMessage checks a Dashboard-signed message against the pinned key and the agent's state.
// The returned message is set whenever the signature verified, even when it is refused.
func verifyMessage(env envelope, pub ed25519.PublicKey, keyID, agentID, typ string, last int64, now time.Time) (*message, error) {
	payload, err := base64.StdEncoding.Strict().DecodeString(env.Payload)
	if err != nil {
		return nil, refusal{"bad_payload"}
	}
	sig, err := base64.StdEncoding.Strict().DecodeString(env.Signature)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return nil, refusal{"bad_signature"}
	}
	if env.KeyID != keyID {
		return nil, refusal{"unknown_key_id"}
	}
	if !ed25519.Verify(pub, messageBytes(payload), sig) {
		return nil, refusal{"bad_signature"}
	}
	var m message
	if err := json.Unmarshal(payload, &m); err != nil {
		return nil, refusal{"bad_payload"}
	}
	switch {
	case m.V != 1:
		return &m, refusal{"bad_version"}
	case m.KeyID != keyID:
		return &m, refusal{"unknown_key_id"}
	case m.AgentID != agentID:
		return &m, refusal{"wrong_agent"}
	case m.Type != typ:
		return &m, refusal{"wrong_type"}
	case m.Sequence <= last:
		return &m, errNotNewer
	case m.IssuedAt > now.Add(clockSkew).Unix():
		return &m, refusal{"issued_in_future"}
	}
	if typ == "command" {
		switch {
		case m.ExpiresAt <= 0:
			return &m, refusal{"no_expiry"}
		case now.Unix() >= m.ExpiresAt:
			return &m, refusal{"expired"}
		case m.ExpiresAt > now.Add(commandMaxLife+clockSkew).Unix():
			return &m, refusal{"expiry_too_far"}
		}
	} else if m.ExpiresAt != 0 {
		return &m, refusal{"unexpected_expiry"}
	}
	return &m, nil
}
