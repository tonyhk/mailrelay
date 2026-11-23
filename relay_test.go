package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/smtp"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	gosmtp "github.com/emersion/go-smtp"
)

// ---- fake upstream SMTP server ----
type fakeUpstream struct {
	mu   sync.Mutex
	mode string // ok | rcpt5xx | data4xx
	got  [][]byte
	addr string
}

type fakeSession struct{ f *fakeUpstream }

func (s *fakeSession) Reset()                                 {}
func (s *fakeSession) Logout() error                          { return nil }
func (s *fakeSession) Mail(string, *gosmtp.MailOptions) error { return nil }
func (s *fakeSession) Rcpt(string, *gosmtp.RcptOptions) error {
	if s.f.getMode() == "rcpt5xx" {
		return &gosmtp.SMTPError{Code: 550, EnhancedCode: gosmtp.EnhancedCode{5, 1, 1}, Message: "no such user"}
	}
	return nil
}
func (s *fakeSession) Data(r io.Reader) error {
	b, _ := io.ReadAll(r)
	if s.f.getMode() == "data4xx" {
		return &gosmtp.SMTPError{Code: 451, EnhancedCode: gosmtp.EnhancedCode{4, 3, 0}, Message: "try later"}
	}
	s.f.mu.Lock()
	s.f.got = append(s.f.got, b)
	s.f.mu.Unlock()
	return nil
}

func (f *fakeUpstream) NewSession(*gosmtp.Conn) (gosmtp.Session, error) { return &fakeSession{f}, nil }
func (f *fakeUpstream) getMode() string                                 { f.mu.Lock(); defer f.mu.Unlock(); return f.mode }
func (f *fakeUpstream) setMode(m string)                                { f.mu.Lock(); f.mode = m; f.mu.Unlock() }
func (f *fakeUpstream) count() int                                      { f.mu.Lock(); defer f.mu.Unlock(); return len(f.got) }

func startFake(t *testing.T) *fakeUpstream {
	f := &fakeUpstream{mode: "ok"}
	srv := gosmtp.NewServer(f)
	srv.Domain = "fake.upstream"
	srv.AllowInsecureAuth = true
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	f.addr = ln.Addr().String()
	go srv.Serve(ln)
	t.Cleanup(func() { srv.Close() })
	return f
}

type env struct {
	cfg      *Config
	store    *Store
	settings *RuntimeSettings
	engine   *Engine
	fake     *fakeUpstream
	smtpAddr string
	web      *httptest.Server
	dir      string
	srv      *gosmtp.Server
}

func newEnv(t *testing.T, dir string, mutate func(*Config)) *env {
	t.Helper()
	fake := startFake(t)
	host, port, _ := net.SplitHostPort(fake.addr)
	var p int
	fmt.Sscan(port, &p)
	cfg := defaultConfig()
	cfg.Hostname = "relay.test"
	cfg.LogDB = filepath.Join(dir, "mailrelay.db")
	cfg.LogFile = filepath.Join(dir, "log.jsonl")
	cfg.QueueDir = filepath.Join(dir, "queue")
	cfg.LogStdout = false
	cfg.Upstreams = []Upstream{{Name: "fake", Host: host, Port: p, Security: "none", Timeout: 5, VerifyTLS: true}}
	cfg.RelayUsers = map[string]string{}
	if mutate != nil {
		mutate(cfg)
	}
	if err := cfg.validate(true); err != nil {
		t.Fatal(err)
	}
	store, err := openStore(cfg.LogDB, cfg.LogFile, false)
	if err != nil {
		t.Fatal(err)
	}
	settings, err := newRuntimeSettings(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := newEngine(cfg, store, newSender(cfg, store), settings)
	if err != nil {
		t.Fatal(err)
	}
	info, err := prepareTLS(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.TLSInfo = info
	srv, err := buildSMTPServer(cfg, engine, settings)
	if err != nil {
		t.Fatal(err)
	}
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	go srv.Serve(ln)
	os.Setenv("MAILRELAY_ADMIN_PASSWORD", "pw")
	httpd, err := newWeb(cfg, store, engine, settings, []byte("<html>dash</html>"))
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(httpd.Handler)
	e := &env{cfg, store, settings, engine, fake, ln.Addr().String(), ts, dir, srv}
	t.Cleanup(func() { ts.Close(); srv.Close(); store.Close() })
	return e
}

func (e *env) send(t *testing.T, auth smtp.Auth, from string, to ...string) error {
	t.Helper()
	c, err := smtp.Dial(e.smtpAddr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := c.Hello("client.test"); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
			t.Fatal(err)
		}
	}
	if auth != nil {
		if err := c.Auth(auth); err != nil {
			return err
		}
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, r := range to {
		if err := c.Rcpt(r); err != nil {
			return err
		}
	}
	w, err := c.Data()
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "From: %s\r\nTo: %s\r\nSubject: =?utf-8?q?h=C3=A9llo?=\r\nMessage-ID: <abc@x>\r\n\r\nbody\r\n.dot line\r\n", from, to[0])
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}

func (e *env) api(t *testing.T, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.web.URL+path, rd)
	req.SetBasicAuth("admin", "pw")
	if method != "GET" {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out map[string]any
	b, _ := io.ReadAll(resp.Body)
	json.Unmarshal(b, &out)
	return resp.StatusCode, out
}

func status(t *testing.T, e *env, id string) string {
	m, err := e.store.getMessage(id)
	if err != nil || m == nil {
		t.Fatalf("message %s: %v", id, err)
	}
	return m["status"].(string)
}

func lastID(t *testing.T, e *env) string {
	rows, _ := e.store.messages(1, "", "", "")
	if len(rows) == 0 {
		t.Fatal("no messages")
	}
	return rows[0]["relay_id"].(string)
}

func TestRelayAllowedAndDelivered(t *testing.T) {
	e := newEnv(t, t.TempDir(), nil)
	if err := e.send(t, nil, "a@example.com", "b@example.org"); err != nil {
		t.Fatal(err)
	}
	if e.fake.count() != 1 {
		t.Fatalf("upstream got %d messages", e.fake.count())
	}
	id := lastID(t, e)
	if s := status(t, e, id); s != "sent" {
		t.Fatalf("status %s", s)
	}
	got := string(e.fake.got[0])
	if !strings.Contains(got, "Received: from client.test") || !strings.Contains(got, "\r\n.dot line\r\n") {
		t.Fatalf("unexpected upstream data:\n%s", got)
	}
	m, _ := e.store.getMessage(id)
	if m["subject"] != "héllo" || m["upstream_name"] != "fake" || len(m["attempt_log"].([]Row)) != 1 {
		t.Fatalf("bad message row: %v", m)
	}
	if b, _ := os.ReadFile(e.cfg.LogFile); !strings.Contains(string(b), `"event":"smtp_attempt"`) {
		t.Fatal("no jsonl line")
	}
}

func TestRelayDeniedOutsideNetworks(t *testing.T) {
	e := newEnv(t, t.TempDir(), nil)
	if code, out := e.api(t, "PUT", "/api/settings", map[string]any{"allowed_networks": "10.0.0.0/8"}); code != 200 {
		t.Fatal(code, out)
	}
	err := e.send(t, nil, "a@example.com", "b@example.org")
	if err == nil || !strings.Contains(err.Error(), "554") {
		t.Fatalf("expected 554, got %v", err)
	}
	if code, _ := e.api(t, "PUT", "/api/settings", map[string]any{"allowed_networks": "0.0.0.0/0"}); code != 400 {
		t.Fatal("open relay guard failed")
	}
}

func TestAuthAndRequireAuth(t *testing.T) {
	e := newEnv(t, t.TempDir(), nil)
	// guard: no require_auth without a user
	if code, _ := e.api(t, "PUT", "/api/settings", map[string]any{"require_auth": true}); code != 400 {
		t.Fatal("require_auth guard failed")
	}
	if code, out := e.api(t, "POST", "/api/users", map[string]any{"username": "bob", "password": "secret123"}); code != 200 {
		t.Fatal(code, out)
	}
	if code, out := e.api(t, "PUT", "/api/settings", map[string]any{"require_auth": true}); code != 200 {
		t.Fatal(code, out)
	}
	if err := e.send(t, nil, "a@example.com", "b@example.org"); err == nil || !strings.Contains(err.Error(), "530") {
		t.Fatalf("expected 530, got %v", err)
	}
	if err := e.send(t, smtp.PlainAuth("", "bob", "wrongwrong", "127.0.0.1"), "a@example.com", "b@example.org"); err == nil {
		t.Fatal("bad password accepted")
	}
	if err := e.send(t, smtp.PlainAuth("", "bob", "secret123", "127.0.0.1"), "a@example.com", "b@example.org"); err != nil {
		t.Fatal(err)
	}
	if st := status(t, e, lastID(t, e)); st != "sent" {
		t.Fatal(st)
	}
	// last enabled user cannot be deleted while login is required
	if code, _ := e.api(t, "DELETE", "/api/users/bob", nil); code != 400 {
		t.Fatal("last user guard failed")
	}
	// wrong content type
	req, _ := http.NewRequest("PUT", e.web.URL+"/api/settings", strings.NewReader("{}"))
	req.SetBasicAuth("admin", "pw")
	resp, _ := http.DefaultClient.Do(req)
	if resp.StatusCode != 415 {
		t.Fatal(resp.StatusCode)
	}
	// unauthenticated
	resp, _ = http.Get(e.web.URL + "/api/settings")
	if resp.StatusCode != 401 {
		t.Fatal(resp.StatusCode)
	}
	if resp, _ = http.Get(e.web.URL + "/health"); resp.StatusCode != 200 {
		t.Fatal("health")
	}
}

func TestQueueRetryBounceAndPersistence(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, dir, nil)
	e.fake.setMode("data4xx")
	if err := e.send(t, nil, "a@example.com", "b@example.org"); err != nil {
		t.Fatal(err) // temporary upstream failure is accepted into the queue
	}
	id := lastID(t, e)
	if s := status(t, e, id); s != "queued" {
		t.Fatalf("status %s", s)
	}
	if len(e.engine.queued()) != 1 {
		t.Fatal("not spooled")
	}
	// "restart": new engine on the same dirs sees the queue and the DB
	e.fake.setMode("ok")
	e2cfg := *e.cfg
	e2, err := newEngine(&e2cfg, e.store, newSender(&e2cfg, e.store), e.settings)
	if err != nil {
		t.Fatal(err)
	}
	if len(e2.queued()) != 1 {
		t.Fatal("queue lost")
	}
	if n := e2.processQueue(true, ""); n != 1 {
		t.Fatalf("processed %d", n)
	}
	if s := status(t, e, id); s != "sent" || len(e2.queued()) != 0 {
		t.Fatalf("status %s", s)
	}
	// permanent failure bounces
	e.fake.setMode("rcpt5xx")
	err = e.send(t, nil, "a@example.com", "b@example.org")
	if err == nil || !strings.Contains(err.Error(), "554") {
		t.Fatalf("expected 554 bounce, got %v", err)
	}
	if s := status(t, e, lastID(t, e)); s != "bounced" {
		t.Fatal(s)
	}
	// overview + attempts API
	code, ov := e.api(t, "GET", "/api/overview", nil)
	if code != 200 || ov["sent"].(float64) != 1 || ov["bounced"].(float64) != 1 {
		t.Fatal(code, ov)
	}
}

func TestSendAPIAndReply(t *testing.T) {
	e := newEnv(t, t.TempDir(), func(c *Config) { c.FromAddress = "relay@example.com"; c.FromName = "Relay" })
	code, out := e.api(t, "POST", "/api/send", map[string]any{"to": []string{"x@example.org"}, "subject": "Grüße", "body": "hi"})
	if code != 200 || out["smtp_code"].(float64) != 250 {
		t.Fatal(code, out)
	}
	raw := string(e.fake.got[0])
	if !strings.Contains(raw, "From: Relay <relay@example.com>") || !strings.Contains(raw, "Subject: =?utf-8?q?Gr") {
		t.Fatal(raw)
	}
	orig := "From: Al <al@example.net>\r\nTo: relay@example.com\r\nSubject: Q\r\nMessage-ID: <m1@x>\r\nDate: Mon, 1 Jan 2024 10:00:00 +0000\r\n\r\nquestion?\r\n"
	code, out = e.api(t, "POST", "/api/reply", map[string]any{"original_eml": orig, "body": "answer"})
	if code != 200 {
		t.Fatal(code, out)
	}
	raw = string(e.fake.got[1])
	for _, want := range []string{"In-Reply-To: <m1@x>", "Subject: Re: Q", "To: al@example.net", "> question?"} {
		if !strings.Contains(raw, want) {
			t.Fatalf("missing %q in\n%s", want, raw)
		}
	}
}

func TestRewriteFrom(t *testing.T) {
	e := newEnv(t, t.TempDir(), func(c *Config) {
		c.FromAddress = "relay@example.com"
		c.RewriteFrom = true
	})
	if err := e.send(t, nil, "orig@example.net", "b@example.org"); err != nil {
		t.Fatal(err)
	}
	raw := string(e.fake.got[0])
	if !strings.Contains(raw, "From: relay@example.com") || !strings.Contains(raw, "Reply-To: orig@example.net") {
		t.Fatal(raw)
	}
}

func TestSelfSignedSTARTTLSAndAuthNeedsTLS(t *testing.T) {
	dir := t.TempDir()
	e := newEnv(t, dir, func(c *Config) { c.TLSSelfSigned = true; c.TLSSANs = []string{"10.1.2.3"} })
	if e.cfg.TLSInfo == nil || !contains(e.cfg.TLSInfo.Names, "10.1.2.3") || !contains(e.cfg.TLSInfo.Names, "relay.test") {
		t.Fatalf("tls info %+v", e.cfg.TLSInfo)
	}
	c, _ := smtp.Dial(e.smtpAddr)
	defer c.Close()
	c.Hello("x")
	if ok, params := c.Extension("AUTH"); ok {
		t.Fatalf("AUTH offered before STARTTLS: %s", params)
	}
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true}); err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.Extension("AUTH"); !ok {
		t.Fatal("AUTH not offered after STARTTLS")
	}
	// the cert is reused on the next start
	e2cfg := defaultConfig()
	e2cfg.Hostname, e2cfg.LogDB, e2cfg.TLSSelfSigned, e2cfg.TLSSANs = "relay.test", e.cfg.LogDB, true, []string{"10.1.2.3"}
	info, err := prepareTLS(e2cfg)
	if err != nil || info.Source != "self-signed (reused)" || info.SHA256 != e.cfg.TLSInfo.SHA256 {
		t.Fatalf("%v %+v", err, info)
	}
	// a new name regenerates it
	e2cfg.TLSSANs = []string{"10.1.2.3", "other.example"}
	e2cfg.TLSCert, e2cfg.TLSKey = "", ""
	info, _ = prepareTLS(e2cfg)
	if info.Source != "generated" {
		t.Fatalf("%+v", info)
	}
}

func TestTLS10Option(t *testing.T) {
	e := newEnv(t, t.TempDir(), func(c *Config) { c.TLSSelfSigned = true; c.TLSMinVersion = "1.0" })
	c, _ := smtp.Dial(e.smtpAddr)
	defer c.Close()
	c.Hello("x")
	if err := c.StartTLS(&tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS10, MaxVersion: tls.VersionTLS10}); err != nil {
		t.Skipf("TLS 1.0 client handshake not possible with this Go runtime: %v", err)
	}
}

func TestPythonDatabaseCompat(t *testing.T) {
	// A database created by an older version lacks newer columns; opening must add them.
	dir := t.TempDir()
	e := newEnv(t, dir, nil)
	e.store.db.Exec("DROP TABLE relay_users")
	e.store.db.Exec("CREATE TABLE relay_users (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)")
	e.store.Close()
	s, err := openStore(e.cfg.LogDB, "", false)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.upsertRelayUser("x", "h", true, "n"); err != nil {
		t.Fatal(err)
	}
	// a hash produced by the Python version verifies
	pyHash := "pbkdf2_sha256$200000$00112233445566778899aabbccddeeff$6a29890a93f421796f6941550198678950277845aeed11728137e4c012b31e67"
	if !checkPassword("pässword", pyHash) || checkPassword("password", pyHash) {
		t.Fatal("python hash not verified")
	}
	h, _ := hashPassword("pässword")
	if !checkPassword("pässword", h) || checkPassword("nope", h) {
		t.Fatal("password hash roundtrip")
	}
}
