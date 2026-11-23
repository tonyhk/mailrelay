package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/mail"
	"net/textproto"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// ---------------------------------------------------------------- message helpers
func newRelayID() string {
	b := make([]byte, 3)
	rand.Read(b)
	return time.Now().UTC().Format("060102150405") + strings.ToUpper(hex.EncodeToString(b))
}

var crlfRE = regexp.MustCompile(`\r?\n`)

func normalizeCRLF(raw []byte) []byte { return crlfRE.ReplaceAll(raw, []byte("\r\n")) }

func splitHead(raw []byte) (head, body []byte) {
	i := bytes.Index(raw, []byte("\r\n\r\n"))
	if i < 0 {
		return raw, nil
	}
	return raw[:i+2], raw[i+2:]
}

func formatAddr(name, addr string) string {
	if name == "" {
		return addr
	}
	if plainNameRE.MatchString(name) {
		return name + " <" + addr + ">"
	}
	return (&mail.Address{Name: name, Address: addr}).String()
}

var plainNameRE = regexp.MustCompile(`^[A-Za-z0-9!#$%&'*+/=?^_{|}~ -]+$`)

func httpDate(t time.Time) string { return t.UTC().Format(http.TimeFormat) }

// rewriteFromHeader replaces the From: header (keeps the original as Reply-To if there is none). Body untouched.
func rewriteFromHeader(raw []byte, fromAddr, fromName string) []byte {
	head, body := splitHead(raw)
	var out, fromLines [][]byte
	inFrom := false
	for _, line := range bytes.Split(head, []byte("\r\n")) {
		if len(line) == 0 {
			continue
		}
		if line[0] == ' ' || line[0] == '\t' {
			if inFrom {
				fromLines = append(fromLines, line)
			} else {
				out = append(out, line)
			}
			continue
		}
		name, _, _ := bytes.Cut(line, []byte(":"))
		inFrom = strings.EqualFold(string(bytes.TrimSpace(name)), "from")
		if inFrom {
			fromLines = append(fromLines, line)
		} else {
			out = append(out, line)
		}
	}
	newLines := [][]byte{[]byte("From: " + formatAddr(fromName, fromAddr))}
	if len(fromLines) > 0 {
		hasReplyTo := false
		for _, l := range out {
			if bytes.HasPrefix(bytes.ToLower(l), []byte("reply-to:")) {
				hasReplyTo = true
			}
		}
		if !hasReplyTo {
			_, v, _ := bytes.Cut(bytes.Join(fromLines, []byte("\r\n")), []byte(":"))
			newLines = append(newLines, append([]byte("Reply-To:"), v...))
		}
	}
	res := bytes.Join(append(newLines, out...), []byte("\r\n"))
	res = append(res, '\r', '\n')
	return append(res, body...)
}

// headerValues returns Subject, Message-ID and In-Reply-To of a raw message (tolerant parser).
func headerValues(raw []byte) (subject string, msgID, inReplyTo *string) {
	head, _ := splitHead(raw)
	h, _ := textproto.NewReader(bufio.NewReader(bytes.NewReader(append(append([]byte{}, head...), '\r', '\n')))).ReadMIMEHeader()
	dec := new(mime.WordDecoder)
	get := func(k string) string {
		v := strings.TrimSpace(h.Get(k))
		if d, err := dec.DecodeHeader(v); err == nil {
			v = d
		}
		return v
	}
	s := []rune(get("Subject"))
	if len(s) > 500 {
		s = s[:500]
	}
	subject = string(s)
	if v := get("Message-Id"); v != "" {
		msgID = &v
	}
	if v := get("In-Reply-To"); v != "" {
		inReplyTo = &v
	}
	return
}

// ---------------------------------------------------------------- engine
type ClientInfo struct {
	Source     string // relay | api
	ClientIP   string
	ClientHelo string
	ClientUser string
	ClientTLS  bool
}

type queueItem struct {
	MailFrom  string   `json:"mail_from"`
	Rcpts     []string `json:"rcpts"`
	Meta      Meta     `json:"meta"`
	Attempt   int      `json:"attempt"`
	FirstSeen float64  `json:"first_seen"`
	NextTry   float64  `json:"next_try"`
	Upstream  *string  `json:"upstream"`
}

type queuedEntry struct {
	RelayID string
	queueItem
}

type Engine struct {
	cfg      *Config
	store    *Store
	sender   *Sender
	settings *RuntimeSettings
	qdir     string
	qmu      sync.Mutex
}

func newEngine(cfg *Config, store *Store, sender *Sender, settings *RuntimeSettings) (*Engine, error) {
	if err := os.MkdirAll(cfg.QueueDir, 0o755); err != nil {
		return nil, err
	}
	return &Engine{cfg: cfg, store: store, sender: sender, settings: settings, qdir: cfg.QueueDir}, nil
}

func unixNow() float64 { return float64(time.Now().UnixNano()) / 1e9 }

// accept takes a message in, tries to deliver it now, queues it if upstream is temporarily unavailable.
// It returns the SMTP answer for the client.
func (e *Engine) accept(raw []byte, mailFrom string, rcpts []string, client ClientInfo, upstream string) (int, smtp.EnhancedCode, string, string) {
	rt := e.settings.RT()
	relayID := newRelayID()
	raw = normalizeCRLF(raw)
	clientMailFrom := mailFrom
	if client.Source == "" {
		client.Source = "relay"
	}
	if rt.RewriteFrom && client.Source == "relay" {
		raw = rewriteFromHeader(raw, rt.FromAddress, rt.FromName)
		mailFrom = rt.FromAddress
	}
	proto := "ESMTP"
	if client.ClientTLS {
		proto += "S"
	}
	if client.ClientUser != "" {
		proto += "A"
	}
	helo := client.ClientHelo
	if helo == "" {
		helo = "unknown"
	}
	ipTxt := client.ClientIP
	if ipTxt == "" {
		ipTxt = "api"
	}
	received := fmt.Sprintf("Received: from %s (%s)\r\n\tby %s (mailrelay) with %s id %s;\r\n\t%s\r\n",
		helo, ipTxt, e.cfg.Hostname, proto, relayID, httpDate(time.Now()))
	raw = append([]byte(received), raw...)

	subject, msgID, inReplyTo := headerValues(raw)
	meta := Meta{Source: client.Source, RelayID: relayID, ClientIP: nonEmpty(client.ClientIP),
		ClientHelo: nonEmpty(client.ClientHelo), ClientUser: nonEmpty(client.ClientUser),
		Subject: subject, MessageID: msgID, InReplyTo: inReplyTo}
	tls := 0
	if client.ClientTLS {
		tls = 1
	}
	if err := e.store.createMessage(Row{
		"relay_id": relayID, "received_utc": nowISO(), "source": meta.Source, "status": "sending",
		"client_ip": meta.ClientIP, "client_helo": meta.ClientHelo, "client_user": meta.ClientUser,
		"client_tls": tls, "client_mail_from": clientMailFrom, "mail_from": mailFrom,
		"rcpt_to": strings.Join(rcpts, ", "), "subject": meta.Subject, "message_id": meta.MessageID,
		"size_bytes": len(raw), "attempts": 0,
	}); err != nil {
		logf("[store] cannot record message: %v", err)
		return 451, smtp.EnhancedCode{4, 3, 0}, "Temporary relay error, try again later", relayID
	}
	return e.try(relayID, raw, mailFrom, rcpts, meta, 1, unixNow(), upstream)
}

func (e *Engine) try(relayID string, raw []byte, mailFrom string, rcpts []string, meta Meta, attempt int,
	firstSeen float64, upstream string) (int, smtp.EnhancedCode, string, string) {
	rt := e.settings.RT()
	d := e.sender.deliver(raw, mailFrom, rcpts, meta, attempt, upstream)
	f := d.Final
	common := Row{"attempts": attempt, "upstream_name": f.UpstreamName, "upstream_host": f.UpstreamHost,
		"upstream_ip": f.UpstreamIP, "smtp_code": f.SMTPCode, "smtp_response": f.SMTPResponse,
		"last_error": f.Error, "next_retry_utc": nil}
	with := func(status string) Row {
		r := Row{"status": status}
		for k, v := range common {
			r[k] = v
		}
		return r
	}
	switch {
	case d.OK:
		e.unspool(relayID)
		e.store.updateMessage(relayID, with("sent"))
		return 250, smtp.EnhancedCode{2, 0, 0}, "Ok: queued as " + relayID, relayID
	case d.Permanent:
		e.unspool(relayID)
		e.store.updateMessage(relayID, with("bounced"))
		code, resp := 0, ""
		if f.SMTPCode != nil {
			code = *f.SMTPCode
		}
		if f.SMTPResponse != nil {
			resp = *f.SMTPResponse
		}
		txt := fmt.Sprintf("Rejected by upstream %s: %d %s", f.UpstreamName, code, resp)
		if r := []rune(txt); len(r) > 390 {
			txt = string(r[:390])
		}
		return 554, smtp.EnhancedCode{5, 0, 0}, txt, relayID
	case unixNow()-firstSeen >= rt.QueueMaxAgeHours*3600:
		e.unspool(relayID)
		e.store.updateMessage(relayID, with("expired"))
		return 451, smtp.EnhancedCode{4, 4, 7}, "Message expired in queue", relayID
	}
	idx := min(attempt-1, len(rt.RetryMinutes)-1)
	nxt := unixNow() + float64(rt.RetryMinutes[idx]*60)
	if err := e.spool(relayID, raw, queueItem{MailFrom: mailFrom, Rcpts: rcpts, Meta: meta, Attempt: attempt,
		FirstSeen: firstSeen, NextTry: nxt, Upstream: nonEmpty(upstream)}); err != nil {
		logf("[queue] cannot spool %s: %v", relayID, err)
		e.store.updateMessage(relayID, with("sending"))
		return 451, smtp.EnhancedCode{4, 3, 0}, "Temporary relay error, try again later", relayID
	}
	q := with("queued")
	q["next_retry_utc"] = isoTime(time.Unix(0, int64(nxt*1e9)))
	e.store.updateMessage(relayID, q)
	return 250, smtp.EnhancedCode{2, 0, 0}, "Ok: queued as " + relayID + " (upstream unavailable, will retry)", relayID
}

// ---- disk queue (survives restarts; lives in the data volume) ----
func (e *Engine) spool(relayID string, raw []byte, item queueItem) error {
	eml := filepath.Join(e.qdir, relayID+".eml")
	if _, err := os.Stat(eml); err != nil {
		if err := os.WriteFile(eml, raw, 0o644); err != nil {
			return err
		}
	}
	b, _ := json.Marshal(item)
	tmp := filepath.Join(e.qdir, "."+relayID+".json.tmp")
	if err := os.WriteFile(tmp, b, 0o644); err != nil {
		return err
	}
	return os.Rename(tmp, filepath.Join(e.qdir, relayID+".json"))
}

func (e *Engine) unspool(relayID string) {
	os.Remove(filepath.Join(e.qdir, relayID+".json"))
	os.Remove(filepath.Join(e.qdir, relayID+".eml"))
}

func (e *Engine) queued() []queuedEntry {
	files, _ := filepath.Glob(filepath.Join(e.qdir, "*.json"))
	sort.Strings(files)
	out := []queuedEntry{}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var it queueItem
		if json.Unmarshal(b, &it) != nil {
			continue
		}
		out = append(out, queuedEntry{strings.TrimSuffix(filepath.Base(f), ".json"), it})
	}
	return out
}

func (e *Engine) processQueue(force bool, only string) int {
	if !e.qmu.TryLock() {
		return 0
	}
	defer e.qmu.Unlock()
	n := 0
	for _, it := range e.queued() {
		if (only != "" && it.RelayID != only) || (!force && it.NextTry > unixNow()) {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(e.qdir, it.RelayID+".eml"))
		if err != nil {
			e.unspool(it.RelayID)
			continue
		}
		up := ""
		if it.Upstream != nil {
			up = *it.Upstream
		}
		e.try(it.RelayID, raw, it.MailFrom, it.Rcpts, it.Meta, it.Attempt+1, it.FirstSeen, up)
		n++
	}
	return n
}

func (e *Engine) runQueue(stop <-chan struct{}) {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			func() {
				defer func() {
					if r := recover(); r != nil {
						logf("[queue] error: %v", r)
					}
				}()
				e.processQueue(false, "")
			}()
		}
	}
}

// ---------------------------------------------------------------- inbound SMTP
type backend struct {
	cfg      *Config
	engine   *Engine
	settings *RuntimeSettings
}

func (b *backend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &session{b: b, conn: c}, nil
}

type session struct {
	b      *backend
	conn   *smtp.Conn
	authed bool
	user   string
	from   string
	rcpts  []string
}

func (s *session) clientIP() string {
	if h, _, err := net.SplitHostPort(s.conn.Conn().RemoteAddr().String()); err == nil {
		return h
	}
	return s.conn.Conn().RemoteAddr().String()
}

func (s *session) AuthMechanisms() []string { return []string{sasl.Plain, sasl.Login} }

func (s *session) Auth(mech string) (sasl.Server, error) {
	verify := func(login, pw string) error {
		if s.b.settings.Verify(login, pw) {
			s.authed, s.user = true, login
			return nil
		}
		logf("[smtp] AUTH failed for '%s' from %s", login, s.clientIP())
		return &smtp.SMTPError{Code: 535, EnhancedCode: smtp.EnhancedCode{5, 7, 8}, Message: "Authentication credentials invalid"}
	}
	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(_, user, pw string) error { return verify(user, pw) }), nil
	case sasl.Login:
		return &loginServer{verify: verify}, nil
	}
	return nil, smtp.ErrAuthUnknownMechanism
}

// loginServer implements the (non-standard but common) LOGIN mechanism.
type loginServer struct {
	step   int
	user   string
	verify func(user, pw string) error
}

func (l *loginServer) Next(resp []byte) ([]byte, bool, error) {
	switch l.step {
	case 0:
		l.step = 1
		if resp != nil {
			l.user = string(resp)
			l.step = 2
			return []byte("Password:"), false, nil
		}
		return []byte("Username:"), false, nil
	case 1:
		l.user = string(resp)
		l.step = 2
		return []byte("Password:"), false, nil
	default:
		return nil, true, l.verify(l.user, string(resp))
	}
}

func (s *session) Reset() { s.from, s.rcpts = "", nil }

func (s *session) Logout() error { return nil }

func (s *session) Mail(from string, _ *smtp.MailOptions) error {
	rt := s.b.settings.RT()
	ipTxt := s.clientIP()
	if !s.authed {
		if rt.RequireAuth {
			return &smtp.SMTPError{Code: 530, EnhancedCode: smtp.EnhancedCode{5, 7, 0}, Message: "Authentication required"}
		}
		if !ipAllowed(ipTxt, rt.AllowedNetworks) {
			hint := ""
			if s.b.settings.UserCount(true) > 0 {
				hint = " - authenticate first"
			}
			logf("[smtp] relay denied for %s (MAIL FROM %s)", ipTxt, from)
			return &smtp.SMTPError{Code: 554, EnhancedCode: smtp.EnhancedCode{5, 7, 1},
				Message: "Relay access denied for " + ipTxt + hint}
		}
	}
	if len(rt.AllowedSenderDomains) > 0 && from != "" {
		dom := strings.ToLower(from[strings.LastIndex(from, "@")+1:])
		if !contains(rt.AllowedSenderDomains, dom) {
			return &smtp.SMTPError{Code: 553, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: "Sender domain not allowed"}
		}
	}
	s.from, s.rcpts = from, nil
	return nil
}

func (s *session) Rcpt(to string, _ *smtp.RcptOptions) error {
	if len(s.rcpts) >= s.b.settings.RT().MaxRecipients {
		return &smtp.SMTPError{Code: 452, EnhancedCode: smtp.EnhancedCode{4, 5, 3}, Message: "Too many recipients"}
	}
	s.rcpts = append(s.rcpts, to)
	return nil
}

func (s *session) Data(r io.Reader) error {
	raw, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	_, isTLS := s.conn.TLSConnectionState()
	client := ClientInfo{Source: "relay", ClientIP: s.clientIP(), ClientHelo: s.conn.Hostname(),
		ClientUser: s.user, ClientTLS: isTLS}
	var (
		code int
		enh  smtp.EnhancedCode
		text string
	)
	func() {
		defer func() {
			if r := recover(); r != nil {
				logf("[smtp] relay error: %v", r)
				code, enh, text = 451, smtp.EnhancedCode{4, 3, 0}, "Temporary relay error, try again later"
			}
		}()
		code, enh, text, _ = s.b.engine.accept(raw, s.from, append([]string(nil), s.rcpts...), client, "")
	}()
	return &smtp.SMTPError{Code: code, EnhancedCode: enh, Message: text}
}

func tlsMinVersion(v string) uint16 {
	switch v {
	case "1.0":
		return tls.VersionTLS10
	case "1.1":
		return tls.VersionTLS11
	case "1.3":
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

func buildSMTPServer(cfg *Config, engine *Engine, settings *RuntimeSettings) (*smtp.Server, error) {
	srv := smtp.NewServer(&backend{cfg, engine, settings})
	srv.Addr = net.JoinHostPort(cfg.SMTPListenHost, fmt.Sprint(cfg.SMTPListenPort))
	srv.Domain = cfg.Hostname
	srv.MaxMessageBytes = int64(cfg.MaxMessageMB) * 1024 * 1024
	srv.MaxLineLength = 4000
	srv.EnableSMTPUTF8 = true
	srv.ReadTimeout = 5 * time.Minute
	srv.WriteTimeout = 5 * time.Minute
	srv.ErrorLog = errLogger{}
	srv.AllowInsecureAuth = true
	if cfg.TLSCert != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLSCert, cfg.TLSKey)
		if err != nil {
			return nil, err
		}
		tc := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tlsMinVersion(cfg.TLSMinVersion)}
		if tc.MinVersion < tls.VersionTLS12 {
			// old printers / copiers: also allow the legacy cipher suites Go disables by default
			tc.CipherSuites = nil
			for _, c := range tls.CipherSuites() {
				tc.CipherSuites = append(tc.CipherSuites, c.ID)
			}
			for _, c := range tls.InsecureCipherSuites() {
				tc.CipherSuites = append(tc.CipherSuites, c.ID)
			}
		}
		srv.TLSConfig = tc
		srv.AllowInsecureAuth = !cfg.AuthRequireTLS
	}
	return srv, nil
}

type errLogger struct{}

func (errLogger) Printf(format string, v ...any) { logf("[smtp] "+format, v...) }
func (errLogger) Println(v ...any)               { logf("[smtp] %s", strings.TrimSpace(fmt.Sprintln(v...))) }

var _ = errors.New
