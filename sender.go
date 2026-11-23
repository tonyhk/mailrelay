package main

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"time"
)

// Delivery is the outcome of trying the upstream servers in order.
type Delivery struct {
	OK        bool
	Permanent bool
	Final     *SendRecord
	Attempts  []*SendRecord
}

// Meta is what we know about the client and the message; it is stored in the queue file and logged per attempt.
type Meta struct {
	Source     string  `json:"source"`
	RelayID    string  `json:"relay_id"`
	ClientIP   *string `json:"client_ip"`
	ClientHelo *string `json:"client_helo"`
	ClientUser *string `json:"client_user"`
	Subject    string  `json:"subject"`
	MessageID  *string `json:"message_id"`
	InReplyTo  *string `json:"in_reply_to"`
}

func sp(s string) *string { return &s }
func ip(i int) *int       { return &i }
func nonEmpty(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// respError is an SMTP reply with an unexpected code.
type respError struct {
	Code int
	Text string
}

func (e *respError) Error() string { return fmt.Sprintf("(%d, %q)", e.Code, e.Text) }

func collapse(s string) string { return strings.Join(strings.Fields(s), " ") }

// smtpClient is a minimal SMTP client that keeps the greeting banner and reports the stage a failure happened in.
type smtpClient struct {
	conn    net.Conn
	tp      *textproto.Conn
	timeout time.Duration
	banner  string
	exts    map[string]string
	tlsVer  string
}

func (c *smtpClient) arm() { c.conn.SetDeadline(time.Now().Add(c.timeout)) }

func (c *smtpClient) setConn(conn net.Conn) {
	c.conn = conn
	c.tp = textproto.NewConn(conn)
}

// cmd sends a command and reads the reply (no code check).
func (c *smtpClient) cmd(format string, args ...any) (int, string, error) {
	c.arm()
	if err := c.tp.PrintfLine(format, args...); err != nil {
		return 0, "", err
	}
	return c.read()
}

func (c *smtpClient) read() (int, string, error) {
	c.arm()
	code, msg, err := c.tp.ReadResponse(0)
	if e, ok := err.(*textproto.Error); ok { // ReadResponse(0) never returns this, kept for safety
		return e.Code, e.Msg, nil
	}
	return code, msg, err
}

func (c *smtpClient) ehlo(name string) error {
	code, msg, err := c.cmd("EHLO %s", name)
	if err != nil {
		return err
	}
	if code != 250 {
		code, msg, err = c.cmd("HELO %s", name)
		if err != nil {
			return err
		}
		if code != 250 {
			return &respError{code, msg}
		}
		c.exts = map[string]string{}
		return nil
	}
	c.exts = map[string]string{}
	for i, l := range strings.Split(msg, "\n") {
		if i == 0 {
			continue
		}
		k, v, _ := strings.Cut(strings.TrimSpace(l), " ")
		c.exts[strings.ToLower(k)] = v
	}
	return nil
}

func tlsVersionName(v uint16) string {
	switch v {
	case tls.VersionTLS10:
		return "TLSv1"
	case tls.VersionTLS11:
		return "TLSv1.1"
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	}
	return fmt.Sprintf("0x%04x", v)
}

func upstreamTLS(u Upstream) *tls.Config {
	return &tls.Config{ServerName: u.Host, InsecureSkipVerify: !u.VerifyTLS, MinVersion: tls.VersionTLS12}
}

type Sender struct {
	cfg   *Config
	store *Store
}

func newSender(cfg *Config, store *Store) *Sender { return &Sender{cfg, store} }

func (s *Sender) attempt(up Upstream, raw []byte, mailFrom string, rcpts []string, meta Meta, attempt int) *SendRecord {
	rec := &SendRecord{
		TimestampUTC: nowISO(), UpstreamName: up.Name, UpstreamHost: up.Host, UpstreamPort: up.Port,
		Status: "failed", Security: sp(up.Security), AuthUser: nonEmpty(up.Username),
		MailFrom: sp(mailFrom), RcptTo: sp(strings.Join(rcpts, ", ")), SizeBytes: ip(len(raw)),
		Source: meta.Source, RelayID: sp(meta.RelayID), Attempt: attempt, ClientIP: meta.ClientIP,
		ClientHelo: meta.ClientHelo, ClientUser: meta.ClientUser, Subject: sp(meta.Subject),
		MessageID: meta.MessageID, InReplyTo: meta.InReplyTo,
	}
	start := time.Now()
	stage := "connect"
	c := &smtpClient{timeout: time.Duration(up.Timeout) * time.Second}
	if c.timeout <= 0 {
		c.timeout = 30 * time.Second
	}
	defer func() {
		rec.DurationMS = ip(int(time.Since(start) / time.Millisecond))
		if c.conn != nil {
			c.conn.SetDeadline(time.Now().Add(2 * time.Second))
			c.tp.PrintfLine("QUIT")
			c.conn.Close()
		}
	}()
	fail := func(err error) *SendRecord {
		if re, ok := err.(*respError); ok {
			rec.SMTPCode, rec.SMTPResponse = ip(re.Code), sp(collapse(re.Text))
			rec.Error = sp(fmt.Sprintf("%s: %d %s", stage, re.Code, collapse(re.Text)))
			if re.Code >= 500 && (stage == "rcpt" || stage == "data") {
				rec.Permanent = 1
			}
		} else {
			rec.Error = sp(fmt.Sprintf("%s: %v", stage, err))
		}
		return rec
	}

	addr := net.JoinHostPort(up.Host, fmt.Sprint(up.Port))
	conn, err := (&net.Dialer{Timeout: c.timeout}).Dial("tcp", addr)
	if err != nil {
		return fail(err)
	}
	rec.UpstreamIP = nil
	if h, _, err := net.SplitHostPort(conn.RemoteAddr().String()); err == nil {
		rec.UpstreamIP = sp(h)
	}
	if up.Security == "ssl" {
		tc := tls.Client(conn, upstreamTLS(up))
		conn.SetDeadline(time.Now().Add(c.timeout))
		if err := tc.Handshake(); err != nil {
			conn.Close()
			return fail(err)
		}
		c.tlsVer = tlsVersionName(tc.ConnectionState().Version)
		conn = tc
	}
	c.setConn(conn)
	code, msg, err := c.read()
	if err != nil {
		return fail(err)
	}
	if code == 220 {
		rec.ServerBanner = sp(msg)
	} else {
		return fail(&respError{code, msg})
	}
	if err := c.ehlo(s.cfg.Hostname); err != nil {
		return fail(err)
	}
	if up.Security == "starttls" {
		stage = "starttls"
		if _, ok := c.exts["starttls"]; !ok {
			return fail(fmt.Errorf("STARTTLS extension not supported by server."))
		}
		code, msg, err := c.cmd("STARTTLS")
		if err != nil {
			return fail(err)
		}
		if code != 220 {
			return fail(&respError{code, msg})
		}
		tc := tls.Client(c.conn, upstreamTLS(up))
		c.arm()
		if err := tc.Handshake(); err != nil {
			return fail(err)
		}
		c.tlsVer = tlsVersionName(tc.ConnectionState().Version)
		c.setConn(tc)
		if err := c.ehlo(s.cfg.Hostname); err != nil {
			return fail(err)
		}
	}
	if c.tlsVer != "" {
		rec.TLSVersion = sp(c.tlsVer)
	}
	if up.Username != "" {
		stage = "auth"
		if err := s.login(c, up); err != nil {
			return fail(err)
		}
	}

	stage = "mail"
	opts := ""
	if _, ok := c.exts["size"]; ok {
		opts += fmt.Sprintf(" SIZE=%d", len(raw))
	}
	if _, ok := c.exts["8bitmime"]; ok && has8bit(raw) {
		opts += " BODY=8BITMIME"
	}
	if _, ok := c.exts["smtputf8"]; ok && !isASCII(mailFrom+strings.Join(rcpts, "")) {
		opts += " SMTPUTF8"
	}
	if code, msg, err = c.cmd("MAIL FROM:<%s>%s", mailFrom, opts); err != nil {
		return fail(err)
	} else if code != 250 {
		return fail(&respError{code, msg})
	}

	stage = "rcpt"
	refused := []string{}
	var last *respError
	for _, r := range rcpts {
		code, msg, err := c.cmd("RCPT TO:<%s>", r)
		if err != nil {
			return fail(err)
		}
		if code != 250 && code != 251 {
			refused = append(refused, fmt.Sprintf("'%s': '%d %s'", r, code, collapse(msg)))
			last = &respError{code, msg}
		}
	}
	if len(refused) == len(rcpts) && last != nil {
		return fail(last)
	}

	stage = "data"
	if code, msg, err = c.cmd("DATA"); err != nil {
		return fail(err)
	} else if code != 354 {
		return fail(&respError{code, msg})
	}
	c.arm()
	w := c.tp.DotWriter()
	if _, err := w.Write(raw); err != nil {
		return fail(err)
	}
	if err := w.Close(); err != nil {
		return fail(err)
	}
	code, msg, err = c.read()
	if err != nil {
		return fail(err)
	}
	rec.SMTPCode, rec.SMTPResponse = ip(code), sp(collapse(msg))
	if code != 250 {
		return fail(&respError{code, msg})
	}
	rec.Status = "sent"
	if len(refused) > 0 {
		rec.Error = sp("recipients refused by upstream: {" + strings.Join(refused, ", ") + "}")
	}
	return rec
}

func (s *Sender) login(c *smtpClient, up Upstream) error {
	pw, err := up.Password()
	if err != nil {
		return err
	}
	auth, ok := c.exts["auth"]
	if !ok {
		return fmt.Errorf("SMTP AUTH extension not supported by server.")
	}
	mechs := strings.Fields(strings.ToUpper(auth))
	has := func(m string) bool {
		for _, x := range mechs {
			if x == m {
				return true
			}
		}
		return false
	}
	b64 := base64.StdEncoding
	switch {
	case has("PLAIN"):
		code, msg, err := c.cmd("AUTH PLAIN %s", b64.EncodeToString([]byte("\x00"+up.Username+"\x00"+pw)))
		if err != nil {
			return err
		}
		if code != 235 {
			return &respError{code, msg}
		}
	case has("LOGIN"):
		code, msg, err := c.cmd("AUTH LOGIN %s", b64.EncodeToString([]byte(up.Username)))
		if err != nil {
			return err
		}
		if code == 334 {
			code, msg, err = c.cmd("%s", b64.EncodeToString([]byte(pw)))
			if err != nil {
				return err
			}
		}
		if code != 235 {
			return &respError{code, msg}
		}
	default:
		return fmt.Errorf("No suitable authentication method found.")
	}
	return nil
}

func has8bit(b []byte) bool {
	for _, x := range b {
		if x > 127 {
			return true
		}
	}
	return false
}

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] > 127 {
			return false
		}
	}
	return true
}

// deliver tries the upstream servers in order. A 5xx on RCPT/DATA is permanent; anything else moves on.
func (s *Sender) deliver(raw []byte, mailFrom string, rcpts []string, meta Meta, attempt int, upstream string) *Delivery {
	ups := []Upstream{}
	for _, u := range s.cfg.Upstreams {
		if upstream == "" || u.Name == upstream {
			ups = append(ups, u)
		}
	}
	if len(ups) == 0 {
		ups = s.cfg.Upstreams
	}
	d := &Delivery{}
	for _, up := range ups {
		rec := s.attempt(up, raw, mailFrom, rcpts, meta, attempt)
		if _, err := s.store.writeAttempt(rec); err != nil {
			logf("[store] cannot write attempt: %v", err)
		}
		d.Attempts = append(d.Attempts, rec)
		d.Final = rec
		if rec.Status == "sent" {
			d.OK = true
			return d
		}
		if rec.Permanent == 1 {
			d.Permanent = true
			return d
		}
	}
	return d
}
