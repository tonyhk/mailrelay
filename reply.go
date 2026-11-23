package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"net/textproto"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

func addrDomain(addr string) string {
	if i := strings.LastIndex(addr, "@"); i >= 0 {
		return addr[i+1:]
	}
	return "localhost"
}

// parseAddrs is the lenient equivalent of Python's email.utils.getaddresses: returns only the addresses.
func parseAddrs(values ...string) []string {
	var out []string
	for _, v := range values {
		if strings.TrimSpace(v) == "" {
			continue
		}
		list, err := mail.ParseAddressList(v)
		if err != nil {
			// fall back to splitting on commas
			for _, p := range strings.Split(v, ",") {
				if a, err := mail.ParseAddress(strings.TrimSpace(p)); err == nil {
					out = append(out, a.Address)
				}
			}
			continue
		}
		for _, a := range list {
			out = append(out, a.Address)
		}
	}
	return out
}

func encodeHeader(s string) string {
	if isASCII(s) && !strings.ContainsAny(s, "\r\n") {
		return s
	}
	return mime.QEncoding.Encode("utf-8", strings.NewReplacer("\r", " ", "\n", " ").Replace(s))
}

func newMsgID(addr string) string {
	b := make([]byte, 6)
	rand.Read(b)
	return fmt.Sprintf("<%d.%s@%s>", time.Now().UnixNano(), hex.EncodeToString(b), addrDomain(addr))
}

func qpBody(s string) string {
	var buf bytes.Buffer
	w := quotedprintable.NewWriter(&buf)
	w.Write([]byte(strings.ReplaceAll(strings.ReplaceAll(s, "\r\n", "\n"), "\n", "\r\n")))
	w.Close()
	return buf.String()
}

type outMessage struct {
	Raw   []byte
	Rcpts []string
}

func buildMessage(fromAddr, fromName string, to []string, subject, body string, cc []string, html string,
	inReplyTo, references string) (*outMessage, error) {
	rcpts := parseAddrs(append(append([]string{}, strings.Join(to, ", ")), strings.Join(cc, ", "))...)
	if len(rcpts) == 0 {
		return nil, errors.New("no recipients")
	}
	var h bytes.Buffer
	hdr := func(k, v string) { h.WriteString(k + ": " + v + "\r\n") }
	hdr("From", formatAddr(fromName, fromAddr))
	hdr("To", strings.Join(to, ", "))
	if len(cc) > 0 {
		hdr("Cc", strings.Join(cc, ", "))
	}
	hdr("Subject", encodeHeader(subject))
	hdr("Date", httpDate(time.Now()))
	hdr("Message-ID", newMsgID(fromAddr))
	if inReplyTo != "" {
		hdr("In-Reply-To", inReplyTo)
		if references != "" {
			hdr("References", strings.TrimSpace(references+" "+inReplyTo))
		} else {
			hdr("References", inReplyTo)
		}
	}
	hdr("MIME-Version", "1.0")
	if html == "" {
		hdr("Content-Type", `text/plain; charset="utf-8"`)
		hdr("Content-Transfer-Encoding", "quoted-printable")
		h.WriteString("\r\n" + qpBody(body))
	} else {
		var mb bytes.Buffer
		mw := multipart.NewWriter(&mb)
		hdr("Content-Type", `multipart/alternative; boundary="`+mw.Boundary()+`"`)
		for _, p := range [][2]string{{"plain", body}, {"html", html}} {
			pw, _ := mw.CreatePart(textproto.MIMEHeader{
				"Content-Type":              {`text/` + p[0] + `; charset="utf-8"`},
				"Content-Transfer-Encoding": {"quoted-printable"},
			})
			io.WriteString(pw, qpBody(p[1]))
		}
		mw.Close()
		h.WriteString("\r\n")
		h.Write(bytes.ReplaceAll(mb.Bytes(), []byte("\r\n"), []byte("\n")))
		raw := bytes.ReplaceAll(h.Bytes(), []byte("\r\n"), []byte("\n"))
		return &outMessage{Raw: normalizeCRLF(raw), Rcpts: rcpts}, nil
	}
	return &outMessage{Raw: h.Bytes(), Rcpts: rcpts}, nil
}

func decodePart(body io.Reader, cte, charset string) string {
	var r io.Reader = body
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		r = base64.NewDecoder(base64.StdEncoding, &stripNL{r})
	case "quoted-printable":
		r = quotedprintable.NewReader(r)
	}
	b, _ := io.ReadAll(r)
	switch strings.ToLower(charset) {
	case "iso-8859-1", "latin1", "windows-1252", "cp1252":
		rs := make([]rune, len(b))
		for i, c := range b {
			rs[i] = rune(c)
		}
		return string(rs)
	}
	if !utf8.Valid(b) {
		return strings.ToValidUTF8(string(b), "�")
	}
	return string(b)
}

type stripNL struct{ r io.Reader }

func (s *stripNL) Read(p []byte) (int, error) {
	n, err := s.r.Read(p)
	out := p[:0]
	for _, c := range p[:n] {
		if c != '\r' && c != '\n' {
			out = append(out, c)
		}
	}
	return len(out), err
}

// plainBody finds the text/plain body of a message (first plain part of a multipart).
func plainBody(header mail.Header, body io.Reader) string {
	ct := header.Get("Content-Type")
	if ct == "" {
		ct = "text/plain"
	}
	mt, params, err := mime.ParseMediaType(ct)
	if err != nil {
		mt = "text/plain"
	}
	cte := header.Get("Content-Transfer-Encoding")
	switch {
	case strings.HasPrefix(mt, "multipart/"):
		mr := multipart.NewReader(body, params["boundary"])
		for {
			p, err := mr.NextRawPart()
			if err != nil {
				return ""
			}
			if s := plainBody(mail.Header(p.Header), p); s != "" {
				return s
			}
		}
	case mt == "text/plain":
		return decodePart(body, cte, params["charset"])
	}
	return ""
}

var reRE = regexp.MustCompile(`(?i)^\s*re\s*:`)

func replySubject(s string) string {
	if reRE.MatchString(s) {
		return s
	}
	return strings.TrimSpace("Re: " + s)
}

func decodedHeader(m *mail.Message, k string) string {
	v := m.Header.Get(k)
	if d, err := new(mime.WordDecoder).DecodeHeader(v); err == nil {
		return d
	}
	return v
}

// buildReply replies to Reply-To (or From) and keeps the thread with In-Reply-To / References.
func buildReply(originalEML []byte, fromAddr, fromName, body string, replyAll, quote bool, html string) (*outMessage, error) {
	orig, err := mail.ReadMessage(bytes.NewReader(originalEML))
	if err != nil {
		return nil, fmt.Errorf("cannot parse original message: %v", err)
	}
	target := orig.Header.Get("Reply-To")
	if target == "" {
		target = orig.Header.Get("From")
	}
	to := parseAddrs(target)
	var cc []string
	if replyAll {
		me := strings.ToLower(fromAddr)
		for _, a := range parseAddrs(orig.Header["To"]...) {
			if strings.ToLower(a) != me && !contains(to, a) && !contains(cc, a) {
				cc = append(cc, a)
			}
		}
		for _, a := range parseAddrs(orig.Header["Cc"]...) {
			if strings.ToLower(a) != me && !contains(to, a) && !contains(cc, a) {
				cc = append(cc, a)
			}
		}
	}
	if len(to) == 0 {
		return nil, errors.New("original message has no From or Reply-To address")
	}
	text := body
	if quote {
		plain := decodeBodyOf(orig)
		var q []string
		for _, l := range strings.Split(strings.ReplaceAll(strings.TrimSpace(plain), "\r\n", "\n"), "\n") {
			q = append(q, "> "+l)
		}
		text += fmt.Sprintf("\n\nOn %s, %s wrote:\n%s\n", orig.Header.Get("Date"), decodedHeader(orig, "From"), strings.Join(q, "\n"))
	}
	return buildMessage(fromAddr, fromName, to, replySubject(decodedHeader(orig, "Subject")), text, cc, html,
		orig.Header.Get("Message-ID"), orig.Header.Get("References"))
}

func decodeBodyOf(m *mail.Message) string { return plainBody(m.Header, m.Body) }
