package main

import (
	"bytes"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const maxBody = 30 * 1024 * 1024

type webApp struct {
	cfg       *Config
	store     *Store
	engine    *Engine
	settings  *RuntimeSettings
	token     string
	adminPW   string
	dashboard []byte
}

func eq(a, b string) bool { return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1 }

func newWeb(cfg *Config, store *Store, engine *Engine, settings *RuntimeSettings, dashboard []byte) (*http.Server, error) {
	token, _, err := readSecret(cfg.APITokenEnv)
	if err != nil {
		return nil, err
	}
	pw, _, err := readSecret(cfg.AdminPasswordEnv)
	if err != nil {
		return nil, err
	}
	if pw == "" {
		pw = token
	}
	if pw == "" {
		return nil, fmt.Errorf("Set %s (dashboard) and/or %s (API)", cfg.AdminPasswordEnv, cfg.APITokenEnv)
	}
	w := &webApp{cfg, store, engine, settings, token, pw, dashboard}
	return &http.Server{Addr: net.JoinHostPort(cfg.WebListenHost, fmt.Sprint(cfg.WebListenPort)),
		Handler: w, ReadHeaderTimeout: 15 * time.Second}, nil
}

type statusWriter struct {
	http.ResponseWriter
	code int
}

func (s *statusWriter) WriteHeader(c int) { s.code = c; s.ResponseWriter.WriteHeader(c) }

func (w *webApp) send(rw http.ResponseWriter, code int, body []byte, ctype string) {
	h := rw.Header()
	h.Set("Content-Type", ctype)
	h.Set("Content-Length", strconv.Itoa(len(body)))
	h.Set("Cache-Control", "no-store")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("X-Frame-Options", "DENY")
	rw.WriteHeader(code)
	rw.Write(body)
}

func (w *webApp) json(rw http.ResponseWriter, code int, payload any) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(payload); err != nil {
		w.send(rw, 500, []byte(`{"error":"encoding failed"}`), "application/json")
		return
	}
	w.send(rw, code, bytes.TrimRight(buf.Bytes(), "\n"), "application/json")
}

func (w *webApp) authorized(rw http.ResponseWriter, r *http.Request) (string, bool) {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") && w.token != "" && eq(h[7:], w.token) {
		return "api-token", true
	}
	if strings.HasPrefix(h, "Basic ") {
		if b, err := base64.StdEncoding.DecodeString(h[6:]); err == nil {
			user, pw, _ := strings.Cut(string(b), ":")
			if eq(user, w.cfg.AdminUser) && eq(pw, w.adminPW) {
				return user, true
			}
		}
	}
	rw.Header().Set("WWW-Authenticate", `Basic realm="mailrelay", charset="UTF-8"`)
	w.send(rw, 401, []byte(`{"error":"unauthorized"}`), "application/json")
	return "", false
}

func (w *webApp) configSummary() Row {
	rt := w.settings.RT()
	ups := []Row{}
	for i, u := range w.cfg.Upstreams {
		ups = append(ups, Row{"order": i + 1, "name": u.Name, "host": u.Host, "port": u.Port,
			"security": u.Security, "username": u.Username})
	}
	var rewrite any
	if rt.RewriteFrom {
		rewrite = rt.FromAddress
	}
	return Row{
		"hostname": w.cfg.Hostname, "smtp_port": w.cfg.SMTPListenPort,
		"allowed_networks": rt.AllowedNetworks, "auth_users": w.settings.UserCount(true),
		"require_auth": rt.RequireAuth, "starttls": w.cfg.TLSCert != "", "tls": w.cfg.TLSInfo,
		"rewrite_from": rewrite, "max_message_mb": w.cfg.MaxMessageMB, "retry_minutes": rt.RetryMinutes,
		"queue_max_age_hours": rt.QueueMaxAgeHours, "upstreams": ups,
	}
}

func qInt(q url.Values, k string, def int) (int, error) {
	v := q.Get(k)
	if v == "" {
		return def, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		return 0, fmt.Errorf("invalid literal for int(): '%s'", v)
	}
	return n, nil
}

func (w *webApp) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	sw := &statusWriter{ResponseWriter: rw, code: 200}
	w.route(sw, r)
	p := r.URL.Path
	if !(strings.HasPrefix(p, "/health") || strings.HasPrefix(p, "/api/overview") || strings.HasPrefix(p, "/api/messages")) {
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		logf("[web] %s \"%s %s %s\" %d -", host, r.Method, r.URL.RequestURI(), r.Proto, sw.code)
	}
}

func (w *webApp) route(rw http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if r.Method == http.MethodGet || r.Method == http.MethodHead {
		w.get(rw, r, path)
		return
	}
	if strings.HasPrefix(path, "/api/settings") || strings.HasPrefix(path, "/api/users") {
		if r.Method == http.MethodPut || r.Method == http.MethodPost || r.Method == http.MethodDelete {
			w.settingsWrite(rw, r, path)
			return
		}
	}
	if r.Method == http.MethodPost {
		w.post(rw, r, path)
		return
	}
	w.json(rw, 404, Row{"error": "not found"})
}

func (w *webApp) fail(rw http.ResponseWriter, err error) {
	w.json(rw, 500, Row{"error": err.Error()})
}

func (w *webApp) get(rw http.ResponseWriter, r *http.Request, path string) {
	q := r.URL.Query()
	if path == "/health" {
		w.json(rw, 200, Row{"ok": true})
		return
	}
	if _, ok := w.authorized(rw, r); !ok {
		return
	}
	bad := func(err error) { w.json(rw, 400, Row{"error": "ValueError: " + err.Error()}) }
	switch {
	case path == "/" || path == "/index.html":
		w.send(rw, 200, w.dashboard, "text/html; charset=utf-8")
	case path == "/api/overview":
		hours, err := qInt(q, "hours", 24)
		if err != nil {
			bad(err)
			return
		}
		ov, err := w.store.overview(hours)
		if err != nil {
			w.fail(rw, err)
			return
		}
		ov["config"] = w.configSummary()
		w.json(rw, 200, ov)
	case path == "/api/messages":
		limit, err := qInt(q, "limit", 100)
		if err != nil {
			bad(err)
			return
		}
		rows, err := w.store.messages(min(limit, 1000), q.Get("status"), q.Get("q"), q.Get("since"))
		if err != nil {
			w.fail(rw, err)
			return
		}
		w.json(rw, 200, rows)
	case strings.HasPrefix(path, "/api/messages/"):
		id := path[strings.LastIndex(path, "/")+1:]
		if u, err := url.PathUnescape(id); err == nil {
			id = u
		}
		m, err := w.store.getMessage(id)
		if err != nil {
			w.fail(rw, err)
		} else if m == nil {
			w.json(rw, 404, Row{"error": "not found"})
		} else {
			w.json(rw, 200, m)
		}
	case path == "/api/settings":
		w.settingsPayload(rw, 200)
	case path == "/api/attempts":
		limit, err := qInt(q, "limit", 100)
		if err != nil {
			bad(err)
			return
		}
		rows, err := w.store.attempts(min(limit, 1000), q.Get("upstream"), q.Get("status"), q.Get("since"), "")
		if err != nil {
			w.fail(rw, err)
			return
		}
		w.json(rw, 200, rows)
	default:
		w.json(rw, 404, Row{"error": "not found"})
	}
}

// orderedSettings keeps the key order of the settings object stable (same as the Python API).
type orderedSettings struct {
	keys []string
	m    map[string]any
}

func (o orderedSettings) MarshalJSON() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			buf.WriteByte(',')
		}
		kb, _ := json.Marshal(k)
		vb, err := json.Marshal(o.m[k])
		if err != nil {
			return nil, err
		}
		buf.Write(kb)
		buf.WriteByte(':')
		buf.Write(vb)
	}
	buf.WriteByte('}')
	return buf.Bytes(), nil
}

func (w *webApp) settingsPayload(rw http.ResponseWriter, code int) {
	view, order, err := w.settings.View()
	if err != nil {
		w.fail(rw, err)
		return
	}
	w.json(rw, code, Row{"settings": orderedSettings{order, view}, "users": w.settings.Users()})
}

func readJSON(r *http.Request) (map[string]any, error) {
	if r.ContentLength > maxBody {
		return nil, fmt.Errorf("request too large")
	}
	b, err := io.ReadAll(io.LimitReader(r.Body, maxBody+1))
	if err != nil {
		return nil, err
	}
	if len(b) > maxBody {
		return nil, fmt.Errorf("request too large")
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return map[string]any{}, nil
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return nil, fmt.Errorf("invalid JSON: %v", err)
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("request body must be a JSON object")
	}
	return m, nil
}

func (w *webApp) settingsWrite(rw http.ResponseWriter, r *http.Request, path string) {
	by, ok := w.authorized(rw, r)
	if !ok {
		return
	}
	ct, _, _ := strings.Cut(r.Header.Get("Content-Type"), ";")
	if strings.TrimSpace(ct) != "application/json" {
		w.json(rw, 415, Row{"error": "Content-Type must be application/json"})
		return
	}
	req, err := readJSON(r)
	if err != nil {
		w.json(rw, 400, Row{"error": err.Error()})
		return
	}
	str := func(k string) string { s, _ := req[k].(string); return s }
	switch {
	case r.Method == http.MethodPut && path == "/api/settings":
		err = w.settings.Update(req, by)
	case r.Method == http.MethodPost && path == "/api/settings/reset":
		var keys []string
		if l, ok := req["keys"].([]any); ok {
			for _, k := range l {
				keys = append(keys, scalarStr(k))
			}
		}
		err = w.settings.Reset(keys, by)
	case r.Method == http.MethodPost && path == "/api/users":
		var pw *string
		if p, ok := req["password"].(string); ok {
			pw = &p
		}
		var enabled any = true
		if e, ok := req["enabled"]; ok {
			enabled = e
		}
		err = w.settings.SaveUser(str("username"), pw, enabled, str("note"), by)
	case r.Method == http.MethodDelete && strings.HasPrefix(path, "/api/users/"):
		name := path[len("/api/users/"):]
		if u, e := url.PathUnescape(name); e == nil {
			name = u
		}
		err = w.settings.DeleteUser(name, by)
	default:
		w.json(rw, 404, Row{"error": "not found"})
		return
	}
	switch e := err.(type) {
	case nil:
		w.settingsPayload(rw, 200)
	case userError:
		w.json(rw, 400, Row{"error": e.Error()})
	default:
		if err == errNotFound {
			w.json(rw, 404, Row{"error": "not found: " + path[strings.LastIndex(path, "/")+1:]})
		} else {
			w.json(rw, 500, Row{"error": err.Error()})
		}
	}
}

func strList(v any) ([]string, bool) {
	switch x := v.(type) {
	case nil:
		return nil, true
	case string:
		return []string{x}, true
	case []any:
		var out []string
		for _, e := range x {
			s, ok := e.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}

func (w *webApp) post(rw http.ResponseWriter, r *http.Request, path string) {
	if _, ok := w.authorized(rw, r); !ok {
		return
	}
	req, err := readJSON(r)
	if err != nil {
		w.json(rw, 400, Row{"error": "ValueError: " + err.Error()})
		return
	}
	badReq := func(format string, a ...any) { w.json(rw, 400, Row{"error": fmt.Sprintf(format, a...)}) }
	need := func(k string) (any, bool) {
		v, ok := req[k]
		if !ok {
			badReq("KeyError: '%s'", k)
		}
		return v, ok
	}
	switch path {
	case "/api/queue/retry":
		rid, _ := req["relay_id"].(string)
		go w.engine.processQueue(true, rid)
		var shown any = "all"
		if rid != "" {
			shown = rid
		}
		w.json(rw, 202, Row{"retrying": shown, "queued": len(w.engine.queued())})
	case "/api/send", "/api/reply":
		rt := w.settings.RT()
		if rt.FromAddress == "" {
			badReq("MAILRELAY_FROM_ADDRESS is not set")
			return
		}
		var msg *outMessage
		str := func(k string) string { s, _ := req[k].(string); return s }
		if path == "/api/reply" {
			eml, ok := need("original_eml")
			if !ok {
				return
			}
			body, ok := need("body")
			if !ok {
				return
			}
			emls, ok1 := eml.(string)
			bodys, ok2 := body.(string)
			if !ok1 || !ok2 {
				badReq("TypeError: original_eml and body must be strings")
				return
			}
			replyAll, _ := req["reply_all"].(bool)
			quote := true
			if q, ok := req["quote"].(bool); ok {
				quote = q
			}
			msg, err = buildReply([]byte(emls), rt.FromAddress, rt.FromName, bodys, replyAll, quote, str("html"))
		} else {
			toV, ok := need("to")
			if !ok {
				return
			}
			subj, ok := need("subject")
			if !ok {
				return
			}
			body, ok := need("body")
			if !ok {
				return
			}
			to, ok1 := strList(toV)
			cc, ok2 := strList(req["cc"])
			subjS, ok3 := subj.(string)
			bodyS, ok4 := body.(string)
			if !ok1 || !ok2 || !ok3 || !ok4 {
				badReq("TypeError: invalid field type")
				return
			}
			msg, err = buildMessage(rt.FromAddress, rt.FromName, to, subjS, bodyS, cc, str("html"),
				str("in_reply_to"), str("references"))
		}
		if err != nil {
			badReq("ValueError: %v", err)
			return
		}
		host, _, _ := net.SplitHostPort(r.RemoteAddr)
		code, enh, text, rid := w.engine.accept(msg.Raw, rt.FromAddress, msg.Rcpts,
			ClientInfo{Source: "api", ClientIP: host}, str("upstream"))
		m, _ := w.store.getMessage(rid)
		status := 200
		if code != 250 {
			status = 502
		}
		w.json(rw, status, Row{"smtp_code": code, "smtp_text": fmt.Sprintf("%d.%d.%d %s", enh[0], enh[1], enh[2], text), "message": m})
	default:
		w.json(rw, 404, Row{"error": "not found"})
	}
}
