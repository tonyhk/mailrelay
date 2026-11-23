package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	_ "modernc.org/sqlite"
)

func nowISO() string { return isoTime(time.Now()) }

func isoTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000") + "+00:00"
}

type Row = map[string]any

// SendRecord is one delivery attempt to one upstream server. Field order = column order.
type SendRecord struct {
	TimestampUTC string  `json:"timestamp_utc"`
	UpstreamName string  `json:"upstream_name"`
	UpstreamHost string  `json:"upstream_host"`
	UpstreamPort int     `json:"upstream_port"`
	Status       string  `json:"status"` // sent | failed
	Source       string  `json:"source"` // relay | api
	RelayID      *string `json:"relay_id"`
	Attempt      int     `json:"attempt"`
	ClientIP     *string `json:"client_ip"`
	ClientHelo   *string `json:"client_helo"`
	ClientUser   *string `json:"client_user"`
	UpstreamIP   *string `json:"upstream_ip"`
	Security     *string `json:"security"`
	TLSVersion   *string `json:"tls_version"`
	ServerBanner *string `json:"server_banner"`
	AuthUser     *string `json:"auth_user"`
	MailFrom     *string `json:"mail_from"`
	RcptTo       *string `json:"rcpt_to"`
	Subject      *string `json:"subject"`
	MessageID    *string `json:"message_id"`
	InReplyTo    *string `json:"in_reply_to"`
	SizeBytes    *int    `json:"size_bytes"`
	SMTPCode     *int    `json:"smtp_code"`
	SMTPResponse *string `json:"smtp_response"`
	Error        *string `json:"error"`
	Permanent    int     `json:"permanent"` // 1 = upstream rejected the message itself (5xx on RCPT/DATA)
	DurationMS   *int    `json:"duration_ms"`
}

type col struct{ name, def string }

var attemptCols = []col{
	{"timestamp_utc", "TEXT NOT NULL"}, {"upstream_name", "TEXT NOT NULL"}, {"upstream_host", "TEXT NOT NULL"},
	{"upstream_port", "INTEGER NOT NULL"}, {"status", "TEXT NOT NULL"}, {"source", "TEXT"}, {"relay_id", "TEXT"},
	{"attempt", "INTEGER"}, {"client_ip", "TEXT"}, {"client_helo", "TEXT"}, {"client_user", "TEXT"},
	{"upstream_ip", "TEXT"}, {"security", "TEXT"}, {"tls_version", "TEXT"}, {"server_banner", "TEXT"},
	{"auth_user", "TEXT"}, {"mail_from", "TEXT"}, {"rcpt_to", "TEXT"}, {"subject", "TEXT"}, {"message_id", "TEXT"},
	{"in_reply_to", "TEXT"}, {"size_bytes", "INTEGER"}, {"smtp_code", "INTEGER"}, {"smtp_response", "TEXT"},
	{"error", "TEXT"}, {"permanent", "INTEGER"}, {"duration_ms", "INTEGER"},
}

var messageCols = []col{
	{"relay_id", "TEXT PRIMARY KEY"}, {"received_utc", "TEXT NOT NULL"}, {"updated_utc", "TEXT"},
	{"source", "TEXT"}, {"status", "TEXT NOT NULL"}, // sending | sent | queued | bounced | expired
	{"client_ip", "TEXT"}, {"client_helo", "TEXT"}, {"client_user", "TEXT"}, {"client_tls", "INTEGER"},
	{"client_mail_from", "TEXT"}, {"mail_from", "TEXT"}, {"rcpt_to", "TEXT"}, {"subject", "TEXT"},
	{"message_id", "TEXT"}, {"size_bytes", "INTEGER"}, {"attempts", "INTEGER DEFAULT 0"},
	{"upstream_name", "TEXT"}, {"upstream_host", "TEXT"}, {"upstream_ip", "TEXT"}, {"smtp_code", "INTEGER"},
	{"smtp_response", "TEXT"}, {"last_error", "TEXT"}, {"next_retry_utc", "TEXT"},
}

var settingsCols = []col{{"key", "TEXT PRIMARY KEY"}, {"value", "TEXT NOT NULL"}, {"updated_utc", "TEXT"}, {"updated_by", "TEXT"}}

var userCols = []col{
	{"username", "TEXT PRIMARY KEY"}, {"password_hash", "TEXT NOT NULL"}, {"enabled", "INTEGER DEFAULT 1"},
	{"note", "TEXT"}, {"created_utc", "TEXT"}, {"updated_utc", "TEXT"}, {"last_login_utc", "TEXT"},
}

type Store struct {
	mu     sync.Mutex
	db     *sql.DB
	jsonl  string
	stdout bool
}

func openStore(dbPath, jsonlPath string, stdout bool) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0o755); err != nil {
		return nil, err
	}
	dsn := "file:" + filepath.ToSlash(dbPath) + "?_pragma=busy_timeout(30000)&_pragma=journal_mode(WAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	s := &Store{db: db, jsonl: jsonlPath, stdout: stdout}
	if err := s.ensure("smtp_log", append([]col{{"id", "INTEGER PRIMARY KEY AUTOINCREMENT"}}, attemptCols...)); err != nil {
		return nil, err
	}
	for _, t := range []struct {
		n string
		c []col
	}{{"messages", messageCols}, {"settings", settingsCols}, {"relay_users", userCols}} {
		if err := s.ensure(t.n, t.c); err != nil {
			return nil, err
		}
	}
	_, err = db.Exec(`
		CREATE INDEX IF NOT EXISTS idx_log_time ON smtp_log(timestamp_utc);
		CREATE INDEX IF NOT EXISTS idx_log_upstream ON smtp_log(upstream_name);
		CREATE INDEX IF NOT EXISTS idx_log_relay ON smtp_log(relay_id);
		CREATE INDEX IF NOT EXISTS idx_msg_time ON messages(received_utc);
		CREATE INDEX IF NOT EXISTS idx_msg_status ON messages(status);`)
	if err != nil {
		return nil, err
	}
	if jsonlPath != "" {
		if err := os.MkdirAll(filepath.Dir(jsonlPath), 0o755); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *Store) Close() { s.db.Close() }

// ensure creates the table, or adds any columns missing from an older version.
func (s *Store) ensure(table string, cols []col) error {
	parts := make([]string, len(cols))
	for i, c := range cols {
		parts[i] = c.name + " " + c.def
	}
	if _, err := s.db.Exec(fmt.Sprintf("CREATE TABLE IF NOT EXISTS %s (%s)", table, strings.Join(parts, ", "))); err != nil {
		return err
	}
	have := map[string]bool{}
	rows, err := s.db.Query(fmt.Sprintf("PRAGMA table_info(%s)", table))
	if err != nil {
		return err
	}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt any
		if err := rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return err
		}
		have[name] = true
	}
	rows.Close()
	for _, c := range cols {
		if !have[c.name] {
			def := strings.ReplaceAll(strings.ReplaceAll(c.def, "NOT NULL", ""), "PRIMARY KEY", "")
			if _, err := s.db.Exec(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table, c.name, def)); err != nil {
				return err
			}
		}
	}
	return nil
}

// query runs a statement and returns the rows as maps (the shape the JSON API and CLI use).
func (s *Store) query(q string, args ...any) ([]Row, error) {
	rows, err := s.db.Query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	names, _ := rows.Columns()
	out := []Row{}
	for rows.Next() {
		vals := make([]any, len(names))
		ptrs := make([]any, len(names))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		r := Row{}
		for i, n := range names {
			if b, ok := vals[i].([]byte); ok {
				vals[i] = string(b)
			}
			r[n] = vals[i]
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) one(q string, args ...any) (Row, error) {
	r, err := s.query(q, args...)
	if err != nil || len(r) == 0 {
		return nil, err
	}
	return r[0], nil
}

// ---- attempts ----
func (s *Store) writeAttempt(rec *SendRecord) (int64, error) {
	b, _ := json.Marshal(rec)
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var row map[string]any
	dec.Decode(&row)

	names := make([]string, len(attemptCols))
	marks := make([]string, len(attemptCols))
	args := make([]any, len(attemptCols))
	for i, c := range attemptCols {
		names[i], marks[i] = c.name, "?"
		if n, ok := row[c.name].(json.Number); ok {
			if iv, err := n.Int64(); err == nil {
				args[i] = iv
				continue
			}
		}
		args[i] = row[c.name]
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.Exec(fmt.Sprintf("INSERT INTO smtp_log (%s) VALUES (%s)", strings.Join(names, ", "), strings.Join(marks, ", ")), args...)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()

	// {"event":"smtp_attempt","id":N, ...columns in order}
	var line bytes.Buffer
	line.WriteString(`{"event":"smtp_attempt","id":` + fmt.Sprint(id))
	for i, c := range attemptCols {
		v, _ := json.Marshal(args[i])
		if n, ok := args[i].(json.Number); ok {
			v = []byte(n.String())
		}
		line.WriteString(`,"` + c.name + `":` + string(v))
	}
	line.WriteString("}")
	if s.jsonl != "" {
		if f, err := os.OpenFile(s.jsonl, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644); err == nil {
			f.Write(append(line.Bytes(), '\n'))
			f.Close()
		}
	}
	if s.stdout {
		fmt.Fprintln(os.Stdout, line.String())
	}
	return id, nil
}

func (s *Store) attempts(limit int, upstream, status, since, relayID string) ([]Row, error) {
	q, args := "SELECT * FROM smtp_log WHERE 1=1", []any{}
	for _, f := range []struct{ c, v string }{{"upstream_name", upstream}, {"status", status}, {"relay_id", relayID}} {
		if f.v != "" {
			q += " AND " + f.c + " = ?"
			args = append(args, f.v)
		}
	}
	if since != "" {
		q += " AND timestamp_utc >= ?"
		args = append(args, since)
	}
	q += " ORDER BY id DESC LIMIT ?"
	args = append(args, limit)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.query(q, args...)
}

// ---- messages ----
func (s *Store) createMessage(f Row) error {
	names, marks, args := []string{}, []string{}, []any{}
	for k, v := range f {
		names, marks, args = append(names, k), append(marks, "?"), append(args, v)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec(fmt.Sprintf("INSERT INTO messages (%s) VALUES (%s)", strings.Join(names, ", "), strings.Join(marks, ", ")), args...)
	return err
}

func (s *Store) updateMessage(relayID string, f Row) error {
	f["updated_utc"] = nowISO()
	sets, args := []string{}, []any{}
	for k, v := range f {
		sets, args = append(sets, k+" = ?"), append(args, v)
	}
	args = append(args, relayID)
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("UPDATE messages SET "+strings.Join(sets, ", ")+" WHERE relay_id = ?", args...)
	return err
}

func (s *Store) getMessage(relayID string) (Row, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.one("SELECT * FROM messages WHERE relay_id = ?", relayID)
	if err != nil || r == nil {
		return nil, err
	}
	att, err := s.query("SELECT * FROM smtp_log WHERE relay_id = ? ORDER BY id", relayID)
	if err != nil {
		return nil, err
	}
	r["attempt_log"] = att
	return r, nil
}

func (s *Store) messages(limit int, status, q, since string) ([]Row, error) {
	sq, args := "SELECT * FROM messages WHERE 1=1", []any{}
	if status == "failed" {
		sq += " AND status IN ('bounced','expired')"
	} else if status != "" {
		sq += " AND status = ?"
		args = append(args, status)
	}
	if since != "" {
		sq += " AND received_utc >= ?"
		args = append(args, since)
	}
	if q != "" {
		sq += " AND (relay_id LIKE ? OR mail_from LIKE ? OR client_mail_from LIKE ? OR rcpt_to LIKE ?" +
			" OR subject LIKE ? OR client_ip LIKE ? OR client_user LIKE ? OR message_id LIKE ?)"
		for i := 0; i < 8; i++ {
			args = append(args, "%"+q+"%")
		}
	}
	sq += " ORDER BY received_utc DESC LIMIT ?"
	args = append(args, limit)
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.query(sq, args...)
}

func (s *Store) overview(hours int) (Row, error) {
	since := isoTime(time.Now().Add(-time.Duration(hours) * time.Hour))
	s.mu.Lock()
	defer s.mu.Unlock()
	counts := map[string]int64{}
	var received int64
	rows, err := s.query("SELECT status, COUNT(*) n FROM messages WHERE received_utc >= ? GROUP BY status", since)
	if err != nil {
		return nil, err
	}
	for _, r := range rows {
		counts[r["status"].(string)] = r["n"].(int64)
		received += r["n"].(int64)
	}
	q1, _ := s.one("SELECT COUNT(*) n FROM messages WHERE status = 'queued'")
	b1, _ := s.one("SELECT COALESCE(SUM(size_bytes),0) n FROM messages WHERE received_utc >= ?", since)
	ups := Row{}
	urows, err := s.query(`SELECT upstream_name, SUM(status='sent') sent, SUM(status='failed') failed,
			MAX(CASE WHEN status='sent' THEN timestamp_utc END) last_ok,
			CAST(AVG(CASE WHEN status='sent' THEN duration_ms END) AS INTEGER) avg_ms
		FROM smtp_log WHERE timestamp_utc >= ? GROUP BY upstream_name`, since)
	if err != nil {
		return nil, err
	}
	for _, r := range urows {
		name, _ := r["upstream_name"].(string)
		e, _ := s.one("SELECT timestamp_utc, error, upstream_ip FROM smtp_log WHERE upstream_name = ? AND status='failed' ORDER BY id DESC LIMIT 1", name)
		if e != nil {
			r["last_error"] = e
		} else {
			r["last_error"] = nil
		}
		ip, _ := s.one("SELECT upstream_ip, server_banner FROM smtp_log WHERE upstream_name = ? AND upstream_ip IS NOT NULL ORDER BY id DESC LIMIT 1", name)
		r["last_ip"], r["last_banner"] = nil, nil
		if ip != nil {
			r["last_ip"], r["last_banner"] = ip["upstream_ip"], ip["server_banner"]
		}
		ups[name] = r
	}
	clients, err := s.query(`SELECT client_ip, COALESCE(client_user,'') client_user, COUNT(*) messages,
			SUM(status='sent') sent, MAX(received_utc) last_seen
		FROM messages WHERE received_utc >= ? GROUP BY client_ip, client_user
		ORDER BY messages DESC LIMIT 10`, since)
	if err != nil {
		return nil, err
	}
	return Row{
		"window_hours": hours, "received": received, "sent": counts["sent"], "queued_now": q1["n"],
		"bounced": counts["bounced"], "expired": counts["expired"], "bytes": b1["n"],
		"upstreams": ups, "clients": clients,
	}, nil
}

// ---- runtime settings (changed from the web UI) ----
type savedSetting struct {
	Value      any
	UpdatedUTC *string
	UpdatedBy  *string
}

func (s *Store) getSettings() (map[string]savedSetting, error) {
	s.mu.Lock()
	rows, err := s.query("SELECT * FROM settings")
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	out := map[string]savedSetting{}
	for _, r := range rows {
		var v any
		if err := json.Unmarshal([]byte(r["value"].(string)), &v); err != nil {
			continue
		}
		ss := savedSetting{Value: v}
		if t, ok := r["updated_utc"].(string); ok {
			ss.UpdatedUTC = &t
		}
		if t, ok := r["updated_by"].(string); ok {
			ss.UpdatedBy = &t
		}
		out[r["key"].(string)] = ss
	}
	return out, nil
}

func (s *Store) setSettings(values map[string]any, by string) error {
	ts := nowISO()
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range values {
		b, _ := json.Marshal(v)
		if _, err := s.db.Exec(`INSERT INTO settings (key, value, updated_utc, updated_by) VALUES (?, ?, ?, ?)
			ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_utc=excluded.updated_utc, updated_by=excluded.updated_by`,
			k, string(b), ts, by); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) deleteSettings(keys []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, k := range keys {
		if _, err := s.db.Exec("DELETE FROM settings WHERE key = ?", k); err != nil {
			return err
		}
	}
	return nil
}

// ---- relay users (SMTP AUTH accounts managed in the web UI) ----
func (s *Store) listRelayUsers() ([]Row, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rows, err := s.query("SELECT * FROM relay_users ORDER BY username")
	for _, r := range rows {
		n, _ := r["enabled"].(int64)
		r["enabled"] = n != 0
	}
	return rows, err
}

func (s *Store) upsertRelayUser(username, passwordHash string, enabled bool, note string) error {
	ts := nowISO()
	en := 0
	if enabled {
		en = 1
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ex, err := s.one("SELECT 1 x FROM relay_users WHERE username = ?", username)
	if err != nil {
		return err
	}
	if ex != nil {
		q, args := "UPDATE relay_users SET enabled = ?, note = ?, updated_utc = ?", []any{en, note, ts}
		if passwordHash != "" {
			q += ", password_hash = ?"
			args = append(args, passwordHash)
		}
		_, err = s.db.Exec(q+" WHERE username = ?", append(args, username)...)
		return err
	}
	_, err = s.db.Exec("INSERT INTO relay_users (username, password_hash, enabled, note, created_utc, updated_utc) VALUES (?, ?, ?, ?, ?, ?)",
		username, passwordHash, en, note, ts, ts)
	return err
}

func (s *Store) deleteRelayUser(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, err := s.db.Exec("DELETE FROM relay_users WHERE username = ?", username)
	return err
}

func (s *Store) touchRelayUser(username string) string {
	ts := nowISO()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.db.Exec("UPDATE relay_users SET last_login_utc = ? WHERE username = ?", ts, username)
	return ts
}
