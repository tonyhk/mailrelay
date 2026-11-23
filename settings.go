package main

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
)

type runtimeKey struct{ Key, Type, Label string }

// Order matters for the API output (it mirrors the Python dict order).
var runtimeKeys = []runtimeKey{
	{"allowed_networks", "cidrs", "Networks allowed to relay without login"},
	{"require_auth", "bool", "Every client must log in, even from allowed networks"},
	{"allowed_sender_domains", "domains", "Allowed sender domains (empty = any)"},
	{"max_recipients", "int", "Max recipients per message"},
	{"rewrite_from", "bool", "Rewrite envelope sender + From: to the relay address"},
	{"from_address", "email", "Relay From address"},
	{"from_name", "str", "Relay From name"},
	{"retry_minutes", "ints", "Retry schedule in minutes (last value repeats)"},
	{"queue_max_age_hours", "float", "Give up on queued mail after (hours)"},
}

func keyInfo(k string) (runtimeKey, bool) {
	for _, rk := range runtimeKeys {
		if rk.Key == k {
			return rk, true
		}
	}
	return runtimeKey{}, false
}

// Runtime is an immutable snapshot of the settings that can change without a restart.
type Runtime struct {
	AllowedNetworks      []string
	RequireAuth          bool
	AllowedSenderDomains []string
	MaxRecipients        int
	RewriteFrom          bool
	FromAddress          string
	FromName             string
	RetryMinutes         []int
	QueueMaxAgeHours     float64
}

func runtimeToMap(r *Runtime) map[string]any {
	return map[string]any{
		"allowed_networks": r.AllowedNetworks, "require_auth": r.RequireAuth,
		"allowed_sender_domains": r.AllowedSenderDomains, "max_recipients": r.MaxRecipients,
		"rewrite_from": r.RewriteFrom, "from_address": r.FromAddress, "from_name": r.FromName,
		"retry_minutes": r.RetryMinutes, "queue_max_age_hours": r.QueueMaxAgeHours,
	}
}

func runtimeFromMap(m map[string]any) *Runtime {
	return &Runtime{
		AllowedNetworks: m["allowed_networks"].([]string), RequireAuth: m["require_auth"].(bool),
		AllowedSenderDomains: m["allowed_sender_domains"].([]string), MaxRecipients: m["max_recipients"].(int),
		RewriteFrom: m["rewrite_from"].(bool), FromAddress: m["from_address"].(string),
		FromName: m["from_name"].(string), RetryMinutes: m["retry_minutes"].([]int),
		QueueMaxAgeHours: m["queue_max_age_hours"].(float64),
	}
}

func runtimeDefaults(c *Config) *Runtime {
	nets := c.AllowedNetworks
	if nets == nil {
		nets = []string{}
	}
	doms := c.AllowedSenderDomains
	if doms == nil {
		doms = []string{}
	}
	return &Runtime{
		AllowedNetworks: nets, RequireAuth: c.RequireAuth, AllowedSenderDomains: doms,
		MaxRecipients: c.MaxRecipients, RewriteFrom: c.RewriteFrom, FromAddress: c.FromAddress,
		FromName: c.FromName, RetryMinutes: c.RetryMinutes, QueueMaxAgeHours: c.QueueMaxAgeHours,
	}
}

var (
	usernameRE = regexp.MustCompile(`^[A-Za-z0-9._@+-]{1,64}$`)
	domainRE   = regexp.MustCompile(`^[a-z0-9.-]+\.[a-z0-9-]+$`)
	emailRE    = regexp.MustCompile(`^[^@\s]+@[^@\s]+\.[^@\s]+$`)
	splitRE    = regexp.MustCompile(`[,\s]+`)
)

const pbkdf2Iter = 200_000

func hashPassword(pw string) (string, error) {
	salt := make([]byte, 16)
	rand.Read(salt)
	dk, err := pbkdf2.Key(sha256.New, pw, salt, pbkdf2Iter, 32)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("pbkdf2_sha256$%d$%s$%s", pbkdf2Iter, hex.EncodeToString(salt), hex.EncodeToString(dk)), nil
}

func checkPassword(pw, stored string) bool {
	parts := strings.Split(stored, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2_sha256" {
		return false
	}
	it, err := strconv.Atoi(parts[1])
	if err != nil || it < 1 {
		return false
	}
	salt, err := hex.DecodeString(parts[2])
	if err != nil {
		return false
	}
	want, err := hex.DecodeString(parts[3])
	if err != nil {
		return false
	}
	got, err := pbkdf2.Key(sha256.New, pw, salt, it, len(want))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(got, want) == 1
}

func scalarStr(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		if x == math.Trunc(x) {
			return strconv.FormatFloat(x, 'f', -1, 64)
		}
		return strconv.FormatFloat(x, 'g', -1, 64)
	case bool:
		if x {
			return "True"
		}
		return "False"
	case nil:
		return "None"
	}
	return fmt.Sprint(v)
}

func items(v any) []string {
	var raw []string
	switch x := v.(type) {
	case nil:
		return nil
	case string:
		raw = splitRE.Split(x, -1)
	case []string:
		raw = x
	case []any:
		for _, e := range x {
			raw = append(raw, scalarStr(e))
		}
	case []int:
		for _, e := range x {
			raw = append(raw, strconv.Itoa(e))
		}
	default:
		raw = []string{scalarStr(v)}
	}
	var out []string
	for _, s := range raw {
		if s = strings.TrimSpace(s); s != "" {
			out = append(out, s)
		}
	}
	return out
}

func toBool(v any) (bool, error) {
	switch x := v.(type) {
	case bool:
		return x, nil
	case string:
		switch strings.ToLower(x) {
		case "1", "true", "yes", "on":
			return true, nil
		case "0", "false", "no", "off", "":
			return false, nil
		}
	case float64:
		return x != 0, nil
	case int:
		return x != 0, nil
	}
	return false, errors.New("must be true or false")
}

func toInt(v any) (int, error) {
	switch x := v.(type) {
	case float64:
		return int(x), nil
	case int:
		return x, nil
	case string:
		n, err := strconv.Atoi(strings.TrimSpace(x))
		if err != nil {
			return 0, fmt.Errorf("invalid literal for int(): '%s'", x)
		}
		return n, nil
	}
	return 0, fmt.Errorf("int() argument must be a string or a number, not '%T'", v)
}

func toFloat(v any) (float64, error) {
	switch x := v.(type) {
	case float64:
		return x, nil
	case int:
		return float64(x), nil
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(x), 64)
		if err != nil {
			return 0, fmt.Errorf("could not convert string to float: '%s'", x)
		}
		return f, nil
	}
	return 0, fmt.Errorf("float() argument must be a string or a number, not '%T'", v)
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

// normalize validates one runtime setting and returns it in canonical form.
func normalize(key string, value any) (any, error) {
	rk, _ := keyInfo(key)
	switch rk.Type {
	case "cidrs":
		out := []string{}
		for _, n := range items(value) {
			p, err := parseNet(n)
			if err != nil {
				return nil, fmt.Errorf("'%s' is not a valid IP network", n)
			}
			if p.Bits() == 0 {
				return nil, fmt.Errorf("'%s' would make this an open relay", n)
			}
			if s := p.String(); !contains(out, s) {
				out = append(out, s)
			}
		}
		return out, nil
	case "domains":
		out := []string{}
		for _, d := range items(value) {
			d = strings.TrimLeft(strings.ToLower(d), "@")
			if !domainRE.MatchString(d) {
				return nil, fmt.Errorf("'%s' is not a valid domain", d)
			}
			if !contains(out, d) {
				out = append(out, d)
			}
		}
		return out, nil
	case "bool":
		return toBool(value)
	case "int":
		v, err := toInt(value)
		if err != nil {
			return nil, err
		}
		if v < 1 || v > 10000 {
			return nil, errors.New("must be between 1 and 10000")
		}
		return v, nil
	case "float":
		v, err := toFloat(value)
		if err != nil {
			return nil, err
		}
		if !(v > 0 && v <= 24*30) {
			return nil, errors.New("must be between 0 and 720")
		}
		return v, nil
	case "ints":
		out := []int{}
		for _, x := range items(value) {
			n, err := toInt(x)
			if err != nil {
				return nil, err
			}
			out = append(out, n)
		}
		if len(out) == 0 {
			return nil, errors.New("needs at least one value, each 1..1440 minutes")
		}
		for _, n := range out {
			if n < 1 || n > 24*60 {
				return nil, errors.New("needs at least one value, each 1..1440 minutes")
			}
		}
		return out, nil
	case "email":
		v := ""
		if value != nil {
			v = strings.TrimSpace(scalarStr(value))
		}
		if v != "" && !emailRE.MatchString(v) {
			return nil, errors.New("is not a valid email address")
		}
		return v, nil
	}
	v := ""
	if value != nil {
		v = strings.TrimSpace(scalarStr(value))
	}
	if r := []rune(v); len(r) > 200 {
		v = string(r[:200])
	}
	return v, nil
}

func ipAllowed(ip string, networks []string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	addr = addr.Unmap()
	for _, n := range networks {
		if p, err := parseNet(n); err == nil && p.Contains(addr) {
			return true
		}
	}
	return false
}

// RuntimeSettings owns the live runtime values and the relay user list.
type RuntimeSettings struct {
	store    *Store
	mu       sync.Mutex // serialises writers
	rt       atomic.Pointer[Runtime]
	defaults *Runtime
	envUsers map[string]string // read-only, from env / file

	umu     sync.RWMutex
	dbUsers map[string]Row

	Warnings []string
}

func newRuntimeSettings(cfg *Config, store *Store) (*RuntimeSettings, error) {
	s := &RuntimeSettings{store: store, defaults: runtimeDefaults(cfg), envUsers: map[string]string{}, dbUsers: map[string]Row{}}
	for k, v := range cfg.RelayUsers {
		s.envUsers[k] = v
	}
	saved, err := store.getSettings()
	if err != nil {
		return nil, err
	}
	values := runtimeToMap(s.defaults)
	for _, rk := range runtimeKeys {
		sv, ok := saved[rk.Key]
		if !ok {
			continue
		}
		n, err := normalize(rk.Key, sv.Value)
		if err != nil {
			s.Warnings = append(s.Warnings, fmt.Sprintf("ignoring saved setting %s: %v", rk.Key, err))
			continue
		}
		values[rk.Key] = n
	}
	if err := s.reloadUsers(); err != nil {
		return nil, err
	}
	s.Warnings = append(s.Warnings, s.check(values)...)
	s.rt.Store(runtimeFromMap(values))
	return s, nil
}

func (s *RuntimeSettings) RT() *Runtime { return s.rt.Load() }

func (s *RuntimeSettings) reloadUsers() error {
	rows, err := s.store.listRelayUsers()
	if err != nil {
		return err
	}
	m := map[string]Row{}
	for _, r := range rows {
		m[r["username"].(string)] = r
	}
	s.umu.Lock()
	s.dbUsers = m
	s.umu.Unlock()
	return nil
}

func (s *RuntimeSettings) check(values map[string]any) []string {
	var p []string
	if values["rewrite_from"].(bool) && values["from_address"].(string) == "" {
		p = append(p, "rewrite From needs a From address")
	}
	if values["require_auth"].(bool) && s.UserCount(true) == 0 {
		p = append(p, "requiring login needs at least one enabled relay user")
	}
	return p
}

func (s *RuntimeSettings) View() (map[string]any, []string, error) {
	saved, err := s.store.getSettings()
	if err != nil {
		return nil, nil, err
	}
	cur, def := runtimeToMap(s.RT()), runtimeToMap(s.defaults)
	out := map[string]any{}
	var order []string
	for _, rk := range runtimeKeys {
		sv, over := saved[rk.Key]
		out[rk.Key] = map[string]any{"value": cur[rk.Key], "default": def[rk.Key], "type": rk.Type, "label": rk.Label,
			"overridden": over, "updated_utc": sv.UpdatedUTC, "updated_by": sv.UpdatedBy}
		order = append(order, rk.Key)
	}
	return out, order, nil
}

func (s *RuntimeSettings) Overridden() []string {
	saved, _ := s.store.getSettings()
	var out []string
	for _, rk := range runtimeKeys {
		if _, ok := saved[rk.Key]; ok {
			out = append(out, rk.Key)
		}
	}
	return out
}

type userError struct{ msg string }

func (e userError) Error() string { return e.msg }

func verr(format string, a ...any) error { return userError{fmt.Sprintf(format, a...)} }

var errNotFound = errors.New("not found")

func (s *RuntimeSettings) Update(changes map[string]any, by string) error {
	var unknown []string
	for k := range changes {
		if _, ok := keyInfo(k); !ok {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return verr("not a runtime setting: %s", strings.Join(unknown, ", "))
	}
	s.mu.Lock()
	values := runtimeToMap(s.RT())
	normalized := map[string]any{}
	for _, rk := range runtimeKeys { // deterministic error order
		v, ok := changes[rk.Key]
		if !ok {
			continue
		}
		n, err := normalize(rk.Key, v)
		if err != nil {
			s.mu.Unlock()
			return verr("%s: %v", rk.Key, err)
		}
		normalized[rk.Key] = n
		values[rk.Key] = n
	}
	if p := s.check(values); len(p) > 0 {
		s.mu.Unlock()
		return verr("%s", strings.Join(p, "; "))
	}
	cur := runtimeToMap(s.RT())
	if err := s.store.setSettings(normalized, by); err != nil {
		s.mu.Unlock()
		return err
	}
	s.rt.Store(runtimeFromMap(values))
	s.mu.Unlock()
	for _, rk := range runtimeKeys {
		if n, ok := normalized[rk.Key]; ok && !reflect.DeepEqual(n, cur[rk.Key]) {
			logf("[settings] %s set %s = %v", by, rk.Key, n)
		}
	}
	return nil
}

func (s *RuntimeSettings) Reset(keys []string, by string) error {
	var ks []string
	for _, k := range keys {
		if _, ok := keyInfo(k); ok {
			ks = append(ks, k)
		}
	}
	s.mu.Lock()
	values := runtimeToMap(s.RT())
	def := runtimeToMap(s.defaults)
	for _, k := range ks {
		values[k] = def[k]
	}
	if p := s.check(values); len(p) > 0 {
		s.mu.Unlock()
		return verr("%s", strings.Join(p, "; "))
	}
	if err := s.store.deleteSettings(ks); err != nil {
		s.mu.Unlock()
		return err
	}
	s.rt.Store(runtimeFromMap(values))
	s.mu.Unlock()
	for _, k := range ks {
		logf("[settings] %s reset %s to default %v", by, k, def[k])
	}
	return nil
}

// ---- relay users ----
func (s *RuntimeSettings) UserCount(enabledOnly bool) int {
	s.umu.RLock()
	defer s.umu.RUnlock()
	n := len(s.envUsers)
	for _, u := range s.dbUsers {
		if u["enabled"].(bool) || !enabledOnly {
			n++
		}
	}
	return n
}

func (s *RuntimeSettings) Users() []Row {
	s.umu.RLock()
	defer s.umu.RUnlock()
	out := []Row{}
	names := make([]string, 0, len(s.envUsers))
	for u := range s.envUsers {
		names = append(names, u)
	}
	sort.Strings(names)
	for _, u := range names {
		out = append(out, Row{"username": u, "source": "env", "enabled": true, "note": "from MAILRELAY_RELAY_USERS"})
	}
	dn := make([]string, 0, len(s.dbUsers))
	for u := range s.dbUsers {
		dn = append(dn, u)
	}
	sort.Strings(dn)
	for _, u := range dn {
		r := Row{}
		for k, v := range s.dbUsers[u] {
			if k != "password_hash" {
				r[k] = v
			}
		}
		r["source"] = "db"
		out = append(out, r)
	}
	return out
}

func (s *RuntimeSettings) SaveUser(username string, password *string, enabled any, note, by string) error {
	username = strings.TrimSpace(username)
	if !usernameRE.MatchString(username) {
		return verr("username: 1-64 characters, letters, digits and . _ @ + -")
	}
	if _, ok := s.envUsers[username]; ok {
		return verr("'%s' is defined in MAILRELAY_RELAY_USERS and can only be changed there", username)
	}
	en, err := toBool(enabled)
	if err != nil {
		return verr("%v", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.umu.RLock()
	existing := s.dbUsers[username]
	s.umu.RUnlock()
	pwHash := ""
	switch {
	case password != nil && *password != "":
		if len([]rune(*password)) < 8 {
			return verr("password must be at least 8 characters")
		}
		if pwHash, err = hashPassword(*password); err != nil {
			return err
		}
	case existing != nil:
	default:
		return verr("password is required for a new user")
	}
	if existing != nil && existing["enabled"].(bool) && !en {
		if err := s.guardLastUser(username); err != nil {
			return err
		}
	}
	if r := []rune(note); len(r) > 200 {
		note = string(r[:200])
	}
	if err := s.store.upsertRelayUser(username, pwHash, en, note); err != nil {
		return err
	}
	if err := s.reloadUsers(); err != nil {
		return err
	}
	verb, dis := "created", ""
	if existing != nil {
		verb = "updated"
	}
	if !en {
		dis = " (disabled)"
	}
	logf("[settings] %s %s relay user '%s'%s", by, verb, username, dis)
	return nil
}

func (s *RuntimeSettings) DeleteUser(username, by string) error {
	if _, ok := s.envUsers[username]; ok {
		return verr("'%s' is defined in MAILRELAY_RELAY_USERS and can only be removed there", username)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.umu.RLock()
	u, ok := s.dbUsers[username]
	s.umu.RUnlock()
	if !ok {
		return errNotFound
	}
	if u["enabled"].(bool) {
		if err := s.guardLastUser(username); err != nil {
			return err
		}
	}
	if err := s.store.deleteRelayUser(username); err != nil {
		return err
	}
	if err := s.reloadUsers(); err != nil {
		return err
	}
	logf("[settings] %s deleted relay user '%s'", by, username)
	return nil
}

func (s *RuntimeSettings) guardLastUser(username string) error {
	if s.RT().RequireAuth && s.UserCount(true) <= 1 {
		return verr("'%s' is the last enabled user while login is required - turn that off first", username)
	}
	return nil
}

func (s *RuntimeSettings) Verify(login, password string) bool {
	if expected, ok := s.envUsers[login]; ok {
		return subtle.ConstantTimeCompare([]byte(expected), []byte(password)) == 1
	}
	s.umu.RLock()
	u := s.dbUsers[login]
	s.umu.RUnlock()
	if u != nil && u["enabled"].(bool) {
		if h, _ := u["password_hash"].(string); checkPassword(password, h) {
			ts := s.store.touchRelayUser(login)
			s.umu.Lock()
			if cur := s.dbUsers[login]; cur != nil {
				cur["last_login_utc"] = ts
			}
			s.umu.Unlock()
			return true
		}
	}
	return false
}
