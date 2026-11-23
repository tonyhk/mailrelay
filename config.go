package main

import (
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

var privateNets = []string{"127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "::1/128", "fc00::/7"}

// readSecret returns $VAR, or the contents of the file named by $VAR_FILE (Docker secrets).
func readSecret(name string) (string, bool, error) {
	if v, ok := os.LookupEnv(name); ok {
		return v, true, nil
	}
	if p := os.Getenv(name + "_FILE"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return "", false, err
		}
		return strings.TrimSpace(string(b)), true, nil
	}
	return "", false, nil
}

type Upstream struct {
	Name        string `toml:"name"`
	Host        string `toml:"host"`
	Port        int    `toml:"port"`
	Security    string `toml:"security"` // starttls | ssl | none
	Username    string `toml:"username"`
	PasswordEnv string `toml:"password_env"`
	Timeout     int    `toml:"timeout"`
	VerifyTLS   bool   `toml:"verify_tls"`
}

func (u Upstream) Password() (string, error) {
	if u.PasswordEnv == "" {
		return "", nil
	}
	v, ok, err := readSecret(u.PasswordEnv)
	if err != nil {
		return "", err
	}
	if !ok {
		return "", fmt.Errorf("Upstream '%s': %s (or %s_FILE) is not set", u.Name, u.PasswordEnv, u.PasswordEnv)
	}
	return v, nil
}

// Config holds the static settings. The values in Runtime (settings.go) start from the fields marked "runtime".
type Config struct {
	FromAddress string `toml:"from_address"` // runtime
	FromName    string `toml:"from_name"`    // runtime
	Hostname    string `toml:"hostname"`
	RewriteFrom bool   `toml:"rewrite_from"` // runtime

	SMTPListenHost       string            `toml:"smtp_listen_host"`
	SMTPListenPort       int               `toml:"smtp_listen_port"`
	AllowedNetworks      []string          `toml:"allowed_networks"` // runtime
	RelayUsers           map[string]string `toml:"relay_users"`
	RequireAuth          bool              `toml:"require_auth"` // runtime
	TLSCert              string            `toml:"tls_cert"`
	TLSKey               string            `toml:"tls_key"`
	TLSSelfSigned        bool              `toml:"tls_self_signed"`
	TLSSelfSignedDays    int               `toml:"tls_self_signed_days"`
	TLSSANs              []string          `toml:"tls_sans"`
	TLSDir               string            `toml:"tls_dir"`
	TLSMinVersion        string            `toml:"tls_min_version"`
	AuthRequireTLS       bool              `toml:"auth_require_tls"`
	MaxMessageMB         int               `toml:"max_message_mb"`
	MaxRecipients        int               `toml:"max_recipients"`         // runtime
	AllowedSenderDomains []string          `toml:"allowed_sender_domains"` // runtime

	QueueDir         string  `toml:"queue_dir"`
	RetryMinutes     []int   `toml:"retry_minutes"`       // runtime
	QueueMaxAgeHours float64 `toml:"queue_max_age_hours"` // runtime

	LogDB     string `toml:"log_db"`
	LogFile   string `toml:"log_file"`
	LogStdout bool   `toml:"log_stdout"`

	WebListenHost    string `toml:"web_listen_host"`
	WebListenPort    int    `toml:"web_listen_port"`
	APITokenEnv      string `toml:"api_token_env"`
	AdminUser        string `toml:"admin_user"`
	AdminPasswordEnv string `toml:"admin_password_env"`

	Upstreams []Upstream `toml:"-"`

	TLSInfo *TLSInfo `toml:"-"` // set at startup by prepareTLS
}

func defaultConfig() *Config {
	return &Config{
		Hostname: "mailrelay", SMTPListenHost: "0.0.0.0", SMTPListenPort: 2525,
		AllowedNetworks: append([]string(nil), privateNets...), TLSSelfSignedDays: 3650, TLSMinVersion: "1.2",
		AuthRequireTLS: true, MaxMessageMB: 25, MaxRecipients: 100,
		QueueDir: "data/queue", RetryMinutes: []int{1, 5, 15, 30, 60}, QueueMaxAgeHours: 24,
		LogDB: "data/mailrelay.db", LogFile: "data/smtp_log.jsonl", LogStdout: true,
		WebListenHost: "0.0.0.0", WebListenPort: 8080,
		APITokenEnv: "MAILRELAY_API_TOKEN", AdminUser: "admin", AdminPasswordEnv: "MAILRELAY_ADMIN_PASSWORD",
	}
}

func (c *Config) validate(strict bool) error {
	if strict && len(c.Upstreams) == 0 {
		return fmt.Errorf("config: at least one upstream is required (SMTP_1_HOST ...)")
	}
	for _, u := range c.Upstreams {
		if u.Security != "starttls" && u.Security != "ssl" && u.Security != "none" {
			return fmt.Errorf("upstream '%s': security must be starttls, ssl or none", u.Name)
		}
	}
	if c.RewriteFrom && c.FromAddress == "" {
		return fmt.Errorf("config: MAILRELAY_REWRITE_FROM needs MAILRELAY_FROM_ADDRESS")
	}
	if (c.TLSCert != "") != (c.TLSKey != "") {
		return fmt.Errorf("config: set both MAILRELAY_TLS_CERT and MAILRELAY_TLS_KEY")
	}
	switch c.TLSMinVersion {
	case "1.0", "1.1", "1.2", "1.3":
	default:
		return fmt.Errorf("config: MAILRELAY_TLS_MIN_VERSION must be 1.0, 1.1, 1.2 or 1.3")
	}
	if c.TLSSelfSignedDays < 1 || c.TLSSelfSignedDays > 36500 {
		return fmt.Errorf("config: MAILRELAY_TLS_SELF_SIGNED_DAYS must be 1..36500")
	}
	for _, n := range c.TLSSANs {
		r := strings.NewReplacer(".", "", "-", "", ":", "").Replace(n)
		ok := r != ""
		for _, ch := range r {
			if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z') {
				ok = false
			}
		}
		if !ok {
			return fmt.Errorf("config: MAILRELAY_TLS_SANS entry '%s' is not a host name or IP", n)
		}
	}
	for _, n := range c.AllowedNetworks {
		if _, err := parseNet(n); err != nil {
			return fmt.Errorf("'%s' does not appear to be an IPv4 or IPv6 network", n)
		}
	}
	if len(c.RetryMinutes) == 0 {
		c.RetryMinutes = []int{5}
	}
	for i, d := range c.AllowedSenderDomains {
		c.AllowedSenderDomains[i] = strings.TrimLeft(strings.ToLower(d), "@")
	}
	return nil
}

// parseNet parses a CIDR (host bits allowed, like Python's strict=False) or a bare address.
func parseNet(s string) (netip.Prefix, error) {
	if !strings.Contains(s, "/") {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return netip.PrefixFrom(a, a.BitLen()), nil
	}
	p, err := netip.ParsePrefix(s)
	if err != nil {
		return p, err
	}
	return p.Masked(), nil
}

func loadFile(path string, strict bool) (*Config, error) {
	cfg := defaultConfig()
	var raw struct {
		App      toml.Primitive `toml:"app"`
		Upstream []Upstream     `toml:"upstream"`
	}
	md, err := toml.DecodeFile(path, &raw)
	if err != nil {
		return nil, err
	}
	if md.IsDefined("app") {
		if err := md.PrimitiveDecode(raw.App, cfg); err != nil {
			return nil, err
		}
	}
	for _, u := range raw.Upstream {
		if u.Port == 0 {
			u.Port = 587
		}
		if u.Security == "" {
			u.Security = "starttls"
		}
		if u.Timeout == 0 {
			u.Timeout = 30
		}
		cfg.Upstreams = append(cfg.Upstreams, u)
	}
	// verify_tls defaults to true unless the file says otherwise
	for i := range cfg.Upstreams {
		cfg.Upstreams[i].VerifyTLS = true
	}
	var again struct {
		Upstream []struct {
			VerifyTLS *bool `toml:"verify_tls"`
		} `toml:"upstream"`
	}
	if _, err := toml.DecodeFile(path, &again); err == nil {
		for i, u := range again.Upstream {
			if u.VerifyTLS != nil && i < len(cfg.Upstreams) {
				cfg.Upstreams[i].VerifyTLS = *u.VerifyTLS
			}
		}
	}
	return cfg, cfg.validate(strict)
}

func splitList(v string) []string {
	var out []string
	for _, x := range strings.Split(v, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func envUsers() (map[string]string, error) {
	var entries []string
	if v, ok := os.LookupEnv("MAILRELAY_RELAY_USERS"); ok {
		entries = splitList(v)
	} else if p := os.Getenv("MAILRELAY_RELAY_USERS_FILE"); p != "" {
		b, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		for _, l := range strings.Split(string(b), "\n") {
			l = strings.TrimSpace(l)
			if l != "" && !strings.HasPrefix(l, "#") {
				entries = append(entries, l)
			}
		}
	} else {
		return nil, nil
	}
	users := map[string]string{}
	for _, e := range entries {
		user, pw, ok := strings.Cut(e, ":")
		if !ok {
			return nil, fmt.Errorf("MAILRELAY_RELAY_USERS: entry '%s' must be user:password", user)
		}
		users[user] = pw
	}
	return users, nil
}

func loadEnv(strict bool) (*Config, error) {
	cfg := defaultConfig()
	var errs []error
	get := func(k, d string) string {
		if v, ok := os.LookupEnv(k); ok {
			return v
		}
		return d
	}
	b := func(k string, d bool) bool {
		v, ok := os.LookupEnv(k)
		if !ok {
			return d
		}
		switch strings.ToLower(v) {
		case "1", "true", "yes", "on":
			return true
		}
		return false
	}
	num := func(k string, d int) int {
		v, ok := os.LookupEnv(k)
		if !ok {
			return d
		}
		n, err := strconv.Atoi(strings.TrimSpace(v))
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: invalid integer %q", k, v))
		}
		return n
	}
	for n := 1; os.Getenv(fmt.Sprintf("SMTP_%d_HOST", n)) != ""; n++ {
		p := fmt.Sprintf("SMTP_%d_", n)
		sec := strings.ToLower(get(p+"SECURITY", "starttls"))
		defPort := 587
		if sec == "ssl" {
			defPort = 465
		}
		u := Upstream{Name: get(p+"NAME", fmt.Sprintf("smtp%d", n)), Host: os.Getenv(p + "HOST"),
			Port: num(p+"PORT", defPort), Security: sec, Username: get(p+"USERNAME", ""),
			Timeout: num(p+"TIMEOUT", 30), VerifyTLS: b(p+"VERIFY_TLS", true)}
		if os.Getenv(p+"PASSWORD") != "" || os.Getenv(p+"PASSWORD_FILE") != "" {
			u.PasswordEnv = p + "PASSWORD"
		}
		cfg.Upstreams = append(cfg.Upstreams, u)
	}
	users, err := envUsers()
	if err != nil {
		return nil, err
	}
	cfg.RelayUsers = users
	cfg.FromAddress = get("MAILRELAY_FROM_ADDRESS", "")
	cfg.FromName = get("MAILRELAY_FROM_NAME", "")
	cfg.Hostname = get("MAILRELAY_HOSTNAME", "mailrelay")
	cfg.RewriteFrom = b("MAILRELAY_REWRITE_FROM", false)
	cfg.SMTPListenPort = num("MAILRELAY_SMTP_LISTEN_PORT", 2525)
	if l := splitList(os.Getenv("MAILRELAY_ALLOWED_NETWORKS")); len(l) > 0 {
		cfg.AllowedNetworks = l
	}
	cfg.RequireAuth = b("MAILRELAY_REQUIRE_AUTH", false)
	cfg.TLSCert = get("MAILRELAY_TLS_CERT", "")
	cfg.TLSKey = get("MAILRELAY_TLS_KEY", "")
	cfg.TLSSelfSigned = b("MAILRELAY_TLS_SELF_SIGNED", false)
	cfg.TLSSelfSignedDays = num("MAILRELAY_TLS_SELF_SIGNED_DAYS", 3650)
	cfg.TLSSANs = splitList(os.Getenv("MAILRELAY_TLS_SANS"))
	cfg.TLSDir = get("MAILRELAY_TLS_DIR", "")
	cfg.TLSMinVersion = get("MAILRELAY_TLS_MIN_VERSION", "1.2")
	cfg.AuthRequireTLS = b("MAILRELAY_AUTH_REQUIRE_TLS", true)
	cfg.MaxMessageMB = num("MAILRELAY_MAX_MESSAGE_MB", 25)
	cfg.MaxRecipients = num("MAILRELAY_MAX_RECIPIENTS", 100)
	cfg.AllowedSenderDomains = splitList(os.Getenv("MAILRELAY_ALLOWED_SENDER_DOMAINS"))
	cfg.QueueDir = get("MAILRELAY_QUEUE_DIR", "data/queue")
	cfg.RetryMinutes = nil
	for _, x := range splitList(get("MAILRELAY_RETRY_MINUTES", "1,5,15,30,60")) {
		n, err := strconv.Atoi(x)
		if err != nil {
			errs = append(errs, fmt.Errorf("MAILRELAY_RETRY_MINUTES: invalid integer %q", x))
		}
		cfg.RetryMinutes = append(cfg.RetryMinutes, n)
	}
	if v, err := strconv.ParseFloat(get("MAILRELAY_QUEUE_MAX_AGE_HOURS", "24"), 64); err == nil {
		cfg.QueueMaxAgeHours = v
	} else {
		errs = append(errs, fmt.Errorf("MAILRELAY_QUEUE_MAX_AGE_HOURS: invalid number"))
	}
	cfg.LogDB = get("MAILRELAY_LOG_DB", "data/mailrelay.db")
	cfg.LogFile = get("MAILRELAY_LOG_FILE", "data/smtp_log.jsonl")
	cfg.LogStdout = b("MAILRELAY_LOG_STDOUT", true)
	cfg.WebListenPort = num("MAILRELAY_WEB_LISTEN_PORT", 8080)
	cfg.AdminUser = get("MAILRELAY_ADMIN_USER", "admin")
	if len(errs) > 0 {
		return nil, errs[0]
	}
	return cfg, cfg.validate(strict)
}

// loadConfig uses the TOML file if it exists, otherwise environment variables.
// strict=false (read-only CLI commands) does not require upstream servers.
func loadConfig(path string, strict bool) (*Config, error) {
	if path != "" {
		if st, err := os.Stat(path); err == nil && st.Mode().IsRegular() {
			return loadFile(path, strict)
		}
	}
	return loadEnv(strict)
}
