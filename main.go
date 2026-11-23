// mailrelay: SMTP relay to an authenticated upstream server with per-message logging and a web overview.
//
//	mailrelay [-c config.toml] serve | messages | attempts | queue | show <relay_id> | healthcheck

package main

import (
	"context"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"
)

const version = "2.0.0"

//go:embed dashboard.html
var dashboardHTML []byte

func logf(format string, a ...any) {
	fmt.Fprintf(os.Stdout, format+"\n", a...)
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func serve(cfg *Config) error {
	info, err := prepareTLS(cfg) // may generate a self-signed cert into the data volume
	if err != nil {
		return err
	}
	cfg.TLSInfo = info
	store, err := openStore(cfg.LogDB, cfg.LogFile, cfg.LogStdout)
	if err != nil {
		return err
	}
	defer store.Close()
	settings, err := newRuntimeSettings(cfg, store) // applies values saved in the web UI over env defaults
	if err != nil {
		return err
	}
	engine, err := newEngine(cfg, store, newSender(cfg, store), settings)
	if err != nil {
		return err
	}
	httpd, err := newWeb(cfg, store, engine, settings, dashboardHTML)
	if err != nil {
		return err
	}
	smtpd, err := buildSMTPServer(cfg, engine, settings)
	if err != nil {
		return err
	}
	stop := make(chan struct{})
	go engine.runQueue(stop)

	errc := make(chan error, 2)
	webLn, err := net.Listen("tcp", httpd.Addr)
	if err != nil {
		return err
	}
	smtpLn, err := net.Listen("tcp", smtpd.Addr)
	if err != nil {
		return err
	}
	go func() { errc <- httpd.Serve(webLn) }()
	go func() { errc <- smtpd.Serve(smtpLn) }()

	rt := settings.RT()
	logf("mailrelay %s: SMTP relay on :%d, overview on :%d", version, cfg.SMTPListenPort, cfg.WebListenPort)
	var ups []string
	for _, u := range cfg.Upstreams {
		ups = append(ups, fmt.Sprintf("%s=%s:%d/%s", u.Name, u.Host, u.Port, u.Security))
	}
	logf("  upstreams: %s", strings.Join(ups, ", "))
	if ti := cfg.TLSInfo; ti != nil {
		names := strings.Join(ti.Names, ", ")
		if names == "" {
			names = ti.Subject
		}
		extra := ""
		if !cfg.AuthRequireTLS {
			extra = ", AUTH also without STARTTLS"
		}
		logf("  STARTTLS: %s cert for %s, valid until %s, min TLS %s%s", ti.Source, names, ti.NotAfter[:10], cfg.TLSMinVersion, extra)
		logf("  STARTTLS SHA-256 fingerprint: %s", ti.SHA256)
	} else {
		logf("  STARTTLS: off (set MAILRELAY_TLS_SELF_SIGNED=true or MAILRELAY_TLS_CERT/_KEY)")
	}
	line := "  clients allowed from: " + strings.Join(rt.AllowedNetworks, ", ")
	if n := settings.UserCount(true); n > 0 {
		line += fmt.Sprintf(" + SMTP AUTH (%d users)", n)
	}
	if rt.RequireAuth {
		line += " (auth required)"
	}
	logf("%s", line)
	if o := settings.Overridden(); len(o) > 0 {
		logf("  set in web UI (override env): %s", strings.Join(o, ", "))
	}
	for _, w := range settings.Warnings {
		logf("  WARNING: %s", w)
	}
	if n := len(engine.queued()); n > 0 {
		logf("  %d message(s) waiting in queue", n)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	var runErr error
	select {
	case <-sig:
	case runErr = <-errc:
	}
	close(stop)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	smtpd.Shutdown(ctx)
	httpd.Shutdown(ctx)
	if runErr == http.ErrServerClosed {
		runErr = nil
	}
	return runErr
}

type tcol struct {
	head, key string
	width     int
}

func cell(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case int64:
		if x == 0 {
			return ""
		}
		return fmt.Sprint(x)
	case float64:
		if x == 0 {
			return ""
		}
		return fmt.Sprint(x)
	}
	return fmt.Sprint(v)
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		r = r[:n]
	}
	return string(r)
}

func printTable(rows []Row, cols []tcol) {
	widths := make([]int, len(cols))
	for i, c := range cols {
		widths[i] = len([]rune(c.head))
		for _, r := range rows {
			if l := len([]rune(trunc(cell(r[c.key]), c.width))); l > widths[i] {
				widths[i] = l
			}
		}
	}
	pad := func(s string, w int) string { return s + strings.Repeat(" ", max(0, w-len([]rune(s)))) }
	var h []string
	for i, c := range cols {
		h = append(h, pad(c.head, widths[i]))
	}
	fmt.Println(strings.Join(h, "  "))
	for _, r := range rows {
		var l []string
		for i, c := range cols {
			l = append(l, pad(trunc(cell(r[c.key]), c.width), widths[i]))
		}
		fmt.Println(strings.Join(l, "  "))
	}
}

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

// healthcheck replaces the Python one-liner: web /health must answer and the SMTP port must greet with 220.
func healthcheck(cfg *Config) int {
	c := &http.Client{Timeout: 3 * time.Second}
	resp, err := c.Get(fmt.Sprintf("http://127.0.0.1:%d/health", cfg.WebListenPort))
	if err != nil || resp.StatusCode != 200 {
		fmt.Fprintln(os.Stderr, "web health check failed:", err)
		return 1
	}
	resp.Body.Close()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", cfg.SMTPListenPort), 3*time.Second)
	if err != nil {
		fmt.Fprintln(os.Stderr, "smtp check failed:", err)
		return 1
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	buf := make([]byte, 64)
	n, _ := conn.Read(buf)
	if !strings.HasPrefix(string(buf[:n]), "220") {
		fmt.Fprintln(os.Stderr, "smtp check failed: no 220 greeting")
		return 1
	}
	return 0
}

func main() {
	defConfig := os.Getenv("MAILRELAY_CONFIG")
	if defConfig == "" {
		defConfig = "config.toml"
	}
	global := flag.NewFlagSet("mailrelay", flag.ExitOnError)
	var cfgPath string
	global.StringVar(&cfgPath, "c", defConfig, "TOML file; if missing, configuration is read from environment variables")
	global.StringVar(&cfgPath, "config", defConfig, "same as -c")
	global.Usage = func() {
		fmt.Fprintln(os.Stderr, "usage: mailrelay [-c config.toml] {serve|messages|attempts|show <relay_id>|queue|healthcheck} [flags]")
		global.PrintDefaults()
	}
	global.Parse(os.Args[1:])
	args := global.Args()
	if len(args) == 0 {
		global.Usage()
		os.Exit(2)
	}
	cmd, rest := args[0], args[1:]

	cfg, err := loadConfig(cfgPath, cmd == "serve")
	if err != nil {
		if cmd == "healthcheck" {
			cfg = defaultConfig()
		} else {
			die("%v", err)
		}
	}

	switch cmd {
	case "serve":
		if err := serve(cfg); err != nil {
			die("%v", err)
		}
	case "healthcheck":
		os.Exit(healthcheck(cfg))
	case "messages":
		fs := flag.NewFlagSet("messages", flag.ExitOnError)
		limit := fs.Int("limit", 30, "")
		status := fs.String("status", "", "sent|queued|bounced|expired|failed")
		var search string
		fs.StringVar(&search, "q", "", "")
		fs.StringVar(&search, "search", "", "")
		asJSON := fs.Bool("json", false, "")
		fs.Parse(rest)
		store := mustStore(cfg)
		rows, err := store.messages(*limit, *status, search, "")
		if err != nil {
			die("%v", err)
		}
		if *asJSON {
			printJSON(rows)
			return
		}
		printTable(rows, []tcol{{"RECEIVED (UTC)", "received_utc", 23}, {"RELAY ID", "relay_id", 18}, {"CLIENT", "client_ip", 15},
			{"FROM", "mail_from", 28}, {"TO", "rcpt_to", 28}, {"STATUS", "status", 7}, {"VIA", "upstream_name", 12},
			{"UPSTREAM IP", "upstream_ip", 15}, {"TRIES", "attempts", 3}, {"SUBJECT", "subject", 40}})
	case "attempts":
		fs := flag.NewFlagSet("attempts", flag.ExitOnError)
		limit := fs.Int("limit", 30, "")
		upstream := fs.String("upstream", "", "")
		status := fs.String("status", "", "sent|failed")
		since := fs.String("since", "", "")
		asJSON := fs.Bool("json", false, "")
		fs.Parse(rest)
		store := mustStore(cfg)
		rows, err := store.attempts(*limit, *upstream, *status, *since, "")
		if err != nil {
			die("%v", err)
		}
		if *asJSON {
			printJSON(rows)
			return
		}
		for _, r := range rows {
			r["server"] = fmt.Sprintf("%v:%v", r["upstream_host"], r["upstream_port"])
			if r["status"] == "sent" {
				r["detail"] = r["smtp_response"]
			} else {
				r["detail"] = r["error"]
			}
		}
		printTable(rows, []tcol{{"TIME (UTC)", "timestamp_utc", 29}, {"RELAY ID", "relay_id", 18}, {"SERVER", "upstream_name", 12},
			{"HOST:PORT", "server", 32}, {"IP", "upstream_ip", 15}, {"STATUS", "status", 6}, {"DETAIL", "detail", 70}})
	case "show":
		if len(rest) != 1 {
			die("usage: mailrelay show <relay_id>")
		}
		m, err := mustStore(cfg).getMessage(rest[0])
		if err != nil {
			die("%v", err)
		}
		if m == nil {
			fmt.Fprintln(os.Stderr, "not found")
			os.Exit(1)
		}
		printJSON(m)
	case "queue":
		rows, err := mustStore(cfg).messages(500, "queued", "", "")
		if err != nil {
			die("%v", err)
		}
		printTable(rows, []tcol{{"RELAY ID", "relay_id", 18}, {"RECEIVED (UTC)", "received_utc", 23}, {"TO", "rcpt_to", 30},
			{"TRIES", "attempts", 3}, {"NEXT RETRY (UTC)", "next_retry_utc", 23}, {"LAST ERROR", "last_error", 70}})
	default:
		global.Usage()
		os.Exit(2)
	}
}

func mustStore(cfg *Config) *Store {
	s, err := openStore(cfg.LogDB, "", false)
	if err != nil {
		die("%v", err)
	}
	return s
}
