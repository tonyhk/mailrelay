package main

// STARTTLS certificate for inbound clients.
//
// MAILRELAY_TLS_CERT / MAILRELAY_TLS_KEY   use your own certificate (e.g. from an internal CA)
// MAILRELAY_TLS_SELF_SIGNED=true           otherwise generate a self-signed one in <data>/tls/ on first start
//
// The generated certificate is kept in the data volume and reused. It is regenerated when it is missing or
// unreadable, expires within 30 days, or no longer covers MAILRELAY_HOSTNAME / MAILRELAY_TLS_SANS.
// RSA 2048 is used on purpose: many printers, copiers and NAS boxes cannot do ECDSA.

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const renewBefore = 30 * 24 * time.Hour

type TLSInfo struct {
	Subject    string   `json:"subject"`
	Names      []string `json:"names"`
	NotAfter   string   `json:"not_after"`
	SHA256     string   `json:"sha256"`
	SelfSigned bool     `json:"self_signed"`
	Source     string   `json:"source"`
}

func wantedNames(cfg *Config) []string {
	var names []string
	for _, n := range append([]string{cfg.Hostname}, cfg.TLSSANs...) {
		n = strings.ToLower(strings.TrimSpace(n))
		if n != "" && !contains(names, n) {
			names = append(names, n)
		}
	}
	return names
}

func certNames(c *x509.Certificate) []string {
	set := map[string]bool{}
	for _, n := range c.DNSNames {
		set[strings.ToLower(n)] = true
	}
	for _, ip := range c.IPAddresses {
		set[ip.String()] = true
	}
	out := make([]string, 0, len(set))
	for n := range set {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

func loadCert(path string) (*x509.Certificate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("no PEM certificate in %s", path)
	}
	return x509.ParseCertificate(blk.Bytes)
}

func certInfo(path string) (*TLSInfo, error) {
	c, err := loadCert(path)
	if err != nil {
		return nil, err
	}
	fp := sha256.Sum256(c.Raw)
	h := strings.ToUpper(hex.EncodeToString(fp[:]))
	var pairs []string
	for i := 0; i < len(h); i += 2 {
		pairs = append(pairs, h[i:i+2])
	}
	return &TLSInfo{
		Subject: c.Subject.String(), Names: certNames(c),
		NotAfter: c.NotAfter.UTC().Format("2006-01-02T15:04:05") + "+00:00",
		SHA256:   strings.Join(pairs, ":"), SelfSigned: string(c.RawIssuer) == string(c.RawSubject),
	}, nil
}

func needsNew(certPath, keyPath string, names []string) string {
	if _, err := os.Stat(certPath); err != nil {
		return "no certificate yet"
	}
	if _, err := os.Stat(keyPath); err != nil {
		return "no certificate yet"
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return fmt.Sprintf("existing certificate unreadable (%v)", err)
	}
	c, err := loadCert(certPath)
	if err != nil {
		return fmt.Sprintf("existing certificate unreadable (%v)", err)
	}
	if time.Until(c.NotAfter) < renewBefore {
		return "expires " + c.NotAfter.UTC().Format("2006-01-02")
	}
	have := certNames(c)
	var missing []string
	for _, n := range names {
		if !contains(have, n) {
			missing = append(missing, n)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return "does not cover " + strings.Join(missing, ", ")
	}
	return ""
}

func generateCert(certPath, keyPath string, names []string, days int) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	cn := names[0]
	if len(cn) > 64 {
		cn = cn[:64]
	}
	tpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn, Organization: []string{"mailrelay self-signed"}},
		NotBefore:             time.Now().Add(-5 * time.Minute),
		NotAfter:              time.Now().Add(time.Duration(days) * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	for _, n := range names {
		if ip := net.ParseIP(n); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, n)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return err
	}
	tmpKey, tmpCert := keyPath+".tmp", certPath+".tmp"
	if err := os.WriteFile(tmpKey, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(tmpCert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmpKey, keyPath); err != nil {
		return err
	}
	return os.Rename(tmpCert, certPath)
}

// prepareTLS makes sure cfg.TLSCert / cfg.TLSKey point to usable files. Returns nil info if TLS is off.
func prepareTLS(cfg *Config) (*TLSInfo, error) {
	if cfg.TLSCert != "" { // own certificate always wins
		for _, f := range [][2]string{{"MAILRELAY_TLS_CERT", cfg.TLSCert}, {"MAILRELAY_TLS_KEY", cfg.TLSKey}} {
			if st, err := os.Stat(f[1]); err != nil || !st.Mode().IsRegular() {
				return nil, fmt.Errorf("%s=%s does not exist (mount it, or unset both and use MAILRELAY_TLS_SELF_SIGNED=true)", f[0], f[1])
			}
		}
		info, err := certInfo(cfg.TLSCert)
		if err != nil {
			return nil, err
		}
		info.Source = "file"
		return info, nil
	}
	if !cfg.TLSSelfSigned {
		return nil, nil
	}
	dir := cfg.TLSDir
	if dir == "" {
		dir = filepath.Join(filepath.Dir(cfg.LogDB), "tls")
	}
	certPath, keyPath := filepath.Join(dir, "selfsigned-cert.pem"), filepath.Join(dir, "selfsigned-key.pem")
	names := wantedNames(cfg)
	reason := needsNew(certPath, keyPath, names)
	if reason != "" {
		logf("  generating self-signed certificate for %s (%s)", strings.Join(names, ", "), reason)
		if err := generateCert(certPath, keyPath, names, cfg.TLSSelfSignedDays); err != nil {
			return nil, err
		}
	}
	cfg.TLSCert, cfg.TLSKey = certPath, keyPath
	info, err := certInfo(certPath)
	if err != nil {
		return nil, err
	}
	info.Source = "self-signed (reused)"
	if reason != "" {
		info.Source = "generated"
	}
	return info, nil
}
