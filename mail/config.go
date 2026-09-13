package mail

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// defaultMaxMessageBytes caps an accepted message at 25 MB, the de facto limit
// most public MTAs advertise.
const defaultMaxMessageBytes = 25 * 1024 * 1024

// Queue tuning. These are deliberately not configurable: they only matter when
// a remote host is down, and the retry ladder below spans roughly two days.
const (
	queueRetryInterval = 5 * time.Minute
	queueMaxAttempts   = 12
)

// Protocol timeouts. Mail sessions are long-lived by nature: an IMAP client
// holds a connection open between polls, and a slow sender may take minutes to
// finish DATA.
const (
	smtpReadTimeout  = 5 * time.Minute
	smtpWriteTimeout = 5 * time.Minute
	imapAutoLogout   = 30 * time.Minute
)

var domainPattern = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)

// Config is the mail server configuration parsed from the environment.
//
// A listener with an empty address is disabled. The TLS listeners are also
// skipped when no certificate is configured, since implicit TLS cannot work
// without one.
type Config struct {
	Domain       string
	ExtraDomains []string
	Hostname     string

	SMTPAddr          string
	SubmissionAddr    string
	SubmissionTLSAddr string
	POP3Addr          string
	POP3TLSAddr       string
	IMAPAddr          string
	IMAPTLSAddr       string

	TLSCertFile string
	TLSKeyFile  string

	MaxMessageBytes int64

	// Relay enables delivery to domains this server does not own. With it off,
	// submission only accepts local recipients.
	Relay bool
	// SmarthostAddr relays every outgoing message through another MTA instead of
	// looking up the recipient's MX records. Set this when outbound port 25 is
	// blocked, which is the default on most cloud providers.
	SmarthostAddr     string
	SmarthostUser     string
	SmarthostPassword string

	DKIMDomain   string
	DKIMSelector string
	DKIMKeyFile  string

	// QueueDir holds messages awaiting relay.
	QueueDir string
}

// Enabled reports whether the mail server should run at all. Mail is opt-in:
// with no MAIL_DOMAIN the service behaves exactly as it did before.
func (c *Config) Enabled() bool {
	return c != nil && c.Domain != ""
}

// ConfigFromEnv reads the MAIL_* environment. It returns a disabled config when
// MAIL_DOMAIN is unset, and an error only when a value is present but unusable.
func ConfigFromEnv() (*Config, error) {
	cfg := &Config{
		Domain:            strings.ToLower(strings.TrimSpace(os.Getenv("MAIL_DOMAIN"))),
		Hostname:          strings.ToLower(strings.TrimSpace(os.Getenv("MAIL_HOSTNAME"))),
		SMTPAddr:          addrFromEnv("MAIL_SMTP_ADDR", ":25"),
		SubmissionAddr:    addrFromEnv("MAIL_SUBMISSION_ADDR", ":587"),
		SubmissionTLSAddr: addrFromEnv("MAIL_SUBMISSION_TLS_ADDR", ":465"),
		POP3Addr:          addrFromEnv("MAIL_POP3_ADDR", ":110"),
		POP3TLSAddr:       addrFromEnv("MAIL_POP3_TLS_ADDR", ":995"),
		IMAPAddr:          addrFromEnv("MAIL_IMAP_ADDR", ":143"),
		IMAPTLSAddr:       addrFromEnv("MAIL_IMAP_TLS_ADDR", ":993"),
		TLSCertFile:       strings.TrimSpace(os.Getenv("MAIL_TLS_CERT_FILE")),
		TLSKeyFile:        strings.TrimSpace(os.Getenv("MAIL_TLS_KEY_FILE")),
		MaxMessageBytes:   defaultMaxMessageBytes,
		Relay:             true,
		SmarthostAddr:     strings.TrimSpace(os.Getenv("MAIL_SMARTHOST_ADDR")),
		SmarthostUser:     os.Getenv("MAIL_SMARTHOST_USER"),
		SmarthostPassword: os.Getenv("MAIL_SMARTHOST_PASSWORD"),
		DKIMDomain:        strings.ToLower(strings.TrimSpace(os.Getenv("MAIL_DKIM_DOMAIN"))),
		DKIMSelector:      strings.TrimSpace(os.Getenv("MAIL_DKIM_SELECTOR")),
		DKIMKeyFile:       strings.TrimSpace(os.Getenv("MAIL_DKIM_KEY_FILE")),
		QueueDir:          "",
	}

	if !cfg.Enabled() {
		return cfg, nil
	}
	if !domainPattern.MatchString(cfg.Domain) {
		return nil, fmt.Errorf("MAIL_DOMAIN must be a domain name, got %q", cfg.Domain)
	}
	if cfg.Hostname == "" {
		cfg.Hostname = cfg.Domain
	}

	for _, extra := range strings.Split(os.Getenv("MAIL_EXTRA_DOMAINS"), ",") {
		extra = strings.ToLower(strings.TrimSpace(extra))
		if extra == "" {
			continue
		}
		if !domainPattern.MatchString(extra) {
			return nil, fmt.Errorf("MAIL_EXTRA_DOMAINS entry %q is not a domain name", extra)
		}
		cfg.ExtraDomains = append(cfg.ExtraDomains, extra)
	}

	if raw := strings.TrimSpace(os.Getenv("MAIL_MAX_MESSAGE_BYTES")); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || parsed <= 0 {
			return nil, fmt.Errorf("MAIL_MAX_MESSAGE_BYTES must be a positive integer, got %q", raw)
		}
		cfg.MaxMessageBytes = parsed
	}

	if raw, ok := os.LookupEnv("MAIL_RELAY"); ok {
		relay, err := strconv.ParseBool(strings.TrimSpace(raw))
		if err != nil {
			return nil, fmt.Errorf("MAIL_RELAY must be a boolean, got %q", raw)
		}
		cfg.Relay = relay
	}

	if (cfg.TLSCertFile == "") != (cfg.TLSKeyFile == "") {
		return nil, fmt.Errorf("MAIL_TLS_CERT_FILE and MAIL_TLS_KEY_FILE must be set together")
	}

	if cfg.DKIMSelector != "" || cfg.DKIMKeyFile != "" {
		if cfg.DKIMSelector == "" || cfg.DKIMKeyFile == "" {
			return nil, fmt.Errorf("MAIL_DKIM_SELECTOR and MAIL_DKIM_KEY_FILE must be set together")
		}
		if cfg.DKIMDomain == "" {
			cfg.DKIMDomain = cfg.Domain
		}
	}

	return cfg, nil
}

// addrFromEnv reads a listener address. An unset variable falls back to the
// default; an explicitly empty value, "off" or "disabled" turns the listener
// off.
func addrFromEnv(key, fallback string) string {
	raw, ok := os.LookupEnv(key)
	if !ok {
		return fallback
	}
	raw = strings.TrimSpace(raw)
	switch strings.ToLower(raw) {
	case "", "off", "disabled", "none":
		return ""
	}
	return raw
}

// tlsConfig loads the certificate shared by every mail listener. It returns nil
// when no certificate is configured.
func (c *Config) tlsConfig() (*tls.Config, error) {
	if c.TLSCertFile == "" {
		return nil, nil
	}
	cert, err := tls.LoadX509KeyPair(c.TLSCertFile, c.TLSKeyFile)
	if err != nil {
		return nil, fmt.Errorf("load mail TLS certificate: %w", err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		ServerName:   c.Hostname,
	}, nil
}

// dkimSigner loads the DKIM key. It returns a nil signer when DKIM is not
// configured, in which case outgoing mail is simply not signed.
func (c *Config) dkimSigner() (crypto.Signer, error) {
	if c.DKIMKeyFile == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(c.DKIMKeyFile)
	if err != nil {
		return nil, fmt.Errorf("read DKIM key: %w", err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("DKIM key %s is not PEM encoded", c.DKIMKeyFile)
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse DKIM key: %w", err)
	}
	switch key := parsed.(type) {
	case *rsa.PrivateKey:
		return key, nil
	case ed25519.PrivateKey:
		return key, nil
	default:
		return nil, fmt.Errorf("DKIM key type %T is not supported, use RSA or Ed25519", parsed)
	}
}
