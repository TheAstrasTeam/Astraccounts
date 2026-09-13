package mail

import (
	"context"
	"crypto"
	"crypto/tls"
	"fmt"
	"net"
	"path/filepath"
	"sync"

	"Astraccounts/logger"

	"github.com/emersion/go-imap/server"
	"github.com/emersion/go-smtp"
)

// Server owns every mail listener and the outbound queue.
//
// Listeners are created eagerly in Start so a port clash or a bad certificate
// is reported to main instead of surfacing later inside a goroutine.
type Server struct {
	cfg      *Config
	accounts Accounts
	store    *Store
	tls      *tls.Config
	dkim     crypto.Signer
	queue    *queue

	mu          sync.Mutex
	closed      bool
	listeners   []net.Listener
	addrs       map[string]string
	smtpServers []*smtp.Server
	imapServers []*server.Server
	wg          sync.WaitGroup
}

// New prepares a mail server. dataDir is the directory holding the service's
// state, used here for the outbound queue.
func New(cfg *Config, accounts Accounts, dataDir string) (*Server, error) {
	tlsConfig, err := cfg.tlsConfig()
	if err != nil {
		return nil, err
	}
	signer, err := cfg.dkimSigner()
	if err != nil {
		return nil, err
	}
	if cfg.QueueDir == "" {
		cfg.QueueDir = filepath.Join(dataDir, "queue")
	}

	srv := &Server{
		cfg:      cfg,
		accounts: accounts,
		store:    NewStore(accounts),
		tls:      tlsConfig,
		dkim:     signer,
		addrs:    make(map[string]string),
	}
	srv.queue = newQueue(srv, cfg.QueueDir)
	return srv, nil
}

// Store exposes the mail store so callers can provision or inspect mailboxes.
func (s *Server) Store() *Store {
	return s.store
}

// Addr reports the address a listener actually bound to, which is how a caller
// discovers the port when the configuration asked for :0. Roles are "smtp",
// "submission", "submission-tls", "pop3", "pop3-tls", "imap" and "imap-tls".
func (s *Server) Addr(role string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.addrs[role]
}

// Start binds every configured listener and starts serving.
func (s *Server) Start() error {
	if s.tls == nil {
		logger.Warn("Mail TLS is not configured; clients will send passwords in cleartext " +
			"and implicit TLS ports stay closed")
	}
	if s.dkim == nil && s.cfg.Relay {
		logger.Warn("DKIM signing is not configured; outgoing mail is more likely to be " +
			"treated as spam")
	}

	if err := s.startSMTP("smtp", s.cfg.SMTPAddr, false, false); err != nil {
		return err
	}
	if err := s.startSMTP("submission", s.cfg.SubmissionAddr, true, false); err != nil {
		return err
	}
	if err := s.startSMTP("submission-tls", s.cfg.SubmissionTLSAddr, true, true); err != nil {
		return err
	}
	if err := s.startPOP3("pop3", s.cfg.POP3Addr, false); err != nil {
		return err
	}
	if err := s.startPOP3("pop3-tls", s.cfg.POP3TLSAddr, true); err != nil {
		return err
	}
	if err := s.startIMAP("imap", s.cfg.IMAPAddr, false); err != nil {
		return err
	}
	if err := s.startIMAP("imap-tls", s.cfg.IMAPTLSAddr, true); err != nil {
		return err
	}

	if s.cfg.Relay {
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.queue.run()
		}()
	}

	logger.Info("Mail server started",
		"domain", s.cfg.Domain, "hostname", s.cfg.Hostname, "relay", s.cfg.Relay)
	return nil
}

// listen binds addr, wrapping it in TLS for the implicit-TLS ports. An empty
// address disables the listener, and implicit TLS without a certificate is
// skipped rather than treated as an error.
func (s *Server) listen(role, addr string, implicitTLS bool) (net.Listener, error) {
	if addr == "" {
		return nil, nil
	}
	if implicitTLS && s.tls == nil {
		return nil, nil
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("listen %s: %w", addr, err)
	}
	bound := listener.Addr().String()
	if implicitTLS {
		listener = tls.NewListener(listener, s.tls)
	}

	s.mu.Lock()
	s.listeners = append(s.listeners, listener)
	s.addrs[role] = bound
	s.mu.Unlock()
	return listener, nil
}

func (s *Server) startSMTP(role, addr string, submission, implicitTLS bool) error {
	listener, err := s.listen(role, addr, implicitTLS)
	if listener == nil || err != nil {
		return err
	}

	srv := smtp.NewServer(&smtpBackend{server: s, submission: submission})
	srv.Domain = s.cfg.Hostname
	srv.MaxMessageBytes = s.cfg.MaxMessageBytes
	srv.MaxRecipients = 100
	srv.ReadTimeout = smtpReadTimeout
	srv.WriteTimeout = smtpWriteTimeout
	srv.TLSConfig = s.tls
	// AUTH over cleartext is only tolerated when the server has no certificate
	// at all; with TLS available, clients must upgrade first.
	srv.AllowInsecureAuth = s.tls == nil

	s.mu.Lock()
	s.smtpServers = append(s.smtpServers, srv)
	s.mu.Unlock()

	logger.Info("Mail listener ready",
		"proto", role, "addr", s.Addr(role), "implicit_tls", implicitTLS)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := srv.Serve(listener); err != nil && !s.closing() {
			logger.Error("SMTP server stopped", "err", err, "addr", addr)
		}
	}()
	return nil
}

func (s *Server) startPOP3(role, addr string, implicitTLS bool) error {
	listener, err := s.listen(role, addr, implicitTLS)
	if listener == nil || err != nil {
		return err
	}

	logger.Info("Mail listener ready", "proto", "pop3", "addr", s.Addr(role), "implicit_tls", implicitTLS)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		// Connections arriving on an implicit-TLS listener are already wrapped
		// by tls.NewListener, so the session never has to upgrade them.
		s.servePOP3(listener, false)
	}()
	return nil
}

func (s *Server) startIMAP(role, addr string, implicitTLS bool) error {
	listener, err := s.listen(role, addr, implicitTLS)
	if listener == nil || err != nil {
		return err
	}

	srv := server.New(&imapBackend{server: s})
	srv.Addr = addr
	srv.TLSConfig = s.tls
	srv.AllowInsecureAuth = s.tls == nil
	srv.AutoLogout = imapAutoLogout

	s.mu.Lock()
	s.imapServers = append(s.imapServers, srv)
	s.mu.Unlock()

	logger.Info("Mail listener ready", "proto", "imap", "addr", s.Addr(role), "implicit_tls", implicitTLS)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		if err := srv.Serve(listener); err != nil && !s.closing() {
			logger.Error("IMAP server stopped", "err", err, "addr", addr)
		}
	}()
	return nil
}

func (s *Server) closing() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.closed
}

// Shutdown stops accepting connections and waits for the serving goroutines.
func (s *Server) Shutdown(ctx context.Context) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	listeners := s.listeners
	smtpServers := s.smtpServers
	imapServers := s.imapServers
	s.mu.Unlock()

	for _, srv := range smtpServers {
		_ = srv.Shutdown(ctx)
	}
	for _, srv := range imapServers {
		_ = srv.Close()
	}
	for _, listener := range listeners {
		_ = listener.Close()
	}
	if s.cfg.Relay {
		s.queue.shutdown()
	}

	s.wg.Wait()
	logger.Info("Mail server stopped")
	return nil
}
