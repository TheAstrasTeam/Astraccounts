package mail

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"Astraccounts/logger"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// queue is the outbound spool. Messages are written to disk before the
// submitting client is told the message was accepted, so nothing is lost if the
// process dies between accepting and relaying.
type queue struct {
	server *Server
	dir    string

	mu   sync.Mutex
	wake chan struct{}
	stop chan struct{}
	done chan struct{}
}

// queueEntry is the sidecar JSON describing one spooled message.
type queueEntry struct {
	ID        string    `json:"id"`
	From      string    `json:"from"`
	To        []string  `json:"to"`
	Attempts  int       `json:"attempts"`
	FirstTry  time.Time `json:"first_try"`
	NextTry   time.Time `json:"next_try"`
	LastError string    `json:"last_error,omitempty"`
}

func newQueue(server *Server, dir string) *queue {
	return &queue{
		server: server,
		dir:    dir,
		wake:   make(chan struct{}, 1),
		stop:   make(chan struct{}),
		done:   make(chan struct{}),
	}
}

func (q *queue) entryPath(id string) string { return filepath.Join(q.dir, id+".json") }
func (q *queue) bodyPath(id string) string  { return filepath.Join(q.dir, id+".eml") }

// enqueue spools a message for delivery to remote recipients.
func (q *queue) enqueue(from string, to []string, message []byte) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if err := os.MkdirAll(q.dir, 0700); err != nil {
		return err
	}

	id := fmt.Sprintf("%d-%s", time.Now().UnixNano(), randomID(6))
	if err := os.WriteFile(q.bodyPath(id), message, 0600); err != nil {
		return err
	}

	entry := &queueEntry{
		ID:       id,
		From:     from,
		To:       to,
		FirstTry: time.Now(),
		NextTry:  time.Now(),
	}
	if err := q.writeEntry(entry); err != nil {
		_ = os.Remove(q.bodyPath(id))
		return err
	}

	logger.Info("Mail queued for relay", "id", id, "rcpts", len(to))
	q.signal()
	return nil
}

func (q *queue) writeEntry(entry *queueEntry) error {
	data, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(q.entryPath(entry.ID), append(data, '\n'), 0600)
}

func (q *queue) remove(id string) {
	if err := os.Remove(q.entryPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		logger.Error("Failed to remove queue entry", "err", err, "id", id)
	}
	if err := os.Remove(q.bodyPath(id)); err != nil && !errors.Is(err, os.ErrNotExist) {
		logger.Error("Failed to remove queued message", "err", err, "id", id)
	}
}

func (q *queue) signal() {
	select {
	case q.wake <- struct{}{}:
	default:
	}
}

// run drives the queue until shutdown. A single worker is enough: this server
// stores one JSON file per user, so it is not going to be pushing bulk mail.
func (q *queue) run() {
	defer close(q.done)

	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	q.flush()
	for {
		select {
		case <-q.stop:
			return
		case <-q.wake:
			q.flush()
		case <-ticker.C:
			q.flush()
		}
	}
}

func (q *queue) shutdown() {
	close(q.stop)
	<-q.done
}

// flush attempts every message whose retry time has come.
func (q *queue) flush() {
	entries, err := os.ReadDir(q.dir)
	if errors.Is(err, os.ErrNotExist) {
		return
	}
	if err != nil {
		logger.Error("Failed to read mail queue", "err", err)
		return
	}

	for _, file := range entries {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
			continue
		}
		select {
		case <-q.stop:
			return
		default:
		}

		entry, err := q.readEntry(strings.TrimSuffix(file.Name(), ".json"))
		if err != nil {
			logger.Error("Failed to read queue entry", "err", err, "file", file.Name())
			continue
		}
		if time.Now().Before(entry.NextTry) {
			continue
		}
		q.attempt(entry)
	}
}

func (q *queue) readEntry(id string) (*queueEntry, error) {
	data, err := os.ReadFile(q.entryPath(id))
	if err != nil {
		return nil, err
	}
	var entry queueEntry
	if err := json.Unmarshal(data, &entry); err != nil {
		return nil, err
	}
	return &entry, nil
}

// attempt tries one delivery round for a spooled message, splitting recipients
// by domain and keeping only those that failed temporarily.
func (q *queue) attempt(entry *queueEntry) {
	message, err := os.ReadFile(q.bodyPath(entry.ID))
	if err != nil {
		logger.Error("Queued message body missing, dropping", "err", err, "id", entry.ID)
		q.remove(entry.ID)
		return
	}

	entry.Attempts++
	var deferred []string
	var lastErr error

	for domain, rcpts := range groupByDomain(entry.To) {
		err := q.deliverDomain(domain, entry.From, rcpts, message)
		if err == nil {
			logger.Info("Mail relayed", "id", entry.ID, "domain", domain, "rcpts", len(rcpts))
			continue
		}
		lastErr = err

		if permanent(err) {
			logger.Warn("Mail permanently rejected",
				"id", entry.ID, "domain", domain, "err", err)
			q.bounce(entry, rcpts, err)
			continue
		}
		logger.Warn("Mail delivery deferred",
			"id", entry.ID, "domain", domain, "attempt", entry.Attempts, "err", err)
		deferred = append(deferred, rcpts...)
	}

	if len(deferred) == 0 {
		q.remove(entry.ID)
		return
	}

	if entry.Attempts >= queueMaxAttempts {
		logger.Error("Giving up on queued mail",
			"id", entry.ID, "attempts", entry.Attempts, "rcpts", deferred)
		q.bounce(entry, deferred, fmt.Errorf("gave up after %d attempts: %v", entry.Attempts, lastErr))
		q.remove(entry.ID)
		return
	}

	entry.To = deferred
	entry.NextTry = time.Now().Add(backoff(entry.Attempts))
	if lastErr != nil {
		entry.LastError = lastErr.Error()
	}
	if err := q.writeEntry(entry); err != nil {
		logger.Error("Failed to update queue entry", "err", err, "id", entry.ID)
	}
}

// backoff grows the retry delay geometrically, capped so a long outage still
// gets retried every few hours.
func backoff(attempts int) time.Duration {
	delay := queueRetryInterval
	for i := 1; i < attempts; i++ {
		delay *= 2
		if delay >= 6*time.Hour {
			return 6 * time.Hour
		}
	}
	return delay
}

func groupByDomain(rcpts []string) map[string][]string {
	grouped := make(map[string][]string)
	for _, rcpt := range rcpts {
		_, domain, ok := SplitAddress(rcpt)
		if !ok {
			continue
		}
		grouped[domain] = append(grouped[domain], rcpt)
	}
	return grouped
}

// deliverDomain sends one message to every recipient at a domain.
func (q *queue) deliverDomain(domain, from string, rcpts []string, message []byte) error {
	cfg := q.server.cfg

	if cfg.SmarthostAddr != "" {
		return q.deliverSmarthost(from, rcpts, message)
	}

	hosts, err := mxHosts(domain)
	if err != nil {
		return err
	}

	var lastErr error
	for _, host := range hosts {
		err := sendTo(net.JoinHostPort(host, "25"), host, cfg.Hostname, nil, from, rcpts, message, false)
		if err == nil {
			return nil
		}
		lastErr = err
		if permanent(err) {
			return err
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no usable MX host for %s", domain)
	}
	return lastErr
}

// deliverSmarthost relays through a configured provider instead of contacting
// the recipient's MX. This is the path to use when outbound port 25 is blocked.
func (q *queue) deliverSmarthost(from string, rcpts []string, message []byte) error {
	cfg := q.server.cfg

	host, port, err := net.SplitHostPort(cfg.SmarthostAddr)
	if err != nil {
		host, port = cfg.SmarthostAddr, "587"
	}

	var auth sasl.Client
	if cfg.SmarthostUser != "" {
		auth = sasl.NewPlainClient("", cfg.SmarthostUser, cfg.SmarthostPassword)
	}
	return sendTo(net.JoinHostPort(host, port), host, cfg.Hostname, auth,
		from, rcpts, message, port == "465")
}

// sendTo performs one SMTP transaction.
//
// For MX delivery TLS is opportunistic and the certificate is not verified:
// public MTAs routinely present self-signed or mismatched certificates, and
// refusing them would fail more mail than it protects. A smarthost is different
// because credentials are sent, so its certificate is verified.
func sendTo(addr, serverName, helo string, auth sasl.Client, from string, rcpts []string, message []byte, implicitTLS bool) error {
	var client *smtp.Client
	var err error

	switch {
	case implicitTLS:
		client, err = smtp.DialTLS(addr, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
	case auth != nil:
		client, err = smtp.DialStartTLS(addr, &tls.Config{ServerName: serverName, MinVersion: tls.VersionTLS12})
	default:
		client, err = smtp.DialStartTLS(addr, &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: true,
		})
		if err != nil {
			// The peer does not offer STARTTLS; fall back to cleartext, which is
			// still how a large share of the internet's MX traffic moves.
			client, err = smtp.Dial(addr)
		}
	}
	if err != nil {
		return err
	}
	defer client.Close()

	if err := client.Hello(helo); err != nil {
		return err
	}
	if auth != nil {
		if err := client.Auth(auth); err != nil {
			return err
		}
	}
	if err := client.Mail(from, nil); err != nil {
		return err
	}
	for _, rcpt := range rcpts {
		if err := client.Rcpt(rcpt, nil); err != nil {
			return err
		}
	}
	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(message); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}
	return client.Quit()
}

// mxHosts resolves a domain's mail exchangers, preference order preserved. A
// domain with no MX record falls back to its own address record, as RFC 5321
// requires.
func mxHosts(domain string) ([]string, error) {
	records, err := net.LookupMX(domain)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && !dnsErr.IsTemporary && !dnsErr.IsTimeout {
			if _, ipErr := net.LookupHost(domain); ipErr == nil {
				return []string{domain}, nil
			}
			return nil, &permanentError{err: fmt.Errorf("no mail host for %s: %w", domain, err)}
		}
		return nil, err
	}

	sort.SliceStable(records, func(i, j int) bool { return records[i].Pref < records[j].Pref })

	hosts := make([]string, 0, len(records))
	for _, record := range records {
		host := strings.TrimSuffix(record.Host, ".")
		// A single "." MX means the domain explicitly accepts no mail.
		if host == "" {
			continue
		}
		hosts = append(hosts, host)
	}
	if len(hosts) == 0 {
		if _, err := net.LookupHost(domain); err == nil {
			return []string{domain}, nil
		}
		return nil, &permanentError{err: fmt.Errorf("domain %s accepts no mail", domain)}
	}
	return hosts, nil
}

// permanentError marks a failure that must not be retried.
type permanentError struct{ err error }

func (e *permanentError) Error() string { return e.err.Error() }
func (e *permanentError) Unwrap() error { return e.err }

// permanent reports whether a delivery error is final. A 5xx SMTP reply and an
// authoritative DNS answer are permanent; everything else gets another try.
func permanent(err error) bool {
	var marked *permanentError
	if errors.As(err, &marked) {
		return true
	}
	var smtpErr *smtp.SMTPError
	if errors.As(err, &smtpErr) {
		return smtpErr.Code >= 500 && smtpErr.Code < 600
	}
	return false
}

// bounce reports a failure back to a local sender by delivering a message to
// their own mailbox. Senders are always local here because only authenticated
// submission can queue mail.
func (q *queue) bounce(entry *queueEntry, rcpts []string, cause error) {
	local, domain, ok := SplitAddress(entry.From)
	if !ok || !q.server.isLocalDomain(domain) {
		logger.Warn("Cannot bounce to non-local sender",
			"from", entry.From, "id", entry.ID)
		return
	}
	account, found := q.server.accounts.FindByID(local)
	if !found {
		return
	}

	var body bytes.Buffer
	fmt.Fprintf(&body, "Received: by %s with internal id %s; %s\r\n",
		q.server.cfg.Hostname, randomID(8), time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&body, "From: <MAILER-DAEMON@%s>\r\n", q.server.cfg.Domain)
	fmt.Fprintf(&body, "To: <%s>\r\n", entry.From)
	fmt.Fprintf(&body, "Subject: Undelivered mail returned to sender\r\n")
	fmt.Fprintf(&body, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	fmt.Fprintf(&body, "Message-ID: <%s@%s>\r\n", randomID(16), q.server.cfg.Domain)
	fmt.Fprintf(&body, "Content-Type: text/plain; charset=utf-8\r\n")
	fmt.Fprintf(&body, "\r\n")
	fmt.Fprintf(&body, "This message could not be delivered to:\r\n\r\n")
	for _, rcpt := range rcpts {
		fmt.Fprintf(&body, "    %s\r\n", rcpt)
	}
	fmt.Fprintf(&body, "\r\nReason: %s\r\n", cause)
	fmt.Fprintf(&body, "Queue id: %s, attempts: %d, first tried %s\r\n",
		entry.ID, entry.Attempts, entry.FirstTry.Format(time.RFC1123Z))

	if _, err := q.server.store.Append(account.UID, Inbox, nil, time.Now(), body.Bytes()); err != nil {
		logger.Error("Failed to deliver bounce", "err", err, "uid", account.UID)
	}
}
