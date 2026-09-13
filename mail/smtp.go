package mail

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"Astraccounts/auth"
	"Astraccounts/logger"

	"github.com/emersion/go-message/textproto"
	"github.com/emersion/go-msgauth/dkim"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// smtpBackend serves one of the two SMTP roles.
//
// The MX listener takes mail from the internet for local mailboxes and must
// never relay. The submission listener takes mail from authenticated users and
// is the only path that may send outwards. Keeping them as separate listeners
// with separate policy is what stops the service from being an open relay.
type smtpBackend struct {
	server     *Server
	submission bool
}

func (b *smtpBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &smtpSession{backend: b, conn: c}, nil
}

type smtpRecipient struct {
	addr    string
	account *auth.Account // non-nil when the recipient is local
}

type smtpSession struct {
	backend *smtpBackend
	conn    *smtp.Conn

	account *auth.Account // set once AUTH succeeds
	from    string
	rcpts   []smtpRecipient
}

// Reset drops the message in progress but keeps the authenticated identity, as
// RSET requires.
func (s *smtpSession) Reset() {
	s.from = ""
	s.rcpts = nil
}

func (s *smtpSession) Logout() error {
	return nil
}

// AuthMechanisms advertises AUTH on the submission listener only. Returning an
// empty list on the MX listener keeps AUTH out of the EHLO response entirely.
func (s *smtpSession) AuthMechanisms() []string {
	if !s.backend.submission {
		return nil
	}
	return []string{sasl.Plain, sasl.Login}
}

// Auth authenticates a submission client against the account store. PLAIN and
// LOGIN both hand over a cleartext password, so go-smtp is configured to refuse
// them on an unencrypted connection whenever a certificate is available.
func (s *smtpSession) Auth(mech string) (sasl.Server, error) {
	if !s.backend.submission {
		return nil, smtp.ErrAuthUnsupported
	}

	authenticate := func(username, password string) error {
		account, ok := s.backend.server.login(username, password)
		if !ok {
			logger.Warn("Mail auth failed",
				"proto", "smtp", "user", username, "remote", s.remoteAddr())
			return smtp.ErrAuthFailed
		}
		s.account = &account
		return nil
	}

	switch mech {
	case sasl.Plain:
		return sasl.NewPlainServer(func(identity, username, password string) error {
			if identity != "" && identity != username {
				return smtp.ErrAuthFailed
			}
			return authenticate(username, password)
		}), nil
	case sasl.Login:
		return newLoginServer(authenticate), nil
	default:
		return nil, smtp.ErrAuthUnknownMechanism
	}
}

func (s *smtpSession) remoteAddr() string {
	if conn := s.conn.Conn(); conn != nil {
		return conn.RemoteAddr().String()
	}
	return "unknown"
}

// remoteIP renders the peer for a Received header. RFC 5321 wants the address
// literal without the ephemeral source port.
func (s *smtpSession) remoteIP() string {
	conn := s.conn.Conn()
	if conn == nil {
		return "[unknown]"
	}
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return "[" + conn.RemoteAddr().String() + "]"
	}
	return "[" + host + "]"
}

func (s *smtpSession) encrypted() bool {
	_, ok := s.conn.TLSConnectionState()
	return ok
}

// Mail handles MAIL FROM. Submission requires an authenticated sender and
// refuses to send on behalf of anyone else, so a stolen client config cannot be
// used to forge another local user.
func (s *smtpSession) Mail(from string, _ *smtp.MailOptions) error {
	if s.backend.submission {
		if s.account == nil {
			return smtp.ErrAuthRequired
		}
		owned := s.account.Address(s.backend.server.cfg.Domain)
		if !strings.EqualFold(from, owned) {
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 7, 1},
				Message:      "Sender must be " + owned,
			}
		}
	}

	s.from = from
	s.rcpts = nil
	return nil
}

// Rcpt handles RCPT TO and decides local delivery versus relay.
func (s *smtpSession) Rcpt(to string, _ *smtp.RcptOptions) error {
	server := s.backend.server

	local, domain, ok := SplitAddress(to)
	if !ok {
		return &smtp.SMTPError{
			Code:         501,
			EnhancedCode: smtp.EnhancedCode{5, 1, 3},
			Message:      "Malformed recipient address",
		}
	}

	if server.isLocalDomain(domain) {
		account, found := server.accounts.FindByID(local)
		if !found {
			return &smtp.SMTPError{
				Code:         550,
				EnhancedCode: smtp.EnhancedCode{5, 1, 1},
				Message:      "No such user here",
			}
		}
		s.rcpts = append(s.rcpts, smtpRecipient{addr: to, account: &account})
		return nil
	}

	// A remote recipient is only acceptable from an authenticated submission
	// client. Without this branch the MX listener would be an open relay.
	if !s.backend.submission || s.account == nil {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "Relay access denied",
		}
	}
	if !server.cfg.Relay {
		return &smtp.SMTPError{
			Code:         550,
			EnhancedCode: smtp.EnhancedCode{5, 7, 1},
			Message:      "Relaying is disabled on this server",
		}
	}
	s.rcpts = append(s.rcpts, smtpRecipient{addr: to})
	return nil
}

// Data reads the message, stamps it, and either files it into local mailboxes
// or hands it to the outbound queue.
func (s *smtpSession) Data(r io.Reader) error {
	server := s.backend.server
	if len(s.rcpts) == 0 {
		return &smtp.SMTPError{
			Code:         554,
			EnhancedCode: smtp.EnhancedCode{5, 5, 1},
			Message:      "No valid recipients",
		}
	}

	limit := server.cfg.MaxMessageBytes
	raw, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return err
	}
	if int64(len(raw)) > limit {
		return &smtp.SMTPError{
			Code:         552,
			EnhancedCode: smtp.EnhancedCode{5, 3, 4},
			Message:      fmt.Sprintf("Message exceeds %d bytes", limit),
		}
	}
	raw = normaliseLineEndings(raw)

	if s.backend.submission {
		raw = s.stampSubmission(raw)
		if signed, err := server.sign(raw); err != nil {
			// An unsigned message still beats a bounced one; DKIM only affects
			// how the far end scores it.
			logger.Error("DKIM signing failed, sending unsigned", "err", err)
		} else {
			raw = signed
		}
	}

	var localErr error
	var remote []string
	for _, rcpt := range s.rcpts {
		message := append(s.received(rcpt.addr), raw...)

		if rcpt.account == nil {
			remote = append(remote, rcpt.addr)
			continue
		}
		if _, err := server.store.Append(rcpt.account.UID, Inbox, nil, time.Now(), message); err != nil {
			logger.Error("Local mail delivery failed",
				"err", err, "uid", rcpt.account.UID, "rcpt", rcpt.addr)
			localErr = err
			continue
		}
		logger.Info("Mail delivered",
			"to", rcpt.addr, "uid", rcpt.account.UID, "bytes", len(message))
	}

	if len(remote) > 0 {
		message := append(s.received(""), raw...)
		if err := server.queue.enqueue(s.from, remote, message); err != nil {
			logger.Error("Failed to queue outbound mail", "err", err, "rcpts", remote)
			return &smtp.SMTPError{
				Code:         451,
				EnhancedCode: smtp.EnhancedCode{4, 3, 0},
				Message:      "Could not queue message for delivery",
			}
		}
	}

	if localErr != nil {
		return &smtp.SMTPError{
			Code:         451,
			EnhancedCode: smtp.EnhancedCode{4, 3, 0},
			Message:      "Could not store message",
		}
	}
	return nil
}

// stampSubmission fills in the headers a mail client is allowed to omit but
// that receiving MTAs expect to see.
func (s *smtpSession) stampSubmission(raw []byte) []byte {
	header, err := readHeader(raw)
	if err != nil {
		return raw
	}

	var extra bytes.Buffer
	if !header.Has("Date") {
		fmt.Fprintf(&extra, "Date: %s\r\n", time.Now().Format(time.RFC1123Z))
	}
	if !header.Has("Message-ID") {
		fmt.Fprintf(&extra, "Message-ID: <%s@%s>\r\n", randomID(16), s.backend.server.cfg.Domain)
	}
	if !header.Has("From") && s.account != nil {
		fmt.Fprintf(&extra, "From: <%s>\r\n", s.account.Address(s.backend.server.cfg.Domain))
	}
	if extra.Len() == 0 {
		return raw
	}
	return append(extra.Bytes(), raw...)
}

// received builds the trace header prepended to every message passing through.
func (s *smtpSession) received(rcpt string) []byte {
	protocol := "SMTP"
	if s.backend.submission {
		protocol = "ESMTPA"
	}
	if s.encrypted() {
		protocol += "S"
	}

	var b bytes.Buffer
	fmt.Fprintf(&b, "Received: from %s (%s)\r\n", helo(s.conn.Hostname()), s.remoteIP())
	fmt.Fprintf(&b, "\tby %s with %s id %s\r\n",
		s.backend.server.cfg.Hostname, protocol, randomID(8))
	if rcpt != "" {
		fmt.Fprintf(&b, "\tfor <%s>", rcpt)
	} else {
		b.WriteString("\t")
	}
	fmt.Fprintf(&b, "; %s\r\n", time.Now().Format(time.RFC1123Z))
	return b.Bytes()
}

func helo(name string) string {
	if name == "" {
		return "unknown"
	}
	return name
}

// sign applies a DKIM signature when a key is configured.
func (s *Server) sign(raw []byte) ([]byte, error) {
	if s.dkim == nil {
		return raw, nil
	}
	var signed bytes.Buffer
	options := &dkim.SignOptions{
		Domain:   s.cfg.DKIMDomain,
		Selector: s.cfg.DKIMSelector,
		Signer:   s.dkim,
	}
	if err := dkim.Sign(&signed, bytes.NewReader(raw), options); err != nil {
		return raw, err
	}
	return signed.Bytes(), nil
}

// login authenticates a mail client. Clients may use either the bare user ID or
// the full mailbox address as the username, because both are what users think
// of as "their e-mail login".
func (s *Server) login(username, password string) (auth.Account, bool) {
	if local, domain, ok := SplitAddress(username); ok && s.isLocalDomain(domain) {
		username = local
	}
	return s.accounts.Authenticate(username, password)
}

func readHeader(raw []byte) (textproto.Header, error) {
	return textproto.ReadHeader(bufio.NewReader(bytes.NewReader(raw)))
}

// normaliseLineEndings rewrites bare LF as CRLF. Mail on the wire is CRLF, but
// a sloppy client can still emit LF, and a mixed message breaks both DKIM
// canonicalisation and header parsing.
func normaliseLineEndings(raw []byte) []byte {
	if !bytes.ContainsRune(raw, '\n') {
		return raw
	}
	var out bytes.Buffer
	out.Grow(len(raw) + len(raw)/16)
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\n' && (i == 0 || raw[i-1] != '\r') {
			out.WriteString("\r\n")
			continue
		}
		out.WriteByte(raw[i])
	}
	return out.Bytes()
}

func randomID(bytesLen int) string {
	buf := make([]byte, bytesLen)
	if _, err := rand.Read(buf); err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

// loginServer implements the server side of the obsolete but widely used SASL
// LOGIN mechanism. go-sasl only ships the client half, and several Windows mail
// clients try LOGIN before PLAIN.
//
// go-smtp calls Next(nil) when the client sends no initial response, and an
// empty client reply arrives as a non-nil zero-length slice, so the step
// counter cannot be driven into a loop by an empty username.
type loginServer struct {
	authenticate func(username, password string) error
	username     string
	step         int
}

func newLoginServer(authenticate func(username, password string) error) sasl.Server {
	return &loginServer{authenticate: authenticate}
}

func (l *loginServer) Next(response []byte) (challenge []byte, done bool, err error) {
	switch l.step {
	case 0:
		if response == nil {
			return []byte("Username:"), false, nil
		}
		l.username = string(response)
		l.step = 1
		return []byte("Password:"), false, nil
	case 1:
		if err := l.authenticate(l.username, string(response)); err != nil {
			return nil, false, err
		}
		l.step = 2
		return nil, true, nil
	default:
		return nil, false, errors.New("mail: unexpected SASL LOGIN state")
	}
}
