package mail

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"

	"Astraccounts/auth"
	"Astraccounts/logger"
)

// pop3IdleTimeout is the session inactivity limit. RFC 1939 requires at least
// ten minutes for the autologout timer.
const pop3IdleTimeout = 10 * time.Minute

// servePOP3 accepts POP3 connections until the listener is closed.
//
// POP3 is implemented directly rather than pulled in as a dependency: RFC 1939
// is a dozen commands operating on a flat INBOX, which is exactly the shape the
// store already has.
func (s *Server) servePOP3(listener net.Listener, implicitTLS bool) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			if s.closing() {
				return
			}
			logger.Error("POP3 accept failed", "err", err)
			return
		}

		if implicitTLS {
			conn = tls.Server(conn, s.tls)
		}
		go func() {
			session := &pop3Session{server: s, conn: conn}
			defer session.close()
			session.serve()
		}()
	}
}

// pop3Session is one client connection. POP3 is strictly sequential, so no
// locking is needed beyond what the store already does.
type pop3Session struct {
	server *Server
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer

	account *auth.Account
	user    string

	// snapshot fixes message numbers for the whole session, as POP3 requires:
	// mail arriving mid-session must not renumber anything.
	snapshot *Snapshot
	deleted  map[uint32]bool
}

func (p *pop3Session) close() {
	_ = p.conn.Close()
}

func (p *pop3Session) serve() {
	p.reader = bufio.NewReader(p.conn)
	p.writer = bufio.NewWriter(p.conn)
	p.deleted = make(map[uint32]bool)

	p.ok("Astraccounts POP3 ready")
	for {
		_ = p.conn.SetReadDeadline(time.Now().Add(pop3IdleTimeout))

		line, err := p.reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")

		command, argument := line, ""
		if index := strings.IndexByte(line, ' '); index >= 0 {
			command, argument = line[:index], strings.TrimSpace(line[index+1:])
		}

		if !p.handle(strings.ToUpper(command), argument) {
			return
		}
	}
}

// handle runs one command and reports whether the session continues.
func (p *pop3Session) handle(command, argument string) bool {
	switch command {
	case "CAPA":
		p.capabilities()
	case "STLS":
		return p.startTLS()
	case "USER":
		p.user = argument
		p.ok("send PASS")
	case "PASS":
		p.pass(argument)
	case "QUIT":
		p.quit()
		return false
	case "NOOP":
		p.ok("")
	case "STAT":
		p.stat()
	case "LIST":
		p.list(argument)
	case "UIDL":
		p.uidl(argument)
	case "RETR":
		p.retr(argument)
	case "TOP":
		p.top(argument)
	case "DELE":
		p.dele(argument)
	case "RSET":
		p.rset()
	default:
		p.err("unknown command")
	}
	return true
}

func (p *pop3Session) ok(message string) {
	if message == "" {
		p.respond("+OK")
		return
	}
	p.respond("+OK " + message)
}

func (p *pop3Session) err(message string) {
	p.respond("-ERR " + message)
}

func (p *pop3Session) respond(line string) {
	_ = p.conn.SetWriteDeadline(time.Now().Add(time.Minute))
	_, _ = p.writer.WriteString(line + "\r\n")
	_ = p.writer.Flush()
}

func (p *pop3Session) encrypted() bool {
	_, ok := p.conn.(*tls.Conn)
	return ok
}

func (p *pop3Session) capabilities() {
	p.ok("capability list follows")
	lines := []string{"TOP", "USER", "UIDL"}
	if p.server.tls != nil && !p.encrypted() {
		lines = append(lines, "STLS")
	}
	for _, line := range lines {
		_, _ = p.writer.WriteString(line + "\r\n")
	}
	_, _ = p.writer.WriteString(".\r\n")
	_ = p.writer.Flush()
}

func (p *pop3Session) startTLS() bool {
	if p.server.tls == nil {
		p.err("TLS not configured")
		return true
	}
	if p.encrypted() {
		p.err("already using TLS")
		return true
	}

	p.ok("begin TLS negotiation")
	tlsConn := tls.Server(p.conn, p.server.tls)
	if err := tlsConn.Handshake(); err != nil {
		logger.Warn("POP3 STLS handshake failed", "err", err)
		return false
	}
	p.conn = tlsConn
	p.reader = bufio.NewReader(tlsConn)
	p.writer = bufio.NewWriter(tlsConn)
	return true
}

// pass completes authentication and takes the mailbox snapshot.
func (p *pop3Session) pass(password string) {
	if p.account != nil {
		p.err("already authenticated")
		return
	}
	if p.user == "" {
		p.err("send USER first")
		return
	}
	// Cleartext credentials are only refused when TLS is actually available;
	// otherwise a server without a certificate could never be used at all.
	if p.server.tls != nil && !p.encrypted() {
		p.err("STLS required before authentication")
		return
	}

	account, ok := p.server.login(p.user, password)
	if !ok {
		logger.Warn("Mail auth failed",
			"proto", "pop3", "user", p.user, "remote", p.conn.RemoteAddr().String())
		p.err("authentication failed")
		return
	}

	snapshot, err := p.server.store.Snapshot(account.UID, Inbox)
	if err != nil {
		logger.Error("Failed to open INBOX for POP3", "err", err, "uid", account.UID)
		p.err("mailbox unavailable")
		return
	}

	p.account = &account
	p.snapshot = snapshot
	p.ok(fmt.Sprintf("mailbox ready, %d messages", len(snapshot.Messages)))
}

// message resolves a 1-based POP3 message number against the snapshot.
func (p *pop3Session) message(argument string) (int, *Message, bool) {
	if p.account == nil {
		p.err("not authenticated")
		return 0, nil, false
	}
	number, err := strconv.Atoi(argument)
	if err != nil || number < 1 || number > len(p.snapshot.Messages) {
		p.err("no such message")
		return 0, nil, false
	}
	msg := p.snapshot.Messages[number-1]
	if p.deleted[msg.UID] {
		p.err("message is deleted")
		return 0, nil, false
	}
	return number, msg, true
}

func (p *pop3Session) stat() {
	if p.account == nil {
		p.err("not authenticated")
		return
	}
	var count int
	var size uint64
	for _, msg := range p.snapshot.Messages {
		if p.deleted[msg.UID] {
			continue
		}
		count++
		size += uint64(msg.Size)
	}
	p.ok(fmt.Sprintf("%d %d", count, size))
}

func (p *pop3Session) list(argument string) {
	if argument != "" {
		number, msg, ok := p.message(argument)
		if !ok {
			return
		}
		p.ok(fmt.Sprintf("%d %d", number, msg.Size))
		return
	}
	if p.account == nil {
		p.err("not authenticated")
		return
	}

	p.ok("scan listing follows")
	for i, msg := range p.snapshot.Messages {
		if p.deleted[msg.UID] {
			continue
		}
		_, _ = fmt.Fprintf(p.writer, "%d %d\r\n", i+1, msg.Size)
	}
	_, _ = p.writer.WriteString(".\r\n")
	_ = p.writer.Flush()
}

// uidl reports a persistent identifier per message. UIDVALIDITY is included so
// the identifier cannot be reused if a mailbox is recreated.
func (p *pop3Session) uidl(argument string) {
	if argument != "" {
		number, msg, ok := p.message(argument)
		if !ok {
			return
		}
		p.ok(fmt.Sprintf("%d %s", number, p.uid(msg)))
		return
	}
	if p.account == nil {
		p.err("not authenticated")
		return
	}

	p.ok("unique-id listing follows")
	for i, msg := range p.snapshot.Messages {
		if p.deleted[msg.UID] {
			continue
		}
		_, _ = fmt.Fprintf(p.writer, "%d %s\r\n", i+1, p.uid(msg))
	}
	_, _ = p.writer.WriteString(".\r\n")
	_ = p.writer.Flush()
}

func (p *pop3Session) uid(msg *Message) string {
	return fmt.Sprintf("%d.%d", p.snapshot.UIDValidity, msg.UID)
}

func (p *pop3Session) retr(argument string) {
	_, msg, ok := p.message(argument)
	if !ok {
		return
	}
	body, err := p.server.store.Body(p.account.UID, Inbox, msg)
	if err != nil {
		logger.Error("Failed to read message for POP3", "err", err, "uid", p.account.UID)
		p.err("message unavailable")
		return
	}

	p.ok(fmt.Sprintf("%d octets", len(body)))
	p.writeDotted(body, -1)

	// Downloading a message marks it read, matching what other POP3 servers do,
	// so the IMAP view of the same mailbox stays sensible.
	if err := p.server.store.SetFlags(p.account.UID, Inbox,
		[]uint32{msg.UID}, []string{FlagSeen}, FlagsAdd); err != nil {
		logger.Error("Failed to flag message as seen", "err", err, "uid", p.account.UID)
	}
}

func (p *pop3Session) top(argument string) {
	fields := strings.Fields(argument)
	if len(fields) != 2 {
		p.err("usage: TOP msg lines")
		return
	}
	lines, err := strconv.Atoi(fields[1])
	if err != nil || lines < 0 {
		p.err("invalid line count")
		return
	}
	_, msg, ok := p.message(fields[0])
	if !ok {
		return
	}

	body, err := p.server.store.Body(p.account.UID, Inbox, msg)
	if err != nil {
		p.err("message unavailable")
		return
	}
	p.ok("top of message follows")
	p.writeDotted(body, lines)
}

func (p *pop3Session) dele(argument string) {
	_, msg, ok := p.message(argument)
	if !ok {
		return
	}
	p.deleted[msg.UID] = true
	p.ok("message marked for deletion")
}

// rset un-marks every deletion, as RFC 1939 requires.
func (p *pop3Session) rset() {
	if p.account == nil {
		p.err("not authenticated")
		return
	}
	p.deleted = make(map[uint32]bool)
	p.ok("deletions cleared")
}

// quit enters the UPDATE state: deletions marked during the session are
// committed here and nowhere else.
func (p *pop3Session) quit() {
	if p.account == nil {
		p.ok("bye")
		return
	}

	uids := make([]uint32, 0, len(p.deleted))
	for uid := range p.deleted {
		uids = append(uids, uid)
	}
	if len(uids) > 0 {
		if err := p.server.store.Remove(p.account.UID, Inbox, uids); err != nil {
			logger.Error("POP3 deletion failed", "err", err, "uid", p.account.UID)
			p.err("could not delete messages")
			return
		}
		logger.Info("POP3 session removed messages",
			"uid", p.account.UID, "count", len(uids))
	}
	p.ok("bye")
}

// writeDotted writes a multi-line response body with dot-stuffing. A non
// negative bodyLines limit stops after that many lines of the body, which is
// what TOP needs.
func (p *pop3Session) writeDotted(body []byte, bodyLines int) {
	_ = p.conn.SetWriteDeadline(time.Now().Add(5 * time.Minute))

	headerDone := bodyLines < 0
	emitted := 0
	reader := bufio.NewReader(bytes.NewReader(body))

	for {
		line, err := reader.ReadString('\n')
		if line != "" {
			trimmed := strings.TrimRight(line, "\r\n")

			if !headerDone && trimmed == "" {
				headerDone = true
			} else if headerDone && bodyLines >= 0 {
				if emitted >= bodyLines {
					break
				}
				emitted++
			}

			if strings.HasPrefix(trimmed, ".") {
				trimmed = "." + trimmed
			}
			_, _ = p.writer.WriteString(trimmed + "\r\n")
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
	}

	_, _ = p.writer.WriteString(".\r\n")
	_ = p.writer.Flush()
}
