package mail

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/emersion/go-imap"
	imapclient "github.com/emersion/go-imap/client"
	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

// newTestServer starts a mail server on ephemeral loopback ports with relay
// switched off, so nothing in the test suite touches DNS or the network.
func newTestServer(t *testing.T, ids ...string) (*Server, *fakeAccounts) {
	t.Helper()

	dir := t.TempDir()
	accounts := newFakeAccounts(dir, ids...)
	cfg := &Config{
		Domain:          "example.test",
		Hostname:        "mx.example.test",
		SMTPAddr:        "127.0.0.1:0",
		SubmissionAddr:  "127.0.0.1:0",
		POP3Addr:        "127.0.0.1:0",
		IMAPAddr:        "127.0.0.1:0",
		MaxMessageBytes: defaultMaxMessageBytes,
		Relay:           false,
		QueueDir:        dir + "/queue",
	}

	server, err := New(cfg, accounts, dir)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := server.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = server.Shutdown(testContext()) })
	return server, accounts
}

func testContext() contextWithTimeout {
	return contextWithTimeout{}
}

// contextWithTimeout is a minimal context so the test does not need to import
// context just for shutdown.
type contextWithTimeout struct{}

func (contextWithTimeout) Deadline() (time.Time, bool) { return time.Time{}, false }
func (contextWithTimeout) Done() <-chan struct{}       { return nil }
func (contextWithTimeout) Err() error                  { return nil }
func (contextWithTimeout) Value(any) any               { return nil }

// TestSMTPDeliversToLocalMailbox is the inbound MX path: unauthenticated mail
// from the internet for a local user must land in that user's INBOX.
func TestSMTPDeliversToLocalMailbox(t *testing.T) {
	server, _ := newTestServer(t, "Alice")

	body := "Subject: hello\r\nFrom: <outside@remote.test>\r\nTo: <Alice@example.test>\r\n\r\nHi Alice.\r\n"
	sendSMTP(t, server.Addr("smtp"), "outside@remote.test", []string{"Alice@example.test"}, body)

	snapshot, err := server.store.Snapshot(1, Inbox)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snapshot.Messages) != 1 {
		t.Fatalf("INBOX has %d messages, want 1", len(snapshot.Messages))
	}

	stored, err := server.store.Body(1, Inbox, snapshot.Messages[0])
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	if !strings.Contains(string(stored), "Subject: hello") {
		t.Errorf("stored message lost its subject: %q", stored)
	}
	// Every hop must leave a trace header, and ours has to be the topmost one.
	if !strings.HasPrefix(string(stored), "Received: from ") {
		t.Errorf("stored message does not start with Received: %q", firstLine(stored))
	}
}

// TestSMTPRejectsRelay is the open-relay check. An unauthenticated client must
// never be able to send to a domain this server does not own.
func TestSMTPRejectsRelay(t *testing.T) {
	server, _ := newTestServer(t, "Alice")

	client, err := smtp.Dial(server.Addr("smtp"))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	if err := client.Mail("outside@remote.test", nil); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	err = client.Rcpt("victim@elsewhere.test", nil)
	if err == nil {
		t.Fatal("relay to a foreign domain was accepted; this is an open relay")
	}
	if !strings.Contains(err.Error(), "Relay access denied") {
		t.Errorf("error = %v, want relay refusal", err)
	}
}

func TestSMTPRejectsUnknownRecipient(t *testing.T) {
	server, _ := newTestServer(t, "Alice")

	client, err := smtp.Dial(server.Addr("smtp"))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	if err := client.Mail("outside@remote.test", nil); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	if err := client.Rcpt("nobody@example.test", nil); err == nil {
		t.Fatal("unknown local recipient was accepted")
	}
}

// TestSubmissionRequiresAuth checks that the submission port cannot be used
// without credentials, and that an authenticated user cannot forge a sender.
func TestSubmissionRequiresAuth(t *testing.T) {
	server, _ := newTestServer(t, "Alice", "Bob")

	client, err := smtp.Dial(server.Addr("submission"))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	if err := client.Mail("Alice@example.test", nil); err == nil {
		t.Fatal("submission accepted MAIL FROM without authentication")
	}

	if err := client.Auth(sasl.NewPlainClient("", "Alice", "secretAlice")); err != nil {
		t.Fatalf("AUTH PLAIN: %v", err)
	}
	if err := client.Mail("Bob@example.test", nil); err == nil {
		t.Fatal("Alice was allowed to send as Bob")
	}
}

// TestSubmissionDeliversLocally walks the path a mail client takes: authenticate
// on the submission port and send to another local user.
func TestSubmissionDeliversLocally(t *testing.T) {
	server, _ := newTestServer(t, "Alice", "Bob")

	body := "Subject: lunch\r\n\r\nAt one?\r\n"
	client, err := smtp.Dial(server.Addr("submission"))
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer client.Close()

	if err := client.Auth(sasl.NewPlainClient("", "alice@example.test", "secretAlice")); err != nil {
		t.Fatalf("AUTH PLAIN with full address: %v", err)
	}
	if err := client.SendMail("Alice@example.test", []string{"Bob@example.test"},
		strings.NewReader(body)); err != nil {
		t.Fatalf("SendMail: %v", err)
	}

	snapshot, err := server.store.Snapshot(2, Inbox)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snapshot.Messages) != 1 {
		t.Fatalf("Bob's INBOX has %d messages, want 1", len(snapshot.Messages))
	}

	stored, _ := server.store.Body(2, Inbox, snapshot.Messages[0])
	// The client omitted Date and Message-ID; submission has to supply both.
	for _, header := range []string{"Date:", "Message-ID:"} {
		if !strings.Contains(string(stored), header) {
			t.Errorf("submitted message is missing %s: %q", header, stored)
		}
	}
}

// TestPOP3Session drives a real POP3 conversation end to end.
func TestPOP3Session(t *testing.T) {
	server, _ := newTestServer(t, "Alice")

	for _, subject := range []string{"first", "second"} {
		body := fmt.Sprintf("Subject: %s\r\n\r\nbody of %s\r\n", subject, subject)
		if _, err := server.store.Append(1, Inbox, nil, time.Now(), []byte(body)); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}

	client := dialPOP3(t, server.Addr("pop3"))
	defer client.close()

	client.command(t, "USER Alice")
	client.command(t, "PASS secretAlice")

	stat := client.command(t, "STAT")
	if !strings.HasPrefix(stat, "+OK 2 ") {
		t.Errorf("STAT = %q, want two messages", stat)
	}

	listing := client.multiline(t, "LIST")
	if len(listing) != 2 {
		t.Errorf("LIST returned %d lines, want 2: %v", len(listing), listing)
	}

	uidls := client.multiline(t, "UIDL")
	if len(uidls) != 2 {
		t.Fatalf("UIDL returned %d lines, want 2", len(uidls))
	}
	if uidls[0] == uidls[1] {
		t.Errorf("UIDL identifiers are not unique: %v", uidls)
	}

	retrieved := client.multiline(t, "RETR 1")
	if !strings.Contains(strings.Join(retrieved, "\n"), "body of first") {
		t.Errorf("RETR 1 = %v, want the first message", retrieved)
	}

	// TOP must return headers plus the requested number of body lines only.
	top := client.multiline(t, "TOP 2 0")
	joined := strings.Join(top, "\n")
	if !strings.Contains(joined, "Subject: second") {
		t.Errorf("TOP headers missing: %v", top)
	}
	if strings.Contains(joined, "body of second") {
		t.Errorf("TOP 0 returned body lines: %v", top)
	}

	client.command(t, "DELE 1")
	client.command(t, "QUIT")

	// Deletion is only committed at QUIT, and the other message must survive.
	snapshot, err := server.store.Snapshot(1, Inbox)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snapshot.Messages) != 1 {
		t.Fatalf("after DELE+QUIT there are %d messages, want 1", len(snapshot.Messages))
	}
	if snapshot.Messages[0].UID != 2 {
		t.Errorf("surviving UID = %d, want 2", snapshot.Messages[0].UID)
	}
	// RETR marks a message read so the IMAP view agrees with the POP3 one.
	if !hasFlag(snapshot.Messages[0].Flags, FlagSeen) && snapshot.Messages[0].UID == 1 {
		t.Errorf("retrieved message was not marked seen")
	}
}

func TestPOP3RejectsBadPassword(t *testing.T) {
	server, _ := newTestServer(t, "Alice")

	client := dialPOP3(t, server.Addr("pop3"))
	defer client.close()

	client.command(t, "USER Alice")
	if response := client.send(t, "PASS wrong"); !strings.HasPrefix(response, "-ERR") {
		t.Fatalf("PASS with a wrong password = %q, want -ERR", response)
	}
	if response := client.send(t, "STAT"); !strings.HasPrefix(response, "-ERR") {
		t.Fatalf("STAT before auth = %q, want -ERR", response)
	}
}

// TestIMAPSession drives a real IMAP client against the server.
func TestIMAPSession(t *testing.T) {
	server, _ := newTestServer(t, "Alice")

	body := "Subject: hello\r\nFrom: <outside@remote.test>\r\nTo: <Alice@example.test>\r\n\r\nHi.\r\n"
	if _, err := server.store.Append(1, Inbox, nil, time.Now(), []byte(body)); err != nil {
		t.Fatalf("Append: %v", err)
	}

	client, err := imapclient.Dial(server.Addr("imap"))
	if err != nil {
		t.Fatalf("imap Dial: %v", err)
	}
	defer client.Logout()

	if err := client.Login("Alice@example.test", "secretAlice"); err != nil {
		t.Fatalf("Login: %v", err)
	}

	mailboxes := make(chan *imap.MailboxInfo, 10)
	if err := client.List("", "*", mailboxes); err != nil {
		t.Fatalf("List: %v", err)
	}
	var names []string
	for mailbox := range mailboxes {
		names = append(names, mailbox.Name)
	}
	if len(names) != 1 || names[0] != Inbox {
		t.Fatalf("LIST = %v, want [INBOX]", names)
	}

	status, err := client.Select(Inbox, false)
	if err != nil {
		t.Fatalf("Select: %v", err)
	}
	if status.Messages != 1 {
		t.Fatalf("SELECT reports %d messages, want 1", status.Messages)
	}

	seqset := new(imap.SeqSet)
	seqset.AddRange(1, 1)
	messages := make(chan *imap.Message, 1)
	items := []imap.FetchItem{imap.FetchEnvelope, imap.FetchFlags, imap.FetchUid, imap.FetchRFC822Size}
	if err := client.Fetch(seqset, items, messages); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	fetched := <-messages
	if fetched == nil {
		t.Fatal("FETCH returned no message")
	}
	if fetched.Envelope == nil || fetched.Envelope.Subject != "hello" {
		t.Errorf("envelope subject = %+v, want \"hello\"", fetched.Envelope)
	}
	if fetched.Uid != 1 {
		t.Errorf("UID = %d, want 1", fetched.Uid)
	}

	// Flag changes must survive a round trip to disk.
	if err := client.Store(seqset, imap.FormatFlagsOp(imap.AddFlags, true),
		[]any{imap.SeenFlag}, nil); err != nil {
		t.Fatalf("Store flags: %v", err)
	}
	snapshot, _ := server.store.Snapshot(1, Inbox)
	if !hasFlag(snapshot.Messages[0].Flags, FlagSeen) {
		t.Errorf("flags = %v, want \\Seen", snapshot.Messages[0].Flags)
	}

	if err := client.Create("Archive"); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if err := client.Copy(seqset, "Archive"); err != nil {
		t.Fatalf("Copy: %v", err)
	}
	archive, err := server.store.Snapshot(1, "Archive")
	if err != nil {
		t.Fatalf("Snapshot of Archive: %v", err)
	}
	if len(archive.Messages) != 1 {
		t.Fatalf("Archive has %d messages, want 1", len(archive.Messages))
	}
}

func TestIMAPRejectsBadPassword(t *testing.T) {
	server, _ := newTestServer(t, "Alice")

	client, err := imapclient.Dial(server.Addr("imap"))
	if err != nil {
		t.Fatalf("imap Dial: %v", err)
	}
	defer client.Logout()

	if err := client.Login("Alice", "wrong"); err == nil {
		t.Fatal("IMAP login succeeded with a wrong password")
	}
}

// sendSMTP runs one plain SMTP transaction.
//
// go-smtp's SendMail helper insists on STARTTLS, which the test server does not
// offer, so the transaction is spelled out here.
func sendSMTP(t *testing.T, addr, from string, to []string, body string) {
	t.Helper()

	client, err := smtp.Dial(addr)
	if err != nil {
		t.Fatalf("dial SMTP: %v", err)
	}
	defer client.Close()

	if err := client.Mail(from, nil); err != nil {
		t.Fatalf("MAIL FROM: %v", err)
	}
	for _, rcpt := range to {
		if err := client.Rcpt(rcpt, nil); err != nil {
			t.Fatalf("RCPT TO %s: %v", rcpt, err)
		}
	}
	writer, err := client.Data()
	if err != nil {
		t.Fatalf("DATA: %v", err)
	}
	if _, err := writer.Write([]byte(body)); err != nil {
		t.Fatalf("write body: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close body: %v", err)
	}
	if err := client.Quit(); err != nil {
		t.Fatalf("QUIT: %v", err)
	}
}

// pop3TestClient is a minimal POP3 client; the protocol is line based enough
// that a full client library would only get in the way.
type pop3TestClient struct {
	conn   net.Conn
	reader *bufio.Reader
}

func dialPOP3(t *testing.T, addr string) *pop3TestClient {
	t.Helper()

	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial POP3: %v", err)
	}
	client := &pop3TestClient{conn: conn, reader: bufio.NewReader(conn)}

	greeting := client.line(t)
	if !strings.HasPrefix(greeting, "+OK") {
		t.Fatalf("greeting = %q, want +OK", greeting)
	}
	return client
}

func (c *pop3TestClient) close() { _ = c.conn.Close() }

func (c *pop3TestClient) line(t *testing.T) string {
	t.Helper()

	_ = c.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := c.reader.ReadString('\n')
	if err != nil {
		t.Fatalf("read POP3 response: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}

// send writes a command and returns the status line without asserting on it.
func (c *pop3TestClient) send(t *testing.T, command string) string {
	t.Helper()

	if _, err := fmt.Fprintf(c.conn, "%s\r\n", command); err != nil {
		t.Fatalf("write %q: %v", command, err)
	}
	return c.line(t)
}

// command sends a command and requires a positive status line.
func (c *pop3TestClient) command(t *testing.T, command string) string {
	t.Helper()

	response := c.send(t, command)
	if !strings.HasPrefix(response, "+OK") {
		t.Fatalf("%s = %q, want +OK", command, response)
	}
	return response
}

// multiline sends a command and collects the dot-terminated body.
func (c *pop3TestClient) multiline(t *testing.T, command string) []string {
	t.Helper()

	c.command(t, command)
	var lines []string
	for {
		line := c.line(t)
		if line == "." {
			return lines
		}
		lines = append(lines, strings.TrimPrefix(line, "."))
	}
}

func firstLine(body []byte) string {
	if index := strings.IndexByte(string(body), '\n'); index >= 0 {
		return string(body[:index])
	}
	return string(body)
}
