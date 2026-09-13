package mail

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"time"

	"Astraccounts/auth"
	"Astraccounts/logger"

	"github.com/emersion/go-imap"
	"github.com/emersion/go-imap/backend"
	"github.com/emersion/go-imap/backend/backendutil"
	gomessage "github.com/emersion/go-message"
	"github.com/emersion/go-message/textproto"
)

// imapBackend adapts the on-disk Store to go-imap's backend interfaces.
type imapBackend struct {
	server *Server
}

func (b *imapBackend) Login(_ *imap.ConnInfo, username, password string) (backend.User, error) {
	account, ok := b.server.login(username, password)
	if !ok {
		logger.Warn("Mail auth failed", "proto", "imap", "user", username)
		return nil, backend.ErrInvalidCredentials
	}
	return &imapUser{server: b.server, account: account}, nil
}

// translateError maps store errors onto the ones go-imap turns into proper
// tagged NO responses.
func translateError(err error) error {
	switch {
	case errors.Is(err, ErrNoSuchMailbox):
		return backend.ErrNoSuchMailbox
	case errors.Is(err, ErrMailboxExists):
		return backend.ErrMailboxAlreadyExists
	default:
		return err
	}
}

type imapUser struct {
	server  *Server
	account auth.Account
}

// Username reports the full address, which is what clients display.
func (u *imapUser) Username() string {
	return u.account.Address(u.server.cfg.Domain)
}

func (u *imapUser) ListMailboxes(subscribed bool) ([]backend.Mailbox, error) {
	names, err := u.server.store.ListMailboxes(u.account.UID)
	if err != nil {
		return nil, err
	}

	mailboxes := make([]backend.Mailbox, 0, len(names))
	for _, name := range names {
		if subscribed {
			snapshot, err := u.server.store.Snapshot(u.account.UID, name)
			if err != nil || !snapshot.Subscribed {
				continue
			}
		}
		mailboxes = append(mailboxes, &imapMailbox{user: u, name: name})
	}
	return mailboxes, nil
}

func (u *imapUser) GetMailbox(name string) (backend.Mailbox, error) {
	if _, err := u.server.store.Snapshot(u.account.UID, name); err != nil {
		return nil, translateError(err)
	}
	return &imapMailbox{user: u, name: CanonicalMailbox(name)}, nil
}

func (u *imapUser) CreateMailbox(name string) error {
	return translateError(u.server.store.CreateMailbox(u.account.UID, name))
}

func (u *imapUser) DeleteMailbox(name string) error {
	return translateError(u.server.store.DeleteMailbox(u.account.UID, name))
}

func (u *imapUser) RenameMailbox(from, to string) error {
	return translateError(u.server.store.RenameMailbox(u.account.UID, from, to))
}

func (u *imapUser) Logout() error {
	return nil
}

type imapMailbox struct {
	user *imapUser
	name string
}

func (m *imapMailbox) Name() string {
	return m.name
}

func (m *imapMailbox) Info() (*imap.MailboxInfo, error) {
	return &imap.MailboxInfo{Delimiter: Delimiter, Name: m.name}, nil
}

func (m *imapMailbox) snapshot() (*Snapshot, error) {
	snapshot, err := m.user.server.store.Snapshot(m.user.account.UID, m.name)
	if err != nil {
		return nil, translateError(err)
	}
	return snapshot, nil
}

func (m *imapMailbox) Status(items []imap.StatusItem) (*imap.MailboxStatus, error) {
	snapshot, err := m.snapshot()
	if err != nil {
		return nil, err
	}

	status := imap.NewMailboxStatus(m.name, items)
	// Advertising the system flags as permanent lets clients file, flag and
	// delete mail; \* additionally allows arbitrary keywords.
	status.Flags = []string{FlagSeen, FlagAnswered, FlagFlagged, FlagDeleted, FlagDraft}
	status.PermanentFlags = append(append([]string(nil), status.Flags...), "\\*")
	status.UnseenSeqNum = unseenSeqNum(snapshot)

	for _, item := range items {
		switch item {
		case imap.StatusMessages:
			status.Messages = uint32(len(snapshot.Messages))
		case imap.StatusUidNext:
			status.UidNext = snapshot.UIDNext
		case imap.StatusUidValidity:
			status.UidValidity = snapshot.UIDValidity
		case imap.StatusRecent:
			// \Recent is not tracked: it would have to be reset per session and
			// no client depends on it.
			status.Recent = 0
		case imap.StatusUnseen:
			status.Unseen = snapshot.Unseen()
		}
	}
	return status, nil
}

func unseenSeqNum(snapshot *Snapshot) uint32 {
	for i, msg := range snapshot.Messages {
		if !hasFlag(msg.Flags, FlagSeen) {
			return uint32(i + 1)
		}
	}
	return 0
}

func (m *imapMailbox) SetSubscribed(subscribed bool) error {
	return translateError(m.user.server.store.SetSubscribed(m.user.account.UID, m.name, subscribed))
}

// Check has no housekeeping to do: every mutation is already flushed to disk.
func (m *imapMailbox) Check() error {
	return nil
}

func (m *imapMailbox) ListMessages(uid bool, seqSet *imap.SeqSet, items []imap.FetchItem, ch chan<- *imap.Message) error {
	defer close(ch)

	snapshot, err := m.snapshot()
	if err != nil {
		return err
	}

	for i, msg := range snapshot.Messages {
		seqNum := uint32(i + 1)
		if !seqSet.Contains(identifier(uid, seqNum, msg.UID)) {
			continue
		}

		fetched, err := m.fetch(msg, seqNum, items)
		if err != nil {
			logger.Error("Failed to fetch message",
				"err", err, "uid", m.user.account.UID, "mailbox", m.name, "msg", msg.UID)
			continue
		}
		ch <- fetched
	}
	return nil
}

// fetch builds one FETCH response. Bodies are read from disk per message, which
// keeps memory flat regardless of mailbox size.
func (m *imapMailbox) fetch(msg *Message, seqNum uint32, items []imap.FetchItem) (*imap.Message, error) {
	var body []byte
	load := func() ([]byte, error) {
		if body != nil {
			return body, nil
		}
		loaded, err := m.user.server.store.Body(m.user.account.UID, m.name, msg)
		if err != nil {
			return nil, err
		}
		body = loaded
		return body, nil
	}

	fetched := imap.NewMessage(seqNum, items)
	for _, item := range items {
		switch item {
		case imap.FetchFlags:
			fetched.Flags = msg.Flags
		case imap.FetchInternalDate:
			fetched.InternalDate = msg.Date
		case imap.FetchRFC822Size:
			fetched.Size = msg.Size
		case imap.FetchUid:
			fetched.Uid = msg.UID
		case imap.FetchEnvelope:
			raw, err := load()
			if err != nil {
				return nil, err
			}
			header, err := readHeader(raw)
			if err != nil {
				return nil, err
			}
			fetched.Envelope, _ = backendutil.FetchEnvelope(header)
		case imap.FetchBody, imap.FetchBodyStructure:
			raw, err := load()
			if err != nil {
				return nil, err
			}
			reader := bufio.NewReader(bytes.NewReader(raw))
			header, err := textproto.ReadHeader(reader)
			if err != nil {
				return nil, err
			}
			fetched.BodyStructure, _ = backendutil.FetchBodyStructure(header, reader, item == imap.FetchBodyStructure)
		default:
			section, err := imap.ParseBodySectionName(item)
			if err != nil {
				// Not a body section: nothing this server can answer.
				continue
			}
			raw, err := load()
			if err != nil {
				return nil, err
			}
			reader := bufio.NewReader(bytes.NewReader(raw))
			header, err := textproto.ReadHeader(reader)
			if err != nil {
				return nil, err
			}
			literal, err := backendutil.FetchBodySection(header, reader, section)
			if err != nil {
				// A request for a part that does not exist yields NIL, not an
				// error, per RFC 3501.
				continue
			}
			fetched.Body[section] = literal
		}
	}
	return fetched, nil
}

func (m *imapMailbox) SearchMessages(uid bool, criteria *imap.SearchCriteria) ([]uint32, error) {
	snapshot, err := m.snapshot()
	if err != nil {
		return nil, err
	}

	var ids []uint32
	for i, msg := range snapshot.Messages {
		seqNum := uint32(i + 1)

		raw, err := m.user.server.store.Body(m.user.account.UID, m.name, msg)
		if err != nil {
			continue
		}
		entity, err := gomessage.Read(bytes.NewReader(raw))
		if err != nil && entity == nil {
			continue
		}

		matched, err := backendutil.Match(entity, seqNum, msg.UID, msg.Date, msg.Flags, criteria)
		if err != nil || !matched {
			continue
		}
		ids = append(ids, identifier(uid, seqNum, msg.UID))
	}
	return ids, nil
}

func (m *imapMailbox) CreateMessage(flags []string, date time.Time, body imap.Literal) error {
	raw, err := io.ReadAll(body)
	if err != nil {
		return err
	}
	_, err = m.user.server.store.Append(m.user.account.UID, m.name, flags, date, normaliseLineEndings(raw))
	return translateError(err)
}

func (m *imapMailbox) UpdateMessagesFlags(uid bool, seqset *imap.SeqSet, operation imap.FlagsOp, flags []string) error {
	uids, err := m.resolve(uid, seqset)
	if err != nil {
		return err
	}

	var op FlagOp
	switch operation {
	case imap.SetFlags:
		op = FlagsSet
	case imap.AddFlags:
		op = FlagsAdd
	case imap.RemoveFlags:
		op = FlagsRemove
	default:
		return nil
	}
	return translateError(m.user.server.store.SetFlags(m.user.account.UID, m.name, uids, flags, op))
}

func (m *imapMailbox) CopyMessages(uid bool, seqset *imap.SeqSet, dest string) error {
	uids, err := m.resolve(uid, seqset)
	if err != nil {
		return err
	}
	return translateError(m.user.server.store.Copy(m.user.account.UID, m.name, dest, uids))
}

func (m *imapMailbox) Expunge() error {
	snapshot, err := m.snapshot()
	if err != nil {
		return err
	}
	doomed := snapshot.Deleted()
	if len(doomed) == 0 {
		return nil
	}
	return translateError(m.user.server.store.Remove(m.user.account.UID, m.name, doomed))
}

// resolve turns a sequence set into concrete UIDs.
func (m *imapMailbox) resolve(uid bool, seqset *imap.SeqSet) ([]uint32, error) {
	snapshot, err := m.snapshot()
	if err != nil {
		return nil, err
	}

	var uids []uint32
	for i, msg := range snapshot.Messages {
		seqNum := uint32(i + 1)
		if seqset.Contains(identifier(uid, seqNum, msg.UID)) {
			uids = append(uids, msg.UID)
		}
	}
	return uids, nil
}

func identifier(uid bool, seqNum, msgUID uint32) uint32 {
	if uid {
		return msgUID
	}
	return seqNum
}
