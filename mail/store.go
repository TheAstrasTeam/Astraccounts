package mail

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"Astraccounts/auth"
)

// Inbox is the mailbox every account always has. IMAP requires the name to be
// case-insensitive, so it is normalised to this spelling on the way in.
const Inbox = "INBOX"

// Delimiter is the IMAP hierarchy separator reported to clients.
const Delimiter = "/"

var (
	// ErrNoSuchMailbox is returned when a mailbox does not exist.
	ErrNoSuchMailbox = errors.New("no such mailbox")
	// ErrMailboxExists is returned when creating a mailbox that is already there.
	ErrMailboxExists = errors.New("mailbox already exists")
	// ErrMailboxForbidden is returned for operations INBOX does not allow.
	ErrMailboxForbidden = errors.New("mailbox cannot be deleted or renamed")
)

// Accounts is the slice of the user store the mail server depends on. It is an
// interface so the mail tests do not have to pay for bcrypt.
type Accounts interface {
	Authenticate(query, password string) (auth.Account, bool)
	FindByID(id string) (auth.Account, bool)
	UserDir(uid int) string
}

// Message is one stored message as recorded in a mailbox index. The body lives
// in its own file and is immutable once written, so only this record is ever
// rewritten.
type Message struct {
	UID   uint32    `json:"uid"`
	File  string    `json:"file"`
	Size  uint32    `json:"size"`
	Date  time.Time `json:"date"`
	Flags []string  `json:"flags"`
}

// mailboxIndex is the whole content of a mailbox's index.json.
type mailboxIndex struct {
	UIDValidity uint32     `json:"uidvalidity"`
	UIDNext     uint32     `json:"uidnext"`
	Subscribed  bool       `json:"subscribed"`
	Messages    []*Message `json:"messages"`
}

// Store is the on-disk gateway for all mail data, mirroring the role
// auth.UserStore plays for user records. Every mailbox mutation is serialised
// through mu: mail arrives from the SMTP listeners while IMAP and POP3 sessions
// are reading, and each change rewrites a whole index.json.
type Store struct {
	accounts Accounts
	mu       sync.Mutex
}

// NewStore creates a store that reads and writes under each account's user
// directory.
func NewStore(accounts Accounts) *Store {
	return &Store{accounts: accounts}
}

// CanonicalMailbox normalises a mailbox name: INBOX in any casing is the same
// mailbox, everything else keeps the client's spelling.
func CanonicalMailbox(name string) string {
	name = strings.Trim(name, Delimiter)
	if strings.EqualFold(name, Inbox) {
		return Inbox
	}
	return name
}

// encodeMailboxName maps an IMAP mailbox name to a single directory name.
//
// Mailbox names may contain the hierarchy delimiter and arbitrary UTF-7, none
// of which is safe to hand to the filesystem, so anything outside a small safe
// set is percent-encoded. Names are kept readable on purpose: INBOX stays
// "INBOX" on disk.
func encodeMailboxName(name string) string {
	var b strings.Builder
	for _, r := range name {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9',
			r == '.', r == '-', r == '_':
			b.WriteRune(r)
		default:
			b.WriteString(fmt.Sprintf("%%%02X", r))
		}
	}
	return b.String()
}

func decodeMailboxName(dir string) string {
	var b strings.Builder
	for i := 0; i < len(dir); i++ {
		if dir[i] == '%' && i+2 < len(dir) {
			var r rune
			if _, err := fmt.Sscanf(dir[i+1:i+3], "%02X", &r); err == nil {
				b.WriteRune(r)
				i += 2
				continue
			}
		}
		b.WriteByte(dir[i])
	}
	return b.String()
}

func (s *Store) mailRoot(uid int) string {
	return filepath.Join(s.accounts.UserDir(uid), "mail")
}

func (s *Store) mailboxDir(uid int, name string) string {
	return filepath.Join(s.mailRoot(uid), encodeMailboxName(CanonicalMailbox(name)))
}

func (s *Store) indexPath(uid int, name string) string {
	return filepath.Join(s.mailboxDir(uid, name), "index.json")
}

// readIndex loads a mailbox index. INBOX is materialised on demand so a freshly
// registered account can be opened by a client before any mail has arrived.
func (s *Store) readIndex(uid int, name string) (*mailboxIndex, error) {
	name = CanonicalMailbox(name)
	data, err := os.ReadFile(s.indexPath(uid, name))
	if errors.Is(err, os.ErrNotExist) {
		if name != Inbox {
			return nil, ErrNoSuchMailbox
		}
		return newMailboxIndex(), nil
	}
	if err != nil {
		return nil, err
	}

	var index mailboxIndex
	if err := json.Unmarshal(data, &index); err != nil {
		return nil, err
	}
	if index.UIDValidity == 0 {
		index.UIDValidity = uidValidity()
	}
	if index.UIDNext == 0 {
		index.UIDNext = 1
	}
	return &index, nil
}

func newMailboxIndex() *mailboxIndex {
	return &mailboxIndex{
		UIDValidity: uidValidity(),
		UIDNext:     1,
		Subscribed:  true,
		Messages:    []*Message{},
	}
}

// uidValidity returns a value that must change whenever UIDs are reused, and
// must not change otherwise. The creation time satisfies both.
func uidValidity() uint32 {
	return uint32(time.Now().Unix())
}

func (s *Store) writeIndex(uid int, name string, index *mailboxIndex) error {
	dir := s.mailboxDir(uid, name)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(index, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "index.json"), append(data, '\n'), 0600)
}

// ListMailboxes returns every mailbox of an account, INBOX first. INBOX is
// always present even when nothing has been written to disk yet.
func (s *Store) ListMailboxes(uid int) ([]string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	entries, err := os.ReadDir(s.mailRoot(uid))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	names := []string{Inbox}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := decodeMailboxName(entry.Name())
		if CanonicalMailbox(name) == Inbox {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names[1:])
	return names, nil
}

// CreateMailbox creates an empty mailbox, including any missing parents.
func (s *Store) CreateMailbox(uid int, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	name = CanonicalMailbox(name)
	if name == "" {
		return ErrNoSuchMailbox
	}
	if _, err := os.Stat(s.indexPath(uid, name)); err == nil {
		return ErrMailboxExists
	}
	if name == Inbox {
		return ErrMailboxExists
	}
	return s.writeIndex(uid, name, newMailboxIndex())
}

// DeleteMailbox removes a mailbox and its messages. INBOX cannot be deleted.
func (s *Store) DeleteMailbox(uid int, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	name = CanonicalMailbox(name)
	if name == Inbox {
		return ErrMailboxForbidden
	}
	if _, err := os.Stat(s.indexPath(uid, name)); err != nil {
		return ErrNoSuchMailbox
	}
	return os.RemoveAll(s.mailboxDir(uid, name))
}

// RenameMailbox moves a mailbox. Renaming INBOX would have to move its messages
// and leave INBOX in place, which no client here needs, so it is refused.
func (s *Store) RenameMailbox(uid int, from, to string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	from, to = CanonicalMailbox(from), CanonicalMailbox(to)
	if from == Inbox || to == Inbox {
		return ErrMailboxForbidden
	}
	if _, err := os.Stat(s.indexPath(uid, from)); err != nil {
		return ErrNoSuchMailbox
	}
	if _, err := os.Stat(s.indexPath(uid, to)); err == nil {
		return ErrMailboxExists
	}
	if err := os.MkdirAll(filepath.Dir(s.mailboxDir(uid, to)), 0700); err != nil {
		return err
	}
	return os.Rename(s.mailboxDir(uid, from), s.mailboxDir(uid, to))
}

// SetSubscribed records the IMAP subscription state of a mailbox.
func (s *Store) SetSubscribed(uid int, name string, subscribed bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, err := s.readIndex(uid, name)
	if err != nil {
		return err
	}
	index.Subscribed = subscribed
	return s.writeIndex(uid, name, index)
}

// Snapshot is a point-in-time view of a mailbox. POP3 sessions are defined in
// terms of one of these: message numbers are fixed for the whole session.
type Snapshot struct {
	Name        string
	UIDValidity uint32
	UIDNext     uint32
	Subscribed  bool
	Messages    []*Message
}

// Snapshot returns the current state of a mailbox.
func (s *Store) Snapshot(uid int, name string) (*Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, err := s.readIndex(uid, name)
	if err != nil {
		return nil, err
	}
	messages := make([]*Message, 0, len(index.Messages))
	for _, msg := range index.Messages {
		copied := *msg
		copied.Flags = append([]string(nil), msg.Flags...)
		messages = append(messages, &copied)
	}
	return &Snapshot{
		Name:        CanonicalMailbox(name),
		UIDValidity: index.UIDValidity,
		UIDNext:     index.UIDNext,
		Subscribed:  index.Subscribed,
		Messages:    messages,
	}, nil
}

// Append stores a message and returns its assigned UID. The mailbox is created
// when it does not exist yet, which is what makes delivery to a brand new
// account work.
func (s *Store) Append(uid int, name string, flags []string, date time.Time, body []byte) (uint32, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	name = CanonicalMailbox(name)
	index, err := s.readIndex(uid, name)
	if errors.Is(err, ErrNoSuchMailbox) {
		index = newMailboxIndex()
	} else if err != nil {
		return 0, err
	}

	if date.IsZero() {
		date = time.Now()
	}
	msgUID := index.UIDNext
	file := fmt.Sprintf("%08d.eml", msgUID)

	dir := s.mailboxDir(uid, name)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return 0, err
	}
	if err := os.WriteFile(filepath.Join(dir, file), body, 0600); err != nil {
		return 0, err
	}

	index.Messages = append(index.Messages, &Message{
		UID:   msgUID,
		File:  file,
		Size:  uint32(len(body)),
		Date:  date,
		Flags: normaliseFlags(flags),
	})
	index.UIDNext = msgUID + 1
	if err := s.writeIndex(uid, name, index); err != nil {
		return 0, err
	}
	return msgUID, nil
}

// Body reads a stored message body.
func (s *Store) Body(uid int, mailbox string, msg *Message) ([]byte, error) {
	return os.ReadFile(filepath.Join(s.mailboxDir(uid, mailbox), msg.File))
}

// SetFlags replaces, adds or removes flags on the given UIDs.
func (s *Store) SetFlags(uid int, name string, uids []uint32, flags []string, op FlagOp) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, err := s.readIndex(uid, name)
	if err != nil {
		return err
	}
	wanted := make(map[uint32]bool, len(uids))
	for _, u := range uids {
		wanted[u] = true
	}
	for _, msg := range index.Messages {
		if !wanted[msg.UID] {
			continue
		}
		msg.Flags = applyFlags(msg.Flags, flags, op)
	}
	return s.writeIndex(uid, name, index)
}

// Copy appends copies of the given UIDs to another mailbox, preserving flags
// and internal dates.
func (s *Store) Copy(uid int, from, to string, uids []uint32) error {
	source, err := s.Snapshot(uid, from)
	if err != nil {
		return err
	}

	s.mu.Lock()
	if _, err := s.readIndex(uid, to); err != nil {
		s.mu.Unlock()
		return err
	}
	s.mu.Unlock()

	wanted := make(map[uint32]bool, len(uids))
	for _, u := range uids {
		wanted[u] = true
	}
	for _, msg := range source.Messages {
		if !wanted[msg.UID] {
			continue
		}
		body, err := s.Body(uid, from, msg)
		if err != nil {
			return err
		}
		if _, err := s.Append(uid, to, msg.Flags, msg.Date, body); err != nil {
			return err
		}
	}
	return nil
}

// Remove deletes the given UIDs and their body files. It backs both IMAP
// EXPUNGE and the POP3 commit at QUIT.
func (s *Store) Remove(uid int, name string, uids []uint32) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	index, err := s.readIndex(uid, name)
	if err != nil {
		return err
	}
	doomed := make(map[uint32]bool, len(uids))
	for _, u := range uids {
		doomed[u] = true
	}

	kept := make([]*Message, 0, len(index.Messages))
	for _, msg := range index.Messages {
		if !doomed[msg.UID] {
			kept = append(kept, msg)
			continue
		}
		path := filepath.Join(s.mailboxDir(uid, name), msg.File)
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	index.Messages = kept
	return s.writeIndex(uid, name, index)
}

// Deleted returns the UIDs carrying the \Deleted flag.
func (snapshot *Snapshot) Deleted() []uint32 {
	var uids []uint32
	for _, msg := range snapshot.Messages {
		if hasFlag(msg.Flags, FlagDeleted) {
			uids = append(uids, msg.UID)
		}
	}
	return uids
}

// Unseen reports how many messages lack \Seen.
func (snapshot *Snapshot) Unseen() uint32 {
	var count uint32
	for _, msg := range snapshot.Messages {
		if !hasFlag(msg.Flags, FlagSeen) {
			count++
		}
	}
	return count
}

// TotalSize reports the summed RFC822 size of the mailbox, which POP3 STAT
// needs.
func (snapshot *Snapshot) TotalSize() uint64 {
	var total uint64
	for _, msg := range snapshot.Messages {
		total += uint64(msg.Size)
	}
	return total
}
