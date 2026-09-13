package mail

import (
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"Astraccounts/auth"
)

// fakeAccounts is an in-memory account source. The real store hashes with
// bcrypt, which would dominate the runtime of these tests for no benefit.
type fakeAccounts struct {
	root      string
	passwords map[string]string
	accounts  map[string]auth.Account
}

func newFakeAccounts(root string, ids ...string) *fakeAccounts {
	accounts := &fakeAccounts{
		root:      root,
		passwords: make(map[string]string),
		accounts:  make(map[string]auth.Account),
	}
	for i, id := range ids {
		accounts.accounts[strings.ToLower(id)] = auth.Account{
			ID:    id,
			UID:   i + 1,
			Email: id + "@external.example",
		}
		accounts.passwords[strings.ToLower(id)] = "secret" + id
	}
	return accounts
}

func (f *fakeAccounts) Authenticate(query, password string) (auth.Account, bool) {
	key := strings.ToLower(query)
	account, ok := f.accounts[key]
	if !ok || f.passwords[key] != password {
		return auth.Account{}, false
	}
	return account, true
}

func (f *fakeAccounts) FindByID(id string) (auth.Account, bool) {
	account, ok := f.accounts[strings.ToLower(id)]
	return account, ok
}

func (f *fakeAccounts) UserDir(uid int) string {
	return filepath.Join(f.root, strconv.Itoa(uid))
}

func TestSplitAddress(t *testing.T) {
	cases := []struct {
		in     string
		local  string
		domain string
		ok     bool
	}{
		{"alice@example.com", "alice", "example.com", true},
		{"<alice@Example.COM>", "alice", "example.com", true},
		{"Alice@example.com", "Alice", "example.com", true},
		{"a@b@example.com", "a@b", "example.com", true},
		{"alice", "", "", false},
		{"@example.com", "", "", false},
		{"alice@", "", "", false},
		{"ali ce@example.com", "", "", false},
	}

	for _, tc := range cases {
		local, domain, ok := SplitAddress(tc.in)
		if ok != tc.ok || local != tc.local || domain != tc.domain {
			t.Errorf("SplitAddress(%q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.in, local, domain, ok, tc.local, tc.domain, tc.ok)
		}
	}
}

// TestInboxExistsWithoutDelivery covers the promise that registering is enough
// to have a working mailbox: nothing is written to disk until the first
// message, but INBOX must still be listable and selectable.
func TestInboxExistsWithoutDelivery(t *testing.T) {
	accounts := newFakeAccounts(t.TempDir(), "Alice")
	store := NewStore(accounts)

	names, err := store.ListMailboxes(1)
	if err != nil {
		t.Fatalf("ListMailboxes: %v", err)
	}
	if len(names) != 1 || names[0] != Inbox {
		t.Fatalf("mailboxes = %v, want [INBOX]", names)
	}

	snapshot, err := store.Snapshot(1, "inbox")
	if err != nil {
		t.Fatalf("Snapshot of lowercase inbox: %v", err)
	}
	if len(snapshot.Messages) != 0 {
		t.Fatalf("new INBOX has %d messages, want 0", len(snapshot.Messages))
	}
	if snapshot.UIDNext != 1 {
		t.Fatalf("UIDNext = %d, want 1", snapshot.UIDNext)
	}
}

func TestAppendAssignsIncreasingUIDs(t *testing.T) {
	accounts := newFakeAccounts(t.TempDir(), "Alice")
	store := NewStore(accounts)

	first, err := store.Append(1, Inbox, nil, time.Now(), []byte("Subject: one\r\n\r\nbody"))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	second, err := store.Append(1, Inbox, []string{FlagSeen}, time.Now(), []byte("Subject: two\r\n\r\nbody"))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if first != 1 || second != 2 {
		t.Fatalf("UIDs = %d, %d; want 1, 2", first, second)
	}

	snapshot, err := store.Snapshot(1, Inbox)
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snapshot.Messages) != 2 {
		t.Fatalf("message count = %d, want 2", len(snapshot.Messages))
	}
	if snapshot.Unseen() != 1 {
		t.Fatalf("unseen = %d, want 1", snapshot.Unseen())
	}

	body, err := store.Body(1, Inbox, snapshot.Messages[0])
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	if !strings.Contains(string(body), "Subject: one") {
		t.Fatalf("body = %q, want the first message", body)
	}
}

// TestUIDsSurviveExpunge guards the IMAP rule that UIDs are never reused: a
// client that reconnects after an expunge must not see an old UID point at a
// different message.
func TestUIDsSurviveExpunge(t *testing.T) {
	accounts := newFakeAccounts(t.TempDir(), "Alice")
	store := NewStore(accounts)

	for i := 0; i < 3; i++ {
		if _, err := store.Append(1, Inbox, nil, time.Now(), []byte("body")); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	if err := store.SetFlags(1, Inbox, []uint32{2}, []string{FlagDeleted}, FlagsAdd); err != nil {
		t.Fatalf("SetFlags: %v", err)
	}

	snapshot, _ := store.Snapshot(1, Inbox)
	deleted := snapshot.Deleted()
	if len(deleted) != 1 || deleted[0] != 2 {
		t.Fatalf("deleted = %v, want [2]", deleted)
	}
	if err := store.Remove(1, Inbox, deleted); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	next, err := store.Append(1, Inbox, nil, time.Now(), []byte("body"))
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if next != 4 {
		t.Fatalf("UID after expunge = %d, want 4", next)
	}

	snapshot, _ = store.Snapshot(1, Inbox)
	var uids []uint32
	for _, msg := range snapshot.Messages {
		uids = append(uids, msg.UID)
	}
	if len(uids) != 3 || uids[0] != 1 || uids[1] != 3 || uids[2] != 4 {
		t.Fatalf("UIDs = %v, want [1 3 4]", uids)
	}
}

func TestMailboxLifecycle(t *testing.T) {
	accounts := newFakeAccounts(t.TempDir(), "Alice")
	store := NewStore(accounts)

	if err := store.CreateMailbox(1, "Archive"); err != nil {
		t.Fatalf("CreateMailbox: %v", err)
	}
	if err := store.CreateMailbox(1, "Archive"); err != ErrMailboxExists {
		t.Fatalf("duplicate CreateMailbox = %v, want ErrMailboxExists", err)
	}
	if err := store.CreateMailbox(1, "INBOX"); err != ErrMailboxExists {
		t.Fatalf("CreateMailbox(INBOX) = %v, want ErrMailboxExists", err)
	}
	if err := store.DeleteMailbox(1, Inbox); err != ErrMailboxForbidden {
		t.Fatalf("DeleteMailbox(INBOX) = %v, want ErrMailboxForbidden", err)
	}

	// A name with the hierarchy delimiter has to survive the round trip through
	// the filesystem encoding.
	if err := store.CreateMailbox(1, "Work/2026 Q1"); err != nil {
		t.Fatalf("CreateMailbox nested: %v", err)
	}
	names, err := store.ListMailboxes(1)
	if err != nil {
		t.Fatalf("ListMailboxes: %v", err)
	}
	if len(names) != 3 || names[0] != Inbox {
		t.Fatalf("mailboxes = %v, want INBOX plus two", names)
	}
	var found bool
	for _, name := range names {
		if name == "Work/2026 Q1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("mailboxes = %v, want to contain %q", names, "Work/2026 Q1")
	}

	if err := store.RenameMailbox(1, "Archive", "Old"); err != nil {
		t.Fatalf("RenameMailbox: %v", err)
	}
	if _, err := store.Snapshot(1, "Archive"); err != ErrNoSuchMailbox {
		t.Fatalf("Snapshot of renamed mailbox = %v, want ErrNoSuchMailbox", err)
	}
	if _, err := store.Snapshot(1, "Old"); err != nil {
		t.Fatalf("Snapshot of new name: %v", err)
	}

	if err := store.DeleteMailbox(1, "Old"); err != nil {
		t.Fatalf("DeleteMailbox: %v", err)
	}
	if _, err := store.Snapshot(1, "Old"); err != ErrNoSuchMailbox {
		t.Fatalf("Snapshot after delete = %v, want ErrNoSuchMailbox", err)
	}
}

func TestCopyPreservesFlagsAndBody(t *testing.T) {
	accounts := newFakeAccounts(t.TempDir(), "Alice")
	store := NewStore(accounts)

	if _, err := store.Append(1, Inbox, []string{FlagSeen}, time.Now(), []byte("hello")); err != nil {
		t.Fatalf("Append: %v", err)
	}
	if err := store.CreateMailbox(1, "Archive"); err != nil {
		t.Fatalf("CreateMailbox: %v", err)
	}
	if err := store.Copy(1, Inbox, "Archive", []uint32{1}); err != nil {
		t.Fatalf("Copy: %v", err)
	}

	snapshot, err := store.Snapshot(1, "Archive")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	if len(snapshot.Messages) != 1 {
		t.Fatalf("copied count = %d, want 1", len(snapshot.Messages))
	}
	if !hasFlag(snapshot.Messages[0].Flags, FlagSeen) {
		t.Fatalf("flags = %v, want \\Seen preserved", snapshot.Messages[0].Flags)
	}

	body, err := store.Body(1, "Archive", snapshot.Messages[0])
	if err != nil {
		t.Fatalf("Body: %v", err)
	}
	if string(body) != "hello" {
		t.Fatalf("body = %q, want %q", body, "hello")
	}

	// Copying must not disturb the source mailbox.
	source, _ := store.Snapshot(1, Inbox)
	if len(source.Messages) != 1 {
		t.Fatalf("source count = %d, want 1", len(source.Messages))
	}
}

func TestApplyFlags(t *testing.T) {
	current := []string{FlagSeen, FlagFlagged}

	if got := applyFlags(current, []string{FlagDeleted}, FlagsAdd); len(got) != 3 {
		t.Errorf("add = %v, want three flags", got)
	}
	if got := applyFlags(current, []string{FlagSeen}, FlagsRemove); len(got) != 1 || got[0] != FlagFlagged {
		t.Errorf("remove = %v, want [\\Flagged]", got)
	}
	if got := applyFlags(current, []string{FlagDraft}, FlagsSet); len(got) != 1 || got[0] != FlagDraft {
		t.Errorf("set = %v, want [\\Draft]", got)
	}
	if got := applyFlags(nil, []string{FlagSeen, FlagSeen}, FlagsAdd); len(got) != 1 {
		t.Errorf("duplicate add = %v, want one flag", got)
	}
	// \Recent is not tracked and must never be persisted.
	if got := applyFlags(nil, []string{"\\Recent", FlagSeen}, FlagsAdd); len(got) != 1 {
		t.Errorf("recent add = %v, want \\Recent dropped", got)
	}
}

func TestNormaliseLineEndings(t *testing.T) {
	got := normaliseLineEndings([]byte("a\nb\r\nc\n"))
	if string(got) != "a\r\nb\r\nc\r\n" {
		t.Fatalf("got %q, want CRLF throughout without doubling", got)
	}
}
