package auth

import (
	"path/filepath"
	"strconv"
	"strings"
)

// Account is the read-only view of a stored user that other packages need.
// The mail server has to authenticate logins and resolve local recipients
// without reaching into the on-disk layout itself, but `user` stays unexported
// so password hashes and TOTP secrets cannot leak out of this package.
type Account struct {
	ID    string
	UID   int
	Email string
}

// Address returns the mailbox address this account owns on domain.
// The local part is the user ID, so it is already restricted to the characters
// allowed by idPattern and never needs quoting.
func (a Account) Address(domain string) string {
	return a.ID + "@" + domain
}

func accountOf(u user) Account {
	return Account{ID: u.ID, UID: u.UID, Email: u.Email}
}

// Authenticate reports the account matching query (user ID or registration
// e-mail address) when password is correct. It is the credential check behind
// SMTP AUTH, POP3 USER/PASS and IMAP LOGIN.
//
// Callers must not hold UserStore.mu: verifyPassword takes it.
func (s *UserStore) Authenticate(query, password string) (Account, bool) {
	target, ok := s.verifyPassword(query, password)
	if !ok {
		return Account{}, false
	}
	return accountOf(*target), true
}

// FindByID resolves a user ID to an account without checking a password. It is
// used to decide whether an SMTP recipient is local.
//
// register only rejects an exact ID collision, so "Bob" and "bob" can both
// exist. SMTP local parts are case-insensitive in practice, so an exact match
// wins first and a case-insensitive match is only accepted when it is unique;
// an ambiguous ID resolves to nothing and the recipient is rejected rather than
// delivered to the wrong person.
func (s *UserStore) FindByID(id string) (Account, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	users, err := s.loadUsers()
	if err != nil {
		return Account{}, false
	}
	for _, existing := range users {
		if existing.ID == id {
			return accountOf(existing), true
		}
	}

	var folded Account
	matches := 0
	for _, existing := range users {
		if strings.EqualFold(existing.ID, id) {
			folded = accountOf(existing)
			matches++
		}
	}
	if matches == 1 {
		return folded, true
	}
	return Account{}, false
}

// UserDir returns the directory holding one user's data. Mail storage lives
// beside user.json so a user and their mailboxes stay in a single tree.
func (s *UserStore) UserDir(uid int) string {
	return filepath.Join(s.root, strconv.Itoa(uid))
}
