package auth

import (
	"encoding/json"
	"errors"
	"net/mail"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"Astraccounts/logger"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

var (
	idPattern  = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
	pwdPattern = regexp.MustCompile(`^[A-Za-z0-9_!@#$%^&*]+$`)
)

type user struct {
	ID            string         `json:"id"`
	Email         string         `json:"email"`
	Password      string         `json:"password"`
	UID           int            `json:"UID"`
	Profile       map[string]any `json:"profile"`
	TOTPSecret    string         `json:"totp_secret,omitempty"`
	TOTPVerified  bool           `json:"totp_verified,omitempty"`
	RecoveryCodes []string       `json:"recovery_codes,omitempty"`
}

// UserStore persists users as data/user/[UID]/user.json files.
type UserStore struct {
	root string
	mu   sync.Mutex
}

// NewUserStore creates a store rooted at the given directory.
func NewUserStore(root string) *UserStore {
	return &UserStore{root: root}
}

type registerRequest struct {
	Username string `json:"username"`
	ID       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

type loginRequest struct {
	Query    string `json:"query"`
	Password string `json:"password"`
}

func (s *UserStore) register(req registerRequest) (int, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	users, err := s.loadUsers()
	if err != nil {
		return 0, 0, err
	}
	for _, existing := range users {
		if existing.ID == req.ID {
			return 0, 2, nil
		}
		if strings.EqualFold(existing.Email, req.Email) {
			return 0, 3, nil
		}
	}

	uid := 1
	for _, existing := range users {
		if existing.UID >= uid {
			uid = existing.UID + 1
		}
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		return 0, 0, err
	}
	newUser := user{
		ID:       req.ID,
		Email:    req.Email,
		Password: string(hash),
		UID:      uid,
		// The server owns both built-in profile keys at registration time.
		Profile: map[string]any{
			ProfileKeyUsername: req.Username,
			ProfileKeyRegister: time.Now().Unix(),
		},
	}
	if err := s.writeUser(newUser); err != nil {
		return 0, 0, err
	}
	return uid, 0, nil
}

// login reports the matched user's ID when the credentials are correct.
func (s *UserStore) login(query, password string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	users, err := s.loadUsers()
	if err != nil {
		return "", false
	}
	for _, existing := range users {
		if (existing.ID == query || strings.EqualFold(existing.Email, query)) &&
			bcrypt.CompareHashAndPassword([]byte(existing.Password), []byte(password)) == nil {
			return existing.ID, true
		}
	}
	return "", false
}

// updateProfile merges updates into the profile of the given UID. The token
// must be valid and belong to that user.
func (s *UserStore) updateProfile(uid int, token string, issuer *TokenIssuer, updates map[string]any) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	target, found, err := s.readUser(uid)
	if err != nil {
		return err
	}
	if !found {
		return errProfileDenied
	}
	id, ok := issuer.Verify(token)
	if !ok || id != target.ID {
		return errProfileDenied
	}

	if len(updates) == 0 {
		return nil
	}
	if target.Profile == nil {
		target.Profile = make(map[string]any, len(updates))
	}
	for key, value := range updates {
		target.Profile[key] = value
	}
	return s.writeUser(target)
}

// userPath returns the on-disk location of a user record.
func (s *UserStore) userPath(uid int) string {
	return filepath.Join(s.root, strconv.Itoa(uid), "user.json")
}

// readUser loads a single user by UID. The second result is false when no such
// user exists.
func (s *UserStore) readUser(uid int) (user, bool, error) {
	if uid < 1 {
		return user{}, false, nil
	}
	data, err := os.ReadFile(s.userPath(uid))
	if errors.Is(err, os.ErrNotExist) {
		return user{}, false, nil
	}
	if err != nil {
		return user{}, false, err
	}
	var existing user
	if err := json.Unmarshal(data, &existing); err != nil {
		return user{}, false, err
	}
	return existing, true, nil
}

// writeUser stores a user record, creating its directory when needed.
func (s *UserStore) writeUser(u user) error {
	if err := os.MkdirAll(filepath.Dir(s.userPath(u.UID)), 0755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(u, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.userPath(u.UID), append(data, '\n'), 0600)
}

func (s *UserStore) loadUsers() ([]user, error) {
	entries, err := os.ReadDir(s.root)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	users := make([]user, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(s.root, entry.Name(), "user.json"))
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var existing user
		if err := json.Unmarshal(data, &existing); err != nil {
			return nil, err
		}
		users = append(users, existing)
	}
	return users, nil
}

// RegisterHandler handles POST /api/register.
//
// mailDomain is the domain the mail server accepts, or "" when mail is
// disabled. When set, the response also reports the mailbox the new account
// owns, which is the user ID at that domain.
func RegisterHandler(store *UserStore, mailDomain string) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req registerRequest
		if c.ShouldBindJSON(&req) != nil {
			c.JSON(400, gin.H{"status": 400, "err": 0})
			return
		}
		if errCode := validateRegister(req); errCode != 0 {
			c.JSON(400, gin.H{"status": 400, "err": errCode})
			return
		}
		uid, errCode, err := store.register(req)
		if err != nil {
			logger.Error("Failed to register user", "err", err)
			c.JSON(500, gin.H{"status": 500})
			return
		}
		if errCode != 0 {
			c.JSON(400, gin.H{"status": 400, "err": errCode})
			return
		}
		if mailDomain == "" {
			c.JSON(201, gin.H{"status": 201, "UID": uid})
			return
		}
		c.JSON(201, gin.H{"status": 201, "UID": uid, "mail": req.ID + "@" + mailDomain})
	}
}

// LoginHandler handles POST /api/login.
func LoginHandler(store *UserStore, issuer *TokenIssuer) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req loginRequest
		if c.ShouldBindJSON(&req) != nil || req.Query == "" || req.Password == "" {
			c.JSON(400, gin.H{"status": 400})
			return
		}
		id, ok := store.login(req.Query, req.Password)
		if !ok {
			c.JSON(400, gin.H{"status": 400})
			return
		}
		c.JSON(200, gin.H{"status": 200, "token": issuer.Issue(id)})
	}
}

func validateRegister(req registerRequest) int {
	if req.Username == "" || strings.ContainsAny(req.Username, "\r\n") {
		return 1
	}
	if !idPattern.MatchString(req.ID) {
		return 2
	}
	address, err := mail.ParseAddress(req.Email)
	if err != nil || address.Address != req.Email || !strings.Contains(req.Email, "@") {
		return 3
	}
	if !pwdPattern.MatchString(req.Password) {
		return 4
	}
	return 0
}
