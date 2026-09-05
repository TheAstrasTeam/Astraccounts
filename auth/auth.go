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

	"Astraccounts/logger"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

var (
	idPattern  = regexp.MustCompile(`^[A-Za-z0-9_]+$`)
	pwdPattern = regexp.MustCompile(`^[A-Za-z0-9_!@#$%^&*]+$`)
)

type user struct {
	Username string `json:"username"`
	ID       string `json:"id"`
	Email    string `json:"email"`
	Password string `json:"password"`
	UID      int    `json:"UID"`
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
	newUser := user{Username: req.Username, ID: req.ID, Email: req.Email, Password: string(hash), UID: uid}
	if err := os.MkdirAll(filepath.Join(s.root, strconv.Itoa(uid)), 0755); err != nil {
		return 0, 0, err
	}
	data, err := json.MarshalIndent(newUser, "", "  ")
	if err != nil {
		return 0, 0, err
	}
	if err := os.WriteFile(filepath.Join(s.root, strconv.Itoa(uid), "user.json"), append(data, '\n'), 0600); err != nil {
		return 0, 0, err
	}
	return uid, 0, nil
}

func (s *UserStore) login(query, password string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	users, err := s.loadUsers()
	if err != nil {
		return false
	}
	for _, existing := range users {
		if (existing.ID == query || strings.EqualFold(existing.Email, query)) &&
			bcrypt.CompareHashAndPassword([]byte(existing.Password), []byte(password)) == nil {
			return true
		}
	}
	return false
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
func RegisterHandler(store *UserStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req registerRequest
		if c.ShouldBindJSON(&req) != nil {
			c.JSON(400, gin.H{"status": "400", "err": 0})
			return
		}
		if errCode := validateRegister(req); errCode != 0 {
			c.JSON(400, gin.H{"status": "400", "err": errCode})
			return
		}
		uid, errCode, err := store.register(req)
		if err != nil {
			logger.Error("Failed to register user", "err", err)
			c.JSON(500, gin.H{"status": "500"})
			return
		}
		if errCode != 0 {
			c.JSON(400, gin.H{"status": "400", "err": errCode})
			return
		}
		c.JSON(201, gin.H{"status": "201", "UID": uid})
	}
}

// LoginHandler handles POST /api/login.
func LoginHandler(store *UserStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req loginRequest
		if c.ShouldBindJSON(&req) != nil || req.Query == "" || req.Password == "" || !store.login(req.Query, req.Password) {
			c.JSON(400, gin.H{"status": 400})
			return
		}
		c.JSON(200, gin.H{"status": 200})
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
