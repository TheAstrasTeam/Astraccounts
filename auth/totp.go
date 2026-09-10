package auth

import (
	"crypto/rand"
	"encoding/base32"
	"strings"

	"Astraccounts/logger"

	"github.com/gin-gonic/gin"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// totpSignRequest matches /api/totp/sign request body
type totpSignRequest struct {
	Query    string `json:"query"`
	Password string `json:"password"`
}

// totpVerifyRequest matches /api/totp/verify request body
type totpVerifyRequest struct {
	Query    string `json:"query"`
	Password string `json:"password"`
	Code     string `json:"code"`
}

// totpUnsignRequest matches /api/totp/unsign request body
type totpUnsignRequest struct {
	Query    string `json:"query"`
	Password string `json:"password"`
}

// totpLoginRequest matches /api/login/totp request body
type totpLoginRequest struct {
	Query string `json:"query"`
	Code  string `json:"code"`
}

// recoveryCodeLoginRequest matches /api/login/recovery_code request body
type recoveryCodeLoginRequest struct {
	Query        string `json:"query"`
	RecoveryCode string `json:"recovery_code"`
}

// generateRecoveryCodes creates 10 recovery codes in XXXX-XXXX-XXXX-XXXX format.
func generateRecoveryCodes() ([]string, error) {
	codes := make([]string, 10)
	for i := 0; i < 10; i++ {
		bytes := make([]byte, 10)
		if _, err := rand.Read(bytes); err != nil {
			return nil, err
		}
		raw := strings.ToUpper(base32.StdEncoding.EncodeToString(bytes))[:16]
		codes[i] = raw[:4] + "-" + raw[4:8] + "-" + raw[8:12] + "-" + raw[12:]
	}
	return codes, nil
}

// verifyPassword checks credentials and returns the user if valid.
func (s *UserStore) verifyPassword(query, password string) (*user, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	users, err := s.loadUsers()
	if err != nil {
		return nil, false
	}
	for _, existing := range users {
		if (existing.ID == query || strings.EqualFold(existing.Email, query)) &&
			bcrypt.CompareHashAndPassword([]byte(existing.Password), []byte(password)) == nil {
			return &existing, true
		}
	}
	return nil, false
}

// TotpSignHandler handles POST /api/totp/sign
// Generates a TOTP secret and returns the otpauth:// URI.
// TOTP is NOT yet verified; the user must call /api/totp/verify with a valid
// code to activate it.
func TotpSignHandler(store *UserStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req totpSignRequest
		if c.ShouldBindJSON(&req) != nil || req.Query == "" || req.Password == "" {
			c.JSON(400, gin.H{"status": 400})
			return
		}

		target, ok := store.verifyPassword(req.Query, req.Password)
		if !ok {
			c.JSON(400, gin.H{"status": 400})
			return
		}

		// Reject if TOTP is already set up and verified
		if target.TOTPVerified {
			c.JSON(400, gin.H{"status": 400, "err": 1})
			return
		}

		// Allow re-generating a secret if previous sign was never verified
		// (user lost the QR code or timed out).
		key, err := totp.Generate(totp.GenerateOpts{
			Issuer:      "Astraccounts",
			AccountName: target.ID,
			Period:      30,
			Digits:      6,
			Algorithm:   otp.AlgorithmSHA1,
		})
		if err != nil {
			logger.Error("Failed to generate TOTP secret", "err", err)
			c.JSON(500, gin.H{"status": 500})
			return
		}

		// Save secret but NOT verified; clear any leftover recovery codes
		target.TOTPSecret = key.Secret()
		target.TOTPVerified = false
		target.RecoveryCodes = nil

		if err := store.writeUser(*target); err != nil {
			logger.Error("Failed to save TOTP secret", "err", err)
			c.JSON(500, gin.H{"status": 500})
			return
		}

		c.JSON(200, gin.H{
			"status":      200,
			"otpauth_url": key.String(),
		})
	}
}

// TotpVerifyHandler handles POST /api/totp/verify
// Verifies the first TOTP code. On success TOTP is marked as verified and
// recovery codes are returned. On failure TOTP is removed entirely so the
// user must start over from /api/totp/sign.
func TotpVerifyHandler(store *UserStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req totpVerifyRequest
		if c.ShouldBindJSON(&req) != nil || req.Query == "" || req.Password == "" || req.Code == "" {
			c.JSON(400, gin.H{"status": 400})
			return
		}

		target, ok := store.verifyPassword(req.Query, req.Password)
		if !ok {
			c.JSON(400, gin.H{"status": 400})
			return
		}

		if target.TOTPSecret == "" || target.TOTPVerified {
			c.JSON(400, gin.H{"status": 400})
			return
		}

		// Verify the TOTP code against the secret
		if !totp.Validate(req.Code, target.TOTPSecret) {
			// Code wrong → remove TOTP setup entirely, user must start over
			target.TOTPSecret = ""
			target.TOTPVerified = false
			target.RecoveryCodes = nil
			if err := store.writeUser(*target); err != nil {
				logger.Error("Failed to revert TOTP after failed verify", "err", err)
				c.JSON(500, gin.H{"status": 500})
				return
			}
			c.JSON(400, gin.H{"status": 400})
			return
		}

		// Code correct → mark as verified and generate recovery codes
		recoveryCodes, err := generateRecoveryCodes()
		if err != nil {
			logger.Error("Failed to generate recovery codes", "err", err)
			c.JSON(500, gin.H{"status": 500})
			return
		}

		target.TOTPVerified = true
		target.RecoveryCodes = recoveryCodes

		if err := store.writeUser(*target); err != nil {
			logger.Error("Failed to save verified TOTP", "err", err)
			c.JSON(500, gin.H{"status": 500})
			return
		}

		c.JSON(200, gin.H{
			"status":         200,
			"recovery_codes": recoveryCodes,
		})
	}
}

// TotpUnsignHandler handles POST /api/totp/unsign
func TotpUnsignHandler(store *UserStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req totpUnsignRequest
		if c.ShouldBindJSON(&req) != nil || req.Query == "" || req.Password == "" {
			c.JSON(400, gin.H{"status": 400})
			return
		}

		target, ok := store.verifyPassword(req.Query, req.Password)
		if !ok {
			c.JSON(400, gin.H{"status": 400})
			return
		}

		if target.TOTPSecret == "" {
			c.JSON(400, gin.H{"status": 400, "err": 2})
			return
		}

		target.TOTPSecret = ""
		target.TOTPVerified = false
		target.RecoveryCodes = nil

		if err := store.writeUser(*target); err != nil {
			logger.Error("Failed to remove TOTP", "err", err)
			c.JSON(500, gin.H{"status": 500})
			return
		}

		c.JSON(200, gin.H{"status": 200})
	}
}

// TotpLoginHandler handles POST /api/login/totp
func TotpLoginHandler(store *UserStore, issuer *TokenIssuer) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req totpLoginRequest
		if c.ShouldBindJSON(&req) != nil || req.Query == "" || req.Code == "" {
			c.JSON(400, gin.H{"status": 400})
			return
		}

		store.mu.Lock()
		users, err := store.loadUsers()
		if err != nil {
			store.mu.Unlock()
			c.JSON(500, gin.H{"status": 500})
			return
		}
		store.mu.Unlock()

		var target *user
		for _, existing := range users {
			if existing.ID == req.Query || strings.EqualFold(existing.Email, req.Query) {
				target = &existing
				break
			}
		}

		// Reject when not set up, or set up but not yet verified
		if target == nil || !target.TOTPVerified || target.TOTPSecret == "" {
			c.JSON(400, gin.H{"status": 400})
			return
		}

		if !totp.Validate(req.Code, target.TOTPSecret) {
			c.JSON(400, gin.H{"status": 400})
			return
		}

		c.JSON(200, gin.H{"status": 200, "token": issuer.Issue(target.ID)})
	}
}

// RecoveryCodeLoginHandler handles POST /api/login/recovery_code
func RecoveryCodeLoginHandler(store *UserStore, issuer *TokenIssuer) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req recoveryCodeLoginRequest
		if c.ShouldBindJSON(&req) != nil || req.Query == "" || req.RecoveryCode == "" {
			c.JSON(400, gin.H{"status": 400})
			return
		}

		store.mu.Lock()
		users, err := store.loadUsers()
		if err != nil {
			store.mu.Unlock()
			c.JSON(500, gin.H{"status": 500})
			return
		}
		store.mu.Unlock()

		var target *user
		for _, existing := range users {
			if existing.ID == req.Query || strings.EqualFold(existing.Email, req.Query) {
				target = &existing
				break
			}
		}

		if target == nil || !target.TOTPVerified || len(target.RecoveryCodes) == 0 {
			c.JSON(400, gin.H{"status": 400})
			return
		}

		upperCode := strings.ToUpper(req.RecoveryCode)
		found := false
		newCodes := make([]string, 0, len(target.RecoveryCodes))
		for _, code := range target.RecoveryCodes {
			if strings.EqualFold(code, upperCode) && !found {
				found = true
				continue
			}
			newCodes = append(newCodes, code)
		}

		if !found {
			c.JSON(400, gin.H{"status": 400})
			return
		}

		target.RecoveryCodes = newCodes
		if err := store.writeUser(*target); err != nil {
			logger.Error("Failed to update recovery codes", "err", err)
			c.JSON(500, gin.H{"status": 500})
			return
		}

		c.JSON(200, gin.H{"status": 200, "token": issuer.Issue(target.ID)})
	}
}
