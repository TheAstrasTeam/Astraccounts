package auth

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"time"
)

// tokenPrefix marks a token issued by this service.
const tokenPrefix = "aat"

// TokenIssuer creates and verifies stateless login tokens.
//
// Layout: aat_<user id>_<issued at unix seconds>_<HMAC-SHA256 hex>
// The payload carries only the user ID and the issue time. Usernames,
// passwords and password hashes are never part of a token.
type TokenIssuer struct {
	secret    []byte
	validSecs int64
}

// NewTokenIssuer builds an issuer signing with secret and expiring tokens
// validSecs seconds after they were issued.
func NewTokenIssuer(secret []byte, validSecs int64) *TokenIssuer {
	return &TokenIssuer{secret: secret, validSecs: validSecs}
}

// Issue returns a signed token for the given user ID.
func (t *TokenIssuer) Issue(id string) string {
	payload := tokenPrefix + "_" + id + "_" + strconv.FormatInt(time.Now().Unix(), 10)
	return payload + "_" + t.sign(payload)
}

// Verify reports the user ID carried by a token. It returns false when the
// token is malformed, has a bad signature, or is outside its validity window.
func (t *TokenIssuer) Verify(token string) (string, bool) {
	// The signature and timestamp never contain "_", while a user ID may,
	// so both trailing fields are split off from the right.
	payload, signature, ok := cutLast(token, "_")
	if !ok {
		return "", false
	}
	rest, issuedAtRaw, ok := cutLast(payload, "_")
	if !ok {
		return "", false
	}
	id, ok := strings.CutPrefix(rest, tokenPrefix+"_")
	if !ok || !idPattern.MatchString(id) {
		return "", false
	}

	issuedAt, err := strconv.ParseInt(issuedAtRaw, 10, 64)
	if err != nil {
		return "", false
	}
	if !hmac.Equal([]byte(signature), []byte(t.sign(payload))) {
		return "", false
	}

	age := time.Now().Unix() - issuedAt
	if age < 0 || age >= t.validSecs {
		return "", false
	}
	return id, true
}

func (t *TokenIssuer) sign(payload string) string {
	mac := hmac.New(sha256.New, t.secret)
	mac.Write([]byte(payload))
	return hex.EncodeToString(mac.Sum(nil))
}

// cutLast splits s around the last instance of sep.
func cutLast(s, sep string) (before, after string, found bool) {
	index := strings.LastIndex(s, sep)
	if index < 0 {
		return "", "", false
	}
	return s[:index], s[index+len(sep):], true
}
