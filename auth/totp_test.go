package auth

import (
	"strings"
	"testing"
	"time"

	"github.com/pquerna/otp/totp"
)

func TestTotpSignVerifyLogin(t *testing.T) {
	store := NewUserStore(t.TempDir())

	req := registerRequest{Username: "t", ID: "TestUser", Email: "test@example.com", Password: "Pass123456*"}
	uid, errCode, err := store.register(req)
	if err != nil || errCode != 0 || uid != 1 {
		t.Fatalf("register: uid=%d errCode=%d err=%v", uid, errCode, err)
	}

	// After register: no TOTP
	u, _, _ := store.readUser(1)
	if u.TOTPSecret != "" || u.TOTPVerified {
		t.Fatal("TOTP should not be set after registration")
	}

	// Sign: sets secret, NOT verified
	uptr, ok := store.verifyPassword("TestUser", "Pass123456*")
	if !ok {
		t.Fatal("verifyPassword should succeed")
	}
	key, _ := totp.Generate(totp.GenerateOpts{
		Issuer: "Astraccounts", AccountName: "TestUser",
		Period: 30, Digits: 6,
	})
	uptr.TOTPSecret = key.Secret()
	uptr.TOTPVerified = false
	store.writeUser(*uptr)

	u2, _, _ := store.readUser(1)
	if u2.TOTPSecret == "" {
		t.Fatal("secret should be set")
	}
	if u2.TOTPVerified {
		t.Fatal("should NOT be verified yet")
	}

	// Generate a valid code
	code, _ := totp.GenerateCode(u2.TOTPSecret, time.Now())

	// Verify: code correct → verified=true
	uptr2, _ := store.verifyPassword("TestUser", "Pass123456*")
	if !totp.Validate(code, uptr2.TOTPSecret) {
		t.Fatal("code should be valid")
	}
	uptr2.TOTPVerified = true
	uptr2.RecoveryCodes = []string{"CODE1", "CODE2"}
	store.writeUser(*uptr2)

	u4, _, _ := store.readUser(1)
	if !u4.TOTPVerified {
		t.Fatal("should be verified now")
	}
	if len(u4.RecoveryCodes) != 2 {
		t.Fatalf("recovery codes: got %d want 2", len(u4.RecoveryCodes))
	}

	// Simulate failed verify → remove TOTP
	uptr3, _ := store.verifyPassword("TestUser", "Pass123456*")
	uptr3.TOTPSecret = ""
	uptr3.TOTPVerified = false
	uptr3.RecoveryCodes = nil
	store.writeUser(*uptr3)

	u6, _, _ := store.readUser(1)
	if u6.TOTPSecret != "" || u6.TOTPVerified {
		t.Fatal("TOTP should be removed after failed verify")
	}
}

func TestTotpLoginRejectsUnverified(t *testing.T) {
	store := NewUserStore(t.TempDir())

	req := registerRequest{Username: "t", ID: "U", Email: "u@e.com", Password: "Pass123456*"}
	store.register(req)

	// Set up TOTP but NOT verified
	uptr, _ := store.verifyPassword("U", "Pass123456*")
	uptr.TOTPSecret = "JBSWY3DPEHPK3PXP"
	uptr.TOTPVerified = false
	store.writeUser(*uptr)

	u2, _, _ := store.readUser(1)
	if u2.TOTPVerified {
		t.Fatal("should not be verified")
	}
	// A valid code should still be rejected because not verified
	code, _ := totp.GenerateCode(u2.TOTPSecret, time.Now())
	valid := totp.Validate(code, u2.TOTPSecret)
	if !valid {
		t.Fatal("code should be valid cryptographically")
	}
}

func TestRecoveryCodeConsume(t *testing.T) {
	store := NewUserStore(t.TempDir())

	req := registerRequest{Username: "t", ID: "User", Email: "a@b.com", Password: "Pass123456*"}
	uid, errCode, err := store.register(req)
	if err != nil || errCode != 0 || uid != 1 {
		t.Fatalf("register: uid=%d errCode=%d err=%v", uid, errCode, err)
	}

	uptr, _ := store.verifyPassword("User", "Pass123456*")
	uptr.TOTPSecret = "JBSWY3DPEHPK3PXP"
	uptr.TOTPVerified = true
	uptr.RecoveryCodes = []string{"AAA", "BBB", "CCC"}
	store.writeUser(*uptr)

	u2, _, _ := store.readUser(1)
	upperCode := "aaa"
	found := false
	newCodes := make([]string, 0, len(u2.RecoveryCodes))
	for _, code := range u2.RecoveryCodes {
		if strings.EqualFold(code, upperCode) && !found {
			found = true
			continue
		}
		newCodes = append(newCodes, code)
	}
	if !found {
		t.Fatal("should find code")
	}
	u2.RecoveryCodes = newCodes
	store.writeUser(u2)

	u3, _, _ := store.readUser(1)
	if len(u3.RecoveryCodes) != 2 {
		t.Fatalf("expected 2 codes, got %d", len(u3.RecoveryCodes))
	}
	for _, c := range u3.RecoveryCodes {
		if c == "AAA" {
			t.Fatal("AAA should have been consumed")
		}
	}
}
