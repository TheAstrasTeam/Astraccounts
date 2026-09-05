package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func validRegisterRequest() registerRequest {
	return registerRequest{
		Username: "示例",
		ID:       "ExampleUser",
		Email:    "user@example.com",
		Password: "Example123456*",
	}
}

func TestValidateRegister(t *testing.T) {
	tests := []struct {
		name string
		edit func(*registerRequest)
		want int
	}{
		{"username", func(req *registerRequest) { req.Username = "bad\nname" }, 1},
		{"id", func(req *registerRequest) { req.ID = "bad-id" }, 2},
		{"email", func(req *registerRequest) { req.Email = "not-an-email" }, 3},
		{"password", func(req *registerRequest) { req.Password = "bad password" }, 4},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := validRegisterRequest()
			tt.edit(&req)
			if got := validateRegister(req); got != tt.want {
				t.Fatalf("validateRegister() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestUserStoreRegisterAndLogin(t *testing.T) {
	store := newUserStore(t.TempDir())
	req := validRegisterRequest()
	uid, errCode, err := store.register(req)
	if err != nil || errCode != 0 || uid != 1 {
		t.Fatalf("register() = uid %d, errCode %d, err %v", uid, errCode, err)
	}

	data, err := os.ReadFile(filepath.Join(store.root, "1", "user.json"))
	if err != nil {
		t.Fatal(err)
	}
	var saved user
	if err := json.Unmarshal(data, &saved); err != nil {
		t.Fatal(err)
	}
	if saved.Password == req.Password || saved.UID != 1 {
		t.Fatal("password was not hashed or UID was not persisted")
	}
	if !store.login(req.ID, req.Password) || !store.login(req.Email, req.Password) {
		t.Fatal("valid credentials did not log in")
	}
	if store.login(req.ID, "wrong-password") {
		t.Fatal("invalid password logged in")
	}
}
