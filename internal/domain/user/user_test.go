package user

import (
	"errors"
	"testing"
)

func newTestUser(t *testing.T) *User {
	t.Helper()
	u, err := NewUser("a@example.com", "password1", "alice")
	if err != nil {
		t.Fatal(err)
	}
	return u
}

func TestNewUser(t *testing.T) {
	u := newTestUser(t)
	if !u.IsActive || u.IsDeleted || u.PasswordHash == "password1" {
		t.Fatalf("unexpected new user: %+v", u)
	}
	if !u.CheckPassword("password1") || u.CheckPassword("wrong") {
		t.Fatal("password check broken")
	}
}

func TestNewUserFromHash(t *testing.T) {
	u := NewUserFromHash("a@example.com", "somehash", "alice")
	if u.PasswordHash != "somehash" || !u.IsActive || u.CreatedAt.IsZero() || u.CreatedAt != u.UpdatedAt {
		t.Fatalf("unexpected user: %+v", u)
	}
}

func TestLifecycle(t *testing.T) {
	u := newTestUser(t)

	if err := u.Enable(); !errors.Is(err, ErrUserAlreadyActive) {
		t.Errorf("enable active: %v", err)
	}
	if err := u.Disable(); err != nil || u.IsActive {
		t.Fatalf("disable: %v", err)
	}
	if err := u.Disable(); !errors.Is(err, ErrUserInactive) {
		t.Errorf("disable inactive: %v", err)
	}
	if err := u.Enable(); err != nil || !u.IsActive {
		t.Fatalf("enable: %v", err)
	}
	if err := u.Delete(); err != nil || !u.IsDeleted || u.IsActive {
		t.Fatalf("delete: %v %+v", err, u)
	}
	for name, fn := range map[string]func() error{"delete": u.Delete, "enable": u.Enable, "disable": u.Disable} {
		if err := fn(); !errors.Is(err, ErrUserDeleted) {
			t.Errorf("%s after delete: %v", name, err)
		}
	}
}

func TestUpdateInfo(t *testing.T) {
	u := newTestUser(t)
	before := u.UpdatedAt

	if err := u.UpdateInfo(UpdateUserParams{}); err != nil || u.UpdatedAt != before {
		t.Fatalf("no-op update changed timestamp: %v", err)
	}

	email, name := "b@example.com", "bob"
	if err := u.UpdateInfo(UpdateUserParams{Email: &email, Username: &name}); err != nil {
		t.Fatal(err)
	}
	if u.Email != email || u.Username != name {
		t.Errorf("fields not updated: %+v", u)
	}

	_ = u.Disable()
	if err := u.UpdateInfo(UpdateUserParams{Email: &email}); !errors.Is(err, ErrUserInactive) {
		t.Errorf("update inactive: %v", err)
	}
}
