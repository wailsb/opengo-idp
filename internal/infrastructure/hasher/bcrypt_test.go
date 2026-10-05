package hasher

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

func TestBcrypt_HashAndCompare(t *testing.T) {
	h, err := NewBcrypt(bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}

	hash, err := h.Hash("s3cret-pass")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if hash == "s3cret-pass" {
		t.Fatal("hash must not equal the plain password")
	}
	if err := h.Compare(hash, "s3cret-pass"); err != nil {
		t.Fatalf("compare correct password: %v", err)
	}
	if err := h.Compare(hash, "wrong"); !errors.Is(err, ErrMismatch) {
		t.Fatalf("compare wrong password: got %v, want ErrMismatch", err)
	}
}

func TestBcrypt_MalformedHash(t *testing.T) {
	h, _ := NewBcrypt(bcrypt.MinCost)
	err := h.Compare("not-a-hash", "x")
	if err == nil || errors.Is(err, ErrMismatch) {
		t.Fatalf("got %v, want a non-mismatch error", err)
	}
}

func TestBcrypt_RejectsTooLongPassword(t *testing.T) {
	h, _ := NewBcrypt(bcrypt.MinCost)
	if _, err := h.Hash(strings.Repeat("a", 73)); err == nil {
		t.Fatal("expected error for password over 72 bytes")
	}
}

func TestNewBcrypt_Cost(t *testing.T) {
	if h, err := NewBcrypt(0); err != nil || h.cost != bcrypt.DefaultCost {
		t.Fatalf("cost 0: got %+v, %v", h, err)
	}
	if _, err := NewBcrypt(bcrypt.MaxCost + 1); err == nil {
		t.Fatal("expected error for cost above max")
	}
	if _, err := NewBcrypt(1); err == nil {
		t.Fatal("expected error for cost below min")
	}
}
