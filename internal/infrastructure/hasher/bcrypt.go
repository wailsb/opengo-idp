// Package hasher implements password hashing for the auth usecases.
package hasher

import (
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"
)

var ErrMismatch = errors.New("password does not match hash")

// Bcrypt hashes passwords with bcrypt. bcrypt only reads the first 72 bytes of a
// password, so Hash rejects longer passwords instead of silently truncating them.
type Bcrypt struct {
	cost int
}

// NewBcrypt returns a hasher with the given cost; a cost of 0 uses bcrypt.DefaultCost.
func NewBcrypt(cost int) (*Bcrypt, error) {
	if cost == 0 {
		cost = bcrypt.DefaultCost
	}
	if cost < bcrypt.MinCost || cost > bcrypt.MaxCost {
		return nil, fmt.Errorf("bcrypt cost %d out of range [%d, %d]", cost, bcrypt.MinCost, bcrypt.MaxCost)
	}
	return &Bcrypt{cost: cost}, nil
}

func (b *Bcrypt) Hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), b.cost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// Compare returns ErrMismatch for a wrong password and another error for a malformed hash.
func (b *Bcrypt) Compare(hashedPassword, plainPassword string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(plainPassword))
	if errors.Is(err, bcrypt.ErrMismatchedHashAndPassword) {
		return ErrMismatch
	}
	return err
}
