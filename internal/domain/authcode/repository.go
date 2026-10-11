package authcode

import "context"

// Repository persists authorization codes. GetAndDelete MUST be atomic (e.g. Redis
// GETDEL) so a leaked code cannot be exchanged more than once.
type Repository interface {
	Create(ctx context.Context, code *AuthCode) error

	// GetAndDelete returns the stored code and removes it in one atomic step. It
	// returns ErrAuthCodeNotFound when the code is missing (either never issued
	// or already consumed).
	GetAndDelete(ctx context.Context, code string) (*AuthCode, error)
}
