package access

import (
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidPermissionSlug   = errors.New("invalid permission slug: expected <resource>:<action>")
	ErrPermissionNotFound      = errors.New("permission not found")
	ErrPermissionAlreadyExists = errors.New("permission already exists")
)

// Permission is the atomic unit of authorization, identified by a
// "<resource>:<action>" slug such as "user:read".
type Permission struct {
	ID          uuid.UUID
	Slug        string
	Description string
	CreatedAt   time.Time
}

func NewPermission(slug, description string) (*Permission, error) {
	slug = strings.TrimSpace(slug)
	if !isValidPermissionSlug(slug) {
		return nil, ErrInvalidPermissionSlug
	}

	return &Permission{
		ID:          uuid.New(),
		Slug:        slug,
		Description: description,
		CreatedAt:   time.Now().UTC(),
	}, nil
}

// isValidPermissionSlug requires a non-empty resource and action separated by ':'
// and rejects embedded whitespace.
func isValidPermissionSlug(slug string) bool {
	if slug == "" || strings.ContainsAny(slug, " \t\r\n") {
		return false
	}

	resource, action, found := strings.Cut(slug, ":")
	return found && resource != "" && action != ""
}
