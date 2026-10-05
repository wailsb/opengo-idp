package access

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalidRoleName   = errors.New("role name must not be empty")
	ErrInvalidRoleSlug   = errors.New("role slug must not be empty or contain whitespace")
	ErrRoleNotFound      = errors.New("role not found")
	ErrRoleAlreadyExists = errors.New("role already exists")
)

// Role groups permissions under a named, assignable unit (e.g. "admin").
type Role struct {
	ID          uuid.UUID
	Name        string
	Slug        string
	Description string
	Permissions []Permission
	CreatedAt   time.Time
}

func NewRole(name, slug, description string) (*Role, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrInvalidRoleName
	}

	slug = strings.TrimSpace(slug)
	if slug == "" || strings.ContainsAny(slug, " \t\r\n") {
		return nil, ErrInvalidRoleSlug
	}

	return &Role{
		ID:          uuid.New(),
		Name:        name,
		Slug:        slug,
		Description: description,
		Permissions: []Permission{},
		CreatedAt:   time.Now().UTC(),
	}, nil
}

// AddPermission attaches p to the role. Adding an already attached permission is a no-op.
func (r *Role) AddPermission(p Permission) {
	if r.HasPermission(p.ID) {
		return
	}
	r.Permissions = append(r.Permissions, p)
}

// RemovePermission detaches the permission with the given ID. Removing an absent permission is a no-op.
func (r *Role) RemovePermission(permissionID uuid.UUID) {
	r.Permissions = slices.DeleteFunc(r.Permissions, func(p Permission) bool {
		return p.ID == permissionID
	})
}

func (r *Role) HasPermission(permissionID uuid.UUID) bool {
	return slices.ContainsFunc(r.Permissions, func(p Permission) bool {
		return p.ID == permissionID
	})
}
