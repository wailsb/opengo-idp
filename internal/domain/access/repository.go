package access

import (
	"context"
	"slices"

	"github.com/google/uuid"
)

// UserAccessSummary is the resolved authorization view of a user: role slugs plus the
// flattened, de-duplicated permission slugs granted via roles and direct assignments.
type UserAccessSummary struct {
	Roles       []string
	Permissions []string
}

// NewUserAccessSummary flattens roles and direct permissions into a summary with unique,
// sorted slugs. Adapters can use it to keep resolution rules in the domain.
func NewUserAccessSummary(roles []Role, directPermissions []Permission) *UserAccessSummary {
	roleSlugs := make([]string, 0, len(roles))
	permSlugs := make([]string, 0, len(directPermissions))

	for _, r := range roles {
		roleSlugs = append(roleSlugs, r.Slug)
		for _, p := range r.Permissions {
			permSlugs = append(permSlugs, p.Slug)
		}
	}
	for _, p := range directPermissions {
		permSlugs = append(permSlugs, p.Slug)
	}

	slices.Sort(roleSlugs)
	slices.Sort(permSlugs)

	return &UserAccessSummary{
		Roles:       slices.Compact(roleSlugs),
		Permissions: slices.Compact(permSlugs),
	}
}

func (s *UserAccessSummary) HasRole(slug string) bool {
	return slices.Contains(s.Roles, slug)
}

func (s *UserAccessSummary) HasPermission(slug string) bool {
	return slices.Contains(s.Permissions, slug)
}

// Repository defines the storage contract for roles, permissions and their assignments.
type Repository interface {
	// Permissions
	CreatePermission(ctx context.Context, permission *Permission) error
	GetPermissionBySlug(ctx context.Context, slug string) (*Permission, error)
	ListPermissions(ctx context.Context) ([]Permission, error)

	// Roles
	CreateRole(ctx context.Context, role *Role) error
	GetRoleBySlug(ctx context.Context, slug string) (*Role, error)
	AssignPermissionsToRole(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error

	// User assignments
	AssignRolesToUser(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error
	AssignDirectPermissionsToUser(ctx context.Context, userID uuid.UUID, permissionIDs []uuid.UUID) error

	// GetUserAccessSummary resolves the user's roles and the union of role-granted
	// and direct permissions, with each permission listed once.
	GetUserAccessSummary(ctx context.Context, userID uuid.UUID) (*UserAccessSummary, error)
}
