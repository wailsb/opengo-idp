package postgres

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/wailsb/opengo-idp/internal/domain/access"
	"github.com/wailsb/opengo-idp/internal/domain/user"
)

type AccessRepository struct {
	db DBTX
}

var _ access.Repository = (*AccessRepository)(nil)

func NewAccessRepository(db DBTX) *AccessRepository {
	return &AccessRepository{db: db}
}

// fkErrors maps foreign key constraint names from the schema to the domain error for
// the missing referenced row.
var fkErrors = map[string]error{
	"role_permissions_role_id_fkey":              access.ErrRoleNotFound,
	"role_permissions_permission_id_fkey":        access.ErrPermissionNotFound,
	"user_roles_user_id_fkey":                    user.ErrUserNotFound,
	"user_roles_role_id_fkey":                    access.ErrRoleNotFound,
	"user_direct_permissions_user_id_fkey":       user.ErrUserNotFound,
	"user_direct_permissions_permission_id_fkey": access.ErrPermissionNotFound,
}

func mapFKError(err error) error {
	if name, ok := constraintViolation(err, codeForeignKeyViolation); ok {
		if domainErr, known := fkErrors[name]; known {
			return domainErr
		}
	}
	return err
}

// Permissions

func (r *AccessRepository) CreatePermission(ctx context.Context, p *access.Permission) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO permissions (id, slug, description, created_at)
		VALUES ($1, $2, NULLIF($3, ''), $4)`,
		p.ID, p.Slug, p.Description, p.CreatedAt,
	)
	if _, ok := constraintViolation(err, codeUniqueViolation); ok {
		return access.ErrPermissionAlreadyExists
	}
	return err
}

func (r *AccessRepository) GetPermissionBySlug(ctx context.Context, slug string) (*access.Permission, error) {
	var p access.Permission
	err := r.db.QueryRow(ctx, `
		SELECT id, slug, COALESCE(description, ''), created_at
		FROM permissions
		WHERE slug = $1`, slug,
	).Scan(&p.ID, &p.Slug, &p.Description, &p.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, access.ErrPermissionNotFound
	}
	if err != nil {
		return nil, err
	}

	p.CreatedAt = p.CreatedAt.UTC()
	return &p, nil
}

func (r *AccessRepository) ListPermissions(ctx context.Context) ([]access.Permission, error) {
	rows, err := r.db.Query(ctx, `
		SELECT id, slug, COALESCE(description, ''), created_at
		FROM permissions
		ORDER BY slug`)
	if err != nil {
		return nil, err
	}

	permissions, err := pgx.CollectRows(rows, func(row pgx.CollectableRow) (access.Permission, error) {
		var p access.Permission
		err := row.Scan(&p.ID, &p.Slug, &p.Description, &p.CreatedAt)
		p.CreatedAt = p.CreatedAt.UTC()
		return p, err
	})
	if err != nil {
		return nil, err
	}
	return permissions, nil
}

// Roles

// CreateRole inserts the role together with any permissions already attached to it.
// Both inserts run in one statement, so a missing permission leaves no partial role.
func (r *AccessRepository) CreateRole(ctx context.Context, role *access.Role) error {
	permissionIDs := make([]uuid.UUID, 0, len(role.Permissions))
	for _, p := range role.Permissions {
		permissionIDs = append(permissionIDs, p.ID)
	}

	_, err := r.db.Exec(ctx, `
		WITH new_role AS (
			INSERT INTO roles (id, name, slug, description, created_at)
			VALUES ($1, $2, $3, NULLIF($4, ''), $5)
			RETURNING id
		)
		INSERT INTO role_permissions (role_id, permission_id)
		SELECT new_role.id, pid FROM new_role, unnest($6::uuid[]) AS pid
		ON CONFLICT DO NOTHING`,
		role.ID, role.Name, role.Slug, role.Description, role.CreatedAt, permissionIDs,
	)
	if _, ok := constraintViolation(err, codeUniqueViolation); ok {
		return access.ErrRoleAlreadyExists
	}
	return mapFKError(err)
}

// GetRoleBySlug loads the role with its permissions in a single query.
func (r *AccessRepository) GetRoleBySlug(ctx context.Context, slug string) (*access.Role, error) {
	rows, err := r.db.Query(ctx, `
		SELECT r.id, r.name, r.slug, COALESCE(r.description, ''), r.created_at,
		       p.id, p.slug, COALESCE(p.description, ''), p.created_at
		FROM roles r
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		LEFT JOIN permissions p ON p.id = rp.permission_id
		WHERE r.slug = $1
		ORDER BY p.slug`, slug)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var role *access.Role
	for rows.Next() {
		var (
			current     access.Role
			permID      uuid.NullUUID
			permSlug    *string
			permDesc    string
			permCreated *time.Time
		)
		if err := rows.Scan(
			&current.ID, &current.Name, &current.Slug, &current.Description, &current.CreatedAt,
			&permID, &permSlug, &permDesc, &permCreated,
		); err != nil {
			return nil, err
		}

		if role == nil {
			current.CreatedAt = current.CreatedAt.UTC()
			current.Permissions = []access.Permission{}
			role = &current
		}
		// A role without permissions yields one row with NULL permission columns.
		if permID.Valid {
			role.Permissions = append(role.Permissions, access.Permission{
				ID:          permID.UUID,
				Slug:        *permSlug,
				Description: permDesc,
				CreatedAt:   permCreated.UTC(),
			})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	if role == nil {
		return nil, access.ErrRoleNotFound
	}
	return role, nil
}

// AssignPermissionsToRole adds permissions to the role; already assigned ones are kept.
func (r *AccessRepository) AssignPermissionsToRole(ctx context.Context, roleID uuid.UUID, permissionIDs []uuid.UUID) error {
	if len(permissionIDs) == 0 {
		return nil
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO role_permissions (role_id, permission_id)
		SELECT $1, unnest($2::uuid[])
		ON CONFLICT DO NOTHING`, roleID, permissionIDs)
	return mapFKError(err)
}

// User assignments

// AssignRolesToUser adds roles to the user; already assigned ones are kept.
func (r *AccessRepository) AssignRolesToUser(ctx context.Context, userID uuid.UUID, roleIDs []uuid.UUID) error {
	if len(roleIDs) == 0 {
		return nil
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO user_roles (user_id, role_id)
		SELECT $1, unnest($2::uuid[])
		ON CONFLICT DO NOTHING`, userID, roleIDs)
	return mapFKError(err)
}

// AssignDirectPermissionsToUser adds permissions to the user; already assigned ones are kept.
func (r *AccessRepository) AssignDirectPermissionsToUser(ctx context.Context, userID uuid.UUID, permissionIDs []uuid.UUID) error {
	if len(permissionIDs) == 0 {
		return nil
	}
	_, err := r.db.Exec(ctx, `
		INSERT INTO user_direct_permissions (user_id, permission_id)
		SELECT $1, unnest($2::uuid[])
		ON CONFLICT DO NOTHING`, userID, permissionIDs)
	return mapFKError(err)
}

// GetUserAccessSummary fetches role-granted and direct permissions in one round trip.
// Each row is either (role_slug, permission_slug-or-NULL) for an assigned role, or
// (NULL, permission_slug) for a direct grant. Flattening and de-duplication are left
// to access.NewUserAccessSummary.
func (r *AccessRepository) GetUserAccessSummary(ctx context.Context, userID uuid.UUID) (*access.UserAccessSummary, error) {
	rows, err := r.db.Query(ctx, `
		SELECT r.slug, p.slug
		FROM user_roles ur
		JOIN roles r ON r.id = ur.role_id
		LEFT JOIN role_permissions rp ON rp.role_id = r.id
		LEFT JOIN permissions p ON p.id = rp.permission_id
		WHERE ur.user_id = $1

		UNION ALL

		SELECT NULL, p.slug
		FROM user_direct_permissions udp
		JOIN permissions p ON p.id = udp.permission_id
		WHERE udp.user_id = $1`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var (
		roles       []access.Role
		roleIndex   = map[string]int{}
		directPerms []access.Permission
	)
	for rows.Next() {
		var roleSlug, permSlug *string
		if err := rows.Scan(&roleSlug, &permSlug); err != nil {
			return nil, err
		}

		if roleSlug == nil {
			directPerms = append(directPerms, access.Permission{Slug: *permSlug})
			continue
		}

		i, seen := roleIndex[*roleSlug]
		if !seen {
			i = len(roles)
			roleIndex[*roleSlug] = i
			roles = append(roles, access.Role{Slug: *roleSlug})
		}
		if permSlug != nil {
			roles[i].Permissions = append(roles[i].Permissions, access.Permission{Slug: *permSlug})
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	return access.NewUserAccessSummary(roles, directPerms), nil
}
