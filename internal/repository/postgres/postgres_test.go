package postgres_test

// Integration tests run against a real PostgreSQL and are skipped unless PG_TEST_DSN is set:
//
//	docker run --rm -d --name idp-pg-test -p 55432:5432 -e POSTGRES_PASSWORD=test postgres:17
//	PG_TEST_DSN=postgres://postgres:test@localhost:55432/postgres go test ./internal/repository/postgres/...
//
// Each run applies the migration inside a fresh schema and drops it afterwards.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/wailsb/opengo-idp/internal/domain/access"
	"github.com/wailsb/opengo-idp/internal/domain/client"
	"github.com/wailsb/opengo-idp/internal/domain/user"
	"github.com/wailsb/opengo-idp/internal/repository/postgres"
)

func setupDB(t *testing.T) *pgx.Conn {
	t.Helper()
	dsn := os.Getenv("PG_TEST_DSN")
	if dsn == "" {
		t.Skip("PG_TEST_DSN not set")
	}

	ctx := context.Background()
	conn, err := pgx.Connect(ctx, dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}

	schema := fmt.Sprintf("test_%d", time.Now().UnixNano())
	migration, err := os.ReadFile("../../../migrations/000001_init_schema.up.sql")
	if err != nil {
		t.Fatalf("read migration: %v", err)
	}
	if _, err := conn.Exec(ctx, fmt.Sprintf("CREATE SCHEMA %s; SET search_path TO %s", schema, schema)); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	if _, err := conn.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("apply migration: %v", err)
	}

	t.Cleanup(func() {
		_, _ = conn.Exec(ctx, fmt.Sprintf("DROP SCHEMA %s CASCADE", schema))
		_ = conn.Close(ctx)
	})
	return conn
}

func mustNoErr(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func wantErr(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("got error %v, want %v", got, want)
	}
}

func TestUserRepository(t *testing.T) {
	ctx := context.Background()
	repo := postgres.NewUserRepository(setupDB(t))

	u, err := user.NewUser("alice@example.com", "s3cret", "alice")
	mustNoErr(t, err)
	mustNoErr(t, repo.Create(ctx, u))

	dup, _ := user.NewUser("alice@example.com", "x", "other")
	wantErr(t, repo.Create(ctx, dup), user.ErrUserAlreadyExists)

	got, err := repo.GetByEmail(ctx, "alice@example.com")
	mustNoErr(t, err)
	if got.ID != u.ID || !got.CheckPassword("s3cret") || got.CreatedAt.Location() != time.UTC {
		t.Fatalf("unexpected user %+v", got)
	}
	_, err = repo.GetByUsername(ctx, "alice")
	mustNoErr(t, err)
	_, err = repo.GetByEmailOrUsername(ctx, "alice")
	mustNoErr(t, err)
	_, err = repo.GetByID(ctx, uuid.New())
	wantErr(t, err, user.ErrUserNotFound)

	newName := "alice2"
	mustNoErr(t, got.UpdateInfo(user.UpdateUserParams{Username: &newName}))
	mustNoErr(t, repo.Update(ctx, got))
	got, err = repo.GetByID(ctx, u.ID)
	mustNoErr(t, err)
	if got.Username != "alice2" {
		t.Fatalf("update not persisted: %q", got.Username)
	}
	wantErr(t, repo.Update(ctx, dup), user.ErrUserNotFound)

	mustNoErr(t, repo.Delete(ctx, u.ID))
	got, err = repo.GetByID(ctx, u.ID)
	mustNoErr(t, err)
	if !got.IsDeleted || got.IsActive {
		t.Fatalf("soft delete not applied: %+v", got)
	}
	wantErr(t, repo.Delete(ctx, u.ID), user.ErrUserDeleted)
	wantErr(t, repo.Delete(ctx, uuid.New()), user.ErrUserNotFound)
}

func TestAccessRepository(t *testing.T) {
	ctx := context.Background()
	db := setupDB(t)
	users := postgres.NewUserRepository(db)
	repo := postgres.NewAccessRepository(db)

	u, _ := user.NewUser("bob@example.com", "pw", "bob")
	mustNoErr(t, users.Create(ctx, u))

	read, _ := access.NewPermission("user:read", "Read users")
	write, _ := access.NewPermission("user:write", "")
	audit, _ := access.NewPermission("audit:read", "")
	for _, p := range []*access.Permission{read, write, audit} {
		mustNoErr(t, repo.CreatePermission(ctx, p))
	}
	wantErr(t, repo.CreatePermission(ctx, read), access.ErrPermissionAlreadyExists)

	gotPerm, err := repo.GetPermissionBySlug(ctx, "user:read")
	mustNoErr(t, err)
	if gotPerm.ID != read.ID || gotPerm.Description != "Read users" {
		t.Fatalf("unexpected permission %+v", gotPerm)
	}
	_, err = repo.GetPermissionBySlug(ctx, "nope:nope")
	wantErr(t, err, access.ErrPermissionNotFound)

	all, err := repo.ListPermissions(ctx)
	mustNoErr(t, err)
	if len(all) != 3 || all[0].Slug != "audit:read" {
		t.Fatalf("unexpected list %+v", all)
	}

	admin, _ := access.NewRole("Admin", "admin", "")
	admin.AddPermission(*read)
	mustNoErr(t, repo.CreateRole(ctx, admin))
	wantErr(t, repo.CreateRole(ctx, admin), access.ErrRoleAlreadyExists)

	viewer, _ := access.NewRole("Viewer", "viewer", "")
	mustNoErr(t, repo.CreateRole(ctx, viewer))

	ghost := access.Permission{ID: uuid.New(), Slug: "ghost:read"}
	broken, _ := access.NewRole("Broken", "broken", "")
	broken.AddPermission(ghost)
	wantErr(t, repo.CreateRole(ctx, broken), access.ErrPermissionNotFound)
	_, err = repo.GetRoleBySlug(ctx, "broken")
	wantErr(t, err, access.ErrRoleNotFound) // no partial insert

	mustNoErr(t, repo.AssignPermissionsToRole(ctx, admin.ID, []uuid.UUID{read.ID, write.ID, write.ID}))
	wantErr(t, repo.AssignPermissionsToRole(ctx, uuid.New(), []uuid.UUID{read.ID}), access.ErrRoleNotFound)
	wantErr(t, repo.AssignPermissionsToRole(ctx, admin.ID, []uuid.UUID{uuid.New()}), access.ErrPermissionNotFound)

	gotRole, err := repo.GetRoleBySlug(ctx, "admin")
	mustNoErr(t, err)
	if len(gotRole.Permissions) != 2 || gotRole.Permissions[0].Slug != "user:read" {
		t.Fatalf("unexpected role %+v", gotRole)
	}
	gotViewer, err := repo.GetRoleBySlug(ctx, "viewer")
	mustNoErr(t, err)
	if gotViewer.Permissions == nil || len(gotViewer.Permissions) != 0 {
		t.Fatalf("empty role should have empty permissions: %+v", gotViewer)
	}

	mustNoErr(t, repo.AssignRolesToUser(ctx, u.ID, []uuid.UUID{admin.ID, viewer.ID}))
	mustNoErr(t, repo.AssignRolesToUser(ctx, u.ID, []uuid.UUID{admin.ID}))
	wantErr(t, repo.AssignRolesToUser(ctx, uuid.New(), []uuid.UUID{admin.ID}), user.ErrUserNotFound)
	mustNoErr(t, repo.AssignDirectPermissionsToUser(ctx, u.ID, []uuid.UUID{read.ID, audit.ID}))
	wantErr(t, repo.AssignDirectPermissionsToUser(ctx, u.ID, []uuid.UUID{uuid.New()}), access.ErrPermissionNotFound)

	summary, err := repo.GetUserAccessSummary(ctx, u.ID)
	mustNoErr(t, err)
	if !slices.Equal(summary.Roles, []string{"admin", "viewer"}) ||
		!slices.Equal(summary.Permissions, []string{"audit:read", "user:read", "user:write"}) {
		t.Fatalf("unexpected summary %+v", summary)
	}

	empty, err := repo.GetUserAccessSummary(ctx, uuid.New())
	mustNoErr(t, err)
	if len(empty.Roles) != 0 || len(empty.Permissions) != 0 {
		t.Fatalf("unexpected summary for unknown user %+v", empty)
	}
}

func TestClientRepository(t *testing.T) {
	ctx := context.Background()
	repo := postgres.NewClientRepository(setupDB(t))

	conf, secret, err := client.NewClient("web", []string{"https://app/cb"},
		[]string{client.GrantTypeAuthorizationCode, client.GrantTypeRefreshToken}, true)
	mustNoErr(t, err)
	mustNoErr(t, repo.Create(ctx, conf))
	wantErr(t, repo.Create(ctx, conf), client.ErrClientAlreadyExists)

	got, err := repo.GetByClientID(ctx, conf.ClientID)
	mustNoErr(t, err)
	if !got.VerifySecret(secret) || !slices.Equal(got.RedirectURIs, conf.RedirectURIs) ||
		!slices.Equal(got.AllowedGrantTypes, conf.AllowedGrantTypes) {
		t.Fatalf("unexpected client %+v", got)
	}

	pub, _, err := client.NewClient("spa", []string{"https://spa/cb"}, []string{client.GrantTypeAuthorizationCode}, false)
	mustNoErr(t, err)
	mustNoErr(t, repo.Create(ctx, pub))
	gotPub, err := repo.GetByClientID(ctx, pub.ClientID)
	mustNoErr(t, err)
	if gotPub.ClientSecretHash != "" || gotPub.IsConfidential {
		t.Fatalf("unexpected public client %+v", gotPub)
	}

	got.Name = "web v2"
	got.RedirectURIs = append(got.RedirectURIs, "https://app/cb2")
	mustNoErr(t, repo.Update(ctx, got))
	got, err = repo.GetByClientID(ctx, conf.ClientID)
	mustNoErr(t, err)
	if got.Name != "web v2" || len(got.RedirectURIs) != 2 {
		t.Fatalf("update not persisted %+v", got)
	}

	mustNoErr(t, repo.Delete(ctx, conf.ID))
	_, err = repo.GetByClientID(ctx, conf.ClientID)
	wantErr(t, err, client.ErrClientNotFound)
	wantErr(t, repo.Delete(ctx, conf.ID), client.ErrClientNotFound)
	wantErr(t, repo.Update(ctx, conf), client.ErrClientNotFound)
}
