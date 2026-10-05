package access

import (
	"errors"
	"slices"
	"testing"
)

func TestNewPermission(t *testing.T) {
	p, err := NewPermission(" user:read ", "read users")
	if err != nil || p.Slug != "user:read" {
		t.Fatalf("got %+v, %v", p, err)
	}
	for _, slug := range []string{"", "user", ":read", "user:", "user :read", "user:re ad"} {
		if _, err := NewPermission(slug, ""); !errors.Is(err, ErrInvalidPermissionSlug) {
			t.Errorf("slug %q: got %v", slug, err)
		}
	}
}

func TestNewRole(t *testing.T) {
	r, err := NewRole(" Admin ", "admin", "")
	if err != nil || r.Name != "Admin" || r.Permissions == nil {
		t.Fatalf("got %+v, %v", r, err)
	}
	if _, err := NewRole(" ", "x", ""); !errors.Is(err, ErrInvalidRoleName) {
		t.Errorf("empty name: %v", err)
	}
	if _, err := NewRole("x", "a b", ""); !errors.Is(err, ErrInvalidRoleSlug) {
		t.Errorf("slug with space: %v", err)
	}
}

func TestRolePermissions(t *testing.T) {
	r, _ := NewRole("Admin", "admin", "")
	p, _ := NewPermission("user:read", "")

	r.AddPermission(*p)
	r.AddPermission(*p) // no-op
	if len(r.Permissions) != 1 || !r.HasPermission(p.ID) {
		t.Fatalf("add: %+v", r.Permissions)
	}
	r.RemovePermission(p.ID)
	r.RemovePermission(p.ID) // no-op
	if len(r.Permissions) != 0 || r.HasPermission(p.ID) {
		t.Fatalf("remove: %+v", r.Permissions)
	}
}

func TestNewUserAccessSummary(t *testing.T) {
	read, _ := NewPermission("user:read", "")
	write, _ := NewPermission("user:write", "")
	admin, _ := NewRole("Admin", "admin", "")
	admin.AddPermission(*read)
	admin.AddPermission(*write)
	viewer, _ := NewRole("Viewer", "viewer", "")
	viewer.AddPermission(*read)

	s := NewUserAccessSummary([]Role{*viewer, *admin}, []Permission{*read})

	if !slices.Equal(s.Roles, []string{"admin", "viewer"}) {
		t.Errorf("roles = %v", s.Roles)
	}
	if !slices.Equal(s.Permissions, []string{"user:read", "user:write"}) {
		t.Errorf("permissions must be sorted and de-duplicated: %v", s.Permissions)
	}
	if !s.HasRole("admin") || s.HasRole("root") || !s.HasPermission("user:write") || s.HasPermission("user:delete") {
		t.Error("lookup helpers broken")
	}

	empty := NewUserAccessSummary(nil, nil)
	if len(empty.Roles) != 0 || len(empty.Permissions) != 0 {
		t.Errorf("empty summary: %+v", empty)
	}
}
