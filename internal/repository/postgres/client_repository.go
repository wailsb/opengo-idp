package postgres

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"github.com/wailsb/opengo-idp/internal/domain/client"
)

type ClientRepository struct {
	db DBTX
}

var _ client.Repository = (*ClientRepository)(nil)

func NewClientRepository(db DBTX) *ClientRepository {
	return &ClientRepository{db: db}
}

// Public clients have an empty ClientSecretHash in the domain and NULL in the database;
// NULLIF/COALESCE translate between the two. TEXT[] columns map directly to []string.

func (r *ClientRepository) Create(ctx context.Context, c *client.Client) error {
	_, err := r.db.Exec(ctx, `
		INSERT INTO clients (id, client_id, client_secret_hash, name, redirect_uris, allowed_grant_types, is_confidential, created_at)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6, $7, $8)`,
		c.ID, c.ClientID, c.ClientSecretHash, c.Name,
		nonNil(c.RedirectURIs), nonNil(c.AllowedGrantTypes), c.IsConfidential, c.CreatedAt,
	)
	if _, ok := constraintViolation(err, codeUniqueViolation); ok {
		return client.ErrClientAlreadyExists
	}
	return err
}

func (r *ClientRepository) GetByClientID(ctx context.Context, clientID string) (*client.Client, error) {
	var c client.Client
	err := r.db.QueryRow(ctx, `
		SELECT id, client_id, COALESCE(client_secret_hash, ''), name, redirect_uris, allowed_grant_types, is_confidential, created_at
		FROM clients
		WHERE client_id = $1`, clientID,
	).Scan(&c.ID, &c.ClientID, &c.ClientSecretHash, &c.Name, &c.RedirectURIs, &c.AllowedGrantTypes, &c.IsConfidential, &c.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, client.ErrClientNotFound
	}
	if err != nil {
		return nil, err
	}

	c.CreatedAt = c.CreatedAt.UTC()
	return &c, nil
}

// Update persists every mutable field, including the secret hash to support rotation.
// ClientID and CreatedAt are immutable.
func (r *ClientRepository) Update(ctx context.Context, c *client.Client) error {
	tag, err := r.db.Exec(ctx, `
		UPDATE clients
		SET client_secret_hash = NULLIF($2, ''),
		    name = $3,
		    redirect_uris = $4,
		    allowed_grant_types = $5,
		    is_confidential = $6
		WHERE id = $1`,
		c.ID, c.ClientSecretHash, c.Name, nonNil(c.RedirectURIs), nonNil(c.AllowedGrantTypes), c.IsConfidential,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return client.ErrClientNotFound
	}
	return nil
}

func (r *ClientRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.db.Exec(ctx, `DELETE FROM clients WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return client.ErrClientNotFound
	}
	return nil
}

// nonNil turns a nil slice into an empty one: pgx encodes nil as SQL NULL, which the
// NOT NULL array columns reject.
func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}
