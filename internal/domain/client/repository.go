package client

import (
	"context"

	"github.com/google/uuid"
)

// Repository defines the storage contract for registered OAuth2/OIDC clients.
type Repository interface {
	Create(ctx context.Context, client *Client) error
	GetByClientID(ctx context.Context, clientID string) (*Client, error)
	Update(ctx context.Context, client *Client) error
	Delete(ctx context.Context, id uuid.UUID) error
}
