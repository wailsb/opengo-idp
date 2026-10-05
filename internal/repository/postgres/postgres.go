// Package postgres implements the domain repository ports with raw SQL over pgx v5.
package postgres

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// DBTX is satisfied by *pgxpool.Pool, *pgx.Conn and pgx.Tx, so repositories can run
// against a pool or inside a caller-managed transaction.
type DBTX interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// PostgreSQL SQLSTATE codes mapped to domain errors.
const (
	codeUniqueViolation     = "23505"
	codeForeignKeyViolation = "23503"
)

// constraintViolation reports the violated constraint name when err is a PostgreSQL
// error with the given SQLSTATE code.
func constraintViolation(err error, code string) (string, bool) {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == code {
		return pgErr.ConstraintName, true
	}
	return "", false
}
