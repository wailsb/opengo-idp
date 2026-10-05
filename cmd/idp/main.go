// Command idp runs the identity provider and its provisioning commands.
//
//	idp [serve]                                       start the HTTP server
//	idp create-user -email E -username U              password read from stdin
//	idp create-client -name N [-confidential] [-grant G]... [-redirect-uri URI]...
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wailsb/opengo-idp/internal/config"
	"github.com/wailsb/opengo-idp/internal/infrastructure/hasher"
	jwtinfra "github.com/wailsb/opengo-idp/internal/infrastructure/jwt"
	redisinfra "github.com/wailsb/opengo-idp/internal/infrastructure/redis"
	"github.com/wailsb/opengo-idp/internal/repository/postgres"
	redisrepo "github.com/wailsb/opengo-idp/internal/repository/redis"
	"github.com/wailsb/opengo-idp/internal/transport/httpapi"
	"github.com/wailsb/opengo-idp/internal/usecase/admin"
	"github.com/wailsb/opengo-idp/internal/usecase/auth"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}

	cfg, err := config.Load(os.LookupEnv)
	if err != nil {
		return fmt.Errorf("load config: %w", err)
	}
	log := newLogger(cfg.LogLevel)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := pgxpool.New(ctx, cfg.Postgres.DSN)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("postgres ping: %w", err)
	}

	pwHasher, err := hasher.NewBcrypt(cfg.Auth.BcryptCost)
	if err != nil {
		return err
	}
	adminSvc := admin.NewService(postgres.NewUserRepository(pool), postgres.NewClientRepository(pool), pwHasher)

	switch cmd {
	case "serve":
		return serve(ctx, cfg, log, pool, pwHasher)
	case "create-user":
		return createUser(ctx, adminSvc, args)
	case "create-client":
		return createClient(ctx, adminSvc, args)
	default:
		return fmt.Errorf("unknown command %q (want serve, create-user or create-client)", cmd)
	}
}

func serve(ctx context.Context, cfg *config.Config, log *slog.Logger, pool *pgxpool.Pool, pwHasher *hasher.Bcrypt) error {
	rdb, err := redisinfra.NewClient(cfg.Redis.Addr(), cfg.Redis.Password, cfg.Redis.DB)
	if err != nil {
		return err
	}
	defer rdb.Close()

	keys, err := loadKeys(cfg.Auth.SigningKeyPath, log)
	if err != nil {
		return err
	}
	tokens, err := jwtinfra.NewService(keys, jwtinfra.Config{
		Issuer:          cfg.Auth.Issuer,
		AccessTokenTTL:  cfg.Auth.AccessTokenTTL,
		RefreshTokenTTL: cfg.Auth.RefreshTokenTTL,
		IDTokenTTL:      cfg.Auth.IDTokenTTL,
	})
	if err != nil {
		return err
	}

	authSvc, err := auth.NewService(auth.Deps{
		Users:          postgres.NewUserRepository(pool),
		Sessions:       redisrepo.NewSessionRepository(rdb),
		Clients:        postgres.NewClientRepository(pool),
		Access:         postgres.NewAccessRepository(pool),
		Hasher:         pwHasher,
		Tokens:         tokens,
		SessionTTL:     cfg.Auth.SessionTTL,
		AccessTokenTTL: cfg.Auth.AccessTokenTTL,
	})
	if err != nil {
		return err
	}

	api := httpapi.NewServer(authSvc, tokens, httpapi.Config{
		Issuer:        cfg.Auth.Issuer,
		SecureCookies: cfg.HTTP.SecureCookies,
	}, log)

	srv := &http.Server{
		Addr:              cfg.HTTP.Addr,
		Handler:           api.Handler(),
		ReadTimeout:       cfg.HTTP.ReadTimeout,
		ReadHeaderTimeout: cfg.HTTP.ReadTimeout,
		WriteTimeout:      cfg.HTTP.WriteTimeout,
	}

	errCh := make(chan error, 1)
	go func() {
		log.Info("idp listening", "addr", cfg.HTTP.Addr, "issuer", cfg.Auth.Issuer)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
	}

	log.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), cfg.HTTP.ShutdownTimeout)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}

func loadKeys(path string, log *slog.Logger) (*jwtinfra.RSAKeyProvider, error) {
	if path != "" {
		return jwtinfra.LoadRSAKeyProvider(path)
	}
	log.Warn("AUTH_SIGNING_KEY_PATH not set: using an ephemeral signing key; tokens will not survive a restart")
	return jwtinfra.GenerateRSAKeyProvider(2048)
}

func createUser(ctx context.Context, svc *admin.Service, args []string) error {
	fs := flag.NewFlagSet("create-user", flag.ContinueOnError)
	email := fs.String("email", "", "user email (required)")
	username := fs.String("username", "", "username (required)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	// The password comes from stdin, never a flag, so it stays out of shell history
	// and the process list.
	fmt.Fprint(os.Stderr, "password: ")
	password, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && password == "" {
		return fmt.Errorf("read password: %w", err)
	}
	password = strings.TrimRight(password, "\r\n")

	u, err := svc.CreateUser(ctx, admin.CreateUserInput{Email: *email, Username: *username, Password: password})
	if err != nil {
		return err
	}
	fmt.Printf("created user %s (%s)\n", u.ID, u.Email)
	return nil
}

type stringList []string

func (s *stringList) String() string     { return strings.Join(*s, ",") }
func (s *stringList) Set(v string) error { *s = append(*s, v); return nil }

func createClient(ctx context.Context, svc *admin.Service, args []string) error {
	fs := flag.NewFlagSet("create-client", flag.ContinueOnError)
	name := fs.String("name", "", "client display name (required)")
	confidential := fs.Bool("confidential", false, "issue a client secret")
	var grants, redirects stringList
	fs.Var(&grants, "grant", "allowed grant type (repeatable)")
	fs.Var(&redirects, "redirect-uri", "allowed redirect URI (repeatable)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	c, secret, err := svc.CreateClient(ctx, admin.CreateClientInput{
		Name:           *name,
		RedirectURIs:   redirects,
		GrantTypes:     grants,
		IsConfidential: *confidential,
	})
	if err != nil {
		return err
	}
	fmt.Printf("client_id:     %s\n", c.ClientID)
	if secret != "" {
		fmt.Printf("client_secret: %s\n(store it now: it cannot be shown again)\n", secret)
	}
	return nil
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	if err := lvl.UnmarshalText([]byte(level)); err != nil {
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
