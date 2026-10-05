package config

import (
	"strings"
	"testing"
	"time"
)

func lookupFrom(env map[string]string) func(string) (string, bool) {
	return func(k string) (string, bool) {
		v, ok := env[k]
		return v, ok
	}
}

func minimalEnv() map[string]string {
	return map[string]string{
		"POSTGRES_DSN": "postgres://u:p@localhost/db",
		"AUTH_ISSUER":  "https://idp.example.com",
	}
}

func TestLoad_Defaults(t *testing.T) {
	cfg, err := Load(lookupFrom(minimalEnv()))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.Addr != ":8080" || !cfg.HTTP.SecureCookies || cfg.HTTP.ReadTimeout != 10*time.Second {
		t.Errorf("http defaults: %+v", cfg.HTTP)
	}
	if cfg.Redis.Addr() != "localhost:6379" || cfg.Redis.DB != 0 {
		t.Errorf("redis defaults: %+v", cfg.Redis)
	}
	if cfg.Auth.AccessTokenTTL != 15*time.Minute || cfg.Auth.SessionTTL != 24*time.Hour || cfg.Auth.BcryptCost != 12 {
		t.Errorf("auth defaults: %+v", cfg.Auth)
	}
	if cfg.LogLevel != "info" {
		t.Errorf("log level = %q", cfg.LogLevel)
	}
}

func TestLoad_Overrides(t *testing.T) {
	env := minimalEnv()
	env["HTTP_ADDR"] = ":9000"
	env["HTTP_SECURE_COOKIES"] = "false"
	env["REDIS_PORT"] = "6380"
	env["AUTH_ACCESS_TOKEN_TTL"] = "5m"

	cfg, err := Load(lookupFrom(env))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HTTP.Addr != ":9000" || cfg.HTTP.SecureCookies || cfg.Redis.Port != 6380 || cfg.Auth.AccessTokenTTL != 5*time.Minute {
		t.Errorf("overrides not applied: %+v", cfg)
	}
}

func TestLoad_Errors(t *testing.T) {
	cases := map[string]struct {
		mutate  func(map[string]string)
		wantErr string
	}{
		"missing dsn":    {func(e map[string]string) { delete(e, "POSTGRES_DSN") }, "POSTGRES_DSN is required"},
		"missing issuer": {func(e map[string]string) { delete(e, "AUTH_ISSUER") }, "AUTH_ISSUER is required"},
		"bad int":        {func(e map[string]string) { e["REDIS_PORT"] = "abc" }, "REDIS_PORT"},
		"bad duration":   {func(e map[string]string) { e["AUTH_SESSION_TTL"] = "forever" }, "AUTH_SESSION_TTL"},
		"bad bool":       {func(e map[string]string) { e["HTTP_SECURE_COOKIES"] = "maybe" }, "HTTP_SECURE_COOKIES"},
		"negative ttl":   {func(e map[string]string) { e["AUTH_ID_TOKEN_TTL"] = "-1m" }, "AUTH_ID_TOKEN_TTL must be positive"},
		"refresh > sess": {func(e map[string]string) { e["AUTH_REFRESH_TOKEN_TTL"] = "48h" }, "must not exceed"},
		"non-url issuer": {func(e map[string]string) { e["AUTH_ISSUER"] = "idp" }, "http(s) URL"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			env := minimalEnv()
			tc.mutate(env)
			_, err := Load(lookupFrom(env))
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want error containing %q", err, tc.wantErr)
			}
		})
	}
}
