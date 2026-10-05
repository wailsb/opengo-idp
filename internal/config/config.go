// Package config loads service configuration from environment variables.
//
// Fields are bound with `env:"NAME"` (or `env:"NAME,required"`) and an optional
// `envDefault:"value"` tag. Supported kinds: string, bool, int and time.Duration.
package config

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	HTTP     HTTPConfig
	Postgres PostgresConfig
	Redis    RedisConfig
	Auth     AuthConfig
	LogLevel string `env:"LOG_LEVEL" envDefault:"info"`
}

type HTTPConfig struct {
	Addr            string        `env:"HTTP_ADDR" envDefault:":8080"`
	ReadTimeout     time.Duration `env:"HTTP_READ_TIMEOUT" envDefault:"10s"`
	WriteTimeout    time.Duration `env:"HTTP_WRITE_TIMEOUT" envDefault:"10s"`
	ShutdownTimeout time.Duration `env:"HTTP_SHUTDOWN_TIMEOUT" envDefault:"15s"`
	// SecureCookies must stay true outside local plain-HTTP development.
	SecureCookies bool `env:"HTTP_SECURE_COOKIES" envDefault:"true"`
}

type PostgresConfig struct {
	DSN string `env:"POSTGRES_DSN,required"`
}

type RedisConfig struct {
	Host     string `env:"REDIS_HOST" envDefault:"localhost"`
	Port     int    `env:"REDIS_PORT" envDefault:"6379"`
	Password string `env:"REDIS_PASSWORD"`
	DB       int    `env:"REDIS_DB" envDefault:"0"`
}

func (r RedisConfig) Addr() string {
	return fmt.Sprintf("%s:%d", r.Host, r.Port)
}

type AuthConfig struct {
	Issuer string `env:"AUTH_ISSUER,required"`
	// SigningKeyPath points to a PEM RSA private key. When empty an ephemeral key is
	// generated at startup (development only: tokens die with the process).
	SigningKeyPath  string        `env:"AUTH_SIGNING_KEY_PATH"`
	SessionTTL      time.Duration `env:"AUTH_SESSION_TTL" envDefault:"24h"`
	AccessTokenTTL  time.Duration `env:"AUTH_ACCESS_TOKEN_TTL" envDefault:"15m"`
	RefreshTokenTTL time.Duration `env:"AUTH_REFRESH_TOKEN_TTL" envDefault:"24h"`
	IDTokenTTL      time.Duration `env:"AUTH_ID_TOKEN_TTL" envDefault:"1h"`
	BcryptCost      int           `env:"AUTH_BCRYPT_COST" envDefault:"12"`
}

// Load reads configuration through lookup (os.LookupEnv in production).
func Load(lookup func(string) (string, bool)) (*Config, error) {
	cfg := &Config{}
	if err := bind(reflect.ValueOf(cfg).Elem(), lookup); err != nil {
		return nil, err
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func (c *Config) validate() error {
	var errs []error
	durations := map[string]time.Duration{
		"AUTH_SESSION_TTL":       c.Auth.SessionTTL,
		"AUTH_ACCESS_TOKEN_TTL":  c.Auth.AccessTokenTTL,
		"AUTH_REFRESH_TOKEN_TTL": c.Auth.RefreshTokenTTL,
		"AUTH_ID_TOKEN_TTL":      c.Auth.IDTokenTTL,
	}
	for name, d := range durations {
		if d <= 0 {
			errs = append(errs, fmt.Errorf("%s must be positive", name))
		}
	}
	// A refresh token outliving its session would only ever be rejected.
	if c.Auth.RefreshTokenTTL > c.Auth.SessionTTL {
		errs = append(errs, errors.New("AUTH_REFRESH_TOKEN_TTL must not exceed AUTH_SESSION_TTL"))
	}
	if !strings.HasPrefix(c.Auth.Issuer, "https://") && !strings.HasPrefix(c.Auth.Issuer, "http://") {
		errs = append(errs, errors.New("AUTH_ISSUER must be an http(s) URL"))
	}
	return errors.Join(errs...)
}

var durationType = reflect.TypeOf(time.Duration(0))

func bind(v reflect.Value, lookup func(string) (string, bool)) error {
	t := v.Type()
	var errs []error
	for i := range t.NumField() {
		field, fv := t.Field(i), v.Field(i)

		if field.Type.Kind() == reflect.Struct {
			if err := bind(fv, lookup); err != nil {
				errs = append(errs, err)
			}
			continue
		}

		tag := field.Tag.Get("env")
		if tag == "" {
			continue
		}
		name, opts, _ := strings.Cut(tag, ",")

		raw, ok := lookup(name)
		if !ok || raw == "" {
			if opts == "required" {
				errs = append(errs, fmt.Errorf("%s is required", name))
				continue
			}
			raw, ok = field.Tag.Lookup("envDefault")
			if !ok {
				continue
			}
		}

		if err := setField(fv, raw); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
		}
	}
	return errors.Join(errs...)
}

func setField(fv reflect.Value, raw string) error {
	if fv.Type() == durationType {
		d, err := time.ParseDuration(raw)
		if err != nil {
			return err
		}
		fv.SetInt(int64(d))
		return nil
	}

	switch fv.Kind() {
	case reflect.String:
		fv.SetString(raw)
	case reflect.Bool:
		b, err := strconv.ParseBool(raw)
		if err != nil {
			return err
		}
		fv.SetBool(b)
	case reflect.Int:
		n, err := strconv.Atoi(raw)
		if err != nil {
			return err
		}
		fv.SetInt(int64(n))
	default:
		return fmt.Errorf("unsupported field kind %s", fv.Kind())
	}
	return nil
}
