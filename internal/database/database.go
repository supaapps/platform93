package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"
	"github.com/riverqueue/river/riverdriver/riverpgxv5"
	"github.com/riverqueue/river/rivermigrate"
	"github.com/supaapps/platform93/migrations"
)

func Open(ctx context.Context, databaseURL string) (*pgxpool.Pool, error) {
	config, err := pgxpool.ParseConfig(databaseURL)
	if err != nil {
		return nil, fmt.Errorf("parse database configuration: %w", err)
	}
	config.MinConns = 2
	config.MaxConns = 20
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("ping database: %w", err)
	}
	return pool, nil
}

func Migrate(databaseURL string) error {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	if err := goose.Up(db, "."); err != nil {
		return err
	}
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	migrator, err := rivermigrate.New(riverpgxv5.New(pool), nil)
	if err != nil {
		return err
	}
	_, err = migrator.Migrate(context.Background(), rivermigrate.DirectionUp, nil)
	return err
}

func Status(databaseURL string) error {
	db, err := sql.Open("pgx", databaseURL)
	if err != nil {
		return err
	}
	defer db.Close()
	goose.SetBaseFS(migrations.FS)
	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	if err := goose.Status(db, "."); err != nil {
		return err
	}
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	migrator, err := rivermigrate.New(riverpgxv5.New(pool), nil)
	if err != nil {
		return err
	}
	result, err := migrator.Validate(context.Background(), nil)
	if err != nil {
		return err
	}
	if !result.OK {
		return fmt.Errorf("River migrations are incomplete: %s", result.Messages)
	}
	return nil
}

func ValidateAuthorization(databaseURL string) error {
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		return err
	}
	defer pool.Close()
	var invalidRoles int
	if err = pool.QueryRow(context.Background(), `SELECT count(*) FROM roles
WHERE key !~ '^[a-z][a-z0-9_-]{0,62}$' OR NOT public.valid_permission_keys(permissions)`).Scan(&invalidRoles); err != nil {
		return fmt.Errorf("validate role permissions: %w", err)
	}
	var invalidGrants int
	if err = pool.QueryRow(context.Background(), `SELECT count(*) FROM permission_grants
WHERE NOT public.valid_permission_key(permission) OR split_part(permission,':',1)='roles'
OR canonical_scope <> '/applications/' || application_id::text ||
CASE WHEN workspace_id IS NULL THEN '' ELSE '/workspaces/' || workspace_id::text END || '/' || replace(permission,':','/')`).Scan(&invalidGrants); err != nil {
		return fmt.Errorf("validate direct permission grants: %w", err)
	}
	if invalidRoles != 0 || invalidGrants != 0 {
		return fmt.Errorf("authorization data is invalid: roles=%d permission_grants=%d", invalidRoles, invalidGrants)
	}
	return nil
}
