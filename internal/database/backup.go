package database

import (
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

func Backup(ctx context.Context, databaseURL, destination string, stderr io.Writer) error {
	if destination == "" {
		return fmt.Errorf("backup destination is required")
	}
	abs, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(abs), 0o700); err != nil {
		return fmt.Errorf("create backup directory: %w", err)
	}
	temporary, err := os.CreateTemp(filepath.Dir(abs), ".platform93-backup-*.dump")
	if err != nil {
		return fmt.Errorf("create backup file: %w", err)
	}
	temporaryPath := temporary.Name()
	if err = temporary.Close(); err != nil {
		return err
	}
	defer os.Remove(temporaryPath)
	if err = os.Chmod(temporaryPath, 0o600); err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "pg_dump", "--format=custom", "--no-owner", "--no-privileges", "--file", temporaryPath)
	connectionEnv, _, err := libpqApplication(databaseURL)
	if err != nil {
		return err
	}
	command.Env = append(os.Environ(), connectionEnv...)
	command.Stderr = stderr
	if err = command.Run(); err != nil {
		return fmt.Errorf("pg_dump failed: %w", err)
	}
	if err = os.Rename(temporaryPath, abs); err != nil {
		return fmt.Errorf("finalize backup: %w", err)
	}
	return nil
}

func Restore(ctx context.Context, databaseURL, source string, stderr io.Writer) error {
	if source == "" {
		return fmt.Errorf("backup source is required")
	}
	if info, err := os.Stat(source); err != nil || !info.Mode().IsRegular() {
		return fmt.Errorf("backup source is not a regular file")
	}
	connectionEnv, databaseName, err := libpqApplication(databaseURL)
	if err != nil {
		return err
	}
	command := exec.CommandContext(ctx, "pg_restore", "--clean", "--if-exists", "--no-owner", "--no-privileges", "--exit-on-error", "--dbname", databaseName, source)
	command.Env = append(os.Environ(), connectionEnv...)
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("pg_restore failed: %w", err)
	}
	return nil
}

func libpqApplication(databaseURL string) ([]string, string, error) {
	config, err := pgx.ParseConfig(databaseURL)
	if err != nil {
		return nil, "", fmt.Errorf("parse database connection: %w", err)
	}
	sslMode := "require"
	if parsed, parseErr := url.Parse(databaseURL); parseErr == nil && strings.Contains(databaseURL, "://") {
		if value := parsed.Query().Get("sslmode"); value != "" {
			sslMode = value
		}
	} else if config.TLSConfig == nil {
		sslMode = "disable"
	}
	if strings.TrimSpace(config.Host) == "" || strings.TrimSpace(config.Database) == "" {
		return nil, "", fmt.Errorf("database host and name are required for backup operations")
	}
	return []string{
		"PGHOST=" + config.Host,
		"PGPORT=" + strconv.Itoa(int(config.Port)),
		"PGUSER=" + config.User,
		"PGPASSWORD=" + config.Password,
		"PGDATABASE=" + config.Database,
		"PGSSLMODE=" + sslMode,
	}, config.Database, nil
}
