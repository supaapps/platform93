package database

import (
	"context"
	"io"
	"path/filepath"
	"testing"
)

func TestBackupAndRestoreRequirePaths(t *testing.T) {
	if Backup(context.Background(), "postgres://invalid", "", io.Discard) == nil {
		t.Fatal("backup accepted an empty destination")
	}
	if Restore(context.Background(), "postgres://invalid", filepath.Join(t.TempDir(), "missing.dump"), io.Discard) == nil {
		t.Fatal("restore accepted a missing source")
	}
}

func TestLibpqApplicationFromURI(t *testing.T) {
	values, databaseName, err := libpqApplication("postgres://user:password@db.example:5544/platform93?sslmode=verify-full")
	if err != nil {
		t.Fatal(err)
	}
	if databaseName != "platform93" {
		t.Fatalf("unexpected database name %q", databaseName)
	}
	wanted := map[string]bool{"PGHOST=db.example": true, "PGPORT=5544": true, "PGUSER=user": true, "PGPASSWORD=password": true, "PGDATABASE=platform93": true, "PGSSLMODE=verify-full": true}
	for _, value := range values {
		delete(wanted, value)
	}
	if len(wanted) != 0 {
		t.Fatalf("missing libpq variables: %v", wanted)
	}
}
