package httpapi

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/objectstorage"
	"github.com/supaapps/platform93/internal/platform"
)

// RunStorageSweep expires abandoned reservations and completes queued S3
// deletions. Row locks make the sweep safe across any number of workers.
func RunStorageSweep(ctx context.Context, app *platform.App) error {
	_, err := app.DB.Exec(ctx, `UPDATE storage_objects SET status='deleting',last_error='upload reservation expired',version=version+1,updated_at=now()
WHERE id IN (SELECT id FROM storage_objects WHERE status='pending' AND upload_expires_at<=now() ORDER BY upload_expires_at LIMIT 100 FOR UPDATE SKIP LOCKED)`)
	if err != nil {
		return err
	}
	server := &Server{app: app}
	for range 25 {
		processed, processErr := server.deleteOneStorageObject(ctx)
		if processErr != nil {
			return processErr
		}
		if !processed {
			break
		}
	}
	return nil
}

func (s *Server) deleteOneStorageObject(ctx context.Context) (bool, error) {
	tx, err := s.app.DB.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer tx.Rollback(ctx)
	object, err := scanStorageObject(tx.QueryRow(ctx, storageObjectSelect+` JOIN storage_providers sp ON sp.id=o.storage_provider_id
WHERE o.status='deleting' AND sp.status='active' AND sp.verified_at IS NOT NULL
ORDER BY o.updated_at,o.id FOR UPDATE OF o SKIP LOCKED LIMIT 1`))
	if err == pgx.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	provider, err := scanStorageProvider(tx.QueryRow(ctx, storageProviderSelect+` WHERE sp.id=$1 AND sp.status='active' AND sp.verified_at IS NOT NULL`, object.ProviderID))
	if err != nil {
		return true, err
	}
	config, err := s.decryptStorageProvider(provider)
	var client *objectstorage.Client
	if err == nil {
		client, err = objectstorage.New(ctx, config)
	}
	if err == nil {
		deleteContext, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = client.Delete(deleteContext, object.BucketName, object.ObjectKey)
		cancel()
	}
	if err != nil {
		_, updateErr := tx.Exec(ctx, "UPDATE storage_objects SET last_error=$1,updated_at=now() WHERE id=$2", truncate(err.Error(), 1000), object.ID)
		if updateErr != nil {
			return true, updateErr
		}
		return true, tx.Commit(ctx)
	}
	_, err = tx.Exec(ctx, `UPDATE storage_objects SET status='deleted',deleted_at=now(),last_error=NULL,version=version+1,updated_at=now() WHERE id=$1`, object.ID)
	if err == nil {
		_, err = s.app.Emit(ctx, tx, parseOptionalUUID(object.ApplicationID), "storage.object.deleted", "storage_object/"+object.ID,
			map[string]any{"type": "worker"}, storageObjectEventData(object.ID, object.OwnerType, object.Visibility, object.SizeBytes))
	}
	if err != nil {
		return true, fmt.Errorf("commit storage deletion: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return true, err
	}
	return true, nil
}
