package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/objectstorage"
)

var unsafeStorageFilename = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

type storageOwner struct {
	ApplicationID *string
	Type          string
	ID            *string
}

type storedStorageObject struct {
	ID, ProviderID, OwnerType, Visibility, BucketRole, BucketName, ObjectKey, Filename, ContentType, Status string
	ApplicationID, OwnerID, ETag, LastError                                                                 *string
	SizeBytes, Version                                                                                      int64
	Metadata                                                                                                []byte
	UploadExpiresAt, ReadyAt, DeletedAt                                                                     *time.Time
	CreatedAt, UpdatedAt                                                                                    time.Time
}

type createStorageUploadRequest struct {
	Filename    string         `json:"filename"`
	ContentType string         `json:"content_type"`
	SizeBytes   int64          `json:"size_bytes"`
	Visibility  string         `json:"visibility"`
	Purpose     string         `json:"purpose,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

func (s *Server) createMyStorageUpload(w http.ResponseWriter, r *http.Request) {
	id := actor(r).ID
	applicationID := chi.URLParam(r, "application_id")
	s.createStorageUpload(w, r, storageOwner{ApplicationID: &applicationID, Type: "user", ID: &id}, false)
}
func (s *Server) createWorkspaceStorageUpload(w http.ResponseWriter, r *http.Request) {
	id, applicationID := chi.URLParam(r, "workspace_id"), chi.URLParam(r, "application_id")
	owner := storageOwner{ApplicationID: &applicationID, Type: "workspace", ID: &id}
	if !s.authorizeRuntimeStorage(w, r, owner, "write") {
		return
	}
	s.createStorageUpload(w, r, owner, false)
}
func (s *Server) createApplicationStorageUpload(w http.ResponseWriter, r *http.Request) {
	applicationID := chi.URLParam(r, "application_id")
	owner := storageOwner{ApplicationID: &applicationID, Type: "application"}
	if !s.authorizeRuntimeStorage(w, r, owner, "write") {
		return
	}
	s.createStorageUpload(w, r, owner, false)
}
func (s *Server) createControlApplicationStorageUpload(w http.ResponseWriter, r *http.Request) {
	applicationID := chi.URLParam(r, "application_id")
	if !s.authorizeApplicationStorageControl(w, r, applicationID, true) {
		return
	}
	s.createStorageUpload(w, r, storageOwner{ApplicationID: &applicationID, Type: "application"}, true)
}
func (s *Server) createInstallationStorageUpload(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProviderScope(w, r, installationProviderScope(), true) {
		return
	}
	s.createStorageUpload(w, r, storageOwner{Type: "installation"}, true)
}

func (s *Server) createStorageUpload(w http.ResponseWriter, r *http.Request, owner storageOwner, control bool) {
	if strings.TrimSpace(r.Header.Get("Idempotency-Key")) == "" {
		kernel.WriteProblem(w, r, http.StatusBadRequest, "idempotency_key_required", "Storage upload creation requires an Idempotency-Key header.")
		return
	}
	var request createStorageUploadRequest
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	request.Filename = safeStorageFilename(request.Filename)
	request.ContentType = strings.ToLower(strings.TrimSpace(request.ContentType))
	request.Visibility = strings.ToLower(strings.TrimSpace(request.Visibility))
	if request.Filename == "" || request.SizeBytes < 1 || (request.Visibility != "public" && request.Visibility != "private") ||
		request.ContentType == "" || len(request.ContentType) > 255 || strings.ContainsAny(request.ContentType, "\r\n") ||
		(request.Purpose != "" && request.Purpose != "email_image") {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_storage_upload", "Filename, content type, positive size, and public or private visibility are required.")
		return
	}
	if owner.Type == "installation" && request.Visibility != "public" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_storage_upload", "Installation template assets must use public storage.")
		return
	}
	if request.Purpose == "email_image" && (request.Visibility != "public" || !emailImageContentType(request.ContentType)) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_email_image", "Managed email images must be public PNG, JPEG, or GIF files.")
		return
	}
	var provider storedStorageProvider
	var err error
	if owner.Type == "installation" {
		provider, err = s.resolveInstallationStorageProvider(r.Context())
	} else {
		provider, err = s.resolveStorageProvider(r.Context(), *owner.ApplicationID, request.Visibility)
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "storage_provider_unavailable", "No verified active storage provider supplies the requested bucket type.")
		return
	}
	limit := provider.MaxObjectBytes
	if request.Purpose == "email_image" {
		limit = min(limit, provider.MaxEmailImageBytes)
	}
	if request.SizeBytes > limit {
		kernel.WriteProblem(w, r, http.StatusRequestEntityTooLarge, "storage_object_too_large", fmt.Sprintf("The object exceeds the effective %d-byte limit.", limit))
		return
	}
	config, err := s.decryptStorageProvider(provider)
	var client *objectstorage.Client
	if err == nil {
		client, err = objectstorage.New(r.Context(), config)
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusBadGateway, "storage_provider_unavailable", "The storage provider could not be initialized.")
		return
	}
	bucket := config.PublicBucket
	if request.Visibility == "private" {
		bucket = config.PrivateBucket
	}
	objectID := kernel.NewID()
	key, err := s.storageObjectKey(r.Context(), owner, objectID.String(), request.Filename)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "storage_key_failed", "The storage key could not be generated.")
		return
	}
	expiresAt := s.app.Now().Add(10 * time.Minute)
	metadata := request.Metadata
	if metadata == nil {
		metadata = map[string]any{}
	}
	if request.Purpose != "" {
		metadata["purpose"] = request.Purpose
	}
	metadataJSON, err := json.Marshal(metadata)
	if err != nil || len(metadataJSON) > 16*1024 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_storage_metadata", "Object metadata must be a JSON object no larger than 16 KiB.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err == nil && owner.ApplicationID != nil {
		_, err = tx.Exec(r.Context(), "SELECT pg_advisory_xact_lock(hashtextextended($1,0))", *owner.ApplicationID)
		var usedBytes, usedObjects int64
		if err == nil {
			err = tx.QueryRow(r.Context(), `SELECT COALESCE(sum(size_bytes),0),count(*) FROM storage_objects
WHERE application_id=$1 AND status IN ('pending','ready','deleting')`, *owner.ApplicationID).Scan(&usedBytes, &usedObjects)
		}
		if err == nil && (usedBytes+request.SizeBytes > provider.MaxApplicationBytes || usedObjects+1 > provider.MaxApplicationObjectCount) {
			_ = tx.Rollback(r.Context())
			kernel.WriteProblem(w, r, http.StatusConflict, "storage_quota_exceeded", "The application storage byte or object quota would be exceeded.")
			return
		}
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO storage_objects
(id,application_id,storage_provider_id,owner_type,owner_id,visibility,bucket_role,bucket_name,object_key,filename,content_type,size_bytes,metadata,upload_expires_at)
VALUES($1,$2,$3,$4,$5,$6,$6,$7,$8,$9,$10,$11,$12,$13)`, objectID, owner.ApplicationID, provider.ID, owner.Type, owner.ID,
			request.Visibility, bucket, key, request.Filename, request.ContentType, request.SizeBytes, metadataJSON, expiresAt)
	}
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, parseOptionalUUID(owner.ApplicationID), "storage.object.upload_requested", "storage_object/"+objectID.String(), actor(r),
			storageObjectEventData(objectID.String(), owner.Type, request.Visibility, request.SizeBytes))
	}
	if err == nil && !control {
		err = s.insertStorageAudit(r.Context(), tx, r, owner.ApplicationID, "storage.upload_requested", objectID.String(), map[string]any{"visibility": request.Visibility, "size_bytes": request.SizeBytes})
	}
	if err == nil {
		err = tx.Commit(r.Context())
	} else if tx != nil {
		_ = tx.Rollback(r.Context())
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "storage_upload_creation_failed", "The upload reservation could not be committed.")
		return
	}
	uploadURL, headers, err := client.PresignPut(r.Context(), bucket, key, request.ContentType, request.SizeBytes, 10*time.Minute)
	if err != nil {
		_, _ = s.app.DB.Exec(r.Context(), "UPDATE storage_objects SET status='failed',last_error='presigning failed',updated_at=now() WHERE id=$1", objectID)
		kernel.WriteProblem(w, r, http.StatusBadGateway, "storage_upload_presign_failed", "The provider did not issue an upload URL.")
		return
	}
	response := map[string]any{"object": storageObjectResponse(storedStorageObject{ID: objectID.String(), ProviderID: provider.ID, ApplicationID: owner.ApplicationID,
		OwnerType: owner.Type, OwnerID: owner.ID, Visibility: request.Visibility, BucketRole: request.Visibility, BucketName: bucket, ObjectKey: key,
		Filename: request.Filename, ContentType: request.ContentType, SizeBytes: request.SizeBytes, Metadata: metadataJSON, Status: "pending", UploadExpiresAt: &expiresAt,
		Version: 1, CreatedAt: s.app.Now(), UpdatedAt: s.app.Now()}, ""), "upload_url": uploadURL, "upload_expires_at": expiresAt, "required_headers": uploadHeaders(headers)}
	kernel.WriteJSON(w, http.StatusCreated, response)
}

func safeStorageFilename(value string) string {
	value = filepath.Base(strings.TrimSpace(value))
	value = unsafeStorageFilename.ReplaceAllString(value, "-")
	value = strings.Trim(value, ".-_ ")
	if len(value) > 180 {
		value = value[:180]
	}
	return value
}

func (s *Server) storageObjectKey(ctx context.Context, owner storageOwner, id, filename string) (string, error) {
	if owner.Type == "installation" {
		return "installation/template-assets/" + id + "/" + filename, nil
	}
	var organizationID string
	if err := s.app.DB.QueryRow(ctx, "SELECT organization_id FROM applications WHERE id=$1 AND deleted_at IS NULL", *owner.ApplicationID).Scan(&organizationID); err != nil {
		return "", err
	}
	base := "organizations/" + organizationID + "/applications/" + *owner.ApplicationID + "/"
	switch owner.Type {
	case "application":
		base += "application/"
	case "user":
		base += "users/" + *owner.ID + "/"
	case "workspace":
		base += "workspaces/" + *owner.ID + "/"
	default:
		return "", fmt.Errorf("unsupported owner")
	}
	return base + id + "/" + filename, nil
}

func uploadHeaders(headers http.Header) map[string]string {
	result := map[string]string{}
	for key, values := range headers {
		if strings.EqualFold(key, "host") || strings.EqualFold(key, "authorization") || len(values) == 0 {
			continue
		}
		result[key] = values[0]
	}
	return result
}

func (s *Server) completeMyStorageUpload(w http.ResponseWriter, r *http.Request) {
	id, applicationID := actor(r).ID, chi.URLParam(r, "application_id")
	s.completeStorageUpload(w, r, storageOwner{ApplicationID: &applicationID, Type: "user", ID: &id}, false)
}
func (s *Server) completeWorkspaceStorageUpload(w http.ResponseWriter, r *http.Request) {
	id, applicationID := chi.URLParam(r, "workspace_id"), chi.URLParam(r, "application_id")
	owner := storageOwner{ApplicationID: &applicationID, Type: "workspace", ID: &id}
	if !s.authorizeRuntimeStorage(w, r, owner, "write") {
		return
	}
	s.completeStorageUpload(w, r, owner, false)
}
func (s *Server) completeApplicationStorageUpload(w http.ResponseWriter, r *http.Request) {
	applicationID := chi.URLParam(r, "application_id")
	owner := storageOwner{ApplicationID: &applicationID, Type: "application"}
	if !s.authorizeRuntimeStorage(w, r, owner, "write") {
		return
	}
	s.completeStorageUpload(w, r, owner, false)
}
func (s *Server) completeControlApplicationStorageUpload(w http.ResponseWriter, r *http.Request) {
	applicationID := chi.URLParam(r, "application_id")
	if !s.authorizeApplicationStorageControl(w, r, applicationID, true) {
		return
	}
	s.completeStorageUpload(w, r, storageOwner{ApplicationID: &applicationID, Type: "application"}, true)
}
func (s *Server) completeInstallationStorageUpload(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProviderScope(w, r, installationProviderScope(), true) {
		return
	}
	s.completeStorageUpload(w, r, storageOwner{Type: "installation"}, true)
}

func (s *Server) completeStorageUpload(w http.ResponseWriter, r *http.Request, owner storageOwner, control bool) {
	object, err := s.loadOwnedStorageObject(r.Context(), chi.URLParam(r, "object_id"), owner)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "storage_object_not_found", "The storage object was not found.")
		return
	}
	if object.Status == "ready" {
		s.writeStorageObject(w, r, object)
		return
	}
	if object.Status != "pending" || object.UploadExpiresAt == nil || object.UploadExpiresAt.Before(s.app.Now()) {
		kernel.WriteProblem(w, r, http.StatusConflict, "storage_upload_expired", "The upload reservation is no longer completable.")
		return
	}
	provider, err := s.loadPinnedStorageProvider(r.Context(), object.ProviderID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "storage_provider_disabled", "The pinned storage provider is disabled or unavailable.")
		return
	}
	config, err := s.decryptStorageProvider(provider)
	var client *objectstorage.Client
	if err == nil {
		client, err = objectstorage.New(r.Context(), config)
	}
	var head objectstorage.Head
	if err == nil {
		head, err = client.Head(r.Context(), object.BucketName, object.ObjectKey)
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusBadGateway, "storage_upload_not_found", "The uploaded object could not be verified at the provider.")
		return
	}
	if head.Size != object.SizeBytes || !strings.EqualFold(strings.TrimSpace(strings.Split(head.ContentType, ";")[0]), object.ContentType) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "storage_upload_mismatch", "The provider object size or content type does not match the reservation.")
		return
	}
	metadata := decodeMap(object.Metadata)
	if metadata["purpose"] == "email_image" {
		prefix, prefixErr := client.ReadPrefix(r.Context(), object.BucketName, object.ObjectKey, 32)
		if prefixErr != nil || !validEmailImageBytes(object.ContentType, prefix) {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_email_image", "The uploaded bytes do not match the declared supported image format.")
			return
		}
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err == nil {
		result, updateErr := tx.Exec(r.Context(), `UPDATE storage_objects SET status='ready',etag=$1,ready_at=now(),upload_expires_at=NULL,version=version+1,updated_at=now()
WHERE id=$2 AND status='pending' AND upload_expires_at>now()`, head.ETag, object.ID)
		err = updateErr
		if err == nil && result.RowsAffected() != 1 {
			err = fmt.Errorf("upload changed")
		}
	}
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, parseOptionalUUID(object.ApplicationID), "storage.object.ready", "storage_object/"+object.ID, actor(r), storageObjectEventData(object.ID, object.OwnerType, object.Visibility, object.SizeBytes))
	}
	if err == nil && !control {
		err = s.insertStorageAudit(r.Context(), tx, r, object.ApplicationID, "storage.upload_completed", object.ID, map[string]any{"etag": head.ETag})
	}
	if err == nil {
		err = tx.Commit(r.Context())
	} else if tx != nil {
		_ = tx.Rollback(r.Context())
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "storage_upload_completion_failed", "The verified upload could not be committed.")
		return
	}
	object.Status, object.ETag, object.UploadExpiresAt = "ready", &head.ETag, nil
	object.Version++
	s.writeStorageObject(w, r, object)
}

func emailImageContentType(value string) bool {
	return value == "image/png" || value == "image/jpeg" || value == "image/gif"
}
func validEmailImageBytes(contentType string, value []byte) bool {
	switch contentType {
	case "image/png":
		return len(value) >= 8 && bytes.Equal(value[:8], []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'})
	case "image/jpeg":
		return len(value) >= 3 && value[0] == 0xff && value[1] == 0xd8 && value[2] == 0xff
	case "image/gif":
		return len(value) >= 6 && (string(value[:6]) == "GIF87a" || string(value[:6]) == "GIF89a")
	}
	return false
}

func (s *Server) listMyStorageObjects(w http.ResponseWriter, r *http.Request) {
	id, app := actor(r).ID, chi.URLParam(r, "application_id")
	s.listStorageObjects(w, r, storageOwner{ApplicationID: &app, Type: "user", ID: &id}, nil)
}
func (s *Server) listWorkspaceStorageObjects(w http.ResponseWriter, r *http.Request) {
	id, app := chi.URLParam(r, "workspace_id"), chi.URLParam(r, "application_id")
	owner := storageOwner{ApplicationID: &app, Type: "workspace", ID: &id}
	if !s.authorizeRuntimeStorage(w, r, owner, "read") {
		return
	}
	s.listStorageObjects(w, r, owner, nil)
}
func (s *Server) listApplicationStorageObjects(w http.ResponseWriter, r *http.Request) {
	app := chi.URLParam(r, "application_id")
	owner := storageOwner{ApplicationID: &app, Type: "application"}
	if !s.authorizeRuntimeStorage(w, r, owner, "read") {
		return
	}
	s.listStorageObjects(w, r, owner, nil)
}
func (s *Server) listControlApplicationStorageObjects(w http.ResponseWriter, r *http.Request) {
	app := chi.URLParam(r, "application_id")
	if !s.authorizeApplicationStorageControl(w, r, app, false) {
		return
	}
	s.listStorageObjects(w, r, storageOwner{ApplicationID: &app}, nil)
}
func (s *Server) listInstallationStorageObjects(w http.ResponseWriter, r *http.Request) {
	if !s.authorizeProviderScope(w, r, installationProviderScope(), false) {
		return
	}
	kind := "installation"
	s.listStorageObjects(w, r, storageOwner{Type: kind}, nil)
}
func (s *Server) listOrganizationStorageObjects(w http.ResponseWriter, r *http.Request) {
	organizationID := chi.URLParam(r, "organization_id")
	if !s.authorizeProviderScope(w, r, organizationProviderScope(organizationID), false) {
		return
	}
	s.listStorageObjects(w, r, storageOwner{}, &organizationID)
}

func (s *Server) listStorageObjects(w http.ResponseWriter, r *http.Request, owner storageOwner, organizationID *string) {
	query := storageObjectSelect + ` WHERE o.status<>'deleted'`
	args := []any{}
	if organizationID != nil {
		query += ` AND EXISTS(SELECT 1 FROM applications a WHERE a.id=o.application_id AND a.organization_id=$1)`
		args = append(args, *organizationID)
	}
	if owner.ApplicationID != nil {
		args = append(args, *owner.ApplicationID)
		query += fmt.Sprintf(" AND o.application_id=$%d", len(args))
	}
	if owner.Type != "" {
		args = append(args, owner.Type)
		query += fmt.Sprintf(" AND o.owner_type=$%d", len(args))
	}
	if owner.ID != nil {
		args = append(args, *owner.ID)
		query += fmt.Sprintf(" AND o.owner_id=$%d", len(args))
	}
	if visibility := r.URL.Query().Get("visibility"); visibility == "public" || visibility == "private" {
		args = append(args, visibility)
		query += fmt.Sprintf(" AND o.visibility=$%d", len(args))
	}
	query += " ORDER BY o.created_at DESC,o.id DESC LIMIT 101"
	rows, err := s.app.DB.Query(r.Context(), query, args...)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "storage_object_list_failed", "Storage objects could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		object, scanErr := scanStorageObject(rows)
		if scanErr == nil {
			items = append(items, s.storageObjectResponseWithURL(r.Context(), object))
		}
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) getMyStorageObject(w http.ResponseWriter, r *http.Request) {
	id, app := actor(r).ID, chi.URLParam(r, "application_id")
	s.getStorageObject(w, r, storageOwner{ApplicationID: &app, Type: "user", ID: &id}, nil)
}
func (s *Server) getWorkspaceStorageObject(w http.ResponseWriter, r *http.Request) {
	id, app := chi.URLParam(r, "workspace_id"), chi.URLParam(r, "application_id")
	owner := storageOwner{ApplicationID: &app, Type: "workspace", ID: &id}
	if s.authorizeRuntimeStorage(w, r, owner, "read") {
		s.getStorageObject(w, r, owner, nil)
	}
}
func (s *Server) getApplicationStorageObject(w http.ResponseWriter, r *http.Request) {
	app := chi.URLParam(r, "application_id")
	owner := storageOwner{ApplicationID: &app, Type: "application"}
	if s.authorizeRuntimeStorage(w, r, owner, "read") {
		s.getStorageObject(w, r, owner, nil)
	}
}
func (s *Server) getControlApplicationStorageObject(w http.ResponseWriter, r *http.Request) {
	app := chi.URLParam(r, "application_id")
	if !s.authorizeApplicationStorageControl(w, r, app, false) {
		return
	}
	s.getStorageObject(w, r, storageOwner{ApplicationID: &app}, nil)
}
func (s *Server) getInstallationStorageObject(w http.ResponseWriter, r *http.Request) {
	if s.authorizeProviderScope(w, r, installationProviderScope(), false) {
		s.getStorageObject(w, r, storageOwner{Type: "installation"}, nil)
	}
}
func (s *Server) getOrganizationStorageObject(w http.ResponseWriter, r *http.Request) {
	organizationID := chi.URLParam(r, "organization_id")
	if s.authorizeProviderScope(w, r, organizationProviderScope(organizationID), false) {
		s.getStorageObject(w, r, storageOwner{}, &organizationID)
	}
}
func (s *Server) getStorageObject(w http.ResponseWriter, r *http.Request, owner storageOwner, organizationID *string) {
	object, err := s.loadStorageObjectForAccess(r.Context(), chi.URLParam(r, "object_id"), owner, organizationID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "storage_object_not_found", "The storage object was not found.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, s.storageObjectResponseWithURL(r.Context(), object))
}

func (s *Server) downloadMyStorageObject(w http.ResponseWriter, r *http.Request) {
	id, app := actor(r).ID, chi.URLParam(r, "application_id")
	s.downloadStorageObject(w, r, storageOwner{ApplicationID: &app, Type: "user", ID: &id}, nil, false)
}
func (s *Server) downloadWorkspaceStorageObject(w http.ResponseWriter, r *http.Request) {
	id, app := chi.URLParam(r, "workspace_id"), chi.URLParam(r, "application_id")
	owner := storageOwner{ApplicationID: &app, Type: "workspace", ID: &id}
	if s.authorizeRuntimeStorage(w, r, owner, "read") {
		s.downloadStorageObject(w, r, owner, nil, false)
	}
}
func (s *Server) downloadApplicationStorageObject(w http.ResponseWriter, r *http.Request) {
	app := chi.URLParam(r, "application_id")
	owner := storageOwner{ApplicationID: &app, Type: "application"}
	if s.authorizeRuntimeStorage(w, r, owner, "read") {
		s.downloadStorageObject(w, r, owner, nil, false)
	}
}
func (s *Server) downloadControlApplicationStorageObject(w http.ResponseWriter, r *http.Request) {
	app := chi.URLParam(r, "application_id")
	if !s.authorizeApplicationStorageControl(w, r, app, true) {
		return
	}
	s.downloadStorageObject(w, r, storageOwner{ApplicationID: &app}, nil, true)
}
func (s *Server) downloadInstallationStorageObject(w http.ResponseWriter, r *http.Request) {
	if s.authorizeProviderScope(w, r, installationProviderScope(), true) {
		s.downloadStorageObject(w, r, storageOwner{Type: "installation"}, nil, true)
	}
}
func (s *Server) downloadOrganizationStorageObject(w http.ResponseWriter, r *http.Request) {
	organizationID := chi.URLParam(r, "organization_id")
	if s.authorizeProviderScope(w, r, organizationProviderScope(organizationID), true) {
		s.downloadStorageObject(w, r, storageOwner{}, &organizationID, true)
	}
}
func (s *Server) downloadStorageObject(w http.ResponseWriter, r *http.Request, owner storageOwner, organizationID *string, control bool) {
	object, err := s.loadStorageObjectForAccess(r.Context(), chi.URLParam(r, "object_id"), owner, organizationID)
	if err != nil || object.Status != "ready" {
		kernel.WriteProblem(w, r, http.StatusNotFound, "storage_object_not_found", "A ready storage object was not found.")
		return
	}
	provider, err := s.loadPinnedStorageProvider(r.Context(), object.ProviderID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "storage_provider_disabled", "The pinned storage provider is disabled or unavailable.")
		return
	}
	config, err := s.decryptStorageProvider(provider)
	var client *objectstorage.Client
	if err == nil {
		client, err = objectstorage.New(r.Context(), config)
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusBadGateway, "storage_provider_unavailable", "The storage provider could not be initialized.")
		return
	}
	uri := client.PublicURL(object.BucketName, object.ObjectKey)
	expiresAt := any(nil)
	if object.Visibility == "private" {
		uri, err = client.PresignGet(r.Context(), object.BucketName, object.ObjectKey, 5*time.Minute)
		expiresAt = s.app.Now().Add(5 * time.Minute)
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusBadGateway, "storage_download_presign_failed", "The provider did not issue a download URL.")
		return
	}
	if object.Visibility == "private" && !control {
		_, _ = s.app.DB.Exec(r.Context(), `INSERT INTO audit_records(id,organization_id,application_id,actor_type,actor_id,action,target_type,target_id,request_id,changes)
SELECT $1,a.organization_id,$2,$3,$4,'storage.private_download','storage_object',$5,$6,'{}'::jsonb FROM applications a WHERE a.id=$2`, kernel.NewID(), object.ApplicationID, actor(r).Type, actor(r).ID, object.ID, kernel.RequestID(r.Context()))
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"url": uri, "expires_at": expiresAt, "visibility": object.Visibility})
}

func (s *Server) deleteMyStorageObject(w http.ResponseWriter, r *http.Request) {
	id, app := actor(r).ID, chi.URLParam(r, "application_id")
	s.deleteStorageObject(w, r, storageOwner{ApplicationID: &app, Type: "user", ID: &id}, nil, false)
}
func (s *Server) deleteWorkspaceStorageObject(w http.ResponseWriter, r *http.Request) {
	id, app := chi.URLParam(r, "workspace_id"), chi.URLParam(r, "application_id")
	owner := storageOwner{ApplicationID: &app, Type: "workspace", ID: &id}
	if s.authorizeRuntimeStorage(w, r, owner, "delete") {
		s.deleteStorageObject(w, r, owner, nil, false)
	}
}
func (s *Server) deleteApplicationStorageObject(w http.ResponseWriter, r *http.Request) {
	app := chi.URLParam(r, "application_id")
	owner := storageOwner{ApplicationID: &app, Type: "application"}
	if s.authorizeRuntimeStorage(w, r, owner, "delete") {
		s.deleteStorageObject(w, r, owner, nil, false)
	}
}
func (s *Server) deleteControlApplicationStorageObject(w http.ResponseWriter, r *http.Request) {
	app := chi.URLParam(r, "application_id")
	if !s.authorizeApplicationStorageControl(w, r, app, true) {
		return
	}
	s.deleteStorageObject(w, r, storageOwner{ApplicationID: &app}, nil, true)
}
func (s *Server) deleteInstallationStorageObject(w http.ResponseWriter, r *http.Request) {
	if s.authorizeProviderScope(w, r, installationProviderScope(), true) {
		s.deleteStorageObject(w, r, storageOwner{Type: "installation"}, nil, true)
	}
}
func (s *Server) deleteOrganizationStorageObject(w http.ResponseWriter, r *http.Request) {
	organizationID := chi.URLParam(r, "organization_id")
	if s.authorizeProviderScope(w, r, organizationProviderScope(organizationID), true) {
		s.deleteStorageObject(w, r, storageOwner{}, &organizationID, true)
	}
}
func (s *Server) deleteStorageObject(w http.ResponseWriter, r *http.Request, owner storageOwner, organizationID *string, control bool) {
	object, err := s.loadStorageObjectForAccess(r.Context(), chi.URLParam(r, "object_id"), owner, organizationID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "storage_object_not_found", "The storage object was not found.")
		return
	}
	if _, err = s.loadPinnedStorageProvider(r.Context(), object.ProviderID); err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "storage_provider_disabled", "The pinned storage provider is disabled; deletion is blocked until it is re-enabled.")
		return
	}
	var references int64
	_ = s.app.DB.QueryRow(r.Context(), "SELECT count(*) FROM notification_template_assets WHERE storage_object_id=$1", object.ID).Scan(&references)
	force := control && r.URL.Query().Get("force") == "true"
	if references > 0 && !force {
		kernel.WriteProblem(w, r, http.StatusConflict, "storage_object_referenced", "The managed image is referenced by an email template. Use an explicitly audited force deletion to break those references.")
		return
	}
	if force && strings.TrimSpace(r.Header.Get("X-Audit-Reason")) == "" {
		kernel.WriteProblem(w, r, http.StatusBadRequest, "audit_reason_required", "X-Audit-Reason is required for forced template asset deletion.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err == nil && force {
		_, err = tx.Exec(r.Context(), "DELETE FROM notification_template_assets WHERE storage_object_id=$1", object.ID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), "UPDATE storage_objects SET status='deleting',version=version+1,updated_at=now() WHERE id=$1 AND status IN ('pending','ready','failed')", object.ID)
	}
	if err == nil && !control {
		err = s.insertStorageAudit(r.Context(), tx, r, object.ApplicationID, "storage.delete_requested", object.ID, map[string]any{"force": false})
	}
	if err == nil {
		err = tx.Commit(r.Context())
	} else if tx != nil {
		_ = tx.Rollback(r.Context())
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "storage_delete_failed", "Object deletion could not be queued.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) authorizeRuntimeStorage(w http.ResponseWriter, r *http.Request, owner storageOwner, action string) bool {
	current := actor(r)
	prefix := "/applications/" + *owner.ApplicationID
	if owner.Type == "workspace" {
		prefix += "/workspaces/" + *owner.ID
	}
	wanted := prefix + "/storage/" + action
	if actorHasPermission(current, wanted) {
		return true
	}
	kernel.WriteProblem(w, r, http.StatusForbidden, "storage_permission_required", "The actor does not have "+wanted+" permission.")
	return false
}

func (s *Server) authorizeApplicationStorageControl(w http.ResponseWriter, r *http.Request, applicationID string, write bool) bool {
	var organizationID string
	if err := s.app.DB.QueryRow(r.Context(), "SELECT organization_id FROM applications WHERE id=$1 AND deleted_at IS NULL", applicationID).Scan(&organizationID); err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "application_not_found", "The application was not found.")
		return false
	}
	if write {
		if _, allowed := s.organizationManagementRole(r, organizationID); allowed {
			return true
		}
		kernel.WriteProblem(w, r, http.StatusForbidden, "organization_permission_required", "An organization owner or administrator is required to manage application storage.")
		return false
	}
	if s.controlUserBelongsToOrganization(r, organizationID) {
		return true
	}
	kernel.WriteProblem(w, r, http.StatusNotFound, "application_not_found", "The application was not found.")
	return false
}

const storageObjectSelect = `SELECT o.id,o.application_id::text,o.storage_provider_id,o.owner_type,o.owner_id::text,o.visibility,o.bucket_role,o.bucket_name,o.object_key,
o.filename,o.content_type,o.size_bytes,o.etag,o.metadata,o.status,o.upload_expires_at,o.ready_at,o.deleted_at,o.last_error,o.version,o.created_at,o.updated_at FROM storage_objects o`

func scanStorageObject(row storageRow) (storedStorageObject, error) {
	var value storedStorageObject
	err := row.Scan(&value.ID, &value.ApplicationID, &value.ProviderID, &value.OwnerType, &value.OwnerID, &value.Visibility, &value.BucketRole,
		&value.BucketName, &value.ObjectKey, &value.Filename, &value.ContentType, &value.SizeBytes, &value.ETag, &value.Metadata, &value.Status,
		&value.UploadExpiresAt, &value.ReadyAt, &value.DeletedAt, &value.LastError, &value.Version, &value.CreatedAt, &value.UpdatedAt)
	return value, err
}
func (s *Server) loadOwnedStorageObject(ctx context.Context, id string, owner storageOwner) (storedStorageObject, error) {
	query := storageObjectSelect + ` WHERE o.id=$1 AND o.application_id IS NOT DISTINCT FROM $2::uuid AND o.owner_type=$3 AND o.owner_id IS NOT DISTINCT FROM $4::uuid AND o.status<>'deleted'`
	return scanStorageObject(s.app.DB.QueryRow(ctx, query, id, owner.ApplicationID, owner.Type, owner.ID))
}
func (s *Server) loadStorageObjectForAccess(ctx context.Context, id string, owner storageOwner, organizationID *string) (storedStorageObject, error) {
	query := storageObjectSelect + ` WHERE o.id=$1 AND o.status<>'deleted'`
	args := []any{id}
	if organizationID != nil {
		args = append(args, *organizationID)
		query += fmt.Sprintf(" AND EXISTS(SELECT 1 FROM applications a WHERE a.id=o.application_id AND a.organization_id=$%d)", len(args))
	}
	if owner.ApplicationID != nil {
		args = append(args, *owner.ApplicationID)
		query += fmt.Sprintf(" AND o.application_id=$%d", len(args))
	}
	if owner.Type != "" {
		args = append(args, owner.Type)
		query += fmt.Sprintf(" AND o.owner_type=$%d", len(args))
	}
	if owner.ID != nil {
		args = append(args, *owner.ID)
		query += fmt.Sprintf(" AND o.owner_id=$%d", len(args))
	}
	return scanStorageObject(s.app.DB.QueryRow(ctx, query, args...))
}
func (s *Server) loadPinnedStorageProvider(ctx context.Context, id string) (storedStorageProvider, error) {
	return scanStorageProvider(s.app.DB.QueryRow(ctx, storageProviderSelect+` WHERE sp.id=$1 AND sp.status='active' AND sp.verified_at IS NOT NULL`, id))
}
func storageObjectResponse(object storedStorageObject, publicURL string) map[string]any {
	return map[string]any{"id": object.ID, "application_id": object.ApplicationID, "provider_id": object.ProviderID, "owner_type": object.OwnerType,
		"owner_id": object.OwnerID, "visibility": object.Visibility, "filename": object.Filename, "content_type": object.ContentType,
		"size_bytes": object.SizeBytes, "etag": object.ETag, "metadata": decodeMap(object.Metadata), "status": object.Status,
		"public_url": optionalResponseString(publicURL), "upload_expires_at": object.UploadExpiresAt, "ready_at": object.ReadyAt,
		"deleted_at": object.DeletedAt, "last_error": object.LastError, "version": object.Version, "created_at": object.CreatedAt, "updated_at": object.UpdatedAt}
}
func (s *Server) storageObjectResponseWithURL(ctx context.Context, object storedStorageObject) map[string]any {
	uri := ""
	if object.Status == "ready" && object.Visibility == "public" {
		if provider, err := s.loadPinnedStorageProvider(ctx, object.ProviderID); err == nil {
			if config, configErr := s.decryptStorageProvider(provider); configErr == nil {
				if client, clientErr := objectstorage.New(ctx, config); clientErr == nil {
					uri = client.PublicURL(object.BucketName, object.ObjectKey)
				}
			}
		}
	}
	return storageObjectResponse(object, uri)
}
func (s *Server) writeStorageObject(w http.ResponseWriter, r *http.Request, object storedStorageObject) {
	kernel.WriteJSON(w, http.StatusOK, s.storageObjectResponseWithURL(r.Context(), object))
}
func optionalResponseString(value string) any {
	if value == "" {
		return nil
	}
	return value
}
func storageObjectEventData(id, ownerType, visibility string, size int64) map[string]any {
	return map[string]any{"object_id": id, "owner_type": ownerType, "visibility": visibility, "size_bytes": size}
}
func (s *Server) insertStorageAudit(ctx context.Context, tx pgx.Tx, r *http.Request, applicationID *string, action, objectID string, changes any) error {
	if applicationID == nil {
		return nil
	}
	encoded, _ := json.Marshal(changes)
	current := actor(r)
	_, err := tx.Exec(ctx, `INSERT INTO audit_records(id,organization_id,application_id,actor_type,actor_id,action,target_type,target_id,request_id,changes)
SELECT $1,a.organization_id,$2,$3,$4,$5,'storage_object',$6,$7,$8 FROM applications a WHERE a.id=$2`, kernel.NewID(), *applicationID,
		current.Type, current.ID, action, objectID, kernel.RequestID(ctx), encoded)
	return err
}
