package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/objectstorage"
)

const (
	defaultStorageObjectBytes      = int64(25 * 1024 * 1024)
	defaultStorageEmailImageBytes  = int64(2 * 1024 * 1024)
	defaultStorageApplicationBytes = int64(10 * 1024 * 1024 * 1024)
	defaultStorageApplicationCount = int64(100_000)
)

type storageProviderRequest struct {
	Name                      string  `json:"name"`
	Endpoint                  string  `json:"endpoint"`
	Region                    string  `json:"region"`
	AccessKeyID               string  `json:"access_key_id"`
	SecretAccessKey           string  `json:"secret_access_key"`
	ForcePathStyle            bool    `json:"force_path_style"`
	PublicBucket              *string `json:"public_bucket,omitempty"`
	PrivateBucket             *string `json:"private_bucket,omitempty"`
	PublicBaseURL             *string `json:"public_base_url,omitempty"`
	Inheritable               bool    `json:"inheritable"`
	AllowPrivateEndpoint      bool    `json:"allow_private_endpoint"`
	MaxObjectBytes            int64   `json:"max_object_bytes,omitempty"`
	MaxEmailImageBytes        int64   `json:"max_email_image_bytes,omitempty"`
	MaxApplicationBytes       int64   `json:"max_application_bytes,omitempty"`
	MaxApplicationObjectCount int64   `json:"max_application_objects,omitempty"`
}

type storedStorageProvider struct {
	ID                        string
	OrganizationID            *string
	ApplicationID             *string
	Name                      string
	Endpoint                  string
	Region                    string
	ForcePathStyle            bool
	PublicBucket              *string
	PrivateBucket             *string
	PublicBaseURL             *string
	CredentialsCiphertext     string
	Inheritable               bool
	AllowPrivateEndpoint      bool
	MaxObjectBytes            int64
	MaxEmailImageBytes        int64
	MaxApplicationBytes       int64
	MaxApplicationObjectCount int64
	Status                    string
	VerifiedAt                *time.Time
	DisabledAt                *time.Time
	LastError                 *string
	Version                   int64
	CreatedAt                 time.Time
	UpdatedAt                 time.Time
}

func (s *Server) createInstallationStorageProvider(w http.ResponseWriter, r *http.Request) {
	s.createStorageProvider(w, r, installationProviderScope())
}
func (s *Server) createOrganizationStorageProvider(w http.ResponseWriter, r *http.Request) {
	s.createStorageProvider(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")))
}
func (s *Server) createApplicationStorageProvider(w http.ResponseWriter, r *http.Request) {
	s.createStorageProvider(w, r, applicationProviderScope(chi.URLParam(r, "application_id")))
}

func (s *Server) createStorageProvider(w http.ResponseWriter, r *http.Request, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, true) {
		return
	}
	var request storageProviderRequest
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	request.applyDefaults()
	config, err := request.config(scope)
	if err != nil || objectstorage.Validate(r.Context(), config) != nil || !validStorageLimits(request) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_storage_provider", storageProviderValidationDetail(err))
		return
	}
	id := kernel.NewID()
	credentials, _ := json.Marshal(map[string]string{"access_key_id": request.AccessKeyID, "secret_access_key": request.SecretAccessKey})
	ciphertext, err := s.app.Vault.Encrypt(credentials, "storage-provider:"+id.String())
	if err == nil {
		_, err = s.app.DB.Exec(r.Context(), `INSERT INTO storage_providers
(id,organization_id,application_id,name,endpoint,region,force_path_style,public_bucket,private_bucket,public_base_url,credentials_ciphertext,inheritable,allow_private_endpoint,max_object_bytes,max_email_image_bytes,max_application_bytes,max_application_objects)
VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`, id, scope.OrganizationID, scope.ApplicationID,
			strings.TrimSpace(request.Name), strings.TrimRight(strings.TrimSpace(request.Endpoint), "/"), strings.TrimSpace(request.Region), request.ForcePathStyle,
			nullableTrimmed(request.PublicBucket), nullableTrimmed(request.PrivateBucket), nullableTrimmed(request.PublicBaseURL), ciphertext,
			scope.inheritable(request.Inheritable), request.AllowPrivateEndpoint, request.MaxObjectBytes, request.MaxEmailImageBytes,
			request.MaxApplicationBytes, request.MaxApplicationObjectCount)
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "storage_provider_creation_failed", "The storage provider could not be stored.")
		return
	}
	provider, _ := s.loadStorageProvider(r.Context(), id.String(), scope, false)
	kernel.WriteJSON(w, http.StatusCreated, storageProviderResponse(provider))
}

func (request *storageProviderRequest) applyDefaults() {
	if request.MaxObjectBytes == 0 {
		request.MaxObjectBytes = defaultStorageObjectBytes
	}
	if request.MaxEmailImageBytes == 0 {
		request.MaxEmailImageBytes = defaultStorageEmailImageBytes
	}
	if request.MaxApplicationBytes == 0 {
		request.MaxApplicationBytes = defaultStorageApplicationBytes
	}
	if request.MaxApplicationObjectCount == 0 {
		request.MaxApplicationObjectCount = defaultStorageApplicationCount
	}
}

func (request storageProviderRequest) config(scope providerScope) (objectstorage.Config, error) {
	if strings.TrimSpace(request.Name) == "" || len(request.Name) > 200 {
		return objectstorage.Config{}, fmt.Errorf("provider name is required")
	}
	if request.AllowPrivateEndpoint && scope.name() != "installation" {
		return objectstorage.Config{}, fmt.Errorf("private endpoints may only be authorized by the installation")
	}
	return objectstorage.Config{Endpoint: request.Endpoint, Region: request.Region, AccessKeyID: request.AccessKeyID,
		SecretAccessKey: request.SecretAccessKey, ForcePathStyle: request.ForcePathStyle, PublicBucket: storageStringValue(request.PublicBucket),
		PrivateBucket: storageStringValue(request.PrivateBucket), PublicBaseURL: storageStringValue(request.PublicBaseURL),
		AllowPrivateEndpoint: request.AllowPrivateEndpoint}, nil
}

func validStorageLimits(request storageProviderRequest) bool {
	return request.MaxObjectBytes > 0 && request.MaxObjectBytes <= 5*1024*1024*1024 &&
		request.MaxEmailImageBytes > 0 && request.MaxEmailImageBytes <= request.MaxObjectBytes &&
		request.MaxApplicationBytes >= request.MaxObjectBytes && request.MaxApplicationObjectCount > 0 && request.MaxApplicationObjectCount <= 100_000_000
}

func storageProviderValidationDetail(err error) string {
	if err != nil {
		return err.Error()
	}
	return "The provider endpoint, credentials, buckets, or limits are invalid."
}

func nullableTrimmed(value *string) any {
	if value == nil || strings.TrimSpace(*value) == "" {
		return nil
	}
	return strings.TrimSpace(*value)
}
func storageStringValue(value *string) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(*value)
}

func (s *Server) listInstallationStorageProviders(w http.ResponseWriter, r *http.Request) {
	s.listStorageProviders(w, r, installationProviderScope())
}
func (s *Server) listOrganizationStorageProviders(w http.ResponseWriter, r *http.Request) {
	s.listStorageProviders(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")))
}
func (s *Server) listApplicationStorageProviders(w http.ResponseWriter, r *http.Request) {
	s.listStorageProviders(w, r, applicationProviderScope(chi.URLParam(r, "application_id")))
}

func (s *Server) listStorageProviders(w http.ResponseWriter, r *http.Request, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, false) {
		return
	}
	query := storageProviderSelect + ` WHERE sp.application_id IS NULL AND sp.organization_id IS NULL ORDER BY sp.created_at DESC`
	args := []any{}
	if scope.OrganizationID != nil {
		query = storageProviderSelect + ` WHERE sp.organization_id=$1 OR (sp.application_id IS NULL AND sp.organization_id IS NULL AND sp.inheritable) ORDER BY sp.organization_id NULLS LAST,sp.created_at DESC`
		args = []any{*scope.OrganizationID}
	} else if scope.ApplicationID != nil {
		query = storageProviderSelect + ` JOIN applications a ON a.id=$1 WHERE sp.application_id=$1 OR
(sp.application_id IS NULL AND sp.organization_id=a.organization_id AND sp.inheritable) OR
(sp.application_id IS NULL AND sp.organization_id IS NULL AND sp.inheritable)
ORDER BY CASE WHEN sp.application_id IS NOT NULL THEN 0 WHEN sp.organization_id IS NOT NULL THEN 1 ELSE 2 END,sp.created_at DESC`
		args = []any{*scope.ApplicationID}
	}
	rows, err := s.app.DB.Query(r.Context(), query, args...)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "storage_provider_list_failed", "Storage providers could not be loaded.")
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	publicChosen, privateChosen := false, false
	for rows.Next() {
		provider, scanErr := scanStorageProvider(rows)
		if scanErr != nil {
			continue
		}
		item := storageProviderResponse(provider)
		active := provider.Status == "active" && provider.VerifiedAt != nil
		item["effective_for_public"] = active && provider.PublicBucket != nil && !publicChosen
		item["effective_for_private"] = active && provider.PrivateBucket != nil && !privateChosen
		if item["effective_for_public"] == true {
			publicChosen = true
		}
		if item["effective_for_private"] == true {
			privateChosen = true
		}
		items = append(items, item)
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": nil})
}

func (s *Server) getInstallationStorageProvider(w http.ResponseWriter, r *http.Request) {
	s.getStorageProvider(w, r, installationProviderScope())
}
func (s *Server) getOrganizationStorageProvider(w http.ResponseWriter, r *http.Request) {
	s.getStorageProvider(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")))
}
func (s *Server) getApplicationStorageProvider(w http.ResponseWriter, r *http.Request) {
	s.getStorageProvider(w, r, applicationProviderScope(chi.URLParam(r, "application_id")))
}
func (s *Server) getStorageProvider(w http.ResponseWriter, r *http.Request, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, false) {
		return
	}
	provider, err := s.loadStorageProvider(r.Context(), chi.URLParam(r, "provider_id"), scope, true)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "storage_provider_not_found", "The storage provider was not found.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, storageProviderResponse(provider))
}

func (s *Server) updateInstallationStorageProvider(w http.ResponseWriter, r *http.Request) {
	s.updateStorageProvider(w, r, installationProviderScope())
}
func (s *Server) updateOrganizationStorageProvider(w http.ResponseWriter, r *http.Request) {
	s.updateStorageProvider(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")))
}
func (s *Server) updateApplicationStorageProvider(w http.ResponseWriter, r *http.Request) {
	s.updateStorageProvider(w, r, applicationProviderScope(chi.URLParam(r, "application_id")))
}

func (s *Server) updateStorageProvider(w http.ResponseWriter, r *http.Request, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, true) {
		return
	}
	var request struct {
		Name                      *string `json:"name"`
		Endpoint                  *string `json:"endpoint"`
		Region                    *string `json:"region"`
		AccessKeyID               *string `json:"access_key_id"`
		SecretAccessKey           *string `json:"secret_access_key"`
		ForcePathStyle            *bool   `json:"force_path_style"`
		PublicBucket              *string `json:"public_bucket"`
		PrivateBucket             *string `json:"private_bucket"`
		PublicBaseURL             *string `json:"public_base_url"`
		Inheritable               *bool   `json:"inheritable"`
		AllowPrivateEndpoint      *bool   `json:"allow_private_endpoint"`
		MaxObjectBytes            *int64  `json:"max_object_bytes"`
		MaxEmailImageBytes        *int64  `json:"max_email_image_bytes"`
		MaxApplicationBytes       *int64  `json:"max_application_bytes"`
		MaxApplicationObjectCount *int64  `json:"max_application_objects"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	provider, err := s.loadStorageProvider(r.Context(), chi.URLParam(r, "provider_id"), scope, true)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "storage_provider_not_found", "The storage provider was not found.")
		return
	}
	config, err := s.decryptStorageProvider(provider)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "storage_provider_secret_unavailable", "Storage credentials could not be decrypted.")
		return
	}
	configurationChanged := false
	if request.Name != nil {
		provider.Name = strings.TrimSpace(*request.Name)
	}
	if request.Endpoint != nil {
		configurationChanged = true
		provider.Endpoint = strings.TrimRight(strings.TrimSpace(*request.Endpoint), "/")
		config.Endpoint = provider.Endpoint
	}
	if request.Region != nil {
		configurationChanged = true
		provider.Region = strings.TrimSpace(*request.Region)
		config.Region = provider.Region
	}
	if request.AccessKeyID != nil {
		configurationChanged = true
		config.AccessKeyID = strings.TrimSpace(*request.AccessKeyID)
	}
	if request.SecretAccessKey != nil {
		configurationChanged = true
		config.SecretAccessKey = *request.SecretAccessKey
	}
	if request.ForcePathStyle != nil {
		configurationChanged = true
		provider.ForcePathStyle = *request.ForcePathStyle
		config.ForcePathStyle = *request.ForcePathStyle
	}
	if request.PublicBucket != nil {
		configurationChanged = true
		value := strings.TrimSpace(*request.PublicBucket)
		config.PublicBucket = value
		provider.PublicBucket = optionalString(value)
	}
	if request.PrivateBucket != nil {
		configurationChanged = true
		value := strings.TrimSpace(*request.PrivateBucket)
		config.PrivateBucket = value
		provider.PrivateBucket = optionalString(value)
	}
	if request.PublicBaseURL != nil {
		configurationChanged = true
		value := strings.TrimSpace(*request.PublicBaseURL)
		config.PublicBaseURL = value
		provider.PublicBaseURL = optionalString(value)
	}
	if request.AllowPrivateEndpoint != nil {
		configurationChanged = true
		if *request.AllowPrivateEndpoint && scope.name() != "installation" {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_storage_provider", "Private endpoints may only be authorized by the installation.")
			return
		}
		provider.AllowPrivateEndpoint, config.AllowPrivateEndpoint = *request.AllowPrivateEndpoint, *request.AllowPrivateEndpoint
	}
	if request.Inheritable != nil {
		provider.Inheritable = scope.inheritable(*request.Inheritable)
	}
	if request.MaxObjectBytes != nil {
		provider.MaxObjectBytes = *request.MaxObjectBytes
	}
	if request.MaxEmailImageBytes != nil {
		provider.MaxEmailImageBytes = *request.MaxEmailImageBytes
	}
	if request.MaxApplicationBytes != nil {
		provider.MaxApplicationBytes = *request.MaxApplicationBytes
	}
	if request.MaxApplicationObjectCount != nil {
		provider.MaxApplicationObjectCount = *request.MaxApplicationObjectCount
	}
	limits := storageProviderRequest{MaxObjectBytes: provider.MaxObjectBytes, MaxEmailImageBytes: provider.MaxEmailImageBytes, MaxApplicationBytes: provider.MaxApplicationBytes, MaxApplicationObjectCount: provider.MaxApplicationObjectCount}
	if provider.Name == "" || objectstorage.Validate(r.Context(), config) != nil || !validStorageLimits(limits) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_storage_provider", "The provider endpoint, credentials, buckets, or limits are invalid.")
		return
	}
	credentials, _ := json.Marshal(map[string]string{"access_key_id": config.AccessKeyID, "secret_access_key": config.SecretAccessKey})
	ciphertext, err := s.app.Vault.Encrypt(credentials, "storage-provider:"+provider.ID)
	status, verifiedAt, lastError := provider.Status, provider.VerifiedAt, provider.LastError
	if configurationChanged {
		verifiedAt, lastError = nil, nil
		if status != "disabled" {
			status = "unverified"
		}
	}
	if err == nil {
		result, updateErr := s.app.DB.Exec(r.Context(), `UPDATE storage_providers SET name=$1,endpoint=$2,region=$3,force_path_style=$4,public_bucket=$5,private_bucket=$6,public_base_url=$7,
credentials_ciphertext=$8,inheritable=$9,allow_private_endpoint=$10,max_object_bytes=$11,max_email_image_bytes=$12,max_application_bytes=$13,max_application_objects=$14,
status=$15,verified_at=$16,last_error=$17,version=version+1,updated_at=now() WHERE id=$18 AND version=$19`, provider.Name, provider.Endpoint,
			provider.Region, provider.ForcePathStyle, provider.PublicBucket, provider.PrivateBucket, provider.PublicBaseURL, ciphertext, provider.Inheritable,
			provider.AllowPrivateEndpoint, provider.MaxObjectBytes, provider.MaxEmailImageBytes, provider.MaxApplicationBytes, provider.MaxApplicationObjectCount,
			status, verifiedAt, lastError, provider.ID, provider.Version)
		err = updateErr
		if err == nil && result.RowsAffected() != 1 {
			err = fmt.Errorf("version conflict")
		}
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "storage_provider_version_conflict", "The storage provider changed concurrently.")
		return
	}
	provider, _ = s.loadStorageProvider(r.Context(), provider.ID, scope, true)
	kernel.WriteJSON(w, http.StatusOK, storageProviderResponse(provider))
}

func optionalString(value string) *string {
	if value == "" {
		return nil
	}
	return &value
}

func (s *Server) verifyInstallationStorageProvider(w http.ResponseWriter, r *http.Request) {
	s.verifyStorageProvider(w, r, installationProviderScope())
}
func (s *Server) verifyOrganizationStorageProvider(w http.ResponseWriter, r *http.Request) {
	s.verifyStorageProvider(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")))
}
func (s *Server) verifyApplicationStorageProvider(w http.ResponseWriter, r *http.Request) {
	s.verifyStorageProvider(w, r, applicationProviderScope(chi.URLParam(r, "application_id")))
}
func (s *Server) verifyStorageProvider(w http.ResponseWriter, r *http.Request, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, true) {
		return
	}
	provider, err := s.loadStorageProvider(r.Context(), chi.URLParam(r, "provider_id"), scope, true)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "storage_provider_not_found", "The storage provider was not found.")
		return
	}
	config, err := s.decryptStorageProvider(provider)
	var client *objectstorage.Client
	if err == nil {
		client, err = objectstorage.New(r.Context(), config)
	}
	if err == nil && provider.PublicBucket != nil {
		err = client.VerifyBucket(r.Context(), *provider.PublicBucket, true)
	}
	if err == nil && provider.PrivateBucket != nil {
		err = client.VerifyBucket(r.Context(), *provider.PrivateBucket, false)
	}
	if err != nil {
		message := truncate(err.Error(), 1000)
		_, _ = s.app.DB.Exec(r.Context(), "UPDATE storage_providers SET status='error',last_error=$1,verified_at=NULL,updated_at=now() WHERE id=$2", message, provider.ID)
		kernel.WriteProblem(w, r, http.StatusBadGateway, "storage_provider_verification_failed", "S3 connectivity, credentials, or bucket visibility verification failed: "+message)
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), "UPDATE storage_providers SET status='active',verified_at=now(),disabled_at=NULL,last_error=NULL,updated_at=now() WHERE id=$1", provider.ID)
	}
	applicationID := parseOptionalUUID(provider.ApplicationID)
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, applicationID, "storage.provider.verified", "storage_provider/"+provider.ID, actor(r), providerEventData(provider))
	}
	if err == nil {
		err = tx.Commit(r.Context())
	} else if tx != nil {
		_ = tx.Rollback(r.Context())
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "storage_provider_verification_save_failed", "Verification succeeded but its state could not be committed.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) disableInstallationStorageProvider(w http.ResponseWriter, r *http.Request) {
	s.disableStorageProvider(w, r, installationProviderScope())
}
func (s *Server) disableOrganizationStorageProvider(w http.ResponseWriter, r *http.Request) {
	s.disableStorageProvider(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")))
}
func (s *Server) disableApplicationStorageProvider(w http.ResponseWriter, r *http.Request) {
	s.disableStorageProvider(w, r, applicationProviderScope(chi.URLParam(r, "application_id")))
}
func (s *Server) disableStorageProvider(w http.ResponseWriter, r *http.Request, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, true) {
		return
	}
	provider, err := s.loadStorageProvider(r.Context(), chi.URLParam(r, "provider_id"), scope, true)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "storage_provider_not_found", "The storage provider was not found.")
		return
	}
	var objects, applications int64
	_ = s.app.DB.QueryRow(r.Context(), `SELECT count(*),count(DISTINCT application_id) FROM storage_objects WHERE storage_provider_id=$1 AND status<>'deleted'`, provider.ID).Scan(&objects, &applications)
	if objects > 0 && r.URL.Query().Get("confirm_affected_objects") != "true" {
		writeStorageDisableConflict(w, r, objects, applications)
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err == nil {
		_, err = tx.Exec(r.Context(), "UPDATE storage_providers SET status='disabled',disabled_at=now(),updated_at=now() WHERE id=$1", provider.ID)
	}
	if err == nil {
		_, err = s.app.Emit(r.Context(), tx, parseOptionalUUID(provider.ApplicationID), "storage.provider.disabled", "storage_provider/"+provider.ID, actor(r), providerEventData(provider))
	}
	if err == nil {
		err = tx.Commit(r.Context())
	} else if tx != nil {
		_ = tx.Rollback(r.Context())
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "storage_provider_disable_failed", "The storage provider could not be disabled.")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func writeStorageDisableConflict(w http.ResponseWriter, r *http.Request, objects, applications int64) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusConflict)
	_ = json.NewEncoder(w).Encode(kernel.Problem{Type: "https://platform93.dev/problems/storage_provider_disable_confirmation_required", Title: http.StatusText(http.StatusConflict),
		Status: http.StatusConflict, Code: "storage_provider_disable_confirmation_required", Detail: "Disabling blocks Platform93 operations but does not revoke anonymous public URLs or unexpired private URLs.",
		RequestID: kernel.RequestID(r.Context()), Errors: map[string]any{"affected_objects": objects, "affected_applications": applications}})
}

func (s *Server) enableInstallationStorageProvider(w http.ResponseWriter, r *http.Request) {
	s.enableStorageProvider(w, r, installationProviderScope())
}
func (s *Server) enableOrganizationStorageProvider(w http.ResponseWriter, r *http.Request) {
	s.enableStorageProvider(w, r, organizationProviderScope(chi.URLParam(r, "organization_id")))
}
func (s *Server) enableApplicationStorageProvider(w http.ResponseWriter, r *http.Request) {
	s.enableStorageProvider(w, r, applicationProviderScope(chi.URLParam(r, "application_id")))
}
func (s *Server) enableStorageProvider(w http.ResponseWriter, r *http.Request, scope providerScope) {
	if !s.authorizeProviderScope(w, r, scope, true) {
		return
	}
	provider, err := s.loadStorageProvider(r.Context(), chi.URLParam(r, "provider_id"), scope, true)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "storage_provider_not_found", "The storage provider was not found.")
		return
	}
	status := "unverified"
	if provider.VerifiedAt != nil {
		status = "active"
	}
	_, err = s.app.DB.Exec(r.Context(), "UPDATE storage_providers SET status=$1,disabled_at=NULL,last_error=NULL,updated_at=now() WHERE id=$2", status, provider.ID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "storage_provider_enable_failed", "The storage provider could not be enabled.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"id": provider.ID, "status": status})
}

const storageProviderSelect = `SELECT sp.id,sp.organization_id::text,sp.application_id::text,sp.name,sp.endpoint,sp.region,sp.force_path_style,
sp.public_bucket,sp.private_bucket,sp.public_base_url,sp.credentials_ciphertext,sp.inheritable,sp.allow_private_endpoint,sp.max_object_bytes,
sp.max_email_image_bytes,sp.max_application_bytes,sp.max_application_objects,sp.status,sp.verified_at,sp.disabled_at,sp.last_error,sp.version,sp.created_at,sp.updated_at FROM storage_providers sp`

type storageRow interface{ Scan(...any) error }

func scanStorageProvider(row storageRow) (storedStorageProvider, error) {
	var value storedStorageProvider
	err := row.Scan(&value.ID, &value.OrganizationID, &value.ApplicationID, &value.Name, &value.Endpoint, &value.Region, &value.ForcePathStyle,
		&value.PublicBucket, &value.PrivateBucket, &value.PublicBaseURL, &value.CredentialsCiphertext, &value.Inheritable, &value.AllowPrivateEndpoint,
		&value.MaxObjectBytes, &value.MaxEmailImageBytes, &value.MaxApplicationBytes, &value.MaxApplicationObjectCount, &value.Status, &value.VerifiedAt,
		&value.DisabledAt, &value.LastError, &value.Version, &value.CreatedAt, &value.UpdatedAt)
	return value, err
}

func (s *Server) loadStorageProvider(ctx context.Context, id string, scope providerScope, includeDisabled bool) (storedStorageProvider, error) {
	query := storageProviderSelect + ` WHERE sp.id=$1 AND sp.application_id IS NOT DISTINCT FROM $2::uuid AND sp.organization_id IS NOT DISTINCT FROM $3::uuid`
	if !includeDisabled {
		query += ` AND sp.status<>'disabled'`
	}
	return scanStorageProvider(s.app.DB.QueryRow(ctx, query, id, scope.ApplicationID, scope.OrganizationID))
}

func (s *Server) resolveStorageProvider(ctx context.Context, applicationID, visibility string) (storedStorageProvider, error) {
	bucketCheck := "sp.public_bucket IS NOT NULL"
	if visibility == "private" {
		bucketCheck = "sp.private_bucket IS NOT NULL"
	}
	query := storageProviderSelect + ` JOIN applications a ON a.id=$1 WHERE sp.status='active' AND sp.verified_at IS NOT NULL AND ` + bucketCheck + ` AND
(sp.application_id=$1 OR (sp.application_id IS NULL AND sp.organization_id=a.organization_id AND sp.inheritable) OR
 (sp.application_id IS NULL AND sp.organization_id IS NULL AND sp.inheritable))
ORDER BY CASE WHEN sp.application_id IS NOT NULL THEN 0 WHEN sp.organization_id IS NOT NULL THEN 1 ELSE 2 END,sp.created_at DESC LIMIT 1`
	return scanStorageProvider(s.app.DB.QueryRow(ctx, query, applicationID))
}

func (s *Server) resolveInstallationStorageProvider(ctx context.Context) (storedStorageProvider, error) {
	return scanStorageProvider(s.app.DB.QueryRow(ctx, storageProviderSelect+` WHERE sp.application_id IS NULL AND sp.organization_id IS NULL
AND sp.status='active' AND sp.verified_at IS NOT NULL AND sp.public_bucket IS NOT NULL ORDER BY sp.created_at DESC LIMIT 1`))
}

func (s *Server) decryptStorageProvider(provider storedStorageProvider) (objectstorage.Config, error) {
	plaintext, err := s.app.Vault.Decrypt(provider.CredentialsCiphertext, "storage-provider:"+provider.ID)
	var credentials struct {
		AccessKeyID     string `json:"access_key_id"`
		SecretAccessKey string `json:"secret_access_key"`
	}
	if err == nil {
		err = json.Unmarshal(plaintext, &credentials)
	}
	return objectstorage.Config{Endpoint: provider.Endpoint, Region: provider.Region, AccessKeyID: credentials.AccessKeyID,
		SecretAccessKey: credentials.SecretAccessKey, ForcePathStyle: provider.ForcePathStyle, PublicBucket: dereference(provider.PublicBucket),
		PrivateBucket: dereference(provider.PrivateBucket), PublicBaseURL: dereference(provider.PublicBaseURL), AllowPrivateEndpoint: provider.AllowPrivateEndpoint}, err
}

func storageProviderResponse(provider storedStorageProvider) map[string]any {
	return map[string]any{"id": provider.ID, "provider": "s3", "name": provider.Name, "scope": providerScopeName(provider),
		"organization_id": provider.OrganizationID, "application_id": provider.ApplicationID, "endpoint": provider.Endpoint, "region": provider.Region,
		"force_path_style": provider.ForcePathStyle, "public_bucket": provider.PublicBucket, "private_bucket": provider.PrivateBucket,
		"public_base_url": provider.PublicBaseURL, "credentials_configured": provider.CredentialsCiphertext != "", "inheritable": provider.Inheritable,
		"allow_private_endpoint": provider.AllowPrivateEndpoint, "max_object_bytes": provider.MaxObjectBytes,
		"max_email_image_bytes": provider.MaxEmailImageBytes, "max_application_bytes": provider.MaxApplicationBytes,
		"max_application_objects": provider.MaxApplicationObjectCount, "status": provider.Status, "verified_at": provider.VerifiedAt,
		"disabled_at": provider.DisabledAt, "last_error": provider.LastError, "version": provider.Version,
		"created_at": provider.CreatedAt, "updated_at": provider.UpdatedAt}
}

func providerScopeName(provider storedStorageProvider) string {
	if provider.ApplicationID != nil {
		return "application"
	}
	if provider.OrganizationID != nil {
		return "organization"
	}
	return "installation"
}
func providerEventData(provider storedStorageProvider) map[string]any {
	return map[string]any{"provider_id": provider.ID, "scope": providerScopeName(provider), "public_enabled": provider.PublicBucket != nil, "private_enabled": provider.PrivateBucket != nil}
}
func parseOptionalUUID(value *string) *uuid.UUID {
	if value == nil {
		return nil
	}
	parsed, err := uuid.Parse(*value)
	if err != nil {
		return nil
	}
	return &parsed
}
func dereference(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func (s *Server) storageCapabilities(ctx context.Context, applicationID string) map[string]any {
	result := map[string]any{"public_uploads_enabled": false, "private_uploads_enabled": false}
	if provider, err := s.resolveStorageProvider(ctx, applicationID, "public"); err == nil {
		result["public_uploads_enabled"] = true
		result["max_public_object_bytes"] = provider.MaxObjectBytes
		result["max_email_image_bytes"] = provider.MaxEmailImageBytes
		result["public_provider_scope"] = providerScopeName(provider)
	}
	if provider, err := s.resolveStorageProvider(ctx, applicationID, "private"); err == nil {
		result["private_uploads_enabled"] = true
		result["max_private_object_bytes"] = provider.MaxObjectBytes
		result["private_provider_scope"] = providerScopeName(provider)
	}
	return result
}
