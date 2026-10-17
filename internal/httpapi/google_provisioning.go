package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/supaapps/platform93/internal/kernel"
)

type provisionGoogleUser struct {
	Email            string         `json:"email"`
	FirstName        string         `json:"first_name,omitempty"`
	LastName         string         `json:"last_name,omitempty"`
	Username         *string        `json:"username,omitempty"`
	Locale           string         `json:"locale,omitempty"`
	CustomAttributes map[string]any `json:"custom_attributes,omitempty"`
}

type provisionGoogleRequest struct {
	GoogleSub string               `json:"google_sub"`
	Reason    string               `json:"reason"`
	UserID    *string              `json:"user_id,omitempty"`
	User      *provisionGoogleUser `json:"user,omitempty"`
}

type provisionGoogleResponse struct {
	User        userResponse `json:"user"`
	IdentityID  string       `json:"identity_id"`
	Provider    string       `json:"provider"`
	CreatedUser bool         `json:"created_user"`
}

func (s *Server) provisionGoogleUser(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(r.Header.Get("Idempotency-Key")) == "" {
		kernel.WriteProblem(w, r, http.StatusBadRequest, "idempotency_key_required", "Idempotency-Key is required.")
		return
	}
	var request provisionGoogleRequest
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if len(request.GoogleSub) == 0 || len(request.GoogleSub) > 255 || !utf8.ValidString(request.GoogleSub) || strings.ContainsFunc(request.GoogleSub, func(c rune) bool { return unicode.IsSpace(c) || unicode.IsControl(c) }) || strings.TrimSpace(request.Reason) == "" || utf8.RuneCountInString(request.Reason) > 500 || (request.UserID == nil) == (request.User == nil) {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_google_provisioning", "Provide a Google subject (1-255 bytes, no whitespace or controls), a reason (1-500 characters), and exactly one of user_id or user.")
		return
	}
	applicationID, err := applicationID(r)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_application_id", "The application identifier is invalid.")
		return
	}
	if request.UserID != nil {
		parsed, parseErr := uuid.Parse(*request.UserID)
		if parseErr != nil {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_user_id", "A valid user UUID is required.")
			return
		}
		value := parsed.String()
		request.UserID = &value
	}
	if request.User != nil {
		u := request.User
		u.Email = kernel.NormalizeEmail(u.Email)
		address, emailErr := mail.ParseAddress(u.Email)
		u.Locale, err = normalizeNotificationLocale(u.Locale)
		if emailErr != nil || address.Address != u.Email || err != nil || len(u.Email) > 320 || utf8.RuneCountInString(u.FirstName) > 200 || utf8.RuneCountInString(u.LastName) > 200 || u.Username != nil && utf8.RuneCountInString(*u.Username) > 200 {
			kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_provisioned_user", "Provide a valid email, locale, and profile fields of at most 200 characters.")
			return
		}
		if u.CustomAttributes == nil {
			u.CustomAttributes = map[string]any{}
		}
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		s.googleProvisioningError(w, r, err)
		return
	}
	defer rollback(tx, r.Context())
	// Serialize imports of the same identity even when they target different users.
	_, err = tx.Exec(r.Context(), `SELECT pg_advisory_xact_lock(hashtextextended($1,0))`, "google-provision:"+applicationID.String()+":"+request.GoogleSub)
	if err != nil {
		s.googleProvisioningError(w, r, err)
		return
	}
	userID := ""
	if request.UserID != nil {
		userID = *request.UserID
	} else {
		if err = enforceUserLimit(r.Context(), tx, applicationID.String()); err != nil {
			s.googleProvisioningError(w, r, err)
			return
		}
		userID = kernel.NewID().String()
		u := request.User
		attributes, _ := json.Marshal(u.CustomAttributes)
		_, err = tx.Exec(r.Context(), `INSERT INTO users(id,application_id,email,normalized_email,first_name,last_name,username,locale,custom_attributes)
VALUES($1,$2,$3,$3,$4,$5,$6,$7,$8)`, userID, applicationID, u.Email, u.FirstName, u.LastName, u.Username, u.Locale, attributes)
		if err != nil {
			s.googleProvisioningError(w, r, err)
			return
		}
	}
	var active bool
	err = tx.QueryRow(r.Context(), `SELECT status='active' FROM users WHERE application_id=$1 AND id=$2 FOR UPDATE`, applicationID, userID).Scan(&active)
	if errors.Is(err, pgx.ErrNoRows) || err == nil && !active {
		kernel.WriteProblem(w, r, http.StatusConflict, "provisioning_user_unavailable", "The target must be an active user in this application.")
		return
	}
	if err != nil {
		s.googleProvisioningError(w, r, err)
		return
	}
	var identityID, linkedUser string
	err = tx.QueryRow(r.Context(), `SELECT id,user_id FROM user_identities WHERE application_id=$1 AND provider='google' AND provider_subject=$2`, applicationID, request.GoogleSub).Scan(&identityID, &linkedUser)
	if err == nil && (linkedUser != userID || request.User != nil) {
		kernel.WriteProblem(w, r, http.StatusConflict, "google_identity_conflict", "This Google identity is already linked to another account.")
		return
	}
	newLink := errors.Is(err, pgx.ErrNoRows)
	if err != nil && !newLink {
		s.googleProvisioningError(w, r, err)
		return
	}
	if newLink {
		var hasGoogle bool
		err = tx.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM user_identities WHERE application_id=$1 AND user_id=$2 AND provider='google')`, applicationID, userID).Scan(&hasGoogle)
		if err != nil {
			s.googleProvisioningError(w, r, err)
			return
		}
		if hasGoogle {
			kernel.WriteProblem(w, r, http.StatusConflict, "google_identity_conflict", "The user already has a different Google identity. Provisioning cannot replace it.")
			return
		}
		identityID = kernel.NewID().String()
		_, err = tx.Exec(r.Context(), `INSERT INTO user_identities(id,application_id,user_id,provider,provider_subject) VALUES($1,$2,$3,'google',$4)`, identityID, applicationID, userID, request.GoogleSub)
		if err == nil && request.User != nil {
			_, err = s.app.Emit(r.Context(), tx, &applicationID, "user.created", "user/"+userID, actor(r), map[string]any{"user_id": userID, "email_verified": false, "is_org_verified": false})
		}
		if err == nil {
			_, err = s.app.Emit(r.Context(), tx, &applicationID, "user.identity.provisioned", "user/"+userID, actor(r), map[string]any{"user_id": userID, "identity_id": identityID, "provider": "google", "created_user": request.User != nil})
		}
		if err == nil {
			_, err = tx.Exec(r.Context(), `INSERT INTO audit_records(id,organization_id,application_id,actor_type,actor_id,action,target_type,target_id,reason,request_id,changes)
SELECT $1,organization_id,id,'control_user',$3,'user.identity.provisioned','user',$4,$5,$6,jsonb_build_object('identity_id',$7::text,'provider','google','created_user',$8::boolean) FROM applications WHERE id=$2`, kernel.NewID(), applicationID, actor(r).ID, userID, request.Reason, kernel.RequestID(r.Context()), identityID, request.User != nil)
		}
		if err != nil {
			s.googleProvisioningError(w, r, err)
			return
		}
	}
	user, ok := scanUser(tx.QueryRow(r.Context(), `SELECT id,application_id,email,first_name,last_name,username,locale,email_verified_at IS NOT NULL,is_org_verified,status,custom_attributes,version,created_at,updated_at FROM users WHERE id=$1 AND application_id=$2`, userID, applicationID))
	if !ok {
		s.googleProvisioningError(w, r, errors.New("user read failed"))
		return
	}
	if err = tx.Commit(r.Context()); err != nil {
		s.googleProvisioningError(w, r, err)
		return
	}
	status := http.StatusOK
	if request.User != nil {
		status = http.StatusCreated
	}
	kernel.WriteJSON(w, status, provisionGoogleResponse{User: user, IdentityID: identityID, Provider: "google", CreatedUser: request.User != nil})
}

func (s *Server) googleProvisioningError(w http.ResponseWriter, r *http.Request, err error) {
	var limit organizationLimitError
	var postgres *pgconn.PgError
	switch {
	case errors.As(err, &limit):
		kernel.WriteProblem(w, r, http.StatusConflict, "organization_user_limit_reached", limit.Error())
	case errors.As(err, &postgres) && postgres.Code == "23505":
		kernel.WriteProblem(w, r, http.StatusConflict, "google_provisioning_conflict", "The email, username, or Google identity is already in use. Select the existing user explicitly when appropriate.")
	default:
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "google_provisioning_failed", "The account and identity could not be provisioned.")
	}
}
