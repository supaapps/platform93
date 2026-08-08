package httpapi

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/identity"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
)

func (s *Server) operatorEmailStart(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Email    string `json:"email"`
		Delivery string `json:"delivery"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if request.Delivery == "" {
		request.Delivery = "both"
	}
	if request.Delivery != "code" && request.Delivery != "link" && request.Delivery != "both" {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "invalid_delivery", "Delivery must be code, link, or both.")
		return
	}
	if !s.allowAuthAttempt(w, r, "operator_email_start", kernel.NormalizeEmail(request.Email), 5, 10*time.Minute) {
		return
	}
	responseID := kernel.NewID()
	var operatorExists, configured bool
	_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM operators WHERE normalized_email=$1 AND status='active'),
EXISTS(SELECT 1 FROM installations WHERE setup_completed_at IS NOT NULL) AND EXISTS(SELECT 1 FROM notification_providers WHERE application_id IS NULL AND organization_id IS NULL AND disabled_at IS NULL)`, kernel.NormalizeEmail(request.Email)).Scan(&operatorExists, &configured)
	if operatorExists && configured {
		code := randomCode(8)
		link, _ := secure.RandomToken("p93_ops_link_", 32)
		var codeDigest, linkDigest []byte
		if request.Delivery != "link" {
			codeDigest = s.app.Vault.Digest(code)
		}
		if request.Delivery != "code" {
			linkDigest = s.app.Vault.Digest(link)
		}
		notificationID := kernel.NewID()
		deliveredCode, magicLink := code, ""
		if request.Delivery == "link" {
			deliveredCode = ""
		}
		if request.Delivery != "code" {
			magicLink = appendCredentialQuery(strings.TrimRight(s.app.PublicURL, "/")+"/?operator_challenge=true", map[string]string{"challenge_id": responseID.String(), "link_token": link})
		}
		templateID, templateLocale, payload, renderErr := s.renderSystemNotification(r.Context(), nil, operatorSignInTemplate, request.Email, map[string]any{
			"code": deliveredCode, "magic_link": magicLink, "expires_minutes": 10,
		})
		if renderErr != nil {
			kernel.WriteProblem(w, r, http.StatusInternalServerError, "challenge_template_unavailable", "The operator sign-in email template is unavailable or invalid.")
			return
		}
		tx, err := s.app.DB.Begin(r.Context())
		if err == nil {
			defer rollback(tx, r.Context())
			_, err = tx.Exec(r.Context(), `INSERT INTO operator_login_challenges
(id,normalized_email,code_digest,link_digest,expires_at) VALUES ($1,$2,$3,$4,$5)`, responseID, kernel.NormalizeEmail(request.Email), codeDigest, linkDigest, s.app.Now().Add(10*time.Minute))
			var ciphertext string
			if err == nil {
				ciphertext, err = s.app.Vault.Encrypt(payload, "notification:"+notificationID.String())
			}
			if err == nil {
				_, err = tx.Exec(r.Context(), `INSERT INTO notifications
(id,application_id,template_id,recipient,locale,payload_ciphertext,status) VALUES ($1,NULL,$2,$3,$4,$5,'queued')`, notificationID, templateID, request.Email, templateLocale, ciphertext)
			}
			if err != nil || tx.Commit(r.Context()) != nil {
				kernel.WriteProblem(w, r, http.StatusInternalServerError, "challenge_delivery_failed", "The operator challenge could not be queued.")
				return
			}
		}
	}
	kernel.WriteJSON(w, http.StatusAccepted, map[string]any{"challenge_id": responseID, "expires_in": 600})
}

func (s *Server) operatorEmailVerify(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ChallengeID string `json:"challenge_id"`
		Code        string `json:"code"`
		LinkToken   string `json:"link_token"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if !s.allowAuthAttempt(w, r, "operator_email_verify", request.ChallengeID, 10, 10*time.Minute) {
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The operator challenge could not be verified.")
		return
	}
	defer rollback(tx, r.Context())
	var normalized string
	var codeDigest, linkDigest []byte
	var attempts int
	err = tx.QueryRow(r.Context(), `SELECT normalized_email,code_digest,link_digest,attempts FROM operator_login_challenges
WHERE id=$1 AND consumed_at IS NULL AND expires_at>now() FOR UPDATE`, request.ChallengeID).Scan(&normalized, &codeDigest, &linkDigest, &attempts)
	valid := err == nil && attempts < 8 && ((request.Code != "" && equalBytes(codeDigest, s.app.Vault.Digest(strings.ToUpper(request.Code)))) || (request.LinkToken != "" && equalBytes(linkDigest, s.app.Vault.Digest(request.LinkToken))))
	if !valid {
		if err == nil {
			_, _ = tx.Exec(r.Context(), "UPDATE operator_login_challenges SET attempts=attempts+1 WHERE id=$1", request.ChallengeID)
			_ = tx.Commit(r.Context())
		}
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_operator_challenge", "The operator challenge is invalid or expired.")
		return
	}
	var operatorID string
	if tx.QueryRow(r.Context(), "SELECT id FROM operators WHERE normalized_email=$1 AND status='active'", normalized).Scan(&operatorID) != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_operator_challenge", "The operator challenge is invalid or expired.")
		return
	}
	refresh, _ := secure.RandomToken("p93_ops_refresh_", 32)
	sessionID := kernel.NewID()
	_, err = tx.Exec(r.Context(), "UPDATE operator_login_challenges SET consumed_at=now() WHERE id=$1", request.ChallengeID)
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO operator_sessions
(id,operator_id,refresh_digest,kind,ip_address,user_agent,expires_at) VALUES ($1,$2,$3,'operator',$4,$5,$6)`, sessionID, operatorID, s.app.Vault.Digest(refresh), requestIPAddress(r), truncate(r.UserAgent(), 500), s.app.Now().Add(12*time.Hour))
	}
	access, tokenErr := s.issueOperatorAccess(r.Context(), operatorID, sessionID.String(), "operator")
	if err != nil || tokenErr != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "operator_session_failed", "The operator session could not be created.")
		return
	}
	s.setOperatorCookies(w, access, refresh, 12*time.Hour)
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"access_token": access, "refresh_token": refresh, "token_type": "Bearer", "expires_in": 300})
}

func (s *Server) setupStatus(w http.ResponseWriter, r *http.Request) {
	var available, operatorEmailLoginAvailable bool
	err := s.app.DB.QueryRow(r.Context(), `SELECT setup_completed_at IS NULL AND bootstrap_digest IS NOT NULL,
EXISTS(SELECT 1 FROM notification_providers WHERE application_id IS NULL AND organization_id IS NULL AND disabled_at IS NULL)
FROM installations ORDER BY created_at LIMIT 1`).Scan(&available, &operatorEmailLoginAvailable)
	if err != nil {
		available = false
		operatorEmailLoginAvailable = false
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]bool{
		"available":                      available,
		"operator_email_login_available": operatorEmailLoginAvailable,
	})
}

type bootstrapRequest struct {
	Credential  string `json:"credential"`
	Email       string `json:"email"`
	DisplayName string `json:"display_name"`
}

func (s *Server) bootstrap(w http.ResponseWriter, r *http.Request) {
	var request bootstrapRequest
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	normalized := kernel.NormalizeEmail(request.Email)
	if normalized == "" || len(request.Credential) < 32 {
		kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_bootstrap_request", "A valid credential and operator email are required.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Setup could not be started.")
		return
	}
	defer rollback(tx, r.Context())
	var digest []byte
	var complete bool
	err = tx.QueryRow(r.Context(), `SELECT bootstrap_digest, setup_completed_at IS NOT NULL
FROM installations ORDER BY created_at LIMIT 1 FOR UPDATE`).Scan(&digest, &complete)
	want := s.app.Vault.Digest(request.Credential)
	if err != nil || complete || subtle.ConstantTimeCompare(digest, want) != 1 {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_bootstrap_credential", "The bootstrap credential is invalid or unavailable.")
		return
	}
	var operatorID string
	err = tx.QueryRow(r.Context(), `INSERT INTO operators (id,email,normalized_email,display_name)
VALUES ($1,$2,$3,$4) ON CONFLICT (normalized_email) DO UPDATE SET display_name=EXCLUDED.display_name
RETURNING id`, kernel.NewID(), request.Email, normalized, request.DisplayName).Scan(&operatorID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "operator_creation_failed", "The initial operator could not be created.")
		return
	}
	_, err = tx.Exec(r.Context(), `INSERT INTO installation_operator_roles(operator_id,role) VALUES($1,'owner')
ON CONFLICT (operator_id) DO UPDATE SET role='owner',updated_at=now()`, operatorID)
	if err == nil {
		err = s.app.EnsureSigningKey(r.Context(), tx)
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "installation_security_setup_failed", "The installation owner or signing key could not be created.")
		return
	}
	refresh, err := secure.RandomToken("p93_ops_refresh_", 32)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "credential_generation_failed", "The setup session could not be created.")
		return
	}
	sessionID := kernel.NewID()
	_, err = tx.Exec(r.Context(), `INSERT INTO operator_sessions
(id,operator_id,refresh_digest,kind,ip_address,user_agent,expires_at) VALUES ($1,$2,$3,'setup',$4,$5,$6)`,
		sessionID, operatorID, s.app.Vault.Digest(refresh), requestIPAddress(r), truncate(r.UserAgent(), 500), s.app.Now().Add(30*time.Minute))
	access, tokenErr := s.issueOperatorAccessWithQuerier(r.Context(), tx, operatorID, sessionID.String(), "setup")
	if err != nil || tokenErr != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "setup_session_failed", "The setup session could not be committed.")
		return
	}
	s.setOperatorCookies(w, access, refresh, 30*time.Minute)
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"operator_id": operatorID, "access_token": access, "refresh_token": refresh, "token_type": "Bearer", "expires_in": 300})
}

func (s *Server) completeSetup(w http.ResponseWriter, r *http.Request) {
	current := actor(r)
	operatorRefresh, err := secure.RandomToken("p93_ops_refresh_", 32)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "credential_generation_failed", "The operator session could not be created.")
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "Setup could not be completed.")
		return
	}
	defer rollback(tx, r.Context())
	result, err := tx.Exec(r.Context(), `UPDATE installations SET setup_completed_at=now(),bootstrap_digest=NULL,updated_at=now()
WHERE setup_completed_at IS NULL`)
	if err != nil || result.RowsAffected() != 1 {
		kernel.WriteProblem(w, r, http.StatusConflict, "setup_already_complete", "Installation setup is already complete.")
		return
	}
	_, err = tx.Exec(r.Context(), "UPDATE operator_sessions SET revoked_at=now() WHERE id=$1", current.SessionID)
	newSessionID := kernel.NewID()
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO operator_sessions
(id,operator_id,refresh_digest,kind,ip_address,user_agent,expires_at) VALUES ($1,$2,$3,'operator',$4,$5,$6)`,
			newSessionID, current.ID, s.app.Vault.Digest(operatorRefresh), requestIPAddress(r), truncate(r.UserAgent(), 500), s.app.Now().Add(12*time.Hour))
	}
	access, tokenErr := s.issueOperatorAccess(r.Context(), current.ID, newSessionID.String(), "operator")
	if err != nil || tokenErr != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "setup_completion_failed", "Setup could not be completed.")
		return
	}
	s.setOperatorCookies(w, access, operatorRefresh, 12*time.Hour)
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"completed": true, "access_token": access, "refresh_token": operatorRefresh, "token_type": "Bearer", "expires_in": 300})
}

func (s *Server) operatorLogout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie("p93_operator_refresh"); err == nil {
		_, _ = s.app.DB.Exec(r.Context(), "UPDATE operator_sessions SET revoked_at=now() WHERE refresh_digest=$1", s.app.Vault.Digest(cookie.Value))
	}
	s.clearOperatorCookies(w)
	w.WriteHeader(http.StatusNoContent)
}

func operatorCookie(name, value string, ttl time.Duration, secure bool) *http.Cookie {
	return &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteStrictMode, MaxAge: int(ttl.Seconds())}
}

func (s *Server) setOperatorCookies(w http.ResponseWriter, access, refresh string, refreshTTL time.Duration) {
	secureCookie := strings.HasPrefix(s.app.PublicURL, "https://")
	http.SetCookie(w, operatorCookie("p93_operator_access", access, 5*time.Minute, secureCookie))
	http.SetCookie(w, operatorCookie("p93_operator_refresh", refresh, refreshTTL, secureCookie))
}

func (s *Server) clearOperatorCookies(w http.ResponseWriter) {
	secureCookie := strings.HasPrefix(s.app.PublicURL, "https://")
	http.SetCookie(w, operatorCookie("p93_operator_access", "", -time.Hour, secureCookie))
	http.SetCookie(w, operatorCookie("p93_operator_refresh", "", -time.Hour, secureCookie))
}

func (s *Server) issueOperatorAccess(ctx context.Context, operatorID, sessionID, kind string) (string, error) {
	return s.issueOperatorAccessWithQuerier(ctx, s.app.DB, operatorID, sessionID, kind)
}

type operatorTokenQuerier interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *Server) issueOperatorAccessWithQuerier(ctx context.Context, q operatorTokenQuerier, operatorID, sessionID, kind string) (string, error) {
	scopes := []string{"/control/setup/*"}
	if kind == "operator" {
		scopes = scopes[:0]
		var role string
		if q.QueryRow(ctx, "SELECT role FROM installation_operator_roles WHERE operator_id=$1", operatorID).Scan(&role) == nil {
			if role == "owner" || role == "admin" {
				scopes = append(scopes, "/control/*")
			} else {
				scopes = append(scopes, "/control/read")
			}
		}
		rows, err := q.Query(ctx, "SELECT organization_id::text,role FROM organization_memberships WHERE operator_id=$1 ORDER BY organization_id", operatorID)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var organizationID, membershipRole string
				if rows.Scan(&organizationID, &membershipRole) == nil {
					suffix := "/read"
					if membershipRole == "owner" || membershipRole == "admin" {
						suffix = "/*"
					}
					scopes = append(scopes, "/control/organizations/"+organizationID+suffix)
				}
			}
		}
	}
	kid, privateKey, err := s.app.ActiveSigningKeyWith(ctx, q)
	if err != nil {
		return "", err
	}
	now := s.app.Now()
	return identity.Sign(privateKey, kid, identity.Claims{Issuer: s.app.Issuer(), Subject: operatorID,
		Audience: []string{s.app.ControlAudience()}, ExpiresAt: now.Add(5 * time.Minute).Unix(), IssuedAt: now.Unix(),
		NotBefore: now.Add(-5 * time.Second).Unix(), JWTID: kernel.NewID().String(), SessionID: sessionID,
		TokenKind: kind, ActorType: "operator", Scope: strings.Join(scopes, " "), AMR: []string{"email"}})
}
