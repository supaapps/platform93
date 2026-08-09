package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/kernel"
	"github.com/supaapps/platform93/internal/secure"
)

type platformWebAuthnUser struct {
	id          []byte
	email       string
	displayName string
	credentials []webauthnlib.Credential
	methodIDs   map[string]string
}

func (u platformWebAuthnUser) WebAuthnID() []byte                            { return u.id }
func (u platformWebAuthnUser) WebAuthnName() string                          { return u.email }
func (u platformWebAuthnUser) WebAuthnDisplayName() string                   { return u.displayName }
func (u platformWebAuthnUser) WebAuthnCredentials() []webauthnlib.Credential { return u.credentials }

type webAuthnQueryer interface {
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

func (s *Server) beginWebAuthnRegistration(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Origin string `json:"origin,omitempty"`
		Label  string `json:"label,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	wa, origin, err := s.webAuthnForOrigin(r, request.Origin)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "untrusted_webauthn_origin", err.Error())
		return
	}
	rpID, _ := url.Parse(origin)
	user, err := s.loadWebAuthnUser(r.Context(), s.app.DB, chi.URLParam(r, "application_id"), actor(r).ID, rpID.Hostname())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusNotFound, "account_unavailable", "The account is unavailable.")
		return
	}
	options, session, err := wa.BeginRegistration(user)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "webauthn_registration_failed", "WebAuthn registration options could not be created.")
		return
	}
	ceremonyID := kernel.NewID()
	encoded, _ := json.Marshal(session)
	ciphertext, err := s.app.Vault.Encrypt(encoded, "webauthn-ceremony:"+ceremonyID.String())
	if err == nil {
		_, err = s.app.DB.Exec(r.Context(), `INSERT INTO webauthn_ceremonies
(id,application_id,user_id,user_session_id,intent,origin,label,session_ciphertext,expires_at)
VALUES ($1,$2,$3,$4,'register',$5,$6,$7,$8)`, ceremonyID, chi.URLParam(r, "application_id"), actor(r).ID,
			actor(r).SessionID, origin, truncate(strings.TrimSpace(request.Label), 120), ciphertext, session.Expires)
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "webauthn_registration_failed", "The WebAuthn ceremony could not be stored.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"ceremony_id": ceremonyID, "options": options, "expires_at": session.Expires})
}

func (s *Server) finishWebAuthnRegistration(w http.ResponseWriter, r *http.Request) {
	var request struct {
		CeremonyID string          `json:"ceremony_id"`
		Credential json.RawMessage `json:"credential"`
	}
	if !kernel.DecodeJSON(w, r, &request) || request.CeremonyID == "" || len(request.Credential) == 0 {
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The WebAuthn registration could not be completed.")
		return
	}
	defer rollback(tx, r.Context())
	var ciphertext, origin, label string
	err = tx.QueryRow(r.Context(), `SELECT session_ciphertext,origin,label FROM webauthn_ceremonies
WHERE id=$1 AND application_id=$2 AND user_id=$3 AND user_session_id=$4 AND intent='register'
AND consumed_at IS NULL AND expires_at>now() FOR UPDATE`, request.CeremonyID, chi.URLParam(r, "application_id"), actor(r).ID,
		actor(r).SessionID).Scan(&ciphertext, &origin, &label)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_webauthn_ceremony", "The WebAuthn ceremony is invalid or expired.")
		return
	}
	wa, _, err := s.webAuthnForOrigin(r, origin)
	var session webauthnlib.SessionData
	if err == nil {
		var encoded []byte
		encoded, err = s.app.Vault.Decrypt(ciphertext, "webauthn-ceremony:"+request.CeremonyID)
		if err == nil {
			err = json.Unmarshal(encoded, &session)
		}
	}
	user, userErr := s.loadWebAuthnUser(r.Context(), tx, chi.URLParam(r, "application_id"), actor(r).ID, session.RelyingPartyID)
	parsed, parseErr := protocol.ParseCredentialCreationResponseBytes(request.Credential)
	if err != nil || userErr != nil || parseErr != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_webauthn_response", "The WebAuthn registration response is invalid.")
		return
	}
	credential, err := wa.CreateCredential(user, session, parsed)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "webauthn_verification_failed", "The WebAuthn registration response could not be verified.")
		return
	}
	methodID := kernel.NewID()
	credentialJSON, _ := json.Marshal(credential)
	credentialCiphertext, err := s.app.Vault.Encrypt(credentialJSON,
		"webauthn:"+chi.URLParam(r, "application_id")+":"+actor(r).ID+":"+methodID.String())
	if err == nil {
		_, err = tx.Exec(r.Context(), `INSERT INTO user_authentication_methods
(id,application_id,user_id,method_type,label,credential_id,credential_ciphertext,webauthn_rp_id,status,activated_at)
VALUES ($1,$2,$3,'webauthn',$4,$5,$6,$7,'active',now())`, methodID, chi.URLParam(r, "application_id"), actor(r).ID,
			label, credential.ID, credentialCiphertext, session.RelyingPartyID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE webauthn_ceremonies SET consumed_at=now() WHERE id=$1`, request.CeremonyID)
	}
	var recoveryCodes []string
	if err == nil {
		recoveryCodes, err = s.ensureRecoveryCodes(r.Context(), tx, chi.URLParam(r, "application_id"), actor(r).ID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusConflict, "webauthn_registration_failed", "The WebAuthn credential already exists or could not be saved.")
		return
	}
	kernel.WriteJSON(w, http.StatusOK, map[string]any{"method_id": methodID, "recovery_codes": recoveryCodes})
}

func (s *Server) beginWebAuthnAuthentication(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ChallengeID string `json:"challenge_id"`
		Origin      string `json:"origin,omitempty"`
	}
	if !kernel.DecodeJSON(w, r, &request) {
		return
	}
	if !s.allowAuthAttempt(w, r, "webauthn_mfa_begin", request.ChallengeID, 10, 10*time.Minute) {
		return
	}
	var userID string
	err := s.app.DB.QueryRow(r.Context(), `SELECT user_id FROM mfa_login_challenges
WHERE id=$1 AND application_id=$2 AND consumed_at IS NULL AND expires_at>now() AND attempts<8`,
		request.ChallengeID, chi.URLParam(r, "application_id")).Scan(&userID)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_mfa_challenge", "The MFA challenge is invalid or expired.")
		return
	}
	wa, origin, err := s.webAuthnForOrigin(r, request.Origin)
	rpID, _ := url.Parse(origin)
	user, userErr := s.loadWebAuthnUser(r.Context(), s.app.DB, chi.URLParam(r, "application_id"), userID, rpID.Hostname())
	if err != nil || userErr != nil || len(user.credentials) == 0 {
		kernel.WriteProblem(w, r, http.StatusUnprocessableEntity, "webauthn_unavailable", "WebAuthn is unavailable for this challenge and origin.")
		return
	}
	options, session, err := wa.BeginLogin(user)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "webauthn_authentication_failed", "WebAuthn authentication options could not be created.")
		return
	}
	ceremonyID := kernel.NewID()
	encoded, _ := json.Marshal(session)
	ciphertext, err := s.app.Vault.Encrypt(encoded, "webauthn-ceremony:"+ceremonyID.String())
	if err == nil {
		_, err = s.app.DB.Exec(r.Context(), `INSERT INTO webauthn_ceremonies
(id,application_id,user_id,mfa_challenge_id,intent,origin,session_ciphertext,expires_at)
VALUES ($1,$2,$3,$4,'authenticate',$5,$6,$7)`, ceremonyID, chi.URLParam(r, "application_id"), userID,
			request.ChallengeID, origin, ciphertext, session.Expires)
	}
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "webauthn_authentication_failed", "The WebAuthn ceremony could not be stored.")
		return
	}
	kernel.WriteJSON(w, http.StatusCreated, map[string]any{"ceremony_id": ceremonyID, "options": options, "expires_at": session.Expires})
}

func (s *Server) finishWebAuthnAuthentication(w http.ResponseWriter, r *http.Request) {
	var request struct {
		CeremonyID string          `json:"ceremony_id"`
		Credential json.RawMessage `json:"credential"`
	}
	if !kernel.DecodeJSON(w, r, &request) || request.CeremonyID == "" || len(request.Credential) == 0 {
		return
	}
	if !s.allowAuthAttempt(w, r, "webauthn_mfa_finish", request.CeremonyID, 10, 10*time.Minute) {
		return
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "database_error", "The WebAuthn authentication could not be completed.")
		return
	}
	defer rollback(tx, r.Context())
	var ciphertext, origin, userID, challengeID string
	var primaryAMR []string
	err = tx.QueryRow(r.Context(), `SELECT c.session_ciphertext,c.origin,c.user_id,c.mfa_challenge_id,m.primary_amr
FROM webauthn_ceremonies c JOIN mfa_login_challenges m ON m.id=c.mfa_challenge_id
WHERE c.id=$1 AND c.application_id=$2 AND c.intent='authenticate' AND c.consumed_at IS NULL AND c.expires_at>now()
AND m.consumed_at IS NULL AND m.expires_at>now() AND m.attempts<8 FOR UPDATE OF c,m`, request.CeremonyID,
		chi.URLParam(r, "application_id")).Scan(&ciphertext, &origin, &userID, &challengeID, &primaryAMR)
	if err != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_webauthn_ceremony", "The WebAuthn ceremony is invalid or expired.")
		return
	}
	wa, _, err := s.webAuthnForOrigin(r, origin)
	var session webauthnlib.SessionData
	if err == nil {
		var encoded []byte
		encoded, err = s.app.Vault.Decrypt(ciphertext, "webauthn-ceremony:"+request.CeremonyID)
		if err == nil {
			err = json.Unmarshal(encoded, &session)
		}
	}
	user, userErr := s.loadWebAuthnUser(r.Context(), tx, chi.URLParam(r, "application_id"), userID, session.RelyingPartyID)
	parsed, parseErr := protocol.ParseCredentialRequestResponseBytes(request.Credential)
	if err != nil || userErr != nil || parseErr != nil {
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "invalid_webauthn_response", "The WebAuthn authentication response is invalid.")
		return
	}
	credential, err := wa.ValidateLogin(user, session, parsed)
	if err != nil {
		_, _ = tx.Exec(r.Context(), `UPDATE mfa_login_challenges SET attempts=attempts+1 WHERE id=$1`, challengeID)
		_ = tx.Commit(r.Context())
		kernel.WriteProblem(w, r, http.StatusUnauthorized, "webauthn_verification_failed", "The WebAuthn authentication response could not be verified.")
		return
	}
	methodID := user.methodIDs[string(credential.ID)]
	credentialJSON, _ := json.Marshal(credential)
	credentialCiphertext, err := s.app.Vault.Encrypt(credentialJSON,
		"webauthn:"+chi.URLParam(r, "application_id")+":"+userID+":"+methodID)
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE user_authentication_methods SET credential_ciphertext=$1,last_used_at=now()
WHERE id=$2 AND application_id=$3 AND user_id=$4 AND status='active'`, credentialCiphertext, methodID,
			chi.URLParam(r, "application_id"), userID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE webauthn_ceremonies SET consumed_at=now() WHERE id=$1`, request.CeremonyID)
	}
	if err == nil {
		_, err = tx.Exec(r.Context(), `UPDATE mfa_login_challenges SET consumed_at=now() WHERE id=$1`, challengeID)
	}
	if err != nil || tx.Commit(r.Context()) != nil {
		kernel.WriteProblem(w, r, http.StatusInternalServerError, "webauthn_authentication_failed", "The WebAuthn authentication could not be committed.")
		return
	}
	s.issueSession(w, r, userID, append(primaryAMR, "webauthn"))
}

func (s *Server) webAuthnForOrigin(r *http.Request, requested string) (*webauthnlib.WebAuthn, string, error) {
	if strings.TrimSpace(requested) == "" {
		requested = s.app.PublicURL
	}
	parsed, err := url.Parse(requested)
	if err != nil || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return nil, "", &webAuthnOriginError{"The WebAuthn origin is invalid."}
	}
	origin := parsed.Scheme + "://" + parsed.Host
	publicURL, _ := url.Parse(s.app.PublicURL)
	publicOrigin := ""
	if publicURL != nil {
		publicOrigin = publicURL.Scheme + "://" + publicURL.Host
	}
	trusted := origin == publicOrigin
	if !trusted && parsed.Scheme == "https" {
		_ = s.app.DB.QueryRow(r.Context(), `SELECT EXISTS(SELECT 1 FROM application_domains
WHERE application_id=$1 AND hostname=$2 AND verified_at IS NOT NULL)`, chi.URLParam(r, "application_id"), strings.ToLower(parsed.Hostname())).Scan(&trusted)
	}
	if !trusted || parsed.Scheme != "https" && origin != publicOrigin {
		return nil, "", &webAuthnOriginError{"The WebAuthn origin is not verified for this application."}
	}
	var applicationName string
	if s.app.DB.QueryRow(r.Context(), `SELECT name FROM applications WHERE id=$1 AND deleted_at IS NULL`, chi.URLParam(r, "application_id")).Scan(&applicationName) != nil {
		return nil, "", &webAuthnOriginError{"The application is unavailable."}
	}
	wa, err := webauthnlib.New(&webauthnlib.Config{RPID: parsed.Hostname(), RPDisplayName: applicationName, RPOrigins: []string{origin},
		AuthenticatorSelection: protocol.AuthenticatorSelection{ResidentKey: protocol.ResidentKeyRequirementPreferred, UserVerification: protocol.VerificationRequired}})
	return wa, origin, err
}

type webAuthnOriginError struct{ message string }

func (e *webAuthnOriginError) Error() string { return e.message }

func (s *Server) loadWebAuthnUser(ctx context.Context, queryer webAuthnQueryer, applicationID, userID, rpID string) (platformWebAuthnUser, error) {
	var email, firstName, lastName string
	err := queryer.QueryRow(ctx, `SELECT email,first_name,last_name FROM users
WHERE id=$1 AND application_id=$2 AND status='active'`, userID, applicationID).Scan(&email, &firstName, &lastName)
	if err != nil {
		return platformWebAuthnUser{}, err
	}
	parsedID, err := uuid.Parse(userID)
	if err != nil {
		return platformWebAuthnUser{}, err
	}
	result := platformWebAuthnUser{id: parsedID[:], email: email, displayName: strings.TrimSpace(firstName + " " + lastName), methodIDs: map[string]string{}}
	if result.displayName == "" {
		result.displayName = email
	}
	rows, err := queryer.Query(ctx, `SELECT id,credential_id,credential_ciphertext FROM user_authentication_methods
WHERE application_id=$1 AND user_id=$2 AND method_type='webauthn' AND webauthn_rp_id=$3 AND status='active'`, applicationID, userID, rpID)
	if err != nil {
		return platformWebAuthnUser{}, err
	}
	defer rows.Close()
	for rows.Next() {
		var methodID, ciphertext string
		var credentialID []byte
		if rows.Scan(&methodID, &credentialID, &ciphertext) != nil {
			continue
		}
		encoded, decryptErr := s.app.Vault.Decrypt(ciphertext, "webauthn:"+applicationID+":"+userID+":"+methodID)
		var credential webauthnlib.Credential
		if decryptErr == nil && json.Unmarshal(encoded, &credential) == nil && string(credential.ID) == string(credentialID) {
			result.credentials = append(result.credentials, credential)
			result.methodIDs[string(credential.ID)] = methodID
		}
	}
	return result, rows.Err()
}

func (s *Server) ensureRecoveryCodes(ctx context.Context, tx pgx.Tx, applicationID, userID string) ([]string, error) {
	var existing bool
	if err := tx.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM user_recovery_codes
WHERE application_id=$1 AND user_id=$2 AND used_at IS NULL)`, applicationID, userID).Scan(&existing); err != nil || existing {
		return nil, err
	}
	codes := make([]string, 10)
	for index := range codes {
		value, err := secure.RandomToken("", 9)
		if err != nil {
			return nil, err
		}
		codes[index] = strings.ToUpper(value)
		if _, err = tx.Exec(ctx, `INSERT INTO user_recovery_codes(id,application_id,user_id,code_digest)
VALUES ($1,$2,$3,$4)`, kernel.NewID(), applicationID, userID, s.app.Vault.Digest(codes[index])); err != nil {
			return nil, err
		}
	}
	return codes, nil
}
