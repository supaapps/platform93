package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

var errCredentialSessionInvalid = errors.New("credential session is no longer active")

// Hold these locks until the credential write commits. Recovery either follows
// the write and removes it, or commits first and makes this live-session check fail.
func (s *Server) lockCredentialMutation(r *http.Request, tx pgx.Tx, user string) error {
	current := actor(r)
	if current.Type != "user" || current.ID != user || current.DelegatedBy != "" || current.SessionID == "" {
		return errCredentialSessionInvalid
	}
	var id string
	if err := tx.QueryRow(r.Context(), `SELECT u.id FROM users u JOIN user_sessions s ON s.application_id=u.application_id AND s.user_id=u.id
 WHERE u.application_id=$1 AND u.id=$2 AND u.status='active' AND s.id=$3 AND s.revoked_at IS NULL AND s.expires_at>now() AND s.delegation_id IS NULL FOR SHARE OF u,s`, chi.URLParam(r, "application_id"), user, current.SessionID).Scan(&id); err != nil {
		return errCredentialSessionInvalid
	}
	return nil
}

func (s *Server) storeExternalAuthChallenge(r *http.Request, user, query string, args ...any) error {
	if user == "" {
		_, err := s.app.DB.Exec(r.Context(), query, args...)
		return err
	}
	tx, err := s.app.DB.Begin(r.Context())
	if err != nil {
		return err
	}
	defer rollback(tx, r.Context())
	if err = s.lockCredentialMutation(r, tx, user); err != nil {
		return err
	}
	if _, err = tx.Exec(r.Context(), query, args...); err != nil {
		return err
	}
	return tx.Commit(r.Context())
}

func credentialSessionProblem(w http.ResponseWriter, r *http.Request, err error) bool {
	if !errors.Is(err, errCredentialSessionInvalid) {
		return false
	}
	// Callers return before creating credentials when their session was revoked.
	kernel.WriteProblem(w, r, http.StatusUnauthorized, "authentication_restarted", "Account credentials changed. Sign in again.")
	return true
}
