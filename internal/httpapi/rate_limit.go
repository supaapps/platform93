package httpapi

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/supaapps/platform93/internal/kernel"
)

func (s *Server) allowAuthAttempt(w http.ResponseWriter, r *http.Request, flow, subject string, limit int, window time.Duration) bool {
	type bucket struct {
		key   string
		limit int
	}
	keys := []bucket{{key: flow + ":subject:" + strings.ToLower(strings.TrimSpace(subject)), limit: limit}}
	if ip := requestIPAddress(r); ip != nil {
		// Shared networks must not inherit the much tighter per-account ceiling.
		keys = append(keys, bucket{key: flow + ":ip:" + fmt.Sprint(ip), limit: limit * 5})
	}
	var retryAfter time.Duration
	for _, bucket := range keys {
		var attempts int
		var expiresAt time.Time
		err := s.app.DB.QueryRow(r.Context(), `INSERT INTO auth_rate_limits(bucket_digest,attempts,window_started_at,expires_at)
VALUES($1,1,now(),now()+$2::interval) ON CONFLICT(bucket_digest) DO UPDATE SET
attempts=CASE WHEN auth_rate_limits.expires_at<=now() THEN 1 ELSE auth_rate_limits.attempts+1 END,
window_started_at=CASE WHEN auth_rate_limits.expires_at<=now() THEN now() ELSE auth_rate_limits.window_started_at END,
expires_at=CASE WHEN auth_rate_limits.expires_at<=now() THEN now()+$2::interval ELSE auth_rate_limits.expires_at END
RETURNING attempts,expires_at`, s.app.Vault.Digest(bucket.key), intervalString(window)).Scan(&attempts, &expiresAt)
		if err != nil {
			kernel.WriteProblem(w, r, http.StatusServiceUnavailable, "rate_limit_unavailable", "Authentication cannot be attempted safely at this time.")
			return false
		}
		if attempts > bucket.limit {
			remaining := time.Until(expiresAt)
			if remaining > retryAfter {
				retryAfter = remaining
			}
		}
	}
	if retryAfter > 0 {
		seconds := int(retryAfter.Seconds()) + 1
		w.Header().Set("Retry-After", fmt.Sprint(seconds))
		kernel.WriteProblem(w, r, http.StatusTooManyRequests, "authentication_rate_limited", "Too many authentication attempts were made. Retry later.")
		return false
	}
	return true
}

func intervalString(value time.Duration) string {
	seconds := int64(value / time.Second)
	return fmt.Sprintf("%d seconds", seconds)
}
