package httpapi

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

type bufferedResponse struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newBufferedResponse() *bufferedResponse {
	return &bufferedResponse{header: make(http.Header), status: http.StatusOK}
}

func (w *bufferedResponse) Header() http.Header { return w.header }
func (w *bufferedResponse) WriteHeader(status int) {
	if w.status == http.StatusOK {
		w.status = status
	}
}
func (w *bufferedResponse) Write(value []byte) (int, error) { return w.body.Write(value) }

func (s *Server) idempotent(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if key == "" {
			next.ServeHTTP(w, r)
			return
		}
		if len(key) < 8 || len(key) > 255 {
			kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_idempotency_key", "Idempotency-Key must be between 8 and 255 characters.")
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
		if err != nil {
			kernel.WriteProblem(w, r, http.StatusBadRequest, "invalid_request_body", "The request body is too large.")
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))
		hash := kernel.RequestHash(r, body)
		var applicationID *string
		if value := chi.URLParam(r, "application_id"); value != "" {
			applicationID = &value
		}
		current := actor(r)
		actorKey := current.Type + ":" + current.ID
		recordID := kernel.NewID()
		result, err := s.app.DB.Exec(r.Context(), `INSERT INTO idempotency_records
(id,application_id,actor_key,idempotency_key,request_hash,locked_until,expires_at)
VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (application_id,actor_key,idempotency_key) DO NOTHING`,
			recordID, applicationID, actorKey, key, hash, s.app.Now().Add(2*time.Minute), s.app.Now().Add(24*time.Hour))
		if err != nil {
			kernel.WriteProblem(w, r, http.StatusInternalServerError, "idempotency_unavailable", "Idempotency state could not be stored.")
			return
		}
		if result.RowsAffected() == 0 {
			var existingHash, responseBody []byte
			var responseStatus *int
			var responseHeaders []byte
			err = s.app.DB.QueryRow(r.Context(), `SELECT request_hash,response_status,response_headers,response_body
FROM idempotency_records WHERE application_id IS NOT DISTINCT FROM $1::uuid AND actor_key=$2 AND idempotency_key=$3`, applicationID, actorKey, key).Scan(&existingHash, &responseStatus, &responseHeaders, &responseBody)
			if err != nil {
				kernel.WriteProblem(w, r, http.StatusConflict, "idempotency_in_progress", "A request with this idempotency key is in progress.")
				return
			}
			if !bytes.Equal(existingHash, hash) {
				kernel.WriteProblem(w, r, http.StatusConflict, "idempotency_key_reused", "This idempotency key was already used with a different request.")
				return
			}
			if responseStatus == nil {
				kernel.WriteProblem(w, r, http.StatusConflict, "idempotency_in_progress", "A request with this idempotency key is still in progress.")
				return
			}
			var headers map[string][]string
			_ = json.Unmarshal(responseHeaders, &headers)
			for name, values := range headers {
				for _, value := range values {
					w.Header().Add(name, value)
				}
			}
			w.Header().Set("Idempotent-Replayed", "true")
			w.WriteHeader(*responseStatus)
			_, _ = w.Write(responseBody)
			return
		}
		buffer := newBufferedResponse()
		next.ServeHTTP(buffer, r)
		if buffer.status >= 500 {
			_, _ = s.app.DB.Exec(r.Context(), "DELETE FROM idempotency_records WHERE id=$1", recordID)
		} else {
			headers, _ := json.Marshal(map[string][]string{"Content-Type": buffer.header.Values("Content-Type")})
			_, _ = s.app.DB.Exec(r.Context(), `UPDATE idempotency_records SET response_status=$1,response_headers=$2,
response_body=$3,locked_until=NULL WHERE id=$4`, buffer.status, headers, buffer.body.Bytes(), recordID)
		}
		for name, values := range buffer.header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(buffer.status)
		_, _ = w.Write(buffer.body.Bytes())
	})
}
