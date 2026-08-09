package kernel

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/google/uuid"
)

type Problem struct {
	Type      string         `json:"type"`
	Title     string         `json:"title"`
	Status    int            `json:"status"`
	Detail    string         `json:"detail,omitempty"`
	Code      string         `json:"code"`
	RequestID string         `json:"request_id,omitempty"`
	Errors    map[string]any `json:"errors,omitempty"`
}

func WriteJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func WriteProblem(w http.ResponseWriter, r *http.Request, status int, code, detail string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(Problem{
		Type:      "https://platform93.dev/problems/" + code,
		Title:     http.StatusText(status),
		Status:    status,
		Detail:    detail,
		Code:      code,
		RequestID: RequestID(r.Context()),
	})
}

func DecodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_json", "The request body is not valid for this operation.")
		return false
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		WriteProblem(w, r, http.StatusBadRequest, "invalid_json", "The request body must contain exactly one JSON value.")
		return false
	}
	return true
}

func NewID() uuid.UUID { return uuid.Must(uuid.NewV7()) }

func NormalizeEmail(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

func RequestHash(r *http.Request, body []byte) []byte {
	sum := sha256.Sum256(append([]byte(r.Method+"\n"+r.URL.Path+"\n"), body...))
	return sum[:]
}

func ETag(version int64) string { return fmt.Sprintf(`"v%x"`, version) }

func CheckIfMatch(w http.ResponseWriter, r *http.Request, version int64) bool {
	value := strings.TrimSpace(r.Header.Get("If-Match"))
	if value == "" || value == "*" || value == ETag(version) {
		return true
	}
	WriteProblem(w, r, http.StatusPreconditionFailed, "version_conflict", "The resource changed after it was loaded.")
	return false
}
