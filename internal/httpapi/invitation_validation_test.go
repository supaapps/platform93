package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/supaapps/platform93/internal/kernel"
)

func TestCreateInvitationReportsInvalidOnboardingMethod(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/v1/control/applications/01900000-0000-7000-8000-000000000001/invitations",
		strings.NewReader(`{"email":"person@example.test","onboarding_method":"unsupported"}`))
	request.Header.Set("Content-Type", "application/json")
	request = request.WithContext(kernel.WithActor(request.Context(), kernel.Actor{Type: "control_user"}))
	response := httptest.NewRecorder()

	router := chi.NewRouter()
	router.Post("/v1/control/applications/{application_id}/invitations", (&Server{}).createControlInvitation)
	router.ServeHTTP(response, request)

	if response.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected status %d, got %d", http.StatusUnprocessableEntity, response.Code)
	}
	var problem struct {
		Code   string `json:"code"`
		Detail string `json:"detail"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if problem.Code != "invalid_invitation_onboarding_method" {
		t.Fatalf("unexpected problem code %q", problem.Code)
	}
	if !strings.Contains(problem.Detail, "supported external authentication provider") {
		t.Fatalf("unexpected problem detail %q", problem.Detail)
	}
}

func TestCreateInvitationRejectsInvalidApplicationBeforeDatabaseAccess(t *testing.T) {
	router := chi.NewRouter()
	router.Post("/v1/control/applications/{application_id}/invitations", (&Server{}).createControlInvitation)
	r := httptest.NewRequest(http.MethodPost, "/v1/control/applications/invalid/invitations", strings.NewReader(`{"email":"person@example.test"}`))
	r.Header.Set("Content-Type", "application/json")
	r = r.WithContext(kernel.WithActor(r.Context(), kernel.Actor{Type: "control_user"}))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)
	if w.Code != 422 || !strings.Contains(w.Body.String(), "invalid_application_id") {
		t.Fatalf("%d %s", w.Code, w.Body.String())
	}
}
