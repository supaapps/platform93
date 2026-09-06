package httpapi

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCreateInvitationReportsInvalidOnboardingMethod(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "/v1/control/applications/application/invitations",
		strings.NewReader(`{"email":"person@example.test","onboarding_method":"unsupported"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()

	(&Server{}).createInvitation(response, request, true)

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
