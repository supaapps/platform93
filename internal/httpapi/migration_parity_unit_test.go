package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/supaapps/platform93/internal/kernel"
)

func TestMachineNotificationRejectsBrowserRequests(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodPost, "/v1/applications/app/notifications", nil)
	request.Header.Set("Origin", "https://app.example")
	request = request.WithContext(kernel.WithActor(request.Context(), kernel.Actor{Type: "client"}))
	recorder := httptest.NewRecorder()
	new(Server).queueMachineNotification(recorder, request)
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected browser request to be rejected, got %d", recorder.Code)
	}
}

func TestApplicationServiceAPIsRequireMachineActor(t *testing.T) {
	t.Parallel()
	request := httptest.NewRequest(http.MethodGet, "/v1/applications/app/users", nil)
	request = request.WithContext(kernel.WithActor(request.Context(), kernel.Actor{Type: "user", Permissions: []string{"/applications/app/users/read"}}))
	recorder := httptest.NewRecorder()
	if requireApplicationPermission(recorder, request, "users/read") {
		t.Fatal("application user was accepted by a machine service API")
	}
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("expected forbidden response, got %d", recorder.Code)
	}
}

func TestInvitationPKCEValidation(t *testing.T) {
	t.Parallel()
	if !invitationPKCEChallengePattern.MatchString("abcdefghijklmnopqrstuvwxyzABCDEFGH012345678") {
		t.Fatal("valid 43-character S256 challenge was rejected")
	}
	if invitationPKCEChallengePattern.MatchString("abcdefghijklmnopqrstuvwxyzABCDEFGH01234567+") {
		t.Fatal("non-base64url challenge was accepted")
	}
	if !invitationPKCEVerifierPattern.MatchString("abcdefghijklmnopqrstuvwxyzABCDEFGH012345678") {
		t.Fatal("valid PKCE verifier was rejected")
	}
}
