package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/supaapps/platform93/internal/kernel"
)

type workspaceHTTPFixture struct {
	*oauthSecurityFixture
	controlToken string
}

func newWorkspaceHTTPFixture(t *testing.T) *workspaceHTTPFixture {
	f := newOAuthSecurityFixture(t)
	session := kernel.NewID().String()
	f.exec(`INSERT INTO organization_memberships(organization_id,control_user_id,role)
SELECT organization_id,$2,'admin' FROM applications WHERE id=$1`, f.application, f.controlUser)
	f.exec(`INSERT INTO control_user_sessions(id,control_user_id,refresh_digest,kind,expires_at)
VALUES($1,$2,$3,'control',now()+interval '1 hour')`, session, f.controlUser, f.app.Vault.Digest("workspace-test-session"))
	s := &Server{app: f.app}
	token, err := s.issueControlUserAccess(context.Background(), f.controlUser, session, "control")
	if err != nil {
		t.Fatal(err)
	}
	return &workspaceHTTPFixture{oauthSecurityFixture: f, controlToken: token}
}

func (f *workspaceHTTPFixture) create(body map[string]any) *httptest.ResponseRecorder {
	f.t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		f.t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/v1/control/applications/"+f.application+"/workspaces", strings.NewReader(string(encoded)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", f.app.PublicURL)
	r.AddCookie(&http.Cookie{Name: "p93_control_access", Value: f.controlToken})
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, r)
	return w
}

func TestWorkspaceCreationDashboardMetadataAndEvents(t *testing.T) {
	f := newWorkspaceHTTPFixture(t)
	for _, test := range []struct {
		name     string
		present  bool
		metadata any
		want     map[string]any
	}{
		{"omitted", false, nil, map[string]any{}},
		{"null", true, nil, map[string]any{}},
		{"empty", true, map[string]any{}, map[string]any{}},
		{"supplied", true, map[string]any{"label": "Example", "enabled": true, "nested": map[string]any{"count": float64(3)}}, map[string]any{"label": "Example", "enabled": true, "nested": map[string]any{"count": float64(3)}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			body := map[string]any{"owner_user_id": f.user, "key": "workspace-" + test.name, "name": "Workspace " + test.name}
			if test.present {
				body["metadata"] = test.metadata
			}
			started := time.Now().Add(-time.Second)
			w := f.create(body)
			if w.Code != http.StatusCreated {
				t.Fatalf("dashboard request failed: %d %s", w.Code, w.Body.String())
			}
			var result struct {
				ID       string         `json:"id"`
				Metadata map[string]any `json:"metadata"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(result.Metadata, test.want) {
				t.Fatalf("response metadata: %#v", result.Metadata)
			}
			var stored, payload []byte
			var eventID, subject, actorID string
			var occurred time.Time
			if err := f.app.DB.QueryRow(context.Background(), `SELECT metadata FROM workspaces WHERE id=$1 AND application_id=$2 AND owner_user_id=$3`, result.ID, f.application, f.user).Scan(&stored); err != nil {
				t.Fatal(err)
			}
			var metadata map[string]any
			if err := json.Unmarshal(stored, &metadata); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(metadata, test.want) {
				t.Fatalf("stored metadata: %s", stored)
			}
			if err := f.app.DB.QueryRow(context.Background(), `SELECT id,data,subject,actor->>'id',occurred_at FROM domain_events WHERE application_id=$1 AND event_type='workspace.created' AND data->>'workspace_id'=$2`, f.application, result.ID).Scan(&eventID, &payload, &subject, &actorID, &occurred); err != nil {
				t.Fatal(err)
			}
			var data map[string]any
			if err := json.Unmarshal(payload, &data); err != nil {
				t.Fatal(err)
			}
			want := map[string]any{"workspace_id": result.ID, "owner_user_id": f.user, "key": body["key"], "name": body["name"], "status": "active"}
			if !reflect.DeepEqual(data, want) || subject != "workspace/"+result.ID || actorID != f.controlUser || occurred.Before(started) || occurred.After(time.Now().Add(time.Second)) {
				t.Fatalf("invalid emitted event: %s", payload)
			}
			var billing, outbox, members int
			if err := f.app.DB.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM billing_profiles WHERE application_id=$1 AND subject_type='workspace' AND subject_id=$2),(SELECT count(*) FROM outbox WHERE event_id=$3),(SELECT count(*) FROM workspace_memberships WHERE workspace_id=$2 AND user_id=$4)`, f.application, result.ID, eventID, f.user).Scan(&billing, &outbox, &members); err != nil {
				t.Fatal(err)
			}
			if billing != 1 || outbox != 1 || members != 0 {
				t.Fatalf("invalid atomic state: billing=%d outbox=%d members=%d", billing, outbox, members)
			}
		})
	}
}

func TestWorkspaceCreationRejectsInvalidOwnersAndTrueConflicts(t *testing.T) {
	f := newWorkspaceHTTPFixture(t)
	foreignApp, foreignUser, inactive := kernel.NewID().String(), kernel.NewID().String(), kernel.NewID().String()
	f.exec(`INSERT INTO applications(id,organization_id,name,slug) SELECT $1,organization_id,'Other',$1::uuid::text FROM applications WHERE id=$2`, foreignApp, f.application)
	f.exec(`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,'foreign@example.test','foreign@example.test')`, foreignUser, foreignApp)
	f.exec(`INSERT INTO users(id,application_id,email,normalized_email,status) VALUES($1,$2,'inactive@example.test','inactive@example.test','suspended')`, inactive, f.application)
	for _, owner := range []string{"not-a-uuid", kernel.NewID().String(), foreignUser, inactive} {
		w := f.create(map[string]any{"owner_user_id": owner, "key": "invalid-owner", "name": "Invalid owner", "metadata": map[string]any{}})
		if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "invalid_workspace_owner") {
			t.Fatalf("owner error is misleading: %d %s", w.Code, w.Body.String())
		}
	}
	body := map[string]any{"owner_user_id": f.user, "key": "duplicate", "name": "First", "metadata": map[string]any{}}
	if w := f.create(body); w.Code != http.StatusCreated {
		t.Fatalf("initial creation failed: %d %s", w.Code, w.Body.String())
	}
	if w := f.create(body); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "workspace_conflict") {
		t.Fatalf("duplicate key was not a conflict: %d %s", w.Code, w.Body.String())
	}
	var workspaces, events, billing int
	if err := f.app.DB.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM workspaces WHERE application_id=$1),(SELECT count(*) FROM domain_events WHERE application_id=$1 AND event_type='workspace.created'),(SELECT count(*) FROM billing_profiles WHERE application_id=$1 AND subject_type='workspace')`, f.application).Scan(&workspaces, &events, &billing); err != nil {
		t.Fatal(err)
	}
	if workspaces != 1 || events != 1 || billing != 1 {
		t.Fatalf("rejected requests left partial records: %d %d %d", workspaces, events, billing)
	}
}

func TestWorkspaceCreationEventFailureRollsBackAndIsNotConflict(t *testing.T) {
	f := newWorkspaceHTTPFixture(t)
	f.exec(`UPDATE event_type_definitions SET status='archived' WHERE application_id IS NULL AND name='workspace.created'`)
	w := f.create(map[string]any{"owner_user_id": f.user, "key": "rollback", "name": "Rollback", "metadata": map[string]any{}})
	if w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "workspace_creation_failed") {
		t.Fatalf("storage failure was misreported: %d %s", w.Code, w.Body.String())
	}
	var count int
	if err := f.app.DB.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM workspaces WHERE application_id=$1)+(SELECT count(*) FROM billing_profiles WHERE application_id=$1)+(SELECT count(*) FROM domain_events WHERE application_id=$1)+(SELECT count(*) FROM outbox o JOIN domain_events e ON e.id=o.event_id WHERE e.application_id=$1)`, f.application).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatal("failed creation left partial state")
	}
}

func TestWorkspaceMetadataNilBindingReproducesNotNullViolation(t *testing.T) {
	f := newWorkspaceHTTPFixture(t)
	var metadata map[string]any
	_, err := f.app.DB.Exec(context.Background(), `INSERT INTO workspaces(id,application_id,owner_user_id,key,name,metadata) VALUES($1,$2,$3,'nil-binding','Nil binding',$4)`, kernel.NewID(), f.application, f.user, metadata)
	var pgError *pgconn.PgError
	if !errors.As(err, &pgError) || pgError.Code != "23502" || pgError.ColumnName != "metadata" {
		t.Fatalf("unexpected database diagnosis: %v", err)
	}
	t.Logf("confirmed PostgreSQL %s: column %s rejects SQL NULL", pgError.Code, pgError.ColumnName)
}

func TestWorkspaceCreationPreservesControlAuthorization(t *testing.T) {
	f := newWorkspaceHTTPFixture(t)
	f.exec(`UPDATE organization_memberships SET role='auditor' WHERE control_user_id=$1`, f.controlUser)
	w := f.create(map[string]any{"owner_user_id": f.user, "key": "forbidden", "name": "Forbidden"})
	if w.Code != http.StatusForbidden {
		t.Fatalf("read-only control user created a workspace: %d %s", w.Code, w.Body.String())
	}
	f.exec(`DELETE FROM organization_memberships WHERE control_user_id=$1`, f.controlUser)
	w = f.create(map[string]any{"owner_user_id": f.user, "key": "foreign", "name": "Foreign"})
	if w.Code != http.StatusNotFound {
		t.Fatalf("control user crossed organization boundary: %d %s", w.Code, w.Body.String())
	}
}

func TestWorkspaceCreationBindsUserOwnerToAuthenticatedApplication(t *testing.T) {
	f := newWorkspaceHTTPFixture(t)
	other := kernel.NewID().String()
	f.exec(`INSERT INTO users(id,application_id,email,normalized_email) VALUES($1,$2,'other@example.test','other@example.test')`, other, f.application)
	body := `{"key":"self-owned","name":"Self owned","owner_user_id":"` + other + `"}`
	r := httptest.NewRequest(http.MethodPost, "/v1/applications/"+f.application+"/me/workspaces", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+f.accessToken(false))
	w := httptest.NewRecorder()
	f.router.ServeHTTP(w, r)
	if w.Code != http.StatusCreated {
		t.Fatalf("user workspace creation failed: %d %s", w.Code, w.Body.String())
	}
	var response struct {
		Owner string `json:"owner_user_id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &response); err != nil {
		t.Fatal(err)
	}
	if response.Owner != f.user {
		t.Fatal("application user selected a different owner")
	}
	r = httptest.NewRequest(http.MethodPost, "/v1/applications/"+kernel.NewID().String()+"/me/workspaces", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+f.accessToken(false))
	w = httptest.NewRecorder()
	f.router.ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("cross-application token was accepted: %d", w.Code)
	}
}
